package browser

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"sync/atomic"
	"testing"
	"time"
)

const (
	transportInvalidEndpoint        = "invalid-endpoint"
	transportDiscoveryPath          = "/.well-known/openid-configuration"
	transportForeignRevokeURL       = "https://other.test/revoke"
	transportAuthorizationField     = "authorization_endpoint"
	transportJWKSField              = "jwks_uri"
	transportSigningAlgorithm       = "RS256"
	transportIdleEventName          = "idle discovery connection"
	transportProbePath              = "/probe"
	transportContentTypeHeader      = "Content-Type"
	transportJSONContentType        = "application/json"
	transportHTTPSPrefix            = "https://"
	transportRevokePath             = "/revoke"
	transportIssuerField            = "issuer"
	transportTokenField             = "token_endpoint"
	transportRevocationField        = "revocation_endpoint"
	transportSigningAlgorithmsField = "id_token_signing_alg_values_supported"
	transportClientSecret           = "client-secret"
)

func transportFixture(t *testing.T, mode string) (server *httptest.Server, idleEvents, closedEvents <-chan struct{}) {
	t.Helper()
	idle := make(chan struct{}, 1)
	closed := make(chan struct{}, 1)
	server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case transportDiscoveryPath:
			w.Header().Set(transportContentTypeHeader, transportJSONContentType)
			if mode == "invalid-json" {
				if _, err := io.WriteString(w, "{"); err != nil {
					t.Error(err)
				}
				return
			}
			issuer := transportHTTPSPrefix + r.Host
			revoke := issuer + transportRevokePath
			if mode == transportInvalidEndpoint {
				revoke = transportForeignRevokeURL
			}
			if err := json.NewEncoder(w).Encode(map[string]any{
				transportIssuerField: issuer, transportAuthorizationField: issuer + "/authorize",
				transportTokenField: issuer + "/token", transportJWKSField: issuer + "/keys",
				transportRevocationField:        revoke,
				transportSigningAlgorithmsField: []string{transportSigningAlgorithm},
			}); err != nil {
				t.Error(err)
			}
		case transportProbePath:
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		switch state {
		case http.StateIdle:
			select {
			case idle <- struct{}{}:
			default:
			}
		case http.StateClosed:
			select {
			case closed <- struct{}{}:
			default:
			}
		default:
		}
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, idle, closed
}

func waitTransportEvent(t *testing.T, event <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-event:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for transport event:", name)
	}
}

func TestOwnedTransportClosesIdleConnectionsOnConstructionFailure(t *testing.T) {
	for _, mode := range []string{"invalid-json", transportInvalidEndpoint} {
		t.Run(mode, func(t *testing.T) {
			server, idle, closed := transportFixture(t, mode)
			cfg := endpointTestConfig(server.URL)
			cfg.IssuerCAFile = testIssuerRoots(t, server)
			if _, err := newOIDC(t.Context(), cfg, transportClientSecret, nil, time.Now); err == nil {
				t.Fatal("construction unexpectedly succeeded")
			}
			// The fixture itself never closes keep-alive connections here.
			// Observe both states before test cleanup can close the server.
			waitTransportEvent(t, idle, transportIdleEventName)
			waitTransportEvent(t, closed, "owned connection closed after failure")
		})
	}
}

func assertTransportConnectionReused(t *testing.T, client *http.Client, target string) {
	t.Helper()
	var reused atomic.Bool
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused.Store(info.Reused) },
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !reused.Load() {
		t.Fatal("constructor closed a retained or caller-owned connection")
	}
}

func TestConstructorRetainsSuccessfulAndCallerOwnedTransports(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		injected   bool
	}{
		{"owned success", "valid", false},
		{"caller-owned success", "valid", true},
		{"caller-owned failure", transportInvalidEndpoint, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, idle, _ := transportFixture(t, tc.mode)
			cfg := endpointTestConfig(server.URL)
			cfg.IssuerCAFile = testIssuerRoots(t, server)
			var supplied http.RoundTripper
			var retained *http.Transport
			if tc.injected {
				base, ok := server.Client().Transport.(*http.Transport)
				if !ok {
					t.Fatal("unexpected fixture transport")
				}
				retained = base.Clone()
				supplied = retained
				t.Cleanup(retained.CloseIdleConnections)
			}
			client, err := newOIDC(t.Context(), cfg, transportClientSecret, supplied, time.Now)
			if tc.mode == transportInvalidEndpoint {
				if err == nil {
					t.Fatal("construction unexpectedly succeeded")
				}
				probe := &http.Client{Transport: retained, Timeout: 5 * time.Second}
				waitTransportEvent(t, idle, transportIdleEventName)
				assertTransportConnectionReused(t, probe, server.URL+transportProbePath)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !tc.injected {
				bounded, ok := client.http.Transport.(boundedTransport)
				if !ok {
					t.Fatal("missing bounded transport")
				}
				retained, ok = bounded.base.(*http.Transport)
				if !ok {
					t.Fatal("missing owned transport")
				}
				t.Cleanup(retained.CloseIdleConnections)
			}
			waitTransportEvent(t, idle, transportIdleEventName)
			// Reuse is a positive assertion: no sleep-based claim that an
			// asynchronous CloseIdleConnections call did not happen.
			assertTransportConnectionReused(t, client.http, server.URL+transportProbePath)
		})
	}
}
