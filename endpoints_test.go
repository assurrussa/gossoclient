//nolint:goconst,lll // Explicit URL attacks and route counters make endpoint policy reviewable.
package browser

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type endpointFixture struct {
	server     *httptest.Server
	discovery  atomic.Int32
	explicit   atomic.Int32
	discovered atomic.Int32
	redirected atomic.Int32
	redirects  atomic.Int32
	legacy     atomic.Int32
}

func newEndpointFixture(t *testing.T, revoke string) *endpointFixture {
	t.Helper()
	f := &endpointFixture{}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			f.discovery.Add(1)
			issuer := "https://" + r.Host
			metadata := map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
				"id_token_signing_alg_values_supported": []string{"RS256"},
			}
			if revoke != "" {
				metadata["revocation_endpoint"] = strings.ReplaceAll(revoke, "{issuer}", issuer)
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(metadata); err != nil {
				t.Error(err)
			}
		case "/explicit", "/discovered", "/oauth2/revoke":
			id, secret, ok := r.BasicAuth()
			if !ok || id != "client-123" || secret != "client-secret" || r.Method != http.MethodPost {
				t.Error("revocation credentials/method changed")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := r.ParseForm(); err != nil || r.PostForm.Get("token") != "synthetic-refresh" ||
				r.PostForm.Get("token_type_hint") != "refresh_token" {
				t.Error("revocation form changed", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			switch r.URL.Path {
			case "/explicit":
				f.explicit.Add(1)
			case "/discovered":
				f.discovered.Add(1)
			case "/oauth2/revoke":
				f.legacy.Add(1)
			}
			w.WriteHeader(http.StatusOK)
		case "/redirect":
			f.redirects.Add(1)
			http.Redirect(w, r, "/redirect-target", http.StatusTemporaryRedirect)
		case "/redirect-target":
			f.redirected.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func endpointTestConfig(issuer string) config {
	return config{
		Issuer: issuer, ClientID: "client-123", ProjectID: testProject,
		Origin: "https://app.test", Callback: "https://app.test/callback",
	}
}

func TestIssuerEndpointPolicy(t *testing.T) {
	const issuer = "https://issuer.test"
	for _, endpoint := range []string{
		"", issuer, "/revoke", "//issuer.test/revoke", "http://issuer.test/revoke",
		"https://other.test/revoke", "https://user@issuer.test/revoke",
		issuer + "/revoke#fragment", issuer + "/revoke#", issuer + "/revoke?key=value",
		issuer + "/revoke?", issuer + "/revoke\n", issuer + "/%0d%0a",
		issuer + "/%5cevil", issuer + "//other.test", issuer + "/has space",
		"https://ISSUER.test/revoke", "https://issuer.test:443/revoke",
		"HTTPS://issuer.test/revoke", "https://issuer.test:8443/revoke", issuer + "/a%2fb",
		issuer + "/" + strings.Repeat("a", 2048),
	} {
		t.Run(endpoint, func(t *testing.T) {
			if err := ValidateIssuerEndpoint(issuer, endpoint); err == nil {
				t.Fatal("unsafe endpoint accepted")
			}
			for _, central := range []bool{false, true} {
				c := endpointTestConfig(issuer)
				if central {
					c.CentralLogoutURL = endpoint
				} else {
					c.RevocationEndpoint = endpoint
				}
				// Empty values are optional at this layer: discovery may supply
				// revocation and an omitted central link is supported.
				if endpoint != "" && c.validate() == nil {
					t.Fatal("configured endpoint escaped validation")
				}
			}
		})
	}
	for _, endpoint := range []string{issuer + "/revoke", issuer + "/oidc/revoke", issuer + "/"} {
		if err := ValidateIssuerEndpoint(issuer, endpoint); err != nil {
			t.Fatal("safe endpoint rejected", err)
		}
	}
	if err := ValidateIssuerEndpoint("https://ISSUER.test", "https://ISSUER.test/revoke"); err == nil {
		t.Fatal("noncanonical issuer accepted")
	}
}

func TestRevocationSelectionAndNoGuessedFallback(t *testing.T) {
	for _, tc := range []struct {
		name, advertised, explicit, want string
		ok                               bool
	}{
		{"discovery", "{issuer}/discovered", "", "/discovered", true},
		{"explicit takes precedence", "{issuer}/discovered", "/explicit", "/explicit", true},
		{"explicit without discovery", "", "/explicit", "/explicit", true},
		{"explicit ignores unused metadata", "https://other.test/revoke", "/explicit", "/explicit", true},
		{"missing", "", "", "", false},
		{"foreign", "https://other.test/revoke", "", "", false},
		{"userinfo", "https://user@issuer.test/revoke", "", "", false},
		{"fragment", "{issuer}/discovered#fragment", "", "", false},
		{"empty fragment", "{issuer}/discovered#", "", "", false},
		{"query", "{issuer}/discovered?x=y", "", "", false},
		{"relative", "/discovered", "", "", false},
		{"insecure", "http://issuer.test/discovered", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newEndpointFixture(t, tc.advertised)
			c := endpointTestConfig(fixture.server.URL)
			if tc.explicit != "" {
				c.RevocationEndpoint = fixture.server.URL + tc.explicit
			}
			client, err := newOIDC(t.Context(), c, "client-secret", fixture.server.Client().Transport, time.Now)
			if !tc.ok {
				if err == nil {
					t.Fatal("invalid discovery accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if client.config.RevocationEndpoint != fixture.server.URL+tc.want {
				t.Fatal("incorrect endpoint selected")
			}
			if err := client.revoke(t.Context(), "synthetic-refresh"); err != nil {
				t.Fatal(err)
			}
			if fixture.explicit.Load()+fixture.discovered.Load() != 1 || fixture.legacy.Load() != 0 {
				t.Fatal("revocation used an unselected or guessed route")
			}
		})
	}
}

func TestUnsafeExplicitEndpointsFailBeforeDiscovery(t *testing.T) {
	fixture := newEndpointFixture(t, "{issuer}/discovered")
	for _, central := range []bool{false, true} {
		c := endpointTestConfig(fixture.server.URL)
		if central {
			c.CentralLogoutURL = "https://other.test/sign-out"
		} else {
			c.RevocationEndpoint = "https://other.test/revoke"
		}
		if _, err := newOIDC(t.Context(), c, "client-secret", fixture.server.Client().Transport, time.Now); err == nil {
			t.Fatal("cross-origin explicit endpoint accepted")
		}
	}
	if fixture.discovery.Load() != 0 {
		t.Fatal("invalid explicit endpoint caused network discovery")
	}
}

func TestRevocationRedirectIsNotFollowedOrRetried(t *testing.T) {
	fixture := newEndpointFixture(t, "{issuer}/redirect")
	client, err := newOIDC(t.Context(), endpointTestConfig(fixture.server.URL), "client-secret",
		fixture.server.Client().Transport, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.revoke(t.Context(), "synthetic-refresh"); err == nil || fixture.redirected.Load() != 0 || fixture.redirects.Load() != 1 {
		t.Fatal("revocation redirect followed or acknowledged")
	}
}

func TestLegacyConstructorKeepsRoutesWhileStrictConstructorDoesNotGuess(t *testing.T) {
	fixture := newEndpointFixture(t, "")
	roots := testIssuerRoots(t, fixture.server)
	c := Config{
		Issuer: fixture.server.URL, ClientID: "client-123", ProjectID: testProject,
		Origin: "https://app.test", Callback: "https://app.test/callback", IssuerCAFile: roots,
	}
	legacy, err := New(t.Context(), c, Options{
		Store: optionTestStore(), ClientSecret: "client-secret", StorageKey: make([]byte, 32),
	})
	if err != nil {
		t.Fatal("legacy construction changed", err)
	}
	if legacy.app.config.RevocationEndpoint != c.Issuer+"/oauth2/revoke" ||
		legacy.app.config.CentralLogoutURL != c.Issuer+"/sso/logout" {
		t.Fatal("legacy routing changed")
	}
	if err := legacy.app.oidc.revoke(t.Context(), "synthetic-refresh"); err != nil || fixture.legacy.Load() != 1 {
		t.Fatal("legacy revocation changed", err)
	}
	values := validTestOptions()
	values[0] = WithIssuer(c.Issuer)
	values = append(values, WithIssuerCAFile(roots))
	if _, err := NewWithOptions(t.Context(), values...); err == nil {
		t.Fatal("strict constructor invented a revocation route")
	}
	values = append(values, WithRevocationEndpoint(c.Issuer+"/explicit"))
	strict, err := NewWithOptions(t.Context(), values...)
	if err != nil {
		t.Fatal(err)
	}
	if strict.app.config.CentralLogoutURL != "" {
		t.Fatal("strict constructor invented a central logout link")
	}
}

func TestCentralLogoutLinkIsOptional(t *testing.T) {
	for _, link := range []string{"", "https://issuer.test/confirm-sign-out"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://app.test/", nil)
		testRender(w, r, View{CSRF: "synthetic", CentralLogout: link})
		body := w.Body.String()
		if link == "" && strings.Contains(body, "href=") {
			t.Fatal("missing central URL rendered a link")
		}
		if link != "" && !strings.Contains(body, `href="`+link+`"`) {
			t.Fatal("configured central URL omitted")
		}
	}
}
