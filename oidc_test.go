//nolint:goconst,lll // Explicit wire literals and fixture cases stay readable at each assertion.
package browser

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

const (
	testProject = "20000000-0000-4000-8000-000000000002"
	testSID     = "30000000-0000-4000-8000-000000000003"
)

type authority struct {
	t                *testing.T
	server           *httptest.Server
	signer           jose.Signer
	key              *rsa.PrivateKey
	now              time.Time
	mu               sync.Mutex
	nonce, challenge string
	claims           func(map[string]any)
	calls            atomic.Int32
	requests         atomic.Int32
	mode             string
	arrived          chan struct{}
	release          chan struct{}
}

func newAuthority(t *testing.T) *authority {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key").WithType("JWT"))
	if e != nil {
		t.Fatal(e)
	}
	p := &authority{t: t, key: key, signer: signer, now: time.Now().UTC().Truncate(time.Second)}
	p.server = httptest.NewTLSServer(http.HandlerFunc(p.serve))
	t.Cleanup(p.server.Close)
	return p
}

func (p *authority) token(nonce string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	claims := map[string]any{"iss": p.server.URL, "sub": "subject-123", "aud": "client-123", "iat": p.now.Unix(), "exp": p.now.Add(5 * time.Minute).Unix(), "auth_time": p.now.Add(-time.Minute).Unix(), "sid": testSID, "project_id": testProject, "token_use": "id", "nonce": nonce, "authhub_profile": map[string]string{"display_name": "Example"}}
	if p.claims != nil {
		p.claims(claims)
	}
	raw, e := json.Marshal(claims)
	if e != nil {
		p.t.Fatal(e)
	}
	signed, e := p.signer.Sign(raw)
	if e != nil {
		p.t.Fatal(e)
	}
	result, e := signed.CompactSerialize()
	if e != nil {
		p.t.Fatal(e)
	}
	return result
}

func (p *authority) serve(w http.ResponseWriter, r *http.Request) {
	p.requests.Add(1)
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		if e := json.NewEncoder(w).Encode(map[string]any{"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/oauth2/authorize", "token_endpoint": p.server.URL + "/oauth2/token", "jwks_uri": p.server.URL + "/oauth2/jwks", "revocation_endpoint": p.server.URL + "/oauth2/revoke", "id_token_signing_alg_values_supported": []string{"RS256"}}); e != nil {
			p.t.Error(e)
		}
	case "/oauth2/jwks":
		if e := json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"}}}); e != nil {
			p.t.Error(e)
		}
	case "/oauth2/revoke":
		w.WriteHeader(http.StatusOK)
	case "/oauth2/token":
		p.serveToken(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *authority) serveToken(w http.ResponseWriter, r *http.Request) {
	p.calls.Add(1)
	_ = r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok || id != "client-123" || secret != "client-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
		return
	}
	p.mu.Lock()
	mode, nonce, challenge, arrived, release := p.mode, p.nonce, p.challenge, p.arrived, p.release
	p.mu.Unlock()
	if arrived != nil {
		select {
		case arrived <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if mode == "lost" {
		h, ok := w.(http.Hijacker)
		if !ok {
			p.t.Error("fixture cannot hijack")
			return
		}
		connection, _, e := h.Hijack()
		if e == nil {
			_ = connection.Close()
		}
		return
	}
	if mode == "deny" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
		return
	}
	if mode == "outage" {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"error":"temporarily_unavailable"}`)
		return
	}
	if r.Form.Get("grant_type") == "authorization_code" {
		hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if r.Form.Get("code") != "one-code" || base64.RawURLEncoding.EncodeToString(hash[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
			return
		}
	}
	if e := json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 999999, "refresh_token": fmt.Sprintf("rotated-%d", p.calls.Load()), "id_token": p.token(nonce)}); e != nil {
		p.t.Error(e)
	}
}

func (p *authority) client(t *testing.T, now func() time.Time) *oidcClient {
	t.Helper()
	c := config{Issuer: p.server.URL, ClientID: "client-123", ProjectID: testProject, Origin: "https://app.example.test", Callback: "https://app.example.test/callback"}
	client, e := newOIDC(context.Background(), c, "client-secret", p.server.Client().Transport, now)
	if e != nil {
		t.Fatal(e)
	}
	return client
}

func TestOfficialDiscoveryExchangeJWKSAndSignedDeadline(t *testing.T) {
	p := newAuthority(t)
	client := p.client(t, func() time.Time { return p.now })
	verifier := oauth2.GenerateVerifier()
	target, _ := url.Parse(client.oauth.AuthCodeURL("state", oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", "nonce")))
	p.nonce = "nonce"
	p.challenge = target.Query().Get("code_challenge")
	if target.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("missing PKCE")
	}
	token, e := client.oauth.Exchange(client.context(context.Background()), "one-code", oauth2.VerifierOption(verifier))
	if e != nil {
		t.Fatal(e)
	}
	proof, e := client.verify(context.Background(), token, "nonce", nil)
	if e != nil {
		t.Fatal(e)
	}
	if !proof.FreshUntil.Equal(p.now.Add(5*time.Minute)) || !token.Expiry.After(proof.FreshUntil) {
		t.Fatal("freshness used receipt expires_in")
	}
	if proof.Subject != "subject-123" || proof.ProjectID != testProject {
		t.Fatal("identity")
	}
}

func TestVerifiedClaimNegatives(t *testing.T) {
	p := newAuthority(t)
	client := p.client(t, func() time.Time { return p.now })
	cases := map[string]func(map[string]any){"issuer": func(m map[string]any) { m["iss"] = "https://other.invalid" }, "audience": func(m map[string]any) { m["aud"] = "other" }, "project": func(m map[string]any) { m["project_id"] = "wrong" }, "purpose": func(m map[string]any) { m["token_use"] = "access" }, "nonce": func(m map[string]any) { m["nonce"] = "wrong" }, "future_iat": func(m map[string]any) { m["iat"] = p.now.Add(31 * time.Second).Unix() }, "expired": func(m map[string]any) { m["exp"] = p.now.Unix() }, "metadata_shape": func(m map[string]any) { m["authhub_profile"] = map[string]any{"name": 3} }, "missing_iat": func(m map[string]any) { delete(m, "iat") }}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			p.claims = mutation
			tok := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
			if _, e := client.verify(context.Background(), tok, "nonce", nil); e == nil {
				t.Fatal("accepted invalid proof")
			}
		})
	}
	p.claims = nil
	raw := p.token("nonce")
	parts := strings.Split(raw, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	if _, e := client.verify(context.Background(), (&oauth2.Token{}).WithExtra(map[string]any{"id_token": strings.Join(parts, ".")}), "nonce", nil); e == nil {
		t.Fatal("bad signature accepted")
	}
}

func TestRefreshIdentityAndNoSlidingDeadline(t *testing.T) {
	p := newAuthority(t)
	now := p.now
	client := p.client(t, func() time.Time { return now })
	client.config.Freshness = 20 * time.Second
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	first, e := client.verify(context.Background(), token, "nonce", nil)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(10 * time.Second)
	next, e := client.verify(context.Background(), token, "", &first)
	if e != nil || !next.FreshUntil.Equal(first.FreshUntil) {
		t.Fatal("verification slid freshness", e)
	}
	now = first.FreshUntil
	if _, e = client.verify(context.Background(), token, "", &first); e == nil {
		t.Fatal("accepted deadline equality")
	}
	now = p.now
	for _, key := range []string{"sub", "project_id", "sid", "auth_time"} {
		t.Run(key, func(t *testing.T) {
			p.claims = func(m map[string]any) {
				if key == "auth_time" {
					m[key] = p.now.Add(-30 * time.Second).Unix()
				} else {
					m[key] = "other"
				}
			}
			if _, e := client.verify(context.Background(), (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("")}), "", &first); e == nil {
				t.Fatal("refresh identity changed")
			}
		})
	}
}

func TestLostExchangeUsesExactlyOneAttempt(t *testing.T) {
	p := newAuthority(t)
	p.mode = "lost"
	c := p.client(t, func() time.Time { return p.now })
	_, e := c.oauth.Exchange(c.context(context.Background()), "code", oauth2.VerifierOption(oauth2.GenerateVerifier()))
	if e == nil || p.calls.Load() != 1 {
		t.Fatalf("error=%v attempts=%d", e, p.calls.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestTransportBoundsAndNoRedirect(t *testing.T) {
	t.Run("body", func(t *testing.T) {
		transport := boundedTransport{origin: "https://issuer.test", base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponse+1)))}, nil
		})}
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://issuer.test/keys", nil)
		res, e := transport.RoundTrip(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		if _, e = io.ReadAll(res.Body); e == nil {
			t.Fatal("unbounded response")
		}
	})
	t.Run("origin", func(t *testing.T) {
		transport := boundedTransport{origin: "https://issuer.test", base: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("foreign origin requested")
			return nil, errors.New("bad")
		})}
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://other.test/keys", nil)
		res, e := transport.RoundTrip(r)
		if res != nil {
			_ = res.Body.Close()
		}
		if e == nil {
			t.Fatal("accepted foreign origin")
		}
	})
	t.Run("redirect", func(t *testing.T) {
		var reached atomic.Bool
		target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached.Store(true) }))
		defer target.Close()
		issuer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
		defer issuer.Close()
		cfg := config{Issuer: issuer.URL, ClientID: "client", ProjectID: testProject, Origin: "https://app.test", Callback: "https://app.test/callback"}
		if _, e := newOIDC(context.Background(), cfg, "secret", issuer.Client().Transport, time.Now); e == nil || reached.Load() {
			t.Fatal("followed discovery redirect")
		}
	})
}

func TestReturnPathAndProtectedStorage(t *testing.T) {
	for _, path := range []string{"https://evil.test", "//evil.test", "/%2f/evil.test", "/\\evil.test", "/callback", "/\r\nLocation: x"} {
		if safeReturn(path) != "/" {
			t.Fatal(path)
		}
	}
	a, e := newAEAD(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	encrypted, e := seal(a, "secret", "binding")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = unseal(a, encrypted, "other"); e == nil {
		t.Fatal("accepted wrong AEAD binding")
	}
	if strings.Contains(string(encrypted), "secret") {
		t.Fatal("stored plaintext")
	}
}

func TestSlowBodyRetainsConcurrencyBudget(t *testing.T) {
	budget := &requestBudget{slots: make(chan struct{}, 1)}
	tr := boundedTransport{origin: "https://issuer.test", budget: budget, base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Body: io.NopCloser(strings.NewReader("body"))}, nil
	})}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://issuer.test/keys", nil)
	one, e := tr.RoundTrip(req)
	if e != nil {
		t.Fatal(e)
	}
	res, e := tr.RoundTrip(req)
	if res != nil {
		_ = res.Body.Close()
	}
	if e == nil {
		t.Fatal("released concurrency slot before body completion")
	}
	if e = one.Body.Close(); e != nil {
		t.Fatal(e)
	}
	_ = one.Body.Close()
	next, e := tr.RoundTrip(req)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.ReadAll(next.Body)
	_ = next.Body.Close()
	if len(budget.slots) != 0 {
		t.Fatal("body slot leaked")
	}
}

func TestMaintenanceCandidateStrictParsing(t *testing.T) {
	valid := `{"version":1,"clientId":"client-123","secret":"secret"}`
	if s, e := parseClientSecret([]byte(valid), "client-123"); e != nil || s != "secret" {
		t.Fatal("valid candidate rejected")
	}
	for _, raw := range []string{`{"version":1,"clientId":"client-123","secret":"one","secret":"two"}`, `{"version":1,"clientId":"other","secret":"secret"}`, `{"version":1,"clientId":"client-123","secret":null}`, valid + ` {}`, strings.Replace(valid, `"version":1`, `"version":2`, 1), strings.Replace(valid, `"secret":"secret"`, `"secret":"secret","extra":true`, 1)} {
		if _, e := parseClientSecret([]byte(raw), "client-123"); e == nil {
			t.Fatal("accepted malformed candidate")
		}
	}
}

func TestFutureIssuedProofCannotSlideOnReverification(t *testing.T) {
	p := newAuthority(t)
	now := p.now
	client := p.client(t, func() time.Time { return now })
	p.claims = func(m map[string]any) {
		m["iat"] = p.now.Add(20 * time.Second).Unix()
		m["exp"] = p.now.Add(6 * time.Minute).Unix()
	}
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("")})
	first, e := client.verify(context.Background(), token, "", nil)
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(10 * time.Second)
	again, e := client.verify(context.Background(), token, "", &first)
	if e != nil || !again.FreshUntil.Equal(first.FreshUntil) {
		t.Fatal("future iat slid original receipt clamp", e)
	}
}

func TestUntrustedTLSIsRejected(t *testing.T) {
	p := newAuthority(t)
	cfg := config{Issuer: p.server.URL, ClientID: "client", ProjectID: testProject, Origin: "https://app.test", Callback: "https://app.test/callback"}
	if _, e := newOIDC(context.Background(), cfg, "secret", nil, time.Now); e == nil {
		t.Fatal("untrusted TLS was accepted")
	}
}
