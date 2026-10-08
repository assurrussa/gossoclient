//nolint:goconst,lll // Explicit wire literals and fixture cases stay readable at each assertion.
package browser

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func testStore(t *testing.T) (*store, func() *store) {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_DATABASE")
	if dsn == "" {
		t.Skip("SSO_TEST_DATABASE required for durable PostgreSQL tests")
	}
	cfg, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal("invalid test database configuration")
	}
	base := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = base.Close() })
	random, e := randomSecret()
	if e != nil {
		t.Fatal(e)
	}
	name := "sso_test_" + hex.EncodeToString([]byte(random)[:12])
	if _, e = base.ExecContext(context.Background(), `CREATE SCHEMA `+name); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = base.ExecContext(context.Background(), `DROP SCHEMA `+name+` CASCADE`) })
	open := func() *store {
		c := cfg.Copy()
		c.RuntimeParams["search_path"] = name
		db := stdlib.OpenDB(*c)
		db.SetMaxOpenConns(8)
		t.Cleanup(func() { _ = db.Close() })
		return &store{db: db}
	}
	s := open()
	if _, e = s.db.ExecContext(context.Background(), schema); e != nil {
		t.Fatal(e)
	}
	if e = s.ready(context.Background()); e != nil {
		t.Fatal(e)
	}
	return s, open
}

func testApp(t *testing.T) (*app, *authority, func() *store) {
	t.Helper()
	s, reopen := testStore(t)
	p := newAuthority(t)
	client := p.client(t, time.Now)
	aead, e := newAEAD(make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	return &app{config: client.config, oidc: client, store: s, aead: aead, now: time.Now, slots: make(chan struct{}, 32), render: testRender}, p, reopen
}

func request(a *app, method, path string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	var body string
	if form != nil {
		body = form.Encode()
	}
	r := httptest.NewRequestWithContext(context.Background(), method, a.config.Origin+path, strings.NewReader(body))
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", a.config.Origin)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func startLogin(t *testing.T, a *app, p *authority) (*http.Cookie, string) {
	t.Helper()
	home := request(a, "GET", "/", nil, nil)
	if home.Code != http.StatusOK {
		t.Fatalf("home: %d", home.Code)
	}
	cookies := home.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("cookie missing")
	}
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" || cookie.Path != "/" {
		t.Fatal("unsafe cookie")
	}
	v, e := a.store.load(context.Background(), digest(cookie.Value))
	if e != nil {
		t.Fatal(e)
	}
	response := request(a, "POST", "/login", cookie, url.Values{"csrf": {v.CSRF}})
	if response.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", response.Code)
	}
	target, e := url.Parse(response.Header().Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	q := target.Query()
	p.mu.Lock()
	p.nonce = q.Get("nonce")
	p.challenge = q.Get("code_challenge")
	p.mu.Unlock()
	return cookie, q.Get("state")
}

func callback(a *app, cookie *http.Cookie, state string) *httptest.ResponseRecorder {
	return request(a, "GET", "/callback?"+url.Values{"state": {state}, "code": {"one-code"}}.Encode(), cookie, nil)
}

func signedIn(t *testing.T, a *app, p *authority) (*http.Cookie, session) {
	t.Helper()
	cookie, state := startLogin(t, a, p)
	w := callback(a, cookie, state)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("callback %d: %s", w.Code, w.Body.String())
	}
	v, e := a.store.load(context.Background(), digest(cookie.Value))
	if e != nil {
		t.Fatal(e)
	}
	return cookie, v
}

func dueSession(t *testing.T, a *app, v session) session {
	t.Helper()
	v.FreshUntil = time.Now().Add(15 * time.Second)
	v.Proof.FreshUntil = v.FreshUntil
	if _, e := a.store.db.ExecContext(context.Background(), `UPDATE sso_example_sessions SET fresh_until=$2 WHERE cookie_digest=$1`, v.ID, v.FreshUntil); e != nil {
		t.Fatal(e)
	}
	return v
}

func TestPostgresLoginRestartOneUseAndStateBinding(t *testing.T) {
	a, p, reopen := testApp(t)
	cookie, state := startLogin(t, a, p)
	if w := callback(a, cookie, strings.Repeat("x", 43)); w.Code != http.StatusBadRequest || p.calls.Load() != 0 {
		t.Fatal("bad state reached exchange")
	}
	if w := callback(a, &http.Cookie{Name: cookieName, Value: strings.Repeat("x", 43), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode}, state); w.Code != http.StatusBadRequest {
		t.Fatal("wrong browser accepted")
	}
	if e := a.store.db.Close(); e != nil {
		t.Fatal(e)
	}
	a.store = reopen()
	if w := callback(a, cookie, state); w.Code != http.StatusSeeOther {
		t.Fatalf("restart callback %d", w.Code)
	}
	if w := callback(a, cookie, state); w.Code != http.StatusBadRequest || p.calls.Load() != 1 {
		t.Fatal("code exchange repeated")
	}
	if w := request(a, "GET", "/", cookie, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "subject-123") {
		t.Fatal("session did not persist")
	}
}

func TestPostgresCallbackNoncePKCEAndPurpose(t *testing.T) {
	for _, which := range []string{"nonce", "pkce", "project", "purpose", "issuer"} {
		t.Run(which, func(t *testing.T) {
			a, p, _ := testApp(t)
			cookie, state := startLogin(t, a, p)
			switch which {
			case "pkce":
				l := login{State: digest(state), SessionID: digest(cookie.Value)}
				encrypted, e := seal(a.aead, "wrong", l.binding())
				if e != nil {
					t.Fatal(e)
				}
				if _, e = a.store.db.ExecContext(context.Background(), `UPDATE sso_example_logins SET verifier_cipher=$1`, encrypted); e != nil {
					t.Fatal(e)
				}
			default:
				p.claims = func(m map[string]any) {
					switch which {
					case "nonce":
						m["nonce"] = "wrong"
					case "project":
						m["project_id"] = "wrong"
					case "purpose":
						m["token_use"] = "access"
					case "issuer":
						m["iss"] = "https://wrong.test"
					}
				}
			}
			if w := callback(a, cookie, state); w.Code != http.StatusUnauthorized {
				t.Fatalf("accepted invalid %s: %d", which, w.Code)
			}
			v, e := a.store.load(context.Background(), digest(cookie.Value))
			if e != nil || v.Status == "active" {
				t.Fatal("installed invalid proof")
			}
		})
	}
}

func TestPostgresConcurrentRefreshOneOwnerAndRestartClaim(t *testing.T) {
	a, p, reopen := testApp(t)
	_, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	release := delayTokens(p)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, e := a.authorize(context.Background(), v); results <- e }()
	}
	awaitToken(t, p.arrived)
	// A second app instance has the same database and cannot retry the claimed secret.
	other := *a
	other.store = reopen()
	current, e := other.store.load(context.Background(), v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if current.RefreshState != "claimed" {
		t.Fatal("no durable owner")
	}
	if _, e = other.authorize(context.Background(), current); !errors.Is(e, errRefreshPending) {
		t.Fatal("unresolved owner authorized cached proof", e)
	}
	release()
	wg.Wait()
	close(results)
	for e := range results {
		if e != nil && !errors.Is(e, errRefreshPending) {
			t.Fatal(e)
		}
	}
	if p.calls.Load() != 2 {
		t.Fatalf("token attempts %d, want initial + one refresh", p.calls.Load())
	}
	final, e := a.store.load(context.Background(), v.ID)
	if e != nil || final.Generation != v.Generation+1 || final.RefreshState != "ready" {
		t.Fatal("rotation not committed", e)
	}
}

func TestPostgresLogoutFencesDelayedCallback(t *testing.T) {
	a, p, _ := testApp(t)
	cookie, state := startLogin(t, a, p)
	release := delayTokens(p)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- callback(a, cookie, state) }()
	awaitToken(t, p.arrived)
	v, e := a.store.load(context.Background(), digest(cookie.Value))
	if e != nil {
		t.Fatal(e)
	}
	if w := request(a, "POST", "/logout", cookie, url.Values{"csrf": {v.CSRF}}); w.Code != http.StatusSeeOther {
		t.Fatal("logout failed")
	}
	release()
	if w := <-done; w.Code != http.StatusUnauthorized {
		t.Fatalf("late callback %d", w.Code)
	}
	v, e = a.store.load(context.Background(), v.ID)
	if e != nil || v.Status != "ended" || v.Proof != nil {
		t.Fatal("callback resurrected session")
	}
}

func TestPostgresLogoutFencesDelayedRefresh(t *testing.T) {
	a, p, _ := testApp(t)
	cookie, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	release := delayTokens(p)
	done := make(chan error, 1)
	go func() { _, e := a.authorize(context.Background(), v); done <- e }()
	awaitToken(t, p.arrived)
	if w := request(a, "POST", "/logout", cookie, url.Values{"csrf": {v.CSRF}}); w.Code != http.StatusSeeOther {
		t.Fatal("logout failed")
	}
	release()
	if e := <-done; e == nil {
		t.Fatal("late refresh authorized")
	}
	final, e := a.store.load(context.Background(), v.ID)
	if e != nil || final.Status != "ended" || final.Proof != nil {
		t.Fatal("refresh resurrected session")
	}
}

func TestPostgresLostRefreshNeverRetriesBeforeOrAfterDeadline(t *testing.T) {
	for _, mode := range []string{"lost", "outage"} {
		t.Run(mode, func(t *testing.T) {
			a, p, reopen := testApp(t)
			_, v := signedIn(t, a, p)
			v = dueSession(t, a, v)
			p.mode = mode
			current, e := a.authorize(context.Background(), v)
			if e != nil {
				t.Fatal("unexpired verified proof unavailable", e)
			}
			if current.RefreshState != "uncertain" || len(current.Cipher) != 0 {
				t.Fatal("uncertain secret retained as retryable")
			}
			a.store = reopen()
			for i := 0; i < 3; i++ {
				if _, e = a.authorize(context.Background(), current); e != nil {
					t.Fatal(e)
				}
			}
			a.now = func() time.Time { return v.FreshUntil }
			if _, e = a.authorize(context.Background(), current); e == nil {
				t.Fatal("outage slid deadline")
			}
			if p.calls.Load() != 2 {
				t.Fatalf("old secret retried: %d requests", p.calls.Load())
			}
		})
	}
}

func TestPostgresDefiniteDenialEndsImmediately(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	p.mode = "deny"
	if _, e := a.authorize(context.Background(), v); e == nil {
		t.Fatal("denial allowed old proof")
	}
	v, e := a.store.load(context.Background(), v.ID)
	if e != nil || v.Status != "ended" {
		t.Fatal("denial not terminal")
	}
}

func TestPostgresCrashAfterRefreshClaimCannotRetry(t *testing.T) {
	a, p, reopen := testApp(t)
	_, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	won, e := a.store.claimRefresh(context.Background(), v, "dead-process")
	if e != nil || !won {
		t.Fatal(e)
	}
	_ = a.store.db.Close()
	a.store = reopen()
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.authorize(context.Background(), current); !errors.Is(e, errRefreshPending) {
		t.Fatal("abandoned owner was not fenced", e)
	}
	a.now = func() time.Time { return v.FreshUntil }
	if _, e = a.authorize(context.Background(), current); e == nil {
		t.Fatal("abandoned claim allowed expired proof")
	}
	if p.calls.Load() != 1 {
		t.Fatal("abandoned owner reused secret")
	}
}

func TestPostgresLogoutCSRFMissingAndForeignOrigin(t *testing.T) {
	a, p, _ := testApp(t)
	cookie, v := signedIn(t, a, p)
	if w := request(a, "POST", "/logout", cookie, url.Values{"csrf": {"wrong"}}); w.Code != http.StatusBadRequest {
		t.Fatal("bad CSRF accepted")
	}
	r := httptest.NewRequestWithContext(context.Background(), "POST", a.config.Origin+"/logout", strings.NewReader(url.Values{"csrf": {v.CSRF}}.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://evil.test")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatal("foreign origin accepted")
	}
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil || current.Status != "active" {
		t.Fatal("CSRF attempt changed session")
	}
}

func TestPostgresAbsoluteExpiryFencesDelayedRefresh(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	release := delayTokens(p)
	done := make(chan error, 1)
	var clockMu sync.Mutex
	clock := time.Now()
	a.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	go func() { _, e := a.authorize(context.Background(), v); done <- e }()
	awaitToken(t, p.arrived)
	clockMu.Lock()
	clock = v.AbsoluteUntil
	clockMu.Unlock()
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.authorize(context.Background(), current); e == nil {
		t.Fatal("expired proof accepted")
	}
	release()
	if e := <-done; e == nil {
		t.Fatal("late response revived absolute-expired session")
	}
	final, e := a.store.load(context.Background(), v.ID)
	if e != nil || final.Status != "ended" {
		t.Fatal("absolute expiry was not terminal")
	}
}

func TestPostgresIdleSessionCanObtainNewCentralProof(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	v.FreshUntil = time.Now().Add(-time.Second)
	v.Proof.FreshUntil = v.FreshUntil
	if _, e := a.store.db.ExecContext(context.Background(), `UPDATE sso_example_sessions SET fresh_until=$2 WHERE cookie_digest=$1`, v.ID, v.FreshUntil); e != nil {
		t.Fatal(e)
	}
	p.claims = func(m map[string]any) {
		m["iat"] = p.now.Add(time.Second).Unix()
		m["exp"] = p.now.Add(5 * time.Minute).Unix()
	}
	current, e := a.authorize(context.Background(), v)
	if e != nil || !current.FreshUntil.After(v.FreshUntil) || p.calls.Load() != 2 {
		t.Fatal("idle renewal did not obtain fresh central proof", e)
	}
}

func TestPostgresDelayedNewProofMayCrossOldDeadline(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	release := delayTokens(p)
	done := make(chan error, 1)
	var clockMu sync.Mutex
	clock := time.Now()
	a.now = func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	p.claims = func(m map[string]any) {
		m["iat"] = p.now.Add(20 * time.Second).Unix()
		m["exp"] = p.now.Add(5 * time.Minute).Unix()
	}
	go func() { _, e := a.authorize(context.Background(), v); done <- e }()
	awaitToken(t, p.arrived)
	clockMu.Lock()
	clock = v.FreshUntil
	clockMu.Unlock()
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.authorize(context.Background(), current); e == nil {
		t.Fatal("old expired proof authorized while refresh pending")
	}
	release()
	if e := <-done; e != nil {
		t.Fatal("new central proof was incorrectly rejected", e)
	}
	final, e := a.store.load(context.Background(), v.ID)
	if e != nil || final.Status != "active" || !final.FreshUntil.After(v.FreshUntil) {
		t.Fatal("fresh proof was not installed")
	}
}

func TestPostgresConfigurationChangeRejectsStoredProof(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	a.config.ClientID = "different-client"
	if _, e := a.authorize(context.Background(), v); e == nil {
		t.Fatal("old configured audience authorized")
	}
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil || current.Status != "ended" {
		t.Fatal("config mismatch was not fenced")
	}
}

// Bounded barriers let a regression fail rather than hanging fixture shutdown.
func delayTokens(p *authority) func() {
	p.arrived = make(chan struct{}, 1)
	p.release = make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(p.release) }) }
	p.t.Cleanup(release)
	return release
}

func awaitToken(t *testing.T, arrived <-chan struct{}) {
	t.Helper()
	select {
	case <-arrived:
	case <-time.After(10 * time.Second):
		t.Fatal("token request did not reach barrier")
	}
}

func TestPostgresDatabaseOutageFailsClosed(t *testing.T) {
	a, p, reopen := testApp(t)
	cookie, v := signedIn(t, a, p)
	if e := a.store.db.Close(); e != nil {
		t.Fatal(e)
	}
	w := request(a, http.MethodGet, "/", cookie, nil)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), v.Proof.Subject) {
		t.Fatal("database outage disclosed or authorized a cached identity")
	}
	if _, e := a.authorize(context.Background(), v); e == nil {
		t.Fatal("database outage authorized stale local memory")
	}
	if p.calls.Load() != 1 {
		t.Fatal("database outage triggered an unowned token request")
	}
	a.store = reopen()
	if w = request(a, http.MethodGet, "/", cookie, nil); w.Code != http.StatusOK {
		t.Fatal("restored durable proof unavailable")
	}
}
