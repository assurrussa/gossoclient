package browser

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

const (
	testCallbackPath = "/callback"
	testCallbackCode = "one-code"
	testCallbackLocation = "Location"
	testCallbackSuperseded = "superseded"
	testCallbackReturn = "/?notifyhub_sso=invitation&invitation=opaque-invitation"
)

type callbackDelivery struct {
	*httptest.ResponseRecorder
	committed bool
}

func (w *callbackDelivery) WriteHeader(status int) {
	w.committed = true
	w.ResponseRecorder.WriteHeader(status)
}

func (w *callbackDelivery) Write(body []byte) (int, error) {
	w.committed = true
	return w.ResponseRecorder.Write(body)
}

func callbackRequest(t *testing.T, a *app, cookie *http.Cookie, state string) *http.Request {
	query := url.Values{"state": {state}, "code": {testCallbackCode}}
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, a.config.Origin+testCallbackPath+"?"+query.Encode(), nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func beginCallbackLogin(t *testing.T, a *app, p *authority, cookie *http.Cookie) (*http.Cookie, string) {
	t.Helper()
	if cookie == nil {
		home := request(a, http.MethodGet, "/", nil, nil)
		if home.Code != http.StatusOK || len(home.Result().Cookies()) != 1 {
			t.Fatal("browser session unavailable")
		}
		cookie = home.Result().Cookies()[0]
	}
	row, err := a.store.load(t.Context(), digest(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	response := request(a, http.MethodPost, "/login", cookie,
		url.Values{"csrf": {row.CSRF}, "return": {testCallbackReturn}})
	if response.Code != http.StatusSeeOther {
		t.Fatal("begin failed", response.Code)
	}
	target, err := url.Parse(response.Header().Get(testCallbackLocation))
	if err != nil {
		t.Fatal(err)
	}
	q := target.Query()
	p.mu.Lock()
	p.nonce, p.challenge = q.Get("nonce"), q.Get("code_challenge")
	p.mu.Unlock()
	return cookie, q.Get("state")
}

func assertNoCallbackOutcome(t *testing.T, outcome CallbackOutcome, err error) {
	t.Helper()
	if err == nil || outcome.ReturnPath() != "" || outcome.Proof().SessionReference() != "" {
		t.Fatal("failed callback supplied authority", err)
	}
}

func TestCallbackResultCommittedImmutableAndOneUse(t *testing.T) {
	for _, backend := range []string{"postgres", conformanceSQLiteSingleBackend, "sqlite-pool"} {
		t.Run(backend, func(t *testing.T) {
			store, _ := testConformanceStore(t, backend)
			a, p := conformanceApp(t, store)
			client := &Client{app: a}
			cookie, state := beginCallbackLogin(t, a, p, nil)
			w := &callbackDelivery{ResponseRecorder: httptest.NewRecorder()}
			outcome, err := client.CallbackResult(w, callbackRequest(t, a, cookie, state))
			if err != nil || w.committed || w.Body.Len() != 0 || w.Header().Get(testCallbackLocation) != "" ||
				outcome.ReturnPath() != testCallbackReturn || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("callback committed HTTP success or lost state-bound return", err)
			}
			proof := outcome.Proof()
			if proof.Generation() <= 0 || proof.Binding().LoginGeneration != proof.Generation() {
				t.Fatal("callback lost exact committed login generation")
			}
			if _, err = client.Check(t.Context(), proof.Binding()); err != nil {
				t.Fatal("callback result was not durably installed", err)
			}
			identity := proof.Identity()
			identity.Subject = "edited"
			if outcome.Proof().Identity().Subject == identity.Subject {
				t.Fatal("callback outcome was mutable")
			}
			replay := httptest.NewRecorder()
			failed, replayErr := client.CallbackResult(replay, callbackRequest(t, a, cookie, state))
			assertNoCallbackOutcome(t, failed, replayErr)
			if replay.Code != http.StatusBadRequest || p.calls.Load() != 1 {
				t.Fatal("callback replay exchanged a second code")
			}
		})
	}
}

func TestCallbackResultCannotUseExistingCookieOrFailedLogin(t *testing.T) {
	store, _ := testConformanceStore(t, conformanceSQLiteSingleBackend)
	a, p := conformanceApp(t, store)
	client := &Client{app: a}
	cookie, original := signedIn(t, a, p)
	before := p.calls.Load()
	w := httptest.NewRecorder()
	outcome, err := client.CallbackResult(w, callbackRequest(t, a, cookie, "forged"))
	assertNoCallbackOutcome(t, outcome, err)
	if p.calls.Load() != before {
		t.Fatal("forged callback exchanged a code")
	}
	cookie, state := beginCallbackLogin(t, a, p, cookie)
	failed := callbackRequest(t, a, cookie, state)
	q := failed.URL.Query()
	q.Del("code")
	q.Set("error", "access_denied")
	failed.URL.RawQuery = q.Encode()
	outcome, err = client.CallbackResult(httptest.NewRecorder(), failed)
	assertNoCallbackOutcome(t, outcome, err)
	outcome, err = client.CallbackResult(httptest.NewRecorder(), callbackRequest(t, a, cookie, state))
	assertNoCallbackOutcome(t, outcome, err)
	if p.calls.Load() != before {
		t.Fatal("failed login returned a cached proof or exchanged again")
	}
	current, loadErr := a.store.load(t.Context(), original.ID)
	if loadErr != nil || current.Generation <= original.Generation {
		t.Fatal("new pending login did not retain normal generation fence", loadErr)
	}
}

type callbackStorageFailure struct {
	sessionStorage
	phase string
	installed bool
}

func (s *callbackStorageFailure) installLogin(ctx context.Context, l login, p identity, cipher []byte) error {
	if s.phase == "before-install" {
		return errors.New("fixture storage unavailable")
	}
	if err := s.sessionStorage.installLogin(ctx, l, p, cipher); err != nil {
		return err
	}
	s.installed = true
	if s.phase == "unknown-install" {
		return errors.New("fixture commit acknowledgement lost")
	}
	return nil
}

func (s *callbackStorageFailure) load(ctx context.Context, id string) (session, error) {
	if s.installed && s.phase == "reread" {
		return session{}, errors.New("fixture reread unavailable")
	}
	row, err := s.sessionStorage.load(ctx, id)
	if s.installed && s.phase == testCallbackSuperseded {
		row.Generation++
	}
	return row, err
}

func TestCallbackResultFailsClosedOnStorageAndGenerationFailure(t *testing.T) {
	for _, phase := range []string{"before-install", "unknown-install", "reread", testCallbackSuperseded} {
		t.Run(phase, func(t *testing.T) {
			store, _ := testConformanceStore(t, conformanceSQLiteSingleBackend)
			a, p := conformanceApp(t, store)
			cookie, state := beginCallbackLogin(t, a, p, nil)
			a.store = &callbackStorageFailure{sessionStorage: a.store, phase: phase}
			outcome, err := (&Client{app: a}).CallbackResult(httptest.NewRecorder(), callbackRequest(t, a, cookie, state))
			assertNoCallbackOutcome(t, outcome, err)
			if phase != testCallbackSuperseded && !errors.Is(err, ErrUnavailable) {
				t.Fatal("storage failure was hidden as identity denial", err)
			}
			if p.calls.Load() != 1 {
				t.Fatal("storage failure retried code exchange")
			}
		})
	}
}

func TestLegacyCallbackStillRedirectsAndTypedRouteIsExact(t *testing.T) {
	store, _ := testConformanceStore(t, conformanceSQLiteSingleBackend)
	a, p := conformanceApp(t, store)
	cookie, state := beginCallbackLogin(t, a, p, nil)
	w := httptest.NewRecorder()
	(&Client{app: a}).Callback(w, callbackRequest(t, a, cookie, state))
	if w.Code != http.StatusSeeOther || w.Header().Get(testCallbackLocation) != testCallbackReturn {
		t.Fatal("legacy Callback response changed")
	}
	r := callbackRequest(t, a, cookie, state)
	r.URL.Path = "/protected"
	outcome, err := (&Client{app: a}).CallbackResult(httptest.NewRecorder(), r)
	assertNoCallbackOutcome(t, outcome, err)
}

func TestCallbackResultInvalidProofAndTransportReturnNoAuthority(t *testing.T) {
	for _, mode := range []string{"invalid-proof", "lost"} {
		t.Run(mode, func(t *testing.T) {
			store, _ := testConformanceStore(t, conformanceSQLiteSingleBackend)
			a, p := conformanceApp(t, store)
			cookie, state := beginCallbackLogin(t, a, p, nil)
			if mode == "invalid-proof" {
				p.claims = func(claims map[string]any) { claims["nonce"] = "wrong" }
			} else {
				p.mode = mode
			}
			w := httptest.NewRecorder()
			outcome, err := (&Client{app: a}).CallbackResult(w, callbackRequest(t, a, cookie, state))
			assertNoCallbackOutcome(t, outcome, err)
			if mode == "lost" && !errors.Is(err, ErrUnavailable) {
				t.Fatal("transport error became a completed login or identity denial", err)
			}
			if p.calls.Load() != 1 || w.Code != http.StatusUnauthorized {
				t.Fatal("callback failure retried exchange or changed legacy HTTP response")
			}
		})
	}
}
