//nolint:goconst,lll // Synthetic requests and failure cases are explicit.
package browser

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func hostLogoutRequest(t *testing.T, a *app, cookie *http.Cookie) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, a.config.Origin+"/native/logout", nil)
	r.Header.Set("Origin", a.config.Origin)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func TestHostLogoutRejectsInvalidRequestBeforeStorage(t *testing.T) {
	a := &app{config: config{Origin: publicTestOrigin}, slots: make(chan struct{}, 1)}
	c := &Client{app: a}
	for _, kind := range []string{"get", plainHTTPCase, "wrong-host", "missing-origin", "foreign-origin", "duplicate-origin", "foreign-fetch", duplicateCookieCase, "short-cookie", "malformed-cookie", "malformed-duplicate"} {
		t.Run(kind, func(t *testing.T) {
			r := hostLogoutRequest(t, a, &http.Cookie{
				Name: cookieName, Value: strings.Repeat("a", 43),
				Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
			switch kind {
			case "get":
				r.Method = http.MethodGet
			case plainHTTPCase:
				r.TLS = nil
				r.Header.Set("X-Forwarded-Proto", "https")
			case "wrong-host":
				r.Host = "evil.test"
			case "missing-origin":
				r.Header.Del("Origin")
			case "foreign-origin":
				r.Header.Set("Origin", "https://evil.test")
			case "duplicate-origin":
				r.Header.Add("Origin", a.config.Origin)
			case "foreign-fetch":
				r.Header.Set("Sec-Fetch-Site", "cross-site")
			case duplicateCookieCase:
				r.AddCookie(&http.Cookie{
					Name: cookieName, Value: strings.Repeat("b", 43),
					Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
				})
			case "malformed-cookie":
				r.Header.Set("Cookie", cookieName+`="unterminated`)
			case "malformed-duplicate":
				r.Header.Add("Cookie", cookieName+`="unterminated`)
			case "short-cookie":
				r.Header.Set("Cookie", cookieName+"=short")
			}
			w := httptest.NewRecorder()
			c.LogoutFromHost(w, r)
			if w.Code != http.StatusBadRequest || len(w.Result().Cookies()) != 0 ||
				w.Header().Get("X-AuthHub-Logout-Scope") != "unconfirmed" {
				t.Fatal("invalid host logout accepted or cleared cookie", w.Code)
			}
		})
	}
}

func TestHostLogoutWithoutCookieIsLocalOnly(t *testing.T) {
	a := &app{config: config{Origin: publicTestOrigin}, slots: make(chan struct{}, 1)}
	w := httptest.NewRecorder()
	(&Client{app: a}).LogoutFromHost(w, hostLogoutRequest(t, a, nil))
	if w.Code != http.StatusSeeOther || w.Header().Get("X-AuthHub-Logout-Scope") != "local-only" ||
		len(w.Result().Cookies()) != 0 {
		t.Fatal("missing RP cookie was not a local-only no-op")
	}
}

func TestHostLogoutNeverRefreshesExpiredProof(t *testing.T) {
	a, authority, _ := testApp(t)
	cookie, v := signedIn(t, a, authority)
	a.now = func() time.Time { return v.FreshUntil.Add(time.Second) }
	calls := authority.calls.Load()
	w := httptest.NewRecorder()
	(&Client{app: a}).LogoutFromHost(w, hostLogoutRequest(t, a, cookie))
	if w.Code != http.StatusSeeOther || w.Header().Get("X-AuthHub-Logout-Scope") != "binding-revoked" ||
		authority.calls.Load() != calls {
		t.Fatal("host logout refreshed or failed", w.Code)
	}
	assertLogoutCookie(t, w)
	row, err := a.store.load(t.Context(), v.ID)
	if err != nil || row.Status != "ended" || row.Proof != nil || row.Cipher != nil {
		t.Fatal("host logout did not commit terminal state", err)
	}
}

func TestHostLogoutStorageFailurePreservesCookie(t *testing.T) {
	a, authority, _ := testApp(t)
	cookie, _ := signedIn(t, a, authority)
	if err := a.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	(&Client{app: a}).LogoutFromHost(w, hostLogoutRequest(t, a, cookie))
	if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 ||
		w.Header().Get("X-AuthHub-Logout-Scope") != "unconfirmed" {
		t.Fatal("storage failure acknowledged or cleared cookie")
	}
}

func TestHostLogoutPendingAndUnknownRowsAreLocalOnly(t *testing.T) {
	for _, kind := range []string{"pending", "unknown"} {
		t.Run(kind, func(t *testing.T) {
			a, authority, _ := testApp(t)
			cookie, _ := startLogin(t, a, authority)
			if kind == "unknown" {
				cookie.Value = strings.Repeat("x", 43)
			}
			w := httptest.NewRecorder()
			(&Client{app: a}).LogoutFromHost(w, hostLogoutRequest(t, a, cookie))
			if w.Code != http.StatusSeeOther || w.Header().Get("X-AuthHub-Logout-Scope") != "local-only" ||
				authority.calls.Load() != 0 {
				t.Fatal("local-only host logout claimed revocation")
			}
			if kind == "pending" {
				assertLogoutCookie(t, w)
			} else if len(w.Result().Cookies()) != 0 {
				t.Fatal("unknown session changed cookie")
			}
		})
	}
}

func TestHostLogoutRemoteFailureRemainsLocalOnly(t *testing.T) {
	a, authority, _ := testApp(t)
	cookie, _ := signedIn(t, a, authority)
	transport := &revokeTransport{next: a.oidc.http.Transport, store: a.store, status: http.StatusServiceUnavailable}
	a.oidc.http.Transport = transport
	w := httptest.NewRecorder()
	(&Client{app: a}).LogoutFromHost(w, hostLogoutRequest(t, a, cookie))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("X-AuthHub-Logout-Scope") != "local-only" ||
		transport.calls.Load() != 1 || !transport.confirmed.Load() {
		t.Fatal("remote failure lost local-first semantics", w.Code)
	}
	assertLogoutCookie(t, w)
}
