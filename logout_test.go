//nolint:goconst,lll // Complete synthetic wire assertions stay together.
package browser

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func logoutSnapshot(t *testing.T, a *app, cookie *http.Cookie, csrf string) (*http.Request, session) {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, a.config.Origin+"/logout",
		strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", a.config.Origin)
	v, _, e := a.formSession(httptest.NewRecorder(), r)
	if e != nil {
		t.Fatal(e)
	}
	return r, v
}

func TestHTTPLogoutOriginalLineage(t *testing.T) {
	for _, successor := range []string{"refresh", "callback", "pending-callback"} {
		t.Run(successor, func(t *testing.T) {
			a, authority, _ := testApp(t)
			cookie, v := signedIn(t, a, authority)
			var state string
			if successor == "pending-callback" {
				state = restartBrowserLogin(t, a, authority, cookie, v.CSRF)
			}
			// Deterministic cut at the production seam: the form has authenticated
			// its snapshot, but its terminal write has not started yet.
			r, snapshot := logoutSnapshot(t, a, cookie, v.CSRF)
			if successor == "refresh" {
				v = dueSession(t, a, v)
				if _, e := a.authorize(t.Context(), v); e != nil {
					t.Fatal(e)
				}
				// Original freshness expiry does not cancel intentional logout.
				a.now = func() time.Time { return snapshot.FreshUntil.Add(time.Second) }
			} else {
				if successor == "callback" {
					state = restartBrowserLogin(t, a, authority, cookie, v.CSRF)
				}
				if w := callback(a, cookie, state); w.Code != http.StatusSeeOther {
					t.Fatal("replacement callback failed", w.Code)
				}
			}
			w := httptest.NewRecorder()
			a.logoutSession(w, r, snapshot)
			row, e := a.store.load(t.Context(), v.ID)
			if e != nil {
				t.Fatal(e)
			}
			assertLogoutSuccessor(t, a, w, row, successor)
		})
	}
}

func TestHTTPLogoutUnconfirmedRevocation(t *testing.T) {
	for _, failure := range []string{"remote", "remote-503", "decrypt"} {
		t.Run(failure, func(t *testing.T) {
			a, authority, _ := testApp(t)
			cookie, v := signedIn(t, a, authority)
			transport := &revokeTransport{next: a.oidc.http.Transport, store: a.store}
			if failure == "remote-503" {
				transport.status = http.StatusServiceUnavailable
			}
			a.oidc.http.Transport = transport
			if failure == "decrypt" {
				if _, e := a.store.db.ExecContext(t.Context(), `UPDATE sso_example_sessions SET refresh_cipher=$1 WHERE cookie_digest=$2`, []byte("invalid-cipher"), v.ID); e != nil {
					t.Fatal(e)
				}
			}
			w := request(a, "POST", "/logout", cookie, url.Values{"csrf": {v.CSRF}})
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" ||
				w.Header().Get("X-AuthHub-Logout-Scope") != "local-only" || !strings.Contains(w.Body.String(), "central revocation unconfirmed") {
				t.Fatal("unconfirmed revoke acknowledged as success", w.Code)
			}
			assertLogoutCookie(t, w)
			row, e := a.store.load(t.Context(), v.ID)
			if e != nil || row.Status != "ended" || row.Proof != nil || row.Cipher != nil {
				t.Fatal("local logout not terminal", e)
			}
			wantCalls := int64(0)
			if failure != "decrypt" {
				wantCalls = 1
				if !transport.confirmed.Load() {
					t.Fatal("remote request preceded local terminal commit")
				}
			}
			if transport.calls.Load() != wantCalls {
				t.Fatal("unexpected revoke attempt or retry")
			}
		})
	}
}

func TestHTTPLogoutPendingIsExplicitlyLocal(t *testing.T) {
	a, authority, _ := testApp(t)
	cookie, _ := startLogin(t, a, authority)
	v, e := a.store.load(t.Context(), digest(cookie.Value))
	if e != nil {
		t.Fatal(e)
	}
	w := request(a, "POST", "/logout", cookie, url.Values{"csrf": {v.CSRF}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/?logout=local-only" ||
		w.Header().Get("X-AuthHub-Logout-Scope") != "local-only" {
		t.Fatal("pending logout claimed remote revocation", w.Code)
	}
	assertLogoutCookie(t, w)
}

func assertLogoutCookie(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != cookieName || cookies[0].MaxAge != -1 ||
		!cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatal("missing secure cookie deletion")
	}
}

func assertLogoutSuccessor(t *testing.T, a *app, w *httptest.ResponseRecorder, row session, successor string) {
	t.Helper()
	if successor == "refresh" {
		if w.Code != http.StatusSeeOther || row.Status != "ended" || row.Proof != nil || row.Cipher != nil ||
			w.Header().Get("X-AuthHub-Logout-Scope") != "binding-revoked" {
			t.Fatal("same-lineage descendant was not ended", w.Code)
		}
		assertLogoutCookie(t, w)
		return
	}
	if w.Code != http.StatusConflict || len(w.Result().Cookies()) != 0 || row.Status != sessionActive {
		t.Fatal("stale logout ended or cleared new login", w.Code)
	}
	if _, e := (&Client{app: a}).Check(t.Context(), a.proof(row).Binding()); e != nil {
		t.Fatal("new callback admission invalid", e)
	}
}
