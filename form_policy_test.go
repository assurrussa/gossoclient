//nolint:goconst // Exact browser-policy and origin cases stay beside their assertions.
package browser

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestFormOriginRequiresOneExactValue(t *testing.T) {
	a := &app{config: config{Origin: "https://app.example.test"}}
	for _, tc := range []struct {
		name    string
		origins []string
	}{
		{"missing", nil},
		{"null", []string{"null"}},
		{"foreign", []string{"https://evil.example"}},
		{"duplicate", []string{a.config.Origin, a.config.Origin}},
		{"expected-first", []string{a.config.Origin, "https://evil.example"}},
		{"foreign-first", []string{"https://evil.example", a.config.Origin}},
		{"joined", []string{a.config.Origin + ", " + a.config.Origin}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, a.config.Origin+"/login",
				strings.NewReader("csrf=synthetic"))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header["Origin"] = tc.origins
			_, _, e := a.formSession(httptest.NewRecorder(), r)
			if e == nil || e.Error() != "invalid origin" {
				t.Fatalf("origin was not rejected before session lookup: %v", e)
			}
		})
	}
}

func TestPostgresFormDocumentsKeepPolicyAndCSRF(t *testing.T) {
	a, p, _ := testApp(t)
	home := request(a, http.MethodGet, "/", nil, nil)
	if home.Code != http.StatusOK || home.Header().Get("Referrer-Policy") != "strict-origin" ||
		!strings.Contains(home.Body.String(), `method="post" action="/login"`) ||
		!strings.Contains(home.Body.String(), `method="post" action="/logout"`) {
		t.Fatal("signed-out form document lost the browser policy or native forms")
	}
	cookie, v := signedIn(t, a, p)
	home = request(a, http.MethodGet, "/", cookie, nil)
	if home.Code != http.StatusOK || home.Header().Get("Referrer-Policy") != "strict-origin" ||
		!strings.Contains(home.Body.String(), `method="post" action="/logout"`) {
		t.Fatal("signed-in form document lost the browser policy or native logout form")
	}
	for _, path := range []string{"/login", "/logout"} {
		for _, csrf := range []string{"", "wrong"} {
			if w := request(a, http.MethodPost, path, cookie, url.Values{"csrf": {csrf}}); w.Code != http.StatusBadRequest {
				t.Fatalf("%s accepted invalid CSRF with the exact origin", path)
			}
		}
		for _, origins := range [][]string{
			nil,
			{"null"},
			{"https://evil.example"},
			{a.config.Origin, a.config.Origin},
			{a.config.Origin, "https://evil.example"},
			{"https://evil.example", a.config.Origin},
		} {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, a.config.Origin+path,
				strings.NewReader(url.Values{"csrf": {v.CSRF}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Sec-Fetch-Site", "same-origin")
			r.Header["Origin"] = origins
			r.AddCookie(cookie)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s accepted invalid Origin with valid CSRF: %v", path, origins)
			}
		}
	}
	current, e := a.store.load(t.Context(), v.ID)
	if e != nil || current.Status != sessionActive || current.Generation != v.Generation {
		t.Fatal("rejected form changed the session generation", e)
	}
	if w := request(a, http.MethodPost, "/logout", cookie, url.Values{"csrf": {v.CSRF}}); w.Code != http.StatusSeeOther {
		t.Fatalf("exact-origin CSRF logout failed: %d", w.Code)
	}
}
