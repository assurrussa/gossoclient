//nolint:goconst,lll // Wire fixtures keep exact host, origin and cookie assertions readable.
package browser

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/assurrussa/gossoclient/ingress"
)

func TestHTTPSReverseProxyIsExplicitAndMutuallyExclusive(t *testing.T) {
	base, _, err := buildOptions(validTestOptions())
	if err != nil || base.HTTPSReverseProxy {
		t.Fatal("direct TLS default changed", err)
	}
	configured, _, err := buildOptions(append(validTestOptions(), WithHTTPSReverseProxy()))
	if err != nil || !configured.HTTPSReverseProxy || configured.Ingress != nil {
		t.Fatal("explicit reverse proxy option failed", err)
	}
	policy, err := ingress.New(t.Context(), ingress.Config{Bind: "127.0.0.1:9080", Host: "app.test", ProxyCIDRs: "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, options := range [][]Option{
		{WithHTTPSReverseProxy(), WithHTTPSReverseProxy()},
		{WithHTTPSReverseProxy(), WithIngress(policy)},
		{WithIngress(policy), WithHTTPSReverseProxy()},
		{WithIngress(nil), WithHTTPSReverseProxy()},
		{WithHTTPSReverseProxy(), WithIngress(nil)},
	} {
		if _, _, err = buildOptions(append(validTestOptions(), options...)); err == nil {
			t.Fatal("ambiguous ingress configuration accepted")
		}
	}
}

func TestHTTPSReverseProxyRetainsRequestBoundary(t *testing.T) {
	a := &app{config: config{Origin: "https://app.test", Issuer: "https://issuer.test"}, slots: make(chan struct{}, 1)}
	request := func() *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.test/missing", nil)
		r.Header.Set("Forwarded", "proto=https;host=app.test")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "app.test")
		r.Header.Set("X-AuthHub-Subject", "forged")
		return r
	}
	r := request()
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatal("forwarding headers enabled reverse proxy mode")
	}
	a.config.HTTPSReverseProxy = true
	r = request()
	// Even contradictory forwarding metadata has no authority in this mode.
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("X-Forwarded-Host", "evil.test")
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound || r.TLS != nil {
		t.Fatal("explicit host adapter failed or fabricated TLS")
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Host = "evil.test" },
		func(r *http.Request) { r.Host = "app.test:443" },
		func(r *http.Request) { r.RequestURI = strings.Repeat("x", 8193) },
	} {
		r = request()
		mutate(r)
		w = httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("host or request-size check weakened")
		}
		if _, err := (&Client{app: a}).Verify(r); !errors.Is(err, ErrDenied) {
			t.Fatal("Verify accepted invalid ingress", err)
		}
	}
	r = request()
	if _, err := (&Client{app: a}).Verify(r); !errors.Is(err, ErrDenied) {
		t.Fatal("identity header granted an anonymous proof", err)
	}
	for _, origin := range []string{"", "null", "https://evil.test", "http://app.test"} {
		r = request()
		r.Method, r.URL.Path = http.MethodPost, "/login"
		r.Header.Set("Origin", origin)
		w = httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("unsafe origin reached session storage")
		}
	}
}

func TestPostgresHTTPSReverseProxyRetainsSecureCookiesAndCSRF(t *testing.T) {
	a, authority, _ := testApp(t)
	a.config.HTTPSReverseProxy = true
	proxyRequest := func(method, path string, cookie *http.Cookie, form url.Values) *httptest.ResponseRecorder {
		body := ""
		if form != nil {
			body = form.Encode()
		}
		r := httptest.NewRequestWithContext(t.Context(), method, strings.Replace(a.config.Origin, "https://", "http://", 1)+path, strings.NewReader(body))
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if form != nil {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", a.config.Origin)
		}
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if r.TLS != nil {
			t.Fatal("proxy adapter changed request TLS")
		}
		return w
	}
	home := proxyRequest(http.MethodGet, "/", nil, nil)
	cookies := home.Result().Cookies()
	if home.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatal("proxy home failed")
	}
	cookie := cookies[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("proxy mode weakened host cookie")
	}
	current, err := a.store.load(t.Context(), digest(cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if response := proxyRequest(http.MethodPost, "/login", cookie, url.Values{"csrf": {"forged"}}); response.Code != http.StatusBadRequest {
		t.Fatal("proxy mode bypassed CSRF")
	}
	response := proxyRequest(http.MethodPost, "/login", cookie, url.Values{"csrf": {current.CSRF}})
	if response.Code != http.StatusSeeOther {
		t.Fatal("proxy login failed")
	}
	target, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	authority.nonce, authority.challenge = target.Query().Get("nonce"), target.Query().Get("code_challenge")
	authority.mu.Unlock()
	response = proxyRequest(http.MethodGet, "/callback?"+url.Values{"state": {target.Query().Get("state")}, "code": {"one-code"}}.Encode(), cookie, nil)
	if response.Code != http.StatusSeeOther {
		t.Fatal("proxy callback failed")
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, strings.Replace(a.config.Origin, "https://", "http://", 1)+"/protected", nil)
	r.AddCookie(cookie)
	if _, err = (&Client{app: a}).Verify(r); err != nil {
		t.Fatal("proxy proof failed", err)
	}
	response = proxyRequest(http.MethodPost, "/logout", cookie, url.Values{"csrf": {current.CSRF}})
	if response.Code != http.StatusSeeOther || response.Header().Get("X-AuthHub-Logout-Scope") != "binding-revoked" {
		t.Fatal("proxy logout failed")
	}
}
