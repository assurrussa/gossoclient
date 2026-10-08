//nolint:goconst,lll // Explicit boundary fixtures retain exact wire values beside assertions.
package browser

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/assurrussa/gossoclient/ingress"
)

func TestPrivateIngressRejectsDirectAndForgedRequestsBeforeSession(t *testing.T) {
	policy, err := ingress.New(t.Context(), ingress.Config{Bind: "127.0.0.1:9080", Host: "app.test", ProxyCIDRs: "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	a := &app{config: config{Origin: "https://app.test", Issuer: "https://login.test", Ingress: policy}, slots: make(chan struct{}, 1)}
	for _, peer := range []string{"127.0.0.2:2345", "192.0.2.2:2345"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://app.test/", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "app.test")
		r.Header.Set("X-AuthHub-Subject", "forged")
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r) // nil session store proves rejection precedes state access.
		if w.Code != http.StatusBadRequest || len(w.Result().Cookies()) != 0 {
			t.Fatal("untrusted backend request reached session")
		}
	}
}

func TestTransportConfiguration(t *testing.T) {
	c := config{Issuer: "https://login.test", Origin: "https://app.test", Callback: "https://app.test/callback", ClientID: "client", ProjectID: testProject, Transport: "private-http", ProxyCIDRs: "127.0.0.1/32"}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.CertFile = "stale-cert"
	if c.validate() == nil {
		t.Fatal("mixed TLS/private configuration accepted")
	}
	c.CertFile = ""
	c.Transport = "tls"
	if c.validate() == nil {
		t.Fatal("private peers accepted in TLS mode")
	}
}
