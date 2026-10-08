//nolint:goconst,lll // Explicit boundary fixtures retain exact wire values beside assertions.
package ingress_test

import (
	"net/http/httptest"
	"testing"

	"github.com/assurrussa/gossoclient/ingress"
)

func TestBoundary(t *testing.T) {
	policy, err := ingress.New(t.Context(), ingress.Config{Bind: "127.0.0.1:9080", Host: "app.test", ProxyCIDRs: "127.0.0.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		peer, host string
		allowed    bool
	}{
		{"127.0.0.1:12345", "app.test", true},
		{"127.0.0.2:12345", "app.test", false},
		{"192.0.2.1:12345", "app.test", false},
		{"127.0.0.1:12345", "forged.test", false},
		{"not-a-peer", "app.test", false},
	} {
		r := httptest.NewRequestWithContext(t.Context(), "GET", "http://"+tc.host+"/", nil)
		r.RemoteAddr = tc.peer
		r.Header.Set("X-Forwarded-For", "127.0.0.1")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", "app.test")
		r.Header.Set("Forwarded", "for=127.0.0.1;proto=https;host=app.test")
		if policy.Allows(r) != tc.allowed {
			t.Fatalf("unexpected peer decision for %s", tc.peer)
		}
	}
}

func TestConfigurationFailsClosed(t *testing.T) {
	for _, bind := range []string{":9080", "0.0.0.0:9080", "[::]:9080", "192.0.2.1:9080", "10.255.255.254:9080", "127.0.0.1:0", "127.0.0.1:09080"} {
		if _, err := ingress.New(t.Context(), ingress.Config{Bind: bind, Host: "app.test", ProxyCIDRs: "127.0.0.1/32"}); err == nil {
			t.Fatalf("accepted bind %s", bind)
		}
	}
	for _, peers := range []string{"", "0.0.0.0/0", "::/0", "192.0.2.0/24", "10.0.0.1/24", "127.0.0.1", "10.0.0.0/7", "::ffff:127.0.0.1/128"} {
		if _, err := ingress.New(t.Context(), ingress.Config{Bind: "127.0.0.1:9080", Host: "app.test", ProxyCIDRs: peers}); err == nil {
			t.Fatalf("accepted peers %s", peers)
		}
	}
	var empty *ingress.Policy
	if empty.Allows(httptest.NewRequestWithContext(t.Context(), "GET", "http://app.test/", nil)) {
		t.Fatal("nil policy allowed request")
	}
}
