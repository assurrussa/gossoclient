package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

const (
	currentSessionTestLegacyScope = "binding-revoked"
	currentSessionTestLogoutPath  = "/logout"
)

func TestCurrentSessionLogoutRequiresExplicitReceiptAndLeavesCleanupOrdinary(t *testing.T) {
	for _, scope := range []string{"", currentSessionTestLegacyScope, "current-session"} {
		t.Run(scope, func(t *testing.T) {
			var calls []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls = append(calls, r.URL.Path)
				if r.Method != http.MethodPost || r.ParseForm() != nil || r.Form.Get("token") != "synthetic-refresh" {
					t.Error("invalid back-channel request")
				}
				if _, _, ok := r.BasicAuth(); !ok {
					t.Error("missing client authentication")
				}
				if r.URL.Path == currentSessionTestLogoutPath {
					w.Header().Set("X-AuthHub-Logout-Scope", scope)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			client := &oidcClient{config: config{
				RevocationEndpoint: server.URL + "/revoke", CurrentSessionLogoutEndpoint: server.URL + currentSessionTestLogoutPath,
			}, oauth: oauth2.Config{ClientID: "synthetic-client", ClientSecret: "synthetic-secret"}, http: server.Client()}
			err := client.revokeForLogout(context.Background(), "synthetic-refresh")
			if (err == nil) != (scope == "current-session") {
				t.Fatalf("scope %q: %v", scope, err)
			}
			if err = client.revoke(context.Background(), "synthetic-refresh"); err != nil {
				t.Fatal(err)
			}
			if len(calls) != 2 || calls[0] != currentSessionTestLogoutPath || calls[1] != "/revoke" {
				t.Fatalf("wrong endpoints: %v", calls)
			}
		})
	}
}
