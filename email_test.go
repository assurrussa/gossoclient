package browser

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testSignedEmail        = "verified@example.test"
	testEmailMissing = "missing"
	testEmailTrue = "true"
	testEmailAliasClaim = "email_alias"
	testEmailClaim         = "email"
	testEmailVerifiedClaim = "email_verified"
	testEmailNonce         = "nonce"
	testEmailIDToken       = "id_token"
	testEmailIdentifiers   = "authhub_identifiers"
)

func TestEmailScopeIsExplicitAndCompatible(t *testing.T) {
	base, _, err := buildOptions(validTestOptions())
	if err != nil || base.RequestEmail {
		t.Fatal("legacy scopes changed", err)
	}
	options := append(validTestOptions(), WithEmailScope())
	selected, _, err := buildOptions(options)
	if err != nil || !selected.RequestEmail {
		t.Fatal("email option not retained", err)
	}
	if _, _, err = buildOptions(append(options, WithEmailScope())); err == nil {
		t.Fatal("duplicate email option accepted")
	}
	if !(Config{RequestEmail: true}).internal().RequestEmail {
		t.Fatal("Config lost explicit email opt-in")
	}
	p := newAuthority(t)
	for _, enabled := range []bool{false, true} {
		c := p.client(t, func() time.Time { return p.now }).config
		c.RequestEmail = enabled
		client, err := newOIDC(t.Context(), c, "client-secret", p.server.Client().Transport,
			func() time.Time { return p.now })
		if err != nil {
			t.Fatal(err)
		}
		want := "openid profile"
		if enabled {
			want += " email"
		}
		if strings.Join(client.oauth.Scopes, " ") != want {
			t.Fatal("unexpected scope selection")
		}
	}
}

func TestSignedEmailClaimsAndNoFallback(t *testing.T) {
	p := newAuthority(t)
	client := p.client(t, func() time.Time { return p.now })
	client.config.RequestEmail = true
	cases := []struct {
		name     string
		claims   map[string]any
		email    string
		verified bool
		denied   bool
	}{
		{name: testEmailMissing},
		{
			name: "verified", claims: map[string]any{testEmailClaim: testSignedEmail, testEmailVerifiedClaim: true},
			email: testSignedEmail, verified: true,
		},
		{
			name: "false", claims: map[string]any{testEmailClaim: testSignedEmail, testEmailVerifiedClaim: false},
			email: testSignedEmail,
		},
		{name: "missing flag", claims: map[string]any{testEmailClaim: testSignedEmail}, email: testSignedEmail},
		{name: "false without email", claims: map[string]any{testEmailVerifiedClaim: false}},
		{name: "true without email", claims: map[string]any{testEmailVerifiedClaim: true}, denied: true},
		{name: "null email", claims: map[string]any{testEmailClaim: nil}, denied: true},
		{name: "null flag", claims: map[string]any{testEmailVerifiedClaim: nil}, denied: true},
		{name: "string flag", claims: map[string]any{testEmailVerifiedClaim: testEmailTrue}, denied: true},
		{name: "number flag", claims: map[string]any{testEmailVerifiedClaim: 1}, denied: true},
		{name: "number email", claims: map[string]any{testEmailClaim: 1}, denied: true},
		{name: "empty email", claims: map[string]any{testEmailClaim: ""}, denied: true},
		{name: "display name", claims: map[string]any{testEmailClaim: "Name <a@example.test>"}, denied: true},
		{name: "space", claims: map[string]any{testEmailClaim: " a@example.test"}, denied: true},
		{name: "newline", claims: map[string]any{testEmailClaim: "a@example.test\n"}, denied: true},
		{name: "long", claims: map[string]any{testEmailClaim: strings.Repeat("a", 255)}, denied: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p.claims = func(m map[string]any) {
				m[testEmailIdentifiers] = map[string]any{
					"version": 1, "login": "User", testEmailAliasClaim: "alias@example.test",
				}
				m["authhub_profile"] = map[string]string{
					testEmailClaim: "profile@example.test", testEmailVerifiedClaim: testEmailTrue,
				}
				for key, value := range tc.claims {
					m[key] = value
				}
			}
			token := (&oauth2.Token{}).WithExtra(map[string]any{testEmailIDToken: p.token(testEmailNonce)})
			got, err := client.verify(t.Context(), token, testEmailNonce, nil)
			if tc.denied {
				if err == nil {
					t.Fatal("malformed signed email accepted")
				}
				return
			}
			if err != nil || got.Email != tc.email || got.EmailVerified != tc.verified {
				t.Fatal("signed email snapshot mismatch", err)
			}
		})
	}
	// Opt-out preserves legacy handling, even for unsolicited malformed claims.
	client.config.RequestEmail = false
	p.claims = func(m map[string]any) { m[testEmailVerifiedClaim] = testEmailTrue }
	token := (&oauth2.Token{}).WithExtra(map[string]any{testEmailIDToken: p.token(testEmailNonce)})
	got, err := client.verify(t.Context(), token, testEmailNonce, nil)
	if err != nil || got.Email != "" || got.EmailVerified {
		t.Fatal("opt-out interpreted email claims", err)
	}
}

func TestEmailClaimsRequireValidSignatureAndRefreshSnapshot(t *testing.T) {
	p := newAuthority(t)
	client := p.client(t, func() time.Time { return p.now })
	client.config.RequestEmail = true
	p.claims = func(m map[string]any) {
		m[testEmailClaim], m[testEmailVerifiedClaim] = testSignedEmail, true
		m[testEmailIdentifiers] = map[string]any{"version": 1, "login": "Before"}
	}
	raw := p.token(testEmailNonce)
	token := (&oauth2.Token{}).WithExtra(map[string]any{testEmailIDToken: raw})
	first, err := client.verify(t.Context(), token, testEmailNonce, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), testSignedEmail, "forged@example.test", 1))
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	tampered := (&oauth2.Token{}).WithExtra(map[string]any{testEmailIDToken: strings.Join(parts, ".")})
	if _, err = client.verify(t.Context(), tampered, testEmailNonce, nil); err == nil {
		t.Fatal("unsigned email mutation accepted")
	}
	p.claims = func(m map[string]any) {
		m[testEmailClaim], m[testEmailVerifiedClaim] = "changed@example.test", true
		m[testEmailIdentifiers] = map[string]any{"version": 1, "login": "After"}
		m["preferred_username"] = "display-only"
	}
	token = (&oauth2.Token{}).WithExtra(map[string]any{testEmailIDToken: p.token("")})
	renamed, err := client.verify(t.Context(), token, "", &first)
	if err != nil || renamed.Subject != first.Subject || renamed.Issuer != first.Issuer ||
		renamed.ProjectID != first.ProjectID || renamed.ClientID != first.ClientID ||
		renamed.Email != "changed@example.test" || renamed.AuthHubIdentifiers == nil ||
		renamed.AuthHubIdentifiers.Login != "After" ||
		first.Email != testSignedEmail || first.AuthHubIdentifiers.Login != "Before" {
		t.Fatal("mutable login/email changed identity or the original proof", err)
	}
	p.claims = func(m map[string]any) { m[testEmailClaim] = testSignedEmail; m[testEmailVerifiedClaim] = false }
	token = (&oauth2.Token{}).WithExtra(map[string]any{testEmailIDToken: p.token("")})
	next, err := client.verify(t.Context(), token, "", &first)
	if err != nil || next.EmailVerified || !first.EmailVerified ||
		!next.FreshUntil.Equal(first.FreshUntil) || !next.AbsoluteUntil.Equal(first.AbsoluteUntil) {
		t.Fatal("refresh inherited verification or changed old snapshot/lifetime", err)
	}
	p.claims = nil
	token = (&oauth2.Token{}).WithExtra(map[string]any{testEmailIDToken: p.token("")})
	next, err = client.verify(t.Context(), token, "", &first)
	if err != nil || next.Email != "" || next.EmailVerified {
		t.Fatal("missing refresh claims inherited verified email", err)
	}
}

func TestEmailProofDurableRestartAndRefresh(t *testing.T) {
	for _, backend := range []string{conformancePostgresBackend, conformanceSQLiteSingleBackend, "sqlite-pool"} {
		t.Run(backend, func(t *testing.T) { testEmailProofPersistence(t, backend) })
	}
}

func testEmailProofPersistence(t *testing.T, backend string) {
	t.Helper()
	s, reopen := testConformanceStore(t, backend)
	a, p := conformanceApp(t, s)
	a.config.RequestEmail, a.oidc.config.RequestEmail = true, true
	p.claims = func(m map[string]any) { m[testEmailClaim] = testSignedEmail; m[testEmailVerifiedClaim] = true }
	cookie, row := signedIn(t, a, p)
	first := a.proof(row)
	if first == nil || first.Identity().Email != testSignedEmail || !first.Identity().EmailVerified {
		t.Fatal("callback did not persist signed email")
	}
	view := first.Identity()
	view.Email, view.EmailVerified = "edited@example.test", false
	if view.Email != "edited@example.test" || view.EmailVerified {
		t.Fatal("identity view edit was not applied")
	}
	if first.Identity().Email != testSignedEmail || !first.Identity().EmailVerified {
		t.Fatal("identity view mutated immutable proof")
	}
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	a.store = reopen()
	restarted := &Client{app: a}
	checked, err := restarted.Check(t.Context(), first.Binding())
	if err != nil || checked.Identity().Email != testSignedEmail || !checked.Identity().EmailVerified {
		t.Fatal("restart lost verified email snapshot", err)
	}
	raw, err := json.Marshal(storedProof{Identity: checked.Identity(), LoginGeneration: row.LoginGeneration})
	if err != nil {
		t.Fatal(err)
	}
	var legacy storedProof
	if err = json.Unmarshal([]byte(`{"issuer":"https://issuer.example.test","subject":"legacy"}`), &legacy); err != nil ||
		legacy.Email != "" || legacy.EmailVerified {
		t.Fatal("legacy proof acquired email verification", err)
	}
	var decoded storedProof
	if err = json.Unmarshal(raw, &decoded); err != nil || !decoded.EmailVerified || decoded.Email != testSignedEmail {
		t.Fatal("stored proof JSON lost email", err)
	}
	p.claims = func(m map[string]any) { m[testEmailClaim] = testSignedEmail; m[testEmailVerifiedClaim] = false }
	a.now = func() time.Time { return row.FreshUntil.Add(-time.Second) }
	if response := request(a, http.MethodGet, "/", cookie, nil); response.Code != http.StatusOK {
		t.Fatal("refresh request failed")
	}
	current, err := a.store.load(t.Context(), row.ID)
	if err != nil || current.Generation != row.Generation+1 || current.Proof.EmailVerified {
		t.Fatal("refresh did not durably downgrade email verification", err)
	}
	if _, err = restarted.Check(t.Context(), first.Binding()); err == nil {
		t.Fatal("old generation survived refresh")
	}
	a.store = reopen()
	fresh := a.proof(current)
	if fresh == nil {
		t.Fatal("refreshed proof missing")
	}
	checked, err = restarted.Check(t.Context(), fresh.Binding())
	if err != nil || checked.Identity().EmailVerified || checked.Identity().Email != testSignedEmail {
		t.Fatal("restart restored old verification", err)
	}
}
