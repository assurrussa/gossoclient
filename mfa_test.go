//nolint:goconst,lll // Explicit signed advisory cases keep boundary assertions readable.
package browser

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"
)

// This signature-verifying fixture uses a pinned in-memory key set. No listener,
// discovery call, polling, or OAuth refresh request is needed by advisory tests.
func newMFAAuthority(t *testing.T) (*authority, *oidcClient) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test-key").WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	p := &authority{t: t, key: key, signer: signer, now: now, sessionEnd: now.Add(time.Hour), server: &httptest.Server{URL: "https://issuer.example"}}
	c := &oidcClient{
		config: config{Issuer: p.server.URL, ClientID: "client-123", ProjectID: testProject},
		verifier: oidc.NewVerifier(p.server.URL, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
			&oidc.Config{ClientID: "client-123", SupportedSigningAlgs: []string{oidc.RS256}, Now: func() time.Time { return p.now }}),
		http: &http.Client{}, now: func() time.Time { return p.now },
	}
	return p, c
}

func TestMFAAdvisorySignedProjectionAndRefresh(t *testing.T) {
	p, c := newMFAAuthority(t)
	token := func() *oauth2.Token { return (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")}) }
	p.claims = func(m map[string]any) {
		m["amr"] = []string{"pwd", "otp"}
		m["authhub_profile"] = map[string]string{"enrolled": "false", "setup_available": "true"}
	}
	legacy, err := c.verify(t.Context(), token(), "nonce", nil)
	if err != nil || legacy.AuthHubMFA != nil {
		t.Fatal("amr/profile became enrollment authority", err)
	}
	p.claims = func(m map[string]any) {
		m["authhub_mfa"] = map[string]any{"version": 1, "enrolled": false, "setup_available": true}
	}
	first, err := c.verify(t.Context(), token(), "nonce", nil)
	if err != nil || first.AuthHubMFA == nil || first.AuthHubMFA.Enrolled || !first.AuthHubMFA.SetupAvailable {
		t.Fatal("verified reminder unavailable", err)
	}
	p.now = p.now.Add(time.Minute)
	p.claims = func(m map[string]any) {
		m["auth_time"] = first.AuthTime
		m["authhub_mfa"] = map[string]any{"version": 1, "enrolled": true, "setup_available": true}
	}
	refreshed, err := c.verify(t.Context(), token(), "", &first)
	if err != nil || refreshed.AuthHubMFA == nil || !refreshed.AuthHubMFA.Enrolled {
		t.Fatal("normal refresh failed to replace advisory", err)
	}
	if first.AuthHubMFA.Enrolled {
		t.Fatal("old snapshot mutated")
	}
	p.claims = func(m map[string]any) { m["auth_time"] = first.AuthTime }
	without, err := c.verify(t.Context(), token(), "", &refreshed)
	if err != nil || without.AuthHubMFA != nil {
		t.Fatal("missing refresh hint retained stale advisory", err)
	}
}

func TestMFAAdvisoryMalformedHintDoesNotBreakLogin(t *testing.T) {
	p, c := newMFAAuthority(t)
	for _, raw := range []string{
		"null", "true", "[]", `"wrong"`, `{}`,
		`{"version":2,"enrolled":false,"setup_available":true}`,
		`{"version":1,"setup_available":true}`,
		`{"version":1,"enrolled":false}`,
		`{"version":"1","enrolled":false,"setup_available":true}`,
		`{"version":1,"enrolled":null,"setup_available":true}`,
		`{"version":1,"enrolled":false,"setup_available":"true"}`,
		`{"version":1,"enrolled":true,"enrolled":false,"setup_available":true}`,
		`{"version":1,"enrolled":false,"setup_available":true,"extra":"unknown"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			p.claims = func(m map[string]any) { m["authhub_mfa"] = json.RawMessage(raw) }
			id, err := c.verify(t.Context(), (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")}), "nonce", nil)
			if err != nil || id.AuthHubMFA != nil {
				t.Fatal("malformed advisory affected authentication or created CTA", err)
			}
		})
	}
	p.claims = func(m map[string]any) {
		m["authhub_mfa"] = map[string]any{"version": 1, "enrolled": false, "setup_available": true}
	}
	parts := strings.Split(p.token("nonce"), ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	id, err := c.verify(t.Context(), (&oauth2.Token{}).WithExtra(map[string]any{"id_token": strings.Join(parts, ".")}), "nonce", nil)
	if err == nil || id.AuthHubMFA != nil {
		t.Fatal("unverified advisory accepted")
	}
}

func TestMFAAdvisoryCopiesAndStoredCompatibility(t *testing.T) {
	now := time.Now()
	original := &MFAEnrollment{Version: 1, SetupAvailable: true}
	row := session{
		ID: "session", Status: sessionActive, Generation: 1, LoginGeneration: 1,
		FreshUntil: now.Add(time.Minute), AbsoluteUntil: now.Add(time.Hour),
		Proof: &identity{AuthHubMFA: original, AbsoluteUntil: now.Add(time.Hour), SessionExpiresAt: now.Add(time.Hour)},
	}
	proof := (&app{now: func() time.Time { return now }}).proof(row)
	if proof == nil {
		t.Fatal("proof missing")
	}
	original.Enrolled = true
	view := proof.Identity()
	view.AuthHubMFA.Enrolled = true
	if proof.Identity().AuthHubMFA.Enrolled {
		t.Fatal("advisory aliased mutable state")
	}
	raw, err := json.Marshal(proof.Identity())
	if err != nil {
		t.Fatal(err)
	}
	var restored identity
	if err = json.Unmarshal(raw, &restored); err != nil || restored.AuthHubMFA == nil || restored.AuthHubMFA.Enrolled {
		t.Fatal("advisory roundtrip failed", err)
	}
	for _, raw := range []string{`{"subject":"legacy"}`, `{"subject":"legacy","authhub_mfa":{"version":1,"setup_available":true}}`, `{"subject":"legacy","authhub_mfa":"bad"}`} {
		var restored identity
		if err = json.Unmarshal([]byte(raw), &restored); err != nil || cloneMFAEnrollment(restored.AuthHubMFA) != nil {
			t.Fatal("legacy/malformed stored advisory affected identity", err)
		}
	}
	row.FreshUntil = now
	if (&app{now: func() time.Time { return now }}).proof(row) != nil {
		t.Fatal("expired proof exposed hint")
	}
}

func TestMFAAdvisoryDuplicateOuterClaimDoesNotBreakLoginOrRenewal(t *testing.T) {
	p, c := newMFAAuthority(t)
	p.claims = func(m map[string]any) {
		m["authhub_mfa"] = map[string]any{"version": 1, "enrolled": false, "setup_available": true}
	}
	first, err := c.verify(t.Context(), (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")}), "nonce", nil)
	if err != nil || first.AuthHubMFA == nil || first.AuthHubMFA.Enrolled {
		t.Fatal("initial signed advisory missing", err)
	}
	p.now = p.now.Add(time.Minute)
	p.claims = func(m map[string]any) { m["auth_time"] = first.AuthTime }
	for _, tc := range []struct{ name, fields string }{
		{"false_then_true", `"authhub_mfa":{"version":1,"enrolled":false,"setup_available":true},"authhub_mfa":{"version":1,"enrolled":true,"setup_available":true}`},
		{"true_then_false", `"authhub_mfa":{"version":1,"enrolled":true,"setup_available":true},"authhub_mfa":{"version":1,"enrolled":false,"setup_available":true}`},
		{"same_value", `"authhub_mfa":{"version":1,"enrolled":false,"setup_available":true},"authhub_mfa":{"version":1,"enrolled":false,"setup_available":true}`},
		{"null_then_valid", `"authhub_mfa":null,"authhub_mfa":{"version":1,"enrolled":false,"setup_available":true}`},
		{"valid_then_null", `"authhub_mfa":{"version":1,"enrolled":false,"setup_available":true},"authhub_mfa":null`},
		{"case_alias", `"authhub_mfa":{"version":1,"enrolled":true,"setup_available":true},"AUTHHUB_MFA":{"version":1,"enrolled":false,"setup_available":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := signedMFAOuterFields(t, p, tc.fields)
			for _, prior := range []*identity{nil, &first} {
				id, verifyErr := c.verify(t.Context(), token, "nonce", prior)
				if verifyErr != nil || id.AuthHubMFA != nil {
					t.Fatal("duplicate advisory affected authentication or survived projection", verifyErr)
				}
				if id.Subject != first.Subject || id.SessionID != first.SessionID || id.AuthTime != first.AuthTime {
					t.Fatal("duplicate advisory changed authenticated identity")
				}
			}
		})
	}
	if first.AuthHubMFA == nil || first.AuthHubMFA.Enrolled || !first.AuthHubMFA.SetupAvailable {
		t.Fatal("renewal changed the earlier advisory snapshot")
	}
}

func TestMFAAdvisorySingleCaseAliasPreserved(t *testing.T) {
	p, c := newMFAAuthority(t)
	token := signedMFAOuterFields(t, p, `"AUTHHUB_MFA":{"version":1,"enrolled":false,"setup_available":true}`)
	id, err := c.verify(t.Context(), token, "nonce", nil)
	if err != nil || id.AuthHubMFA == nil || id.AuthHubMFA.Enrolled || !id.AuthHubMFA.SetupAvailable {
		t.Fatal("single case alias lost advisory compatibility", err)
	}
}

// Sign the duplicate-bearing bytes themselves; map encoding cannot represent
// duplicate outer members. The ordinary verifier still checks this signature.
func signedMFAOuterFields(t *testing.T, p *authority, fields string) *oauth2.Token {
	t.Helper()
	parts := strings.Split(p.token("nonce"), ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw[:len(raw)-1], []byte(","+fields+"}")...)
	signed, err := p.signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return (&oauth2.Token{}).WithExtra(map[string]any{"id_token": compact})
}
