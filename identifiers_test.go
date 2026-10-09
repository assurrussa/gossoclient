//nolint:goconst,lll // Explicit claim and boundary cases remain readable.
package browser

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestCanonicalIdentifiersSignedClaimOnly(t *testing.T) {
	p := newAuthority(t)
	client := p.client(t, func() time.Time { return p.now })
	token := func() *oauth2.Token {
		return (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	}
	p.claims = func(m map[string]any) {
		m["preferred_username"] = "admin"
		m["email"] = "admin@example.test"
		m["email_verified"] = true
		m["authhub_profile"] = map[string]string{"login": "admin", "email_alias": "admin@example.test", "version": "1"}
	}
	legacy, err := client.verify(t.Context(), token(), "nonce", nil)
	if err != nil || legacy.AuthHubIdentifiers != nil {
		t.Fatal("display/standard claims acquired canonical authority", err)
	}
	p.claims = func(m map[string]any) {
		m["authhub_identifiers"] = map[string]any{"version": 1, "login": "Main.Admin", "email_alias": "main+ops@example.test"}
	}
	current, err := client.verify(t.Context(), token(), "nonce", nil)
	if err != nil || current.AuthHubIdentifiers == nil ||
		current.AuthHubIdentifiers.Login != "Main.Admin" || current.AuthHubIdentifiers.EmailAlias != "main+ops@example.test" {
		t.Fatal("valid canonical claim rejected", err)
	}
	// Identifiers describe this issuance, not immutable subject/session pins.
	p.claims = func(m map[string]any) {
		m["authhub_identifiers"] = map[string]any{"version": 1, "login": "Renamed"}
	}
	renamed, err := client.verify(t.Context(), token(), "", &current)
	if err != nil || renamed.AuthHubIdentifiers == nil ||
		renamed.AuthHubIdentifiers.Login != "Renamed" || renamed.AuthHubIdentifiers.EmailAlias != "" {
		t.Fatal("canonical rename could not change current snapshot", err)
	}
}

func TestCanonicalIdentifiersRejectMalformedSignedClaim(t *testing.T) {
	p := newAuthority(t)
	client := p.client(t, func() time.Time { return p.now })
	cases := map[string]any{
		"string":             "admin",
		"null":               nil,
		"null-alias":         map[string]any{"version": 1, "login": "admin", "email_alias": nil},
		"unknown-version":    map[string]any{"version": 2, "login": "admin"},
		"missing-version":    map[string]any{"login": "admin"},
		"string-version":     map[string]any{"version": "1", "login": "admin"},
		"missing-login":      map[string]any{"version": 1, "email_alias": "admin@example.test"},
		"wrong-login-type":   map[string]any{"version": 1, "login": 1},
		"long-login":         map[string]any{"version": 1, "login": strings.Repeat("a", 65)},
		"noncanonical-login": map[string]any{"version": 1, "login": " admin"},
		"unicode-login":      map[string]any{"version": 1, "login": "аdmin"},
		"uppercase-alias":    map[string]any{"version": 1, "login": "admin", "email_alias": "Admin@example.test"},
		"space-alias":        map[string]any{"version": 1, "login": "admin", "email_alias": "a@example.test "},
		"unicode-alias":      map[string]any{"version": 1, "login": "admin", "email_alias": "a@é.test"},
		"long-localpart":     map[string]any{"version": 1, "login": "admin", "email_alias": strings.Repeat("a", 65) + "@example.test"},
		"invalid-alias":      map[string]any{"version": 1, "login": "admin", "email_alias": "a..b@example.test"},
	}
	for name, claim := range cases {
		t.Run(name, func(t *testing.T) {
			p.claims = func(m map[string]any) { m["authhub_identifiers"] = claim }
			token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
			if _, err := client.verify(t.Context(), token, "nonce", nil); err == nil {
				t.Fatal("malformed canonical claim accepted")
			}
		})
	}
}

func TestCanonicalIdentifiersSnapshotCopiesAndPersistence(t *testing.T) {
	now := time.Now()
	original := &CanonicalIdentifiers{Version: 1, Login: "Main.Admin", EmailAlias: "a@example.test"}
	row := session{
		ID: "session", Status: sessionActive, Generation: 1, LoginGeneration: 1,
		FreshUntil: now.Add(time.Minute), AbsoluteUntil: now.Add(time.Hour),
		Proof: &identity{AuthHubIdentifiers: original, AbsoluteUntil: now.Add(time.Hour)},
	}
	a := &app{now: func() time.Time { return now }}
	proof := a.proof(row)
	if proof == nil {
		t.Fatal("proof missing")
	}
	original.Login = "row-mutation"
	view := proof.Identity()
	view.AuthHubIdentifiers.Login = "view-mutation"
	if proof.Identity().AuthHubIdentifiers.Login != "Main.Admin" {
		t.Fatal("canonical identity aliased mutable state")
	}
	raw, err := json.Marshal(proof.Identity())
	if err != nil {
		t.Fatal(err)
	}
	var restored identity
	if err = json.Unmarshal(raw, &restored); err != nil || restored.AuthHubIdentifiers == nil ||
		restored.AuthHubIdentifiers.Login != "Main.Admin" {
		t.Fatal("stored canonical claim failed roundtrip", err)
	}
	var legacy identity
	if err = json.Unmarshal([]byte(`{"subject":"legacy","profile":{"login":"admin","version":"1"}}`), &legacy); err != nil ||
		legacy.AuthHubIdentifiers != nil {
		t.Fatal("legacy stored profile acquired canonical authority", err)
	}
}

func TestCanonicalIdentifiersGrammarBoundaries(t *testing.T) {
	if !validCanonicalIdentifiers(nil) ||
		!validCanonicalIdentifiers(&CanonicalIdentifiers{Version: 1, Login: strings.Repeat("A", 64)}) ||
		!validCanonicalIdentifiers(&CanonicalIdentifiers{Version: 1, Login: "a", EmailAlias: strings.Repeat("a", 64) + "@example.test"}) {
		t.Fatal("valid boundary rejected")
	}
	if validCanonicalIdentifiers(&CanonicalIdentifiers{Version: 1, Login: "_admin"}) ||
		validCanonicalIdentifiers(&CanonicalIdentifiers{Version: 1, Login: "a", EmailAlias: "a@" + strings.Repeat("b", 64) + ".test"}) ||
		validCanonicalIdentifiers(&CanonicalIdentifiers{Version: 1, Login: "a", EmailAlias: strings.Repeat("a", 64) + "@" + strings.Repeat("b.", 96) + "com"}) {
		t.Fatal("invalid identifier boundary accepted")
	}
}
