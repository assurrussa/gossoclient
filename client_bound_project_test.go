//nolint:goconst // Exact signed-claim and durable-binding negatives stay beside their assertions.
package browser

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const otherClientBoundProject = "40000000-0000-4000-8000-000000000004"

func TestAuthHubClientBoundProjectRequiresExplicitExclusiveOption(t *testing.T) {
	values := validTestOptions()
	values[2] = WithAuthHubClientBoundProject()
	cfg, _, err := buildOptions(values)
	if err != nil || !cfg.ClientBoundProject || cfg.ProjectID != "" {
		t.Fatal("explicit immutable-client profile failed", err)
	}
	for _, selection := range [][]Option{
		{WithAuthHubClientBoundProject(), WithProjectID(testProject)},
		{WithProjectID(testProject), WithAuthHubClientBoundProject()},
		{WithAuthHubClientBoundProject(), WithAuthHubClientBoundProject()},
	} {
		base := validTestOptions()
		base = append(base[:2], base[3:]...)
		if _, _, err = buildOptions(append(base, selection...)); err == nil {
			t.Fatal("conflicting project selection accepted")
		}
	}
	cfg, _, err = buildOptions(validTestOptions())
	if err != nil || cfg.ClientBoundProject || !cfg.allowsProject(testProject) || cfg.allowsProject(otherClientBoundProject) {
		t.Fatal("explicit project default weakened", err)
	}
}

func TestValidateAuthHubClientConfigIsExplicitAndNetworkFree(t *testing.T) {
	cfg := Config{
		Issuer: "https://issuer.test", ClientID: "client-123",
		Origin: "https://app.test", Callback: "https://app.test/callback",
	}
	if err := ValidateAuthHubClientConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("legacy validation no longer requires an explicit project")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ProjectID = testProject },
		func(c *Config) { c.Issuer = "http://issuer.test" },
		func(c *Config) { c.ClientID = "" },
		func(c *Config) { c.Origin = c.Issuer; c.Callback = c.Origin + "/callback" },
		func(c *Config) { c.Callback = c.Origin + "/other" },
	} {
		invalid := cfg
		mutate(&invalid)
		if err := ValidateAuthHubClientConfig(invalid); err == nil {
			t.Fatal("invalid client-bound configuration accepted")
		}
	}
}

func clientBoundAuthority(t *testing.T) (*authority, *oidcClient) {
	t.Helper()
	p := newAuthority(t)
	cfg := config{
		Issuer: p.server.URL, ClientID: "client-123", ClientBoundProject: true,
		Origin: "https://app.test", Callback: "https://app.test/callback",
	}
	client, err := newOIDC(t.Context(), cfg, "client-secret", p.server.Client().Transport, func() time.Time { return p.now })
	if err != nil {
		t.Fatal(err)
	}
	return p, client
}

func TestAuthHubClientBoundProjectRequiresFullyVerifiedClaims(t *testing.T) {
	p, client := clientBoundAuthority(t)
	token := func() *oauth2.Token {
		return (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	}
	valid, err := client.verify(t.Context(), token(), "nonce", nil)
	if err != nil || valid.ProjectID != testProject || client.config.ProjectID != "" {
		t.Fatal("signed project not retained or configuration mutated", err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"missing project":      func(m map[string]any) { delete(m, "project_id") },
		"wrong project type":   func(m map[string]any) { m["project_id"] = 123 },
		"zero project":         func(m map[string]any) { m["project_id"] = "00000000-0000-0000-0000-000000000000" },
		"noncanonical project": func(m map[string]any) { m["project_id"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
		"malformed project":    func(m map[string]any) { m["project_id"] = "other" },
		"wrong audience":       func(m map[string]any) { m["aud"] = "another-client"; m["project_id"] = otherClientBoundProject },
		"multiple audiences":   func(m map[string]any) { m["aud"] = []string{"client-123", "another-client"} },
		"wrong issuer":         func(m map[string]any) { m["iss"] = "https://other.test" },
		"wrong purpose":        func(m map[string]any) { m["token_use"] = "access" },
		"wrong nonce":          func(m map[string]any) { m["nonce"] = "forged" },
		"expired":              func(m map[string]any) { m["exp"] = p.now.Unix() },
	} {
		t.Run(name, func(t *testing.T) {
			p.claims = mutate
			if _, verifyErr := client.verify(t.Context(), token(), "nonce", nil); verifyErr == nil {
				t.Fatal("invalid signed proof accepted")
			}
		})
	}
	p.claims = nil
	parts := strings.Split(p.token("nonce"), ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	forged := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": strings.Join(parts, ".")})
	if _, err = client.verify(t.Context(), forged, "nonce", nil); err == nil {
		t.Fatal("unsigned project authority accepted")
	}
	if client.config.ProjectID != "" || !client.config.ClientBoundProject {
		t.Fatal("failed verification changed immutable configuration")
	}
}

func TestAuthHubClientBoundProjectPreservesRefreshAndConcurrentPins(t *testing.T) {
	p, client := clientBoundAuthority(t)
	good := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	prior, err := client.verify(t.Context(), good, "nonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	p.claims = func(m map[string]any) { m["project_id"] = otherClientBoundProject }
	changed := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	if _, err = client.verify(t.Context(), changed, "", &prior); err == nil {
		t.Fatal("different valid project UUID accepted on refresh")
	}
	p.claims = func(m map[string]any) { m["aud"] = "another-client"; m["project_id"] = otherClientBoundProject }
	foreign := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, verifyErr := client.verify(t.Context(), foreign, "nonce", nil); verifyErr == nil {
				t.Error("foreign client project won concurrent admission")
			}
			proof, verifyErr := client.verify(t.Context(), good, "", &prior)
			if verifyErr != nil || proof.ProjectID != testProject {
				t.Error("concurrent invalid proof changed project pin", verifyErr)
			}
		}()
	}
	workers.Wait()
	if client.config.ProjectID != "" {
		t.Fatal("concurrent calls installed a first-login project cache")
	}
}

func TestPostgresAuthHubClientBoundProjectPreservesDurableBindings(t *testing.T) {
	a, authority, _ := testApp(t)
	a.config.ProjectID, a.oidc.config.ProjectID = "", ""
	a.config.ClientBoundProject, a.oidc.config.ClientBoundProject = true, true
	_, current := signedIn(t, a, authority)
	client := &Client{app: a}
	binding := a.proof(current).Binding()
	forged := binding
	forged.ProjectID = otherClientBoundProject
	if _, err := client.Check(t.Context(), forged); !errors.Is(err, ErrDenied) {
		t.Fatal("different valid project accepted by Check", err)
	}
	if err := client.RevokeBinding(t.Context(), forged); !errors.Is(err, ErrDenied) {
		t.Fatal("different valid project accepted by logout", err)
	}
	if _, err := client.Check(t.Context(), binding); err != nil {
		t.Fatal("forged logout changed the current session", err)
	}
	current = dueSession(t, a, current)
	authority.claims = func(m map[string]any) { m["project_id"] = otherClientBoundProject }
	if _, err := a.authorize(t.Context(), current); err == nil {
		t.Fatal("cross-project refresh authorized")
	}
	ended, err := a.store.load(t.Context(), current.ID)
	if err != nil || ended.Status != "ended" || len(ended.Cipher) != 0 || ended.Generation <= current.Generation {
		t.Fatal("cross-project refresh did not durably terminate the row", err)
	}
	if _, err = client.Check(t.Context(), binding); !errors.Is(err, ErrDenied) {
		t.Fatal("cross-project refresh did not terminate the old binding", err)
	}
	authority.claims = nil
	_, current = signedIn(t, a, authority)
	binding = a.proof(current).Binding()
	if err := client.RevokeBinding(t.Context(), binding); err != nil {
		t.Fatal("correct project binding could not log out", err)
	}
}
