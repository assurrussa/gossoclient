//nolint:goconst,lll // Explicit signed methods and malformed wire cases keep boundary assertions readable.
package browser

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestRequiredAMROption(t *testing.T) {
	for _, value := range []string{"", " mfa", "mfa ", "mfa\n", "мфа"} {
		if _, _, err := buildOptions(append(validTestOptions(), WithRequiredAMR(value))); err == nil {
			t.Fatalf("invalid required method %q", value)
		}
	}
	for _, value := range []string{"mfa", "MFA", "pwd"} {
		c, _, err := buildOptions(append(validTestOptions(), WithRequiredAMR(value)))
		if err != nil || c.RequiredAMR != value {
			t.Fatal("method not preserved", err)
		}
	}
	if _, _, err := buildOptions(append(validTestOptions(), WithRequiredAMR("mfa"), WithRequiredAMR("mfa"))); err == nil {
		t.Fatal("duplicate option accepted")
	}
}

func TestVerifiedAMRSignedOnlyStrictAndOptIn(t *testing.T) {
	p, c := newMFAAuthority(t)
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{`["pwd","mfa"]`, []string{"pwd", "mfa"}},
		{`["mfa","mfa"]`, []string{"mfa", "mfa"}},
		{`["MFA"]`, []string{"MFA"}},
		{"", nil},
		{`null`, nil},
		{`[]`, nil},
		{`"mfa"`, nil},
		{`true`, nil},
		{`["mfa",null]`, nil},
		{`["mfa",42]`, nil},
		{`["mfa",""]`, nil},
		{`["mfa"," pwd"]`, nil},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			p.claims = func(m map[string]any) {
				if tc.raw == "" {
					delete(m, "amr")
					return
				}
				m["amr"] = json.RawMessage(tc.raw)
			}
			token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce"), "amr": []string{"mfa"}})
			c.config.RequiredAMR = ""
			id, err := c.verify(t.Context(), token, "nonce", nil)
			if err != nil || !reflect.DeepEqual(id.AMR, tc.want) {
				t.Fatal("opt-out projection", id.AMR, err)
			}
			c.config.RequiredAMR = "mfa"
			_, err = c.verify(t.Context(), token, "nonce", nil)
			want := satisfiesAMR(tc.want, "mfa")
			if !want && errors.Is(err, ErrDenied) {
				t.Fatal("terminal policy error became fresh-admission signal")
			}
			if want && err != nil || !want && !errors.Is(err, ErrRequiredAMR) {
				t.Fatal("required method", err)
			}
		})
	}
	p.claims = func(m map[string]any) {
		m["authhub_mfa"] = map[string]any{"version": 1, "enrolled": true, "setup_available": false}
		m["authhub_profile"] = map[string]string{"amr": "mfa"}
	}
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce"), "amr": []string{"mfa"}})
	if _, err := c.verify(t.Context(), token, "nonce", nil); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("non-ID-token authority", err)
	}
	p.claims = func(m map[string]any) { m["amr"] = []string{"mfa"} }
	parts := strings.Split(p.token("nonce"), ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	if _, err := c.verify(t.Context(), (&oauth2.Token{}).WithExtra(map[string]any{"id_token": strings.Join(parts, ".")}), "nonce", nil); err == nil {
		t.Fatal("tampered AMR accepted")
	}
}

func TestVerifiedAMRNoCarryForward(t *testing.T) {
	p, c := newMFAAuthority(t)
	p.claims = func(m map[string]any) { m["amr"] = []string{"pwd", "mfa"} }
	token := func() *oauth2.Token { return (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")}) }
	first, err := c.verify(t.Context(), token(), "nonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	p.claims = func(m map[string]any) { m["auth_time"] = first.AuthTime }
	next, err := c.verify(t.Context(), token(), "", &first)
	if err != nil || next.AMR != nil || !satisfiesAMR(first.AMR, "mfa") {
		t.Fatal("stale AMR carried", err)
	}
	c.config.RequiredAMR = "mfa"
	if _, err = c.verify(t.Context(), token(), "", &first); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("refresh omission admitted", err)
	}
	p.claims = func(m map[string]any) { m["auth_time"] = first.AuthTime; m["amr"] = []string{"pwd"} }
	if _, err = c.verify(t.Context(), token(), "", &first); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("refresh downgrade admitted", err)
	}
}

func TestRequiredAMRCallbackDenialTerminal(t *testing.T) {
	store, _ := testConformanceStore(t, conformanceSQLiteSingleBackend)
	a, p := conformanceApp(t, store)
	a.config.RequiredAMR = "mfa"
	a.oidc.config.RequiredAMR = "mfa"
	cookie, state := beginCallbackLogin(t, a, p, nil)
	w := httptest.NewRecorder()
	outcome, err := (&Client{app: a}).CallbackResult(w, callbackRequest(t, a, cookie, state))
	if !errors.Is(err, ErrRequiredAMR) || errors.Is(err, ErrDenied) || w.Code != http.StatusUnauthorized || w.Header().Get("Location") != "" || !strings.Contains(w.Body.String(), "Required authentication method") {
		t.Fatal("missing terminal denial", w.Code, err)
	}
	assertNoCallbackOutcome(t, outcome, err)
	row, err := a.store.load(t.Context(), digest(cookie.Value))
	if err != nil || row.Proof != nil || row.Status == sessionActive {
		t.Fatal("failed callback installed proof", err)
	}
}

func TestRequiredAMRDurableBoundariesAndRefresh(t *testing.T) {
	for _, backend := range []string{conformancePostgresBackend, conformanceSQLiteSingleBackend, conformanceSQLitePoolBackend} {
		t.Run(backend, func(t *testing.T) { testRequiredAMRDurableBoundariesAndRefresh(t, backend) })
	}
}

func testRequiredAMRDurableBoundariesAndRefresh(t *testing.T, backend string) {
	t.Helper()

	store, reopen := testConformanceStore(t, backend)
	a, p := conformanceApp(t, store)
	a.config.RequiredAMR = "mfa"
	a.oidc.config.RequiredAMR = "mfa"
	p.claims = func(m map[string]any) { m["amr"] = []string{"pwd", "mfa"} }
	cookie, row := signedIn(t, a, p)
	proof := a.proof(row)
	if proof == nil {
		t.Fatal("missing proof")
	}
	row.Proof.AMR[1] = "changed-method"
	view := proof.Identity()
	view.AMR[1] = "changed-method"
	if proof.Identity().AMR[1] != "mfa" {
		t.Fatal("mutable AMR aliased")
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	a.store = reopen()
	c := &Client{app: a}
	checked, err := c.Check(t.Context(), proof.Binding())
	if err != nil || !reflect.DeepEqual(checked.Identity().AMR, []string{"pwd", "mfa"}) {
		t.Fatal("restart AMR", err)
	}
	if err = c.Valid(t.Context(), *proof); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Verify(requestForProof(t, a, cookie)); err != nil {
		t.Fatal(err)
	}
	// A policy introduced after an opt-out login must reject its legacy proof at
	// every boundary without trusting the external host's binding as authority.
	a.config.RequiredAMR = "otp"
	if _, err = c.Check(t.Context(), proof.Binding()); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("Check policy bypass", err)
	}
	if err = c.Valid(t.Context(), *proof); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("Valid policy bypass", err)
	}
	a.config.RequiredAMR = "mfa"
	p.claims = func(m map[string]any) { m["auth_time"] = proof.Identity().AuthTime; m["amr"] = []string{"pwd"} }
	a.now = func() time.Time { return row.FreshUntil.Add(-time.Second) }
	if _, err = c.Verify(requestForProof(t, a, cookie)); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("refresh downgrade", err)
	}
	current, err := a.store.load(t.Context(), row.ID)
	if err != nil || current.Status != "ended" || current.Proof != nil || len(current.Cipher) != 0 {
		t.Fatal("refresh downgrade not terminal", err)
	}
}

func TestRequiredAMRMissingLegacyProof(t *testing.T) {
	store, _ := testConformanceStore(t, conformanceSQLiteSingleBackend)
	a, p := conformanceApp(t, store)
	cookie, row := signedIn(t, a, p)
	proof := a.proof(row)
	c := &Client{app: a}
	a.config.RequiredAMR = "mfa"
	if _, err := c.Check(t.Context(), proof.Binding()); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("legacy Check admitted", err)
	}
	if err := c.Valid(t.Context(), *proof); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("legacy Valid admitted", err)
	}
	if _, err := c.Verify(requestForProof(t, a, cookie)); !errors.Is(err, ErrRequiredAMR) {
		t.Fatal("legacy Verify admitted", err)
	}
	current, err := a.store.load(t.Context(), row.ID)
	if err != nil || current.Status != "ended" {
		t.Fatal("legacy not terminal", err)
	}
}

func TestVerifiedAMROuterAmbiguity(t *testing.T) {
	p, c := newMFAAuthority(t)
	for _, fields := range []string{
		`"amr":["pwd"],"amr":["mfa"]`,
		`"amr":["mfa"],"amr":["mfa"]`,
		`"amr":null,"amr":["mfa"]`,
		`"AMR":["mfa"]`,
		`"amr":["mfa"],"AMR":["mfa"]`,
	} {
		token := signedMFAOuterFields(t, p, fields)
		c.config.RequiredAMR = ""
		id, err := c.verify(t.Context(), token, "nonce", nil)
		if err != nil || id.AMR != nil {
			t.Fatal("ambiguous claim projected", fields, err)
		}
		c.config.RequiredAMR = "mfa"
		if _, err = c.verify(t.Context(), token, "nonce", nil); !errors.Is(err, ErrRequiredAMR) {
			t.Fatal("ambiguous claim satisfied requirement", fields, err)
		}
	}
}

func TestRequiredAMRMalformedPersistedProof(t *testing.T) {
	for _, raw := range []string{`["mfa",""]`, `["mfa",null]`, `["mfa",42]`, `"mfa"`, `null`, `[]`, `["MFA"]`} {
		t.Run(raw, func(t *testing.T) {
			store, _ := testConformanceStore(t, conformanceSQLiteSingleBackend)
			a, p := conformanceApp(t, store)
			cookie, row := signedIn(t, a, p)
			proof := a.proof(row)
			encoded, err := json.Marshal(storedProof{Identity: *row.Proof, LoginGeneration: row.LoginGeneration})
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err = json.Unmarshal(encoded, &fields); err != nil {
				t.Fatal(err)
			}
			fields["amr"] = json.RawMessage(raw)
			encoded, err = json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = store.db.ExecContext(t.Context(), `UPDATE sso_example_sessions SET proof=? WHERE cookie_digest=?`, encoded, row.ID); err != nil {
				t.Fatal(err)
			}
			a.config.RequiredAMR = "mfa"
			c := &Client{app: a}
			if _, err = c.Check(t.Context(), proof.Binding()); err == nil {
				t.Fatal("malformed stored Check accepted")
			}
			if err = c.Valid(t.Context(), *proof); err == nil {
				t.Fatal("malformed stored Valid accepted")
			}
			if _, err = c.Verify(requestForProof(t, a, cookie)); err == nil {
				t.Fatal("malformed stored Verify accepted")
			}
		})
	}
}
