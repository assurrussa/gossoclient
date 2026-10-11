//nolint:goconst // Expiry regressions retain exact signed and durable fixtures beside each assertion.
package browser

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestSignedSessionExpiryIsAuthoritative(t *testing.T) {
	p := newAuthority(t)
	p.sessionEnd = p.now.Add(time.Hour + 123*time.Microsecond)
	client := p.client(t, func() time.Time { return p.now })
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	first, err := client.verify(t.Context(), token, "nonce", nil)
	if err != nil || !first.AbsoluteUntil.Equal(p.sessionEnd) || !first.SessionExpiresAt.Equal(p.sessionEnd) {
		t.Fatal("signed provider deadline was not preserved", err)
	}
	// Real same-session reauthentication advances auth_time, not the sid's end.
	p.claims = func(m map[string]any) { m["auth_time"] = p.now.Unix() }
	token = (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	reauth, err := client.verify(t.Context(), token, "nonce", nil)
	if err != nil || !reauth.AbsoluteUntil.Equal(first.AbsoluteUntil) || reauth.AuthTime == first.AuthTime {
		t.Fatal("reauthentication invented a new session end", err)
	}
}

func TestSignedSessionExpiryRejectsInvalidClaims(t *testing.T) {
	p := newAuthority(t)
	client := p.client(t, func() time.Time { return p.now })
	cases := map[string]func(map[string]any){
		"absent":              func(m map[string]any) { delete(m, "session_expires_at") },
		"null":                func(m map[string]any) { m["session_expires_at"] = nil },
		"zero":                func(m map[string]any) { m["session_expires_at"] = time.Time{} },
		"number":              func(m map[string]any) { m["session_expires_at"] = p.sessionEnd.Unix() },
		"object":              func(m map[string]any) { m["session_expires_at"] = map[string]string{"end": "later"} },
		"malformed":           func(m map[string]any) { m["session_expires_at"] = "tomorrow" },
		"expired":             func(m map[string]any) { m["session_expires_at"] = p.now.Add(-time.Second) },
		"equality":            func(m map[string]any) { m["session_expires_at"] = p.now },
		"before-token-expiry": func(m map[string]any) { m["session_expires_at"] = p.now.Add(time.Minute) },
		"before-authentication": func(m map[string]any) {
			m["auth_time"] = p.now.Add(20 * time.Second).Unix()
			m["exp"] = p.now.Add(10 * time.Second).Unix()
			m["session_expires_at"] = p.now.Add(15 * time.Second)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p.claims = mutate
			token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
			if _, err := client.verify(t.Context(), token, "nonce", nil); err == nil {
				t.Fatal("invalid signed session expiry accepted")
			}
		})
	}
}

func TestSignedSessionExpiryRefreshAndLegacyBounds(t *testing.T) {
	p := newAuthority(t)
	p.sessionEnd = p.now.Add(time.Hour)
	client := p.client(t, func() time.Time { return p.now })
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("nonce")})
	first, err := client.verify(t.Context(), token, "nonce", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, delta := range []time.Duration{-time.Minute, time.Minute} {
		p.claims = func(m map[string]any) { m["session_expires_at"] = p.sessionEnd.Add(delta) }
		next := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("")})
		if _, err := client.verify(t.Context(), next, "", &first); err == nil {
			t.Fatal("refresh changed the pinned provider deadline")
		}
	}
	p.claims = nil
	for _, oldEnd := range []time.Time{p.now.Add(30 * time.Minute), p.now.Add(24 * time.Hour)} {
		legacy := first
		legacy.SessionExpiresAt = time.Time{}
		legacy.AbsoluteUntil = oldEnd
		next := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("")})
		upgraded, err := client.verify(t.Context(), next, "", &legacy)
		if err != nil || !upgraded.SessionExpiresAt.Equal(p.sessionEnd) ||
			!upgraded.AbsoluteUntil.Equal(minTime(oldEnd, p.sessionEnd)) {
			t.Fatal("legacy upgrade extended an existing bound", err)
		}
	}
	legacy := first
	legacy.SessionExpiresAt = time.Time{}
	p.claims = func(m map[string]any) { delete(m, "session_expires_at") }
	next := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token("")})
	if _, err := client.verify(t.Context(), next, "", &legacy); err == nil {
		t.Fatal("legacy upgrade used an unsigned fallback")
	}
}

func legacyExpirySession(t *testing.T, a *app, v session, end time.Time) session {
	t.Helper()
	v.AbsoluteUntil, v.Proof.AbsoluteUntil = end, end
	v.Proof.SessionExpiresAt = time.Time{}
	proof, err := json.Marshal(storedProof{Identity: *v.Proof, LoginGeneration: v.LoginGeneration})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.store.db.ExecContext(t.Context(),
		"UPDATE sso_example_sessions SET proof=$2, absolute_until=$3 WHERE cookie_digest=$1",
		v.ID, proof, end); err != nil {
		t.Fatal(err)
	}
	return v
}

func legacyExpiryBinding(v session) Binding {
	p := Proof{
		identity: *v.Proof, reference: v.ID, generation: v.Generation,
		loginGeneration: v.LoginGeneration, deadline: minTime(v.FreshUntil, v.AbsoluteUntil),
	}
	return p.Binding()
}

func TestPostgresLegacyExpiryUpgradePreservesLogoutLineage(t *testing.T) {
	a, p, _ := testApp(t)
	p.sessionEnd = p.now.Add(time.Hour)
	cookie, v := signedIn(t, a, p)
	old := legacyExpirySession(t, a, v, p.now.Add(24*time.Hour))
	binding := legacyExpiryBinding(old)
	client := &Client{app: a}
	if a.proof(old) != nil {
		t.Fatal("legacy cached snapshot authorized")
	}
	if _, err := client.Check(t.Context(), binding); !errors.Is(err, ErrDenied) {
		t.Fatal("Check authorized legacy snapshot", err)
	}
	proof, err := client.Verify(requestForProof(t, a, cookie))
	if err != nil || proof.Generation() != old.Generation+1 ||
		proof.Binding().LoginGeneration != old.LoginGeneration ||
		!proof.Identity().AbsoluteUntil.Equal(p.sessionEnd) || p.calls.Load() != 2 {
		t.Fatal("legacy refresh upgrade did not commit exactly once", err)
	}
	row, err := a.store.load(t.Context(), old.ID)
	if err != nil || !row.AbsoluteUntil.Equal(p.sessionEnd) || !row.Proof.SessionExpiresAt.Equal(p.sessionEnd) {
		t.Fatal("signed cap not persisted", err)
	}
	if _, err := client.Check(t.Context(), binding); !errors.Is(err, ErrDenied) {
		t.Fatal("old admission survived upgrade", err)
	}
	for _, forged := range []Binding{
		func() Binding { b := binding; b.LoginGeneration++; return b }(),
		func() Binding { b := binding; b.Generation = proof.Generation(); return b }(),
	} {
		if err := client.RevokeBinding(t.Context(), forged); !errors.Is(err, ErrDenied) {
			t.Fatal("forged logout lineage or same-generation deadline accepted", err)
		}
	}
	if err := client.RevokeBinding(t.Context(), binding); err != nil {
		t.Fatal("original host logout could not terminate tightened descendant", err)
	}
}

func TestPostgresLegacyExpiryUpgradeIsSingleOwner(t *testing.T) {
	a, p, reopen := testApp(t)
	_, v := signedIn(t, a, p)
	v = legacyExpirySession(t, a, v, v.AbsoluteUntil)
	release := delayTokens(p)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.authorize(t.Context(), v)
			results <- err
		}()
	}
	awaitToken(t, p.arrived)
	other := *a
	other.store = reopen()
	current, err := other.store.load(t.Context(), v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.authorize(t.Context(), current); !errors.Is(err, errRefreshPending) {
		t.Error("claimed upgrade admitted old proof", err)
	}
	release()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, errRefreshPending) {
			t.Fatal(err)
		}
	}
	if p.calls.Load() != 2 {
		t.Fatal("legacy refresh was replayed")
	}
	current, err = a.store.load(t.Context(), v.ID)
	if err != nil || current.Generation != v.Generation+1 || a.proof(current) == nil {
		t.Fatal("committed upgrade not admitted", err)
	}
}

func TestPostgresLegacyExpiryUpgradeFailuresNeverAuthorize(t *testing.T) {
	for _, kind := range []string{"deny", "lost", "missing-claim", "malformed-claim", "changed-identity"} {
		t.Run(kind, func(t *testing.T) {
			a, p, _ := testApp(t)
			cookie, v := signedIn(t, a, p)
			v = legacyExpirySession(t, a, v, v.AbsoluteUntil)
			switch kind {
			case "missing-claim":
				p.claims = func(m map[string]any) { delete(m, "session_expires_at") }
			case "malformed-claim":
				p.claims = func(m map[string]any) { m["session_expires_at"] = "bad" }
			case "changed-identity":
				p.claims = func(m map[string]any) { m["sub"] = "other" }
			default:
				p.mode = kind
			}
			client := &Client{app: a}
			for range 2 {
				if _, err := client.Verify(requestForProof(t, a, cookie)); err == nil {
					t.Fatal("failed legacy upgrade authorized")
				}
			}
			if p.calls.Load() != 2 {
				t.Fatal("failed refresh was replayed")
			}
			if _, err := client.Check(t.Context(), legacyExpiryBinding(v)); err == nil {
				t.Fatal("Check admitted failed upgrade")
			}
		})
	}
}

func TestPostgresSignedExpiryAndLocalCapStopRefresh(t *testing.T) {
	for _, localFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "signed", true: "local"}[localFirst], func(t *testing.T) {
			a, p, _ := testApp(t)
			p.sessionEnd = p.now.Add(time.Hour)
			cookie, v := signedIn(t, a, p)
			end := p.sessionEnd
			if localFirst {
				end = p.now.Add(30 * time.Minute)
				if _, err := a.store.db.ExecContext(t.Context(),
					"UPDATE sso_example_sessions SET absolute_until=$2 WHERE cookie_digest=$1", v.ID, end); err != nil {
					t.Fatal(err)
				}
			}
			a.now = func() time.Time { return end }
			client := &Client{app: a}
			if _, err := client.Verify(requestForProof(t, a, cookie)); !errors.Is(err, ErrDenied) {
				t.Fatal("absolute equality authorized", err)
			}
			if p.calls.Load() != 1 {
				t.Fatal("expired absolute deadline reached token endpoint")
			}
		})
	}
}

func TestPostgresLegacyExpiryUpgradeKeepsEarlierLocalEnd(t *testing.T) {
	a, p, _ := testApp(t)
	p.sessionEnd = p.now.Add(time.Hour)
	cookie, v := signedIn(t, a, p)
	localEnd := p.now.Add(30 * time.Minute)
	v = legacyExpirySession(t, a, v, localEnd)
	proof, err := (&Client{app: a}).Verify(requestForProof(t, a, cookie))
	if err != nil || !proof.Identity().AbsoluteUntil.Equal(localEnd) ||
		!proof.Identity().SessionExpiresAt.Equal(p.sessionEnd) {
		t.Fatal("verified provider deadline extended local cookie bound", err)
	}
	row, err := a.store.load(t.Context(), v.ID)
	if err != nil || !row.AbsoluteUntil.Equal(localEnd) {
		t.Fatal("refresh extended persisted local bound", err)
	}
}

func TestPostgresSignedExpiryInstallRechecksAfterLockWait(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	won, err := a.store.claimRefresh(t.Context(), v, "expiry-owner")
	if err != nil || !won {
		t.Fatal("refresh owner unavailable", err)
	}
	end := time.Now().Add(400 * time.Millisecond)
	next := *v.Proof
	next.SessionExpiresAt, next.AbsoluteUntil = end, end
	row := v
	row.Generation++
	cipher, err := seal(a.aead, "synthetic-refresh", row.binding())
	if err != nil {
		t.Fatal(err)
	}
	err = afterRolledBackBlocker(t, a.store, v.ID, end, func() error {
		return a.store.installRefresh(t.Context(), v, "expiry-owner", next, cipher)
	})
	if !errors.Is(err, errFenced) {
		t.Fatal("expired signed bound installed after row-lock wait", err)
	}
	current, err := a.store.load(t.Context(), v.ID)
	if err != nil || current.Generation != v.Generation || current.RefreshState != "claimed" {
		t.Fatal("expired installation changed durable generation", err)
	}
}
