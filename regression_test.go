//nolint:goconst,lll // Regression fixtures keep exact database and protocol literals beside assertions.
package browser

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

// The blocker rolls back without changing the row. This specifically exercises
// PostgreSQL's pre-lock predicate evaluation, not an ordinary changed-row CAS.
func afterRolledBackBlocker(t *testing.T, s *store, id string, deadline time.Time, work func() error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = tx.Rollback() }()
	var locked string
	if e = tx.QueryRowContext(ctx, `SELECT cookie_digest FROM sso_example_sessions WHERE cookie_digest=$1 FOR UPDATE`, id).Scan(&locked); e != nil {
		t.Fatal(e)
	}
	result := make(chan error, 1)
	go func() { result <- work() }()
	for {
		var waiting bool
		e = s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%sso_example_sessions%' AND query NOT LIKE '%pg_stat_activity%')`).Scan(&waiting)
		if e != nil {
			t.Fatal(e)
		}
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("transition did not block on the owned row")
		case <-time.After(5 * time.Millisecond):
		}
	}
	time.Sleep(time.Until(deadline) + 30*time.Millisecond)
	if e = tx.Rollback(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-result:
		return e
	case <-ctx.Done():
		t.Fatal("transition did not finish after rollback")
		return ctx.Err()
	}
}

func TestPostgresLoginInstallRechecksAfterUnchangedLockWait(t *testing.T) {
	a, p, _ := testApp(t)
	cookie, state := startLogin(t, a, p)
	var expiry time.Time
	if e := a.store.db.QueryRowContext(context.Background(), `UPDATE sso_example_logins SET expires_at=clock_timestamp()+interval '400 milliseconds' WHERE state_digest=$1 RETURNING expires_at`, digest(state)).Scan(&expiry); e != nil {
		t.Fatal(e)
	}
	l, e := a.store.claimLogin(context.Background(), digest(state), digest(cookie.Value))
	if e != nil {
		t.Fatal(e)
	}
	token := (&oauth2.Token{}).WithExtra(map[string]any{"id_token": p.token(p.nonce)})
	proof, e := a.oidc.verify(context.Background(), token, p.nonce, nil)
	if e != nil {
		t.Fatal(e)
	}
	v := session{ID: l.SessionID, Generation: l.Generation}
	encrypted, e := seal(a.aead, "synthetic-refresh", v.binding())
	if e != nil {
		t.Fatal(e)
	}
	e = afterRolledBackBlocker(t, a.store, v.ID, expiry, func() error { return a.store.installLogin(context.Background(), l, proof, encrypted) })
	if !errors.Is(e, errFenced) {
		t.Fatal("expired login installed after unchanged-row wait", e)
	}
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil || current.Status != "pending" || current.Proof != nil {
		t.Fatal("expired login changed authorization state")
	}
}

func TestPostgresRefreshInstallRechecksAbsoluteEndAfterLockWait(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	won, e := a.store.claimRefresh(context.Background(), v, "owner")
	if e != nil || !won {
		t.Fatal(e)
	}
	var expiry time.Time
	if e = a.store.db.QueryRowContext(context.Background(), `UPDATE sso_example_sessions SET absolute_until=clock_timestamp()+interval '400 milliseconds' WHERE cookie_digest=$1 RETURNING absolute_until`, v.ID).Scan(&expiry); e != nil {
		t.Fatal(e)
	}
	next := v
	next.Generation++
	encrypted, e := seal(a.aead, "synthetic-rotated", next.binding())
	if e != nil {
		t.Fatal(e)
	}
	e = afterRolledBackBlocker(t, a.store, v.ID, expiry, func() error { return a.store.installRefresh(context.Background(), v, "owner", *v.Proof, encrypted) })
	if !errors.Is(e, errFenced) {
		t.Fatal("refresh installed after absolute end across unchanged-row wait", e)
	}
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil || current.Generation != v.Generation || current.RefreshState != "claimed" {
		t.Fatal("expired refresh changed generation")
	}
}

func TestPostgresClaimRechecksDeadlineAfterLockWait(t *testing.T) {
	a, p, _ := testApp(t)
	_, v := signedIn(t, a, p)
	var expiry time.Time
	if e := a.store.db.QueryRowContext(context.Background(), `UPDATE sso_example_sessions SET absolute_until=clock_timestamp()+interval '400 milliseconds' WHERE cookie_digest=$1 RETURNING absolute_until`, v.ID).Scan(&expiry); e != nil {
		t.Fatal(e)
	}
	e := afterRolledBackBlocker(t, a.store, v.ID, expiry, func() error {
		won, e := a.store.claimRefresh(context.Background(), v, "owner")
		if e != nil {
			return e
		}
		if won {
			return errors.New("expired owner claimed")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

type cancelAtEOF struct {
	io.ReadCloser
	cancel context.CancelFunc
	once   sync.Once
}

func (b *cancelAtEOF) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	if errors.Is(e, io.EOF) {
		b.once.Do(b.cancel)
	}
	return n, e
}

func TestPostgresDefiniteDenialPersistsAfterBrowserCancellation(t *testing.T) {
	a, p, reopen := testApp(t)
	_, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	p.mode = "deny"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := a.oidc.http.Transport
	a.oidc.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		res, e := base.RoundTrip(r)
		if e == nil && r.URL.Path == "/oauth2/token" {
			res.Body = &cancelAtEOF{ReadCloser: res.Body, cancel: cancel}
		}
		return res, e
	})
	if _, e := a.authorize(ctx, v); !errors.Is(e, errFenced) {
		t.Fatal("known denial did not end the session", e)
	}
	if ctx.Err() == nil {
		t.Fatal("browser cancellation was not exercised")
	}
	a.store = reopen()
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil || current.Status != "ended" || current.Proof != nil {
		t.Fatal("denial was lost after cancellation and reopen", e)
	}
}

func rejectTerminalWrites(t *testing.T, db *sql.DB) {
	t.Helper()
	_, e := db.ExecContext(context.Background(), `CREATE FUNCTION refuse_terminal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status='ended' THEN RAISE EXCEPTION 'synthetic terminal failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER refuse_terminal BEFORE UPDATE ON sso_example_sessions FOR EACH ROW EXECUTE FUNCTION refuse_terminal()`)
	if e != nil {
		t.Fatal(e)
	}
}

func TestPostgresUnconfirmedDenialCannotRegainCachedAuthorization(t *testing.T) {
	for _, kind := range []string{"denial", "bad-proof"} {
		t.Run(kind, func(t *testing.T) {
			a, p, reopen := testApp(t)
			cookie, v := signedIn(t, a, p)
			v = dueSession(t, a, v)
			rejectTerminalWrites(t, a.store.db)
			if kind == "denial" {
				p.mode = "deny"
			} else {
				p.claims = func(m map[string]any) { m["project_id"] = "different" }
			}
			if _, e := a.authorize(context.Background(), v); !errors.Is(e, errTerminalUnconfirmed) {
				t.Fatal("terminal persistence failure was hidden", e)
			}
			a.store = reopen()
			current, e := a.store.load(context.Background(), v.ID)
			if e != nil {
				t.Fatal(e)
			}
			if current.Status != "active" || current.RefreshState != "claimed" {
				t.Fatal("failure fixture did not preserve the unresolved fence")
			}
			if _, e = a.authorize(context.Background(), current); !errors.Is(e, errRefreshPending) {
				t.Fatal("unconfirmed denial regained old proof", e)
			}
			w := request(a, http.MethodGet, "/", cookie, nil)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatal("unresolved owner was not unavailable")
			}
			if p.calls.Load() != 2 {
				t.Fatal("unresolved owner retried its secret")
			}
		})
	}
}

func restartBrowserLogin(t *testing.T, a *app, p *authority, cookie *http.Cookie, csrf string) string {
	t.Helper()
	w := request(a, http.MethodPost, "/login", cookie, url.Values{"csrf": {csrf}})
	if w.Code != http.StatusSeeOther {
		t.Fatal("explicit recovery login failed")
	}
	target, e := url.Parse(w.Header().Get("Location"))
	if e != nil {
		t.Fatal(e)
	}
	p.mu.Lock()
	p.nonce = target.Query().Get("nonce")
	p.challenge = target.Query().Get("code_challenge")
	p.mu.Unlock()
	return target.Query().Get("state")
}

func TestPostgresRecoveryFormFencesDelayedOldRefresh(t *testing.T) {
	a, p, _ := testApp(t)
	cookie, v := signedIn(t, a, p)
	v = dueSession(t, a, v)
	release := delayTokens(p)
	done := make(chan error, 1)
	go func() { _, e := a.authorize(context.Background(), v); done <- e }()
	awaitToken(t, p.arrived)
	page := request(a, http.MethodGet, "/", cookie, nil)
	if page.Code != http.StatusServiceUnavailable || !strings.Contains(page.Body.String(), `action="/login"`) || !strings.Contains(page.Body.String(), v.CSRF) || strings.Contains(page.Body.String(), v.Proof.Subject) {
		t.Fatal("503 recovery page omitted sign-in or displayed old identity")
	}
	state := restartBrowserLogin(t, a, p, cookie, v.CSRF)
	pending, e := a.store.load(context.Background(), v.ID)
	if e != nil || pending.Generation <= v.Generation || pending.Status != "pending" {
		t.Fatal("new login did not advance generation")
	}
	release()
	if e = <-done; e == nil {
		t.Fatal("old refresh installed into recovery generation")
	}
	current, e := a.store.load(context.Background(), v.ID)
	if e != nil || current.Generation != pending.Generation || current.Status != "pending" {
		t.Fatal("late refresh changed recovery generation")
	}
	if w := callback(a, cookie, state); w.Code != http.StatusSeeOther {
		t.Fatal("new authorization could not complete")
	}
	current, e = a.store.load(context.Background(), v.ID)
	if e != nil || current.Generation != pending.Generation || current.Status != sessionActive {
		t.Fatal("recovery did not install new proof")
	}
}

func TestPostgresNewLoginFencesDelayedOldCallback(t *testing.T) {
	a, p, _ := testApp(t)
	cookie, oldState := startLogin(t, a, p)
	original, e := a.store.load(context.Background(), digest(cookie.Value))
	if e != nil {
		t.Fatal(e)
	}
	release := delayTokens(p)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- callback(a, cookie, oldState) }()
	awaitToken(t, p.arrived)
	state := restartBrowserLogin(t, a, p, cookie, original.CSRF)
	pending, e := a.store.load(context.Background(), original.ID)
	if e != nil || pending.Generation <= original.Generation {
		t.Fatal("new callback generation missing")
	}
	release()
	if w := <-done; w.Code != http.StatusUnauthorized {
		t.Fatal("old callback replaced newer login")
	}
	current, e := a.store.load(context.Background(), original.ID)
	if e != nil || current.Generation != pending.Generation || current.Status != "pending" {
		t.Fatal("late callback changed newer generation")
	}
	if w := callback(a, cookie, state); w.Code != http.StatusSeeOther {
		t.Fatal("new callback could not complete")
	}
}

func TestPostgresCallbackAcknowledgementUsesCommittedProofDeadlines(t *testing.T) {
	for _, kind := range []string{"spent-login-expiry", "signed-proof-expiry", "absolute-end"} {
		t.Run(kind, func(t *testing.T) {
			a, p, _ := testApp(t)
			cookie, state := startLogin(t, a, p)
			var loginExpiry time.Time
			if e := a.store.db.QueryRowContext(context.Background(), `UPDATE sso_example_logins SET expires_at=clock_timestamp()+interval '5 seconds' WHERE state_digest=$1 RETURNING expires_at`, digest(state)).Scan(&loginExpiry); e != nil {
				t.Fatal(e)
			}
			ackTime := loginExpiry.Add(time.Second)
			want := http.StatusSeeOther
			if kind == "signed-proof-expiry" {
				ackTime = p.now.Add(5 * time.Minute)
				want = http.StatusUnauthorized
			}
			if kind == "absolute-end" {
				var end time.Time
				if e := a.store.db.QueryRowContext(context.Background(), `UPDATE sso_example_sessions SET absolute_until=clock_timestamp()+interval '10 seconds' WHERE cookie_digest=$1 RETURNING absolute_until`, digest(cookie.Value)).Scan(&end); e != nil {
					t.Fatal(e)
				}
				ackTime = end
				want = http.StatusUnauthorized
			}
			// Only the app's post-commit acknowledgement clock changes. SQL eligibility
			// and official signed-token verification retain their real fixture clocks.
			a.now = func() time.Time { return ackTime }
			w := callback(a, cookie, state)
			if w.Code != want {
				t.Fatalf("acknowledgement %s: status=%d", kind, w.Code)
			}
			if want != http.StatusSeeOther && w.Header().Get("Location") != "" {
				t.Fatal("expired acknowledgement redirected")
			}
			current, e := a.store.load(context.Background(), digest(cookie.Value))
			if e != nil || current.Status != sessionActive || current.Proof == nil {
				t.Fatal("test did not retain the confirmed installation", e)
			}
			if current.FreshUntil.After(p.now.Add(5 * time.Minute)) {
				t.Fatal("acknowledgement extended signed proof lifetime")
			}
		})
	}
}
