//nolint:goconst,lll // Fixture literals and complete boundary assertions stay together.
package browser

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestBindingLifecycleRotationRestartAndExpiredLogout(t *testing.T) {
	a, authority, reopen := testApp(t)
	_, v := signedIn(t, a, authority)
	c := &Client{app: a}
	v = dueSession(t, a, v)
	old := a.proof(v).Binding()
	encoded, e := json.Marshal(old)
	if e != nil {
		t.Fatal(e)
	}
	var restored Binding
	if e = json.Unmarshal(encoded, &restored); e != nil {
		t.Fatal(e)
	}
	old = restored
	v = dueSession(t, a, v)
	next, e := a.authorize(t.Context(), v)
	if e != nil {
		t.Fatal(e)
	}
	current := a.proof(next).Binding()
	if current.Generation <= old.Generation || current.LoginGeneration != old.LoginGeneration {
		t.Fatal("refresh changed admission lineage or failed rotation")
	}
	if e = a.store.db.Close(); e != nil {
		t.Fatal(e)
	}
	a.store = reopen()
	if _, e = c.Check(t.Context(), current); e != nil {
		t.Fatal("successor invalid after restart", e)
	}
	// Logout intent remains valid after the old freshness deadline; Check does not.
	a.now = func() time.Time { return old.Deadline.Add(time.Second) }
	if _, e = c.Check(t.Context(), old); !errors.Is(e, ErrDenied) {
		t.Fatal("expired admission authorized")
	}
	if e = c.RevokeBinding(t.Context(), old); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Check(t.Context(), current); !errors.Is(e, ErrDenied) {
		t.Fatal("logout did not end descendant")
	}
	if _, e = a.authorize(t.Context(), next); e == nil {
		t.Fatal("terminal session resurrected")
	}
}

func TestBindingLifecycleLogoutDuringRefresh(t *testing.T) {
	a, authority, _ := testApp(t)
	_, v := signedIn(t, a, authority)
	c := &Client{app: a}
	binding := a.proof(v).Binding()
	v = dueSession(t, a, v)
	release := delayTokens(authority)
	done := make(chan error, 1)
	go func() { _, e := a.authorize(t.Context(), v); done <- e }()
	awaitToken(t, authority.arrived)
	e := c.RevokeBinding(t.Context(), binding)
	release()
	refreshErr := <-done
	if e != nil || refreshErr == nil {
		t.Fatal("logout lost refresh race", e, refreshErr)
	}
	row, e := a.store.load(t.Context(), v.ID)
	if e != nil || row.Status != "ended" || row.Cipher != nil || row.Proof != nil {
		t.Fatal("logout not terminal", e)
	}
}

func TestBindingLifecycleOldLoginCannotRevokeNewLogin(t *testing.T) {
	a, authority, _ := testApp(t)
	cookie, v := signedIn(t, a, authority)
	c := &Client{app: a}
	old := a.proof(v).Binding()
	state := restartBrowserLogin(t, a, authority, cookie, v.CSRF)
	if e := c.RevokeBinding(t.Context(), old); !errors.Is(e, ErrDenied) {
		t.Fatal("old logout ended pending new login", e)
	}
	if w := callback(a, cookie, state); w.Code != http.StatusSeeOther {
		t.Fatal("new callback failed")
	}
	row, e := a.store.load(t.Context(), v.ID)
	if e != nil {
		t.Fatal(e)
	}
	current := a.proof(row).Binding()
	if current.LoginGeneration == old.LoginGeneration || current.CentralSessionID != old.CentralSessionID || current.AuthTime != old.AuthTime {
		t.Fatal("fixture must isolate local lineage from identical central pins")
	}
	if e = c.RevokeBinding(t.Context(), old); !errors.Is(e, ErrDenied) {
		t.Fatal("old login revoked fresh admission", e)
	}
	if _, e = c.Check(t.Context(), current); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*Binding){
		func(b *Binding) { b.Subject = "other" }, func(b *Binding) { b.ClientID = "other" },
		func(b *Binding) { b.Issuer = "https://other-binding.invalid" }, func(b *Binding) { b.ProjectID = "other" },
		func(b *Binding) { b.CentralSessionID = "other" }, func(b *Binding) { b.AuthTime++ },
		func(b *Binding) { b.AbsoluteUntil = b.AbsoluteUntil.Add(time.Second) },
		func(b *Binding) { b.LoginGeneration = 0 }, func(b *Binding) { b.Generation++ },
	} {
		forged := current
		mutate(&forged)
		if e = c.RevokeBinding(t.Context(), forged); !errors.Is(e, ErrDenied) {
			t.Fatal("forged revoke accepted", e)
		}
	}
	if e = c.RevokeBinding(t.Context(), current); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Check(t.Context(), current); !errors.Is(e, ErrDenied) {
		t.Fatal("logout did not end session")
	}
}

type revokeTransport struct {
	next      http.RoundTripper
	store     *store
	calls     atomic.Int64
	confirmed atomic.Bool
	status    int
}

func (r *revokeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Path == "/oauth2/revoke" {
		r.calls.Add(1)
		// A DB lock here would prove the forbidden network-under-lock ordering.
		tx, e := r.store.db.BeginTx(req.Context(), nil)
		if e != nil {
			return nil, e
		}
		defer func() { _ = tx.Rollback() }()
		var status string
		e = tx.QueryRowContext(req.Context(), `SELECT status FROM sso_example_sessions FOR UPDATE NOWAIT`).Scan(&status)
		r.confirmed.Store(e == nil && status == "ended")
		if r.status != 0 {
			return &http.Response{StatusCode: r.status, Body: http.NoBody, Header: make(http.Header)}, nil
		}
		return nil, errors.New("synthetic lost revoke response")
	}
	return r.next.RoundTrip(req)
}

func TestBindingLifecycleRemoteUnknownAndLegacy(t *testing.T) {
	a, authority, _ := testApp(t)
	_, v := signedIn(t, a, authority)
	c := &Client{app: a}
	binding := a.proof(v).Binding()
	transport := &revokeTransport{next: a.oidc.http.Transport, store: a.store}
	a.oidc.http.Transport = transport
	if e := c.RevokeBinding(t.Context(), binding); !errors.Is(e, ErrRevocationUnconfirmed) {
		t.Fatal("remote unknown masked", e)
	}
	if transport.calls.Load() != 1 || !transport.confirmed.Load() {
		t.Fatal("remote revoke retried")
	}
	if _, e := c.Check(t.Context(), binding); !errors.Is(e, ErrDenied) {
		t.Fatal("remote outage resurrected local session")
	}
	_, v = signedIn(t, a, authority)
	binding = a.proof(v).Binding()
	if _, e := a.store.db.ExecContext(t.Context(), `UPDATE sso_example_sessions SET proof=proof-'loginGeneration' WHERE cookie_digest=$1`, v.ID); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Check(t.Context(), binding); !errors.Is(e, ErrDenied) {
		t.Fatal("legacy lineage admitted")
	}
	if e := c.RevokeBinding(t.Context(), binding); !errors.Is(e, ErrDenied) {
		t.Fatal("legacy lineage revoked by guessed marker")
	}
}

// commitLossConnector wraps the standard pgx driver solely in this fixture. It
// commits on PostgreSQL, then loses acknowledgement; no production test hook.
type commitLossConnector struct {
	driver.Connector
	lost *atomic.Bool
}

func (c commitLossConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, e := c.Connector.Connect(ctx)
	if e != nil {
		return nil, e
	}
	return commitLossConn{Conn: conn, lost: c.lost}, nil
}

type commitLossConn struct {
	driver.Conn
	lost *atomic.Bool
}

func (c commitLossConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, errors.New("fixture driver lacks BeginTx")
	}
	tx, e := beginner.BeginTx(ctx, opts)
	if e != nil {
		return nil, e
	}
	return commitLossTx{Tx: tx, lost: c.lost}, nil
}

type commitLossTx struct {
	driver.Tx
	lost *atomic.Bool
}

func (tx commitLossTx) Commit() error {
	if e := tx.Tx.Commit(); e != nil {
		return e
	}
	if tx.lost.Swap(false) {
		return errors.New("synthetic unknown commit acknowledgement")
	}
	return nil
}

func TestBindingLifecycleUnknownCommit(t *testing.T) {
	a, authority, reopen := testApp(t)
	_, v := signedIn(t, a, authority)
	b := a.proof(v).Binding()
	var searchPath string
	if e := a.store.db.QueryRowContext(t.Context(), `SHOW search_path`).Scan(&searchPath); e != nil {
		t.Fatal(e)
	}
	cfg, e := pgx.ParseConfig(os.Getenv("SSO_TEST_DATABASE"))
	if e != nil {
		t.Fatal("fixture config invalid")
	}
	cfg.RuntimeParams["search_path"] = searchPath
	lost := &atomic.Bool{}
	db := sql.OpenDB(commitLossConnector{Connector: stdlib.GetConnector(*cfg), lost: lost})
	t.Cleanup(func() { _ = db.Close() })
	a.store = &store{db: db}
	c := &Client{app: a}
	before := authority.requests.Load()
	lost.Store(true)
	if e = c.RevokeBinding(t.Context(), b); !errors.Is(e, ErrUnavailable) {
		t.Fatal("unknown commit acknowledged", e)
	}
	if authority.requests.Load() != before {
		t.Fatal("network after unknown local commit")
	}
	a.store = reopen()
	if _, e = c.Check(t.Context(), b); !errors.Is(e, ErrDenied) {
		t.Fatal("confirmed persisted terminal state ignored")
	}
}
