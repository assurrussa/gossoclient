package browser

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"modernc.org/sqlite"
)

var injectedDriverSequence atomic.Int64
var errInjectedSQLite = errors.New("injected SQLite outcome")

type injectingSQLiteDriver struct {
	base sqlite.Driver
	mu sync.Mutex
	target string
	after bool
	fired bool
	closes atomic.Int64
	commits atomic.Int64
}

func (d *injectingSQLiteDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.base.Open(name)
	if err != nil { return nil, err }
	return &injectingSQLiteConn{Conn: conn, owner: d}, nil
}

type injectingSQLiteConn struct { driver.Conn; owner *injectingSQLiteDriver }

func (c *injectingSQLiteConn) Close() error {
	c.owner.closes.Add(1)
	return c.Conn.Close()
}

func (c *injectingSQLiteConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	exec, ok := c.Conn.(driver.ExecerContext)
	if !ok { return nil, errors.New("SQLite driver lacks ExecerContext") }
	d := c.owner
	d.mu.Lock()
	inject := !d.fired && strings.TrimSpace(query) == d.target
	if inject { d.fired = true }
	after := d.after
	d.mu.Unlock()
	if query == "COMMIT" { d.commits.Add(1) }
	if inject && !after { return nil, errInjectedSQLite }
	result, err := exec.ExecContext(ctx, query, args)
	if err != nil { return result, err }
	if inject { return nil, errInjectedSQLite }
	return result, nil
}

func (c *injectingSQLiteConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	queryer, ok := c.Conn.(driver.QueryerContext)
	if !ok { return nil, errors.New("SQLite driver lacks QueryerContext") }
	return queryer.QueryContext(ctx, query, args)
}

func TestSQLiteAmbiguousTransactionOutcomes(t *testing.T) {
	for _, mode := range []string{"begin", "rollback", "commit"} {
		t.Run(mode, func(t *testing.T) {
			target := map[string]string{"begin":"BEGIN IMMEDIATE", "rollback":"ROLLBACK", "commit":"COMMIT"}[mode]
			injected := &injectingSQLiteDriver{target:target, after:mode != "rollback"}
			name := fmt.Sprintf("sso-injected-%d", injectedDriverSequence.Add(1))
			sql.Register(name, injected)
			db, err := sql.Open(name, filepath.Join(t.TempDir(), "failures.sqlite"))
			if err != nil { t.Fatal(err) }
			defer func() { _ = db.Close() }()
			db.SetMaxOpenConns(1)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if _, err = db.ExecContext(ctx, SQLiteSchema()); err != nil { t.Fatal(err) }
			s, err := NewSQLiteStore(ctx, db)
			if err != nil { t.Fatal(err) }
			tx, err := s.store.sqlite.beginImmediate(ctx)
			switch mode {
			case "begin":
				if !errors.Is(err, errInjectedSQLite) || tx != nil { t.Fatal("ambiguous BEGIN accepted", err) }
			case "rollback":
				if err != nil { t.Fatal(err) }
				if err = tx.Rollback(); !errors.Is(err, errInjectedSQLite) { t.Fatal("failed rollback accepted", err) }
			case "commit":
				if err != nil { t.Fatal(err) }
				_, err = tx.ExecContext(ctx, "INSERT INTO sso_example_sessions(cookie_digest,status,csrf,absolute_until) VALUES($1,'pending',$2,$3)", "committed", "csrf", time.Now().Add(time.Hour))
				if err != nil { t.Fatal(err) }
				if err = tx.Commit(ctx); !errors.Is(err, errInjectedSQLite) { t.Fatal("unknown COMMIT accepted", err) }
				if injected.commits.Load() != 1 { t.Fatal("COMMIT retried") }
				v, loadErr := s.store.load(ctx, "committed")
				if loadErr != nil || v.Status != "pending" { t.Fatal("test did not commit before losing acknowledgement", loadErr) }
			}
			if injected.closes.Load() == 0 { t.Fatal("uncertain connection returned to pool") }
			if err = s.store.create(ctx, "after-failure", "csrf", time.Now().Add(time.Hour)); err != nil { t.Fatal("pool remained locked", err) }
		})
	}
}
