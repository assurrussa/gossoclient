//nolint:goconst,lll // Complete synthetic SQL and isolation assertions stay together.
package browser

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPostgresSchemaIdentifierValidation(t *testing.T) {
	for _, name := range []string{"app_sso", "MixedCase", "_private", strings.Repeat("a", 63)} {
		if err := validateStoreSchema(name); err != nil {
			t.Fatalf("valid identifier %q: %v", name, err)
		}
		if got := (&store{schema: name}).table("sso_example_sessions"); got != `"`+name+`".sso_example_sessions` {
			t.Fatalf("schema was not quoted: %q", got)
		}
	}
	for _, name := range []string{"", "1schema", "a.b", `"quoted"`, "a-b", "a b", "a;b", "a\n", "схема", strings.Repeat("a", 64)} {
		if _, err := NewPostgresStoreWithSchema(t.Context(), nil, name); err == nil || !strings.Contains(err.Error(), "ASCII identifier") {
			t.Fatalf("invalid schema reached database validation: %q, %v", name, err)
		}
	}
	if got := (&store{}).table("sso_example_sessions"); got != "sso_example_sessions" {
		t.Fatal("legacy unqualified table changed")
	}
	if _, err := NewPostgresStoreWithSchema(t.Context(), nil, "app_sso"); err == nil {
		t.Fatal("nil database accepted")
	}
}

// qualifiedTestStore applies unchanged DDL in an owned transaction. It never
// opens or closes another pool; cleanup leaves the caller's default schema alone.
func qualifiedTestStore(t *testing.T, db *sql.DB) *PostgresStore {
	t.Helper()
	random, err := randomSecret()
	if err != nil {
		t.Fatal(err)
	}
	name := "SSO_" + hex.EncodeToString([]byte(random)[:12])
	quoted := `"` + name + `"`
	if _, err = db.ExecContext(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, cleanupErr := db.ExecContext(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); cleanupErr != nil {
			t.Error(cleanupErr)
		}
	})
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err = tx.ExecContext(t.Context(), "SET LOCAL search_path TO "+quoted); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(t.Context(), Schema()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	selected, err := NewPostgresStoreWithSchema(t.Context(), db, name)
	if err != nil {
		t.Fatal(err)
	}
	return selected
}

func TestPostgresQualifiedStoreSharesPoolAndIsolatesSchemas(t *testing.T) {
	base, _ := testStore(t)
	var before string
	if err := base.db.QueryRowContext(t.Context(), "SHOW search_path").Scan(&before); err != nil {
		t.Fatal(err)
	}
	maxOpen := base.db.Stats().MaxOpenConnections
	selected := qualifiedTestStore(t, base.db)
	if selected.store.db != base.db || base.db.Stats().MaxOpenConnections != maxOpen {
		t.Fatal("constructor did not retain the caller's exact pool")
	}
	legacy, err := NewPostgresStore(t.Context(), base.db)
	if err != nil || legacy.store.schema != "" || legacy.store.db != base.db {
		t.Fatal("legacy constructor behavior changed", err)
	}
	if _, err = NewPostgresStoreWithSchema(t.Context(), base.db, selected.store.schema+"_missing"); err == nil {
		t.Fatal("readiness silently used the default schema")
	}
	until := time.Now().Add(time.Hour)
	stores := []*store{base, selected.store}
	var workers sync.WaitGroup
	for i := range 16 {
		for j, target := range stores {
			workers.Add(1)
			go func() {
				defer workers.Done()
				id, csrf := fmt.Sprintf("shared-%d", i), fmt.Sprintf("schema-%d", j)
				if createErr := target.create(t.Context(), id, csrf, until); createErr != nil {
					t.Error(createErr)
					return
				}
				row, loadErr := target.load(t.Context(), id)
				if loadErr != nil || row.CSRF != csrf {
					t.Error("schemas leaked across concurrent pooled requests", loadErr)
				}
			}()
		}
	}
	workers.Wait()
	// Hold multiple connections simultaneously to inspect each pooled session.
	var conns []*sql.Conn
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for range 4 {
		conn, connErr := base.db.Conn(t.Context())
		if connErr != nil {
			t.Fatal(connErr)
		}
		conns = append(conns, conn)
		var after string
		if connErr = conn.QueryRowContext(t.Context(), "SHOW search_path").Scan(&after); connErr != nil || after != before {
			t.Fatal("shared connection search_path changed", connErr)
		}
	}
}

func TestPostgresQualifiedStoreRetainsSessionLifecycle(t *testing.T) {
	a, authority, _ := testApp(t)
	base := a.store
	selected := qualifiedTestStore(t, base.db)
	a.store = selected.store
	cookie, state := startLogin(t, a, authority)
	id := digest(cookie.Value)
	if err := base.create(t.Context(), id, "host-csrf", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if response := callback(a, cookie, state); response.Code != http.StatusSeeOther {
		t.Fatal("qualified callback failed beside a lookalike host row")
	}
	current, err := a.store.load(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{app: a}
	_, err = client.Verify(requestForProof(t, a, cookie))
	if err != nil {
		t.Fatal(err)
	}
	hostRow, err := base.load(t.Context(), current.ID)
	if err != nil || hostRow.CSRF != "host-csrf" || hostRow.Status != "pending" || hostRow.Generation != 0 {
		t.Fatal("qualified callback changed the default schema", err)
	}
	current.FreshUntil = time.Now().Add(15 * time.Second)
	current.Proof.FreshUntil = current.FreshUntil
	// #nosec G202 -- The schema is generated by this fixture and table names are fixed.
	if _, err = base.db.ExecContext(t.Context(),
		"UPDATE "+a.store.table("sso_example_sessions")+" SET fresh_until=$2 WHERE cookie_digest=$1",
		current.ID, current.FreshUntil); err != nil {
		t.Fatal(err)
	}
	oldBinding := a.proof(current).Binding()
	next, err := a.authorize(t.Context(), current)
	if err != nil || next.Generation <= current.Generation {
		t.Fatal("qualified refresh did not rotate", err)
	}
	if _, err = client.Check(t.Context(), oldBinding); !errors.Is(err, ErrDenied) {
		t.Fatal("superseded qualified binding accepted", err)
	}
	restored, err := NewPostgresStoreWithSchema(t.Context(), base.db, selected.store.schema)
	if err != nil {
		t.Fatal(err)
	}
	a.store = restored.store
	binding := a.proof(next).Binding()
	if _, err = client.Check(t.Context(), binding); err != nil {
		t.Fatal("qualified durable binding did not survive reconstruction", err)
	}
	if err = client.RevokeBinding(t.Context(), binding); err != nil {
		t.Fatal("qualified logout failed", err)
	}
	if _, err = client.Check(t.Context(), binding); !errors.Is(err, ErrDenied) {
		t.Fatal("qualified logout resurrected a binding", err)
	}
	hostRow, err = base.load(t.Context(), current.ID)
	if err != nil || hostRow.CSRF != "host-csrf" || hostRow.Status != "pending" || hostRow.Generation != 0 {
		t.Fatal("qualified refresh/logout changed the default schema", err)
	}
	if err = base.db.PingContext(t.Context()); err != nil {
		t.Fatal("SDK closed the host pool", err)
	}
}
