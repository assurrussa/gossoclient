package browser

import (
	"database/sql"
	"testing"
)

func TestStoreBoundaryRejectsInvalidBackends(t *testing.T) {
	var postgres *PostgresStore
	var sqlite *SQLiteStore
	for _, value := range []Store{
		nil, postgres, sqlite, &PostgresStore{}, &SQLiteStore{},
		&PostgresStore{store: &postgresStore{}},
		&SQLiteStore{store: &sqliteStore{}},
	} {
		if snapshotStore(value) != nil || validStore(value) {
			t.Fatal("invalid backend accepted")
		}
	}
}

func TestStoreBoundarySnapshotsConcreteBackend(t *testing.T) {
	db := new(sql.DB) // Handle identity only; this test performs no database I/O.
	postgres := &PostgresStore{store: &postgresStore{db: db, schema: "selected"}}
	first, ok := snapshotStore(postgres).(*postgresStore)
	if !ok {
		t.Fatal("PostgreSQL backend was not selected")
	}
	second, ok := snapshotStore(postgres).(*postgresStore)
	if !ok || first == second || first == postgres.store {
		t.Fatal("PostgreSQL backend was not independently snapshotted")
	}
	postgres.store.db = nil
	postgres.store.schema = "changed"
	if first.db != db || second.db != db || first.schema != "selected" || second.schema != "selected" {
		t.Fatal("PostgreSQL snapshot changed with constructor input")
	}

	sqlite := &SQLiteStore{store: &sqliteStore{db: db}}
	sqliteFirst, ok := snapshotStore(sqlite).(*sqliteStore)
	if !ok {
		t.Fatal("SQLite backend was not selected")
	}
	sqliteSecond, ok := snapshotStore(sqlite).(*sqliteStore)
	if !ok || sqliteFirst == sqliteSecond || sqliteFirst == sqlite.store {
		t.Fatal("SQLite backend was not independently snapshotted")
	}
	sqlite.store.db = nil
	if sqliteFirst.db != db || sqliteSecond.db != db {
		t.Fatal("SQLite snapshot changed with constructor input")
	}
}
