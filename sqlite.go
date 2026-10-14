package browser

import (
	"context"
	"database/sql"
	"database/sql/driver"
	_ "embed"
	"encoding/json"
	"errors"
	"strings"
"fmt"
"regexp"
	"time"
)

//go:embed sqlite_schema.sql
var sqliteSchema string

// SQLiteSchema returns application-owned DDL. Apply it explicitly before
// construction. Configure durability and busy timeout on the application's
// connections; this package never changes PRAGMA settings or user_version.
// Timestamps are signed INTEGER Unix nanoseconds, never floating-point values.
func SQLiteSchema() string { return sqliteSchema }

// NewSQLiteStore validates existing tables without migrating or owning db.
// SQLite 3.35 or newer is required for UPDATE RETURNING.
func NewSQLiteStore(ctx context.Context, db *sql.DB) (*SQLiteStore, error) {
	if db == nil { return nil, errors.New("session database required") }
	backend := &sqliteStore{db: db}
	if err := backend.ready(ctx); err != nil { return nil, err }
	return &SQLiteStore{store: &store{db: db, sqlite: backend}}, nil
}

type sqliteStore struct { db *sql.DB }

func (s *sqliteStore) table(name string) string { return name }

func (s *sqliteStore) ready(ctx context.Context) error {
	for _, query := range []string{
		"SELECT cookie_digest, generation, status, csrf, proof, fresh_until, absolute_until, refresh_cipher, refresh_state, refresh_owner FROM sso_example_sessions LIMIT 0",
		"SELECT state_digest, cookie_digest, generation, nonce, verifier_cipher, return_path, expires_at, consumed FROM sso_example_logins LIMIT 0",
	} {
		rows, err := s.db.QueryContext(ctx, query)
		if err != nil { return err }
		if err = rows.Close(); err != nil { return err }
	}
	return nil
}

// BEGIN IMMEDIATE takes the write reservation before any deadline is sampled.
// One borrowed connection executes the entire transaction, including COMMIT;
// no operation obtains a second pool connection (MaxOpenConns(1) is supported).
type sqliteTx struct { conn *sql.Conn; done bool }

func (s *sqliteStore) beginImmediate(ctx context.Context) (*sqliteTx, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil { return nil, err }
	for {
		_, err = conn.ExecContext(ctx, "BEGIN IMMEDIATE")
		if err == nil { return &sqliteTx{conn: conn}, nil }
		var coded interface{ Code() int }
		if !errors.As(err, &coded) || (coded.Code()&255 != 5 && coded.Code()&255 != 6) {
			// A cancellation/driver error may leave the BEGIN outcome unknown.
			// Never return a possibly-open transaction to the caller's pool.
			_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			_ = conn.Close()
			return nil, err
		}
		timer := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = conn.Close()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (tx *sqliteTx) Commit(ctx context.Context) error {
	if tx.done { return sql.ErrTxDone }
	_, err := tx.conn.ExecContext(ctx, "COMMIT")
	if err != nil {
		// An unconfirmed commit is not retried. Cleanup never replays an exchange.
		_ = tx.Rollback()
		return err
	}
	tx.done = true
	return tx.conn.Close()
}

func (tx *sqliteTx) Rollback() error {
	if tx.done { return sql.ErrTxDone }
	tx.done = true
	// Request cancellation must not return an open transaction to the pool.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := tx.conn.ExecContext(ctx, "ROLLBACK")
	if err != nil {
		// Discard a connection whose transaction state cannot be confirmed.
		_ = tx.conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	closeErr := tx.conn.Close()
	if err != nil { return err }
	return closeErr
}

type sqliteRow struct { row *sql.Row; err error }

var sqliteParameter = regexp.MustCompile(`\$([0-9]+)`)

func sqliteQuery(query string, args []any) (string, []any, error) {
	values := make([]any, len(args), len(args)+1)
	for i, arg := range args {
		if value, ok := arg.(time.Time); ok {
			n := value.UnixNano()
			if !time.Unix(0, n).Equal(value) { return "", nil, errors.New("SQLite timestamp is outside nanosecond range") }
			values[i] = n
		} else { values[i] = arg }
	}
	query = sqliteParameter.ReplaceAllString(query, "?$1")
	query = strings.ReplaceAll(query, "LEAST(", "min(")
	if strings.Contains(query, "clock_timestamp()") {
		query = strings.ReplaceAll(query, "clock_timestamp()", fmt.Sprintf("?%d", len(values)+1))
		values = append(values, time.Now().UnixNano())
	}
	return query, values, nil
}

func (s *sqliteStore) execContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	query, args, err := sqliteQuery(query, args)
	if err != nil { return nil, err }
	return s.db.ExecContext(ctx, query, args...)
}
func (s *sqliteStore) queryRowContext(ctx context.Context, query string, args ...any) sqliteRow {
	query, args, err := sqliteQuery(query, args)
	if err != nil { return sqliteRow{err: err} }
	return sqliteRow{row: s.db.QueryRowContext(ctx, query, args...)}
}
func (tx *sqliteTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	query, args, err := sqliteQuery(query, args)
	if err != nil { return nil, err }
	return tx.conn.ExecContext(ctx, query, args...)
}
func (tx *sqliteTx) QueryRowContext(ctx context.Context, query string, args ...any) sqliteRow {
	query, args, err := sqliteQuery(query, args)
	if err != nil { return sqliteRow{err: err} }
	return sqliteRow{row: tx.conn.QueryRowContext(ctx, query, args...)}
}

// Scan uses exact integer database conversions. In particular neither generation,
// login lineage nor signed identity claims pass through map[string]any/float64.
func (row sqliteRow) Scan(dest ...any) error {
	if row.err != nil { return row.err }
	values := append([]any(nil), dest...)
	finish := make([]func(), 0)
	for i, target := range dest {
		switch out := target.(type) {
		case *time.Time:
			n := new(int64)
			values[i] = n
			finish = append(finish, func() { *out = time.Unix(0, *n).UTC() })
		case *sql.NullTime:
			n := new(sql.NullInt64)
			values[i] = n
			finish = append(finish, func() {
				*out = sql.NullTime{Valid: n.Valid}
				if n.Valid { out.Time = time.Unix(0, n.Int64).UTC() }
			})
		}
	}
	if err := row.row.Scan(values...); err != nil { return err }
	for _, apply := range finish { apply() }
	return nil
}

func loadSQLiteSession(row sqliteRow) (session, error) {
	var v session
	var proof []byte
	var fresh sql.NullTime
	if err := row.Scan(&v.ID, &v.Generation, &v.Status, &v.CSRF, &proof,
		&fresh, &v.AbsoluteUntil, &v.Cipher, &v.RefreshState, &v.Owner); err != nil {
		return session{}, err
	}
	v.FreshUntil = fresh.Time
	if len(proof) > 0 {
		var p storedProof
		if json.Unmarshal(proof, &p) != nil { return session{}, errors.New("invalid stored proof") }
		v.Proof = &p.Identity
		v.LoginGeneration = p.LoginGeneration
	}
	return v, nil
}
