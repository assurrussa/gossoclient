package browser

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const (
	conformanceNonce               = "nonce"
	conformancePostgresBackend     = "postgres"
	conformanceSQLiteSingleBackend = "sqlite-one-connection"
	conformanceSQLitePoolBackend = "sqlite-pool"
	conformanceState               = "state"
	pendingSessionStatus           = "pending"
)

// The conformance fixture owns its test pool separately from the behavioral
// contract. Database handles are not part of production sessionStorage.
type conformanceStore struct {
	sessionStorage
	db *sql.DB
}

func testSQLiteStore(t *testing.T, maxOpen int) (*sqliteStore, func() *sqliteStore) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	open := func() *sqliteStore {
		db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(maxOpen)
		t.Cleanup(func() { _ = db.Close() })
		return &sqliteStore{db: db}
	}
	s := open()
	if _, err := s.db.ExecContext(t.Context(), SQLiteSchema()); err != nil {
		t.Fatal(err)
	}
	selected, err := NewSQLiteStore(t.Context(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	return selected.store, open
}

func conformanceApp(t *testing.T, s sessionStorage) (*app, *authority) {
	t.Helper()
	p := newAuthority(t)
	client := p.client(t, time.Now)
	aead, err := newAEAD(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return &app{
		config: client.config, oidc: client, store: s, aead: aead,
		now: time.Now, slots: make(chan struct{}, 32), render: testRender,
	}, p
}

func testConformanceStore(t *testing.T, backend string) (conformanceStore, func() conformanceStore) {
	t.Helper()
	if backend == conformancePostgresBackend {
		s, reopen := testStore(t)
		return conformanceStore{sessionStorage: s, db: s.db}, func() conformanceStore {
			next := reopen()
			return conformanceStore{sessionStorage: next, db: next.db}
		}
	}
	maxOpen := 8
	if backend == conformanceSQLiteSingleBackend {
		maxOpen = 1
	}
	s, reopen := testSQLiteStore(t, maxOpen)
	return conformanceStore{sessionStorage: s, db: s.db}, func() conformanceStore {
		next := reopen()
		return conformanceStore{sessionStorage: next, db: next.db}
	}
}

func TestStoreConformance(t *testing.T) {
	for _, backend := range []string{conformancePostgresBackend, conformanceSQLiteSingleBackend, conformanceSQLitePoolBackend} {
		t.Run(backend, func(t *testing.T) {
			t.Run("login-restart-one-use", func(t *testing.T) {
				testConformanceLoginRestart(t, backend)
			})
			t.Run("concurrent-refresh-and-restart", func(t *testing.T) {
				testConformanceConcurrentRefresh(t, backend)
			})
			t.Run("lost-refresh-never-retried", func(t *testing.T) {
				testConformanceLostRefresh(t, backend)
			})
			t.Run("logout-fences-delayed-refresh", func(t *testing.T) {
				testConformanceLogoutFence(t, backend)
			})
			t.Run("exact-generation", func(t *testing.T) {
				testConformanceExactGeneration(t, backend)
			})
		})
	}
}

func testConformanceLoginRestart(t *testing.T, backend string) {
	t.Helper()
	s, reopen := testConformanceStore(t, backend)
	a, p := conformanceApp(t, s)
	cookie, state := startLogin(t, a, p)
	if err := s.db.Close(); err != nil {
		t.Fatal(err)
	}
	a.store = reopen()
	if w := callback(a, cookie, state); w.Code != http.StatusSeeOther {
		t.Fatalf("callback: %d", w.Code)
	}
	if w := callback(a, cookie, state); w.Code != http.StatusBadRequest {
		t.Fatal("replayed callback")
	}
	if p.calls.Load() != 1 {
		t.Fatal("repeated code exchange")
	}
}

func testConformanceConcurrentRefresh(t *testing.T, backend string) {
	t.Helper()
	const claimedRefreshState = "claimed"
	s, reopen := testConformanceStore(t, backend)
	a, p := conformanceApp(t, s)
	_, v := signedIn(t, a, p)
	// A short but still valid deadline forces refresh without backend-specific SQL.
	a.now = func() time.Time { return v.FreshUntil.Add(-time.Second) }
	release := delayTokens(p)
	results := make(chan error, 8)
	for range 8 {
		go func() { _, err := a.authorize(t.Context(), v); results <- err }()
	}
	awaitToken(t, p.arrived)
	other := *a
	other.store = reopen()
	current, err := other.store.load(t.Context(), v.ID)
	if err != nil || current.RefreshState != claimedRefreshState {
		t.Fatal("claim not durable", err)
	}
	if _, err = other.authorize(t.Context(), current); !errors.Is(err, errRefreshPending) {
		t.Fatal("restarted owner retried", err)
	}
	release()
	for range 8 {
		err = <-results
		if err != nil && !errors.Is(err, errRefreshPending) {
			t.Fatal(err)
		}
	}
	if p.calls.Load() != 2 {
		t.Fatal("refresh secret reused", p.calls.Load())
	}
	current, err = s.load(t.Context(), v.ID)
	if err != nil || current.Generation != v.Generation+1 {
		t.Fatal("rotation missing", err)
	}
}

func testConformanceLostRefresh(t *testing.T, backend string) {
	t.Helper()
	s, reopen := testConformanceStore(t, backend)
	a, p := conformanceApp(t, s)
	_, v := signedIn(t, a, p)
	a.now = func() time.Time { return v.FreshUntil.Add(-time.Second) }
	const lostResponseMode = "lost"
	p.mode = lostResponseMode
	current, err := a.authorize(t.Context(), v)
	if err != nil || current.RefreshState != "uncertain" || len(current.Cipher) != 0 {
		t.Fatal("uncertain outcome retained secret", err)
	}
	if err = s.db.Close(); err != nil {
		t.Fatal(err)
	}
	a.store = reopen()
	for range 3 {
		if _, err = a.authorize(t.Context(), current); err != nil {
			t.Fatal(err)
		}
	}
	a.now = func() time.Time { return v.FreshUntil }
	if _, err = a.authorize(t.Context(), current); err == nil {
		t.Fatal("expired proof authorized")
	}
	if p.calls.Load() != 2 {
		t.Fatal("uncertain secret retried")
	}
}

func testConformanceLogoutFence(t *testing.T, backend string) {
	t.Helper()
	const endedSessionStatus = "ended"
	s, _ := testConformanceStore(t, backend)
	a, p := conformanceApp(t, s)
	_, v := signedIn(t, a, p)
	a.now = func() time.Time { return v.FreshUntil.Add(-time.Second) }
	release := delayTokens(p)
	done := make(chan error, 1)
	go func() { _, err := a.authorize(t.Context(), v); done <- err }()
	awaitToken(t, p.arrived)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	// This must complete while issuer HTTP is blocked, including a one-connection pool.
	if err := s.end(ctx, v.ID, &v.Generation); err != nil {
		t.Fatal(err)
	}
	release()
	if err := <-done; err == nil {
		t.Fatal("late refresh authorized")
	}
	current, err := s.load(t.Context(), v.ID)
	if err != nil || current.Status != endedSessionStatus || current.Proof != nil {
		t.Fatal("session resurrected", err)
	}
}

func testConformanceExactGeneration(t *testing.T, backend string) {
	t.Helper()
	s, _ := testConformanceStore(t, backend)
	ctx := t.Context()
	until := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	if err := s.create(ctx, "large", "csrf", until); err != nil {
		t.Fatal(err)
	}
	const large int64 = 9007199254740993
	_, err := s.db.ExecContext(ctx, "UPDATE sso_example_sessions SET generation=$1 WHERE cookie_digest=$2", large, "large")
	if err != nil {
		t.Fatal(err)
	}
	l := login{
		State: conformanceState, SessionID: "large", Nonce: conformanceNonce,
		Verifier: []byte("cipher"), ReturnPath: "/", Expires: until,
	}
	if err := s.begin(ctx, &l); err != nil {
		t.Fatal(err)
	}
	if l.Generation != large+1 {
		t.Fatal("generation rounded")
	}
	claimed, err := s.claimLogin(ctx, l.State, l.SessionID)
	if err != nil || claimed.Generation != large+1 {
		t.Fatal("claim rounded", err)
	}
}

func TestSQLiteWaitThenExpire(t *testing.T) {
	const expiredSessionID = "expired"
	s, _ := testSQLiteStore(t, 2)
	until := time.Now().Add(150 * time.Millisecond)
	if err := s.create(t.Context(), expiredSessionID, "csrf", until); err != nil {
		t.Fatal(err)
	}
	blocker, err := s.beginImmediate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blocker.Rollback() }()
	done := make(chan error, 1)
	go func() {
		l := login{
			State: conformanceState, SessionID: expiredSessionID, Nonce: "n",
			Verifier: []byte("v"), ReturnPath: "/", Expires: until,
		}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		done <- s.begin(ctx, &l)
	}()
	time.Sleep(time.Until(until.Add(30 * time.Millisecond)))
	if err = blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, errFenced) {
		t.Fatal("pre-lock timestamp revived session", err)
	}
}

func TestSQLiteSchemaOwnershipAndValidation(t *testing.T) {
	if _, err := NewSQLiteStore(t.Context(), nil); err == nil {
		t.Fatal("nil accepted")
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "owned.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(1)
	if _, err = NewSQLiteStore(t.Context(), db); err == nil {
		t.Fatal("missing schema accepted")
	}
	if _, err = db.ExecContext(t.Context(), SQLiteSchema()); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(t.Context(), "PRAGMA user_version=42"); err != nil {
		t.Fatal(err)
	}
	store, err := NewSQLiteStore(t.Context(), db)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err = db.QueryRowContext(t.Context(), "PRAGMA user_version").Scan(&version); err != nil || version != 42 {
		t.Fatal("version changed", err)
	}
	snapshot := store.sessionStore()
	store.store.db = nil
	selected, ok := snapshot.(*sqliteStore)
	if !ok || selected.db != db || db.Stats().MaxOpenConnections != 1 {
		t.Fatal("snapshot or pool ownership changed")
	}
	if err = snapshot.create(t.Context(), "nano", "csrf", time.Unix(1800000000, 123456789)); err != nil {
		t.Fatal(err)
	}
	v, err := snapshot.load(t.Context(), "nano")
	if err != nil || v.AbsoluteUntil.Nanosecond() != 123456789 {
		t.Fatal("nanoseconds rounded", err)
	}
	var absent *SQLiteStore
	for _, value := range []Store{nil, absent, &SQLiteStore{}} {
		if validStore(value) {
			t.Fatal("nil/zero accepted")
		}
	}
}

func TestSQLiteParameterOrder(t *testing.T) {
	query, args, err := sqliteQuery("SELECT $3, $1, $3, clock_timestamp(), LEAST($2,$1)", []any{"first", "second", "third"})
	if err != nil || query != "SELECT ?3, ?1, ?3, ?4, min(?2,?1)" || len(args) != 4 {
		t.Fatal(query, args, err)
	}
}

func TestSQLiteConcurrentClaims(t *testing.T) {
	s, reopen := testSQLiteStore(t, 8)
	if err := s.create(t.Context(), "browser", "csrf", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	l := login{
		State: conformanceState, SessionID: "browser", Nonce: conformanceNonce,
		Verifier: []byte("verifier"), ReturnPath: "/", Expires: time.Now().Add(time.Minute),
	}
	if err := s.begin(t.Context(), &l); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 16)
	var wg sync.WaitGroup
	other := reopen()
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			target := s
			if i%2 != 0 {
				target = other
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err := target.claimLogin(ctx, l.State, l.SessionID)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, errFenced) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatal("claim winners", winners)
	}
}

func TestSQLiteGenerationOverflowFailsClosed(t *testing.T) {
	s, _ := testSQLiteStore(t, 1)
	if err := s.create(t.Context(), "max", "csrf", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(t.Context(), "UPDATE sso_example_sessions SET generation=9223372036854775807"); err != nil {
		t.Fatal(err)
	}
	l := login{
		State: conformanceState, SessionID: "max", Nonce: "n",
		Verifier: []byte("v"), ReturnPath: "/", Expires: time.Now().Add(time.Minute),
	}
	if err := s.begin(t.Context(), &l); err == nil {
		t.Fatal("integer overflow accepted")
	}
	v, err := s.load(t.Context(), "max")
	if err != nil || strconv.FormatInt(v.Generation, 10) != "9223372036854775807" {
		t.Fatal("overflow changed generation", err)
	}
	if strings.Contains(SQLiteSchema(), "user_version=") {
		t.Fatal("schema changes application migration version")
	}
}

type embeddedStoreForTest struct{ Store }

func TestStoreRejectsPromotedImplementations(t *testing.T) {
	var absent *embeddedStoreForTest
	for _, value := range []Store{absent, &embeddedStoreForTest{}, &embeddedStoreForTest{Store: optionTestStore()}} {
		if validStore(value) {
			t.Fatal("non-package concrete store accepted")
		}
	}
}

func TestSQLiteCancelledWriterDoesNotLeakConnection(t *testing.T) {
	s, _ := testSQLiteStore(t, 1)
	ctx, cancel := context.WithCancel(t.Context())
	tx, err := s.beginImmediate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if err = tx.Commit(ctx); err == nil {
		t.Fatal("cancelled commit succeeded")
	}
	ctx, stop := context.WithTimeout(t.Context(), 3*time.Second)
	defer stop()
	if err = s.create(ctx, "after-cancel", "csrf", time.Now().Add(time.Hour)); err != nil {
		t.Fatal("connection leaked", err)
	}
	v, err := s.load(ctx, "after-cancel")
	if err != nil || v.Status != pendingSessionStatus {
		t.Fatal("pool unusable after cancel", err)
	}
}
