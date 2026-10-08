package browser

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

//go:embed schema.sql
var schema string
var errFenced = errors.New("session is no longer current")

type (
	store   struct{ db *sql.DB }
	session struct {
		ID                          string
		Generation, LoginGeneration int64
		Status, CSRF                string
		Proof                       *identity
		FreshUntil, AbsoluteUntil   time.Time
		Cipher                      []byte
		RefreshState, Owner         string
	}
)

type login struct {
	State, SessionID string
	Generation       int64
	Nonce            string
	Verifier         []byte
	ReturnPath       string
	Expires          time.Time
}

func (s session) binding() string { return fmt.Sprintf("refresh:%s:%d", s.ID, s.Generation) }
func (l login) binding() string   { return "login:" + l.State + ":" + l.SessionID }

func (s *store) ready(ctx context.Context) error {
	// Fail closed on missing/partial schema; startup does not perform migrations.
	var ok bool
	e := s.db.QueryRowContext(ctx, `
SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND
table_name='sso_example_sessions' AND column_name='refresh_owner') AND EXISTS(SELECT 1 FROM
information_schema.columns WHERE table_schema=current_schema() AND table_name='sso_example_logins' AND
column_name='verifier_cipher')
`).Scan(
		&ok)
	if e != nil {
		return e
	}
	if !ok {
		return errors.New("apply the app-owned schema.sql before startup")
	}
	_, e = s.db.ExecContext(ctx, `
SELECT cookie_digest, generation, status, csrf, proof, fresh_until, absolute_until, refresh_cipher,
refresh_state, refresh_owner FROM sso_example_sessions LIMIT 0
`)
	return e
}

func (s *store) create(ctx context.Context, id, csrf string, until time.Time) error {
	_, e := s.db.ExecContext(ctx, `
INSERT INTO sso_example_sessions(cookie_digest, status, csrf, absolute_until) VALUES($1, 'pending', $2,
$3)
`, id, csrf, until)
	return e
}

// storedProof records a local login lineage, independent of authority claims.
// Refresh preserves it; a new callback establishes a distinct lineage.
type storedProof struct {
	Identity
	LoginGeneration int64 `json:"loginGeneration,omitempty"`
}

func (s *store) load(ctx context.Context, id string) (session, error) {
	return loadSession(s.db.QueryRowContext(ctx, `
SELECT cookie_digest, generation, status, csrf, proof, fresh_until, absolute_until, refresh_cipher,
refresh_state, refresh_owner FROM sso_example_sessions WHERE cookie_digest=$1
`, id))
}

func loadSession(row *sql.Row) (session, error) {
	var v session
	var proof []byte
	var fresh sql.NullTime
	e := row.Scan(
		&v.ID,
		&v.Generation,
		&v.Status,
		&v.CSRF,
		&proof,
		&fresh,
		&v.AbsoluteUntil,
		&v.Cipher,
		&v.RefreshState,
		&v.Owner)
	if e != nil {
		return session{}, e
	}
	v.FreshUntil = fresh.Time
	if len(proof) > 0 {
		var p storedProof
		if json.Unmarshal(proof,
			&p) != nil {
			return session{}, errors.New("invalid stored proof")
		}
		v.Proof = &p.Identity
		v.LoginGeneration = p.LoginGeneration
	}
	return v, nil
}

func lockSession(ctx context.Context, tx *sql.Tx, id string) error {
	var locked string
	e := tx.QueryRowContext(ctx, `
SELECT cookie_digest FROM sso_example_sessions WHERE cookie_digest=$1 FOR UPDATE
`, id).Scan(&locked)
	if errors.Is(e, sql.ErrNoRows) {
		return errFenced
	}
	return e
}

func (s *store) begin(ctx context.Context, l *login) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer func() { _ = tx.Rollback() }()
	if e = lockSession(ctx, tx, l.SessionID); e != nil {
		return e
	}
	// Generation changes invalidate any old callback or in-flight refresh. An ended
	// browser row can never be reactivated; an explicit new browser session is needed.
	e = tx.QueryRowContext(ctx, `
UPDATE sso_example_sessions SET generation=generation+1, status='pending', proof=NULL, fresh_until=NULL,
refresh_cipher=NULL, refresh_state='none', refresh_owner='' WHERE cookie_digest=$1 AND status<>'ended'
AND absolute_until>clock_timestamp() AND $2>clock_timestamp() RETURNING generation
`, l.SessionID, l.Expires).Scan(
		&l.Generation)
	if errors.Is(e, sql.ErrNoRows) {
		return errFenced
	}
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, `
INSERT INTO sso_example_logins(state_digest, cookie_digest, generation, nonce, verifier_cipher,
return_path, expires_at) VALUES($1, $2, $3, $4, $5, $6, $7)
`, l.State, l.SessionID, l.Generation, l.Nonce,
		l.Verifier, l.ReturnPath, l.Expires)
	if e != nil {
		return e
	}
	return tx.Commit() // An unknown commit is never retried.
}

func (s *store) claimLogin(ctx context.Context, state, id string) (login, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return login{}, e
	}
	defer func() { _ = tx.Rollback() }()
	if e = lockSession(ctx, tx, id); e != nil {
		return login{}, e
	}
	// Lock both rows before evaluating either deadline. A rollback by a previous
	// blocker does not guarantee re-evaluation of a SELECT/UPDATE time predicate.
	var locked string
	e = tx.QueryRowContext(ctx, `SELECT state_digest FROM sso_example_logins WHERE state_digest=$1 FOR UPDATE`, state).Scan(&locked)
	if errors.Is(e, sql.ErrNoRows) {
		return login{}, errFenced
	}
	if e != nil {
		return login{}, e
	}
	var gen int64
	e = tx.QueryRowContext(ctx, `
SELECT generation FROM sso_example_sessions WHERE cookie_digest=$1 AND status='pending' AND
absolute_until>clock_timestamp()
`, id).Scan(
		&gen)
	if errors.Is(e, sql.ErrNoRows) {
		return login{}, errFenced
	}
	if e != nil {
		return login{}, e
	}
	var l login
	e = tx.QueryRowContext(ctx, `
UPDATE sso_example_logins SET consumed=true WHERE state_digest=$1 AND cookie_digest=$2 AND generation=$3
AND NOT consumed AND expires_at>clock_timestamp() RETURNING state_digest, cookie_digest, generation,
nonce, verifier_cipher, return_path, expires_at
`, state, id, gen).Scan(
		&l.State,
		&l.SessionID,
		&l.Generation,
		&l.Nonce,
		&l.Verifier,
		&l.ReturnPath,
		&l.Expires)
	if errors.Is(e, sql.ErrNoRows) {
		return login{}, errFenced
	}
	if e != nil {
		return login{}, e
	}
	if e = tx.Commit(); e != nil {
		return login{}, e
	}
	return l, nil
}

func (s *store) installLogin(ctx context.Context, l login, p identity, cipher []byte) error {
	proof, e := json.Marshal(storedProof{Identity: p, LoginGeneration: l.Generation})
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer func() { _ = tx.Rollback() }()
	if e = lockSession(ctx, tx, l.SessionID); e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, `
UPDATE sso_example_sessions SET status='active', proof=$3, fresh_until=$4,
absolute_until=LEAST(absolute_until, $5), refresh_cipher=$6, refresh_state='ready', refresh_owner=''
WHERE cookie_digest=$1 AND generation=$2 AND status='pending' AND absolute_until>clock_timestamp() AND
$4>clock_timestamp() AND $7>clock_timestamp()
`, l.SessionID, l.Generation, proof,
		p.FreshUntil, p.AbsoluteUntil, cipher, l.Expires)
	if e = changed(result, e); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *store) claimRefresh(ctx context.Context, v session, owner string) (bool, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return false, e
	}
	defer func() { _ = tx.Rollback() }()
	if e = lockSession(ctx, tx, v.ID); e != nil {
		return false, e
	}
	result, e := tx.ExecContext(ctx, `
UPDATE sso_example_sessions SET refresh_state='claimed', refresh_owner=$3 WHERE cookie_digest=$1 AND
generation=$2 AND status='active' AND refresh_state='ready' AND absolute_until>clock_timestamp()
`, v.ID, v.Generation, owner)
	if e != nil {
		return false, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return false, e
	}
	if e = tx.Commit(); e != nil {
		return false, e
	}
	return n == 1, nil
}

func (s *store) installRefresh(ctx context.Context, v session, owner string, p identity, cipher []byte) error {
	proof, e := json.Marshal(storedProof{Identity: p, LoginGeneration: v.LoginGeneration})
	if e != nil {
		return e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer func() { _ = tx.Rollback() }()
	if e = lockSession(ctx, tx, v.ID); e != nil {
		return e
	}
	result, e := tx.ExecContext(ctx, `
UPDATE sso_example_sessions SET generation=generation+1, proof=$4, fresh_until=$5, refresh_cipher=$6,
refresh_state='ready', refresh_owner='' WHERE cookie_digest=$1 AND generation=$2 AND refresh_owner=$3 AND
refresh_state='claimed' AND status='active' AND absolute_until>clock_timestamp() AND $5>clock_timestamp()
`, v.ID, v.Generation, owner, proof, p.FreshUntil, cipher)
	if e = changed(result, e); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *store) uncertain(ctx context.Context, v session, owner string) error {
	// No lease expiry may turn claimed/uncertain into ready with the old secret.
	result, e := s.db.ExecContext(ctx, `
UPDATE sso_example_sessions SET refresh_state='uncertain', refresh_cipher=NULL, refresh_owner='' WHERE
cookie_digest=$1 AND generation=$2 AND refresh_owner=$3 AND refresh_state='claimed' AND status='active'
`, v.ID, v.Generation, owner)
	return changed(result, e)
}

func (s *store) end(ctx context.Context, id string, expected *int64) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer func() { _ = tx.Rollback() }()
	var v session
	e = tx.QueryRowContext(ctx, `
SELECT cookie_digest, generation, refresh_cipher FROM sso_example_sessions WHERE cookie_digest=$1 FOR
UPDATE
`, id).Scan(
		&v.ID,
		&v.Generation,
		&v.Cipher)
	if e != nil {
		return e
	}
	if expected != nil && v.Generation != *expected {
		return errFenced
	}
	_, e = tx.ExecContext(ctx, `
UPDATE sso_example_sessions SET generation=generation+1, status='ended', proof=NULL, fresh_until=NULL,
refresh_cipher=NULL, refresh_state='none', refresh_owner='' WHERE cookie_digest=$1
`, id)
	if e != nil {
		return e
	}
	return tx.Commit()
}

// endLocal ends only the original non-active browser state. Callback installs
// active state at the pending generation, so generation alone cannot fence it.
func (s *store) endLocal(ctx context.Context, v session) error {
	result, e := s.db.ExecContext(ctx, `
UPDATE sso_example_sessions SET generation=generation+1, status='ended', proof=NULL, fresh_until=NULL,
refresh_cipher=NULL, refresh_state='none', refresh_owner='' WHERE cookie_digest=$1 AND generation=$2
AND status=$3 AND status<>'active'
`, v.ID, v.Generation, v.Status)
	return changed(result, e)
}

func changed(result sql.Result, e error) error {
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return errFenced
	}
	return nil
}

// endBinding checks the complete admission while holding the same row lock used
// by refresh installation. No network operation occurs inside this transaction.
func (s *store) endBinding(ctx context.Context, b Binding) (session, error) {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return session{}, e
	}
	defer func() { _ = tx.Rollback() }()
	v, e := loadSession(tx.QueryRowContext(ctx, `
SELECT cookie_digest, generation, status, csrf, proof, fresh_until, absolute_until, refresh_cipher,
refresh_state, refresh_owner FROM sso_example_sessions WHERE cookie_digest=$1 FOR UPDATE
`, b.Reference))
	if e != nil {
		return session{}, e
	}
	if v.Status != sessionActive || !matchesBinding(v, b) || b.Generation > v.Generation {
		return session{}, errFenced
	}
	result, e := tx.ExecContext(ctx, `
UPDATE sso_example_sessions SET generation=generation+1, status='ended', proof=NULL, fresh_until=NULL,
refresh_cipher=NULL, refresh_state='none', refresh_owner='' WHERE cookie_digest=$1 AND generation=$2
`, v.ID, v.Generation)
	if e = changed(result, e); e != nil {
		return session{}, e
	}
	if e = tx.Commit(); e != nil {
		return session{}, e
	}
	return v, nil
}

func matchesBinding(v session, b Binding) bool {
	p := v.Proof
	return p != nil && b.LoginGeneration > 0 && b.LoginGeneration == v.LoginGeneration &&
		b.Generation >= b.LoginGeneration && b.Issuer == p.Issuer && b.Subject == p.Subject &&
		b.ProjectID == p.ProjectID && b.ClientID == p.ClientID && b.CentralSessionID == p.SessionID &&
		b.AuthTime == p.AuthTime && b.AbsoluteUntil.Equal(minTime(v.AbsoluteUntil, p.AbsoluteUntil)) &&
		!b.Deadline.IsZero() && !b.Deadline.After(b.AbsoluteUntil)
}
