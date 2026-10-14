package browser

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

func (s *sqliteStore) create(ctx context.Context, id, csrf string, until time.Time) error {
	// #nosec G202 -- Table names are fixed; arguments are bound.
	_, e := s.execContext(ctx, `
INSERT INTO `+s.table("sso_example_sessions")+`(cookie_digest, status, csrf, absolute_until) VALUES($1, 'pending', $2,
$3)
`, id, csrf, until)
	return e
}

func (s *sqliteStore) load(ctx context.Context, id string) (session, error) {
	// #nosec G202 -- Table names are fixed; arguments are bound.
	return loadSQLiteSession(s.queryRowContext(ctx, `
SELECT cookie_digest, generation, status, csrf, proof, fresh_until, absolute_until, refresh_cipher,
refresh_state, refresh_owner FROM `+s.table("sso_example_sessions")+` WHERE cookie_digest=$1
`, id))
}

func (s *sqliteStore) lockSession(ctx context.Context, tx *sqliteTx, id string) error {
	var locked string
	// #nosec G202 -- Table names are fixed; arguments are bound.
	e := tx.QueryRowContext(ctx, `
SELECT cookie_digest FROM `+s.table("sso_example_sessions")+` WHERE cookie_digest=$1
`, id).Scan(&locked)
	if errors.Is(e, sql.ErrNoRows) {
		return errFenced
	}
	return e
}

func (s *sqliteStore) begin(ctx context.Context, l *login) error {
	tx, e := s.beginImmediate(ctx)
	if e != nil {
		return e
	}
	//nolint:contextcheck // Rollback uses a fresh one-second context so canceled requests cannot leak a transaction.
	defer func() { _ = tx.Rollback() }()
	if e = s.lockSession(ctx, tx, l.SessionID); e != nil {
		return e
	}
	// Generation changes invalidate any old callback or in-flight refresh. An ended
	// browser row can never be reactivated; an explicit new browser session is needed.
	// #nosec G202 -- Table names are fixed; arguments are bound.
	e = tx.QueryRowContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET generation=generation+1, status='pending', proof=NULL, fresh_until=NULL,
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
	// #nosec G202 -- Table names are fixed; arguments are bound.
	_, e = tx.ExecContext(ctx, `
INSERT INTO `+s.table("sso_example_logins")+`(state_digest, cookie_digest, generation, nonce, verifier_cipher,
return_path, expires_at) VALUES($1, $2, $3, $4, $5, $6, $7)
`, l.State, l.SessionID, l.Generation, l.Nonce,
		l.Verifier, l.ReturnPath, l.Expires)
	if e != nil {
		return e
	}
	return tx.Commit(ctx) // An unknown commit is never retried.
}

func (s *sqliteStore) claimLogin(ctx context.Context, state, id string) (login, error) {
	tx, e := s.beginImmediate(ctx)
	if e != nil {
		return login{}, e
	}
	//nolint:contextcheck // Rollback uses a fresh one-second context so canceled requests cannot leak a transaction.
	defer func() { _ = tx.Rollback() }()
	if e = s.lockSession(ctx, tx, id); e != nil {
		return login{}, e
	}
	// Lock both rows before evaluating either deadline. A rollback by a previous
	// blocker does not guarantee re-evaluation of a SELECT/UPDATE time predicate.
	var locked string
	// #nosec G202 -- Table names are fixed; arguments are bound.
	e = tx.QueryRowContext(ctx, `
SELECT state_digest FROM `+s.table("sso_example_logins")+` WHERE state_digest=$1
`, state).Scan(&locked)
	if errors.Is(e, sql.ErrNoRows) {
		return login{}, errFenced
	}
	if e != nil {
		return login{}, e
	}
	var gen int64
	// #nosec G202 -- Table names are fixed; arguments are bound.
	e = tx.QueryRowContext(ctx, `
SELECT generation FROM `+s.table("sso_example_sessions")+` WHERE cookie_digest=$1 AND status='pending' AND
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
	// #nosec G202 -- Table names are fixed; arguments are bound.
	e = tx.QueryRowContext(ctx, `
UPDATE `+s.table("sso_example_logins")+` SET consumed=true WHERE state_digest=$1 AND cookie_digest=$2 AND generation=$3
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
	if e = tx.Commit(ctx); e != nil {
		return login{}, e
	}
	return l, nil
}

func (s *sqliteStore) installLogin(ctx context.Context, l login, p identity, cipher []byte) error {
	proof, e := json.Marshal(storedProof{Identity: p, LoginGeneration: l.Generation})
	if e != nil {
		return e
	}
	tx, e := s.beginImmediate(ctx)
	if e != nil {
		return e
	}
	//nolint:contextcheck // Rollback uses a fresh one-second context so canceled requests cannot leak a transaction.
	defer func() { _ = tx.Rollback() }()
	if e = s.lockSession(ctx, tx, l.SessionID); e != nil {
		return e
	}
	// #nosec G202 -- Table names are fixed; arguments are bound.
	result, e := tx.ExecContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET status='active', proof=$3, fresh_until=$4,
absolute_until=LEAST(absolute_until, $5), refresh_cipher=$6, refresh_state='ready', refresh_owner=''
WHERE cookie_digest=$1 AND generation=$2 AND status='pending' AND absolute_until>clock_timestamp() AND
$4>clock_timestamp() AND $7>clock_timestamp()
`, l.SessionID, l.Generation, proof,
		p.FreshUntil, p.AbsoluteUntil, cipher, l.Expires)
	if e = changed(result, e); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *sqliteStore) claimRefresh(ctx context.Context, v session, owner string) (bool, error) {
	tx, e := s.beginImmediate(ctx)
	if e != nil {
		return false, e
	}
	//nolint:contextcheck // Rollback uses a fresh one-second context so canceled requests cannot leak a transaction.
	defer func() { _ = tx.Rollback() }()
	if e = s.lockSession(ctx, tx, v.ID); e != nil {
		return false, e
	}
	// #nosec G202 -- Table names are fixed; arguments are bound.
	result, e := tx.ExecContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET refresh_state='claimed', refresh_owner=$3 WHERE cookie_digest=$1 AND
generation=$2 AND status='active' AND refresh_state='ready' AND absolute_until>clock_timestamp()
`, v.ID, v.Generation, owner)
	if e != nil {
		return false, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return false, e
	}
	if e = tx.Commit(ctx); e != nil {
		return false, e
	}
	return n == 1, nil
}

func (s *sqliteStore) installRefresh(ctx context.Context, v session, owner string, p identity, cipher []byte) error {
	proof, e := json.Marshal(storedProof{Identity: p, LoginGeneration: v.LoginGeneration})
	if e != nil {
		return e
	}
	tx, e := s.beginImmediate(ctx)
	if e != nil {
		return e
	}
	//nolint:contextcheck // Rollback uses a fresh one-second context so canceled requests cannot leak a transaction.
	defer func() { _ = tx.Rollback() }()
	if e = s.lockSession(ctx, tx, v.ID); e != nil {
		return e
	}
	// #nosec G202 -- Table names are fixed; arguments are bound.
	result, e := tx.ExecContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET generation=generation+1, proof=$4, fresh_until=$5, refresh_cipher=$6,
absolute_until=LEAST(absolute_until, $7), refresh_state='ready', refresh_owner=''
WHERE cookie_digest=$1 AND generation=$2 AND refresh_owner=$3 AND
refresh_state='claimed' AND status='active' AND absolute_until>clock_timestamp() AND $5>clock_timestamp() AND $7>clock_timestamp()
`, v.ID, v.Generation, owner, proof, p.FreshUntil, cipher, p.AbsoluteUntil)
	if e = changed(result, e); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *sqliteStore) uncertain(ctx context.Context, v session, owner string) error {
	// No lease expiry may turn claimed/uncertain into ready with the old secret.
	// #nosec G202 -- Table names are fixed; arguments are bound.
	result, e := s.execContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET refresh_state='uncertain', refresh_cipher=NULL, refresh_owner='' WHERE
cookie_digest=$1 AND generation=$2 AND refresh_owner=$3 AND refresh_state='claimed' AND status='active'
`, v.ID, v.Generation, owner)
	return changed(result, e)
}

func (s *sqliteStore) end(ctx context.Context, id string, expected *int64) error {
	tx, e := s.beginImmediate(ctx)
	if e != nil {
		return e
	}
	//nolint:contextcheck // Rollback uses a fresh one-second context so canceled requests cannot leak a transaction.
	defer func() { _ = tx.Rollback() }()
	var v session
	// #nosec G202 -- Table names are fixed; arguments are bound.
	e = tx.QueryRowContext(ctx, `
SELECT cookie_digest, generation, refresh_cipher FROM `+s.table("sso_example_sessions")+` WHERE cookie_digest=$1
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
	// #nosec G202 -- Table names are fixed; arguments are bound.
	_, e = tx.ExecContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET generation=generation+1, status='ended', proof=NULL, fresh_until=NULL,
refresh_cipher=NULL, refresh_state='none', refresh_owner='' WHERE cookie_digest=$1
`, id)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

func (s *sqliteStore) endLocal(ctx context.Context, v session) error {
	// #nosec G202 -- Table names are fixed; arguments are bound.
	result, e := s.execContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET generation=generation+1, status='ended', proof=NULL, fresh_until=NULL,
refresh_cipher=NULL, refresh_state='none', refresh_owner='' WHERE cookie_digest=$1 AND generation=$2
AND status=$3 AND status<>'active'
`, v.ID, v.Generation, v.Status)
	return changed(result, e)
}

func (s *sqliteStore) endBinding(ctx context.Context, b Binding) (session, error) {
	tx, e := s.beginImmediate(ctx)
	if e != nil {
		return session{}, e
	}
	//nolint:contextcheck // Rollback uses a fresh one-second context so canceled requests cannot leak a transaction.
	defer func() { _ = tx.Rollback() }()
	// #nosec G202 -- Table names are fixed; arguments are bound.
	v, e := loadSQLiteSession(tx.QueryRowContext(ctx, `
SELECT cookie_digest, generation, status, csrf, proof, fresh_until, absolute_until, refresh_cipher,
refresh_state, refresh_owner FROM `+s.table("sso_example_sessions")+` WHERE cookie_digest=$1
`, b.Reference))
	if e != nil {
		return session{}, e
	}
	if v.Status != sessionActive || !matchesLogoutBinding(v, b) || b.Generation > v.Generation {
		return session{}, errFenced
	}
	// #nosec G202 -- Table names are fixed; arguments are bound.
	result, e := tx.ExecContext(ctx, `
UPDATE `+s.table("sso_example_sessions")+` SET generation=generation+1, status='ended', proof=NULL, fresh_until=NULL,
refresh_cipher=NULL, refresh_state='none', refresh_owner='' WHERE cookie_digest=$1 AND generation=$2
`, v.ID, v.Generation)
	if e = changed(result, e); e != nil {
		return session{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return session{}, e
	}
	return v, nil
}
