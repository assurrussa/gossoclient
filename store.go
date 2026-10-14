package browser

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var errFenced = errors.New("session is no longer current")

// sessionStorage describes complete durable transitions, not SQL operations.
// Each backend owns its locking, timestamp and commit semantics. Callers must
// finish a transition before starting issuer HTTP and must not replay an
// exchange after an uncertain outcome.
type sessionStorage interface {
	ready(context.Context) error
	create(context.Context, string, string, time.Time) error
	load(context.Context, string) (session, error)
	begin(context.Context, *login) error
	claimLogin(context.Context, string, string) (login, error)
	installLogin(context.Context, login, identity, []byte) error
	claimRefresh(context.Context, session, string) (bool, error)
	installRefresh(context.Context, session, string, identity, []byte) error
	uncertain(context.Context, session, string) error
	end(context.Context, string, *int64) error
	endLocal(context.Context, session) error
	endBinding(context.Context, Binding) (session, error)
}

var _ sessionStorage = (*postgresStore)(nil)
var _ sessionStorage = (*sqliteStore)(nil)

type session struct {
		ID                          string
		Generation, LoginGeneration int64
		Status, CSRF                string
		Proof                       *identity
		FreshUntil, AbsoluteUntil   time.Time
		Cipher                      []byte
		RefreshState, Owner         string
}

type login struct {
	State, SessionID string
	Generation       int64
	Nonce            string
	Verifier         []byte
	ReturnPath       string
	Expires          time.Time
}

// storedProof records a local login lineage, independent of authority claims.
// Refresh preserves it; a new callback establishes a distinct lineage.
type storedProof struct {
	Identity
	LoginGeneration int64 `json:"loginGeneration,omitempty"`
}

// effectiveAbsolute also bounds legacy refresh attempts; a zero signed deadline
// never grants authority. Only proof/Check admit verified, nonzero deadlines.
func effectiveAbsolute(v session) time.Time {
	if v.Proof == nil {
		return time.Time{}
	}
	end := minTime(v.AbsoluteUntil, v.Proof.AbsoluteUntil)
	if !v.Proof.SessionExpiresAt.IsZero() {
		end = minTime(end, v.Proof.SessionExpiresAt)
	}
	return end
}

func (s session) binding() string { return fmt.Sprintf("refresh:%s:%d", s.ID, s.Generation) }
func (l login) binding() string   { return "login:" + l.State + ":" + l.SessionID }

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

func matchesBinding(v session, b Binding) bool {
	p := v.Proof
	return p != nil && b.LoginGeneration > 0 && b.LoginGeneration == v.LoginGeneration &&
		b.Generation >= b.LoginGeneration && b.Issuer == p.Issuer && b.Subject == p.Subject &&
		b.ProjectID == p.ProjectID && b.ClientID == p.ClientID && b.CentralSessionID == p.SessionID &&
		b.AuthTime == p.AuthTime && b.AbsoluteUntil.Equal(effectiveAbsolute(v)) &&
		!b.Deadline.IsZero() && !b.Deadline.After(b.AbsoluteUntil)
}

// A saved host logout may predate a committed legacy deadline upgrade. It may
// terminate descendants of that same login, never authorize them or end a new login.
func matchesLogoutBinding(v session, b Binding) bool {
	if matchesBinding(v, b) {
		return true
	}
	end := effectiveAbsolute(v)
	if v.Proof == nil || v.Proof.SessionExpiresAt.IsZero() || b.Generation >= v.Generation ||
		end.IsZero() || !end.Before(b.AbsoluteUntil) || b.Deadline.IsZero() || b.Deadline.After(b.AbsoluteUntil) {
		return false
	}
	b.AbsoluteUntil = end
	b.Deadline = minTime(b.Deadline, end)
	return matchesBinding(v, b)
}
