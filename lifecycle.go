package browser

import (
	"context"
	"errors"
	"time"
)

// ErrRevocationUnconfirmed means local terminal state committed, but central
// revocation could not be confirmed. Never replay refresh or resurrect a binding.
var ErrRevocationUnconfirmed = errors.New("local logout committed; central revocation unconfirmed")

// RevokeBinding is intentional user logout, not session-replacement cleanup.
// It ends the current generation and refresh descendants of this same login.
// A subsequent login has a different LoginGeneration and cannot be revoked by
// this old binding, even when all central identity claims are unchanged.
// Expired freshness does not cancel logout intent. AbsoluteUntil is a pin.
// Unknown local commit returns ErrUnavailable; no automatic retry or remote
// revoke follows it. ErrRevocationUnconfirmed confirms local termination only.
// Caller must enforce logout request authentication and CSRF protection.
func (c *Client) RevokeBinding(ctx context.Context, b Binding) error {
	return c.endBinding(ctx, b)
}

func (c *Client) endBinding(parent context.Context, b Binding) error {
	a := c.app
	if b.Reference == "" || b.Generation <= 0 || b.LoginGeneration <= 0 ||
		b.Issuer != a.config.Issuer || b.ClientID != a.config.ClientID || b.ProjectID != a.config.ProjectID {
		return ErrDenied
	}
	// Complete bounded logout intent even if the incoming request disconnects.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	old, e := a.store.endBinding(ctx, b)
	cancel()
	if e != nil {
		return publicError(e)
	}
	secret, e := unseal(a.aead, old.Cipher, old.binding())
	if e != nil || secret == "" {
		return ErrRevocationUnconfirmed
	}
	ctx, cancel = context.WithTimeout(context.WithoutCancel(parent), 8*time.Second)
	defer cancel()
	if e = a.oidc.revoke(ctx, secret); e != nil {
		return ErrRevocationUnconfirmed
	}
	return nil
}
