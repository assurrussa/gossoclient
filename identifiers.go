//nolint:tagliatelle // Signed AuthHub claim fields retain protocol snake_case.
package browser

import (
	"encoding/json"
	"regexp"
	"strings"
)

// CanonicalIdentifiers is an optional AuthHub-specific signed identity claim.
// Version 1 asserts that Login and EmailAlias come from the issuer's canonical,
// operator-administered account records, never arbitrary profile metadata.
// Login is case-sensitive. EmailAlias is lowercase and optional; it is a login
// alias, NOT proof of mailbox ownership or an email_verified assertion.
// These are current issuance snapshots, not immutable subject/session pins.
// Hosts may use them only under an explicit account-linking policy for their
// trusted issuer. They grant no local role or permission. Issuer/Subject remains
// the durable identity key; absence must never fall back to profile metadata.
type CanonicalIdentifiers struct {
	Version    int    `json:"version"`
	Login      string `json:"login"`
	EmailAlias string `json:"email_alias,omitempty"`
}

var canonicalLoginPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

var canonicalEmailAliasPattern = regexp.MustCompile(
	"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+([.][a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@" +
		"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$",
)

func validCanonicalIdentifiers(v *CanonicalIdentifiers) bool {
	if v == nil {
		return true
	}
	if v.Version != 1 || !canonicalLoginPattern.MatchString(v.Login) {
		return false
	}
	return v.EmailAlias == "" || (len(v.EmailAlias) <= 254 &&
		strings.IndexByte(v.EmailAlias, '@') <= 64 && canonicalEmailAliasPattern.MatchString(v.EmailAlias))
}

func cloneCanonicalIdentifiers(v *CanonicalIdentifiers) *CanonicalIdentifiers {
	if v == nil {
		return nil
	}
	cloned := *v
	return &cloned
}

func parseCanonicalIdentifiers(raw json.RawMessage) (*CanonicalIdentifiers, bool) {
	if len(raw) == 0 {
		return nil, true
	}
	var wire struct {
		Version    *int            `json:"version"`
		Login      *string         `json:"login"`
		EmailAlias json.RawMessage `json:"email_alias"`
	}
	if json.Unmarshal(raw, &wire) != nil || wire.Version == nil || wire.Login == nil {
		return nil, false
	}
	value := &CanonicalIdentifiers{Version: *wire.Version, Login: *wire.Login}
	if len(wire.EmailAlias) != 0 {
		var alias *string
		if json.Unmarshal(wire.EmailAlias, &alias) != nil || alias == nil {
			return nil, false
		}
		value.EmailAlias = *alias
	}
	return value, validCanonicalIdentifiers(value)
}
