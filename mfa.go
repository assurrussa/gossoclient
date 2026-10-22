//nolint:tagliatelle // The signed advisory claim retains its protocol spelling.
package browser

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/coreos/go-oidc/v3/oidc"
)

// MFAEnrollment is the optional signed authhub_mfa issuance snapshot. It is
// display-only: never use it as MFA proof, admission policy, or a session pin.
// Only a verified Identity from a currently valid Proof supplies this hint.
// Recheck through normal session renewal, not polling or a separate refresh.
// Setup links must use the application's explicitly configured trusted issuer.
type MFAEnrollment struct {
	Version        int  `json:"version"`
	Enrolled       bool `json:"enrolled"`
	SetupAvailable bool `json:"setup_available"`
}

// UnmarshalJSON keeps a malformed stored advisory hint from breaking an
// otherwise valid legacy identity. Version zero suppresses its projection.
func (v *MFAEnrollment) UnmarshalJSON(raw []byte) error {
	*v = MFAEnrollment{}
	if parsed := parseMFAEnrollment(raw); parsed != nil {
		*v = *parsed
	}
	return nil
}

func cloneMFAEnrollment(v *MFAEnrollment) *MFAEnrollment {
	if v == nil || v.Version != 1 {
		return nil
	}
	value := *v
	return &value
}

// Invalid, absent, duplicate, incomplete, or future claims are simply hidden.
// Explicit booleans prevent missing/null enrolled from becoming "not enrolled".
func parseMFAEnrollment(raw json.RawMessage) *MFAEnrollment {
	if len(raw) == 0 || len(raw) > 256 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil
	}
	fields := make(map[string]json.RawMessage, 3)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || (key != "version" && key != "enrolled" && key != "setup_available") {
			return nil
		}
		if _, duplicate := fields[key]; duplicate {
			return nil
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil || len(fields) != 3 {
		return nil
	}
	if _, err := d.Token(); err != io.EOF {
		return nil
	}
	var version *int
	var enrolled, available *bool
	if json.Unmarshal(fields["version"], &version) != nil || version == nil || *version != 1 ||
		json.Unmarshal(fields["enrolled"], &enrolled) != nil || enrolled == nil ||
		json.Unmarshal(fields["setup_available"], &available) != nil || available == nil {
		return nil
	}
	return &MFAEnrollment{Version: *version, Enrolled: *enrolled, SetupAvailable: *available}
}

// Read the already verified payload before JSON's last-key-wins decoding can
// erase an ambiguous outer advisory. All authentication claims keep their
// existing decoding and admission rules; ambiguity only hides this hint.
func verifiedMFAEnrollment(id *oidc.IDToken) *MFAEnrollment {
	var raw json.RawMessage
	if id.Claims(&raw) != nil {
		return nil
	}
	return parseMFAEnrollment(uniqueVerifiedClaim(raw, "authhub_mfa", false))
}
