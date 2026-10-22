package browser

import (
	"encoding/json"

	"github.com/coreos/go-oidc/v3/oidc"
)

// AMR values are case-sensitive strings; duplicates are allowed. Invalid
// arrays are treated as absent as a whole, never partially projected.
func validAMRValue(value string) bool {
	if value == "" {
		return false
	}
	for _, b := range []byte(value) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func satisfiesAMR(methods []string, required string) bool {
	if required == "" {
		return true
	}
	// Also validate persisted legacy snapshots before interpreting any method.
	for _, value := range methods {
		if !validAMRValue(value) {
			return false
		}
	}
	for _, value := range methods {
		if value == required {
			return true
		}
	}
	return false
}

func verifiedAMR(id *oidc.IDToken) []string {
	var raw json.RawMessage
	if id.Claims(&raw) != nil {
		return nil
	}
	found := uniqueVerifiedClaim(raw, "amr", true)
	var values []string
	if json.Unmarshal(found, &values) != nil || len(values) == 0 {
		return nil
	}
	for _, value := range values {
		if !validAMRValue(value) {
			return nil
		}
	}
	return append([]string(nil), values...)
}
