//nolint:goconst // Explicit wire values make the parsing boundary table readable.
package browser

import (
	"encoding/json"
	"testing"
)

func TestUniqueVerifiedClaimBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name       string
		raw        string
		claim      string
		strictName bool
		want       string
	}{
		{"amr_exact", `{"amr":["mfa"]}`, "amr", true, `["mfa"]`},
		{"amr_absent", `{}`, "amr", true, ""},
		{"amr_null", `{"amr":null}`, "amr", true, `null`},
		{"amr_empty", `{"amr":[]}`, "amr", true, `[]`},
		{"amr_wrong_type", `{"amr":"mfa"}`, "amr", true, `"mfa"`},
		{"amr_alias", `{"AMR":["mfa"]}`, "amr", true, ""},
		{"amr_duplicate", `{"amr":null,"amr":["mfa"]}`, "amr", true, ""},
		{"amr_alias_duplicate", `{"amr":["mfa"],"AMR":["mfa"]}`, "amr", true, ""},
		{"mfa_alias", `{"AUTHHUB_MFA":{"version":1}}`, "authhub_mfa", false, `{"version":1}`},
		{"mfa_null", `{"authhub_mfa":null}`, "authhub_mfa", false, `null`},
		{"mfa_duplicate", `{"authhub_mfa":null,"AUTHHUB_MFA":{}}`, "authhub_mfa", false, ""},
		{"malformed", `{"amr":[`, "amr", true, ""},
		{"trailing_value", `{"amr":["mfa"]} true`, "amr", true, ""},
		{"non_object", `[]`, "amr", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := uniqueVerifiedClaim(json.RawMessage(tc.raw), tc.claim, tc.strictName)
			if string(got) != tc.want {
				t.Fatalf("claim = %q, want %q", got, tc.want)
			}
		})
	}
}
