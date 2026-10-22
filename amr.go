package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

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
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil
	}
	var found json.RawMessage
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil
		}
		// Do not allow case-folded or duplicate claim names to bypass exact spelling.
		if strings.EqualFold(key, "amr") {
			if key != "amr" || found != nil {
				return nil
			}
			found = value
		}
	}
	if _, err := d.Token(); err != nil {
		return nil
	}
	if _, err := d.Token(); err != io.EOF {
		return nil
	}
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
