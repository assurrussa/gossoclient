package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

// uniqueVerifiedClaim reads one top-level member from an already verified ID
// token payload. A duplicate or malformed object makes the claim unavailable.
// strictName rejects case aliases for security-critical claims; advisory
// claims retain encoding/json's case-insensitive matching.
func uniqueVerifiedClaim(raw json.RawMessage, name string, strictName bool) json.RawMessage {
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
		if strings.EqualFold(key, name) {
			if found != nil || strictName && key != name {
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
	return found
}
