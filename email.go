package browser

import (
	"encoding/json"
	"net/mail"
	"strings"
	"unicode/utf8"
)

// signedEmail reads only claims inside the already verified ID token. Legacy
// clients neither request nor interpret these claims. No profile/alias fallback.
func signedEmail(enabled bool, rawEmail, rawVerified json.RawMessage) (string, bool, bool) {
	if !enabled {
		return "", false, true
	}
	var email string
	var verified bool
	if len(rawEmail) != 0 {
		var value *string
		if json.Unmarshal(rawEmail, &value) != nil || value == nil || !validSignedEmail(*value) {
			return "", false, false
		}
		email = *value
	}
	if len(rawVerified) != 0 {
		var value *bool
		if json.Unmarshal(rawVerified, &value) != nil || value == nil {
			return "", false, false
		}
		verified = *value
	}
	if verified && email == "" {
		return "", false, false
	}
	return email, verified, true
}

func validSignedEmail(value string) bool {
	if value == "" || len(value) > 254 || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}
