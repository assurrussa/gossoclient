package browser

import "errors"

func validateStoreSchema(name string) error {
	if len(name) == 0 || len(name) > 63 {
		return errors.New("session schema must be an ASCII identifier of 1 to 63 bytes")
	}
	for i, c := range []byte(name) {
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') &&
			(i == 0 || c < '0' || c > '9') {
			return errors.New("session schema must be an ASCII identifier of 1 to 63 bytes")
		}
	}
	return nil
}

// table is used only with fixed SQL table names, never user-provided values.
// The optional schema was validated before construction and is always quoted.
func (s *store) table(name string) string {
	if s.schema == "" {
		return name
	}
	return `"` + s.schema + `".` + name
}
