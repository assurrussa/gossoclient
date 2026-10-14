package browser

// Store is a durable session store constructed by this package. Its private
// method deliberately prevents custom implementations from bypassing the
// session transition protocol. The application owns the database lifetime.
type Store interface {
	sessionStore() sessionStorage
}

func (s *PostgresStore) sessionStore() sessionStorage {
	if s == nil || s.store == nil || s.store.db == nil {
		return nil
	}
	v := *s.store
	return &v
}

// SQLiteStore borrows an application-owned SQLite database. It never opens,
// closes, migrates or changes PRAGMA settings on that database.
type SQLiteStore struct{ store *sqliteStore }

func (s *SQLiteStore) sessionStore() sessionStorage {
	if s == nil || s.store == nil || s.store.db == nil {
		return nil
	}
	v := *s.store
	return &v
}

var _ Store = (*PostgresStore)(nil)
var _ Store = (*SQLiteStore)(nil)

// Select and snapshot the concrete driver only at the public boundary.
// Accept only package-owned concrete wrappers: embedding Store in an external
// type must not introduce a custom transition implementation or a nil panic.
func snapshotStore(s Store) sessionStorage {
	switch v := s.(type) {
	case *PostgresStore:
		return v.sessionStore()
	case *SQLiteStore:
		return v.sessionStore()
	default:
		return nil
	}
}

func validStore(s Store) bool {
	return snapshotStore(s) != nil
}
