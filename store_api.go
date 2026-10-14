package browser

// Store is a durable session store constructed by this package. Its private
// method deliberately prevents custom implementations from bypassing the
// session transition protocol. The application owns the database lifetime.
type Store interface {
	sessionStore() *store
}

func (s *PostgresStore) sessionStore() *store {
	if s == nil || s.store == nil {
		return nil
	}
	v := *s.store
	return &v
}

// SQLiteStore borrows an application-owned SQLite database. It never opens,
// closes, migrates or changes PRAGMA settings on that database.
type SQLiteStore struct { store *store }

func (s *SQLiteStore) sessionStore() *store {
	if s == nil || s.store == nil {
		return nil
	}
	v := *s.store
	if v.sqlite != nil {
		sqlite := *v.sqlite
		v.sqlite = &sqlite
	}
	return &v
}

var _ Store = (*PostgresStore)(nil)
var _ Store = (*SQLiteStore)(nil)

// Accept only package-owned concrete wrappers. Embedding Store in an external
// type must not introduce a custom transition implementation or a nil panic.
func snapshotStore(s Store) *store {
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
	v := snapshotStore(s)
	return v != nil && v.db != nil
}
