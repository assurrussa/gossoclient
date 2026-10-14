-- Apply explicitly to the application's SQLite database. No PRAGMA/user_version changes.
-- Deadlines use exact signed INTEGER Unix nanoseconds.
CREATE TABLE IF NOT EXISTS sso_example_sessions (
 cookie_digest TEXT PRIMARY KEY NOT NULL,
 generation INTEGER NOT NULL DEFAULT 0 CHECK (typeof(generation) = 'integer' AND generation >= 0),
 status TEXT NOT NULL CHECK (status IN ('pending','active','ended')),
 csrf TEXT NOT NULL,
 proof BLOB,
 fresh_until INTEGER CHECK (fresh_until IS NULL OR typeof(fresh_until) = 'integer'),
 absolute_until INTEGER NOT NULL CHECK (typeof(absolute_until) = 'integer'),
 refresh_cipher BLOB,
 refresh_state TEXT NOT NULL DEFAULT 'none' CHECK (refresh_state IN ('none','ready','claimed','uncertain')),
 refresh_owner TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sso_example_logins (
 state_digest TEXT PRIMARY KEY NOT NULL,
 cookie_digest TEXT NOT NULL REFERENCES sso_example_sessions(cookie_digest),
 generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 0),
 nonce TEXT NOT NULL,
 verifier_cipher BLOB NOT NULL,
 return_path TEXT NOT NULL,
 expires_at INTEGER NOT NULL CHECK (typeof(expires_at) = 'integer'),
 consumed INTEGER NOT NULL DEFAULT 0 CHECK (consumed IN (0,1))
);
CREATE INDEX IF NOT EXISTS sso_example_logins_expiry ON sso_example_logins(expires_at);
CREATE INDEX IF NOT EXISTS sso_example_sessions_expiry ON sso_example_sessions(absolute_until);
