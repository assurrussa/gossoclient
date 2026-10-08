-- Apply explicitly to an app-owned PostgreSQL database. Never AuthHub's schema.
CREATE TABLE IF NOT EXISTS sso_example_sessions (
 cookie_digest text PRIMARY KEY,
 generation bigint NOT NULL DEFAULT 0 CHECK (generation >= 0),
 status text NOT NULL CHECK (status IN ('pending','active','ended')),
 csrf text NOT NULL,
 proof jsonb,
 fresh_until timestamptz,
 absolute_until timestamptz NOT NULL,
 refresh_cipher bytea,
 refresh_state text NOT NULL DEFAULT 'none' CHECK (refresh_state IN ('none','ready','claimed','uncertain')),
 refresh_owner text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS sso_example_logins (
 state_digest text PRIMARY KEY,
 cookie_digest text NOT NULL REFERENCES sso_example_sessions(cookie_digest),
 generation bigint NOT NULL,
 nonce text NOT NULL,
 verifier_cipher bytea NOT NULL,
 return_path text NOT NULL,
 expires_at timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS sso_example_logins_expiry ON sso_example_logins(expires_at);
CREATE INDEX IF NOT EXISTS sso_example_sessions_expiry ON sso_example_sessions(absolute_until);
