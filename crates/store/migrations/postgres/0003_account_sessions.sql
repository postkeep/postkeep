-- Browser sessions for the account page. Only a SHA-256 hash of the
-- session token is stored.
CREATE TABLE account_sessions (
    id_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    absolute_expires_at BIGINT NOT NULL
);

CREATE INDEX account_sessions_account ON account_sessions (account_id);
CREATE INDEX account_sessions_expiry ON account_sessions (expires_at);
