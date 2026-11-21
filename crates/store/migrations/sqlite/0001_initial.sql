-- Portable schema for SQLite and PostgreSQL: TEXT and BIGINT only.
-- Secrets (tokens, codes, client secrets) are stored as SHA-256 hashes;
-- iCloud passwords are stored encrypted with AES-256-GCM.

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_ciphertext TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE TABLE oauth_clients (
    id TEXT PRIMARY KEY,
    secret_hash TEXT,
    name TEXT,
    redirect_uris TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE TABLE authorization_requests (
    id_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    state TEXT,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT,
    expires_at BIGINT NOT NULL
);

CREATE TABLE authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT,
    expires_at BIGINT NOT NULL
);

CREATE TABLE grants (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    resource TEXT,
    created_at BIGINT NOT NULL
);

CREATE TABLE access_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL
);

CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES grants (id) ON DELETE CASCADE,
    expires_at BIGINT NOT NULL
);

CREATE INDEX access_tokens_grant ON access_tokens (grant_id);
CREATE INDEX refresh_tokens_grant ON refresh_tokens (grant_id);
CREATE INDEX grants_account ON grants (account_id);
