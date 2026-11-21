-- Opt-in new-mail webhooks, one per account. The custom auth header value
-- and the signing secret are encrypted with AES-256-GCM like passwords.
-- Flags are BIGINT 0/1 to stay portable between SQLite and PostgreSQL.
CREATE TABLE webhooks (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    enabled BIGINT NOT NULL,
    url TEXT NOT NULL,
    auth_header_name TEXT,
    auth_header_value_ciphertext TEXT,
    signing BIGINT NOT NULL,
    signing_secret_ciphertext TEXT NOT NULL,
    include_sender BIGINT NOT NULL,
    consecutive_failures BIGINT NOT NULL,
    disabled_reason TEXT,
    last_attempt_at BIGINT,
    last_success_at BIGINT,
    last_error TEXT,
    -- Watch position: UIDVALIDITY of INBOX and the highest UID reported.
    uid_validity BIGINT,
    last_uid BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE INDEX webhooks_enabled ON webhooks (enabled);

-- The most recent deliveries per account, for the account page.
CREATE TABLE webhook_deliveries (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    test BIGINT NOT NULL,
    succeeded BIGINT NOT NULL,
    summary TEXT NOT NULL,
    elapsed_ms BIGINT
);

CREATE INDEX webhook_deliveries_account ON webhook_deliveries (account_id, created_at);
