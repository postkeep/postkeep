-- Accounts from more than one mail provider, upstream OAuth tokens, push
-- subscriptions and a replayable outbox of new-mail events.
--
-- Rows written by earlier versions keep working unchanged: they become IMAP
-- accounts on the server's default IMAP server, and their encrypted
-- passwords, sessions, grants and webhooks are not touched.

-- How postkeep reaches the mailbox: 'imap' (app password over IMAP and
-- SMTP), 'graph' (Microsoft Graph) or 'gmail' (Gmail API).
ALTER TABLE accounts ADD COLUMN provider TEXT NOT NULL DEFAULT 'imap';
-- IMAP accounts: the server preset ('icloud', 'fastmail', 'yahoo' or
-- 'custom'). NULL means the server's default, which is what every account
-- used before presets existed.
ALTER TABLE accounts ADD COLUMN imap_server TEXT;
-- OAuth accounts: the provider's stable identifier for the user (Microsoft
-- Graph user id, Google `sub`). An account is identified by provider and
-- subject, never by the email address alone.
ALTER TABLE accounts ADD COLUMN subject TEXT;

-- NULL subjects (IMAP accounts) never collide, in SQLite and PostgreSQL.
CREATE UNIQUE INDEX accounts_provider_subject ON accounts (provider, subject);

-- Tokens from Microsoft or Google for OAuth accounts, encrypted with the
-- master key like passwords. OAuth accounts store '' as their password.
CREATE TABLE upstream_tokens (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    refresh_token_ciphertext TEXT NOT NULL,
    access_token_ciphertext TEXT,
    access_expires_at BIGINT,
    scope TEXT NOT NULL,
    -- Set when the provider rejected the refresh token (revoked consent,
    -- changed password, expiry); cleared by signing in again.
    invalid_at BIGINT,
    invalid_reason TEXT,
    updated_at BIGINT NOT NULL
);

-- Sign-ins in progress at Microsoft or Google, keyed by a hash of the
-- `state` sent upstream. Single use; the PKCE verifier and the pending
-- authorization request ID are encrypted.
CREATE TABLE upstream_requests (
    state_hash TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    purpose TEXT NOT NULL,
    request_id_ciphertext TEXT,
    verifier_ciphertext TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX upstream_requests_expiry ON upstream_requests (expires_at);

-- Push notification subscriptions: a Microsoft Graph subscription, or a
-- Gmail `users.watch`.
CREATE TABLE push_subscriptions (
    account_id TEXT PRIMARY KEY REFERENCES accounts (id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    -- Graph subscription id; NULL for Gmail.
    subscription_id TEXT,
    -- SHA-256 of the Graph clientState secret; NULL for Gmail.
    client_state_hash TEXT,
    expires_at BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);

CREATE UNIQUE INDEX push_subscriptions_id ON push_subscriptions (subscription_id);

-- Watch position for providers without UIDs (Graph: newest received time,
-- Gmail: historyId), as provider-specific text.
ALTER TABLE webhooks ADD COLUMN watch_position TEXT;
-- Event numbering: the last sequence number given out and the last one
-- the receiver accepted. Events after `delivered_sequence` are replayed.
ALTER TABLE webhooks ADD COLUMN last_sequence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE webhooks ADD COLUMN delivered_sequence BIGINT NOT NULL DEFAULT 0;

-- New-mail events waiting for, or kept after, delivery. The payload (which
-- may hold a sender and subject) is encrypted.
CREATE TABLE mail_events (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    sequence BIGINT NOT NULL,
    payload_ciphertext TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

CREATE UNIQUE INDEX mail_events_sequence ON mail_events (account_id, sequence);
CREATE INDEX mail_events_created ON mail_events (created_at);
