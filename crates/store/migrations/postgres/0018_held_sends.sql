-- A send held for the user's yes. Only the id's hash and a fingerprint of
-- the arguments are stored, never the message. The hash includes the app,
-- and the fingerprint includes the tool and the raw id, so the database
-- alone cannot test a guess at the message. A matching take deletes the row.
CREATE TABLE held_sends (
    id_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    principal TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX held_sends_account ON held_sends (account_id);
