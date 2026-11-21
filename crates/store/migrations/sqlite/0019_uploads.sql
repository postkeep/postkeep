-- One-time uploads: a file an agent sends to postkeep to attach to one message.
-- The file's bytes are in the operator's bucket, sealed under the upload's own
-- key, as objects named after `object`. The id and the token are stored only as
-- hashes, and the id's hash includes the app. The key and the file's SHA-256
-- are sealed under the tenant's data key, set once the file is in and cleared
-- once the upload is used. So the database alone shows how many uploads wait,
-- how large, when, and for which mailbox and person, never the file, its name
-- or type, or a hash to test a guess against.
CREATE TABLE uploads (
    id_hash TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    account_id TEXT NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    principal TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    claimed_at BIGINT,
    reserved BIGINT,
    object TEXT,
    size BIGINT,
    key_ciphertext TEXT,
    digest_ciphertext TEXT,
    used_at BIGINT
);

CREATE INDEX uploads_account ON uploads (account_id);
