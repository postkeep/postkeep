-- no-transaction
-- External principals. A grant or an authorization code is for exactly one
-- subject: a mailbox account, or a principal, an opaque string that an
-- embedding's sign-in hook approved.
--
-- SQLite cannot drop NOT NULL in place, so `grants` and
-- `authorization_codes` are rebuilt. Every connection turns foreign keys on,
-- and that pragma cannot change inside a transaction: in sqlx's usual
-- migration transaction, dropping `grants` would cascade and delete every
-- access and refresh token. So this migration runs outside it, turns foreign
-- keys off and opens its own transaction. The token tables refer to `grants`
-- by name and keep their rows. If any foreign key is broken afterwards, the
-- check below fails before COMMIT, and closing the connection rolls
-- everything back.
--
-- If the process stops between COMMIT and sqlx recording this migration, it
-- runs again on the next start. Nothing can have stored a principal in
-- between, so copying the tables again loses nothing.
PRAGMA foreign_keys = OFF;
BEGIN IMMEDIATE;

CREATE TABLE grants_new (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    principal TEXT,
    scope TEXT NOT NULL,
    resource TEXT,
    created_at BIGINT NOT NULL,
    CONSTRAINT grants_one_subject CHECK ((account_id IS NULL) <> (principal IS NULL))
);
INSERT INTO grants_new (id, client_id, account_id, scope, resource, created_at)
    SELECT id, client_id, account_id, scope, resource, created_at FROM grants;
DROP TABLE grants;
ALTER TABLE grants_new RENAME TO grants;
CREATE INDEX grants_account ON grants (account_id);
CREATE INDEX grants_client ON grants (client_id);
CREATE INDEX grants_principal ON grants (principal) WHERE principal IS NOT NULL;

CREATE TABLE authorization_codes_new (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    account_id TEXT REFERENCES accounts (id) ON DELETE CASCADE,
    principal TEXT,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scope TEXT NOT NULL,
    resource TEXT,
    expires_at BIGINT NOT NULL,
    used_at BIGINT,
    grant_id TEXT,
    replayed BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT authorization_codes_one_subject CHECK ((account_id IS NULL) <> (principal IS NULL))
);
INSERT INTO authorization_codes_new (code_hash, client_id, account_id, redirect_uri,
    code_challenge, scope, resource, expires_at, used_at, grant_id, replayed)
    SELECT code_hash, client_id, account_id, redirect_uri, code_challenge, scope, resource,
        expires_at, used_at, grant_id, replayed
    FROM authorization_codes;
DROP TABLE authorization_codes;
ALTER TABLE authorization_codes_new RENAME TO authorization_codes;
CREATE INDEX authorization_codes_expiry ON authorization_codes (expires_at);

CREATE TEMP TABLE foreign_key_violations (
    total BIGINT NOT NULL CONSTRAINT no_foreign_key_violations CHECK (total = 0)
);
INSERT INTO foreign_key_violations (total) SELECT
    (SELECT count(*) FROM pragma_foreign_key_check('grants'))
    + (SELECT count(*) FROM pragma_foreign_key_check('authorization_codes'))
    + (SELECT count(*) FROM pragma_foreign_key_check('access_tokens'))
    + (SELECT count(*) FROM pragma_foreign_key_check('refresh_tokens'));
DROP TABLE foreign_key_violations;

COMMIT;
PRAGMA foreign_keys = ON;
