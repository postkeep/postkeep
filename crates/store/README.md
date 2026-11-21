# postkeep-store

Persistence for `postkeep`: connected accounts, OAuth clients,
authorization codes and tokens.

- **Backends**: SQLite by default (`sqlite://...`), PostgreSQL with the
  `postgres` feature (`postgres://...`), both through `sqlx`'s `Any` driver.
  Each backend has its own migrations folder, `migrations/sqlite` and
  `migrations/postgres`, so later migrations can differ. Both start with the
  same 0001 to 0008 that every earlier version applied. A test pins their
  bytes and checksums, so databases created before the split keep starting.
  Never edit a released migration: add a new one to each folder.
- **Tenants**: every account has a `tenant`, an opaque string; this server
  only uses `default`. `Store::for_tenant` scopes address and provider
  lookups and new accounts to another tenant, `accounts_in_tenant` lists
  one tenant's accounts, and `find_account` finds one of them by ID or
  address. On PostgreSQL addresses are unique per tenant
  (migration 0009). SQLite keeps them unique across tenants, so a second
  tenant connecting the same address gets `AccountConflict`. A Microsoft
  or Google sign-in that an embedding starts for a tenant keeps that
  tenant and the embedding's encrypted continuation until its callback
  (`UpstreamPurpose::Continue`, migration 0011).
- **Storage level**: a one-row table (migration 0014) records how new the
  formats in the database are. A build reads up to `STORAGE_LEVEL_READS` and
  writes at `STORAGE_LEVEL_WRITES` by default; connecting to or migrating a
  database recorded above the first is `StorageLevelAhead`.
  `Store::raise_storage_level` raises the level to `STORAGE_LEVEL_READS` and
  never lowers it, and a format above `STORAGE_LEVEL_WRITES` is written only
  where `Store::may_write_level` allows it.
- **Credentials**: stored secrets are encrypted with AES-256-GCM under a
  32-byte master key (hex or base64), or under a tenant's data key that the
  master key wraps (values with the prefix `v2.`). Each ciphertext uses a fresh
  random nonce and is bound to its column and row as associated data (an app
  password to its account's email address), so a row copied onto another
  account fails to decrypt; a data key's values are also bound to the tenant
  of their row. Every encrypted column is read in both formats. App-specific
  passwords, webhook secrets, filter rule patterns, stored events, provider tokens and
  sign-ins in progress are all written under a data key, and a value that an earlier
  version wrote stays under the master key until it is saved again or the sweep
  (`Store::reencrypt`) moves it; an event is never saved again, so one stored
  before stays until the sweep moves it or the outbox removes it, and a sign-in
  is removed when it is used or expires. `Store::destroy_data_keys` destroys a
  tenant's data keys: its values never open again through the database or from
  a logical dump taken afterwards, and no secret is stored for it again
  (`StoreError::KeysDestroyed`).
- **Tokens**: authorization codes, access tokens and refresh tokens are stored
  only as SHA-256 hashes. Codes are single use; refresh tokens rotate on
  every use. A refresh token presented again within the configured grace
  of its first use issues a separate pair, without extending that window.
  Revoking a token revokes its whole grant. Held sends keep a hash of the
  id and app, and a fingerprint of the tool, id and arguments, never the
  message; only a matching take uses the hold up.
- **Grant subjects**: a code and the grant made from it are for a mailbox
  account or for a principal, an opaque string that an embedding approved
  (migration 0010). `revoke_principal_grants` revokes one principal's
  grants. On SQLite, 0010 rebuilds `grants` and `authorization_codes`
  outside sqlx's migration transaction with foreign keys off, so the
  access and refresh tokens that point at them are kept.
- **Expiry**: every short-lived row has an `expires_at`; `Store::purge_expired`
  removes stale rows, including held sends. Webhook outbox rows (`mail_events`)
  are also pruned per account. Nullable `webhooks.outbox_retention_secs` and
  `webhooks.outbox_max_events` override the server defaults; NULL uses
  them. The cap counts delivered and undelivered events. Pruning deletes
  the oldest rows and does not rewind `last_sequence`, `delivered_sequence`
  or the watch cursor.
- **Lock order**: on PostgreSQL, every transaction that writes an
  account's webhook, delivery log, events or filter rules locks its
  `webhooks` row first, deletes of a webhook or an account included.
  The one exception is `save_webhook`'s orphan-rule cleanup, which runs
  only when no webhook row exists. An insert into those tables also
  locks the account's row (its foreign key), so it comes after the
  webhook's row, and an account's own row is deleted last. A reconnect
  updates the account's row before it ends the account's sessions (IMAP)
  or saves its tokens (OAuth), as `save_upstream_tokens` does too, so
  `delete_account` takes that row right after the webhook's, with an
  update that changes nothing: the
  foreign-key lock of an insert, such as `save_webhook`'s, gets past that
  update's lock, where it would wait for a delete's. An account's or a
  principal's authorization codes come before its access tokens, those
  before its refresh tokens, and those before its grants. Refresh rotations
  that issue a pair lock the presented refresh row, then only insert;
  they never lock existing access rows. Reuse that revokes follows the
  deletion order. A replayed code learns its grant from the code's row,
  so it takes the code first, and so does every other writer of codes
  with tokens or grants. `create_grant_for_code` links the code before
  it inserts the grant: the insert's foreign-key lock on the account's
  row would otherwise hold up the account's deletion, which by then
  holds the codes. Writers that keep these orders wait for each other
  in turn; in opposite orders PostgreSQL aborts one of them (40P01).
  SQLite runs one write transaction at a time.

Generate a master key with `openssl rand -hex 32` (any 32 random bytes,
hex or base64 encoded). Losing the key makes stored credentials unreadable,
and users then sign in again.

## Tests

SQLite tests always run. The PostgreSQL test is ignored unless asked for:

```sh
TEST_POSTGRES_URL=postgres://postgres:postgres@localhost/postgres \
  cargo nextest run -p postkeep-store --all-features --run-ignored all
```
