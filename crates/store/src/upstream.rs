//! State for signing in with Microsoft or Google: the encrypted tokens of
//! OAuth accounts and sign-ins in progress.

use std::time::Duration;

use secrecy::{ExposeSecret, SecretString};
use sqlx::any::Any;
use sqlx::{Row, Transaction};

use crate::accounts::{AccountId, Provider};
use crate::crypto::{Slot, hash_secret};
use crate::db::{expires_in, now, rollback_then};
use crate::envelope::Sealer;
use crate::{DEFAULT_TENANT, Result, Store, StoreError};

/// Tokens issued by Microsoft or Google for an account.
#[derive(Clone)]
pub struct UpstreamTokens {
    /// The refresh token.
    pub refresh_token: SecretString,
    /// The current access token, if one is cached.
    pub access_token: Option<SecretString>,
    /// When the access token expires (Unix seconds).
    pub access_expires_at: Option<i64>,
    /// The scopes the user granted, space-separated.
    pub scope: String,
}

impl std::fmt::Debug for UpstreamTokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamTokens")
            .field("access_expires_at", &self.access_expires_at)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// Stored tokens with their status.
#[derive(Debug, Clone)]
pub struct StoredUpstreamTokens {
    /// The tokens.
    pub tokens: UpstreamTokens,
    /// Why the provider rejected the refresh token, if it did. The user
    /// has to sign in again.
    pub invalid_reason: Option<String>,
}

/// What a sign-in at Microsoft or Google is for.
#[derive(Debug, Clone)]
pub enum UpstreamPurpose {
    /// Connecting an account for an MCP client: the pending authorization
    /// request it continues.
    Authorize {
        /// The authorization request ID shown on the sign-in page.
        request_id: SecretString,
    },
    /// Signing in to the account page.
    Account,
    /// Adding a mailbox to one of an embedding's tenants.
    Continue {
        /// The tenant the account is created or updated in.
        tenant: String,
        /// The embedding's own value, handed back when the sign-in
        /// finishes.
        continuation: SecretString,
    },
}

/// A sign-in in progress at Microsoft or Google.
#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    /// [`Provider::Graph`] or [`Provider::Gmail`].
    pub provider: Provider,
    /// What the sign-in is for.
    pub purpose: UpstreamPurpose,
    /// The PKCE code verifier sent with the token request.
    pub code_verifier: SecretString,
    /// Hash of the random value in the browser-binding cookie, so a
    /// callback only completes in the browser that started the sign-in.
    pub binding_hash: String,
}

pub fn refresh_context(account: &AccountId) -> String {
    format!("upstream/refresh/{}", account.0)
}

pub fn access_context(account: &AccountId) -> String {
    format!("upstream/access/{}", account.0)
}

pub fn verifier_context(state_hash: &str) -> String {
    format!("upstream-request/verifier/{state_hash}")
}

pub fn request_id_context(state_hash: &str) -> String {
    format!("upstream-request/request-id/{state_hash}")
}

pub fn continuation_context(state_hash: &str) -> String {
    format!("upstream-request/continuation/{state_hash}")
}

/// The column of an encrypted refresh token.
pub const REFRESH_SLOT: Slot = Slot::new("upstream_tokens", "refresh_token_ciphertext");

/// The column of an encrypted cached access token.
pub const ACCESS_SLOT: Slot = Slot::new("upstream_tokens", "access_token_ciphertext");

/// The column of an encrypted PKCE verifier.
pub const VERIFIER_SLOT: Slot = Slot::new("upstream_requests", "verifier_ciphertext");

/// The column of an encrypted pending authorization request ID.
pub const REQUEST_ID_SLOT: Slot = Slot::new("upstream_requests", "request_id_ciphertext");

/// The column of an encrypted embedding continuation.
pub const CONTINUATION_SLOT: Slot = Slot::new("upstream_requests", "continuation_ciphertext");

/// Writes tokens for an account inside a transaction, clearing any
/// earlier rejection. `sealer` is the account's tenant's, made before the
/// transaction opened; sealing needs no connection.
pub async fn write_tokens(
    sealer: &Sealer,
    tx: &mut Transaction<'static, Any>,
    account: &AccountId,
    tokens: &UpstreamTokens,
) -> Result<()> {
    let (refresh, access) = seal_tokens(sealer, account, tokens)?;
    sqlx::query(
        "INSERT INTO upstream_tokens (account_id, refresh_token_ciphertext, access_token_ciphertext, \
         access_expires_at, scope, invalid_at, invalid_reason, updated_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, NULL, $6) \
         ON CONFLICT (account_id) DO UPDATE SET \
         refresh_token_ciphertext = excluded.refresh_token_ciphertext, \
         access_token_ciphertext = excluded.access_token_ciphertext, \
         access_expires_at = excluded.access_expires_at, scope = excluded.scope, \
         invalid_at = NULL, invalid_reason = NULL, updated_at = excluded.updated_at",
    )
    .bind(&account.0)
    .bind(refresh)
    .bind(access)
    .bind(tokens.access_expires_at)
    .bind(&tokens.scope)
    .bind(now())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The refresh token and the cached access token, if any, sealed for the rows
/// of `account`, which are keyed by its ID.
fn seal_tokens(
    sealer: &Sealer,
    account: &AccountId,
    tokens: &UpstreamTokens,
) -> Result<(String, Option<String>)> {
    let refresh = sealer.seal_secret(REFRESH_SLOT, &account.0, &tokens.refresh_token)?;
    let access = tokens
        .access_token
        .as_ref()
        .map(|token| sealer.seal_secret(ACCESS_SLOT, &account.0, token))
        .transpose()?;
    Ok((refresh, access))
}

/// How often a conditional token write is retried when the ciphertext
/// changes but the plaintext does not (a key rotation re-sealed the row).
const REFRESH_CAS_ATTEMPTS: u32 = 3;

/// What to write when the stored refresh token is still `refresh_token`.
#[derive(Clone, Copy)]
enum RefreshCas<'a> {
    /// Replace the grant with tokens from a successful refresh.
    Save {
        refresh: &'a str,
        access: Option<&'a str>,
        access_expires_at: Option<i64>,
        scope: &'a str,
    },
    /// Record that the provider rejected the grant.
    Invalidate { reason: &'a str },
}

/// The refresh-token ciphertext currently stored, and the tenant of its
/// account, which a v2 value is bound to.
async fn current_refresh_ciphertext(
    pool: &sqlx::AnyPool,
    account: &AccountId,
) -> Result<Option<(String, String)>> {
    let row = sqlx::query(
        "SELECT u.refresh_token_ciphertext, a.tenant FROM upstream_tokens u \
         JOIN accounts a ON a.id = u.account_id WHERE u.account_id = $1",
    )
    .bind(&account.0)
    .fetch_optional(pool)
    .await?;
    row.map(|row| {
        Ok((
            row.try_get("refresh_token_ciphertext")?,
            row.try_get("tenant")?,
        ))
    })
    .transpose()
}

impl Store {
    /// The stored tokens of an OAuth account.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Decrypt`] if the refresh token can't be
    /// decrypted, and another error if the database fails or the key wrapper
    /// does not answer, also for the cached access token.
    /// A token in a format newer than this version reads is
    /// [`StoreError::NewerFormat`], also for the cached access token.
    pub async fn upstream_tokens(
        &self,
        account: &AccountId,
    ) -> Result<Option<StoredUpstreamTokens>> {
        let row = sqlx::query(
            "SELECT u.refresh_token_ciphertext, u.access_token_ciphertext, u.access_expires_at, \
             u.scope, u.invalid_reason, a.tenant FROM upstream_tokens u \
             JOIN accounts a ON a.id = u.account_id WHERE u.account_id = $1",
        )
        .bind(&account.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let tenant: String = row.try_get("tenant")?;
        let refresh: String = row.try_get("refresh_token_ciphertext")?;
        let access: Option<String> = row.try_get("access_token_ciphertext")?;
        let legacy = refresh_context(account);
        let open = self.open_secret(&tenant, REFRESH_SLOT, &account.0, &legacy, &refresh);
        let refresh_token = open.await?;
        let access_token = match access {
            Some(value) => {
                let legacy = access_context(account);
                let open = self.open_secret(&tenant, ACCESS_SLOT, &account.0, &legacy, &value);
                match open.await {
                    Ok(token) => Some(token),
                    // An unreadable cached access token is simply refreshed.
                    Err(StoreError::Decrypt) => None,
                    Err(err) => return Err(err),
                }
            }
            None => None,
        };
        Ok(Some(StoredUpstreamTokens {
            tokens: UpstreamTokens {
                refresh_token,
                access_token,
                access_expires_at: row.try_get("access_expires_at")?,
                scope: row.try_get("scope")?,
            },
            invalid_reason: row.try_get("invalid_reason")?,
        }))
    }

    /// Replaces an account's tokens after a refresh. Microsoft rotates
    /// refresh tokens; when the provider returned no new one, pass the old
    /// one again.
    ///
    /// A refresh that raced a sign-in must use
    /// [`Store::save_upstream_tokens_if_current`] instead: this write is
    /// unconditional.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidInput`] if the account does not exist,
    /// also once a deletion that this call waited for has committed, and
    /// another error if encryption or the query fails, or if the key wrapper
    /// does not answer ([`StoreError::KeyWrap`]): nothing is written then.
    pub async fn save_upstream_tokens(
        &self,
        account: &AccountId,
        tokens: &UpstreamTokens,
    ) -> Result<()> {
        // The row's tenant, not this store's; the key is found before the
        // transaction opens, and the update below still decides.
        let Some(tenant) = self.account_tenant(account).await? else {
            return Err(StoreError::InvalidInput("unknown account"));
        };
        let sealer = self.sealer(&tenant).await?;
        let mut tx = self.begin_write().await?;
        // The account's row first, as a reconnect takes it before it saves
        // the tokens. The update changes nothing. Behind the account's
        // deletion it matches no row once the deletion commits, where a
        // plain read would let the tokens' insert fail on its foreign key.
        let found = sqlx::query("UPDATE accounts SET updated_at = updated_at WHERE id = $1")
            .bind(&account.0)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        if found == 0 {
            return rollback_then(tx, StoreError::InvalidInput("unknown account")).await;
        }
        write_tokens(&sealer, &mut tx, account, tokens).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Replaces the tokens when `refresh_token` is still the one stored.
    ///
    /// Returns `false` when a sign-in or another refresh already replaced
    /// the plaintext; the stored row is left as it is. A key rotation that
    /// only re-encrypts the same refresh token does not count: the
    /// conditional update is retried against the new ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or a query fails, or if every attempt
    /// loses to a re-encryption of the same plaintext. A key wrapper that does
    /// not answer is [`StoreError::KeyWrap`]: nothing is written, and the
    /// stored tokens stay as they are for a later attempt.
    pub async fn save_upstream_tokens_if_current(
        &self,
        account: &AccountId,
        refresh_token: &SecretString,
        tokens: &UpstreamTokens,
    ) -> Result<bool> {
        // The new tokens are sealed before the stored one is read, for the
        // tenant of the account's row, which is not always this store's.
        let Some((_, tenant)) = current_refresh_ciphertext(&self.pool, account).await? else {
            return Ok(false);
        };
        let sealer = self.sealer(&tenant).await?;
        let (refresh, access) = seal_tokens(&sealer, account, tokens)?;
        self.commit_refresh_cas(
            account,
            refresh_token,
            RefreshCas::Save {
                refresh: &refresh,
                access: access.as_deref(),
                access_expires_at: tokens.access_expires_at,
                scope: &tokens.scope,
            },
        )
        .await
    }

    /// Records that the provider rejected the refresh token. The cached
    /// access token is dropped; tools report that the user must sign in
    /// again until they do.
    ///
    /// A refresh that raced a sign-in must use
    /// [`Store::mark_upstream_tokens_invalid_if_current`] instead: this
    /// write is unconditional.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn mark_upstream_tokens_invalid(
        &self,
        account: &AccountId,
        reason: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE upstream_tokens SET invalid_at = $1, invalid_reason = $2, \
             access_token_ciphertext = NULL, access_expires_at = NULL WHERE account_id = $3",
        )
        .bind(now())
        .bind(reason)
        .bind(&account.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Marks the grant invalid when `refresh_token` is still the one stored.
    ///
    /// Returns `false` when a newer sign-in already replaced the plaintext;
    /// that grant is not marked invalid. Re-encrypting the same refresh
    /// token is retried, the same way as
    /// [`Store::save_upstream_tokens_if_current`]. See
    /// [`Store::mark_upstream_tokens_invalid`] for the unconditional write.
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or a query fails, or if every attempt
    /// loses to a re-encryption of the same plaintext.
    pub async fn mark_upstream_tokens_invalid_if_current(
        &self,
        account: &AccountId,
        refresh_token: &SecretString,
        reason: &str,
    ) -> Result<bool> {
        self.commit_refresh_cas(account, refresh_token, RefreshCas::Invalidate { reason })
            .await
    }

    /// Writes `op` while `refresh_token` is still the stored plaintext.
    ///
    /// The ciphertext is read, then the conditional update runs in its own
    /// transaction. Holding the read open would turn a committed
    /// re-encryption into `SQLITE_BUSY_SNAPSHOT` on SQLite and into zero
    /// rows on Postgres. Zero rows are read again: the same plaintext means
    /// the row was only re-encrypted, and the update is retried up to
    /// [`REFRESH_CAS_ATTEMPTS`] times. `false` is returned only when the
    /// plaintext really changed or the row is gone.
    async fn commit_refresh_cas(
        &self,
        account: &AccountId,
        refresh_token: &SecretString,
        op: RefreshCas<'_>,
    ) -> Result<bool> {
        for _ in 0..REFRESH_CAS_ATTEMPTS {
            let Some(current) = self.prepare_refresh_cas(account, refresh_token).await? else {
                return Ok(false);
            };
            let mut tx = self.begin_write().await?;
            let applied = match op {
                RefreshCas::Save {
                    refresh,
                    access,
                    access_expires_at,
                    scope,
                } => sqlx::query(
                    "UPDATE upstream_tokens SET \
                     refresh_token_ciphertext = $1, access_token_ciphertext = $2, \
                     access_expires_at = $3, scope = $4, invalid_at = NULL, invalid_reason = NULL, \
                     updated_at = $5 \
                     WHERE account_id = $6 AND refresh_token_ciphertext = $7 \
                     RETURNING account_id",
                )
                .bind(refresh)
                .bind(access)
                .bind(access_expires_at)
                .bind(scope)
                .bind(now())
                .bind(&account.0)
                .bind(&current)
                .fetch_optional(&mut *tx)
                .await?
                .is_some(),
                RefreshCas::Invalidate { reason } => sqlx::query(
                    "UPDATE upstream_tokens SET invalid_at = $1, invalid_reason = $2, \
                     access_token_ciphertext = NULL, access_expires_at = NULL \
                     WHERE account_id = $3 AND refresh_token_ciphertext = $4 \
                     RETURNING account_id",
                )
                .bind(now())
                .bind(reason)
                .bind(&account.0)
                .bind(&current)
                .fetch_optional(&mut *tx)
                .await?
                .is_some(),
            };
            if applied {
                tx.commit().await?;
                return Ok(true);
            }
        }
        match self
            .stored_refresh_ciphertext_if_current(account, refresh_token)
            .await?
        {
            None => Ok(false),
            Some(_) => Err(StoreError::InvalidInput(
                "the refresh token was re-encrypted on every attempt to update it",
            )),
        }
    }

    /// The stored ciphertext when it still decrypts to `refresh_token`.
    ///
    /// When it does, a test may re-encrypt the row before the conditional
    /// update so the race is deterministic.
    async fn prepare_refresh_cas(
        &self,
        account: &AccountId,
        refresh_token: &SecretString,
    ) -> Result<Option<String>> {
        let current = self
            .stored_refresh_ciphertext_if_current(account, refresh_token)
            .await?;
        #[cfg(test)]
        if current.is_some() {
            fire_refresh_cas_hook(&account.0).await;
        }
        Ok(current)
    }

    /// Ciphertext of the stored refresh token when its plaintext is
    /// `refresh_token`. `None` when the row is missing or the plaintext
    /// differs.
    async fn stored_refresh_ciphertext_if_current(
        &self,
        account: &AccountId,
        refresh_token: &SecretString,
    ) -> Result<Option<String>> {
        let Some((current, tenant)) = current_refresh_ciphertext(&self.pool, account).await? else {
            return Ok(None);
        };
        if !self
            .same_refresh_token(&tenant, account, refresh_token, &current)
            .await?
        {
            return Ok(None);
        }
        Ok(Some(current))
    }

    /// Whether `ciphertext`, stored for an account of `tenant`, decrypts to
    /// `expected`.
    async fn same_refresh_token(
        &self,
        tenant: &str,
        account: &AccountId,
        expected: &SecretString,
        ciphertext: &str,
    ) -> Result<bool> {
        let legacy = refresh_context(account);
        let open = self.open_secret(tenant, REFRESH_SLOT, &account.0, &legacy, ciphertext);
        Ok(open.await?.expose_secret() == expected.expose_secret())
    }

    /// Stores a sign-in in progress under the hash of `state`, the random
    /// value sent to the provider.
    ///
    /// The request ID, the continuation and the verifier are sealed under the
    /// data key of the tenant that the sign-in belongs to: the tenant of
    /// [`UpstreamPurpose::Continue`], else [`DEFAULT_TENANT`], whichever tenant
    /// this store is scoped to. The key is found before the insert; if it
    /// cannot be, nothing is stored.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or the query fails, and
    /// [`StoreError::KeyWrap`] if the key wrapper does not answer.
    pub async fn save_upstream_request(
        &self,
        state: &str,
        request: &UpstreamRequest,
        ttl: Duration,
    ) -> Result<()> {
        let state_hash = hash_secret(state);
        let (purpose, tenant) = match &request.purpose {
            UpstreamPurpose::Authorize { .. } => ("authorize", None),
            UpstreamPurpose::Account => ("account", None),
            UpstreamPurpose::Continue { tenant, .. } => ("continue", Some(tenant.as_str())),
        };
        // The tenant the reader binds the values to (`row_shape`), not this
        // store's: the sign-in's own, else the default one.
        let sealer = self.sealer(tenant.unwrap_or(DEFAULT_TENANT)).await?;
        let seal = |slot, value: &SecretString| sealer.seal_secret(slot, &state_hash, value);
        let (request_id, continuation) = match &request.purpose {
            UpstreamPurpose::Authorize { request_id } => {
                (Some(seal(REQUEST_ID_SLOT, request_id)?), None)
            }
            UpstreamPurpose::Account => (None, None),
            UpstreamPurpose::Continue { continuation, .. } => {
                (None, Some(seal(CONTINUATION_SLOT, continuation)?))
            }
        };
        let verifier = seal(VERIFIER_SLOT, &request.code_verifier)?;
        sqlx::query(
            "INSERT INTO upstream_requests (state_hash, provider, purpose, request_id_ciphertext, \
             tenant, continuation_ciphertext, verifier_ciphertext, binding_hash, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(&state_hash)
        .bind(request.provider.as_str())
        .bind(purpose)
        .bind(request_id)
        .bind(tenant)
        .bind(continuation)
        .bind(verifier)
        .bind(&request.binding_hash)
        .bind(expires_in(ttl))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Removes and returns the live sign-in stored for `state`. Each state
    /// can be used once: a second callback with it finds nothing.
    ///
    /// The sign-in is read and opened first, outside any transaction (opening
    /// may ask the key wrapper, which can take a while), and removed only
    /// then, so a value that cannot be opened for now stays for another try
    /// until the sign-in expires. Of two takes at once, the one whose delete
    /// removes the row returns the sign-in and the other gets `None`; so does
    /// a take whose row expiry cleanup removed meanwhile.
    ///
    /// What happens depends on where an error arose, not on its class:
    ///
    /// - An expired sign-in is removed without being opened, and gives `None`.
    /// - A provider or purpose this version does not know is left in place with
    ///   [`StoreError::InvalidInput`]: a newer release may have written it, and
    ///   it goes when it expires. A known purpose whose row lacks a column it
    ///   needs (a request ID, a tenant, a continuation) is removed with
    ///   [`StoreError::InvalidInput`].
    /// - Of the errors from opening the values, only [`StoreError::Decrypt`]
    ///   removes the sign-in, which is unreadable for good (if that fails, the
    ///   `Decrypt` is still returned). Every other error leaves it, so that
    ///   finishing it works once the cause has passed: `KeyWrap`, a failing
    ///   database, and any error a key wrapper answers (`InvalidInput` too).
    ///   So does [`StoreError::NewerFormat`], for a value that a newer version
    ///   may have written.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails, or one of those that is described
    /// above.
    pub async fn take_upstream_request(&self, state: &str) -> Result<Option<UpstreamRequest>> {
        let state_hash = hash_secret(state);
        let row = sqlx::query(
            "SELECT provider, purpose, request_id_ciphertext, tenant, continuation_ciphertext, \
             verifier_ciphertext, binding_hash, expires_at FROM upstream_requests \
             WHERE state_hash = $1",
        )
        .bind(&state_hash)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let expires_at: i64 = row.try_get("expires_at")?;
        if expires_at <= now() {
            remove_upstream_request(&self.pool, &state_hash).await?;
            return Ok(None);
        }
        let shape = match row_shape(&row) {
            Ok(shape) => shape,
            Err(Unshaped::Unknown(what)) => return Err(StoreError::InvalidInput(what)),
            Err(Unshaped::Inconsistent(what)) => {
                return Err(self
                    .discard_upstream_request(&state_hash, StoreError::InvalidInput(what))
                    .await);
            }
            Err(Unshaped::Failed(err)) => return Err(err),
        };
        let request = match self.open_upstream_request(&state_hash, shape).await {
            Ok(request) => request,
            Err(StoreError::Decrypt) => {
                let gone = self
                    .discard_upstream_request(&state_hash, StoreError::Decrypt)
                    .await;
                return Err(gone);
            }
            Err(err) => return Err(err),
        };
        // Whoever deletes the row owns the sign-in; a take that lost gets none.
        if !remove_upstream_request(&self.pool, &state_hash).await? {
            return Ok(None);
        }
        Ok(Some(request))
    }

    /// Removes a sign-in that can never be finished and returns `err`; if the
    /// removal fails, that is logged and the row goes at expiry.
    async fn discard_upstream_request(&self, state_hash: &str, err: StoreError) -> StoreError {
        if let Err(failure) = remove_upstream_request(&self.pool, state_hash).await {
            tracing::warn!(%failure, "could not remove a sign-in that cannot be finished");
        }
        err
    }

    /// Opens the values of a sign-in for the tenant the row is bound to. The
    /// errors are those of opening only: the row's shape was checked.
    async fn open_upstream_request(
        &self,
        state_hash: &str,
        shape: Shape,
    ) -> Result<UpstreamRequest> {
        let tenant = shape.tenant.as_str();
        let purpose = match shape.purpose {
            PurposeShape::Authorize(stored) => {
                let legacy = request_id_context(state_hash);
                let slot = REQUEST_ID_SLOT;
                let open = self.open_secret(tenant, slot, state_hash, &legacy, &stored);
                UpstreamPurpose::Authorize {
                    request_id: open.await?,
                }
            }
            PurposeShape::Account => UpstreamPurpose::Account,
            PurposeShape::Continue(stored) => {
                let legacy = continuation_context(state_hash);
                let slot = CONTINUATION_SLOT;
                let open = self.open_secret(tenant, slot, state_hash, &legacy, &stored);
                UpstreamPurpose::Continue {
                    tenant: shape.tenant.clone(),
                    continuation: open.await?,
                }
            }
        };
        let legacy = verifier_context(state_hash);
        let open = self.open_secret(tenant, VERIFIER_SLOT, state_hash, &legacy, &shape.verifier);
        let code_verifier = open.await?;
        Ok(UpstreamRequest {
            provider: shape.provider,
            purpose,
            code_verifier,
            binding_hash: shape.binding_hash,
        })
    }
}

/// What a row of `upstream_requests` says before any value is opened.
struct Shape {
    provider: Provider,
    /// The tenant the values are bound to: the one that started the sign-in,
    /// else the default one, a rule that depends on the row alone, not on the
    /// store reading it.
    tenant: String,
    purpose: PurposeShape,
    verifier: String,
    binding_hash: String,
}

/// The purpose of a row, with the stored text it needs.
enum PurposeShape {
    Authorize(String),
    Account,
    Continue(String),
}

/// Why a row has no [`Shape`].
enum Unshaped {
    /// A provider or purpose this version does not know.
    Unknown(&'static str),
    /// A known purpose, and a column it needs is empty.
    Inconsistent(&'static str),
    /// The row could not be read.
    Failed(StoreError),
}

impl From<sqlx::Error> for Unshaped {
    fn from(err: sqlx::Error) -> Self {
        Self::Failed(err.into())
    }
}

/// Reads the shape of a row. It opens nothing, so `InvalidInput` can only come
/// from the row itself.
fn row_shape(row: &sqlx::any::AnyRow) -> std::result::Result<Shape, Unshaped> {
    let provider: String = row.try_get("provider")?;
    let provider = Provider::parse(&provider).ok_or(Unshaped::Unknown("unknown provider"))?;
    let row_tenant: Option<String> = row.try_get("tenant")?;
    let purpose: String = row.try_get("purpose")?;
    let (tenant, purpose) = match purpose.as_str() {
        "authorize" => {
            let stored: Option<String> = row.try_get("request_id_ciphertext")?;
            let stored = stored.ok_or(Unshaped::Inconsistent("missing request id"))?;
            let tenant = row_tenant.unwrap_or_else(|| DEFAULT_TENANT.to_owned());
            (tenant, PurposeShape::Authorize(stored))
        }
        "account" => {
            let tenant = row_tenant.unwrap_or_else(|| DEFAULT_TENANT.to_owned());
            (tenant, PurposeShape::Account)
        }
        "continue" => {
            let stored: Option<String> = row.try_get("continuation_ciphertext")?;
            let (Some(tenant), Some(stored)) = (row_tenant, stored) else {
                return Err(Unshaped::Inconsistent("missing tenant or continuation"));
            };
            (tenant, PurposeShape::Continue(stored))
        }
        _ => return Err(Unshaped::Unknown("unknown purpose")),
    };
    Ok(Shape {
        provider,
        tenant,
        purpose,
        verifier: row.try_get("verifier_ciphertext")?,
        binding_hash: row.try_get("binding_hash")?,
    })
}

/// Deletes the sign-in stored for `state_hash`; whether this call removed it.
async fn remove_upstream_request(pool: &sqlx::AnyPool, state_hash: &str) -> Result<bool> {
    let removed = sqlx::query("DELETE FROM upstream_requests WHERE state_hash = $1")
        .bind(state_hash)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(removed == 1)
}

/// One re-encryption (or sign-in) injected between the read and the update.
#[cfg(test)]
type RefreshCasHook =
    Box<dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>;

/// Runs between the refresh-token read and its conditional update.
///
/// The hook is removed when it runs, so one call simulates a single
/// re-encryption landing in that window.
#[cfg(test)]
fn refresh_cas_hooks()
-> &'static std::sync::Mutex<std::collections::HashMap<String, RefreshCasHook>> {
    static HOOKS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, RefreshCasHook>>,
    > = std::sync::OnceLock::new();
    HOOKS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

#[cfg(test)]
fn insert_refresh_cas_hook(account_id: &str, hook: RefreshCasHook) {
    refresh_cas_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(account_id.to_owned(), hook);
}

#[cfg(test)]
async fn fire_refresh_cas_hook(account_id: &str) {
    let hook = refresh_cas_hooks()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(account_id);
    if let Some(hook) = hook {
        hook().await;
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]
mod tests {
    use std::pin::Pin;

    use secrecy::{ExposeSecret, SecretString};

    use super::{REFRESH_SLOT, RefreshCasHook, Store, UpstreamTokens, insert_refresh_cas_hook};
    use crate::DEFAULT_TENANT;
    use crate::accounts::{AccountId, OAuthAccount, Provider};
    use crate::crypto::MasterKey;

    fn key() -> MasterKey {
        MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap()
    }

    fn secret(value: &str) -> SecretString {
        SecretString::from(value.to_owned())
    }

    fn tokens(refresh: &str) -> UpstreamTokens {
        UpstreamTokens {
            refresh_token: secret(refresh),
            access_token: Some(secret("access-1")),
            access_expires_at: Some(crate::now() + 3600),
            scope: "Mail.Read offline_access".to_owned(),
        }
    }

    async fn sqlite(key: &MasterKey) -> (Store, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("tokens.db").display());
        (Store::connect(&url, key).await.unwrap(), dir, url)
    }

    /// Stores the refresh token of `account` again, sealed anew under its
    /// tenant's data key: the same plaintext in another ciphertext, which is
    /// what a re-encryption that lands between the read and the update does.
    fn reseal_hook(
        store: Store,
        account: AccountId,
        refresh_token: &'static str,
    ) -> RefreshCasHook {
        Box::new(move || {
            Box::pin(async move {
                let tenant = store.sealer(DEFAULT_TENANT).await.unwrap();
                let plaintext = refresh_token.as_bytes();
                let sealed = tenant.seal(REFRESH_SLOT, &account.0, plaintext).unwrap();
                assert!(sealed.starts_with("v2.1."), "{sealed}");
                let updated = sqlx::query(
                    "UPDATE upstream_tokens SET refresh_token_ciphertext = $1 WHERE account_id = $2",
                )
                .bind(&sealed)
                .bind(&account.0)
                .execute(&store.pool)
                .await
                .unwrap()
                .rows_affected();
                assert_eq!(updated, 1, "the refresh token was not sealed again");
            }) as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        })
    }

    #[tokio::test]
    async fn reencryption_between_read_and_write_keeps_the_new_refresh_token() {
        let (store, _dir, _url) = sqlite(&key()).await;
        let account = store
            .upsert_oauth_account(
                &OAuthAccount {
                    provider: Provider::Graph,
                    subject: "person-subject",
                    email: "person@example.com",
                },
                &tokens("refresh-1"),
            )
            .await
            .unwrap();
        let original = store
            .upstream_tokens(&account.id)
            .await
            .unwrap()
            .unwrap()
            .tokens
            .refresh_token;
        let hook = reseal_hook(store.clone(), account.id.clone(), "refresh-1");
        insert_refresh_cas_hook(&account.id.0, hook);
        assert!(
            store
                .save_upstream_tokens_if_current(&account.id, &original, &tokens("refresh-2"))
                .await
                .unwrap()
        );
        let stored = store.upstream_tokens(&account.id).await.unwrap().unwrap();
        assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-2");
        assert_eq!(
            stored
                .tokens
                .access_token
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("access-1")
        );
        store.close().await;
    }

    #[tokio::test]
    async fn reencryption_between_read_and_write_still_marks_the_grant_invalid() {
        let (store, _dir, _url) = sqlite(&key()).await;
        let account = store
            .upsert_oauth_account(
                &OAuthAccount {
                    provider: Provider::Graph,
                    subject: "person-subject",
                    email: "person@example.com",
                },
                &tokens("refresh-1"),
            )
            .await
            .unwrap();
        let refresh = store
            .upstream_tokens(&account.id)
            .await
            .unwrap()
            .unwrap()
            .tokens
            .refresh_token;
        let hook = reseal_hook(store.clone(), account.id.clone(), "refresh-1");
        insert_refresh_cas_hook(&account.id.0, hook);
        assert!(
            store
                .mark_upstream_tokens_invalid_if_current(&account.id, &refresh, "invalid_grant",)
                .await
                .unwrap()
        );
        let invalid = store.upstream_tokens(&account.id).await.unwrap().unwrap();
        assert_eq!(invalid.invalid_reason.as_deref(), Some("invalid_grant"));
        assert!(invalid.tokens.access_token.is_none());
        assert_eq!(invalid.tokens.refresh_token.expose_secret(), "refresh-1");
    }

    #[tokio::test]
    async fn a_replaced_refresh_token_is_not_overwritten_when_the_row_is_rewritten() {
        let (store, _dir, _url) = sqlite(&key()).await;
        let account = store
            .upsert_oauth_account(
                &OAuthAccount {
                    provider: Provider::Gmail,
                    subject: "person-subject",
                    email: "person@example.com",
                },
                &tokens("refresh-1"),
            )
            .await
            .unwrap();
        let original = store
            .upstream_tokens(&account.id)
            .await
            .unwrap()
            .unwrap()
            .tokens
            .refresh_token;
        let signed_in = store.clone();
        let account_id = account.id.clone();
        insert_refresh_cas_hook(
            &account.id.0,
            Box::new(move || {
                Box::pin(async move {
                    signed_in
                        .save_upstream_tokens(&account_id, &tokens("refresh-signed-in"))
                        .await
                        .unwrap();
                }) as Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            }),
        );
        assert!(
            !store
                .save_upstream_tokens_if_current(&account.id, &original, &tokens("refresh-stale"))
                .await
                .unwrap()
        );
        let stored = store.upstream_tokens(&account.id).await.unwrap().unwrap();
        assert_eq!(
            stored.tokens.refresh_token.expose_secret(),
            "refresh-signed-in"
        );
        assert!(stored.invalid_reason.is_none());
    }
}
