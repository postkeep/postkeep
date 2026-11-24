//! Pending authorization requests, authorization codes, grants and tokens.
//!
//! Every secret value (request ID, code, token) is passed in raw and stored
//! as a SHA-256 hash. Redeeming a code or refresh token marks it used
//! atomically. It is kept until it expires so a replay revokes the grant
//! (RFC 9700 section 4.14.2), except for refresh rotations within the
//! configured grace from the first use.
//!
//! A code and the grant made from it are for one [`GrantSubject`]: a
//! mailbox account, or a principal that an embedding approved.

use std::time::Duration;

use sqlx::Row;
use sqlx::any::AnyRow;

use crate::crypto::hash_secret;
use crate::db::{expires_in, now};
use crate::{AccountId, Result, Store, StoreError};

/// An authorization request waiting for the user to sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// Requesting client.
    pub client_id: String,
    /// Redirect URI to return to (already validated against the client).
    pub redirect_uri: String,
    /// Opaque client state to echo back.
    pub state: Option<String>,
    /// PKCE S256 code challenge.
    pub code_challenge: String,
    /// Requested scope.
    pub scope: String,
    /// RFC 8707 resource indicator.
    pub resource: Option<String>,
}

/// Who an authorization code and its grant are for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantSubject {
    /// A mailbox account that signed in on the sign-in page or with
    /// Microsoft or Google.
    Account(AccountId),
    /// A principal that an embedding approved: a non-empty, opaque string
    /// that only the embedding's principal resolver interprets.
    Principal(String),
}

impl GrantSubject {
    /// The `account_id` and `principal` columns.
    fn columns(&self) -> Result<(Option<&str>, Option<&str>)> {
        match self {
            Self::Account(id) => Ok((Some(&id.0), None)),
            Self::Principal(principal) if principal.is_empty() => {
                Err(StoreError::InvalidInput("principal must not be empty"))
            }
            Self::Principal(principal) => Ok((None, Some(principal))),
        }
    }

    fn from_row(row: &AnyRow) -> Result<Self> {
        let principal: Option<String> = row.try_get("principal")?;
        Ok(match principal {
            Some(principal) => Self::Principal(principal),
            None => Self::Account(AccountId(row.try_get("account_id")?)),
        })
    }
}

/// What an authorization code grants once redeemed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeGrant {
    /// Client the code was issued to.
    pub client_id: String,
    /// Who signed in.
    pub subject: GrantSubject,
    /// Redirect URI used in the authorization request.
    pub redirect_uri: String,
    /// PKCE S256 code challenge.
    pub code_challenge: String,
    /// Granted scope.
    pub scope: String,
    /// RFC 8707 resource indicator.
    pub resource: Option<String>,
}

/// The outcome of redeeming a one-time value (an authorization code or a
/// refresh token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redemption<T> {
    /// First use of a valid value.
    Valid(T),
    /// The value was already used. The grant it led to has been revoked.
    Replayed,
    /// Unknown, expired, or issued to another client.
    Invalid,
}

impl<T> Redemption<T> {
    /// The redeemed value, if this was its first valid use.
    #[must_use]
    pub fn valid(self) -> Option<T> {
        match self {
            Self::Valid(value) => Some(value),
            Self::Replayed | Self::Invalid => None,
        }
    }
}

/// The grant behind an access or refresh token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenGrant {
    /// Grant identifier.
    pub grant_id: String,
    /// Client the tokens were issued to.
    pub client_id: String,
    /// Who the tokens act for.
    pub subject: GrantSubject,
    /// The account's email address; `None` for a principal.
    pub email: Option<String>,
    /// Granted scope.
    pub scope: String,
    /// RFC 8707 resource indicator the tokens are bound to.
    pub resource: Option<String>,
    /// Expiry of the presented token (Unix seconds).
    pub expires_at: i64,
}

/// The outcome of [`Store::rotate_refresh_token`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshRotation {
    /// The presented token was marked used and the new pair was stored.
    Rotated(TokenGrant),
    /// The used token was ineligible for grace reuse. Its grant was revoked.
    Replayed,
    /// Unknown, expired, or issued to another client. Nothing was changed.
    Invalid,
    /// The account may not receive tokens. The presented token was marked
    /// used and no new pair was stored.
    Refused(TokenGrant),
}

impl Store {
    /// Stores a pending authorization request under the secret `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn save_authorization_request(
        &self,
        id: &str,
        request: &AuthorizationRequest,
        ttl: Duration,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO authorization_requests \
             (id_hash, client_id, redirect_uri, state, code_challenge, scope, resource, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(hash_secret(id))
        .bind(&request.client_id)
        .bind(&request.redirect_uri)
        .bind(&request.state)
        .bind(&request.code_challenge)
        .bind(&request.scope)
        .bind(&request.resource)
        .bind(expires_in(ttl))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Returns an unexpired pending authorization request.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn authorization_request(&self, id: &str) -> Result<Option<AuthorizationRequest>> {
        let row = sqlx::query(
            "SELECT client_id, redirect_uri, state, code_challenge, scope, resource \
             FROM authorization_requests WHERE id_hash = $1 AND expires_at > $2",
        )
        .bind(hash_secret(id))
        .bind(now())
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok(AuthorizationRequest {
                client_id: row.try_get("client_id")?,
                redirect_uri: row.try_get("redirect_uri")?,
                state: row.try_get("state")?,
                code_challenge: row.try_get("code_challenge")?,
                scope: row.try_get("scope")?,
                resource: row.try_get("resource")?,
            })
        })
        .transpose()
    }

    /// Deletes a pending authorization request.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn delete_authorization_request(&self, id: &str) -> Result<()> {
        sqlx::query("DELETE FROM authorization_requests WHERE id_hash = $1")
            .bind(hash_secret(id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stores an authorization code.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AccountDeleted`] if the code's account is gone,
    /// as when its deletion commits just after a sign-in stored it, and
    /// another error if the principal is empty or the query fails.
    pub async fn save_code(&self, code: &str, grant: &CodeGrant, ttl: Duration) -> Result<()> {
        let (account_id, principal) = grant.subject.columns()?;
        let saved = sqlx::query(
            "INSERT INTO authorization_codes \
             (code_hash, client_id, account_id, principal, redirect_uri, code_challenge, scope, \
             resource, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(hash_secret(code))
        .bind(&grant.client_id)
        .bind(account_id)
        .bind(principal)
        .bind(&grant.redirect_uri)
        .bind(&grant.code_challenge)
        .bind(&grant.scope)
        .bind(&grant.resource)
        .bind(expires_in(ttl))
        .execute(&self.pool)
        .await;
        match (saved, account_id) {
            (Ok(_), _) => Ok(()),
            (Err(err), Some(account)) => Err(self.unless_deleted(account, err).await),
            (Err(err), None) => Err(err.into()),
        }
    }

    /// Redeems an authorization code. The first use of an unexpired code
    /// returns its grant. A second use revokes the grant created from the
    /// first one (OAuth 2.1 section 4.1.3) and returns
    /// [`Redemption::Replayed`].
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn take_code(&self, code: &str) -> Result<Redemption<CodeGrant>> {
        let hash = hash_secret(code);
        let now = now();
        let row = sqlx::query(
            "UPDATE authorization_codes SET used_at = $2 \
             WHERE code_hash = $1 AND used_at IS NULL AND expires_at > $2 \
             RETURNING client_id, account_id, principal, redirect_uri, code_challenge, scope, \
             resource",
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            return Ok(Redemption::Valid(CodeGrant {
                client_id: row.try_get("client_id")?,
                subject: GrantSubject::from_row(&row)?,
                redirect_uri: row.try_get("redirect_uri")?,
                code_challenge: row.try_get("code_challenge")?,
                scope: row.try_get("scope")?,
                resource: row.try_get("resource")?,
            }));
        }
        let mut tx = self.begin_write().await?;
        let replayed = sqlx::query(
            "UPDATE authorization_codes SET replayed = 1 \
             WHERE code_hash = $1 AND used_at IS NOT NULL RETURNING grant_id",
        )
        .bind(&hash)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = replayed else {
            return Ok(Redemption::Invalid);
        };
        let grant_id: Option<String> = row.try_get("grant_id")?;
        if let Some(grant_id) = grant_id {
            revoke_grant(&mut tx, &grant_id).await?;
        }
        tx.commit().await?;
        Ok(Redemption::Replayed)
    }

    /// Creates a grant and returns its ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the principal is empty or the query fails.
    pub async fn create_grant(&self, code: &CodeGrant) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut tx = self.begin_write().await?;
        insert_grant(&mut tx, &id, code).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Links a code just redeemed with [`take_code`](Self::take_code) to a
    /// new grant, creates the grant, and stores `access_token` and
    /// `refresh_token`, in one transaction.
    ///
    /// The tokens have to land with the grant.
    /// [`Store::purge_expired`](crate::Store::purge_expired) deletes every
    /// grant that has no access or refresh token, so a grant committed on
    /// its own can disappear before its tokens are inserted. The token
    /// insert then fails its foreign key, and the code is already spent.
    ///
    /// Returns `None` if the code was replayed or deleted in the meantime.
    /// The transaction is rolled back, so no grant and no tokens are stored.
    /// A later replay of a grant this call did create still revokes it.
    ///
    /// # Errors
    ///
    /// Returns an error if the principal is empty or a query fails.
    pub async fn create_grant_for_code(
        &self,
        code: &str,
        grant: &CodeGrant,
        access_token: &str,
        access_ttl: Duration,
        refresh_token: &str,
        refresh_ttl: Duration,
    ) -> Result<Option<String>> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut tx = self.begin_write().await?;
        // The code before the grant, as every writer of codes takes it: the
        // grant's insert locks the account's row as a foreign key does, and
        // the account's deletion holds the codes and deletes that row last.
        // `grant_id` has no foreign key, so the link can come first.
        let linked = sqlx::query(
            "UPDATE authorization_codes SET grant_id = $2 \
             WHERE code_hash = $1 AND used_at IS NOT NULL AND replayed = 0",
        )
        .bind(hash_secret(code))
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if linked == 0 {
            tx.rollback().await?;
            return Ok(None);
        }
        insert_grant(&mut tx, &id, grant).await?;
        insert_token_pair(
            &mut tx,
            &id,
            access_token,
            access_ttl,
            refresh_token,
            refresh_ttl,
        )
        .await?;
        tx.commit().await?;
        Ok(Some(id))
    }

    /// Stores a new access token and refresh token for a grant that already
    /// has a token row.
    ///
    /// Refresh rotation does not use this. It stores the replacement pair in
    /// the same transaction that marks the presented refresh token used
    /// ([`rotate_refresh_token`](Self::rotate_refresh_token)). The first pair
    /// of a grant created from an authorization code is stored by
    /// [`create_grant_for_code`](Self::create_grant_for_code).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn save_tokens(
        &self,
        grant_id: &str,
        access_token: &str,
        access_ttl: Duration,
        refresh_token: &str,
        refresh_ttl: Duration,
    ) -> Result<()> {
        let mut tx = self.begin_write().await?;
        insert_token_pair(
            &mut tx,
            grant_id,
            access_token,
            access_ttl,
            refresh_token,
            refresh_ttl,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Resolves an unexpired access token to its grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn access_token(&self, token: &str) -> Result<Option<TokenGrant>> {
        let row = sqlx::query(
            "SELECT g.id AS grant_id, g.client_id, g.account_id, g.principal, a.email, g.scope, \
             g.resource, t.expires_at FROM access_tokens t JOIN grants g ON g.id = t.grant_id \
             LEFT JOIN accounts a ON a.id = g.account_id \
             WHERE t.token_hash = $1 AND t.expires_at > $2",
        )
        .bind(hash_secret(token))
        .bind(now())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(token_grant).transpose()
    }

    /// Rotates a refresh token: claims it and stores `access_token` and
    /// `refresh_token` in one transaction, then commits.
    ///
    /// If the transaction fails, nothing is committed. On first use the token
    /// stays unused; grace reuse preserves the first use's timestamp. Splitting
    /// the claim and insert across transactions can leave the token used
    /// without a replacement; a retry then depends on the remaining grace.
    ///
    /// `email_allowed` runs after the claim and before the insert, while the
    /// transaction is still open. It must not use the database. When it
    /// returns `false`, the presented token is still marked used and no new
    /// pair is stored ([`RefreshRotation::Refused`]), which is the same
    /// outcome as claiming the token and then refusing to issue. It sees
    /// only account grants: a principal has no address, so its grant is
    /// rotated without the check.
    ///
    /// A wrong client or an expired token is [`RefreshRotation::Invalid`]
    /// and is left unchanged. Presentations within `reuse_grace` of the
    /// first use issue separate pairs without extending that window. A
    /// zero grace disables this exception. Elapsed time is counted in whole
    /// seconds from the stored first use; a clock behind it fails closed.
    /// Outside the grace, reuse is [`RefreshRotation::Replayed`] and revokes
    /// the grant (RFC 9700 section 4.14.2).
    ///
    /// The claim is one conditional `UPDATE` and it is the first statement
    /// in the transaction, so it takes the write lock before any read. A
    /// concurrent second use then follows the grace or replay path instead
    /// of failing with `SQLITE_BUSY_SNAPSHOT`.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails. A failed rotation rolls back,
    /// preserving the token's prior state: unused on first use, or used with
    /// the original timestamp on grace reuse.
    #[allow(
        clippy::too_many_arguments,
        reason = "the presented token, its replacement pair and the allow-list check are one rotation"
    )]
    pub async fn rotate_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        access_token: &str,
        access_ttl: Duration,
        refresh_token: &str,
        refresh_ttl: Duration,
        reuse_grace: Duration,
        email_allowed: impl Fn(&str) -> bool + Send,
    ) -> Result<RefreshRotation> {
        self.redeem_refresh_token(
            token,
            client_id,
            reuse_grace,
            Some(Replacement {
                access_token,
                access_ttl,
                refresh_token,
                refresh_ttl,
            }),
            email_allowed,
        )
        .await
    }

    /// Redeems a refresh token without issuing a replacement. The first use
    /// marks it used and returns its grant. Presenting a used token again
    /// revokes the whole grant (RFC 9700 section 4.14.2). Expired tokens and
    /// tokens of another client are [`Redemption::Invalid`].
    ///
    /// Prefer [`rotate_refresh_token`](Self::rotate_refresh_token) when the
    /// caller is about to store a new pair. Claiming here and inserting
    /// later leaves the token used if that insert fails.
    ///
    /// The token is claimed with one conditional `UPDATE` before it is read.
    /// A read-then-write under SQLite WAL snapshot isolation makes the loser's
    /// update fail with `SQLITE_BUSY_SNAPSHOT` instead of matching zero rows,
    /// so the replay would surface as a storage error and the grant would
    /// stay live. The claim takes the write lock first; a concurrent second
    /// use then sees zero rows and revokes the grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn take_refresh_token(
        &self,
        token: &str,
        client_id: &str,
    ) -> Result<Redemption<TokenGrant>> {
        // No allow-list is applied, so a claim is never `Refused`.
        Ok(
            match self
                .redeem_refresh_token(token, client_id, Duration::ZERO, None, |_| true)
                .await?
            {
                RefreshRotation::Rotated(grant) | RefreshRotation::Refused(grant) => {
                    Redemption::Valid(grant)
                }
                RefreshRotation::Replayed => Redemption::Replayed,
                RefreshRotation::Invalid => Redemption::Invalid,
            },
        )
    }

    /// Claims `token` and, when `replacement` is set, stores that pair before
    /// committing. See [`rotate_refresh_token`](Self::rotate_refresh_token).
    async fn redeem_refresh_token(
        &self,
        token: &str,
        client_id: &str,
        reuse_grace: Duration,
        replacement: Option<Replacement<'_>>,
        email_allowed: impl Fn(&str) -> bool + Send,
    ) -> Result<RefreshRotation> {
        let hash = hash_secret(token);
        let now = now();
        let mut tx = self.begin_write().await?;
        // Claim before reading. The client and expiry are part of the write
        // so a wrong client or an expired token is left unused. This write
        // is the first statement, so it takes the write lock up front.
        let claimed = sqlx::query(
            "UPDATE refresh_tokens SET used_at = $2 \
             WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2 \
               AND grant_id IN (SELECT id FROM grants WHERE client_id = $3) \
             RETURNING grant_id",
        )
        .bind(&hash)
        .bind(now)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await?;
        if claimed.is_some() {
            return issue_pair(tx, &hash, replacement, email_allowed).await;
        }
        // Not claimed: unknown, expired, another client's, or already used.
        // Only a still-valid token of this client that is already used is a
        // replay. A concurrent claim that committed first looks the same.
        let replay = sqlx::query(
            "SELECT g.id AS grant_id, t.used_at FROM refresh_tokens t \
             JOIN grants g ON g.id = t.grant_id \
             WHERE t.token_hash = $1 AND t.expires_at > $2 AND g.client_id = $3 \
               AND t.used_at IS NOT NULL",
        )
        .bind(&hash)
        .bind(now)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = replay else {
            return Ok(RefreshRotation::Invalid);
        };
        let grant_id: String = row.try_get("grant_id")?;
        let used_at: i64 = row.try_get("used_at")?;
        let current = crate::db::now();
        if replacement.is_some()
            && current >= used_at
            && Duration::from_secs(current.abs_diff(used_at)) < reuse_grace
        {
            // Lock only issuance: revocation must delete access rows first.
            // If a revocation won, the presented token is already gone.
            let locked = sqlx::query(
                "UPDATE refresh_tokens SET used_at = used_at \
                 WHERE token_hash = $1 AND grant_id = $2 RETURNING grant_id",
            )
            .bind(&hash)
            .bind(&grant_id)
            .fetch_optional(&mut *tx)
            .await?;
            if locked.is_none() {
                return Ok(RefreshRotation::Invalid);
            }
            return issue_pair(tx, &hash, replacement, email_allowed).await;
        }
        revoke_grant(&mut tx, &grant_id).await?;
        tx.commit().await?;
        Ok(RefreshRotation::Replayed)
    }

    /// Revokes the grant behind an access or refresh token when that grant
    /// belongs to `client_id`, invalidating all of its tokens. Returns
    /// whether anything was revoked. A token issued to another client is
    /// left alone (RFC 7009 section 2.1).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn revoke_token(&self, token: &str, client_id: &str) -> Result<bool> {
        let hash = hash_secret(token);
        let mut tx = self.begin_write().await?;
        let grant_id: Option<String> = sqlx::query_scalar(
            "SELECT g.id FROM access_tokens t JOIN grants g ON g.id = t.grant_id \
             WHERE t.token_hash = $1 AND g.client_id = $2 \
             UNION \
             SELECT g.id FROM refresh_tokens t JOIN grants g ON g.id = t.grant_id \
             WHERE t.token_hash = $1 AND g.client_id = $2",
        )
        .bind(&hash)
        .bind(client_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(grant_id) = grant_id else {
            return Ok(false);
        };
        revoke_grant(&mut tx, &grant_id).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Revokes every grant of `principal`, with its codes and tokens, for
    /// example when an embedding removes the person behind it. Account
    /// grants are untouched. Returns the number of revoked grants.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn revoke_principal_grants(&self, principal: &str) -> Result<u64> {
        let mut tx = self.begin_write().await?;
        let revoked = revoke_grants(&mut tx, principal, None).await?;
        tx.commit().await?;
        Ok(revoked)
    }
}

/// Revokes a principal's grants, codes and tokens in the caller's transaction.
///
/// `client` limits the revocation to that client ID; `None` revokes them
/// for all clients of the principal. Returns the number of grants revoked.
/// On SQLite, use `BEGIN IMMEDIATE` or call this before the transaction reads.
///
/// # Errors
///
/// Returns an error if a query fails.
pub async fn revoke_grants(
    tx: &mut sqlx::Transaction<'_, sqlx::Any>,
    principal: &str,
    client: Option<&str>,
) -> Result<u64> {
    macro_rules! for_subject {
        ($prefix:literal $(, $suffix:literal)?) => {
            concat!($prefix, "principal = $1 AND client_id = COALESCE($2, client_id)" $(, $suffix)?)
        };
    }
    let query = |statement| sqlx::query(statement).bind(principal).bind(client);
    // The codes, then the tokens, then the grants: the store's lock
    // order, which a replayed code's revocation keeps too.
    for statement in [
        for_subject!("DELETE FROM authorization_codes WHERE "),
        for_subject!(
            "DELETE FROM access_tokens WHERE grant_id IN (SELECT id FROM grants WHERE ",
            ")"
        ),
        for_subject!(
            "DELETE FROM refresh_tokens WHERE grant_id IN (SELECT id FROM grants WHERE ",
            ")"
        ),
    ] {
        query(statement).execute(&mut **tx).await?;
    }
    Ok(query(for_subject!("DELETE FROM grants WHERE "))
        .execute(&mut **tx)
        .await?
        .rows_affected())
}

/// Access and refresh tokens stored in the same transaction as a claim.
#[derive(Clone, Copy)]
struct Replacement<'a> {
    access_token: &'a str,
    access_ttl: Duration,
    refresh_token: &'a str,
    refresh_ttl: Duration,
}

type Transaction<'a> = sqlx::Transaction<'a, sqlx::Any>;

/// Checks the allow-list and issues the replacement in the claim's transaction.
async fn issue_pair(
    mut tx: Transaction<'_>,
    hash: &str,
    replacement: Option<Replacement<'_>>,
    email_allowed: impl Fn(&str) -> bool + Send,
) -> Result<RefreshRotation> {
    let row = sqlx::query(
        "SELECT g.id AS grant_id, g.client_id, g.account_id, g.principal, a.email, \
         g.scope, g.resource, t.expires_at FROM refresh_tokens t \
         JOIN grants g ON g.id = t.grant_id \
         LEFT JOIN accounts a ON a.id = g.account_id \
         WHERE t.token_hash = $1",
    )
    .bind(hash)
    .fetch_one(&mut *tx)
    .await?;
    let grant = token_grant(&row)?;
    if let Some(replacement) = replacement {
        if grant
            .email
            .as_deref()
            .is_some_and(|email| !email_allowed(email))
        {
            tx.commit().await?;
            return Ok(RefreshRotation::Refused(grant));
        }
        insert_token_pair(
            &mut tx,
            &grant.grant_id,
            replacement.access_token,
            replacement.access_ttl,
            replacement.refresh_token,
            replacement.refresh_ttl,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(RefreshRotation::Rotated(grant))
}

async fn insert_grant(tx: &mut Transaction<'_>, id: &str, code: &CodeGrant) -> Result<()> {
    let (account_id, principal) = code.subject.columns()?;
    sqlx::query(
        "INSERT INTO grants (id, client_id, account_id, principal, scope, resource, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(id)
    .bind(&code.client_id)
    .bind(account_id)
    .bind(principal)
    .bind(&code.scope)
    .bind(&code.resource)
    .bind(now())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Inserts an access token and a refresh token for `grant_id`.
async fn insert_token_pair(
    tx: &mut Transaction<'_>,
    grant_id: &str,
    access_token: &str,
    access_ttl: Duration,
    refresh_token: &str,
    refresh_ttl: Duration,
) -> Result<()> {
    sqlx::query("INSERT INTO access_tokens (token_hash, grant_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash_secret(access_token))
        .bind(grant_id)
        .bind(expires_in(access_ttl))
        .execute(&mut **tx)
        .await?;
    sqlx::query(
        "INSERT INTO refresh_tokens (token_hash, grant_id, expires_at) VALUES ($1, $2, $3)",
    )
    .bind(hash_secret(refresh_token))
    .bind(grant_id)
    .bind(expires_in(refresh_ttl))
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Deletes a grant and all of its tokens.
async fn revoke_grant(tx: &mut Transaction<'_>, grant_id: &str) -> Result<()> {
    for statement in [
        "DELETE FROM access_tokens WHERE grant_id = $1",
        "DELETE FROM refresh_tokens WHERE grant_id = $1",
        "DELETE FROM grants WHERE id = $1",
    ] {
        sqlx::query(statement)
            .bind(grant_id)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

fn token_grant(row: &AnyRow) -> Result<TokenGrant> {
    let subject = GrantSubject::from_row(row)?;
    // The foreign key keeps an account grant's account, so its address is
    // never missing.
    let email = match subject {
        GrantSubject::Account(_) => Some(row.try_get("email")?),
        GrantSubject::Principal(_) => None,
    };
    Ok(TokenGrant {
        grant_id: row.try_get("grant_id")?,
        client_id: row.try_get("client_id")?,
        subject,
        email,
        scope: row.try_get("scope")?,
        resource: row.try_get("resource")?,
        expires_at: row.try_get("expires_at")?,
    })
}
