//! Browser sessions for the account page.

use std::time::Duration;

use sqlx::Row;

use crate::accounts::{Account, AccountId, account_from_row};
use crate::crypto::hash_secret;
use crate::db::{expires_in, now};
use crate::{Result, Store};

/// How long sessions last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionTtl {
    /// A session ends after this long without use.
    pub idle: Duration,
    /// A session ends this long after sign-in, however active.
    pub absolute: Duration,
}

/// What the account page shows about an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountOverview {
    /// The account.
    pub account: Account,
    /// When the account was first connected (Unix seconds).
    pub created_at: i64,
    /// Number of apps (OAuth clients) holding a live grant.
    pub apps: u64,
}

/// An app (OAuth client) holding a grant for an account, as the account
/// page lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountClient {
    /// Client identifier.
    pub id: String,
    /// The name the client registered with, if any. Chosen by the client:
    /// treat as untrusted text.
    pub name: Option<String>,
    /// The client's registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// When the account last authorized the client (Unix seconds).
    pub authorized_at: i64,
    /// When the client last got tokens for this account: the later of its
    /// last authorization and its last refresh (Unix seconds).
    pub last_active_at: i64,
}

impl Store {
    /// Stores a session for `account` under the hash of `token` (a random
    /// value chosen by the caller).
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AccountDeleted`](crate::StoreError::AccountDeleted)
    /// if the account is gone, as when its deletion commits just after a
    /// sign-in stored it, and another error if the query fails.
    pub async fn create_session(
        &self,
        token: &str,
        account: &AccountId,
        ttl: SessionTtl,
    ) -> Result<()> {
        let absolute = expires_in(ttl.absolute);
        if let Err(err) = sqlx::query(
            "INSERT INTO account_sessions (id_hash, account_id, created_at, expires_at, absolute_expires_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(hash_secret(token))
        .bind(&account.0)
        .bind(now())
        .bind(expires_in(ttl.idle).min(absolute))
        .bind(absolute)
        .execute(&self.pool)
        .await
        {
            return Err(self.unless_deleted(&account.0, err).await);
        }
        Ok(())
    }

    /// Returns the account of a live session and extends its idle expiry.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn session(&self, token: &str, ttl: SessionTtl) -> Result<Option<Account>> {
        let hash = hash_secret(token);
        let now = now();
        let row = sqlx::query(
            "SELECT a.id, a.email, a.provider, a.imap_server, s.absolute_expires_at FROM account_sessions s \
             JOIN accounts a ON a.id = s.account_id \
             WHERE s.id_hash = $1 AND s.expires_at > $2 AND s.absolute_expires_at > $2",
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let absolute: i64 = row.try_get("absolute_expires_at")?;
        sqlx::query("UPDATE account_sessions SET expires_at = $1 WHERE id_hash = $2")
            .bind(expires_in(ttl.idle).min(absolute))
            .bind(&hash)
            .execute(&self.pool)
            .await?;
        Ok(Some(account_from_row(&row)?))
    }

    /// Ends a session.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn delete_session(&self, token: &str) -> Result<()> {
        sqlx::query("DELETE FROM account_sessions WHERE id_hash = $1")
            .bind(hash_secret(token))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Ends every account-page session of `account` except the one stored
    /// under the hash of `keep`. Returns how many sessions were deleted.
    ///
    /// OAuth grants and tokens are left as they are.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn delete_other_sessions(&self, account: &AccountId, keep: &str) -> Result<u64> {
        let deleted =
            sqlx::query("DELETE FROM account_sessions WHERE account_id = $1 AND id_hash <> $2")
                .bind(&account.0)
                .bind(hash_secret(keep))
                .execute(&self.pool)
                .await?
                .rows_affected();
        Ok(deleted)
    }

    /// The account page summary of an account.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn account_overview(&self, id: &AccountId) -> Result<Option<AccountOverview>> {
        let row = sqlx::query(
            "SELECT id, email, provider, imap_server, created_at, \
             (SELECT COUNT(DISTINCT g.client_id) FROM grants g WHERE g.account_id = accounts.id) AS apps \
             FROM accounts WHERE id = $1",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            let apps: i64 = row.try_get("apps")?;
            Ok(AccountOverview {
                account: account_from_row(&row)?,
                created_at: row.try_get("created_at")?,
                apps: u64::try_from(apps).unwrap_or(0),
            })
        })
        .transpose()
    }

    /// Revokes every grant of an account, with its codes and tokens, so
    /// every connected app must sign in again. Returns the number of
    /// revoked grants.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn revoke_account_grants(&self, id: &AccountId) -> Result<u64> {
        let mut tx = self.begin_write().await?;
        // The codes, then the tokens, then the grants: the store's lock
        // order, which a replayed code's revocation keeps too.
        for statement in [
            "DELETE FROM authorization_codes WHERE account_id = $1",
            "DELETE FROM access_tokens WHERE grant_id IN (SELECT id FROM grants WHERE account_id = $1)",
            "DELETE FROM refresh_tokens WHERE grant_id IN (SELECT id FROM grants WHERE account_id = $1)",
        ] {
            sqlx::query(statement).bind(&id.0).execute(&mut *tx).await?;
        }
        let revoked = sqlx::query("DELETE FROM grants WHERE account_id = $1")
            .bind(&id.0)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(revoked)
    }

    /// The apps holding a grant for an account, most recently authorized
    /// first. Activity is per account: another account's use of the same
    /// client doesn't show.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn account_clients(&self, id: &AccountId) -> Result<Vec<AccountClient>> {
        let rows = sqlx::query(
            "SELECT c.id, c.name, c.redirect_uris, MAX(g.created_at) AS authorized_at, \
             (SELECT MAX(r.used_at) FROM refresh_tokens r JOIN grants rg ON rg.id = r.grant_id \
              WHERE rg.account_id = $2 AND rg.client_id = c.id) AS refreshed_at \
             FROM grants g JOIN oauth_clients c ON c.id = g.client_id \
             WHERE g.account_id = $1 \
             GROUP BY c.id, c.name, c.redirect_uris \
             ORDER BY authorized_at DESC, c.id",
        )
        .bind(&id.0)
        .bind(&id.0)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let redirect_uris: String = row.try_get("redirect_uris")?;
                let authorized_at: i64 = row.try_get("authorized_at")?;
                let refreshed_at: Option<i64> = row.try_get("refreshed_at")?;
                Ok(AccountClient {
                    id: row.try_get("id")?,
                    name: row.try_get("name")?,
                    redirect_uris: redirect_uris.lines().map(str::to_owned).collect(),
                    authorized_at,
                    last_active_at: refreshed_at.map_or(authorized_at, |at| at.max(authorized_at)),
                })
            })
            .collect()
    }

    /// Revokes one app's grants for an account, with their codes and
    /// tokens. Other accounts' grants to the same app are untouched.
    /// Returns the number of revoked grants.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn revoke_client_grants(&self, id: &AccountId, client_id: &str) -> Result<u64> {
        let mut tx = self.begin_write().await?;
        // The codes, then the tokens, then the grants: the store's lock
        // order, which a replayed code's revocation keeps too.
        for statement in [
            "DELETE FROM authorization_codes WHERE account_id = $1 AND client_id = $2",
            "DELETE FROM access_tokens WHERE grant_id IN \
             (SELECT id FROM grants WHERE account_id = $1 AND client_id = $2)",
            "DELETE FROM refresh_tokens WHERE grant_id IN \
             (SELECT id FROM grants WHERE account_id = $1 AND client_id = $2)",
        ] {
            sqlx::query(statement)
                .bind(&id.0)
                .bind(client_id)
                .execute(&mut *tx)
                .await?;
        }
        let revoked = sqlx::query("DELETE FROM grants WHERE account_id = $1 AND client_id = $2")
            .bind(&id.0)
            .bind(client_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(revoked)
    }
}
