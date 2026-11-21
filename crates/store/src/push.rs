//! Push notification subscriptions at Microsoft Graph and Gmail.

use sqlx::Row;

use crate::accounts::{AccountId, Provider};
use crate::crypto::{constant_time_eq, hash_secret};
use crate::db::now;
use crate::{Result, Store, StoreError};

/// A subscription that makes the provider call postkeep when mail arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushSubscription {
    /// [`Provider::Graph`] or [`Provider::Gmail`].
    pub provider: Provider,
    /// The Graph subscription id; `None` for Gmail.
    pub subscription_id: Option<String>,
    /// SHA-256 hash of the Graph `clientState` secret; `None` for Gmail.
    pub client_state_hash: Option<String>,
    /// When the subscription or watch expires (Unix seconds).
    pub expires_at: i64,
}

impl PushSubscription {
    /// Hashes a `clientState` secret for [`PushSubscription::client_state_hash`].
    #[must_use]
    pub fn hash_client_state(client_state: &str) -> String {
        hash_secret(client_state)
    }

    /// Whether `presented` is this subscription's `clientState`, compared
    /// in constant time. Always false when none is stored.
    #[must_use]
    pub fn client_state_matches(&self, presented: &str) -> bool {
        self.client_state_hash
            .as_deref()
            .is_some_and(|stored| constant_time_eq(stored, hash_secret(presented)))
    }
}

impl Store {
    /// Saves an account's subscription, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AccountDeleted`] if the account is gone, as when
    /// its deletion commits while the provider answers a renewal, and another
    /// error if the query fails.
    pub async fn save_push_subscription(
        &self,
        account: &AccountId,
        subscription: &PushSubscription,
    ) -> Result<()> {
        let now = now();
        if let Err(err) = sqlx::query(
            "INSERT INTO push_subscriptions (account_id, provider, subscription_id, client_state_hash, \
             expires_at, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6) \
             ON CONFLICT (account_id) DO UPDATE SET provider = excluded.provider, \
             subscription_id = excluded.subscription_id, client_state_hash = excluded.client_state_hash, \
             expires_at = excluded.expires_at, updated_at = excluded.updated_at",
        )
        .bind(&account.0)
        .bind(subscription.provider.as_str())
        .bind(&subscription.subscription_id)
        .bind(&subscription.client_state_hash)
        .bind(subscription.expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        {
            return Err(self.unless_deleted(&account.0, err).await);
        }
        Ok(())
    }

    /// An account's subscription, if it has one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn push_subscription(&self, account: &AccountId) -> Result<Option<PushSubscription>> {
        let row = sqlx::query(
            "SELECT provider, subscription_id, client_state_hash, expires_at \
             FROM push_subscriptions WHERE account_id = $1",
        )
        .bind(&account.0)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| subscription_from_row(&row)).transpose()
    }

    /// The account and subscription with a Graph subscription id.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn push_subscription_by_id(
        &self,
        subscription_id: &str,
    ) -> Result<Option<(AccountId, PushSubscription)>> {
        let row = sqlx::query(
            "SELECT account_id, provider, subscription_id, client_state_hash, expires_at \
             FROM push_subscriptions WHERE subscription_id = $1",
        )
        .bind(subscription_id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(|row| {
            Ok((
                AccountId(row.try_get("account_id")?),
                subscription_from_row(&row)?,
            ))
        })
        .transpose()
    }

    /// Removes an account's subscription record.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn delete_push_subscription(&self, account: &AccountId) -> Result<()> {
        sqlx::query("DELETE FROM push_subscriptions WHERE account_id = $1")
            .bind(&account.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Removes the account's subscription when its stored id is still
    /// `subscription_id`.
    ///
    /// `None` matches a row whose id is NULL. A replacement that stored a
    /// different Graph subscription id is left in place, so an unsubscribe
    /// that started against the previous id cannot delete the new row.
    /// Returns whether a row was removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn delete_push_subscription_if_id(
        &self,
        account: &AccountId,
        subscription_id: Option<&str>,
    ) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM push_subscriptions WHERE account_id = $1 \
             AND (subscription_id = $2 OR (subscription_id IS NULL AND $2 IS NULL))",
        )
        .bind(&account.0)
        .bind(subscription_id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

fn subscription_from_row(row: &sqlx::any::AnyRow) -> Result<PushSubscription> {
    let provider: String = row.try_get("provider")?;
    Ok(PushSubscription {
        provider: Provider::parse(&provider).ok_or(StoreError::InvalidInput("unknown provider"))?,
        subscription_id: row.try_get("subscription_id")?,
        client_state_hash: row.try_get("client_state_hash")?,
        expires_at: row.try_get("expires_at")?,
    })
}
