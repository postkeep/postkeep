//! Per-account new-mail webhook settings, watch position and delivery log.

use secrecy::SecretString;
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::accounts::AccountId;
use crate::crypto::Slot;
use crate::db::now;
use crate::events::{OutboxLimitChange, OutboxLimitsApplied};
use crate::{Result, Store, StoreError};

/// Consecutive failed deliveries after which a webhook is paused.
pub const MAX_CONSECUTIVE_FAILURES: i64 = 10;
/// Deliveries kept per account.
pub const KEPT_DELIVERIES: i64 = 20;

/// What a user configures.
#[derive(Clone)]
pub struct WebhookSettings {
    /// Whether events are sent.
    pub enabled: bool,
    /// The `https` URL, validated by the caller.
    pub url: String,
    /// A custom header sent with every event, validated by the caller.
    pub auth_header: Option<(String, SecretString)>,
    /// Whether events carry an `X-Signature-256` header.
    pub signing: bool,
    /// The HMAC signing secret (`whsec_…`).
    pub signing_secret: SecretString,
    /// Whether events include the sender and subject.
    pub include_sender: bool,
}

impl std::fmt::Debug for WebhookSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSettings")
            .field("enabled", &self.enabled)
            .field("signing", &self.signing)
            .field("include_sender", &self.include_sender)
            .finish_non_exhaustive()
    }
}

/// A stored webhook with its delivery state.
#[derive(Debug, Clone)]
pub struct Webhook {
    /// The settings.
    pub settings: WebhookSettings,
    /// Failed deliveries in a row.
    pub consecutive_failures: i64,
    /// Why an older version turned the webhook off after failures.
    ///
    /// New failures pause the webhook instead and leave this empty. The
    /// column is still read so a database from before that change can be
    /// migrated, and so a reason written by an older process is harmless.
    pub disabled_reason: Option<String>,
    /// When repeated failures paused delivery (Unix seconds).
    ///
    /// `None` while the webhook is delivering, or while the user has turned
    /// it off. A pause keeps `settings.enabled` set: the watcher keeps
    /// recording events, and delivery retries slowly until a real event
    /// succeeds or the user turns the webhook off.
    pub paused_at: Option<i64>,
    /// When a delivery was last attempted (Unix seconds).
    pub last_attempt_at: Option<i64>,
    /// When a delivery last succeeded (Unix seconds).
    pub last_success_at: Option<i64>,
    /// The last failure's summary, cleared by a success.
    pub last_error: Option<String>,
    /// The IMAP watch position, if an IMAP watcher has started.
    pub cursor: Option<WatchCursor>,
    /// The watch position of a Microsoft Graph or Gmail watcher, in a
    /// provider-specific format.
    pub position: Option<String>,
    /// The sequence number of the latest event.
    pub last_sequence: i64,
    /// The sequence number of the latest event the receiver accepted.
    pub delivered_sequence: i64,
    /// Stored retention override, in seconds.
    ///
    /// `None` uses the server default. Delivered and undelivered events
    /// both count toward the cap in [`outbox_max_events`](Self::outbox_max_events).
    pub outbox_retention_secs: Option<i64>,
    /// Stored cap on kept events, delivered or not.
    ///
    /// `None` uses the server default.
    pub outbox_max_events: Option<i64>,
    /// When the webhook was first saved (Unix seconds). A webhook that is
    /// deleted and saved again has a new time and a rules version of 0.
    pub created_at: i64,
    /// What [`Store::webhook_filter_rules_version`] answers.
    pub filter_rules_version: i64,
}

/// Where the watcher stopped: the folder's `UIDVALIDITY` and the highest
/// UID already reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchCursor {
    /// `UIDVALIDITY` of the watched folder.
    pub uid_validity: u32,
    /// Highest UID already reported (or present when watching began).
    pub last_uid: u32,
}

/// Watch state written in the same transaction as a new-mail event.
///
/// A crash cannot record the event without advancing the cursor or
/// position. That would deliver the same mail again under a new id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatchAdvance {
    /// IMAP cursor. The event is stored only when the row still has
    /// `expected`, the cursor the batch was read from. Otherwise nothing
    /// is written and [`append_mail_event`](crate::Store::append_mail_event)
    /// reports [`crate::AppendOutcome::StaleCursor`]. `next` is the cursor
    /// stored with the event.
    Cursor {
        /// Cursor the batch was read from.
        expected: WatchCursor,
        /// Cursor stored when the compare-and-set succeeds.
        next: WatchCursor,
    },
    /// Graph or Gmail position, in that provider's stored format. The event
    /// is stored only when the row still has `expected`, the position the
    /// batch was read from. Otherwise nothing is written and
    /// [`append_mail_event`](crate::Store::append_mail_event) reports
    /// [`crate::AppendOutcome::StaleCursor`]. `next` is the position stored
    /// with the event.
    Position {
        /// Position the batch was read from; `None` when none was stored.
        expected: Option<String>,
        /// Position stored when the compare-and-set succeeds.
        next: String,
    },
}

/// One delivery, as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryRecord {
    /// When it finished (Unix seconds).
    pub created_at: i64,
    /// Whether it was a test event.
    pub test: bool,
    /// Whether the receiver accepted it.
    pub succeeded: bool,
    /// A one-line description, such as `HTTP 200 OK (after 1 attempt)`.
    pub summary: String,
    /// Time to the response, if one arrived.
    pub elapsed_ms: Option<i64>,
}

/// What recording a delivery changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryEffect {
    /// Nothing beyond the log entry and the counters.
    None,
    /// The failure limit was reached. The webhook stays enabled and is
    /// paused: the watcher keeps recording, and delivery retries slowly
    /// until a real event succeeds.
    Paused,
}

impl Webhook {
    /// Whether repeated failures have paused delivery.
    ///
    /// A webhook the user turned off is not paused, even if an older
    /// `paused_at` were still stored.
    #[must_use]
    pub const fn is_paused(&self) -> bool {
        self.settings.enabled && self.paused_at.is_some()
    }

    /// `active`, `paused`, or `disabled`.
    ///
    /// A missing webhook is `not_configured` and is not represented here.
    #[must_use]
    pub const fn delivery_state(&self) -> &'static str {
        if !self.settings.enabled {
            "disabled"
        } else if self.paused_at.is_some() {
            "paused"
        } else {
            "active"
        }
    }

    /// When the next delivery attempt is due, if the webhook is paused.
    ///
    /// `interval_secs` is the configured pause interval. The base is the
    /// last attempt, or the moment the pause began when nothing has been
    /// tried since. `None` when the webhook is not paused or the interval
    /// is not a positive number of seconds.
    #[must_use]
    pub fn next_retry_at(&self, interval_secs: i64) -> Option<i64> {
        if !self.is_paused() || interval_secs <= 0 {
            return None;
        }
        let base = self.last_attempt_at.or(self.paused_at)?;
        Some(base.saturating_add(interval_secs))
    }
}

pub fn auth_context(account: &AccountId) -> String {
    format!("webhook/auth/{}", account.0)
}

pub fn secret_context(account: &AccountId) -> String {
    format!("webhook/secret/{}", account.0)
}

/// The column of an encrypted custom header value.
pub const AUTH_SLOT: Slot = Slot::new("webhooks", "auth_header_value_ciphertext");

/// The column of an encrypted signing secret.
pub const SECRET_SLOT: Slot = Slot::new("webhooks", "signing_secret_ciphertext");

fn flag(value: bool) -> i64 {
    i64::from(value)
}

/// `(mode, value)` for the outbox UPDATE. Mode 0 keeps the column, 1 stores
/// NULL, and 2 stores `value`. The bound value is unused for modes 0 and 1.
const fn limit_bind(change: OutboxLimitChange<i64>) -> (i64, i64) {
    match change {
        OutboxLimitChange::Keep => (0, 0),
        OutboxLimitChange::Default => (1, 0),
        OutboxLimitChange::Set(value) => (2, value),
    }
}

fn as_u32(value: Option<i64>) -> Option<u32> {
    value.and_then(|value| u32::try_from(value).ok())
}

/// A saved webhook, or why it cannot be used.
///
/// [`LoadedWebhook::Unreadable`] carries only the plaintext on/off flag.
/// The URL, auth header, signing secret and ciphertext are left out.
#[derive(Debug, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "Ready is the usual result and is matched by value; boxing it would clutter every caller"
)]
pub enum LoadedWebhook {
    /// No row is stored.
    Missing,
    /// Settings opened with a configured key.
    Ready(Webhook),
    /// A row is stored, but a secret cannot be decrypted.
    Unreadable {
        /// Whether the stored row has delivery turned on.
        enabled: bool,
    },
}

impl Store {
    /// Builds a webhook from a row of `webhooks` joined with its account's
    /// `tenant`, which its secrets are bound to.
    async fn webhook_from_row(&self, account: &AccountId, row: &AnyRow) -> Result<Webhook> {
        let tenant: String = row.try_get("tenant")?;
        let auth_name: Option<String> = row.try_get("auth_header_name")?;
        let auth_value: Option<String> = row.try_get("auth_header_value_ciphertext")?;
        let auth_header = match (auth_name, auth_value) {
            (Some(name), Some(value)) => {
                let legacy = auth_context(account);
                let open = self.open_secret(&tenant, AUTH_SLOT, &account.0, &legacy, &value);
                Some((name, open.await?))
            }
            _ => None,
        };
        let secret: String = row.try_get("signing_secret_ciphertext")?;
        let legacy = secret_context(account);
        let open = self.open_secret(&tenant, SECRET_SLOT, &account.0, &legacy, &secret);
        let signing_secret = open.await?;
        let uid_validity = as_u32(row.try_get("uid_validity")?);
        let last_uid = as_u32(row.try_get("last_uid")?);
        Ok(Webhook {
            settings: WebhookSettings {
                enabled: row.try_get::<i64, _>("enabled")? != 0,
                url: row.try_get("url")?,
                auth_header,
                signing: row.try_get::<i64, _>("signing")? != 0,
                signing_secret,
                include_sender: row.try_get::<i64, _>("include_sender")? != 0,
            },
            consecutive_failures: row.try_get("consecutive_failures")?,
            disabled_reason: row.try_get("disabled_reason")?,
            paused_at: row.try_get("paused_at")?,
            last_attempt_at: row.try_get("last_attempt_at")?,
            last_success_at: row.try_get("last_success_at")?,
            last_error: row.try_get("last_error")?,
            cursor: uid_validity
                .zip(last_uid)
                .map(|(uid_validity, last_uid)| WatchCursor {
                    uid_validity,
                    last_uid,
                }),
            position: row.try_get("watch_position")?,
            last_sequence: row.try_get("last_sequence")?,
            delivered_sequence: row.try_get("delivered_sequence")?,
            outbox_retention_secs: row.try_get("outbox_retention_secs")?,
            outbox_max_events: row.try_get("outbox_max_events")?,
            created_at: row.try_get("created_at")?,
            filter_rules_version: row.try_get("filter_rules_version")?,
        })
    }

    /// The webhook of an account, if one was ever saved.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a secret can't be decrypted:
    /// [`StoreError::Decrypt`] when it can never be, another error when a
    /// later call may succeed, such as a key wrapper that does not answer.
    /// A secret in a format newer than this version reads is
    /// [`StoreError::NewerFormat`].
    pub async fn webhook(&self, account: &AccountId) -> Result<Option<Webhook>> {
        let row = sqlx::query(
            "SELECT w.*, a.tenant AS tenant FROM webhooks w \
             JOIN accounts a ON a.id = w.account_id WHERE w.account_id = $1",
        )
        .bind(&account.0)
        .fetch_optional(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some(self.webhook_from_row(account, &row).await?)),
            None => Ok(None),
        }
    }

    /// The webhook of an account, distinguishing a row that cannot be decrypted.
    ///
    /// [`Store::webhook`] returns [`StoreError::Decrypt`] for that row. This
    /// reports [`LoadedWebhook::Unreadable`] instead, and does not include
    /// the URL, secrets, or ciphertext.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails. A decryption failure is
    /// [`LoadedWebhook::Unreadable`], not [`StoreError::Decrypt`].
    /// Settings in a format newer than this version reads are not
    /// unreadable: that is [`StoreError::NewerFormat`].
    pub async fn load_webhook(&self, account: &AccountId) -> Result<LoadedWebhook> {
        match self.webhook(account).await {
            Ok(None) => Ok(LoadedWebhook::Missing),
            Ok(Some(hook)) => Ok(LoadedWebhook::Ready(hook)),
            Err(StoreError::Decrypt) => self.webhook_enabled_flag(account).await?.map_or_else(
                || Ok(LoadedWebhook::Missing),
                |enabled| Ok(LoadedWebhook::Unreadable { enabled }),
            ),
            Err(err) => Err(err),
        }
    }

    /// The plaintext enabled flag, without opening secrets.
    async fn webhook_enabled_flag(&self, account: &AccountId) -> Result<Option<bool>> {
        let row = sqlx::query("SELECT enabled FROM webhooks WHERE account_id = $1")
            .bind(&account.0)
            .fetch_optional(&self.pool)
            .await?;
        let enabled: Option<i64> = row.map(|row| row.try_get("enabled")).transpose()?;
        Ok(enabled.map(|value| value != 0))
    }

    /// Saves the settings.
    ///
    /// Enabling a webhook that was off, changing its URL, or saving one
    /// that is paused clears the failure count and any pause. Enabling one
    /// that was off, or changing its URL, also skips events that were not
    /// delivered yet. Saving a paused webhook with the same URL keeps those
    /// events, so they are delivered once the pause is cleared. The watch
    /// position is always kept, so no old mail is reported again. Where none is
    /// stored, the filter rules an older build left when it deleted one go.
    ///
    /// The auth header value and the signing secret are stored under the data
    /// key that [`Store::data_key`] finds or makes for the account's tenant,
    /// whichever tenant this store is scoped to.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidInput`] if the account does not exist, and
    /// an error if encryption or the query fails. A key wrapper that does not
    /// answer is [`StoreError::KeyWrap`] and nothing is written.
    pub async fn save_webhook(
        &self,
        account: &AccountId,
        settings: &WebhookSettings,
    ) -> Result<()> {
        // The secrets are bound to the tenant of the account's row, and the key
        // is found, or made, before the statement.
        let Some(tenant) = self.account_tenant(account).await? else {
            return Err(StoreError::InvalidInput("unknown account"));
        };
        let sealer = self.sealer(&tenant).await?;
        let (auth_name, auth_value) = match &settings.auth_header {
            Some((name, value)) => (
                Some(name.clone()),
                Some(sealer.seal_secret(AUTH_SLOT, &account.0, value)?),
            ),
            None => (None, None),
        };
        let secret = sealer.seal_secret(SECRET_SLOT, &account.0, &settings.signing_secret)?;
        let now = now();
        let mut tx = self.begin_write().await?;
        sqlx::query(
            "DELETE FROM webhook_filter_rules WHERE account_id = $1 \
             AND NOT EXISTS (SELECT 1 FROM webhooks WHERE account_id = $1)",
        )
        .bind(&account.0)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO webhooks (account_id, enabled, url, auth_header_name, auth_header_value_ciphertext, \
             signing, signing_secret_ciphertext, include_sender, consecutive_failures, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, $9, $9) \
             ON CONFLICT (account_id) DO UPDATE SET \
             consecutive_failures = CASE WHEN excluded.enabled = 1 AND (webhooks.enabled = 0 OR webhooks.url <> excluded.url OR webhooks.paused_at IS NOT NULL) \
                 THEN 0 ELSE webhooks.consecutive_failures END, \
             delivered_sequence = CASE WHEN excluded.enabled = 1 AND (webhooks.enabled = 0 OR webhooks.url <> excluded.url) \
                 THEN webhooks.last_sequence ELSE webhooks.delivered_sequence END, \
             paused_at = NULL, \
             disabled_reason = CASE WHEN excluded.enabled = 1 THEN NULL ELSE webhooks.disabled_reason END, \
             enabled = excluded.enabled, url = excluded.url, auth_header_name = excluded.auth_header_name, \
             auth_header_value_ciphertext = excluded.auth_header_value_ciphertext, signing = excluded.signing, \
             signing_secret_ciphertext = excluded.signing_secret_ciphertext, \
             include_sender = excluded.include_sender, updated_at = excluded.updated_at",
        )
        .bind(&account.0)
        .bind(flag(settings.enabled))
        .bind(&settings.url)
        .bind(auth_name)
        .bind(auth_value)
        .bind(flag(settings.signing))
        .bind(secret)
        .bind(flag(settings.include_sender))
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Accounts whose webhook is turned on, including one that is paused.
    ///
    /// A webhook the user turned off is left out. Pausing does not turn it
    /// off, so a paused account keeps its watcher and its queued events.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn enabled_webhooks(&self) -> Result<Vec<AccountId>> {
        let rows =
            sqlx::query("SELECT account_id FROM webhooks WHERE enabled = 1 ORDER BY account_id")
                .fetch_all(&self.pool)
                .await?;
        rows.iter()
            .map(|row| Ok(AccountId(row.try_get("account_id")?)))
            .collect()
    }

    /// Stores the watch position.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn set_watch_cursor(&self, account: &AccountId, cursor: WatchCursor) -> Result<()> {
        sqlx::query("UPDATE webhooks SET uid_validity = $1, last_uid = $2 WHERE account_id = $3")
            .bind(i64::from(cursor.uid_validity))
            .bind(i64::from(cursor.last_uid))
            .bind(&account.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stores `next` as the watch position if it is still `expected`, the one a
    /// batch was read from, and says whether it did: `false` means another
    /// watcher moved it, or the webhook is gone. `None` is a missing position
    /// and matches only a webhook without one. The event sequence stays.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn advance_watch_cursor(
        &self,
        account: &AccountId,
        expected: Option<WatchCursor>,
        next: WatchCursor,
    ) -> Result<bool> {
        // A UID is never negative, so -1 stands for a column that has no value.
        let (uid_validity, last_uid) = expected.map_or((-1, -1), |cursor| {
            (i64::from(cursor.uid_validity), i64::from(cursor.last_uid))
        });
        let moved = sqlx::query(
            "UPDATE webhooks SET uid_validity = $1, last_uid = $2 \
             WHERE account_id = $3 AND COALESCE(uid_validity, -1) = $4 \
             AND COALESCE(last_uid, -1) = $5 RETURNING last_uid",
        )
        .bind(i64::from(next.uid_validity))
        .bind(i64::from(next.last_uid))
        .bind(&account.0)
        .bind(uid_validity)
        .bind(last_uid)
        .fetch_optional(&self.pool)
        .await?;
        Ok(moved.is_some())
    }

    /// Stores the watch position of a Microsoft Graph or Gmail watcher.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn set_watch_position(&self, account: &AccountId, position: &str) -> Result<()> {
        sqlx::query("UPDATE webhooks SET watch_position = $1 WHERE account_id = $2")
            .bind(position)
            .bind(&account.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Stores `next` as the watch position of a Microsoft Graph or Gmail
    /// watcher if it is still `expected`, the one a batch was read from, and
    /// says whether it did: `false` means another watcher moved it, or the
    /// webhook is gone. `None` is a missing position and matches only a row
    /// without one. No event is recorded and the event sequence stays.
    ///
    /// This is the move for a batch that has nothing to report. A batch with
    /// an event moves the position in [`Store::append_mail_event`].
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn advance_watch_position(
        &self,
        account: &AccountId,
        expected: Option<&str>,
        next: &str,
    ) -> Result<bool> {
        let moved = sqlx::query(
            "UPDATE webhooks SET watch_position = $1 \
             WHERE account_id = $2 AND COALESCE(watch_position, '') = $3 RETURNING account_id",
        )
        .bind(next)
        .bind(&account.0)
        .bind(expected.unwrap_or_default())
        .fetch_optional(&self.pool)
        .await?;
        Ok(moved.is_some())
    }

    /// Logs a delivery, keeps only the latest [`KEPT_DELIVERIES`], and
    /// updates the webhook's status. A real (non-test) failure counts
    /// toward [`MAX_CONSECUTIVE_FAILURES`]; reaching it pauses the webhook
    /// while leaving it enabled. A real success clears that pause and
    /// resets the count. A test event does neither: it does not count
    /// toward the limit and it does not recover a paused webhook.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn record_delivery(
        &self,
        account: &AccountId,
        record: &DeliveryRecord,
    ) -> Result<DeliveryEffect> {
        let mut tx = self.begin_write().await?;
        // The webhook's row first, as every writer of the webhook's rows takes
        // it. Logging the delivery locks the account's row (its foreign key), so
        // it comes after.
        let effect = if record.succeeded {
            // A test success still clears `last_error` but must not recover
            // a pause or reset the failure count. Only a real delivery does.
            sqlx::query(
                "UPDATE webhooks SET last_attempt_at = $1, last_success_at = $1, last_error = NULL, \
                 consecutive_failures = CASE WHEN $2 = 1 THEN consecutive_failures ELSE 0 END, \
                 paused_at = CASE WHEN $2 = 1 THEN paused_at ELSE NULL END \
                 WHERE account_id = $3",
            )
            .bind(record.created_at)
            .bind(flag(record.test))
            .bind(&account.0)
            .execute(&mut *tx)
            .await?;
            DeliveryEffect::None
        } else if record.test {
            sqlx::query(
                "UPDATE webhooks SET last_attempt_at = $1, last_error = $2 WHERE account_id = $3",
            )
            .bind(record.created_at)
            .bind(&record.summary)
            .bind(&account.0)
            .execute(&mut *tx)
            .await?;
            DeliveryEffect::None
        } else {
            let failures: i64 = sqlx::query(
                "UPDATE webhooks SET last_attempt_at = $1, last_error = $2, \
                 consecutive_failures = consecutive_failures + 1 WHERE account_id = $3 \
                 RETURNING consecutive_failures",
            )
            .bind(record.created_at)
            .bind(&record.summary)
            .bind(&account.0)
            .fetch_optional(&mut *tx)
            .await?
            .map(|row| row.try_get("consecutive_failures"))
            .transpose()?
            .unwrap_or(0);
            // `COALESCE` keeps the original pause time when this webhook is
            // already paused. A webhook the user turned off (`enabled = 0`)
            // is not paused and is not turned back on.
            let paused = sqlx::query(
                "UPDATE webhooks SET paused_at = COALESCE(paused_at, $1) \
                 WHERE account_id = $2 AND enabled = 1 AND consecutive_failures >= $3 \
                 RETURNING paused_at",
            )
            .bind(record.created_at)
            .bind(&account.0)
            .bind(MAX_CONSECUTIVE_FAILURES)
            .fetch_optional(&mut *tx)
            .await?;
            if paused.is_some() {
                if failures == MAX_CONSECUTIVE_FAILURES {
                    tracing::info!(
                        account_id = %account,
                        failures,
                        "webhook paused after repeated delivery failures"
                    );
                }
                DeliveryEffect::Paused
            } else {
                DeliveryEffect::None
            }
        };
        sqlx::query(
            "INSERT INTO webhook_deliveries (id, account_id, created_at, test, succeeded, summary, elapsed_ms) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&account.0)
        .bind(record.created_at)
        .bind(flag(record.test))
        .bind(flag(record.succeeded))
        .bind(&record.summary)
        .bind(record.elapsed_ms)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "DELETE FROM webhook_deliveries WHERE account_id = $1 AND id NOT IN \
             (SELECT id FROM webhook_deliveries WHERE account_id = $1 ORDER BY created_at DESC, id LIMIT $2)",
        )
        .bind(&account.0)
        .bind(KEPT_DELIVERIES)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(effect)
    }

    /// The latest deliveries, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn recent_deliveries(&self, account: &AccountId) -> Result<Vec<DeliveryRecord>> {
        let rows = sqlx::query(
            "SELECT created_at, test, succeeded, summary, elapsed_ms FROM webhook_deliveries \
             WHERE account_id = $1 ORDER BY created_at DESC, id LIMIT $2",
        )
        .bind(&account.0)
        .bind(KEPT_DELIVERIES)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(DeliveryRecord {
                    created_at: row.try_get("created_at")?,
                    test: row.try_get::<i64, _>("test")? != 0,
                    succeeded: row.try_get::<i64, _>("succeeded")? != 0,
                    summary: row.try_get("summary")?,
                    elapsed_ms: row.try_get("elapsed_ms")?,
                })
            })
            .collect()
    }

    /// Turns delivery on or off without changing the URL or secrets.
    ///
    /// Enabling clears a pause and the failure count. Events kept while the
    /// user had turned the webhook off are skipped; events kept only while
    /// it was paused are kept. Disabling leaves the queue and the failure
    /// count, clears any pause, and stays off: later failures do not turn
    /// it back on.
    ///
    /// A row whose secrets cannot be decrypted is not enabled: the watcher
    /// cannot use it. Disabling that row still clears the flag and any
    /// pause, and returns [`LoadedWebhook::Unreadable`].
    /// [`LoadedWebhook::Missing`] means the account has no saved webhook.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails. A decryption failure is reported
    /// as [`LoadedWebhook::Unreadable`], not as [`StoreError::Decrypt`].
    /// Settings in a format newer than this version reads are
    /// [`StoreError::NewerFormat`], and nothing is changed.
    pub async fn set_webhook_enabled(
        &self,
        account: &AccountId,
        enabled: bool,
    ) -> Result<LoadedWebhook> {
        match self.load_webhook(account).await? {
            LoadedWebhook::Missing => return Ok(LoadedWebhook::Missing),
            LoadedWebhook::Unreadable { enabled: stored } if enabled => {
                return Ok(LoadedWebhook::Unreadable { enabled: stored });
            }
            LoadedWebhook::Unreadable { .. } => {
                let now = now();
                sqlx::query(
                    "UPDATE webhooks SET enabled = 0, paused_at = NULL, updated_at = $1 \
                     WHERE account_id = $2",
                )
                .bind(now)
                .bind(&account.0)
                .execute(&self.pool)
                .await?;
                return Ok(LoadedWebhook::Unreadable { enabled: false });
            }
            LoadedWebhook::Ready(_) => {}
        }
        let now = now();
        if enabled {
            // `enabled` and `last_sequence` in the assignments are the
            // current row, on SQLite and on PostgreSQL.
            sqlx::query(
                "UPDATE webhooks SET \
                 delivered_sequence = CASE WHEN enabled = 0 THEN last_sequence ELSE delivered_sequence END, \
                 consecutive_failures = 0, disabled_reason = NULL, paused_at = NULL, \
                 enabled = 1, updated_at = $1 \
                 WHERE account_id = $2",
            )
            .bind(now)
            .bind(&account.0)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                "UPDATE webhooks SET enabled = 0, paused_at = NULL, updated_at = $1 \
                 WHERE account_id = $2",
            )
            .bind(now)
            .bind(&account.0)
            .execute(&self.pool)
            .await?;
        }
        self.load_webhook(account).await
    }

    /// The stored outbox overrides, without opening secrets.
    ///
    /// `Ok(None)` means no webhook row. `Ok(Some((None, None)))` means a row
    /// that uses both server defaults. The columns are plaintext, so this
    /// works when the URL and secrets cannot be decrypted.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn webhook_outbox_overrides(
        &self,
        account: &AccountId,
    ) -> Result<Option<(Option<i64>, Option<i64>)>> {
        let row = sqlx::query(
            "SELECT outbox_retention_secs, outbox_max_events FROM webhooks WHERE account_id = $1",
        )
        .bind(&account.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        Ok(Some((
            row.try_get("outbox_retention_secs")?,
            row.try_get("outbox_max_events")?,
        )))
    }

    /// Stores outbox overrides and deletes events past the limits now in
    /// effect.
    ///
    /// [`OutboxLimitChange::Keep`] leaves a column unchanged.
    /// [`OutboxLimitChange::Default`] stores NULL, so the account uses the
    /// server default. [`OutboxLimitChange::Set`] stores that value when it
    /// sits inside the current range. A value outside the range is rejected
    /// and nothing is written. Lowering a limit deletes the oldest kept
    /// events immediately, delivered or not. `last_sequence`,
    /// `delivered_sequence` and the watch cursor stay as they are, so a
    /// later delivery continues in order and a missing sequence is a
    /// dropped event.
    ///
    /// `Ok(None)` means the account has no webhook row. The call works
    /// while the webhook is paused or turned off, and when its secrets
    /// cannot be decrypted.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutboxLimit`] when an [`OutboxLimitChange::Set`]
    /// value is below the minimum or above the ceiling. Returns an error
    /// if a query fails.
    pub async fn set_webhook_outbox_limits(
        &self,
        account: &AccountId,
        retention: OutboxLimitChange<i64>,
        max_events: OutboxLimitChange<i64>,
    ) -> Result<Option<OutboxLimitsApplied>> {
        let policy = self.outbox_policy();
        if let OutboxLimitChange::Set(secs) = retention {
            policy
                .check_retention_secs(secs)
                .map_err(StoreError::OutboxLimit)?;
        }
        if let OutboxLimitChange::Set(events) = max_events {
            policy
                .check_max_events(events)
                .map_err(StoreError::OutboxLimit)?;
        }
        let (retention_mode, retention_value) = limit_bind(retention);
        let (events_mode, events_value) = limit_bind(max_events);
        let now = now();
        let mut tx = self.begin_write().await?;
        let row = sqlx::query(
            "UPDATE webhooks SET \
             outbox_retention_secs = CASE WHEN $1 = 0 THEN outbox_retention_secs WHEN $1 = 1 THEN NULL ELSE $2 END, \
             outbox_max_events = CASE WHEN $3 = 0 THEN outbox_max_events WHEN $3 = 1 THEN NULL ELSE $4 END, \
             updated_at = CASE WHEN $1 = 0 AND $3 = 0 THEN updated_at ELSE $5 END \
             WHERE account_id = $6 \
             RETURNING outbox_retention_secs, outbox_max_events",
        )
        .bind(retention_mode)
        .bind(retention_value)
        .bind(events_mode)
        .bind(events_value)
        .bind(now)
        .bind(&account.0)
        .fetch_optional(&mut *tx)
        .await?;
        let Some(row) = row else {
            tx.rollback().await?;
            return Ok(None);
        };
        let stored_retention: Option<i64> = row.try_get("outbox_retention_secs")?;
        let stored_events: Option<i64> = row.try_get("outbox_max_events")?;
        let limits = policy.effective(stored_retention, stored_events);
        let pruned = crate::events::prune_outbox(&mut tx, account, limits, now).await?;
        tx.commit().await?;
        Ok(Some(OutboxLimitsApplied { pruned, limits }))
    }

    /// Deletes an account's webhook, its delivery log and its filter rules.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn delete_webhook(&self, account: &AccountId) -> Result<()> {
        let mut tx = self.begin_write().await?;
        for statement in [
            // The webhook's row first, as every writer of these rows takes it:
            // PostgreSQL aborts one of two writers that take it and another of
            // the account's rows in opposite orders.
            "DELETE FROM webhooks WHERE account_id = $1",
            "DELETE FROM webhook_deliveries WHERE account_id = $1",
            "DELETE FROM mail_events WHERE account_id = $1",
            "DELETE FROM webhook_filter_rules WHERE account_id = $1",
        ] {
            sqlx::query(statement)
                .bind(&account.0)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
