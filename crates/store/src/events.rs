//! The outbox of new-mail events.
//!
//! Every event gets the next sequence number of its account's webhook and
//! is stored (encrypted) before delivery. The webhook remembers the last
//! sequence the receiver accepted, so events that could not be delivered
//! are sent again, in order, until they succeed or age out, and a user can
//! ask for recent events to be sent again.
//!
//! How long events stay, and how many, is per account. A stored override
//! of NULL uses the server default ([`OutboxPolicy`]). The cap counts every
//! kept event, delivered or not: delivered events stay so they can be sent
//! again. Pruning deletes the oldest rows and does not rewind
//! `last_sequence`, `delivered_sequence`, or the watch cursor. A gap in
//! `X-Webhook-Sequence` is an event that was dropped.

use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use secrecy::ExposeSecret;
use sqlx::any::Any;
use sqlx::{Row, Transaction};

use crate::accounts::AccountId;
use crate::crypto::Slot;
use crate::db::now;
use crate::webhooks::{WatchAdvance, WatchCursor};
use crate::{Result, Store, StoreError};

/// Seconds in one day, for the retention constants.
const DAY_SECS: i64 = 24 * 60 * 60;

/// Shortest retention the server or an account may use: one hour.
///
/// The immediate delivery retries finish within about a minute, so one hour
/// still holds mail across a receiver restart. Shorter than that drops mail
/// during an ordinary outage.
pub const MIN_OUTBOX_RETENTION_SECS: i64 = 60 * 60;
/// Fewest events the server or an account may keep.
///
/// Zero would drop the newest event before it could be sent.
pub const MIN_OUTBOX_EVENTS: i64 = 1;
/// Default retention when an account has no override: 7 days.
pub const DEFAULT_OUTBOX_RETENTION_SECS: i64 = 7 * DAY_SECS;
/// Default number of events kept per account, delivered or not.
pub const DEFAULT_OUTBOX_MAX_EVENTS: i64 = 1000;
/// Default ceiling for an account's retention: 30 days.
///
/// Long enough for a receiver that is down for a few weeks. The event cap,
/// not the clock, is what bounds disk when mail is heavy.
pub const DEFAULT_OUTBOX_MAX_RETENTION_SECS: i64 = 30 * DAY_SECS;
/// Default ceiling for an account's kept events.
///
/// A stored event is about 1 KB of encrypted JSON, so 10,000 events is
/// about 10 MB for one account.
pub const DEFAULT_OUTBOX_MAX_EVENTS_LIMIT: i64 = 10_000;
/// Longest retention ceiling a server may configure: 366 days.
pub const ABSOLUTE_MAX_OUTBOX_RETENTION_SECS: i64 = 366 * DAY_SECS;
/// Largest event ceiling a server may configure.
///
/// About 100 MB for one account at 1 KB per event. Past that the operator
/// should run their own queue.
pub const ABSOLUTE_MAX_OUTBOX_EVENTS: i64 = 100_000;

/// Default number of events kept per account, delivered or not.
///
/// This is the historical server-wide constant and the default in
/// [`OutboxPolicy`]. Pruning uses the effective per-account limit.
pub const KEPT_EVENTS: i64 = DEFAULT_OUTBOX_MAX_EVENTS;
/// Default retention when an account has no override.
///
/// Pruning uses the effective per-account retention from [`OutboxPolicy`].
pub const EVENT_RETENTION: Duration = Duration::from_hours(7 * 24);

/// Server defaults and the ceilings an account cannot pass.
///
/// Installed with [`Store::set_outbox_policy`]. Until then the defaults
/// above are in effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxPolicy {
    /// How long events are kept when the account has no override, in seconds.
    pub retention_secs: i64,
    /// How many events are kept when the account has no override.
    ///
    /// Delivered and undelivered events both count.
    pub max_events: i64,
    /// Longest retention an account may set, in seconds.
    pub max_retention_secs: i64,
    /// Most events an account may keep.
    pub max_events_limit: i64,
}

impl Default for OutboxPolicy {
    fn default() -> Self {
        Self {
            retention_secs: DEFAULT_OUTBOX_RETENTION_SECS,
            max_events: DEFAULT_OUTBOX_MAX_EVENTS,
            max_retention_secs: DEFAULT_OUTBOX_MAX_RETENTION_SECS,
            max_events_limit: DEFAULT_OUTBOX_MAX_EVENTS_LIMIT,
        }
    }
}

impl OutboxPolicy {
    /// Checks the defaults against the ceilings and the absolute bounds.
    ///
    /// # Errors
    ///
    /// Returns an error naming `POSTKEEP_WEBHOOK_OUTBOX_*` when a default
    /// is above its ceiling, or a value is outside the absolute range.
    pub fn try_new(
        retention_secs: i64,
        max_events: i64,
        max_retention_secs: i64,
        max_events_limit: i64,
    ) -> std::result::Result<Self, String> {
        check_absolute_secs(
            "POSTKEEP_WEBHOOK_OUTBOX_RETENTION",
            retention_secs,
            ABSOLUTE_MAX_OUTBOX_RETENTION_SECS,
        )?;
        check_absolute_secs(
            "POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION",
            max_retention_secs,
            ABSOLUTE_MAX_OUTBOX_RETENTION_SECS,
        )?;
        check_absolute_events(
            "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS",
            max_events,
            ABSOLUTE_MAX_OUTBOX_EVENTS,
        )?;
        check_absolute_events(
            "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT",
            max_events_limit,
            ABSOLUTE_MAX_OUTBOX_EVENTS,
        )?;
        if retention_secs > max_retention_secs {
            return Err(format!(
                "POSTKEEP_WEBHOOK_OUTBOX_RETENTION ({retention_secs} seconds) is above POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION ({max_retention_secs} seconds)"
            ));
        }
        if max_events > max_events_limit {
            return Err(format!(
                "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS ({max_events}) is above POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT ({max_events_limit})"
            ));
        }
        Ok(Self {
            retention_secs,
            max_events,
            max_retention_secs,
            max_events_limit,
        })
    }

    /// The limits pruning will use for an account.
    ///
    /// `None` means the server default. A stored override outside the
    /// current range (the operator lowered a ceiling after it was saved)
    /// is limited to that range, so one account still cannot pass the
    /// ceiling. It stays an override: the source is not reported as the
    /// default.
    #[must_use]
    pub fn effective(
        self,
        retention_secs: Option<i64>,
        max_events: Option<i64>,
    ) -> EffectiveOutboxLimits {
        let (retention_secs, retention_is_default) =
            retention_secs.map_or((self.retention_secs, true), |value| {
                (
                    value.clamp(MIN_OUTBOX_RETENTION_SECS, self.max_retention_secs),
                    false,
                )
            });
        let (max_events, max_events_is_default) = max_events
            .map_or((self.max_events, true), |value| {
                (value.clamp(MIN_OUTBOX_EVENTS, self.max_events_limit), false)
            });
        EffectiveOutboxLimits {
            retention_secs,
            max_events,
            retention_is_default,
            max_events_is_default,
        }
    }

    /// Rejects a retention outside `1 hour ..= ceiling`. Does not clamp.
    ///
    /// # Errors
    ///
    /// The message names the allowed range and the rejected value.
    pub fn check_retention_secs(self, secs: i64) -> std::result::Result<(), String> {
        if (MIN_OUTBOX_RETENTION_SECS..=self.max_retention_secs).contains(&secs) {
            Ok(())
        } else {
            Err(format!(
                "outbox retention must be from {} to {}, not {}",
                describe_retention(MIN_OUTBOX_RETENTION_SECS),
                describe_retention(self.max_retention_secs),
                describe_retention(secs),
            ))
        }
    }

    /// Rejects an event cap outside `1 ..= ceiling`. Does not clamp.
    ///
    /// # Errors
    ///
    /// The message names the allowed range and the rejected value.
    pub fn check_max_events(self, max_events: i64) -> std::result::Result<(), String> {
        if (MIN_OUTBOX_EVENTS..=self.max_events_limit).contains(&max_events) {
            Ok(())
        } else {
            Err(format!(
                "outbox max events must be from {MIN_OUTBOX_EVENTS} to {}, not {max_events}",
                self.max_events_limit
            ))
        }
    }

    /// The same policy with ceilings no higher than `max_retention_secs`
    /// and `max_events_limit`, such as a plan's. A ceiling below the
    /// default counts as the default, so the defaults stay within reach.
    #[must_use]
    pub fn with_ceilings(self, max_retention_secs: i64, max_events_limit: i64) -> Self {
        Self {
            max_retention_secs: max_retention_secs
                .min(self.max_retention_secs)
                .max(self.retention_secs),
            max_events_limit: max_events_limit
                .min(self.max_events_limit)
                .max(self.max_events),
            ..self
        }
    }
}

/// The retention and event cap pruning uses for one account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveOutboxLimits {
    /// Seconds events are kept.
    pub retention_secs: i64,
    /// Events kept, delivered or not.
    pub max_events: i64,
    /// The account has no retention override.
    pub retention_is_default: bool,
    /// The account has no event-cap override.
    pub max_events_is_default: bool,
}

/// What to do with one stored outbox limit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutboxLimitChange<T> {
    /// Leave the stored value as it is.
    #[default]
    Keep,
    /// Store NULL so the account uses the server default.
    Default,
    /// Store this value. It must sit inside the current policy range.
    Set(T),
}

/// What [`Store::set_webhook_outbox_limits`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutboxLimitsApplied {
    /// Events deleted because they were past the limits now in effect.
    ///
    /// Oldest first. Delivered and undelivered events both count.
    pub pruned: u64,
    /// The limits pruning used.
    pub limits: EffectiveOutboxLimits,
}

/// A retention in words, such as `7 days` or `36 hours`.
///
/// Exact multiples of a day, hour or minute use that unit. Anything else,
/// and any non-positive value, is a number of seconds.
#[must_use]
pub fn format_outbox_retention(secs: i64) -> String {
    if secs <= 0 {
        return format!("{secs} seconds");
    }
    let (count, singular, plural) = if secs % DAY_SECS == 0 {
        (secs / DAY_SECS, "day", "days")
    } else if secs % 3_600 == 0 {
        (secs / 3_600, "hour", "hours")
    } else if secs % 60 == 0 {
        (secs / 60, "minute", "minutes")
    } else {
        (secs, "second", "seconds")
    };
    let unit = if count == 1 { singular } else { plural };
    format!("{count} {unit}")
}

fn describe_retention(secs: i64) -> String {
    let human = format_outbox_retention(secs);
    if human.ends_with("seconds") {
        human
    } else {
        format!("{secs} seconds ({human})")
    }
}

fn check_absolute_secs(name: &str, secs: i64, absolute: i64) -> std::result::Result<(), String> {
    if (MIN_OUTBOX_RETENTION_SECS..=absolute).contains(&secs) {
        Ok(())
    } else {
        Err(format!(
            "{name} must be from {MIN_OUTBOX_RETENTION_SECS} to {absolute} seconds, not {secs}"
        ))
    }
}

fn check_absolute_events(
    name: &str,
    events: i64,
    absolute: i64,
) -> std::result::Result<(), String> {
    if (MIN_OUTBOX_EVENTS..=absolute).contains(&events) {
        Ok(())
    } else {
        Err(format!(
            "{name} must be from {MIN_OUTBOX_EVENTS} to {absolute}, not {events}"
        ))
    }
}

/// A fresh policy lock holding the built-in defaults.
#[must_use]
pub fn default_policy() -> Arc<RwLock<OutboxPolicy>> {
    Arc::new(RwLock::new(OutboxPolicy::default()))
}

/// Deletes events past `limits`, oldest first. Age first, then the cap, so
/// one row is not counted twice. `last_sequence`, `delivered_sequence` and
/// the watch cursor are left alone. A gap in the sequence is an event that
/// was dropped.
pub async fn prune_outbox(
    tx: &mut Transaction<'_, Any>,
    account: &AccountId,
    limits: EffectiveOutboxLimits,
    now_secs: i64,
) -> Result<u64> {
    let cutoff = now_secs.saturating_sub(limits.retention_secs);
    let mut pruned =
        sqlx::query("DELETE FROM mail_events WHERE account_id = $1 AND created_at <= $2")
            .bind(&account.0)
            .bind(cutoff)
            .execute(&mut **tx)
            .await?
            .rows_affected();
    let row = sqlx::query("SELECT MAX(sequence) AS max_seq FROM mail_events WHERE account_id = $1")
        .bind(&account.0)
        .fetch_one(&mut **tx)
        .await?;
    let max_seq: Option<i64> = row.try_get("max_seq")?;
    if let Some(max_seq) = max_seq {
        let drop_through = max_seq.saturating_sub(limits.max_events);
        if drop_through > 0 {
            pruned = pruned.saturating_add(
                sqlx::query("DELETE FROM mail_events WHERE account_id = $1 AND sequence <= $2")
                    .bind(&account.0)
                    .bind(drop_through)
                    .execute(&mut **tx)
                    .await?
                    .rows_affected(),
            );
        }
    }
    Ok(pruned)
}

/// What the purge reads to find the outboxes it prunes: each webhook's
/// limits, and its outbox's oldest event and first and last sequence, NULL
/// for an outbox with no event. Each subquery reads one entry of an index
/// (`mail_events_account_created`, migration 0017, or
/// `mail_events_sequence`), so the read costs a few index pages per webhook,
/// however many events the outboxes hold.
const PURGE_LISTING: &str = "SELECT w.account_id, w.outbox_retention_secs, w.outbox_max_events, \
     (SELECT MIN(e.created_at) FROM mail_events e WHERE e.account_id = w.account_id) AS oldest, \
     (SELECT MIN(e.sequence) FROM mail_events e WHERE e.account_id = w.account_id) AS first_sequence, \
     (SELECT MAX(e.sequence) FROM mail_events e WHERE e.account_id = w.account_id) AS last_sequence \
     FROM webhooks w";

/// What [`Store::append_mail_event`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    /// The event was stored.
    Stored(MailEvent),
    /// The account has no webhook. No event was written.
    NoWebhook,
    /// The stored IMAP cursor or provider position was not the one this
    /// batch was read from. Nothing was written: no event, no new sequence
    /// number, and the cursor or position is unchanged.
    StaleCursor,
}

impl AppendOutcome {
    /// The stored event when this append wrote one.
    #[must_use]
    pub fn stored(self) -> Option<MailEvent> {
        match self {
            Self::Stored(event) => Some(event),
            Self::NoWebhook | Self::StaleCursor => None,
        }
    }
}

/// A stored event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailEvent {
    /// Stable identifier, sent as `X-Webhook-Id` on every attempt.
    pub id: String,
    /// Position in the account's event stream, starting at 1.
    pub sequence: i64,
    /// The JSON payload, without sequence-specific fields.
    pub payload: String,
    /// When the event was recorded (Unix seconds).
    pub created_at: i64,
}

/// One page of events waiting to be delivered.
///
/// Rows that can no longer be decrypted are left out of [`events`](Self::events).
/// They can never be sent. When the whole page failed to decrypt,
/// [`skip_through`](Self::skip_through) is the newest sequence on it: the
/// caller advances `delivered_sequence` to that value and fetches again, so
/// those rows do not stall later events. A row that cannot be opened yet ends
/// the page instead: see [`held`](Self::held).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingMailEvents {
    /// Readable events, oldest first.
    pub events: Vec<MailEvent>,
    /// Newest sequence on the page when every row failed to decrypt.
    pub skip_through: Option<i64>,
    /// The event that ends the page because it cannot be opened yet. Events
    /// before it are in [`events`](Self::events); none after it is read or may
    /// be marked delivered, for the position would pass it.
    pub held: Option<i64>,
    /// How much longer [`held`](Self::held) is held before it is skipped:
    /// `None` for a newer format, which is not skipped for its age.
    pub held_for: Option<Duration>,
}

pub fn payload_context(account: &AccountId, id: &str) -> String {
    format!("event/{}/{id}", account.0)
}

/// The column of an encrypted event payload.
pub const PAYLOAD_SLOT: Slot = Slot::new("mail_events", "payload_ciphertext");

/// Increments the sequence and stores `next` when the cursor is still
/// `expected`. `None` means the row is missing or the cursor changed.
///
/// `last_sequence` changes on every successful claim, so the row counts as
/// modified on SQLite (which omits updates that set only the same values)
/// and on PostgreSQL.
async fn claim_imap_cursor(
    tx: &mut Transaction<'_, Any>,
    account: &AccountId,
    expected: WatchCursor,
    next: WatchCursor,
) -> Result<Option<i64>> {
    let row = sqlx::query(
        "UPDATE webhooks SET last_sequence = last_sequence + 1, uid_validity = $1, last_uid = $2 \
         WHERE account_id = $3 AND uid_validity = $4 AND last_uid = $5 \
         RETURNING last_sequence",
    )
    .bind(i64::from(next.uid_validity))
    .bind(i64::from(next.last_uid))
    .bind(&account.0)
    .bind(i64::from(expected.uid_validity))
    .bind(i64::from(expected.last_uid))
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|row| row.try_get("last_sequence")).transpose()?)
}

/// Increments the sequence and stores `next` when the provider position is
/// still `expected`. `None` means the row is missing or the position
/// changed.
///
/// A missing position compares as the empty string, which no provider
/// position encodes to, so `expected: None` matches only a row without one.
async fn claim_position(
    tx: &mut Transaction<'_, Any>,
    account: &AccountId,
    expected: Option<&str>,
    next: &str,
) -> Result<Option<i64>> {
    let row = sqlx::query(
        "UPDATE webhooks SET last_sequence = last_sequence + 1, watch_position = $1 \
         WHERE account_id = $2 AND COALESCE(watch_position, '') = $3 \
         RETURNING last_sequence",
    )
    .bind(next)
    .bind(&account.0)
    .bind(expected.unwrap_or_default())
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.map(|row| row.try_get("last_sequence")).transpose()?)
}

/// Whether `account` has a webhook row, inside the open transaction.
async fn webhook_row_exists(tx: &mut Transaction<'_, Any>, account: &AccountId) -> Result<bool> {
    Ok(sqlx::query("SELECT 1 FROM webhooks WHERE account_id = $1")
        .bind(&account.0)
        .fetch_optional(&mut **tx)
        .await?
        .is_some())
}

impl Store {
    /// Replaces the server outbox defaults and ceilings.
    ///
    /// Every clone of this store sees the new policy. A prune that already
    /// read the old policy finishes with that policy.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::OutboxLimit`] when a value is outside the
    /// absolute range or a default is above its ceiling. The previous
    /// policy stays in place.
    pub fn set_outbox_policy(&self, policy: OutboxPolicy) -> Result<()> {
        let checked = OutboxPolicy::try_new(
            policy.retention_secs,
            policy.max_events,
            policy.max_retention_secs,
            policy.max_events_limit,
        )
        .map_err(StoreError::OutboxLimit)?;
        *self.outbox.write().unwrap_or_else(PoisonError::into_inner) = checked;
        Ok(())
    }

    /// The server outbox defaults and ceilings.
    #[must_use]
    pub fn outbox_policy(&self) -> OutboxPolicy {
        *self.outbox.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records an event for an account's webhook, with the payload stored
    /// under the data key that [`Store::data_key`] finds or makes for the
    /// account's tenant, whichever tenant this store is scoped to.
    ///
    /// When `advance` is set, the watch cursor or provider position is
    /// updated in the same transaction as the event. A crash cannot leave
    /// the event stored without the new position, which would report the
    /// same mail again under a new id. No event or position is written when
    /// the account has no webhook ([`AppendOutcome::NoWebhook`]).
    ///
    /// An IMAP [`WatchAdvance::Cursor`] and a Graph or Gmail
    /// [`WatchAdvance::Position`] are a compare-and-set on `expected`. The
    /// event, its sequence number and `next` are written only when the
    /// stored cursor or position is still `expected`. A mismatch reports
    /// [`AppendOutcome::StaleCursor`] and writes nothing, so two watchers
    /// that read the same cursor or position cannot both publish that batch.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or a query fails. A key wrapper that
    /// does not answer is [`StoreError::KeyWrap`]: nothing is written, the
    /// position is not advanced, and the call can be repeated.
    pub async fn append_mail_event(
        &self,
        account: &AccountId,
        payload: &str,
        advance: Option<WatchAdvance>,
    ) -> Result<AppendOutcome> {
        // The payload is bound to the tenant of the account's row, which is not
        // always this store's, and to the event's ID. Its key is found, or made,
        // before the transaction opens: inside it, that would wait for the
        // connection or the write lock that the transaction holds.
        let Some(tenant) = self.account_tenant(account).await? else {
            return Ok(AppendOutcome::NoWebhook);
        };
        let sealer = self.sealer(&tenant).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let ciphertext = sealer.seal(PAYLOAD_SLOT, &id, payload.as_bytes())?;
        let created_at = now();
        let mut tx = self.begin_write().await?;
        let claimed = match &advance {
            Some(WatchAdvance::Cursor { expected, next }) => {
                Some(claim_imap_cursor(&mut tx, account, *expected, *next).await?)
            }
            Some(WatchAdvance::Position { expected, next }) => {
                Some(claim_position(&mut tx, account, expected.as_deref(), next).await?)
            }
            None => None,
        };
        let sequence = if let Some(claimed) = claimed {
            let Some(sequence) = claimed else {
                let outcome = if webhook_row_exists(&mut tx, account).await? {
                    AppendOutcome::StaleCursor
                } else {
                    AppendOutcome::NoWebhook
                };
                tx.rollback().await?;
                return Ok(outcome);
            };
            sequence
        } else {
            let row = sqlx::query(
                "UPDATE webhooks SET last_sequence = last_sequence + 1 WHERE account_id = $1 \
                 RETURNING last_sequence",
            )
            .bind(&account.0)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else {
                return Ok(AppendOutcome::NoWebhook);
            };
            row.try_get("last_sequence")?
        };
        sqlx::query(
            "INSERT INTO mail_events (id, account_id, sequence, payload_ciphertext, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&id)
        .bind(&account.0)
        .bind(sequence)
        .bind(ciphertext)
        .bind(created_at)
        .execute(&mut *tx)
        .await?;
        self.enforce_outbox_limits(&mut tx, account, created_at)
            .await?;
        tx.commit().await?;
        Ok(AppendOutcome::Stored(MailEvent {
            id,
            sequence,
            payload: payload.to_owned(),
            created_at,
        }))
    }

    /// How many events are still waiting to be delivered.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn pending_mail_event_count(&self, account: &AccountId) -> Result<i64> {
        let row = sqlx::query(
            "SELECT COUNT(*) AS pending FROM mail_events e \
             JOIN webhooks w ON w.account_id = e.account_id \
             WHERE e.account_id = $1 AND e.sequence > w.delivered_sequence",
        )
        .bind(&account.0)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get("pending")?)
    }

    /// Events after the last delivered one, oldest first.
    ///
    /// A row that can no longer be decrypted is held while it is younger than
    /// [`Store::event_hold`], counted from when it was stored: the page ends
    /// there ([`PendingMailEvents::held`]), for a replica with another key
    /// may open it. Once it is as old as the hold it is skipped, with a
    /// warning. When every row in the page is skipped,
    /// [`PendingMailEvents::skip_through`] is set so the caller can advance
    /// past them. A readable row is never included in that high-water mark:
    /// it is returned in sequence order and must be delivered before anything
    /// after it.
    ///
    /// Only [`StoreError::Decrypt`] makes a row unreadable. Any other
    /// failure, such as a key wrapper that does not answer, is returned and
    /// nothing is skipped: the caller advances past skipped rows for good,
    /// and a later call may read them.
    ///
    /// An event in a format newer than this version reads is
    /// [`StoreError::NewerFormat`]. It is held and never skipped for its age,
    /// for a newer version may read it; the outbox limits remove it in the end.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails, or if a row can't be decrypted for
    /// a reason other than [`StoreError::Decrypt`] and
    /// [`StoreError::NewerFormat`].
    pub async fn pending_mail_events(
        &self,
        account: &AccountId,
        limit: i64,
    ) -> Result<PendingMailEvents> {
        let rows = sqlx::query(
            "SELECT e.id, e.sequence, e.payload_ciphertext, e.created_at, a.tenant \
             FROM mail_events e \
             JOIN webhooks w ON w.account_id = e.account_id \
             JOIN accounts a ON a.id = e.account_id \
             WHERE e.account_id = $1 AND e.sequence > w.delivered_sequence \
             ORDER BY e.sequence LIMIT $2",
        )
        .bind(&account.0)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        let hold_secs = i64::try_from(self.event_hold().as_secs()).unwrap_or(i64::MAX);
        let now_secs = now();
        let mut events = Vec::new();
        // Newest unreadable sequence seen before the first readable row.
        // Cleared once a row opens, so a later readable event is not skipped.
        let mut skip_through: Option<i64> = None;
        let (mut held, mut held_for) = (None, None);
        for row in rows {
            let id: String = row.try_get("id")?;
            let sequence: i64 = row.try_get("sequence")?;
            let created_at: i64 = row.try_get("created_at")?;
            let stored: String = row.try_get("payload_ciphertext")?;
            let tenant: String = row.try_get("tenant")?;
            let legacy = payload_context(account, &id);
            let open = self.open_secret(&tenant, PAYLOAD_SLOT, &id, &legacy, &stored);
            let payload = match open.await {
                Ok(payload) => payload,
                Err(StoreError::Decrypt) if now_secs.saturating_sub(created_at) >= hold_secs => {
                    tracing::warn!(account_id = %account, event_id = %id, sequence, hold_secs, "stored event is unreadable and no longer held; skipping it");
                    if events.is_empty() {
                        skip_through = Some(sequence);
                    }
                    continue;
                }
                Err(err @ (StoreError::Decrypt | StoreError::NewerFormat)) => {
                    tracing::warn!(account_id = %account, event_id = %id, sequence, error = %err, "stored event cannot be opened here yet; holding it and the events after it");
                    held = Some(sequence);
                    // A newer format is not skipped for its age: no end.
                    let left = hold_secs.saturating_sub(now_secs.saturating_sub(created_at));
                    let left = Duration::from_secs(u64::try_from(left).unwrap_or(0));
                    held_for = matches!(err, StoreError::Decrypt).then_some(left);
                    break;
                }
                // A failure that may pass is not a reason to skip: the caller
                // would advance past an event that a later call can read.
                Err(err) => return Err(err),
            };
            skip_through = None;
            events.push(MailEvent {
                id,
                sequence,
                payload: payload.expose_secret().to_owned(),
                created_at,
            });
        }
        Ok(PendingMailEvents {
            events,
            skip_through,
            held,
            held_for,
        })
    }

    /// Sets how long a row that can no longer be decrypted is held before it
    /// is skipped; zero skips at once. Every clone of this store sees it.
    pub fn set_event_hold(&self, hold: Duration) {
        self.event_hold.store(hold.as_secs(), Ordering::Relaxed);
    }

    /// How long such a row is held: an hour until it is set.
    #[must_use]
    pub fn event_hold(&self) -> Duration {
        Duration::from_secs(self.event_hold.load(Ordering::Relaxed))
    }

    /// Records that the receiver accepted every event up to `sequence`.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn mark_mail_events_delivered(
        &self,
        account: &AccountId,
        sequence: i64,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE webhooks SET delivered_sequence = $1 \
             WHERE account_id = $2 AND delivered_sequence < $1 AND last_sequence >= $1",
        )
        .bind(sequence)
        .bind(&account.0)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Marks every event as delivered without sending it, so only events
    /// recorded from now on are sent.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn skip_mail_events(&self, account: &AccountId) -> Result<()> {
        sqlx::query("UPDATE webhooks SET delivered_sequence = last_sequence WHERE account_id = $1")
            .bind(&account.0)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Sends kept events again, starting with `from_sequence`: events are
    /// replayed in order with their original IDs and sequence numbers.
    /// Returns how many kept events will be sent.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn replay_mail_events(&self, account: &AccountId, from_sequence: i64) -> Result<u64> {
        let from = from_sequence.max(1);
        sqlx::query(
            "UPDATE webhooks SET delivered_sequence = $1 \
             WHERE account_id = $2 AND delivered_sequence > $1",
        )
        .bind(from - 1)
        .bind(&account.0)
        .execute(&self.pool)
        .await?;
        let row = sqlx::query(
            "SELECT COUNT(*) AS pending FROM mail_events e JOIN webhooks w ON w.account_id = e.account_id \
             WHERE e.account_id = $1 AND e.sequence > w.delivered_sequence",
        )
        .bind(&account.0)
        .fetch_one(&self.pool)
        .await?;
        let pending: i64 = row.try_get("pending")?;
        Ok(u64::try_from(pending).unwrap_or(0))
    }

    /// The oldest kept sequence number of an account, if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn oldest_mail_event(&self, account: &AccountId) -> Result<Option<i64>> {
        let row =
            sqlx::query("SELECT MIN(sequence) AS oldest FROM mail_events WHERE account_id = $1")
                .bind(&account.0)
                .fetch_one(&self.pool)
                .await?;
        Ok(row.try_get("oldest")?)
    }

    /// Deletes events past each account's retention and cap.
    ///
    /// A lowered server default applies here even when no new mail arrives.
    /// Sequence numbers and delivery positions are left as they are. Each
    /// account is pruned in a transaction of its own that claims the webhook
    /// row before it reads the overrides, as an append does: a change saved
    /// before the claim is the one applied, and a change after it waits.
    ///
    /// Only an outbox that one read before the claims finds with an event
    /// past its limits is claimed, so one with nothing to remove costs no
    /// transaction and no write. A change that lowers the limits after that
    /// read prunes the outbox itself. That read, `PURGE_LISTING`, takes
    /// them from the indexes on `mail_events`, not from every event.
    pub(crate) async fn purge_old_events(&self) -> Result<u64> {
        let now_secs = now();
        let accounts = sqlx::query(PURGE_LISTING).fetch_all(&self.pool).await?;
        let mut removed = 0_u64;
        for listed in accounts {
            let oldest: Option<i64> = listed.try_get("oldest")?;
            let first: Option<i64> = listed.try_get("first_sequence")?;
            let last: Option<i64> = listed.try_get("last_sequence")?;
            // An outbox with no event has nothing to remove.
            let (Some(oldest), Some(first), Some(last)) = (oldest, first, last) else {
                continue;
            };
            let seen = self.outbox_policy().effective(
                listed.try_get("outbox_retention_secs")?,
                listed.try_get("outbox_max_events")?,
            );
            // What `prune_outbox` deletes: an event at or before the cutoff,
            // or one more than the cap behind the newest.
            if oldest > now_secs.saturating_sub(seen.retention_secs)
                && first > last.saturating_sub(seen.max_events)
            {
                continue;
            }
            let account = AccountId(listed.try_get("account_id")?);
            let mut tx = self.begin_write().await?;
            let row = sqlx::query(
                "UPDATE webhooks SET outbox_max_events = outbox_max_events WHERE account_id = $1 \
                 RETURNING outbox_retention_secs, outbox_max_events",
            )
            .bind(&account.0)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(row) = row {
                let retention_secs: Option<i64> = row.try_get("outbox_retention_secs")?;
                let max_events: Option<i64> = row.try_get("outbox_max_events")?;
                let limits = self.outbox_policy().effective(retention_secs, max_events);
                removed = removed
                    .saturating_add(prune_outbox(&mut tx, &account, limits, now_secs).await?);
            }
            tx.commit().await?;
        }
        Ok(removed)
    }

    /// Applies the account's effective limits inside an open transaction.
    ///
    /// The caller has already claimed the webhook row, so this reads the
    /// overrides that claim locked.
    async fn enforce_outbox_limits(
        &self,
        tx: &mut Transaction<'_, Any>,
        account: &AccountId,
        now_secs: i64,
    ) -> Result<()> {
        let row = sqlx::query(
            "SELECT outbox_retention_secs, outbox_max_events FROM webhooks WHERE account_id = $1",
        )
        .bind(&account.0)
        .fetch_one(&mut **tx)
        .await?;
        let retention_secs: Option<i64> = row.try_get("outbox_retention_secs")?;
        let max_events: Option<i64> = row.try_get("outbox_max_events")?;
        let limits = self.outbox_policy().effective(retention_secs, max_events);
        prune_outbox(tx, account, limits, now_secs).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The purge's read goes to each outbox through an index and reads no
    /// account's events in full.
    #[tokio::test]
    async fn sqlite_the_purge_listing_reads_each_outbox_through_an_index() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("plan.db").display());
        let key = crate::MasterKey::parse(&crate::MasterKey::generate_encoded().unwrap()).unwrap();
        let store = Store::connect(&url, &key).await.unwrap();
        let explain = format!("EXPLAIN QUERY PLAN {PURGE_LISTING}");
        let plan = sqlx::query(sqlx::AssertSqlSafe(explain))
            .fetch_all(store.pool())
            .await
            .unwrap()
            .iter()
            .map(|step| step.try_get::<String, _>("detail").unwrap())
            .collect::<Vec<_>>();
        assert!(
            plan.iter()
                .any(|step| step.contains("mail_events_account_created")),
            "{plan:?}"
        );
        assert!(
            !plan.iter().any(|step| step.starts_with("SCAN e")),
            "{plan:?}"
        );
    }

    #[test]
    fn formats_retention_in_the_largest_exact_unit() {
        assert_eq!(format_outbox_retention(7 * DAY_SECS), "7 days");
        assert_eq!(format_outbox_retention(DAY_SECS), "1 day");
        assert_eq!(format_outbox_retention(36 * 3_600), "36 hours");
        assert_eq!(format_outbox_retention(3_600), "1 hour");
        assert_eq!(format_outbox_retention(90 * 60), "90 minutes");
        assert_eq!(format_outbox_retention(60), "1 minute");
        assert_eq!(format_outbox_retention(45), "45 seconds");
        assert_eq!(format_outbox_retention(1), "1 second");
        assert_eq!(format_outbox_retention(0), "0 seconds");
        assert_eq!(format_outbox_retention(-5), "-5 seconds");
    }

    #[test]
    fn historical_constants_match_the_defaults() {
        assert_eq!(
            u64::try_from(DEFAULT_OUTBOX_RETENTION_SECS).unwrap_or(0),
            EVENT_RETENTION.as_secs()
        );
        assert_eq!(KEPT_EVENTS, DEFAULT_OUTBOX_MAX_EVENTS);
    }

    #[test]
    fn rejects_a_default_above_its_ceiling_and_values_past_the_absolute_cap() {
        let above = OutboxPolicy::try_new(30 * DAY_SECS, 1000, DAY_SECS, 10_000);
        assert_eq!(
            above.ok(),
            None,
            "a default above the ceiling is not a policy"
        );
        assert_eq!(
            OutboxPolicy::try_new(30 * DAY_SECS, 1000, DAY_SECS, 10_000).unwrap_err_message(),
            "POSTKEEP_WEBHOOK_OUTBOX_RETENTION (2592000 seconds) is above POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION (86400 seconds)"
        );
        assert_eq!(
            OutboxPolicy::try_new(DAY_SECS, 20_000, 30 * DAY_SECS, 10_000).unwrap_err_message(),
            "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS (20000) is above POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT (10000)"
        );
        assert_eq!(
            OutboxPolicy::try_new(60, 1000, 30 * DAY_SECS, 10_000).unwrap_err_message(),
            "POSTKEEP_WEBHOOK_OUTBOX_RETENTION must be from 3600 to 31622400 seconds, not 60"
        );
        assert_eq!(
            OutboxPolicy::try_new(DAY_SECS, 1000, 30 * DAY_SECS, 100_001).unwrap_err_message(),
            "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT must be from 1 to 100000, not 100001"
        );
        assert!(OutboxPolicy::default().try_rebuild().is_ok());
    }

    #[test]
    fn effective_limits_use_null_as_the_default_and_clamp_a_stored_override() {
        let policy = OutboxPolicy::default();
        let defaults = policy.effective(None, None);
        assert_eq!(defaults.retention_secs, DEFAULT_OUTBOX_RETENTION_SECS);
        assert_eq!(defaults.max_events, DEFAULT_OUTBOX_MAX_EVENTS);
        assert!(defaults.retention_is_default && defaults.max_events_is_default);

        let mut lowered = policy;
        lowered.max_retention_secs = 2 * DAY_SECS;
        lowered.max_events_limit = 2;
        lowered.retention_secs = DAY_SECS;
        lowered.max_events = 2;
        let clamped = lowered.effective(Some(30 * DAY_SECS), Some(9_000));
        assert_eq!(clamped.retention_secs, 2 * DAY_SECS);
        assert_eq!(clamped.max_events, 2);
        assert!(!clamped.retention_is_default);
        assert!(!clamped.max_events_is_default);

        let raised = lowered.effective(Some(10), Some(0));
        assert_eq!(raised.retention_secs, MIN_OUTBOX_RETENTION_SECS);
        assert_eq!(raised.max_events, MIN_OUTBOX_EVENTS);
        assert!(!raised.retention_is_default);
    }

    #[test]
    fn check_names_the_allowed_range_and_does_not_clamp() {
        let policy = OutboxPolicy::default();
        assert!(policy.check_retention_secs(3_600).is_ok());
        assert!(policy.check_retention_secs(30 * DAY_SECS).is_ok());
        assert_eq!(
            policy.check_retention_secs(1_800).unwrap_err_message(),
            "outbox retention must be from 3600 seconds (1 hour) to 2592000 seconds (30 days), not 1800 seconds (30 minutes)"
        );
        assert_eq!(
            policy
                .check_retention_secs(31 * DAY_SECS)
                .unwrap_err_message(),
            "outbox retention must be from 3600 seconds (1 hour) to 2592000 seconds (30 days), not 2678400 seconds (31 days)"
        );
        assert_eq!(
            policy.check_max_events(0).unwrap_err_message(),
            "outbox max events must be from 1 to 10000, not 0"
        );
        assert_eq!(
            policy.check_max_events(10_001).unwrap_err_message(),
            "outbox max events must be from 1 to 10000, not 10001"
        );
        assert!(policy.check_max_events(1).is_ok());
        assert!(policy.check_max_events(10_000).is_ok());
    }

    #[test]
    fn lower_ceilings_stay_within_the_server_ceilings_and_above_the_defaults() {
        let policy = OutboxPolicy::default();
        let plan = policy.with_ceilings(14 * DAY_SECS, 5_000);
        assert_eq!(
            (plan.max_retention_secs, plan.max_events_limit),
            (14 * DAY_SECS, 5_000)
        );
        assert_eq!(
            (plan.retention_secs, plan.max_events),
            (policy.retention_secs, policy.max_events)
        );
        assert_eq!(policy.with_ceilings(366 * DAY_SECS, 100_000), policy);
        let below = policy.with_ceilings(DAY_SECS, 10);
        assert_eq!(
            (below.max_retention_secs, below.max_events_limit),
            (DEFAULT_OUTBOX_RETENTION_SECS, DEFAULT_OUTBOX_MAX_EVENTS)
        );
    }

    trait Message {
        fn unwrap_err_message(self) -> String;
    }

    impl Message for std::result::Result<OutboxPolicy, String> {
        fn unwrap_err_message(self) -> String {
            match self {
                Ok(_) => String::from("expected an error"),
                Err(message) => message,
            }
        }
    }

    impl Message for std::result::Result<(), String> {
        fn unwrap_err_message(self) -> String {
            match self {
                Ok(()) => String::from("expected an error"),
                Err(message) => message,
            }
        }
    }

    impl OutboxPolicy {
        fn try_rebuild(self) -> std::result::Result<Self, String> {
            Self::try_new(
                self.retention_secs,
                self.max_events,
                self.max_retention_secs,
                self.max_events_limit,
            )
        }
    }
}
