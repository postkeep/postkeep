//! Delivery of stored new-mail events (the outbox).
//!
//! Watchers of every provider only *record* events
//! ([`Watchers::publish`]); one pump task per account then sends the
//! account's pending events in sequence order. An event the receiver does
//! not accept after the immediate retries stays pending and is tried
//! again with a growing delay, capped at the pause interval, so a receiver
//! that is down for a while gets every event once it is back, in order,
//! with its original `X-Webhook-Id` and `X-Webhook-Sequence`.
//!
//! After enough real failures the webhook is paused, not turned off. The
//! watcher keeps recording into this outbox. While paused, the pump tries
//! the oldest pending event about once per
//! [`WatchConfig::webhook_retry_interval`](super::WatchConfig::webhook_retry_interval)
//! and does not start a delivery for every new message. A real success
//! clears the pause and the same pass delivers the rest of the backlog.
//! Nothing pending means nothing is probed; the next recorded event waits
//! for the next slot. A restart, saving the settings, turning it back on,
//! a successful test, or signing in again may try once immediately.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use postkeep_store::{
    AccountId, AppendOutcome, DeliveryEffect, DeliveryRecord, MailEvent, StoreError, WatchAdvance,
};
use postkeep_webhook::{
    AuthHeader, Delivery, EventMeta, NewMailEvent, WebhookUrl, deliver, event_request,
};
use secrecy::ExposeSecret;
use tokio_util::sync::CancellationToken;

use super::{WatchSignal, Watchers};

/// Events loaded per batch.
const BATCH: i64 = 20;

/// A running pump.
pub(super) struct Pump {
    cancel: CancellationToken,
    generation: u64,
    /// Set when events were added while the pump was busy.
    again: Arc<AtomicBool>,
}

/// How a pass over the pending events ended.
enum Pass {
    /// Nothing is pending. `paused` is whether the webhook is still paused,
    /// so the next event waits for a slot instead of going out at once.
    Drained {
        /// The webhook is paused.
        paused: bool,
    },
    /// An event was not accepted; try again later. `paused` selects the
    /// slow interval instead of the growing delay.
    Failed {
        /// The failure limit has paused the webhook.
        paused: bool,
        /// Try again by then if that is sooner: the end of a hold. A paused
        /// webhook waits its interval alone.
        retry_by: Option<Duration>,
    },
    /// Cancelled, the webhook is gone or the user turned it off, the
    /// account is gone, or it is not on the allow-list. A pause is not a
    /// stop: the webhook stays enabled and this pump keeps retrying.
    Stop,
}

impl Watchers {
    /// Records `event` for `account` and wakes its pump after the commit.
    ///
    /// When `advance` is set, the watch cursor or position is stored in the
    /// same transaction as the event. [`AppendOutcome::NoWebhook`] means the
    /// account has no webhook: nothing is recorded and the position is left
    /// unchanged. [`AppendOutcome::StaleCursor`] means the compare-and-set
    /// on an IMAP cursor or a Graph or Gmail position lost: nothing is
    /// recorded, and the caller drops the batch and reads the cursor or
    /// position again.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be stored.
    pub async fn publish(
        &self,
        account: &AccountId,
        event: &NewMailEvent,
        advance: Option<WatchAdvance>,
    ) -> Result<AppendOutcome, StoreError> {
        let payload = String::from_utf8_lossy(&event.to_body()).into_owned();
        let stored = self
            .inner
            .store
            .append_mail_event(account, &payload, advance)
            .await?;
        if matches!(stored, AppendOutcome::Stored(_)) {
            self.wake(account);
        }
        Ok(stored)
    }

    /// Makes sure `account`'s pending events are being delivered.
    ///
    /// A pump that is already waiting is left to finish that wait. A new
    /// event must not skip the pause interval. Mail a Gmail or Graph
    /// catch-up records while the webhook is paused is the same: it is
    /// stored, and it is not delivered before the pause interval.
    pub fn wake(&self, account: &AccountId) {
        self.start_pump(account, false);
    }

    /// Tries `account`'s pending events once without waiting out a pause.
    ///
    /// [`Watchers::refresh`] calls this on every account-change notification:
    /// a restart, saving the settings, turning the webhook back on, a
    /// successful test, or signing in again. An
    /// existing pump is cancelled and replaced while the pump map is held,
    /// so a concurrent [`Watchers::wake`] cannot start a pump that would
    /// wait instead.
    pub fn wake_prompt(&self, account: &AccountId) {
        self.start_pump(account, true);
    }

    /// Starts the pump. `prompt` skips the pause wait for the first pass.
    /// Events of a mailbox another process watches are that process's to
    /// deliver.
    fn start_pump(&self, account: &AccountId, prompt: bool) {
        let inner = &self.inner;
        if inner.shutdown.is_cancelled() {
            return;
        }
        if !self.owns(account) {
            self.forward(WatchSignal::Recorded(account.clone()));
            return;
        }
        let mut pumps = inner
            .pumps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pump) = pumps.get(account)
            && !prompt
        {
            pump.again.store(true, Ordering::SeqCst);
            return;
        }
        if let Some(pump) = pumps.remove(account) {
            pump.cancel.cancel();
        }
        if prompt {
            // The first pass tries immediately. Clear any slot while the
            // pump map lock is held, so the pump just removed cannot arm
            // one in between this clear and the new pump's first pass.
            self.pause_deadlines().remove(account);
        }
        let generation = inner
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cancel = inner.shutdown.child_token();
        let again = Arc::new(AtomicBool::new(false));
        pumps.insert(
            account.clone(),
            Pump {
                cancel: cancel.clone(),
                generation,
                again: again.clone(),
            },
        );
        drop(pumps);
        let this = self.clone();
        let account = account.clone();
        inner.tracker.spawn(async move {
            this.pump(&account, &cancel, &again, generation, prompt)
                .await;
        });
    }

    /// Stops the pump of `account`, leaving its pending events stored.
    pub(super) fn stop_pump(&self, account: &AccountId) {
        let mut pumps = self
            .inner
            .pumps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pump = pumps.remove(account);
        self.pause_deadlines().remove(account);
        drop(pumps);
        if let Some(pump) = pump {
            pump.cancel.cancel();
        }
    }

    /// How long a paused webhook waits between delivery attempts.
    #[must_use]
    pub fn retry_interval(&self) -> Duration {
        self.inner.config.webhook_retry_interval
    }

    /// Number of running pumps.
    #[must_use]
    pub fn pumps(&self) -> usize {
        self.inner
            .pumps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    async fn pump(
        &self,
        account: &AccountId,
        cancel: &CancellationToken,
        again: &AtomicBool,
        generation: u64,
        mut prompt: bool,
    ) {
        let config = &self.inner.config;
        let mut failures = 0u32;
        loop {
            // A replacement removes this generation from the map and cancels
            // it. Stop before another pass, so a pump that already recorded
            // a failure cannot deliver again or arm a deadline afterwards.
            // The process that watches the mailbox now delivers the rest.
            if cancel.is_cancelled()
                || !self.pump_current(account, generation)
                || !self.owns(account)
            {
                self.forget_pump(account, generation);
                return;
            }
            if prompt {
                // The account-change notification tries once now. Later
                // passes wait out a pause.
                prompt = false;
                self.clear_pause_deadline(account, generation);
            } else if let Some(wait) = self.pause_wait(account, generation).await {
                tokio::select! {
                    () = cancel.cancelled() => {
                        self.forget_pump(account, generation);
                        return;
                    }
                    () = tokio::time::sleep(wait) => {}
                }
            }
            again.store(false, Ordering::SeqCst);
            let pass = match self.pass(account, cancel, &mut failures).await {
                Ok(pass) => pass,
                Err(err) => {
                    tracing::warn!(account_id = %account, error = %err, "could not deliver stored events");
                    failures = failures.saturating_add(1);
                    Pass::Failed {
                        paused: false,
                        retry_by: None,
                    }
                }
            };
            match pass {
                Pass::Drained { paused } => {
                    if paused {
                        // The slot was used, even when there was nothing to
                        // probe. A later event waits until the next one.
                        self.arm_pause_deadline(account, generation).await;
                    } else {
                        self.clear_pause_deadline(account, generation);
                    }
                    if self.finish_pump(account, again, generation) {
                        return;
                    }
                    if paused {
                        // Events arrived during this pass and the slot was
                        // already due, so deliver them now.
                        self.mark_pause_due(account, generation);
                    }
                }
                Pass::Stop => {
                    self.clear_pause_deadline(account, generation);
                    self.forget_pump(account, generation);
                    return;
                }
                Pass::Failed { paused, retry_by } => {
                    if paused {
                        // The interval alone. Also applying the growing
                        // delay would wait twice.
                        self.arm_pause_deadline(account, generation).await;
                        tracing::info!(
                            account_id = %account,
                            retry_in = ?config.webhook_retry_interval,
                            "webhook is paused; retrying slowly"
                        );
                    } else {
                        self.clear_pause_deadline(account, generation);
                        let cap = config.outbox_max_backoff.min(config.webhook_retry_interval);
                        let delay = config
                            .outbox_min_backoff
                            .saturating_mul(2u32.saturating_pow(failures.saturating_sub(1).min(16)))
                            .min(cap)
                            .min(retry_by.unwrap_or(Duration::MAX));
                        tracing::info!(account_id = %account, retry_in = ?delay, "webhook receiver did not accept an event; keeping it");
                        tokio::select! {
                            () = cancel.cancelled() => {
                                self.forget_pump(account, generation);
                                return;
                            }
                            () = tokio::time::sleep(delay) => {}
                        }
                    }
                }
            }
        }
    }

    /// How long to wait before the next attempt while the webhook is paused.
    ///
    /// The stored webhook decides whether a wait is a pause at all. An
    /// in-memory deadline left behind by a replaced pump is ignored, and
    /// removed when this generation still owns the pump, once the webhook
    /// is not paused. While it is paused, an in-memory deadline wins,
    /// including one that has already passed (try now). Without one, the
    /// stored pause time is used, so a process that lost the in-memory map
    /// still waits out the interval. A sub-second interval cannot be
    /// recovered from Unix-second timestamps and does not wait here; tests
    /// arm the in-memory deadline instead.
    async fn pause_wait(&self, account: &AccountId, generation: u64) -> Option<Duration> {
        let Some(delay) = self.persisted_pause_delay(account).await else {
            self.discard_pause_deadline(account, generation);
            return None;
        };
        if let Some(remaining) = self.pause_remaining(account) {
            return (remaining > Duration::ZERO).then_some(remaining);
        }
        (delay > Duration::ZERO).then_some(delay)
    }

    /// Time left until the in-memory slot, if one was armed.
    fn pause_remaining(&self, account: &AccountId) -> Option<Duration> {
        let deadline = self.pause_deadlines().get(account).copied()?;
        let now = Instant::now();
        if deadline <= now {
            Some(Duration::ZERO)
        } else {
            Some(deadline.saturating_duration_since(now))
        }
    }

    /// The wait implied by `paused_at` / `last_attempt_at` and the
    /// configured interval. `Some(0)` when the slot is already due, or when
    /// the interval is shorter than one second. `None` when not paused.
    async fn persisted_pause_delay(&self, account: &AccountId) -> Option<Duration> {
        // Same rule as a delivery pass: unreadable settings are not a pause
        // to wait out. The pass then stops the pump instead of retrying.
        let hook = match super::readable_webhook(&self.inner.store, account).await {
            Ok(hook) => hook?,
            Err(err) => {
                tracing::warn!(account_id = %account, error = %err, "could not read the webhook pause");
                return None;
            }
        };
        if !hook.is_paused() {
            return None;
        }
        let interval = self.inner.config.webhook_retry_interval;
        if interval.as_secs() == 0 {
            return Some(Duration::ZERO);
        }
        let secs = i64::try_from(interval.as_secs()).unwrap_or(i64::MAX);
        let next = hook.next_retry_at(secs)?;
        let now = postkeep_store::now();
        if next <= now {
            return Some(Duration::ZERO);
        }
        Some(Duration::from_secs(u64::try_from(next - now).unwrap_or(0)))
    }

    async fn arm_pause_deadline(&self, account: &AccountId, generation: u64) {
        let finished = self.wait_to_change_deadline().await;
        let when = Instant::now() + self.inner.config.webhook_retry_interval;
        self.mutate_pause_deadline(account, generation, |deadlines| {
            deadlines.insert(account.clone(), when);
        });
        if let Some(finished) = finished {
            finished.notify_one();
        }
    }

    /// Marks the slot due so the next pass does not wait.
    fn mark_pause_due(&self, account: &AccountId, generation: u64) {
        self.mutate_pause_deadline(account, generation, |deadlines| {
            deadlines.insert(account.clone(), Instant::now());
        });
    }

    fn clear_pause_deadline(&self, account: &AccountId, generation: u64) {
        self.mutate_pause_deadline(account, generation, |deadlines| {
            deadlines.remove(account);
        });
    }

    /// Drops a deadline that must not apply, without the test gate.
    ///
    /// [`Self::pause_wait`] uses this when the stored webhook is not paused.
    /// The gate is only for a pump that is about to arm a slot, so a wait
    /// check does not block a replacement.
    fn discard_pause_deadline(&self, account: &AccountId, generation: u64) {
        self.mutate_pause_deadline(account, generation, |deadlines| {
            deadlines.remove(account);
        });
    }

    /// Changes the in-memory slot only while `generation` still owns the pump.
    ///
    /// The pump map and the deadline map are locked together, pump map
    /// first. A replaced pump can finish the delivery it already started,
    /// then reach this point after the replacement has cleared the slot.
    /// The generation check stops it from arming that slot again.
    fn mutate_pause_deadline(
        &self,
        account: &AccountId,
        generation: u64,
        update: impl FnOnce(&mut std::collections::HashMap<AccountId, Instant>),
    ) {
        let pumps = self
            .inner
            .pumps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pumps
            .get(account)
            .is_some_and(|pump| pump.generation == generation)
        {
            update(&mut self.pause_deadlines());
        }
    }

    fn pump_current(&self, account: &AccountId, generation: u64) -> bool {
        self.inner
            .pumps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(account)
            .is_some_and(|pump| pump.generation == generation)
    }

    /// Parks on the test gate, if a test installed one.
    ///
    /// Returns a notify to signal after the deadline mutation. Production
    /// never installs a gate. The gate is taken once, so only the pump that
    /// reaches a mutation first waits; its replacement does not.
    async fn wait_to_change_deadline(&self) -> Option<std::sync::Arc<tokio::sync::Notify>> {
        let gate = self.take_deadline_gate()?;
        gate.reached.notify_one();
        let _ = gate.release.await;
        Some(gate.finished)
    }

    fn take_deadline_gate(&self) -> Option<DeadlineGate> {
        self.inner
            .deadline_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Parks the next pause-slot arm until `release` is signalled.
    ///
    /// The pump notifies `reached` after it has recorded the delivery and
    /// before it writes the slot. It notifies `finished` after that write
    /// returns. Only the first mutation takes the gate.
    #[cfg(test)]
    fn install_deadline_gate(
        &self,
        reached: std::sync::Arc<tokio::sync::Notify>,
        release: tokio::sync::oneshot::Receiver<()>,
        finished: std::sync::Arc<tokio::sync::Notify>,
    ) {
        *self
            .inner
            .deadline_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(DeadlineGate {
            reached,
            release,
            finished,
        });
    }

    fn pause_deadlines(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::HashMap<AccountId, Instant>> {
        self.inner
            .pause_after
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Removes the pump unless events arrived since its last load.
    /// [`Watchers::wake`] sets `again` under the same lock, so such an
    /// event is never missed. Returns whether the pump should end.
    fn finish_pump(&self, account: &AccountId, again: &AtomicBool, generation: u64) -> bool {
        let mut pumps = self
            .inner
            .pumps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if again.swap(false, Ordering::SeqCst) {
            return false;
        }
        if pumps
            .get(account)
            .is_some_and(|pump| pump.generation == generation)
        {
            pumps.remove(account);
        }
        drop(pumps);
        true
    }

    fn forget_pump(&self, account: &AccountId, generation: u64) {
        let mut pumps = self
            .inner
            .pumps
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if pumps
            .get(account)
            .is_some_and(|pump| pump.generation == generation)
        {
            pumps.remove(account);
        }
    }

    /// Delivers pending events until none are left or one fails.
    async fn pass(
        &self,
        account: &AccountId,
        cancel: &CancellationToken,
        failures: &mut u32,
    ) -> Result<Pass, StoreError> {
        let store = &self.inner.store;
        // Highest sequence already skipped in this pass. A page of
        // unreadable rows at or below it means the cursor did not move.
        let mut advanced_past = 0_i64;
        loop {
            let Some(mut hook) = super::readable_webhook(store, account).await? else {
                return Ok(Pass::Stop);
            };
            if !hook.settings.enabled {
                // A pause keeps the webhook enabled. Only the user turning
                // it off stops delivery; failures retry on the pause interval.
                return Ok(Pass::Stop);
            }
            // The watcher refuses a disallowed account, but events queued
            // before the address was removed would still be sent on the
            // next restart. Stop without delivering them.
            let Some(stored) = store.account(account).await? else {
                tracing::info!(account_id = %account, "account is gone; not delivering queued events");
                return Ok(Pass::Stop);
            };
            if !self.inner.config.email_allowed(&stored.email) {
                tracing::info!(account_id = %account, "account is not on the allow-list; not delivering queued events");
                return Ok(Pass::Stop);
            }
            let pending = store.pending_mail_events(account, BATCH).await?;
            if pending.events.is_empty() {
                // A page of unreadable rows is not an empty outbox. Those
                // rows can never be delivered; advance past them and keep
                // going so a later readable event is not stuck until they
                // age out. `advanced_past` stops a hot loop if the cursor
                // does not move.
                if let Some(sequence) = pending.skip_through
                    && sequence > advanced_past
                {
                    // The store warned about each of these when it skipped it.
                    tracing::info!(account_id = %account, sequence, "skipped unreadable events; delivering later ones");
                    advanced_past = sequence;
                    store.mark_mail_events_delivered(account, sequence).await?;
                    continue;
                }
                if pending.held.is_some() {
                    // The events before it have gone out. It and those after
                    // it wait, for the position would pass it. The receiver did
                    // not fail, so nothing is recorded against the webhook.
                    *failures = failures.saturating_add(1);
                    return Ok(Pass::Failed {
                        paused: hook.is_paused(),
                        retry_by: pending.held_for,
                    });
                }
                return Ok(Pass::Drained {
                    paused: hook.is_paused(),
                });
            }
            for event in pending.events {
                let delivery = tokio::select! {
                    () = cancel.cancelled() => return Ok(Pass::Stop),
                    delivery = self.deliver_event(&hook.settings, &event) => delivery,
                };
                let record = delivery_record(delivery.as_ref());
                if record.succeeded {
                    store
                        .mark_mail_events_delivered(account, event.sequence)
                        .await?;
                } else {
                    tracing::warn!(account_id = %account, sequence = event.sequence, summary = %record.summary, "webhook delivery failed");
                }
                let effect = store.record_delivery(account, &record).await?;
                if record.succeeded {
                    *failures = 0;
                    // A real success clears the stored pause. This page was
                    // loaded before that write, so a later failure in the
                    // same page must not keep treating the webhook as paused.
                    hook.paused_at = None;
                } else {
                    *failures = failures.saturating_add(1);
                    // Already paused, or this failure reached the limit.
                    // Either way the webhook stays enabled and the pump
                    // retries slowly. It does not turn the webhook off.
                    return Ok(Pass::Failed {
                        paused: hook.is_paused() || effect == DeliveryEffect::Paused,
                        retry_by: None,
                    });
                }
            }
        }
    }

    /// Sends one stored event. `Err` holds a summary when the stored
    /// settings are no longer valid.
    async fn deliver_event(
        &self,
        settings: &postkeep_store::WebhookSettings,
        event: &MailEvent,
    ) -> Result<Delivery, String> {
        let url = WebhookUrl::parse(&settings.url).map_err(|err| format!("Invalid URL: {err}"))?;
        let auth = settings
            .auth_header
            .as_ref()
            .map(|(name, value)| AuthHeader::new(name, value.expose_secret()))
            .transpose()
            .map_err(|err| format!("Invalid auth header: {err}"))?;
        let secret = settings
            .signing
            .then(|| settings.signing_secret.expose_secret());
        let body = payload_for_delivery(&event.payload, settings.include_sender)?;
        let request = event_request(
            body.into(),
            url,
            &EventMeta {
                id: &event.id,
                sequence: Some(event.sequence),
                timestamp: postkeep_store::now(),
            },
            auth.as_ref(),
            secret,
        );
        Ok(deliver(
            &self.inner.deliverer,
            &request,
            &self.inner.config.retry_delays,
        )
        .await)
    }
}

/// The body to sign and send.
///
/// When sender and subject are included, the stored bytes are sent
/// unchanged so a retry signs the same body. When they are not, `from`,
/// `from_unclear` and `subject` are removed first. A stored payload that is
/// not JSON is not sent.
fn payload_for_delivery(payload: &str, include_sender: bool) -> Result<Vec<u8>, String> {
    if include_sender {
        return Ok(payload.as_bytes().to_vec());
    }
    let mut value: serde_json::Value =
        serde_json::from_str(payload).map_err(|_| "stored event is not valid JSON".to_owned())?;
    let Some(object) = value.as_object_mut() else {
        return Ok(payload.as_bytes().to_vec());
    };
    let mut removed = false;
    for field in ["from", "from_unclear", "subject"] {
        removed |= object.remove(field).is_some();
    }
    if !removed {
        return Ok(payload.as_bytes().to_vec());
    }
    serde_json::to_vec(&value).map_err(|_| "could not encode the event".to_owned())
}

/// The log entry for a delivery.
fn delivery_record(delivery: Result<&Delivery, &String>) -> DeliveryRecord {
    DeliveryRecord {
        created_at: postkeep_store::now(),
        test: false,
        succeeded: delivery.is_ok_and(Delivery::succeeded),
        summary: delivery.map_or_else(Clone::clone, Delivery::summary),
        elapsed_ms: delivery
            .ok()
            .and_then(|delivery| delivery.result.as_ref().ok())
            .and_then(|response| i64::try_from(response.elapsed.as_millis()).ok()),
    }
}

/// Test hook that pauses a pump after delivery bookkeeping and before it
/// arms the in-memory pause slot.
pub(super) struct DeadlineGate {
    /// Signalled once the pump is about to change the slot.
    reached: std::sync::Arc<tokio::sync::Notify>,
    /// The pump waits here until the test releases it.
    release: tokio::sync::oneshot::Receiver<()>,
    /// Signalled after that pump's deadline mutation returns.
    finished: std::sync::Arc<tokio::sync::Notify>,
}

/// Default first retry delay for an event the receiver did not accept.
pub const OUTBOX_MIN_BACKOFF: Duration = Duration::from_mins(1);
/// Default longest retry delay, and the default pause interval.
///
/// The growing delay never waits longer than a paused webhook does.
pub const OUTBOX_MAX_BACKOFF: Duration = Duration::from_secs(3600);

#[cfg(test)]
mod tests {
    use super::payload_for_delivery;

    #[test]
    fn included_sender_keeps_the_stored_bytes() {
        let payload = "{\n  \"event\": \"new_mail\", \"from\": \"a@example.com\"\n}";
        assert_eq!(
            payload_for_delivery(payload, true).unwrap(),
            payload.as_bytes()
        );
        // Not JSON, but the setting says to send the stored body as-is.
        assert_eq!(payload_for_delivery("not json", true).unwrap(), b"not json");
    }

    #[test]
    fn omitted_sender_strips_from_and_subject_before_signing() {
        let payload = concat!(
            r#"{"event":"new_mail","from":"Ann <ann@example.com>","from_unclear":true,"#,
            r#""subject":"Lunch","id":"1"}"#
        );
        let sent = payload_for_delivery(payload, false).unwrap();
        assert_ne!(sent, payload.as_bytes());
        let value: serde_json::Value = serde_json::from_slice(&sent).unwrap();
        assert!(value.get("from").is_none());
        assert!(value.get("from_unclear").is_none());
        assert!(value.get("subject").is_none());
        assert_eq!(value["event"], "new_mail");
        assert_eq!(value["id"], "1");
    }

    #[test]
    fn omitted_sender_keeps_bytes_that_have_neither_field() {
        let payload = r#"{"event":"new_mail","id":"1"}"#;
        assert_eq!(
            payload_for_delivery(payload, false).unwrap(),
            payload.as_bytes()
        );
        assert_eq!(payload_for_delivery("[1]", false).unwrap(), b"[1]");
    }

    #[test]
    fn omitted_sender_refuses_a_payload_that_is_not_json() {
        let err = payload_for_delivery("not json", false).unwrap_err();
        assert!(err.contains("not valid JSON"), "{err}");
    }

    /// An old paused pump records a failure, then a replacement recovers the
    /// webhook and clears the slot. Releasing the old pump must not arm the
    /// slot again, and a deadline planted after that must not delay an
    /// active webhook.
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        clippy::unwrap_used,
        clippy::expect_used,
        reason = "the interleaving is the point of the test"
    )]
    async fn a_replaced_pump_cannot_rearm_a_recovered_deadline() {
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use postkeep_mail::ImapServers;
        use postkeep_store::{
            DeliveryRecord, MAX_CONSECUTIVE_FAILURES, MasterKey, Store, WebhookSettings,
        };
        use postkeep_webhook::testing::receiver;
        use secrecy::SecretString;
        use tokio::sync::{Notify, oneshot};
        use tokio_util::sync::CancellationToken;

        use super::super::{WatchConfig, Watchers};

        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("outbox.db").display());
        let store = Store::connect(
            &url,
            &MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let email = "rearm@example.com".to_owned();
        let account = store
            .upsert_account(&email, &SecretString::from("password".to_owned()))
            .await
            .unwrap()
            .id;
        let mut receiver = receiver(&[]).await;
        store
            .save_webhook(
                &account,
                &WebhookSettings {
                    enabled: true,
                    url: receiver.url("/hook"),
                    auth_header: None,
                    signing: false,
                    signing_secret: SecretString::from("whsec_test".to_owned()),
                    include_sender: true,
                },
            )
            .await
            .unwrap();
        let failure = DeliveryRecord {
            created_at: postkeep_store::now(),
            test: false,
            succeeded: false,
            summary: "HTTP 500".to_owned(),
            elapsed_ms: None,
        };
        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            store.record_delivery(&account, &failure).await.unwrap();
        }
        assert!(store.webhook(&account).await.unwrap().unwrap().is_paused());
        let payload = String::from_utf8(mail_event(&email, "A").to_body()).unwrap();
        store
            .append_mail_event(&account, &payload, None)
            .await
            .unwrap();

        let interval = Duration::from_secs(3600);
        let watchers = Watchers::new(
            store.clone(),
            ImapServers::default(),
            receiver.deliverer.clone(),
            WatchConfig {
                retry_delays: Vec::new(),
                outbox_min_backoff: Duration::from_millis(20),
                outbox_max_backoff: Duration::from_millis(40),
                webhook_retry_interval: interval,
                ..WatchConfig::default()
            },
            CancellationToken::new(),
        );
        receiver.respond_with(&[500, 200, 200]);
        let reached = Arc::new(Notify::new());
        let finished = Arc::new(Notify::new());
        let (release_tx, release_rx) = oneshot::channel();
        watchers.install_deadline_gate(Arc::clone(&reached), release_rx, Arc::clone(&finished));
        watchers.wake_prompt(&account);
        tokio::time::timeout(Duration::from_secs(5), reached.notified())
            .await
            .expect("the old pump did not reach the deadline");
        let failed_attempt = tokio::time::timeout(Duration::from_secs(5), receiver.requests.recv())
            .await
            .expect("the parked pump did not deliver")
            .unwrap();
        assert_eq!(failed_attempt.json()["id"], "A");
        let failed = store.webhook(&account).await.unwrap().unwrap();
        assert!(
            failed.is_paused(),
            "bookkeeping should still be paused when the old pump is parked"
        );
        assert_eq!(failed.delivered_sequence, 0);

        watchers.wake_prompt(&account);
        let recovered = tokio::time::timeout(Duration::from_secs(5), receiver.requests.recv())
            .await
            .expect("the replacement did not deliver")
            .unwrap();
        assert_eq!(recovered.json()["id"], "A");
        let mut cleared = false;
        for _ in 0..50 {
            let hook = store.webhook(&account).await.unwrap().unwrap();
            if hook.paused_at.is_none() && hook.delivered_sequence >= 1 && watchers.pumps() == 0 {
                cleared = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(cleared, "the replacement did not recover and drain");
        assert!(
            watchers.pause_remaining(&account).is_none(),
            "the replacement left a pause slot behind"
        );

        release_tx.send(()).expect("the old pump dropped the gate");
        tokio::time::timeout(Duration::from_secs(2), finished.notified())
            .await
            .expect("the old pump did not finish the deadline write");
        assert!(
            watchers.pause_remaining(&account).is_none(),
            "the replaced pump armed the pause slot after recovery"
        );

        // The stored webhook is active. An in-memory deadline must not make
        // the next event wait out the pause interval.
        watchers
            .pause_deadlines()
            .insert(account.clone(), Instant::now() + interval);
        let next = String::from_utf8(mail_event(&email, "B").to_body()).unwrap();
        store
            .append_mail_event(&account, &next, None)
            .await
            .unwrap();
        let started = Instant::now();
        watchers.wake(&account);
        let got = tokio::time::timeout(Duration::from_secs(2), receiver.requests.recv())
            .await
            .expect("an active webhook waited on a stale pause slot")
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "waited {:?}, which trusts the planted deadline",
            started.elapsed()
        );
        assert_eq!(got.json()["id"], "B");
        watchers.shutdown(Duration::from_secs(2)).await;
    }

    fn mail_event(email: &str, id: &str) -> postkeep_webhook::NewMailEvent {
        postkeep_webhook::NewMailEvent {
            event: postkeep_webhook::NEW_MAIL,
            test: false,
            account: email.to_owned(),
            folder: "INBOX".to_owned(),
            id: id.to_owned(),
            uid: None,
            message_id: None,
            from: None,
            from_unclear: false,
            subject: None,
            date: None,
            count: 1,
        }
    }
}
