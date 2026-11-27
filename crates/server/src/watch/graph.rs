//! New mail at Microsoft Graph: change-notification subscriptions.
//!
//! For an Outlook account with an enabled webhook, the watcher keeps one
//! subscription to `created` messages in the Inbox and renews it a day
//! before it expires (Graph allows at most 10,080 minutes for messages).
//! Graph calls `POST /push/microsoft` for new messages and
//! `/push/microsoft/lifecycle` for lifecycle events; see [`crate::push`].
//!
//! A pause after delivery failures does not stop or restart this watcher.
//! The subscription still renews a day before it expires, the account
//! keeps its watcher slot, and a push still records new mail. That mail
//! is not delivered until the pause interval. Pausing does not shorten
//! the renewal wait or call Graph more often. The user turning the
//! webhook off (the account page or `set_webhook_enabled`) cancels the
//! session. The replacement calls `graph_unsubscribe`, which deletes the
//! subscription and, when Graph's DELETE fails with anything other than
//! 404, keeps the local row so the next subscribe renews or deletes it.
//! The slot is released either way. Deleting the account unsubscribes the
//! same way first, while its tokens are still stored; see
//! [`Watchers::unsubscribe_before_delete`]. Failures never turn the webhook
//! off.
//!
//! A notification is only a hint: it triggers a *catch-up* that lists
//! Inbox messages received since the stored position and records one
//! event per page (at most 50 messages). The event counts the messages
//! of the page that pass the mailbox's filter rules and describes the
//! newest of them. A page none of which passes moves the position and
//! records no event, and a catch-up whose rules can't be read does
//! nothing until the next one. A burst larger than one page is reported
//! in that run, up to a page budget; a
//! validated `@odata.nextLink` past the budget is stored and the catch-up
//! continues without waiting for another notification. Replayed, duplicated
//! or forged-but-valid notifications therefore never produce duplicate
//! events, and missed ones are caught up on the next notification, the
//! periodic catch-up (every 15 minutes by default,
//! [`WatchConfig::graph_catch_up_interval`](super::WatchConfig::graph_catch_up_interval)),
//! the next renewal, or a `missed` lifecycle event. A catch-up that fails
//! because Graph or the database is briefly unavailable stays pending and
//! is retried with backoff, so that mail does not wait for the next
//! renewal. The retry stops on shutdown, when the webhook is disabled,
//! when the account is removed or not allowed, and when the sign-in has
//! to be renewed. A pause is not that stop: catch-up and renewal
//! continue, and the recorded mail waits for the pause interval.
//! Already-reported messages that share the stored
//! timestamp are skipped by following `@odata.nextLink`, and a tie larger
//! than the page budget cannot stall later mail: the next link is kept
//! and rechecked on the next run.

use std::time::Duration;

use axum::http::{HeaderName, Method, StatusCode};
use postkeep_mail::invisible;
use postkeep_store::{AccountId, AppendOutcome, Provider, PushSubscription, WatchAdvance};
use postkeep_upstream::http::join_segments;
use postkeep_upstream::{ApiClient, ApiError, UpstreamProvider};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::rules::{Fields, Judged, Rules};
use super::{BATCH_LIMIT, Exit, FOLDER, WatchError, WatchSignal, Watchers};
use crate::mailbox::id::{self, GRAPH_PREFIX};

/// Subscription lifetime requested: just under Graph's 10,080-minute
/// maximum for Outlook messages.
pub const SUBSCRIPTION_MINUTES: i64 = 10_070;
/// Renew this long before the subscription expires.
pub const RENEW_BEFORE_SECS: i64 = 24 * 3600;
/// The subscribed resource.
const RESOURCE: &str = "me/mailFolders('inbox')/messages";
/// Pages read per catch-up. Each page holds at most [`BATCH_LIMIT`]
/// messages. A validated `@odata.nextLink` past this budget is stored on
/// the position and another catch-up is scheduled, so a tie or a burst
/// larger than one run is still reported.
const MAX_CATCH_UP_PAGES: usize = 10;
/// Pages of `GET /subscriptions` followed when a create answers 409.
/// Each page is Graph's own page. An orphan past this bound is left in
/// place; the create fails and the watcher retries with backoff.
const MAX_SUBSCRIPTION_LIST_PAGES: usize = 5;

/// The stored position: the newest `receivedDateTime` reported and the
/// ids already reported at exactly that time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphPosition {
    /// RFC 3339 time.
    pub since: String,
    /// Graph ids received at `since` that were already reported.
    #[serde(default)]
    pub ids: Vec<String>,
    /// Validated Graph `@odata.nextLink` to resume from when a tie or a
    /// burst is larger than one catch-up. Absent when the next catch-up
    /// should list from `since`. It is checked against the Graph endpoint
    /// again before it is followed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<String>,
}

impl GraphPosition {
    const PREFIX: &'static str = "graph:";

    pub(super) fn parse(stored: Option<&str>) -> Option<Self> {
        serde_json::from_str(stored?.strip_prefix(Self::PREFIX)?).ok()
    }

    pub(super) fn encode(&self) -> String {
        format!(
            "{}{}",
            Self::PREFIX,
            serde_json::to_string(self).unwrap_or_default()
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Subscription {
    id: String,
}

/// One subscription from `GET /subscriptions`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListedSubscription {
    id: String,
    resource: Option<String>,
    notification_url: Option<String>,
}

/// A page of [`ListedSubscription`].
#[derive(Debug, Deserialize)]
struct SubscriptionList {
    #[serde(default)]
    value: Vec<ListedSubscription>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

/// What to do with the local row when Graph rejects the DELETE with
/// anything other than 404.
#[derive(Clone, Copy)]
enum AfterRemoteDelete {
    /// The subscription is still at Graph. Keep the row so the next
    /// subscribe can renew it instead of creating a duplicate.
    Keep,
    /// Drop the row so a new subscription is created. A 409 on that
    /// create removes the orphan if the remote DELETE failed.
    Drop,
}

#[derive(Debug, Deserialize)]
struct Messages {
    value: Vec<GraphNewMessage>,
    #[serde(default, rename = "@odata.nextLink")]
    next_link: Option<String>,
}

/// Where one catch-up is in the Inbox listing.
struct CatchUpCursor {
    /// Page about to be fetched.
    url: Url,
    /// Filter URL built from the stored time, used if a resume link fails.
    filter_url: Url,
    /// Graph endpoint. Next links are accepted only when they match it.
    base: Url,
    /// The stored resume link has not been fetched successfully yet.
    fallback_to_filter: bool,
    /// Raw next link of a page this run has not fetched yet.
    pending_raw: Option<String>,
    /// Pages fetched in this run. A rejected resume link does not count.
    pages: usize,
    /// The position as stored, which the next write of this run expects:
    /// the one this run read, then the last one it wrote.
    stored: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphNewMessage {
    id: String,
    received_date_time: String,
    subject: Option<String>,
    internet_message_id: Option<String>,
    from: Option<Sender>,
    /// Absent or `null` when Graph has none: a page that fails to parse stalls
    /// the catch-up.
    #[serde(default)]
    to_recipients: Option<Vec<Sender>>,
    /// As for `to_recipients`.
    #[serde(default)]
    cc_recipients: Option<Vec<Sender>>,
}

impl Judged for GraphNewMessage {
    fn fields(&self) -> Fields {
        let address = |sender: &Sender| sender.email_address.as_ref()?.address.clone();
        let recipients = self.to_recipients.iter().chain(&self.cc_recipients);
        let from = self.from.as_ref().and_then(address).unwrap_or_default();
        Fields {
            from_clear: postkeep_mail::mime::clear_address(&from),
            from,
            from_values: Vec::new(),
            to: recipients.flatten().filter_map(address).collect(),
            subject: self.subject.clone().unwrap_or_default(),
        }
    }
}

/// What a page of new mail is described with and judged by.
struct Report<'a> {
    /// The mailbox's address.
    email: &'a str,
    /// Whether an event names the sender and subject.
    include_sender: bool,
    /// The rules that decide which messages count.
    rules: &'a Rules,
}

/// How recording a page ended.
enum PageOutcome {
    /// The page is recorded: the position is now the one this run wrote.
    Recorded,
    /// Another watcher moved the position after this run read it.
    Lost,
    /// The webhook is gone.
    Gone,
}

/// A Graph `recipient`: the sender, or one of the recipients.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sender {
    /// Absent or `null` when Graph has none. Such a recipient has no
    /// address, and does not fail its page.
    #[serde(default)]
    email_address: Option<SenderAddress>,
}

#[derive(Debug, Deserialize)]
struct SenderAddress {
    name: Option<String>,
    address: Option<String>,
}

fn immutable() -> Vec<(HeaderName, String)> {
    vec![(
        HeaderName::from_static("prefer"),
        "IdType=\"ImmutableId\"".to_owned(),
    )]
}

impl Watchers {
    pub(super) fn graph_api(&self, account: &AccountId) -> Option<ApiClient> {
        let push = self.inner.push.get()?;
        push.graph_enabled().then(|| {
            ApiClient::new(
                push.tokens.clone(),
                account.clone(),
                UpstreamProvider::Microsoft,
            )
        })
    }

    /// Keeps the account's subscription alive until cancelled.
    pub(super) async fn graph_session(
        &self,
        account: &AccountId,
        cancel: &CancellationToken,
        failures: &mut u32,
    ) -> Result<Exit, WatchError> {
        // Before any subscription, renewal, or token use, and again before
        // each renewal. A refusal releases the slot and deletes nothing.
        if self.allow_list_blocks(account).await? {
            return Ok(Exit::Disabled);
        }
        let Some(api) = self.graph_api(account) else {
            tracing::info!(account_id = %account, "Microsoft sign-in is not configured; not watching this account");
            return Ok(Exit::Disabled);
        };
        let store = &self.inner.store;
        let hook = super::readable_webhook(store, account).await?;
        if !hook.as_ref().is_some_and(|hook| hook.settings.enabled) {
            // A pause keeps the webhook enabled, so this watcher stays up,
            // keeps renewing the subscription, and keeps the account's
            // slot. Only the user turning the webhook off, or removing it,
            // unsubscribes and releases the slot. A failed DELETE keeps
            // the local row; see `graph_unsubscribe`.
            self.graph_unsubscribe(&api).await;
            return Ok(Exit::Disabled);
        }
        // A first start begins now: existing mail is old. A position another
        // watcher stored after the read above is kept, and the catch-up below
        // reports the mail after it. When the webhook is gone, the loop below
        // unsubscribes.
        let fresh = GraphPosition {
            since: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ids: Vec::new(),
            resume: None,
        };
        let read = hook.and_then(|hook| hook.position);
        let usable = |stored: Option<&str>| GraphPosition::parse(stored).is_some();
        self.start_position(account, read, fresh.encode(), usable)
            .await?;
        loop {
            // The process that watches the mailbox now renews it.
            if !self.owns(account) {
                return Ok(Exit::Stopped);
            }
            if self.allow_list_blocks(account).await? {
                return Ok(Exit::Disabled);
            }
            // Re-read before each renewal. A pause is still enabled, so
            // the subscription keeps renewing and this task keeps the
            // slot. The wait below is not shortened by a pause, so pausing
            // does not call Graph again. The user turning the webhook off
            // cancels this sleep; if the loop does run again it
            // unsubscribes instead of renewing.
            let still_on = super::readable_webhook(store, account)
                .await?
                .is_some_and(|hook| hook.settings.enabled);
            if !still_on {
                self.graph_unsubscribe(&api).await;
                return Ok(Exit::Disabled);
            }
            let expires_at = self.graph_subscribe(&api).await?;
            *failures = 0;
            // Mail that arrived while no subscription existed.
            self.graph_catch_up(account).await?;
            // At least a minute, and normally about six days. A pause does
            // not change this, so it cannot busy-loop or renew early.
            let wait = (expires_at - RENEW_BEFORE_SECS - postkeep_store::now()).max(60);
            let renewal = tokio::time::sleep(Duration::from_secs(wait.unsigned_abs()));
            tokio::pin!(renewal);
            // Graph does not promise every notification, so the Inbox is
            // also listed on a timer. These runs share the account's
            // catch-up coalescing and backoff with notifications.
            let every = self
                .inner
                .config
                .graph_catch_up_interval
                .max(Duration::from_millis(1));
            let mut periodic = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
            periodic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return Ok(Exit::Stopped),
                    () = &mut renewal => break,
                    _ = periodic.tick() => self.schedule_graph_catch_up(account),
                }
            }
        }
    }

    /// Renews the stored subscription, or creates one. Returns when it
    /// expires (Unix seconds).
    ///
    /// A create that Graph answers with 409 is reconciled once: this
    /// app's subscriptions are listed and any Inbox subscription whose
    /// notification URL is this server's are deleted, then the create is
    /// tried once more. A second failure is returned and the watcher
    /// backs off.
    async fn graph_subscribe(&self, api: &ApiClient) -> Result<i64, WatchError> {
        let store = &self.inner.store;
        let account = api.account();
        let expires_at = postkeep_store::now() + SUBSCRIPTION_MINUTES * 60;
        let expiration = chrono::DateTime::from_timestamp(expires_at, 0)
            .unwrap_or_default()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        if let Some(existing) = store.push_subscription(account).await?
            && existing.provider == Provider::Graph
            && let Some(id) = &existing.subscription_id
        {
            if existing.expires_at - RENEW_BEFORE_SECS > postkeep_store::now() {
                return Ok(existing.expires_at);
            }
            let url = join_segments(&api.endpoints().graph, &["subscriptions", id]);
            match api
                .send_json(
                    Method::PATCH,
                    &url,
                    &[],
                    &json!({ "expirationDateTime": expiration }),
                )
                .await
            {
                Ok(_) => {
                    store
                        .save_push_subscription(
                            account,
                            &PushSubscription {
                                expires_at,
                                ..existing.clone()
                            },
                        )
                        .await?;
                    tracing::debug!(account_id = %account, "renewed the Graph subscription");
                    return Ok(expires_at);
                }
                Err(err) if err.status() == Some(StatusCode::NOT_FOUND) => {
                    tracing::info!(account_id = %account, "the Graph subscription is gone; creating a new one");
                }
                Err(err) => return Err(err.into()),
            }
        }
        self.create_graph_subscription(api, expires_at, &expiration)
            .await?;
        Ok(expires_at)
    }

    /// Creates a subscription and stores it.
    ///
    /// On 409, deletes this server's Inbox subscriptions and retries the
    /// create once. The same `clientState` is sent both times; it is
    /// stored only after Graph accepts the create.
    async fn create_graph_subscription(
        &self,
        api: &ApiClient,
        expires_at: i64,
        expiration: &str,
    ) -> Result<(), WatchError> {
        let account = api.account();
        let push = self.inner.push.get().ok_or(WatchError::NotConfigured)?;
        let client_state =
            postkeep_upstream::pkce::random_token().map_err(|_| WatchError::NotConfigured)?;
        let notification_url = push.url(crate::push::GRAPH_PATH);
        let body = json!({
            "changeType": "created",
            "notificationUrl": notification_url.clone(),
            "lifecycleNotificationUrl": push.url(crate::push::GRAPH_LIFECYCLE_PATH),
            "resource": RESOURCE,
            "expirationDateTime": expiration,
            "clientState": client_state.clone(),
            "latestSupportedTlsVersion": "v1_2",
        });
        let url = join_segments(&api.endpoints().graph, &["subscriptions"]);
        let headers = immutable();
        let response = match api.send_json(Method::POST, &url, &headers, &body).await {
            Ok(response) => response,
            Err(err) if err.status() == Some(StatusCode::CONFLICT) => {
                tracing::info!(
                    account_id = %account,
                    "Graph already has this inbox subscription; removing this server's copy and retrying once"
                );
                self.delete_conflicting_subscriptions(api, &notification_url)
                    .await?;
                api.send_json(Method::POST, &url, &headers, &body).await?
            }
            Err(err) => return Err(err.into()),
        };
        let created: Subscription = api.parse(&response)?;
        self.inner
            .store
            .save_push_subscription(
                account,
                &PushSubscription {
                    provider: Provider::Graph,
                    subscription_id: Some(created.id),
                    client_state_hash: Some(PushSubscription::hash_client_state(&client_state)),
                    expires_at,
                },
            )
            .await?;
        tracing::info!(account_id = %account, "created a Graph subscription for new mail");
        Ok(())
    }

    /// Lists this app's subscriptions and deletes Inbox ones that notify
    /// this server. Follows `@odata.nextLink` only while it stays on the
    /// Graph endpoint, and at most [`MAX_SUBSCRIPTION_LIST_PAGES`] pages.
    async fn delete_conflicting_subscriptions(
        &self,
        api: &ApiClient,
        notification_url: &str,
    ) -> Result<(), WatchError> {
        let account = api.account();
        let base = api.endpoints().graph.clone();
        let mut url = join_segments(&base, &["subscriptions"]);
        for _ in 0..MAX_SUBSCRIPTION_LIST_PAGES {
            let page: SubscriptionList = api.get_json(&url, &[]).await?;
            for subscription in &page.value {
                if subscription.id.is_empty()
                    || !conflicts_with_inbox(subscription, notification_url)
                {
                    continue;
                }
                tracing::info!(
                    account_id = %account,
                    subscription_id = %subscription.id,
                    "deleting a Graph subscription that blocked a new one"
                );
                if let Err(err) = delete_at_graph(api, &subscription.id).await
                    && err.status() != Some(StatusCode::NOT_FOUND)
                {
                    return Err(err.into());
                }
            }
            let Some(raw) = page.next_link.as_deref() else {
                return Ok(());
            };
            let Some(next) = crate::mailbox::graph::validated_next_link(&base, Some(raw)) else {
                tracing::warn!(
                    account_id = %account,
                    "ignored a Graph subscription list link that left the Graph endpoint"
                );
                return Ok(());
            };
            url = next;
        }
        tracing::warn!(
            account_id = %account,
            "stopped listing Graph subscriptions after the page budget"
        );
        Ok(())
    }

    /// Deletes the account's subscription at Graph and, when that delete
    /// succeeded or Graph no longer has it, the local row if it still
    /// stores the same id. Best effort: errors are logged.
    ///
    /// A remote failure other than 404 keeps the local row. The
    /// subscription is still at Graph, and forgetting the row would make
    /// the next create fail with 409 until the orphan expires. While the
    /// webhook is disabled the row is unused (catch-up checks `enabled`);
    /// the next subscribe renews it. This returns after one attempt, so a
    /// disabled webhook does not retry. Account deletion calls this before
    /// it removes the row and the tokens; see
    /// [`Self::unsubscribe_before_delete`].
    ///
    /// A replacement stored while the DELETE was in flight keeps its row.
    pub(super) async fn graph_unsubscribe(&self, api: &ApiClient) {
        let account = api.account();
        let existing = match self.inner.store.push_subscription(account).await {
            Ok(Some(existing)) => existing,
            Ok(None) => return,
            Err(err) => {
                tracing::warn!(
                    account_id = %account,
                    error = %err,
                    "could not load the Graph subscription to delete"
                );
                return;
            }
        };
        let Some(id) = existing.subscription_id else {
            if let Err(err) = self
                .inner
                .store
                .delete_push_subscription_if_id(account, None)
                .await
            {
                tracing::warn!(
                    account_id = %account,
                    error = %err,
                    "could not forget the Graph subscription"
                );
            }
            return;
        };
        self.delete_named_subscription(api, &id, AfterRemoteDelete::Keep)
            .await;
    }

    /// Deletes `subscription_id` at Graph and drops the local row when it
    /// still stores that id.
    ///
    /// Returns whether the local row was removed. A newer row is left in
    /// place. With [`AfterRemoteDelete::Keep`], a remote failure other
    /// than 404 leaves the row as well.
    async fn delete_named_subscription(
        &self,
        api: &ApiClient,
        subscription_id: &str,
        on_remote_error: AfterRemoteDelete,
    ) -> bool {
        let account = api.account();
        let remote_gone = match delete_at_graph(api, subscription_id).await {
            Ok(()) => true,
            Err(err) if err.status() == Some(StatusCode::NOT_FOUND) => true,
            Err(err) => {
                tracing::info!(
                    account_id = %account,
                    subscription_id,
                    error = %err,
                    keep_local = matches!(on_remote_error, AfterRemoteDelete::Keep),
                    "could not delete the Graph subscription"
                );
                false
            }
        };
        if !remote_gone && matches!(on_remote_error, AfterRemoteDelete::Keep) {
            return false;
        }
        match self
            .inner
            .store
            .delete_push_subscription_if_id(account, Some(subscription_id))
            .await
        {
            Ok(removed) => removed,
            Err(err) => {
                tracing::warn!(
                    account_id = %account,
                    subscription_id,
                    error = %err,
                    "could not forget the Graph subscription"
                );
                false
            }
        }
    }

    /// Records one event for Inbox messages received since the stored
    /// position. Serialized per account: the lock is held from the read of
    /// the stored position through the publish, so a replacement watcher
    /// waits until this pass commits and cannot record the same page.
    ///
    /// Every write of the position is a compare-and-set on the one this run
    /// holds. One that finds it moved ends the run, and another run reads
    /// the position again.
    pub(crate) async fn graph_catch_up(&self, account: &AccountId) -> Result<(), WatchError> {
        let lock = self.catch_up_lock(account);
        let _guard = lock.lock().await;
        let Some(api) = self.graph_api(account) else {
            return Ok(());
        };
        let store = &self.inner.store;
        let Some(hook) = super::readable_webhook(store, account).await? else {
            return Ok(());
        };
        if !hook.settings.enabled {
            // A pause keeps the webhook enabled, so a push while paused
            // still records. The pump does not deliver until the pause
            // interval. The user turning it off records nothing further.
            return Ok(());
        }
        let Some(account_row) = store.account(account).await? else {
            return Ok(());
        };
        if !self.inner.config.email_allowed(&account_row.email) {
            return Ok(());
        }
        let Some(mut position) = GraphPosition::parse(hook.position.as_deref()) else {
            return Ok(());
        };
        // Rules that can't be read hold the mail where it is, before Graph is asked.
        let Some(rules) = self.rules(account, &hook).await? else {
            return Ok(());
        };
        let report = Report {
            email: &account_row.email,
            include_sender: hook.settings.include_sender,
            rules: &rules,
        };
        let run = self
            .page_through_inbox(account, &api, &report, &mut position, hook.position)
            .await;
        if matches!(run, Err(WatchError::CursorMoved)) {
            // Another watcher moved the position after this run read it, or
            // the webhook is gone. Drop the rest of this run.
            tracing::info!(account_id = %account, "the Graph position changed during this run; reading it again");
            self.schedule_graph_catch_up(account);
            return Ok(());
        }
        run
    }

    /// Stores `position` without an event, only over `stored`, and then
    /// remembers it as `stored`. Fails with [`WatchError::CursorMoved`] when
    /// another watcher moved the position after this run read it, or the
    /// webhook is gone.
    async fn save_position(
        &self,
        account: &AccountId,
        position: &GraphPosition,
        stored: &mut Option<String>,
    ) -> Result<(), WatchError> {
        let encoded = position.encode();
        let store = &self.inner.store;
        if !store
            .advance_watch_position(account, stored.as_deref(), &encoded)
            .await?
        {
            return Err(WatchError::CursorMoved);
        }
        *stored = Some(encoded);
        Ok(())
    }

    /// Lists Inbox pages from the stored position and publishes one event
    /// per page that contains new mail that passes the rules.
    async fn page_through_inbox(
        &self,
        account: &AccountId,
        api: &ApiClient,
        report: &Report<'_>,
        position: &mut GraphPosition,
        mut stored: Option<String>,
    ) -> Result<(), WatchError> {
        let base = api.endpoints().graph.clone();
        let filter_url = inbox_messages_url(api, &position.since);
        let (url, fallback_to_filter) = self
            .opening_page(account, position, &base, &filter_url, &mut stored)
            .await?;
        let mut cursor = CatchUpCursor {
            url,
            filter_url,
            base,
            fallback_to_filter,
            pending_raw: None,
            pages: 0,
            stored,
        };
        loop {
            if cursor.pages == MAX_CATCH_UP_PAGES {
                // The budget was spent before this link. Remember it so
                // the next run does not reread the same tie pages, and
                // schedule that run instead of reporting success.
                let pending_raw = cursor.pending_raw.take();
                self.persist_resume(account, position, pending_raw, &mut cursor.stored)
                    .await?;
                return Ok(());
            }
            let Some(page) = self
                .fetch_inbox_page(account, api, position, &mut cursor)
                .await?
            else {
                continue;
            };
            cursor.pages += 1;
            if !self
                .handle_inbox_page(account, report, position, page, &mut cursor)
                .await?
            {
                return Ok(());
            }
        }
    }

    /// The first URL of this run and whether a failed fetch should fall
    /// back to the filter. A stored link on another host is dropped.
    ///
    /// Listing from `since` after dropping a link is safe: ids already
    /// reported at that time are filtered out.
    async fn opening_page(
        &self,
        account: &AccountId,
        position: &mut GraphPosition,
        base: &Url,
        filter_url: &Url,
        stored: &mut Option<String>,
    ) -> Result<(Url, bool), WatchError> {
        if let Some(resume) = position
            .resume
            .as_deref()
            .and_then(|link| crate::mailbox::graph::validated_next_link(base, Some(link)))
        {
            return Ok((resume, true));
        }
        if position.resume.take().is_some() {
            self.save_position(account, position, stored).await?;
        }
        Ok((filter_url.clone(), false))
    }

    /// Reads one page. `None` means the stored resume link was rejected
    /// and the cursor now points at the filter URL.
    async fn fetch_inbox_page(
        &self,
        account: &AccountId,
        api: &ApiClient,
        position: &mut GraphPosition,
        cursor: &mut CatchUpCursor,
    ) -> Result<Option<Messages>, WatchError> {
        match api.get_json(&cursor.url, &immutable()).await {
            Ok(page) => {
                cursor.fallback_to_filter = false;
                Ok(Some(page))
            }
            Err(err) if cursor.fallback_to_filter => {
                tracing::info!(account_id = %account, error = %err, "stored Graph resume link was rejected; listing from the stored time");
                cursor.fallback_to_filter = false;
                position.resume = None;
                self.save_position(account, position, &mut cursor.stored)
                    .await?;
                cursor.url = cursor.filter_url.clone();
                Ok(None)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Publishes a page that has new mail, or follows one that does not.
    ///
    /// The position moves past every new message of the page. The event counts
    /// those that pass the rules and describes the newest of them. If none
    /// passes, there is no event and the position moves the same way, and
    /// only from where this run read it.
    ///
    /// Returns whether this run should read another page.
    async fn handle_inbox_page(
        &self,
        account: &AccountId,
        report: &Report<'_>,
        position: &mut GraphPosition,
        page: Messages,
        cursor: &mut CatchUpCursor,
    ) -> Result<bool, WatchError> {
        let next_raw = page.next_link;
        let next_url =
            crate::mailbox::graph::validated_next_link(&cursor.base, next_raw.as_deref());
        let fresh: Vec<GraphNewMessage> = page
            .value
            .into_iter()
            .filter(|message| {
                !(message.received_date_time == position.since
                    && position.ids.contains(&message.id))
            })
            .collect();
        if fresh.is_empty() {
            if let Some(next) = next_url {
                cursor.pending_raw = next_raw;
                cursor.url = next;
                return Ok(true);
            }
            if position.resume.take().is_some() {
                self.save_position(account, position, &mut cursor.stored)
                    .await?;
            }
            return Ok(false);
        }
        note_reported(position, &fresh);
        let passing = report.rules.keep(fresh).await;
        let budget_used = cursor.pages == MAX_CATCH_UP_PAGES;
        // Store the next link in the same write as the event when this
        // run cannot follow it. Otherwise the next page is read below.
        position.resume = if budget_used && next_url.is_some() {
            next_raw.clone()
        } else {
            None
        };
        let next = position.encode();
        match self
            .record_page(account, report, &passing, cursor, &next)
            .await?
        {
            PageOutcome::Recorded => cursor.stored = Some(next),
            // `graph_catch_up` drops this page and reads the position again.
            PageOutcome::Lost => return Err(WatchError::CursorMoved),
            // Nothing more is recorded for this account, so no page is read.
            PageOutcome::Gone => return Ok(false),
        }
        match next_url {
            Some(next) if !budget_used => {
                cursor.pending_raw = next_raw;
                cursor.url = next;
                Ok(true)
            }
            Some(_) => {
                self.continue_catch_up(account);
                Ok(false)
            }
            None => Ok(false),
        }
    }

    /// Records a page whose position is `next`: one event for `passing`, the
    /// messages that pass the rules, or only the move when there are none.
    /// The position moves only if it is still the one this run read.
    async fn record_page(
        &self,
        account: &AccountId,
        report: &Report<'_>,
        passing: &[GraphNewMessage],
        cursor: &CatchUpCursor,
        next: &str,
    ) -> Result<PageOutcome, WatchError> {
        let Some(newest) = passing.last() else {
            let expected = cursor.stored.as_deref();
            let store = &self.inner.store;
            let moved = store
                .advance_watch_position(account, expected, next)
                .await?;
            return Ok(if moved {
                PageOutcome::Recorded
            } else {
                PageOutcome::Lost
            });
        };
        let count = passing.len().min(BATCH_LIMIT);
        let event = new_mail_event(report.email, newest, count);
        let event = if report.include_sender {
            event
        } else {
            event.without_sender_and_subject()
        };
        let advance = WatchAdvance::Position {
            expected: cursor.stored.clone(),
            next: next.to_owned(),
        };
        Ok(match self.publish(account, &event, Some(advance)).await? {
            AppendOutcome::Stored(_) => PageOutcome::Recorded,
            AppendOutcome::StaleCursor => PageOutcome::Lost,
            AppendOutcome::NoWebhook => PageOutcome::Gone,
        })
    }

    /// Stores a validated next link and schedules the run that follows it.
    async fn persist_resume(
        &self,
        account: &AccountId,
        position: &mut GraphPosition,
        pending_raw: Option<String>,
        stored: &mut Option<String>,
    ) -> Result<(), WatchError> {
        let Some(raw) = pending_raw else {
            return Ok(());
        };
        position.resume = Some(raw);
        self.save_position(account, position, stored).await?;
        self.continue_catch_up(account);
        Ok(())
    }

    /// Schedules the catch-up that reads pages this run did not reach.
    fn continue_catch_up(&self, account: &AccountId) {
        tracing::info!(account_id = %account, "Outlook catch-up reached its page budget; continuing");
        self.schedule_graph_catch_up(account);
    }

    /// Catches up after a short debounce, in the background.
    ///
    /// At most one catch-up runs for the account. A request while that one
    /// is scheduled or running — including a `missed` lifecycle event —
    /// records a single rerun. A transient failure retries with backoff; a
    /// request during that wait runs the next pass without waiting it out.
    pub fn schedule_graph_catch_up(&self, account: &AccountId) {
        self.schedule_provider_catch_up(account, super::ProviderCatchUp::Graph);
    }

    /// Handles a lifecycle event in the background. `missed` shares the
    /// account's catch-up coalescing instead of starting its own task.
    ///
    /// `subscription_id` is the id verified with the notification.
    /// `reauthorizationRequired` and `subscriptionRemoved` act only on
    /// that id, so a late event cannot drop a subscription that has
    /// replaced it. The event is passed on when another process watches
    /// the mailbox.
    pub fn schedule_graph_lifecycle(
        &self,
        account: &AccountId,
        subscription_id: String,
        event: String,
    ) {
        if event == "missed" {
            self.schedule_graph_catch_up(account);
            return;
        }
        if !self.owns(account) {
            self.forward(WatchSignal::GraphLifecycle {
                account: account.clone(),
                subscription_id,
                event,
            });
            return;
        }
        let this = self.clone();
        let account = account.clone();
        self.inner.tracker.spawn(async move {
            this.graph_lifecycle(&account, &subscription_id, &event)
                .await;
        });
    }

    /// Handles a lifecycle event for the subscription that was verified.
    ///
    /// `missed` schedules a catch-up for the account. The other events
    /// return without changing a row whose id is no longer
    /// `subscription_id`.
    pub(crate) async fn graph_lifecycle(
        &self,
        account: &AccountId,
        subscription_id: &str,
        event: &str,
    ) {
        match event {
            "reauthorizationRequired" => {
                self.reauthorize_verified(account, subscription_id).await;
            }
            "subscriptionRemoved" => {
                match self
                    .inner
                    .store
                    .delete_push_subscription_if_id(account, Some(subscription_id))
                    .await
                {
                    Ok(true) => self.refresh(account),
                    Ok(false) => {
                        tracing::debug!(
                            account_id = %account,
                            subscription_id,
                            "ignoring Graph subscriptionRemoved for a subscription that is no longer current"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            account_id = %account,
                            subscription_id,
                            error = %err,
                            "could not forget the removed Graph subscription"
                        );
                    }
                }
            }
            "missed" => self.schedule_graph_catch_up(account),
            other => {
                tracing::debug!(
                    account_id = %account,
                    subscription_id,
                    lifecycle_event = %other,
                    "ignoring Graph lifecycle event"
                );
            }
        }
    }

    /// Reauthorizes `subscription_id` when it is still the stored one.
    ///
    /// On failure, asks Graph to delete that id and drops the local row
    /// only when it still has that id, then restarts the watcher.
    /// `graph_subscribe` will not replace a stored subscription whose
    /// expiry is still outside the renewal window, so the row has to go
    /// even when the remote DELETE fails. The create that follows
    /// reconciles a leftover subscription on 409. A row stored under a
    /// new id is left alone, and the watcher is restarted only when this
    /// id was the one removed. This does not call `graph_unsubscribe`:
    /// that reads whatever is current and keeps the row when Graph's
    /// DELETE fails, which would leave delivery paused.
    async fn reauthorize_verified(&self, account: &AccountId, subscription_id: &str) {
        let Some(api) = self.graph_api(account) else {
            return;
        };
        let current = match self.inner.store.push_subscription(account).await {
            Ok(Some(subscription)) => subscription.subscription_id,
            Ok(None) => None,
            Err(err) => {
                tracing::warn!(
                    account_id = %account,
                    error = %err,
                    "could not load the Graph subscription to reauthorize"
                );
                return;
            }
        };
        if current.as_deref() != Some(subscription_id) {
            tracing::debug!(
                account_id = %account,
                subscription_id,
                "ignoring Graph reauthorization for a subscription that is no longer current"
            );
            return;
        }
        let url = join_segments(
            &api.endpoints().graph,
            &["subscriptions", subscription_id, "reauthorize"],
        );
        if let Err(err) = api.send_json(Method::POST, &url, &[], &json!({})).await {
            tracing::warn!(
                account_id = %account,
                subscription_id,
                error = %err,
                "could not reauthorize the Graph subscription; recreating it"
            );
            if self
                .delete_named_subscription(&api, subscription_id, AfterRemoteDelete::Drop)
                .await
            {
                self.refresh(account);
                self.schedule_graph_catch_up(account);
            }
        }
    }
}

/// Deletes one subscription at Graph. A 404 is reported as an error so
/// the caller can decide whether the subscription is already gone.
async fn delete_at_graph(api: &ApiClient, subscription_id: &str) -> Result<(), ApiError> {
    let url = join_segments(&api.endpoints().graph, &["subscriptions", subscription_id]);
    api.call(
        Method::DELETE,
        &url,
        &[],
        axum::body::Bytes::new(),
        64 * 1024,
    )
    .await
    .map(|_| ())
}

/// Whether `subscription` is an Inbox subscription that notifies this server.
fn conflicts_with_inbox(subscription: &ListedSubscription, notification_url: &str) -> bool {
    let resource_matches = subscription
        .resource
        .as_deref()
        .is_some_and(|resource| resource.eq_ignore_ascii_case(RESOURCE));
    let url_matches = subscription
        .notification_url
        .as_deref()
        .is_some_and(|url| same_notification_url(url, notification_url));
    resource_matches && url_matches
}

/// Whether `actual` and `expected` name the same notification URL.
///
/// Host and scheme are compared without case, and an explicit default
/// port matches an omitted one. The path and query must be identical, so
/// another server or the lifecycle URL is not this subscription.
fn same_notification_url(actual: &str, expected: &str) -> bool {
    let Ok(actual_url) = Url::parse(actual) else {
        return false;
    };
    let Ok(expected_url) = Url::parse(expected) else {
        return false;
    };
    actual_url.scheme() == expected_url.scheme()
        && actual_url.host() == expected_url.host()
        && actual_url.port_or_known_default() == expected_url.port_or_known_default()
        && actual_url.path() == expected_url.path()
        && actual_url.query() == expected_url.query()
}

/// The first page of Inbox messages received at or after `since`.
fn inbox_messages_url(api: &ApiClient, since: &str) -> Url {
    let mut url = join_segments(
        &api.endpoints().graph,
        &["me", "mailFolders", "inbox", "messages"],
    );
    url.query_pairs_mut()
        .append_pair("$filter", &format!("receivedDateTime ge {since}"))
        .append_pair("$orderby", "receivedDateTime asc")
        .append_pair("$top", &BATCH_LIMIT.to_string())
        .append_pair(
            "$select",
            "id,receivedDateTime,subject,internetMessageId,from,toRecipients,ccRecipients",
        );
    url
}

/// Moves `position` past `fresh`, which is in ascending `receivedDateTime`
/// order. Ids are kept only for the newest timestamp on the page; older
/// ones fall behind `since` and are not listed again.
fn note_reported(position: &mut GraphPosition, fresh: &[GraphNewMessage]) {
    let Some(newest) = fresh.last() else {
        return;
    };
    let newest_time = newest.received_date_time.clone();
    let at_newest: Vec<String> = fresh
        .iter()
        .filter(|message| message.received_date_time == newest_time)
        .map(|message| message.id.clone())
        .collect();
    if newest_time == position.since {
        position.ids.extend(at_newest);
    } else {
        position.since = newest_time;
        position.ids = at_newest;
    }
}

fn new_mail_event(
    email: &str,
    newest: &GraphNewMessage,
    count: usize,
) -> postkeep_webhook::NewMailEvent {
    postkeep_webhook::NewMailEvent {
        event: postkeep_webhook::NEW_MAIL,
        test: false,
        account: email.to_owned(),
        folder: FOLDER.to_owned(),
        id: id::provider_id(GRAPH_PREFIX, &newest.id),
        uid: None,
        message_id: newest
            .internet_message_id
            .as_deref()
            .map(|id| invisible::visible(id.trim().trim_start_matches('<').trim_end_matches('>'))),
        from: newest.from.as_ref().and_then(|from| {
            let sender = from.email_address.as_ref()?;
            let address = sender.address.as_deref()?;
            Some(invisible::email_address(sender.name.as_deref(), address))
        }),
        from_unclear: false,
        subject: newest.subject.as_deref().map(invisible::visible),
        date: chrono::DateTime::parse_from_rfc3339(&newest.received_date_time)
            .ok()
            .map(|date| date.to_rfc3339()),
        count: u32::try_from(count).unwrap_or(u32::MAX),
    }
}

impl From<ApiError> for WatchError {
    fn from(err: ApiError) -> Self {
        Self::Api(Box::new(err))
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]
mod tests {
    use std::pin::pin;
    use std::time::Duration;

    use std::time::Instant;

    use axum::http::StatusCode;
    use postkeep_store::{Provider, PushSubscription, StoreError};
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::harness::{self, Hold, provider_setup};
    use super::super::{WatchConfig, WatchError};
    use super::*;

    #[test]
    fn positions_round_trip() {
        let position = GraphPosition {
            since: "2026-10-08T09:00:00Z".to_owned(),
            ids: vec!["AAMk".to_owned()],
            resume: None,
        };
        assert_eq!(
            GraphPosition::parse(Some(&position.encode())),
            Some(position.clone())
        );
        let with_resume = GraphPosition {
            resume: Some("https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc".to_owned()),
            ..position.clone()
        };
        assert_eq!(
            GraphPosition::parse(Some(&with_resume.encode())),
            Some(with_resume)
        );
        // Positions stored before `resume` existed.
        let legacy = r#"graph:{"since":"2026-10-08T09:00:00Z","ids":["AAMk"]}"#;
        assert_eq!(GraphPosition::parse(Some(legacy)), Some(position));
        assert_eq!(GraphPosition::parse(Some("gmail:{}")), None);
        assert_eq!(GraphPosition::parse(None), None);
    }

    #[test]
    fn conflicting_subscriptions_are_this_servers_inbox_only() {
        let ours = "https://mail.example.com/push/microsoft";
        let listed = |resource: &str, url: &str| ListedSubscription {
            id: "id".to_owned(),
            resource: Some(resource.to_owned()),
            notification_url: Some(url.to_owned()),
        };
        assert!(conflicts_with_inbox(
            &listed(
                "Me/MailFolders('Inbox')/Messages",
                "https://Mail.Example.com/push/microsoft"
            ),
            ours
        ));
        assert!(conflicts_with_inbox(
            &listed(RESOURCE, "https://mail.example.com:443/push/microsoft"),
            ours
        ));
        assert!(!conflicts_with_inbox(
            &listed(RESOURCE, "https://other.example/push/microsoft"),
            ours
        ));
        assert!(!conflicts_with_inbox(
            &listed(
                RESOURCE,
                "https://mail.example.com/push/microsoft/lifecycle"
            ),
            ours
        ));
        assert!(!conflicts_with_inbox(&listed("me/events", ours), ours));
        assert!(!conflicts_with_inbox(
            &listed(RESOURCE, "https://mail.example.com/push/microsoft?extra=1"),
            ours
        ));
        assert!(!conflicts_with_inbox(
            &ListedSubscription {
                id: "id".to_owned(),
                resource: None,
                notification_url: Some(ours.to_owned()),
            },
            ours
        ));
    }

    #[test]
    fn events_filter_invisible_characters() {
        let newest: GraphNewMessage = serde_json::from_value(json!({
            "id": "AAMk-1",
            "receivedDateTime": "2026-10-08T09:00:00Z",
            "subject": "Plans\u{E0068}",
            "internetMessageId": "<a\u{200B}b@x.test>",
            "from": { "emailAddress": {
                "name": "Bank\u{202E}knaB\u{200B}", "address": "bo\u{200B}ss@x.test"
            } }
        }))
        .unwrap();
        let event = new_mail_event("me@example.com", &newest, 1);
        assert_eq!(event.message_id.as_deref(), Some("ab@x.test"));
        assert_eq!(
            event.from.as_deref(),
            Some("Bank\\u{202e}knaB <bo\\u{200b}ss@x.test>")
        );
        assert_eq!(event.subject.as_deref(), Some("Plans"));
    }

    /// A sender without an `emailAddress`, or with a `null` one, is not named.
    #[test]
    fn an_event_names_no_sender_without_an_email_address() {
        for from in [json!({}), json!({ "emailAddress": null })] {
            let newest: GraphNewMessage = serde_json::from_value(json!({
                "id": "AAMk-1",
                "receivedDateTime": "2026-10-08T09:00:00Z",
                "from": from,
            }))
            .unwrap();
            assert_eq!(new_mail_event("me@example.com", &newest, 1).from, None);
        }
    }

    fn tied_message(id: &str, received: &str) -> serde_json::Value {
        json!({
            "id": id,
            "receivedDateTime": received,
            "subject": "same",
            "internetMessageId": format!("<{id}@example.com>"),
            "from": { "emailAddress": { "address": "sender@example.com" } }
        })
    }

    #[tokio::test]
    async fn catch_up_follows_a_page_that_was_already_reported() {
        let mut setup = provider_setup(Provider::Graph).await;
        let since = "2026-10-08T09:00:00Z";
        let ids: Vec<String> = (0..BATCH_LIMIT).map(|n| format!("tied-{n}")).collect();
        let position = GraphPosition {
            since: since.to_owned(),
            ids: ids.clone(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
        let page: Vec<_> = ids.iter().map(|id| tied_message(id, since)).collect();
        let next = format!(
            "{}/graph/v1.0/me/mailFolders/inbox/messages?$skiptoken=page-2",
            setup.server.uri()
        );
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param("$top", "50"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": page,
                "@odata.nextLink": next,
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param("$skiptoken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("later-1", "2026-10-08T09:00:01Z")]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GraphPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(got.json()["id"], "graph.later-1");
        assert_eq!(stored.since, "2026-10-08T09:00:01Z");
        assert_eq!(stored.ids, vec!["later-1".to_owned()]);
        assert_eq!(hook.last_sequence, 1);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn catch_up_ignores_an_off_host_next_link() {
        let setup = provider_setup(Provider::Graph).await;
        let since = "2026-10-08T09:00:00Z";
        let ids: Vec<String> = (0..BATCH_LIMIT).map(|n| format!("tied-{n}")).collect();
        let position = GraphPosition {
            since: since.to_owned(),
            ids: ids.clone(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
        let page: Vec<_> = ids.iter().map(|id| tied_message(id, since)).collect();
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param("$top", "50"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": page,
                "@odata.nextLink": "https://evil.example/graph/v1.0/me/messages?$skiptoken=x",
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.position.as_deref(), Some(position.encode().as_str()));
        assert_eq!(hook.last_sequence, 0);
        assert_eq!(setup.server.received_requests().await.unwrap().len(), 1);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_position_moved_during_the_run_drops_the_page_and_reads_again() {
        let setup = provider_setup(Provider::Graph).await;
        let since = "2026-10-08T09:00:00Z";
        let raced_at = "2026-10-08T09:05:00Z";
        let start = GraphPosition {
            since: since.to_owned(),
            ids: Vec::new(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &start.encode())
            .await
            .unwrap();
        // The listing is held, so another watcher reports the same message
        // and moves the position while this run waits for the page.
        let page = json!({ "value": [tied_message("raced", raced_at)] });
        let (mut hold, responder) = Hold::new(ResponseTemplate::new(200).set_body_json(page));
        Mock::given(method("GET"))
            .and(path(INBOX))
            .respond_with(responder)
            .expect(2)
            .mount(&setup.server)
            .await;
        let moved = GraphPosition {
            since: raced_at.to_owned(),
            ids: vec!["raced".to_owned()],
            resume: None,
        }
        .encode();
        let mut run = pin!(setup.watchers.graph_catch_up(&setup.account));
        hold.arrived_before(&mut run).await;
        setup
            .store
            .set_watch_position(&setup.account, &moved)
            .await
            .unwrap();
        // The held page, then the rerun's.
        hold.release();
        hold.release();
        run.await.unwrap();
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0, "the stale page was not recorded");
        assert_eq!(hook.position.as_deref(), Some(moved.as_str()));

        // The rerun lists from the moved position and finds nothing new.
        harness::wait_for_requests(&setup.server, "GET", INBOX, 2).await;
        wait_until_catch_up_idle(&setup).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0);
        assert_eq!(hook.position.as_deref(), Some(moved.as_str()));
        harness::finish(&setup).await;
    }

    fn next_link(server: &MockServer, token: &str) -> String {
        format!(
            "{}/graph/v1.0/me/mailFolders/inbox/messages?$skiptoken={token}",
            server.uri()
        )
    }

    #[tokio::test]
    async fn catch_up_reports_every_page_of_a_burst() {
        let mut setup = provider_setup(Provider::Graph).await;
        let position = GraphPosition {
            since: "2026-10-08T08:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
        let first: Vec<_> = (0..BATCH_LIMIT)
            .map(|n| tied_message(&format!("batch-{n}"), "2026-10-08T09:00:00Z"))
            .collect();
        let next = next_link(&setup.server, "page-2");
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": first,
                "@odata.nextLink": next,
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param("$skiptoken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("batch-later", "2026-10-08T09:00:01Z")]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let first_event = harness::next_event(&mut setup.receiver).await;
        let second_event = harness::next_event(&mut setup.receiver).await;
        assert_eq!(first_event.json()["id"], "graph.batch-49");
        assert_eq!(first_event.json()["count"], BATCH_LIMIT);
        assert_eq!(second_event.json()["id"], "graph.batch-later");
        assert_eq!(second_event.json()["count"], 1);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GraphPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(stored.since, "2026-10-08T09:00:01Z");
        assert_eq!(stored.ids, vec!["batch-later".to_owned()]);
        assert_eq!(stored.resume, None);
        assert_eq!(hook.last_sequence, 2);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn catch_up_continues_when_tie_pages_exhaust_the_budget() {
        let mut setup = provider_setup(Provider::Graph).await;
        let since = "2026-10-08T09:00:00Z";
        let ids: Vec<String> = (0..MAX_CATCH_UP_PAGES)
            .map(|n| format!("tied-{n}"))
            .collect();
        let position = GraphPosition {
            since: since.to_owned(),
            ids: ids.clone(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message(&ids[0], since)],
                "@odata.nextLink": next_link(&setup.server, "page-2"),
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        for (n, id) in ids.iter().enumerate().skip(1) {
            let token = format!("page-{}", n + 1);
            let following = format!("page-{}", n + 2);
            Mock::given(method("GET"))
                .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
                .and(query_param("$skiptoken", token.as_str()))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "value": [tied_message(id, since)],
                    "@odata.nextLink": next_link(&setup.server, &following),
                })))
                .expect(1)
                .mount(&setup.server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param("$skiptoken", "page-11"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("fresh-1", "2026-10-08T09:00:01Z")]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GraphPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(got.json()["id"], "graph.fresh-1");
        assert_eq!(got.json()["count"], 1);
        assert_eq!(stored.since, "2026-10-08T09:00:01Z");
        assert_eq!(stored.ids, vec!["fresh-1".to_owned()]);
        assert_eq!(stored.resume, None);
        assert_eq!(hook.last_sequence, 1);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn catch_up_does_not_follow_a_stored_resume_link_on_another_host() {
        let mut setup = provider_setup(Provider::Graph).await;
        let position = GraphPosition {
            since: "2026-10-08T08:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: Some("https://evil.example/graph/v1.0/me/messages?$skiptoken=x".to_owned()),
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("kept", "2026-10-08T09:00:00Z")]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GraphPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(got.json()["id"], "graph.kept");
        assert_eq!(stored.resume, None);
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 1);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn catch_up_lists_from_the_stored_time_when_a_resume_link_is_rejected() {
        let mut setup = provider_setup(Provider::Graph).await;
        let position = GraphPosition {
            since: "2026-10-08T08:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: Some(next_link(&setup.server, "stale")),
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param("$skiptoken", "stale"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("after-stale", "2026-10-08T09:00:00Z")]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GraphPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(got.json()["id"], "graph.after-stale");
        assert_eq!(stored.resume, None);
        harness::finish(&setup).await;
    }

    /// A position stored without an event goes only over the one the run
    /// holds, and the run then holds it. Over one another watcher stored after
    /// the run read it, the write is refused and that one stays.
    #[tokio::test]
    async fn a_position_is_saved_only_over_the_one_the_run_holds() {
        let setup = provider_setup(Provider::Graph).await;
        let read = GraphPosition {
            since: "2026-10-08T08:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: Some(next_link(&setup.server, "old")),
        };
        setup
            .store
            .set_watch_position(&setup.account, &read.encode())
            .await
            .unwrap();
        let mut stored = Some(read.encode());
        let dropped = GraphPosition {
            resume: None,
            ..read.clone()
        };
        let save = setup
            .watchers
            .save_position(&setup.account, &dropped, &mut stored);
        save.await.unwrap();
        assert_eq!(stored, Some(dropped.encode()));
        assert_eq!(stored_position(&setup).await, dropped);

        let moved = GraphPosition {
            since: "2026-10-08T09:05:00Z".to_owned(),
            ids: vec!["raced".to_owned()],
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &moved.encode())
            .await
            .unwrap();
        let save = setup
            .watchers
            .save_position(&setup.account, &read, &mut stored);
        let refused = save.await;
        assert!(
            matches!(refused, Err(WatchError::CursorMoved)),
            "{refused:?}"
        );
        assert_eq!(
            stored,
            Some(dropped.encode()),
            "the run holds its own write"
        );
        assert_eq!(stored_position(&setup).await, moved);
        harness::finish(&setup).await;
    }

    /// Dropping a resume link on another host, and storing a next link the run
    /// cannot follow, go only over the position the run read. Over one another
    /// watcher stored meanwhile, both are refused and that one stays.
    #[tokio::test]
    async fn resume_link_writes_over_a_moved_position_are_refused() {
        let setup = provider_setup(Provider::Graph).await;
        let moved = GraphPosition {
            since: "2026-10-08T09:05:00Z".to_owned(),
            ids: vec!["raced".to_owned()],
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &moved.encode())
            .await
            .unwrap();
        let mut position = GraphPosition {
            since: "2026-10-08T08:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: Some(OFF_HOST.to_owned()),
        };
        let read = Some(position.encode());
        let api = setup.watchers.graph_api(&setup.account).unwrap();
        let base = api.endpoints().graph.clone();
        let filter_url = inbox_messages_url(&api, &position.since);

        let mut stored = read.clone();
        let opened = setup
            .watchers
            .opening_page(
                &setup.account,
                &mut position,
                &base,
                &filter_url,
                &mut stored,
            )
            .await;
        assert!(matches!(opened, Err(WatchError::CursorMoved)), "{opened:?}");
        assert_eq!(stored, read);
        assert_eq!(stored_position(&setup).await, moved);

        let link = next_link(&setup.server, "later");
        let persisted = setup
            .watchers
            .persist_resume(&setup.account, &mut position, Some(link), &mut stored)
            .await;
        assert!(
            matches!(persisted, Err(WatchError::CursorMoved)),
            "{persisted:?}"
        );
        assert_eq!(stored, read);
        assert_eq!(stored_position(&setup).await, moved);
        harness::finish(&setup).await;
    }

    /// A catch-up whose stored resume link Graph answers with `answer`, slowly,
    /// while another watcher moves the position on. Dropping the link does not
    /// move that position back: the run ends, and the next one lists from the
    /// moved position.
    async fn drop_a_resume_link_while_another_watcher_moves_on(answer: ResponseTemplate) {
        let setup = provider_setup(Provider::Graph).await;
        let start = GraphPosition {
            since: "2026-10-08T08:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: Some(next_link(&setup.server, "resume")),
        };
        setup
            .store
            .set_watch_position(&setup.account, &start.encode())
            .await
            .unwrap();
        let (mut hold, responder) = Hold::new(answer);
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param("$skiptoken", "resume"))
            .respond_with(responder)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param(
                "$filter",
                "receivedDateTime ge 2026-10-08T09:05:00Z",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .expect(1)
            .mount(&setup.server)
            .await;
        let moved = GraphPosition {
            since: "2026-10-08T09:05:00Z".to_owned(),
            ids: vec!["raced".to_owned()],
            resume: None,
        };
        let mut run = pin!(setup.watchers.graph_catch_up(&setup.account));
        hold.arrived_before(&mut run).await;
        setup
            .store
            .set_watch_position(&setup.account, &moved.encode())
            .await
            .unwrap();
        hold.release();
        run.await.unwrap();
        assert_eq!(stored_position(&setup).await, moved);

        harness::wait_for_requests(&setup.server, "GET", INBOX, 2).await;
        wait_until_catch_up_idle(&setup).await;
        assert_eq!(stored_position(&setup).await, moved);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0);
        harness::finish(&setup).await;
    }

    /// Graph rejects the stored resume link (the fallback in `fetch_inbox_page`),
    /// or answers it with an empty last page (the end of `handle_inbox_page`).
    #[tokio::test]
    async fn dropping_a_resume_link_does_not_move_a_moved_position_back() {
        drop_a_resume_link_while_another_watcher_moves_on(ResponseTemplate::new(404)).await;
        let empty = ResponseTemplate::new(200).set_body_json(json!({ "value": [] }));
        drop_a_resume_link_while_another_watcher_moves_on(empty).await;
    }

    #[tokio::test]
    async fn a_running_catch_up_keeps_one_pending_rerun_including_missed_events() {
        let setup = provider_setup(Provider::Graph).await;
        let position = GraphPosition {
            since: "2026-10-08T09:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "value": [] }))
                    .set_delay(Duration::from_millis(400)),
            )
            .mount(&setup.server)
            .await;

        setup.watchers.schedule_graph_catch_up(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", INBOX, 1).await;
        for _ in 0..30 {
            setup.watchers.schedule_graph_catch_up(&setup.account);
            setup.watchers.schedule_graph_lifecycle(
                &setup.account,
                "sub-1".to_owned(),
                "missed".to_owned(),
            );
        }
        harness::wait_for_requests(&setup.server, "GET", INBOX, 2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            harness::requests(&setup.server, "GET", INBOX).await,
            2,
            "a burst during a running catch-up schedules one rerun, not one task each"
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn failed_reauthorization_recreates_the_subscription_and_catches_up() {
        let mut setup = provider_setup(Provider::Graph).await;
        let old_state = "previous-client-state";
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &PushSubscription {
                    provider: Provider::Graph,
                    subscription_id: Some("sub-old".to_owned()),
                    client_state_hash: Some(PushSubscription::hash_client_state(old_state)),
                    // Far outside the renewal window. A restart that kept
                    // this row would not contact Graph.
                    expires_at: postkeep_store::now() + 7 * 24 * 3600,
                },
            )
            .await
            .unwrap();
        let position = GraphPosition {
            since: "2026-10-08T09:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();

        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions/sub-old/reauthorize"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-old"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": "sub-new" })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("msg-1", "2026-10-08T09:00:01Z")]
            })))
            .mount(&setup.server)
            .await;

        setup
            .watchers
            .graph_lifecycle(&setup.account, "sub-old", "reauthorizationRequired")
            .await;

        let created = request_body(&setup.server, "POST", "/graph/v1.0/subscriptions").await;
        let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
        let client_state = created["clientState"].as_str().unwrap();
        assert_ne!(client_state, old_state);

        let stored = harness::wait_for_subscription(&setup, Some("sub-new"))
            .await
            .unwrap();
        assert!(stored.client_state_matches(client_state));
        assert!(!stored.client_state_matches(old_state));
        assert!(stored.expires_at > postkeep_store::now() + 24 * 3600);

        let event = harness::next_event(&mut setup.receiver).await;
        assert_eq!(event.json()["id"], "graph.msg-1");
        assert_eq!(event.json()["count"], 1);
        harness::finish(&setup).await;
    }

    async fn request_body(server: &MockServer, method_name: &str, exact_path: &str) -> Vec<u8> {
        harness::wait_for_requests(server, method_name, exact_path, 1).await;
        let requests = server.received_requests().await.unwrap_or_default();
        let request = requests.iter().find(|request| {
            request.method.as_str() == method_name && request.url.path() == exact_path
        });
        request.unwrap().body.clone()
    }

    #[tokio::test]
    async fn a_disallowed_account_does_not_subscribe_or_renew() {
        let setup = harness::provider_setup_with(
            Provider::Graph,
            Some(vec!["other@example.com".to_owned()]),
        )
        .await;
        let subscription = PushSubscription {
            provider: Provider::Graph,
            subscription_id: Some("sub-kept".to_owned()),
            client_state_hash: Some(PushSubscription::hash_client_state("state")),
            expires_at: postkeep_store::now() + 7 * 24 * 3600,
        };
        setup
            .store
            .save_push_subscription(&setup.account, &subscription)
            .await
            .unwrap();

        setup.watchers.refresh(&setup.account);
        harness::until(async || setup.watchers.running() == 0).await;
        assert!(
            setup.server.received_requests().await.unwrap().is_empty(),
            "a disallowed account must not subscribe, renew, or refresh a token"
        );
        assert_eq!(
            setup
                .store
                .push_subscription(&setup.account)
                .await
                .unwrap()
                .as_ref(),
            Some(&subscription)
        );
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.position, None);
        assert_eq!(hook.last_sequence, 0);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn unsubscribe_keeps_a_replacement_subscription_record() {
        let setup = provider_setup(Provider::Graph).await;
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &PushSubscription {
                    provider: Provider::Graph,
                    subscription_id: Some("sub-old".to_owned()),
                    client_state_hash: Some(PushSubscription::hash_client_state("old-state")),
                    expires_at: postkeep_store::now() + 3600,
                },
            )
            .await
            .unwrap();
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-old"))
            .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(500)))
            .expect(1)
            .mount(&setup.server)
            .await;

        let api = setup.watchers.graph_api(&setup.account).unwrap();
        let watchers = setup.watchers.clone();
        let unsubscribe = tokio::spawn(async move {
            watchers.graph_unsubscribe(&api).await;
        });
        let old = "/graph/v1.0/subscriptions/sub-old";
        harness::wait_for_requests(&setup.server, "DELETE", old, 1).await;

        let replacement = PushSubscription {
            provider: Provider::Graph,
            subscription_id: Some("sub-new".to_owned()),
            client_state_hash: Some(PushSubscription::hash_client_state("new-state")),
            expires_at: postkeep_store::now() + 7200,
        };
        setup
            .store
            .save_push_subscription(&setup.account, &replacement)
            .await
            .unwrap();
        unsubscribe.await.unwrap();

        let stored = setup
            .store
            .push_subscription(&setup.account)
            .await
            .unwrap()
            .expect("the replacement subscription was deleted");
        assert_eq!(stored.subscription_id.as_deref(), Some("sub-new"));
        assert!(stored.client_state_matches("new-state"));
        harness::finish(&setup).await;
    }

    fn graph_subscription(id: &str, client_state: &str, expires_at: i64) -> PushSubscription {
        PushSubscription {
            provider: Provider::Graph,
            subscription_id: Some(id.to_owned()),
            client_state_hash: Some(PushSubscription::hash_client_state(client_state)),
            expires_at,
        }
    }

    async fn disable_webhook(setup: &harness::ProviderSetup) {
        let mut settings = setup
            .store
            .webhook(&setup.account)
            .await
            .unwrap()
            .unwrap()
            .settings;
        settings.enabled = false;
        setup
            .store
            .save_webhook(&setup.account, &settings)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stale_subscription_removed_keeps_the_replacement() {
        let setup = provider_setup(Provider::Graph).await;
        let replacement = graph_subscription(
            "sub-new",
            "new-state",
            postkeep_store::now() + 7 * 24 * 3600,
        );
        setup
            .store
            .save_push_subscription(&setup.account, &replacement)
            .await
            .unwrap();

        setup
            .watchers
            .graph_lifecycle(&setup.account, "sub-old", "subscriptionRemoved")
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let stored = setup
            .store
            .push_subscription(&setup.account)
            .await
            .unwrap()
            .expect("the replacement subscription was deleted");
        assert_eq!(stored, replacement);
        assert_eq!(
            setup.watchers.running(),
            0,
            "a stale removal must not restart the watcher"
        );
        assert!(
            setup.server.received_requests().await.unwrap().is_empty(),
            "a stale removal must not call Graph"
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn subscription_removed_forgets_the_named_subscription() {
        let setup = provider_setup(Provider::Graph).await;
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &graph_subscription("sub-current", "state", postkeep_store::now() + 3600),
            )
            .await
            .unwrap();
        // A disabled webhook makes the restarted watcher exit without
        // creating a replacement, so the assertion is about this delete.
        disable_webhook(&setup).await;

        setup
            .watchers
            .graph_lifecycle(&setup.account, "sub-current", "subscriptionRemoved")
            .await;
        harness::wait_for_subscription(&setup, None).await;
        harness::until(async || setup.watchers.running() == 0).await;
        assert!(
            setup.server.received_requests().await.unwrap().is_empty(),
            "the row was already gone, so the restarted watcher must not call Graph"
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn stale_reauthorization_does_not_touch_the_replacement() {
        let setup = provider_setup(Provider::Graph).await;
        let replacement = graph_subscription(
            "sub-new",
            "new-state",
            postkeep_store::now() + 7 * 24 * 3600,
        );
        setup
            .store
            .save_push_subscription(&setup.account, &replacement)
            .await
            .unwrap();

        setup
            .watchers
            .graph_lifecycle(&setup.account, "sub-old", "reauthorizationRequired")
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;

        let stored = setup
            .store
            .push_subscription(&setup.account)
            .await
            .unwrap()
            .expect("the replacement subscription was deleted");
        assert_eq!(stored, replacement);
        assert_eq!(setup.watchers.running(), 0);
        assert!(
            setup.server.received_requests().await.unwrap().is_empty(),
            "a stale reauthorization must not call Graph"
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn failed_reauthorization_leaves_a_replacement_stored_while_it_runs() {
        let setup = provider_setup(Provider::Graph).await;
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &graph_subscription("sub-old", "old-state", postkeep_store::now() + 3600),
            )
            .await
            .unwrap();
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions/sub-old/reauthorize"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-old"))
            .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(500)))
            .expect(1)
            .mount(&setup.server)
            .await;

        let watchers = setup.watchers.clone();
        let account = setup.account.clone();
        let lifecycle = tokio::spawn(async move {
            watchers
                .graph_lifecycle(&account, "sub-old", "reauthorizationRequired")
                .await;
        });
        let old = "/graph/v1.0/subscriptions/sub-old";
        harness::wait_for_requests(&setup.server, "DELETE", old, 1).await;

        let replacement = graph_subscription(
            "sub-new",
            "new-state",
            postkeep_store::now() + 7 * 24 * 3600,
        );
        setup
            .store
            .save_push_subscription(&setup.account, &replacement)
            .await
            .unwrap();
        lifecycle.await.unwrap();

        let stored = setup
            .store
            .push_subscription(&setup.account)
            .await
            .unwrap()
            .expect("the replacement subscription was deleted");
        assert_eq!(stored.subscription_id.as_deref(), Some("sub-new"));
        assert!(stored.client_state_matches("new-state"));
        assert_eq!(setup.watchers.running(), 0);
        let deletes: Vec<_> = setup
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.method.as_str() == "DELETE")
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(
            deletes,
            vec!["/graph/v1.0/subscriptions/sub-old".to_owned()]
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn unsubscribe_keeps_the_local_record_when_graph_delete_fails() {
        let setup = provider_setup(Provider::Graph).await;
        let subscription = graph_subscription("sub-kept", "state", postkeep_store::now() + 3600);
        setup
            .store
            .save_push_subscription(&setup.account, &subscription)
            .await
            .unwrap();
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-kept"))
            .respond_with(ResponseTemplate::new(500).set_body_json(json!({
                "error": { "code": "ServiceUnavailable", "message": "try again" }
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        let api = setup.watchers.graph_api(&setup.account).unwrap();
        setup.watchers.graph_unsubscribe(&api).await;

        let stored = setup
            .store
            .push_subscription(&setup.account)
            .await
            .unwrap()
            .expect("a failed delete forgot the local subscription");
        assert_eq!(stored, subscription);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn unsubscribe_forgets_the_local_record_when_graph_delete_succeeds() {
        for status in [204, 404] {
            let setup = provider_setup(Provider::Graph).await;
            setup
                .store
                .save_push_subscription(
                    &setup.account,
                    &graph_subscription("sub-gone", "state", postkeep_store::now() + 3600),
                )
                .await
                .unwrap();
            Mock::given(method("DELETE"))
                .and(path("/graph/v1.0/subscriptions/sub-gone"))
                .respond_with(ResponseTemplate::new(status))
                .expect(1)
                .mount(&setup.server)
                .await;

            let api = setup.watchers.graph_api(&setup.account).unwrap();
            setup.watchers.graph_unsubscribe(&api).await;

            assert!(
                setup
                    .store
                    .push_subscription(&setup.account)
                    .await
                    .unwrap()
                    .is_none(),
                "status {status} should forget the local subscription"
            );
            harness::finish(&setup).await;
        }
    }

    /// A 409, then a list whose second page holds the Inbox orphan, then a create.
    async fn mount_conflict_then_create(server: &MockServer, notification_url: &str) {
        let next = format!("{}/graph/v1.0/subscriptions?$skiptoken=more", server.uri());
        let conflict = json!({
            "error": { "code": "Conflict", "message": "Subscription already exists" }
        });
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(409).set_body_json(conflict))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": "sub-new" })))
            .with_priority(2)
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/subscriptions"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    { "id": "cal-1", "resource": "me/events", "notificationUrl": notification_url },
                    {
                        "id": "other-host",
                        "resource": "me/mailFolders('inbox')/messages",
                        "notificationUrl": "https://other.example/push/microsoft"
                    }
                ],
                "@odata.nextLink": next
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/subscriptions"))
            .and(query_param("$skiptoken", "more"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    {
                        "id": "sub-orphan",
                        "resource": "Me/MailFolders('Inbox')/Messages",
                        "notificationUrl": notification_url
                    },
                    {
                        "id": "lifecycle-only",
                        "resource": "me/mailFolders('inbox')/messages",
                        "notificationUrl": "https://mail.example.com/push/microsoft/lifecycle"
                    }
                ]
            })))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-orphan"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn subscribe_reconciles_a_conflicting_subscription_and_retries_once() {
        let setup = provider_setup(Provider::Graph).await;
        let notification_url = "https://mail.example.com/push/microsoft";
        mount_conflict_then_create(&setup.server, notification_url).await;

        let api = setup.watchers.graph_api(&setup.account).unwrap();
        let expires_at = setup.watchers.graph_subscribe(&api).await.unwrap();
        let stored = setup
            .store
            .push_subscription(&setup.account)
            .await
            .unwrap()
            .expect("the new subscription was not stored");
        assert_eq!(stored.subscription_id.as_deref(), Some("sub-new"));
        assert_eq!(stored.expires_at, expires_at);

        let requests = setup.server.received_requests().await.unwrap();
        let posts: Vec<_> = requests
            .iter()
            .filter(|request| {
                request.method.as_str() == "POST"
                    && request.url.path() == "/graph/v1.0/subscriptions"
            })
            .collect();
        assert_eq!(posts.len(), 2, "the create is retried once");
        let first: serde_json::Value = serde_json::from_slice(&posts[0].body).unwrap();
        let second: serde_json::Value = serde_json::from_slice(&posts[1].body).unwrap();
        assert_eq!(first["clientState"], second["clientState"]);
        assert_eq!(first["notificationUrl"], notification_url);
        assert_eq!(first["resource"], RESOURCE);
        assert!(stored.client_state_matches(second["clientState"].as_str().unwrap()));
        let deletes: Vec<_> = requests
            .iter()
            .filter(|request| request.method.as_str() == "DELETE")
            .map(|request| request.url.path().to_owned())
            .collect();
        assert_eq!(
            deletes,
            vec!["/graph/v1.0/subscriptions/sub-orphan".to_owned()]
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn subscribe_returns_the_conflict_when_the_retry_still_conflicts() {
        let setup = provider_setup(Provider::Graph).await;
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": { "code": "Conflict", "message": "Subscription already exists" }
            })))
            .expect(2)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .expect(1)
            .mount(&setup.server)
            .await;

        let api = setup.watchers.graph_api(&setup.account).unwrap();
        let err = setup.watchers.graph_subscribe(&api).await.unwrap_err();
        assert!(
            matches!(
                err,
                WatchError::Api(ref api) if api.status() == Some(StatusCode::CONFLICT)
            ),
            "{err}"
        );
        assert!(
            setup
                .store
                .push_subscription(&setup.account)
                .await
                .unwrap()
                .is_none()
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn failed_reauthorization_recreates_when_the_remote_delete_fails() {
        let setup = provider_setup(Provider::Graph).await;
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &graph_subscription(
                    "sub-old",
                    "old-state",
                    postkeep_store::now() + 7 * 24 * 3600,
                ),
            )
            .await
            .unwrap();
        store_position(&setup).await;
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions/sub-old/reauthorize"))
            .respond_with(ResponseTemplate::new(503))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-old"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-old"))
            .respond_with(ResponseTemplate::new(204))
            .with_priority(2)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [{
                    "id": "sub-old",
                    "resource": "me/mailFolders('inbox')/messages",
                    "notificationUrl": "https://mail.example.com/push/microsoft"
                }]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(409).set_body_json(json!({
                "error": { "code": "Conflict", "message": "Subscription already exists" }
            })))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(path("/graph/v1.0/subscriptions"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "id": "sub-new" })))
            .with_priority(2)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .mount(&setup.server)
            .await;

        setup
            .watchers
            .graph_lifecycle(&setup.account, "sub-old", "reauthorizationRequired")
            .await;
        let stored = harness::wait_for_subscription(&setup, Some("sub-new"))
            .await
            .unwrap();
        assert!(stored.expires_at > postkeep_store::now() + 24 * 3600);
        tokio::time::sleep(Duration::from_millis(300)).await;
        let posts = setup
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| {
                request.method.as_str() == "POST"
                    && request.url.path() == "/graph/v1.0/subscriptions"
            })
            .count();
        assert_eq!(
            posts, 2,
            "a failed delete is reconciled once, not retried in a loop"
        );
        harness::finish(&setup).await;
    }

    async fn store_position(setup: &harness::ProviderSetup) {
        let position = GraphPosition {
            since: "2026-10-08T09:00:00Z".to_owned(),
            ids: Vec::new(),
            resume: None,
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
    }

    async fn mount_unavailable_then_message(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("after-503", "2026-10-08T09:00:01Z")]
            })))
            .with_priority(2)
            .mount(server)
            .await;
    }

    fn slow_catch_up() -> WatchConfig {
        WatchConfig {
            debounce: Duration::from_millis(20),
            min_backoff: Duration::from_secs(60),
            max_backoff: Duration::from_secs(60),
            ..WatchConfig::default()
        }
    }

    async fn wait_until_catch_up_idle(setup: &harness::ProviderSetup) {
        harness::until(async || !setup.watchers.catch_up_running(&setup.account)).await;
    }

    /// A session starts from the stored position, untouched: its first listing
    /// asks for the mail after that position's time, not after now.
    #[tokio::test]
    async fn a_session_starts_from_the_stored_position() {
        let setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        // Far from its renewal, so the session neither creates nor renews.
        let expires_at = postkeep_store::now() + 3 * 24 * 3600;
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &graph_subscription("sub-live", "state", expires_at),
            )
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param(
                "$filter",
                "receivedDateTime ge 2026-10-08T09:00:00Z",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", INBOX, 1).await;
        let stored = stored_position(&setup).await;
        assert_eq!(stored.since, "2026-10-08T09:00:00Z");
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_failed_catch_up_retries_without_another_push() {
        let mut setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        mount_unavailable_then_message(&setup.server).await;

        setup.watchers.schedule_graph_catch_up(&setup.account);
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "graph.after-503");
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            harness::requests(&setup.server, "GET", INBOX).await,
            2,
            "one 503 and one successful read, with no second push"
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn shutdown_during_catch_up_backoff_ends_the_task() {
        let setup = harness::provider_setup_config(Provider::Graph, slow_catch_up()).await;
        store_position(&setup).await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&setup.server)
            .await;

        setup.watchers.schedule_graph_catch_up(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", INBOX, 1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let started = Instant::now();
        setup.watchers.shutdown(Duration::from_secs(5)).await;
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "shutdown waited {:?} for the backoff",
            started.elapsed()
        );
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 1);
        assert!(!setup.watchers.catch_up_running(&setup.account));
    }

    #[tokio::test]
    async fn a_push_during_backoff_runs_without_waiting_it_out() {
        let mut setup = harness::provider_setup_config(Provider::Graph, slow_catch_up()).await;
        store_position(&setup).await;
        mount_unavailable_then_message(&setup.server).await;

        setup.watchers.schedule_graph_catch_up(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", INBOX, 1).await;
        let started = Instant::now();
        setup.watchers.schedule_graph_catch_up(&setup.account);
        let got = harness::next_event(&mut setup.receiver).await;
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the queued push waited {:?}",
            started.elapsed()
        );
        assert_eq!(got.json()["id"], "graph.after-503");
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 2);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_catch_up_stops_when_the_sign_in_is_no_longer_valid() {
        let setup = harness::provider_setup_config(Provider::Graph, slow_catch_up()).await;
        store_position(&setup).await;
        setup
            .store
            .mark_upstream_tokens_invalid(&setup.account, "invalid_grant")
            .await
            .unwrap();

        setup.watchers.schedule_graph_catch_up(&setup.account);
        wait_until_catch_up_idle(&setup).await;
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 0);
        assert!(!setup.watchers.catch_up_running(&setup.account));
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_disabled_webhook_stops_a_failed_catch_up() {
        let setup = harness::provider_setup_config(Provider::Graph, slow_catch_up()).await;
        store_position(&setup).await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(400)))
            .mount(&setup.server)
            .await;

        setup.watchers.schedule_graph_catch_up(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", INBOX, 1).await;
        let mut settings = setup
            .store
            .webhook(&setup.account)
            .await
            .unwrap()
            .unwrap()
            .settings;
        settings.enabled = false;
        setup
            .store
            .save_webhook(&setup.account, &settings)
            .await
            .unwrap();
        wait_until_catch_up_idle(&setup).await;
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 1);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_removed_account_stops_a_failed_catch_up() {
        let setup = harness::provider_setup_config(Provider::Graph, slow_catch_up()).await;
        store_position(&setup).await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(400)))
            .mount(&setup.server)
            .await;

        setup.watchers.schedule_graph_catch_up(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", INBOX, 1).await;
        assert!(setup.store.delete_account(&setup.account).await.unwrap());
        wait_until_catch_up_idle(&setup).await;
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 1);
        harness::finish(&setup).await;
    }

    /// A renewal that Graph answers after the account's deletion committed
    /// ends the watcher's run as an account that is gone does, and is not
    /// counted as a failure. A save that fails for another reason still is
    /// one, and is counted.
    #[tokio::test]
    async fn a_renewal_behind_the_accounts_deletion_ends_the_run() {
        let setup = provider_setup(Provider::Graph).await;
        let metrics = crate::metrics::Metrics::default();
        setup.watchers.set_metrics(metrics.clone());
        let counted = "postkeep_watcher_errors_total{provider=\"graph\"} 1";
        store_position(&setup).await;
        // Inside the renewal window, so each run renews.
        let stored = graph_subscription("sub-late", "state", postkeep_store::now() + 3600);
        setup
            .store
            .save_push_subscription(&setup.account, &stored)
            .await
            .unwrap();
        let renewal = "/graph/v1.0/subscriptions/sub-late";
        let (mut hold, responder) = Hold::new(ResponseTemplate::new(200));
        Mock::given(method("PATCH"))
            .and(path(renewal))
            .respond_with(responder)
            .mount(&setup.server)
            .await;
        let run = || {
            let (watchers, account) = (setup.watchers.clone(), setup.account.clone());
            tokio::spawn(async move {
                let (mut failures, mut rejections) = (0, 0);
                let cancel = CancellationToken::new();
                watchers
                    .run_once(&account, &cancel, &mut failures, &mut rejections)
                    .await
            })
        };

        let refuse = "CREATE TRIGGER refuse BEFORE UPDATE ON push_subscriptions \
                      BEGIN SELECT RAISE(ABORT, 'refused'); END";
        sqlx::query(refuse)
            .execute(setup.store.pool())
            .await
            .unwrap();
        // The first run's renewal is answered at once.
        hold.release();
        let failed = run().await.unwrap();
        assert!(
            matches!(failed, Err(WatchError::Store(StoreError::Database(_)))),
            "{:?}",
            failed.err()
        );
        let rendered = metrics.render();
        assert!(rendered.lines().any(|line| line == counted), "{rendered}");
        sqlx::query("DROP TRIGGER refuse")
            .execute(setup.store.pool())
            .await
            .unwrap();

        let mut ended = run();
        hold.arrived_before(&mut ended).await;
        assert!(setup.store.delete_account(&setup.account).await.unwrap());
        hold.release();
        let ended = ended.await.unwrap();
        assert!(matches!(ended, Ok(Exit::Disabled)), "{:?}", ended.err());
        let rendered = metrics.render();
        assert!(rendered.lines().any(|line| line == counted), "{rendered}");
        let kept = setup.store.push_subscription(&setup.account).await.unwrap();
        assert_eq!(kept, None);
        harness::finish(&setup).await;
    }

    /// A renewal whose token refresh Microsoft answers after the account's
    /// deletion committed finds the tokens gone. The watcher's run ends as
    /// an account that is gone does, and is not counted as a failure. A run
    /// that fails and can't look for the account keeps its error, and is
    /// counted.
    #[tokio::test]
    async fn a_token_refresh_behind_the_accounts_deletion_ends_the_run() {
        let setup = provider_setup(Provider::Graph).await;
        let metrics = crate::metrics::Metrics::default();
        setup.watchers.set_metrics(metrics.clone());
        let counted = "postkeep_watcher_errors_total{provider=\"graph\"} 1";
        store_position(&setup).await;
        // Inside the renewal window, so each run renews, and with an access
        // token that has expired, so each renewal refreshes it first.
        let stored = graph_subscription("sub-refresh", "state", postkeep_store::now() + 3600);
        setup
            .store
            .save_push_subscription(&setup.account, &stored)
            .await
            .unwrap();
        run_sql(&setup, "UPDATE upstream_tokens SET access_expires_at = 0").await;
        let token = "/microsoft/common/oauth2/v2.0/token";
        let refreshed = json!({ "access_token": "access-2", "expires_in": 3600 });
        let (mut hold, responder) = Hold::new(ResponseTemplate::new(200).set_body_json(refreshed));
        Mock::given(method("POST"))
            .and(path(token))
            .respond_with(responder)
            .mount(&setup.server)
            .await;
        let run = || {
            let (watchers, account) = (setup.watchers.clone(), setup.account.clone());
            tokio::spawn(async move {
                let (mut failures, mut rejections) = (0, 0);
                let cancel = CancellationToken::new();
                watchers
                    .run_once(&account, &cancel, &mut failures, &mut rejections)
                    .await
            })
        };

        // The refresh's save fails, and so does the look for the account.
        let mut failed = run();
        hold.arrived_before(&mut failed).await;
        run_sql(&setup, "ALTER TABLE accounts RENAME TO accounts_moved").await;
        hold.release();
        let failed = failed.await.unwrap();
        run_sql(&setup, "ALTER TABLE accounts_moved RENAME TO accounts").await;
        assert!(
            matches!(failed, Err(WatchError::Api(_))),
            "{:?}",
            failed.err()
        );
        let rendered = metrics.render();
        assert!(rendered.lines().any(|line| line == counted), "{rendered}");

        let mut ended = run();
        hold.arrived_before(&mut ended).await;
        assert!(setup.store.delete_account(&setup.account).await.unwrap());
        hold.release();
        let ended = ended.await.unwrap();
        assert!(matches!(ended, Ok(Exit::Disabled)), "{:?}", ended.err());
        let rendered = metrics.render();
        assert!(rendered.lines().any(|line| line == counted), "{rendered}");
        harness::finish(&setup).await;
    }

    async fn run_sql(setup: &harness::ProviderSetup, statement: &'static str) {
        sqlx::query(statement)
            .execute(setup.store.pool())
            .await
            .unwrap();
    }

    /// A paused webhook renews its Graph subscription, holds its slot, and
    /// records a push. The new mail is not delivered before the pause
    /// interval, and the pause does not call Graph again.
    #[tokio::test]
    async fn a_paused_graph_webhook_keeps_renewing_and_records_without_delivering() {
        let mut setup = provider_setup(Provider::Graph).await;
        harness::pause_webhook(&setup).await;
        store_position(&setup).await;
        // Inside the renewal window, so the running session must PATCH
        // even though delivery is paused.
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &graph_subscription("sub-paused", "state", postkeep_store::now() + 3600),
            )
            .await
            .unwrap();
        Mock::given(method("PATCH"))
            .and(path("/graph/v1.0/subscriptions/sub-paused"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("paused-1", "2026-10-08T09:00:01Z")]
            })))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("paused-2", "2026-10-08T09:00:02Z")]
            })))
            .with_priority(2)
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        harness::wait_for_sequence(&setup, 1).await;
        assert_eq!(
            setup.watchers.running(),
            1,
            "a paused webhook keeps its watcher slot"
        );
        let renewed = setup
            .store
            .push_subscription(&setup.account)
            .await
            .unwrap()
            .expect("the Graph subscription is still stored");
        assert_eq!(renewed.subscription_id.as_deref(), Some("sub-paused"));
        assert!(
            renewed.expires_at > postkeep_store::now() + 24 * 3600,
            "a paused webhook still renews the subscription"
        );
        assert_eq!(
            harness::requests(
                &setup.server,
                "PATCH",
                "/graph/v1.0/subscriptions/sub-paused"
            )
            .await,
            1
        );
        assert_eq!(
            harness::requests(
                &setup.server,
                "DELETE",
                "/graph/v1.0/subscriptions/sub-paused"
            )
            .await,
            0
        );

        // A push while paused records the next message and does not deliver.
        setup.watchers.schedule_graph_catch_up(&setup.account);
        harness::wait_for_sequence(&setup, 2).await;
        let early =
            tokio::time::timeout(Duration::from_millis(300), setup.receiver.requests.recv()).await;
        assert!(
            early.is_err(),
            "paused mail was delivered before the pause interval: {early:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            harness::requests(
                &setup.server,
                "PATCH",
                "/graph/v1.0/subscriptions/sub-paused"
            )
            .await,
            1,
            "a pause must not renew the subscription in a loop"
        );
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 2);
        assert_eq!(setup.watchers.running(), 1);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert!(hook.is_paused());
        assert!(hook.settings.enabled);
        assert_eq!(hook.last_sequence, 2);
        assert_eq!(hook.delivered_sequence, 0);
        harness::finish(&setup).await;
    }

    /// The user turning a paused webhook off, through the store call the
    /// MCP tool uses and the same notification as the account page,
    /// unsubscribes at Graph and frees the slot.
    #[tokio::test]
    async fn disabling_a_graph_webhook_unsubscribes_and_frees_the_slot() {
        let setup = provider_setup(Provider::Graph).await;
        harness::pause_webhook(&setup).await;
        store_position(&setup).await;
        // Outside the renewal window, so the running session keeps the
        // subscription without a PATCH. Disable must still delete it.
        let expires_at = postkeep_store::now() + 8 * 24 * 3600;
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &graph_subscription("sub-live", "state", expires_at),
            )
            .await
            .unwrap();
        Mock::given(method("GET"))
            .and(path("/graph/v1.0/me/mailFolders/inbox/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .mount(&setup.server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/graph/v1.0/subscriptions/sub-live"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", INBOX, 1).await;
        harness::until(async || setup.watchers.running() == 1).await;
        assert_eq!(
            harness::requests(&setup.server, "PATCH", "/graph/v1.0/subscriptions/sub-live").await,
            0,
            "a subscription outside the renewal window is not patched just because it is paused"
        );

        harness::disable_webhook_like_mcp(&setup).await;
        harness::wait_for_subscription(&setup, None).await;
        harness::until(async || setup.watchers.running() == 0).await;
        assert_eq!(
            harness::requests(
                &setup.server,
                "DELETE",
                "/graph/v1.0/subscriptions/sub-live"
            )
            .await,
            1
        );
        assert_eq!(
            harness::requests(&setup.server, "POST", "/graph/v1.0/subscriptions").await,
            0
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(setup.watchers.running(), 0);
        assert_eq!(
            harness::requests(
                &setup.server,
                "DELETE",
                "/graph/v1.0/subscriptions/sub-live"
            )
            .await,
            1,
            "a disabled webhook must not keep calling Graph"
        );
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 1);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert!(!hook.settings.enabled);
        assert!(hook.paused_at.is_none());
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn the_inbox_is_listed_on_a_timer_when_no_notification_comes() {
        let mut setup = harness::provider_setup_config(
            Provider::Graph,
            WatchConfig {
                debounce: Duration::from_millis(20),
                min_backoff: Duration::from_millis(20),
                graph_catch_up_interval: Duration::from_millis(100),
                ..WatchConfig::default()
            },
        )
        .await;
        store_position(&setup).await;
        // Far from its renewal, so the session neither creates nor renews.
        let expires_at = postkeep_store::now() + 3 * 24 * 3600;
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &graph_subscription("sub-live", "state", expires_at),
            )
            .await
            .unwrap();
        let inbox = "/graph/v1.0/me/mailFolders/inbox/messages";
        Mock::given(method("GET"))
            .and(path(inbox))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(inbox))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [tied_message("unannounced", "2026-10-08T09:00:30Z")]
            })))
            .with_priority(2)
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "graph.unannounced");
        // Catch-ups take turns, so the third has finished once a fourth reads.
        harness::wait_for_requests(&setup.server, "GET", INBOX, 4).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(
            hook.last_sequence, 1,
            "later runs see the message as reported"
        );
        for (verb, at) in [
            ("POST", "/graph/v1.0/subscriptions"),
            ("PATCH", "/graph/v1.0/subscriptions/sub-live"),
        ] {
            assert_eq!(
                harness::requests(&setup.server, verb, at).await,
                0,
                "{verb}"
            );
        }
        harness::finish(&setup).await;
    }

    const INBOX: &str = "/graph/v1.0/me/mailFolders/inbox/messages";
    /// A resume link on another host, which a run drops instead of following.
    const OFF_HOST: &str = "https://evil.example/graph/v1.0/me/messages?$skiptoken=x";

    /// A message of an inbox page as Graph answers the watcher's `$select`:
    /// from `sender@example.com`, to `me@example.com`, and the given `cc`.
    fn judged_message(id: &str, received: &str, subject: &str, cc: &[&str]) -> serde_json::Value {
        let recipients = |addresses: &[&str]| -> Vec<_> {
            let one = |address: &&str| json!({ "emailAddress": { "address": address } });
            addresses.iter().map(one).collect()
        };
        json!({
            "id": id,
            "receivedDateTime": received,
            "subject": subject,
            "internetMessageId": format!("<{id}@example.com>"),
            "from": { "emailAddress": { "name": "Sender", "address": "sender@example.com" } },
            "toRecipients": recipients(&["me@example.com"]),
            "ccRecipients": recipients(cc),
        })
    }

    /// Graph gives the sender as one address. Allow rules judge it only when it reads as one
    /// address, as the address of a clear sender must.
    #[test]
    fn allow_rules_judge_the_sender_address_graph_gives() {
        let clear = |address: &str| {
            let mut message = judged_message("m1", "2026-10-08T09:00:01Z", "Hello", &[]);
            message["from"]["emailAddress"]["address"] = json!(address);
            let message: GraphNewMessage = serde_json::from_value(message).unwrap();
            message.fields().from_clear
        };
        assert!(clear("sender@example.com"));
        for address in [
            "boss@y.test@x.test",
            "a b@x.test",
            "@x.test",
            "\"news\"@y.test",
            "",
        ] {
            assert!(!clear(address), "{address:?}");
        }
        for c in "\"(),:;<>[\\]".chars() {
            let address = format!("a{c}b@x.test");
            assert!(!clear(&address), "{address:?}");
        }
    }

    async fn mount_inbox(server: &MockServer, messages: &[serde_json::Value]) {
        Mock::given(method("GET"))
            .and(path(INBOX))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": messages })))
            .expect(1)
            .mount(server)
            .await;
    }

    async fn stored_position(setup: &harness::ProviderSetup) -> GraphPosition {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        GraphPosition::parse(hook.position.as_deref()).unwrap()
    }

    /// Of five new messages two pass the rules, one by its subject and one only
    /// through a Cc address, and the newest message is not one of them. The event
    /// counts the two and describes the newer, and the position passes all five.
    #[tokio::test]
    async fn an_event_counts_and_describes_the_messages_that_pass_the_rules() {
        let mut setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        let (store, id) = (&setup.store, &setup.account);
        harness::allow(store, id, "subject", "equals", "Invoice").await;
        harness::allow(store, id, "to", "equals", "boss@example.com").await;
        mount_inbox(
            &setup.server,
            &[
                judged_message("m1", "2026-10-08T09:00:01Z", "Lunch", &[]),
                judged_message("m2", "2026-10-08T09:00:02Z", "Invoice", &[]),
                judged_message("m3", "2026-10-08T09:00:03Z", "Hello", &[]),
                judged_message("m4", "2026-10-08T09:00:04Z", "Hello", &["Boss@Example.com"]),
                judged_message("m5", "2026-10-08T09:00:05Z", "Lunch again", &[]),
            ],
        )
        .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "graph.m4");
        assert_eq!(got.json()["count"], 2);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = stored_position(&setup).await;
        assert_eq!(stored.since, "2026-10-08T09:00:05Z");
        assert_eq!(stored.ids, vec!["m5".to_owned()]);
        assert_eq!(hook.last_sequence, 1);
        harness::finish(&setup).await;
    }

    /// No message of the page passes: the position moves past it, nothing is
    /// recorded, and the next catch-up does not list it again.
    #[tokio::test]
    async fn a_page_none_of_which_passes_moves_the_position_without_an_event() {
        let setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        harness::allow(&setup.store, &setup.account, "subject", "equals", "Invoice").await;
        mount_inbox(
            &setup.server,
            &[
                judged_message("m1", "2026-10-08T09:00:01Z", "Lunch", &[]),
                judged_message("m2", "2026-10-08T09:00:02Z", "Hello", &[]),
            ],
        )
        .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = stored_position(&setup).await;
        assert_eq!(stored.since, "2026-10-08T09:00:02Z");
        assert_eq!(stored.ids, vec!["m2".to_owned()]);
        assert_eq!((hook.last_sequence, hook.delivered_sequence), (0, 0));
        harness::finish(&setup).await;
    }

    /// Nothing on the first page passes and one message of the second does: the
    /// run goes on from the position it moved, so the second page is recorded.
    #[tokio::test]
    async fn a_page_none_of_which_passes_does_not_end_the_run() {
        let mut setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        harness::allow(&setup.store, &setup.account, "subject", "equals", "Invoice").await;
        let first = [judged_message("m1", "2026-10-08T09:00:01Z", "Lunch", &[])];
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": first,
                "@odata.nextLink": next_link(&setup.server, "page-2"),
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param("$skiptoken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [judged_message("m2", "2026-10-08T09:00:02Z", "Invoice", &[])]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "graph.m2");
        assert_eq!(got.json()["count"], 1);
        let stored = stored_position(&setup).await;
        assert_eq!(stored.since, "2026-10-08T09:00:02Z");
        harness::finish(&setup).await;
    }

    /// Another watcher moves the position past the page while it is read, and
    /// nothing on the page passes: the position stays where that watcher put it,
    /// and the rerun, which reads from there, finds nothing new.
    #[tokio::test]
    async fn a_position_moved_while_nothing_passes_is_not_moved_back() {
        let setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        harness::allow(&setup.store, &setup.account, "subject", "equals", "Invoice").await;
        // The listing is held, so the other watcher moves the position while
        // this run waits for the page. The rerun reads an empty page.
        let page = json!({
            "value": [judged_message("raced", "2026-10-08T09:05:00Z", "Lunch", &[])]
        });
        let (mut hold, responder) = Hold::new(ResponseTemplate::new(200).set_body_json(page));
        Mock::given(method("GET"))
            .and(path(INBOX))
            .respond_with(responder)
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(INBOX))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .with_priority(2)
            .mount(&setup.server)
            .await;
        let moved = GraphPosition {
            since: "2026-10-08T09:06:00Z".to_owned(),
            ids: vec!["later".to_owned()],
            resume: None,
        }
        .encode();
        let mut run = pin!(setup.watchers.graph_catch_up(&setup.account));
        hold.arrived_before(&mut run).await;
        let store = &setup.store;
        store
            .set_watch_position(&setup.account, &moved)
            .await
            .unwrap();
        hold.release();
        run.await.unwrap();
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.position.as_deref(), Some(moved.as_str()));
        assert_eq!(hook.last_sequence, 0);

        harness::wait_for_requests(&setup.server, "GET", INBOX, 2).await;
        wait_until_catch_up_idle(&setup).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.position.as_deref(), Some(moved.as_str()));
        assert_eq!(hook.last_sequence, 0);
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 2);
        harness::finish(&setup).await;
    }

    /// A message is judged by its sender: of two messages, only the one from the
    /// allowed address passes, whatever case the address is in. The usage hook
    /// lets only that oldest rule count, so the newer one, which both match,
    /// judges nothing.
    #[tokio::test]
    async fn a_message_is_judged_by_its_sender() {
        let mut setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        setup.watchers.set_usage_hook(harness::FilterLimit::new(1));
        let (store, id) = (&setup.store, &setup.account);
        harness::allow(store, id, "from", "equals", "boss@example.com").await;
        harness::allow(store, id, "subject", "equals", "Hello").await;
        let mut boss = judged_message("m1", "2026-10-08T09:00:01Z", "Hello", &[]);
        boss["from"] = json!({ "emailAddress": { "address": "Boss@Example.com" } });
        let other = judged_message("m2", "2026-10-08T09:00:02Z", "Hello", &[]);
        mount_inbox(&setup.server, &[boss, other]).await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "graph.m1");
        assert_eq!(got.json()["count"], 1);
        harness::finish(&setup).await;
    }

    /// A message is judged by every address it is sent to, in To or in Cc, and by
    /// no other. A recipient with no address is not judged as an empty one, and
    /// one without an `emailAddress` does not fail the page.
    #[tokio::test]
    async fn a_message_is_judged_by_its_to_and_cc_recipients() {
        let mut setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        let (store, id) = (&setup.store, &setup.account);
        harness::allow(store, id, "to", "equals", "boss@example.com").await;
        harness::allow(store, id, "to", "regex", "^$").await;
        let to = |addresses: &[&str]| {
            let one = |address: &&str| json!({ "emailAddress": { "address": address } });
            json!(addresses.iter().map(one).collect::<Vec<_>>())
        };
        let mut by_to = judged_message("m1", "2026-10-08T09:00:01Z", "Hello", &[]);
        by_to["toRecipients"] = to(&["other@example.com", "Boss@Example.com"]);
        let by_cc = judged_message("m2", "2026-10-08T09:00:02Z", "Hello", &["boss@example.com"]);
        let neither = judged_message(
            "m3",
            "2026-10-08T09:00:03Z",
            "Hello",
            &["other@example.com"],
        );
        let mut nameless = judged_message("m4", "2026-10-08T09:00:04Z", "Hello", &[]);
        nameless["toRecipients"] = json!([{ "emailAddress": { "name": "No Address" } }]);
        let mut bare = judged_message("m5", "2026-10-08T09:00:05Z", "Hello", &[]);
        bare["from"] = json!({});
        bare["toRecipients"] = json!([{}, { "emailAddress": null }]);
        mount_inbox(&setup.server, &[by_to, by_cc, neither, nameless, bare]).await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "graph.m2");
        assert_eq!(got.json()["count"], 2);
        harness::finish(&setup).await;
    }

    /// A page that loses the position has a next link. The run does not follow
    /// it: the rerun reads from the position the other watcher stored.
    #[tokio::test]
    async fn a_lost_position_ends_the_run_before_the_next_page() {
        let setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        // The first listing is held, so the other watcher moves the position
        // while this run waits for it. The rerun reads an empty page.
        let page = json!({
            "value": [judged_message("raced", "2026-10-08T09:05:00Z", "Lunch", &[])],
            "@odata.nextLink": next_link(&setup.server, "page-2"),
        });
        let (mut hold, responder) = Hold::new(ResponseTemplate::new(200).set_body_json(page));
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(responder)
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .with_priority(2)
            .mount(&setup.server)
            .await;
        let moved = GraphPosition {
            since: "2026-10-08T09:06:00Z".to_owned(),
            ids: vec!["later".to_owned()],
            resume: None,
        }
        .encode();
        let mut run = pin!(setup.watchers.graph_catch_up(&setup.account));
        hold.arrived_before(&mut run).await;
        let store = &setup.store;
        store
            .set_watch_position(&setup.account, &moved)
            .await
            .unwrap();
        hold.release();
        run.await.unwrap();

        harness::wait_for_requests(&setup.server, "GET", INBOX, 2).await;
        wait_until_catch_up_idle(&setup).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.position.as_deref(), Some(moved.as_str()));
        assert_eq!(hook.last_sequence, 0);
        assert_eq!(
            harness::requests(&setup.server, "GET", INBOX).await,
            2,
            "no read of page 2"
        );
        harness::finish(&setup).await;
    }

    /// The webhook is deleted while a run waits for a page that has a next link.
    /// The run records nothing and ends there: it does not read the next page.
    #[tokio::test]
    async fn a_webhook_deleted_during_the_run_ends_it_before_the_next_page() {
        let setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        // The first listing is held, so the user deletes the webhook while
        // this run waits for it.
        let page = json!({
            "value": [judged_message("late", "2026-10-08T09:05:00Z", "Lunch", &[])],
            "@odata.nextLink": next_link(&setup.server, "page-2"),
        });
        let (mut hold, responder) = Hold::new(ResponseTemplate::new(200).set_body_json(page));
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(responder)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(INBOX))
            .and(query_param("$skiptoken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .mount(&setup.server)
            .await;
        let mut run = pin!(setup.watchers.graph_catch_up(&setup.account));
        hold.arrived_before(&mut run).await;
        setup.store.delete_webhook(&setup.account).await.unwrap();
        hold.release();
        run.await.unwrap();

        assert_eq!(
            harness::requests(&setup.server, "GET", INBOX).await,
            1,
            "no read of page 2"
        );
        harness::finish(&setup).await;
    }

    /// The event names the sender and the subject when the webhook says so, and
    /// does not otherwise.
    #[tokio::test]
    async fn an_event_names_the_sender_only_when_the_webhook_says_so() {
        for include_sender in [true, false] {
            let mut setup = provider_setup(Provider::Graph).await;
            store_position(&setup).await;
            let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
            let settings = postkeep_store::WebhookSettings {
                include_sender,
                ..hook.settings
            };
            let saved = setup.store.save_webhook(&setup.account, &settings);
            saved.await.unwrap();
            let received = "2026-10-08T09:00:01Z";
            mount_inbox(
                &setup.server,
                &[judged_message("m1", received, "Lunch", &[])],
            )
            .await;

            setup.watchers.graph_catch_up(&setup.account).await.unwrap();
            let json = harness::next_event(&mut setup.receiver).await.json();
            if include_sender {
                assert_eq!(json["from"], "Sender <sender@example.com>");
                assert_eq!(json["subject"], "Lunch");
            } else {
                assert!(json.get("from").is_none() && json.get("subject").is_none());
            }
            harness::finish(&setup).await;
        }
    }

    /// A page of more than the 50 messages asked for is counted as 50.
    #[tokio::test]
    async fn an_event_counts_at_most_a_batch() {
        let mut setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        let message = |n: usize| {
            let received = format!("2026-10-08T09:01:{n:02}Z");
            judged_message(&format!("m{n}"), &received, "Hello", &[])
        };
        let messages: Vec<_> = (0..=BATCH_LIMIT).map(message).collect();
        mount_inbox(&setup.server, &messages).await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["count"], BATCH_LIMIT);
        assert_eq!(got.json()["id"], format!("graph.m{BATCH_LIMIT}"));
        harness::finish(&setup).await;
    }

    /// Rules this version can't read hold the mail: Graph is not asked, nothing
    /// is recorded, and the position stays.
    #[tokio::test]
    async fn rules_that_cannot_be_read_hold_the_mail_without_asking_graph() {
        let setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        harness::allow(&setup.store, &setup.account, "body", "contains", "x").await;
        let before = stored_position(&setup).await;
        Mock::given(method("GET"))
            .and(path(INBOX))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": [] })))
            .expect(0)
            .mount(&setup.server)
            .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        assert_eq!(harness::requests(&setup.server, "GET", INBOX).await, 0);
        assert_eq!(stored_position(&setup).await, before);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn the_inbox_request_selects_the_recipients() {
        let setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        mount_inbox(&setup.server, &[]).await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let requests = setup.server.received_requests().await.unwrap();
        let select = requests[0]
            .url
            .query_pairs()
            .find_map(|(key, value)| (key == "$select").then(|| value.into_owned()))
            .unwrap();
        let selected: Vec<_> = select.split(',').collect();
        assert!(selected.contains(&"toRecipients") && selected.contains(&"ccRecipients"));
        harness::finish(&setup).await;
    }

    /// Graph may answer `null` for the recipients and leave out the sender and the
    /// subject. The page still parses, and such a message is judged as one with
    /// empty values: it does not pass an allow rule on the subject.
    #[tokio::test]
    async fn a_message_without_a_sender_or_recipients_is_judged_with_empty_fields() {
        let mut setup = provider_setup(Provider::Graph).await;
        store_position(&setup).await;
        harness::allow(
            &setup.store,
            &setup.account,
            "subject",
            "contains",
            "Invoice",
        )
        .await;
        mount_inbox(
            &setup.server,
            &[
                json!({ "id": "bare", "receivedDateTime": "2026-10-08T09:00:01Z", "toRecipients": null }),
                json!({
                    "id": "billed",
                    "receivedDateTime": "2026-10-08T09:00:02Z",
                    "subject": "Invoice 7",
                    "toRecipients": null,
                    "ccRecipients": null,
                }),
            ],
        )
        .await;

        setup.watchers.graph_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "graph.billed");
        assert_eq!(got.json()["count"], 1);
        assert_eq!(stored_position(&setup).await.since, "2026-10-08T09:00:02Z");
        harness::finish(&setup).await;
    }
}
