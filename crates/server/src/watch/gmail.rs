//! New mail at Gmail: `users.watch` notifications through Cloud Pub/Sub.
//!
//! For a Gmail account with an enabled webhook, the watcher calls
//! `users.watch` for the Inbox with the configured Pub/Sub topic and
//! repeats the call daily (a watch expires after seven days; Google
//! recommends renewing it once a day). Pub/Sub pushes each change to
//! `POST /push/google`; see [`crate::push`].
//!
//! A pause after delivery failures does not stop or restart this watcher.
//! `users.watch` still renews once a day, the account keeps its watcher
//! slot, and a push still records new mail. That mail is not delivered
//! until the pause interval. Pausing does not shorten the renewal wait or
//! call Gmail more often. The user turning the webhook off (the account
//! page or `set_webhook_enabled`) cancels the session. The replacement
//! calls `users.stop`, drops the local watch, and releases the slot.
//! Failures never turn the webhook off.
//!
//! As with Graph, a notification is only a hint: it triggers a catch-up
//! that reads `history.list` from the stored history id and records one
//! event for the Inbox messages added since. When the stored history id
//! is too old (`404`), or when history paging is cut off while a further
//! page remains, the watcher falls back to a full resync: it lists the
//! newest Inbox messages received after the newest one already reported
//! and restarts from the mailbox's current history id. The resync lists
//! at most one page, so nothing past that page is reported as the newest.
//! A catch-up that fails because Gmail or the database is briefly
//! unavailable is retried with backoff, on the same terms as a Graph
//! catch-up.
//!
//! The event counts the messages that pass the mailbox's filter rules and
//! describes the newest of them. Without rules only the newest message is
//! read, to describe the event. With rules each new message is read, one
//! `messages.get` at a time and oldest first, so that none is hidden behind
//! a newer one; a read that fails in a way a later try may get past is tried
//! again. A pass none of whose messages passes moves the position and
//! records no event. A catch-up whose rules can't be read does nothing, and
//! the next one tries again.

use std::collections::HashSet;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use postkeep_mail::{EmailAddress, invisible};
use postkeep_store::{AccountId, AppendOutcome, Provider, PushSubscription, WatchAdvance};
use postkeep_upstream::{ApiClient, UpstreamProvider};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::rules::{Fields, Judged, Rules};
use super::{BATCH_LIMIT, Exit, FOLDER, WatchError, Watchers, api_is_transient};
use crate::mailbox::id::{self, GMAIL_PREFIX};

/// Renew the watch this often.
const RENEW_EVERY_SECS: i64 = 24 * 3600;
/// History pages read per catch-up.
const MAX_HISTORY_PAGES: usize = 10;
/// Reported ids remembered to drop duplicates.
const RECENT_IDS: usize = 200;
/// The headers asked of every `messages.get`.
const METADATA_HEADERS: [&str; 6] = ["From", "To", "Cc", "Subject", "Message-ID", "Date"];
/// Waits before each retry of a `messages.get` that failed in a way a later
/// try may get past. Reading every new message of a mailbox with rules can take
/// thousands of requests, and one failed request would fail the whole pass.
const METADATA_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(250),
    Duration::from_secs(1),
    Duration::from_secs(4),
];

/// The stored position.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GmailPosition {
    /// The Gmail history id caught up to.
    pub history_id: u64,
    /// `internalDate` (Unix milliseconds) of the newest message reported,
    /// or when watching started; the full-resync starting point.
    pub since_ms: i64,
    /// Message ids reported recently, newest last.
    #[serde(default)]
    pub recent: Vec<String>,
}

impl GmailPosition {
    const PREFIX: &'static str = "gmail:";

    fn parse(stored: Option<&str>) -> Option<Self> {
        serde_json::from_str(stored?.strip_prefix(Self::PREFIX)?).ok()
    }

    fn encode(&self) -> String {
        format!(
            "{}{}",
            Self::PREFIX,
            serde_json::to_string(self).unwrap_or_default()
        )
    }

    fn remember(&mut self, ids: impl IntoIterator<Item = String>) {
        self.recent.extend(ids);
        let excess = self.recent.len().saturating_sub(RECENT_IDS);
        self.recent.drain(..excess);
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WatchResponse {
    history_id: String,
    expiration: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    history_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HistoryPage {
    #[serde(default)]
    history: Vec<History>,
    next_page_token: Option<String>,
    history_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct History {
    #[serde(default)]
    messages_added: Vec<Added>,
}

#[derive(Debug, Deserialize)]
struct Added {
    message: AddedMessage,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AddedMessage {
    id: String,
    #[serde(default)]
    label_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MessageList {
    #[serde(default)]
    messages: Vec<MessageRef>,
}

#[derive(Debug, Deserialize)]
struct MessageRef {
    id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    id: String,
    internal_date: Option<String>,
    payload: Option<Payload>,
}

#[derive(Debug, Deserialize)]
struct Payload {
    #[serde(default)]
    headers: Vec<Header>,
}

#[derive(Debug, Deserialize)]
struct Header {
    name: String,
    value: String,
}

impl Metadata {
    /// Every value of the header `name`, in the order Gmail gave them.
    fn values<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a str> {
        let headers = self.payload.iter().flat_map(|payload| &payload.headers);
        headers
            .filter(move |header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value.as_str())
    }

    /// The first value of the header `name`: the one the event shows.
    fn header(&self, name: &str) -> Option<&str> {
        self.values(name).next()
    }

    fn internal_ms(&self) -> Option<i64> {
        self.internal_date.as_deref()?.parse().ok()
    }

    /// The headers the event shows, as a header block for the parser that
    /// reads IMAP's headers: the first `From` and the first `Subject`, and one
    /// `To` and one `Cc` line with all their values. A parser keeps the last of
    /// repeated headers and the event shows the first, so repeats are not
    /// passed on. A value cannot end its line, so it cannot add a header.
    fn judged_headers(&self) -> String {
        let first = |name: &str| self.header(name).unwrap_or_default().to_owned();
        let all = |name: &str| {
            let values: Vec<_> = self.values(name).filter(|v| !v.trim().is_empty()).collect();
            values.join(", ")
        };
        let lines = [
            ("From", first("From")),
            ("Subject", first("Subject")),
            ("To", all("To")),
            ("Cc", all("Cc")),
        ];
        let mut block = String::new();
        for (name, value) in lines {
            if !value.trim().is_empty() {
                block.extend([name, ": ", &value.replace(['\r', '\n'], " "), "\r\n"]);
            }
        }
        block.push_str("\r\n");
        block
    }
}

impl Judged for Metadata {
    fn fields(&self) -> Fields {
        let block = self.judged_headers();
        let Some(headers) = postkeep_mail::mime::parse_headers(block.as_bytes()) else {
            return Fields::default();
        };
        let address = |a: EmailAddress| a.address;
        Fields {
            from: headers
                .from
                .into_iter()
                .next()
                .map(address)
                .unwrap_or_default(),
            from_clear: self.values("From").count() == 1
                && postkeep_mail::mime::sender(block.as_bytes()).is_some(),
            from_values: self.values("From").map(str::to_owned).collect(),
            to: headers
                .to
                .into_iter()
                .chain(headers.cc)
                .map(address)
                .collect(),
            subject: headers
                .subject
                .or_else(|| self.header("Subject").map(str::to_owned))
                .unwrap_or_default(),
        }
    }
}

fn parse_u64(value: &str) -> Result<u64, WatchError> {
    value
        .parse()
        .map_err(|_| WatchError::Malformed("Gmail returned a non-numeric history id"))
}

fn users_me(api: &ApiClient, segments: &[&str]) -> Url {
    let mut all = vec!["gmail", "v1", "users", "me"];
    all.extend_from_slice(segments);
    postkeep_upstream::http::join_segments(&api.endpoints().gmail, &all)
}

impl Watchers {
    pub(super) fn gmail_api(&self, account: &AccountId) -> Option<ApiClient> {
        let push = self.inner.push.get()?;
        push.google_enabled().then(|| {
            ApiClient::new(
                push.tokens.clone(),
                account.clone(),
                UpstreamProvider::Google,
            )
        })
    }

    /// Keeps the account's watch alive until cancelled.
    pub(super) async fn gmail_session(
        &self,
        account: &AccountId,
        cancel: &CancellationToken,
        failures: &mut u32,
    ) -> Result<Exit, WatchError> {
        // Before any watch, renewal, or token use, and again before each
        // renewal. A refusal releases the slot and deletes nothing.
        if self.allow_list_blocks(account).await? {
            return Ok(Exit::Disabled);
        }
        let Some(api) = self.gmail_api(account) else {
            tracing::info!(account_id = %account, "Gmail push needs Google sign-in and POSTKEEP_GOOGLE_PUBSUB_TOPIC; not watching this account");
            return Ok(Exit::Disabled);
        };
        let store = &self.inner.store;
        let hook = super::readable_webhook(store, account).await?;
        if !hook.as_ref().is_some_and(|hook| hook.settings.enabled) {
            // A pause keeps the webhook enabled, so this watcher stays up,
            // keeps renewing `users.watch`, and keeps the account's slot.
            // Only the user turning the webhook off, or removing it, stops
            // the watch and releases the slot.
            self.gmail_stop(&api).await;
            return Ok(Exit::Disabled);
        }
        let read = hook.and_then(|hook| hook.position);
        let mut has_position = GmailPosition::parse(read.as_deref()).is_some();
        loop {
            // The process that watches the mailbox now renews it.
            if !self.owns(account) {
                return Ok(Exit::Stopped);
            }
            if self.allow_list_blocks(account).await? {
                return Ok(Exit::Disabled);
            }
            // Re-read before each renewal. A pause is still enabled, so
            // the daily `users.watch` continues and this task keeps the
            // slot. The wait below is not shortened by a pause, so pausing
            // does not call Gmail again. The user turning the webhook off
            // cancels this sleep; if the loop does run again it stops the
            // watch instead of renewing it.
            let still_on = super::readable_webhook(store, account)
                .await?
                .is_some_and(|hook| hook.settings.enabled);
            if !still_on {
                self.gmail_stop(&api).await;
                return Ok(Exit::Disabled);
            }
            let (history_id, expires_at) = self.gmail_watch(&api).await?;
            if has_position {
                *failures = 0;
                // Mail that arrived while no watch existed.
                self.gmail_catch_up(account).await?;
            } else {
                // First start: existing mail is old.
                let fresh = GmailPosition {
                    history_id,
                    since_ms: chrono::Utc::now().timestamp_millis(),
                    recent: Vec::new(),
                }
                .encode();
                let usable = |stored: Option<&str>| GmailPosition::parse(stored).is_some();
                let started = self.start_position(account, read.clone(), fresh.clone(), usable);
                let started = started.await?;
                // Only now: a first start that keeps losing the position waits
                // longer each time, as an IMAP one does.
                *failures = 0;
                if started.is_some_and(|started| started != fresh) {
                    // Another watcher stored a position after this session
                    // read none: report the mail after it now.
                    self.gmail_catch_up(account).await?;
                }
                has_position = true;
            }
            // At least a minute, and normally a day. A pause does not
            // change this, so it cannot busy-loop or renew early.
            let wait = RENEW_EVERY_SECS
                .min(expires_at - RENEW_EVERY_SECS - postkeep_store::now())
                .max(60);
            tokio::select! {
                () = cancel.cancelled() => return Ok(Exit::Stopped),
                () = tokio::time::sleep(std::time::Duration::from_secs(wait.unsigned_abs())) => {}
            }
        }
    }

    /// Calls `users.watch`. Returns the current history id and when the
    /// watch expires (Unix seconds).
    async fn gmail_watch(&self, api: &ApiClient) -> Result<(u64, i64), WatchError> {
        let push = self.inner.push.get().ok_or(WatchError::NotConfigured)?;
        let google = push.google.as_ref().ok_or(WatchError::NotConfigured)?;
        let response: WatchResponse = api.parse(
            &api.send_json(
                Method::POST,
                &users_me(api, &["watch"]),
                &[],
                &json!({
                    "topicName": google.topic,
                    "labelIds": ["INBOX"],
                    "labelFilterBehavior": "INCLUDE",
                }),
            )
            .await?,
        )?;
        let history_id = parse_u64(&response.history_id)?;
        let now = postkeep_store::now();
        // A watch lasts seven days; distrust anything outside a sane range.
        let expires_at = (response
            .expiration
            .parse::<i64>()
            .map_err(|_| WatchError::Malformed("Gmail returned a non-numeric expiration"))?
            / 1000)
            .clamp(now, now + 8 * 86_400);
        self.inner
            .store
            .save_push_subscription(
                api.account(),
                &PushSubscription {
                    provider: Provider::Gmail,
                    subscription_id: None,
                    client_state_hash: None,
                    expires_at,
                },
            )
            .await?;
        tracing::debug!(account_id = %api.account(), "watching the Gmail inbox");
        Ok((history_id, expires_at))
    }

    /// Stops the account's watch at Gmail and locally, best effort.
    pub(super) async fn gmail_stop(&self, api: &ApiClient) {
        let store = &self.inner.store;
        let account = api.account();
        if !matches!(store.push_subscription(account).await, Ok(Some(_))) {
            return;
        }
        if let Err(err) = api
            .send_json(Method::POST, &users_me(api, &["stop"]), &[], &json!({}))
            .await
        {
            tracing::info!(account_id = %account, error = %err, "could not stop the Gmail watch; it expires on its own");
        }
        if let Err(err) = store.delete_push_subscription(account).await {
            tracing::warn!(account_id = %account, error = %err, "could not forget the Gmail watch");
        }
    }

    /// Records one event for Inbox messages added since the stored
    /// position that pass the mailbox's filter rules. Serialized per account:
    /// the lock is held from the read of the stored position through the
    /// publish, so a replacement watcher waits until this pass commits and
    /// cannot record the same additions.
    ///
    /// A pass none of whose messages passes moves the position with no
    /// event, and only from where this pass read it.
    pub(crate) async fn gmail_catch_up(&self, account: &AccountId) -> Result<(), WatchError> {
        let lock = self.catch_up_lock(account);
        let _guard = lock.lock().await;
        let Some(api) = self.gmail_api(account) else {
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
        let Some(mut position) = GmailPosition::parse(hook.position.as_deref()) else {
            return Ok(());
        };
        // Rules that can't be read hold the mail where it is, before Gmail is asked.
        let Some(rules) = self.rules(account, &hook).await? else {
            return Ok(());
        };
        let added = match history(&api, position.history_id).await {
            Ok(read) if read.truncated => {
                // The history id on a partial listing is already the mailbox
                // current id, so keeping it would skip every page we did not
                // read. Resync from the newest message already reported.
                tracing::info!(account_id = %account, "Gmail history was cut off; resyncing the inbox");
                let (added, history_id) = resync(&api, position.since_ms).await?;
                position.history_id = history_id;
                added
            }
            Ok(read) => {
                position.history_id = position.history_id.max(read.history_id);
                read.added
            }
            Err(WatchError::Api(err)) if err.status() == Some(StatusCode::NOT_FOUND) => {
                tracing::info!(account_id = %account, "the stored Gmail history id expired; resyncing the inbox");
                let (added, history_id) = resync(&api, position.since_ms).await?;
                position.history_id = history_id;
                added
            }
            Err(err) => return Err(err),
        };
        let recent: HashSet<&String> = position.recent.iter().collect();
        let fresh: Vec<String> = added
            .into_iter()
            .filter(|id| !recent.contains(id))
            .collect();
        drop(recent);
        let found = match &rules {
            Rules::Off => newest_present(&api, &fresh).await?,
            Rules::On(_) => judge(&api, &rules, &fresh).await?,
        };
        position.since_ms = position.since_ms.max(found.newest_ms);
        position.remember(fresh);
        let next = position.encode();
        let recorded = if let Some(newest) = found.newest {
            let event = new_mail_event(&account_row.email, &newest, found.count);
            let event = if hook.settings.include_sender {
                event
            } else {
                event.without_sender_and_subject()
            };
            let advance = WatchAdvance::Position {
                expected: hook.position.clone(),
                next,
            };
            self.publish(account, &event, Some(advance)).await? != AppendOutcome::StaleCursor
        } else {
            let expected = hook.position.as_deref();
            let moved = store.advance_watch_position(account, expected, &next);
            moved.await?
        };
        if !recorded {
            // Another watcher moved the position after this pass read it.
            // Drop this batch and read the position again.
            tracing::info!(account_id = %account, "the Gmail position changed during this pass; reading it again");
            self.schedule_gmail_catch_up(account);
        }
        Ok(())
    }

    /// Catches up after a short debounce, in the background.
    ///
    /// At most one catch-up runs for the account. A request while that one
    /// is scheduled or running records a single rerun. A transient failure
    /// retries with backoff; a request during that wait runs the next pass
    /// without waiting it out.
    pub fn schedule_gmail_catch_up(&self, account: &AccountId) {
        self.schedule_provider_catch_up(account, super::ProviderCatchUp::Gmail);
    }
}

/// One `history.list` read. When `truncated` is set, `added` and
/// `history_id` are incomplete: the mailbox's history id is already the
/// current one, so the caller resyncs instead of storing them.
struct HistoryRead {
    added: Vec<String>,
    history_id: u64,
    truncated: bool,
}

/// Whether this `messagesAdded` entry is Inbox mail.
///
/// The list is requested with `labelId=INBOX`. Google documents that
/// messages in the response typically have only `id` and `threadId`, so
/// `labelIds` is absent and deserializes empty. An empty list is Inbox.
/// When labels are present, `INBOX` is required, which skips a message
/// returned for another label.
fn added_in_inbox(message: &AddedMessage) -> bool {
    message.label_ids.is_empty() || message.label_ids.iter().any(|label| label == "INBOX")
}

/// Inbox messages added after `start`, oldest first, and the newest
/// history id seen.
async fn history(api: &ApiClient, start: u64) -> Result<HistoryRead, WatchError> {
    let mut ids = Vec::new();
    let mut seen = HashSet::new();
    let mut newest = start;
    let mut page_token: Option<String> = None;
    let mut truncated = false;
    for page_index in 0..MAX_HISTORY_PAGES {
        let mut url = users_me(api, &["history"]);
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("startHistoryId", &start.to_string())
                .append_pair("historyTypes", "messageAdded")
                .append_pair("labelId", "INBOX")
                .append_pair("maxResults", "500");
            if let Some(token) = &page_token {
                query.append_pair("pageToken", token);
            }
        }
        let page: HistoryPage = api.get_json(&url, &[]).await?;
        if let Some(id) = page.history_id.as_deref() {
            newest = newest.max(parse_u64(id)?);
        }
        for added in page
            .history
            .into_iter()
            .flat_map(|history| history.messages_added)
        {
            let message = added.message;
            if added_in_inbox(&message) && seen.insert(message.id.clone()) {
                ids.push(message.id);
            }
        }
        match page.next_page_token {
            Some(_) if page_index + 1 == MAX_HISTORY_PAGES => truncated = true,
            Some(token) => page_token = Some(token),
            None => break,
        }
    }
    Ok(HistoryRead {
        added: ids,
        history_id: newest,
        truncated,
    })
}

/// Full resync: Inbox messages received after `since_ms`, oldest first,
/// and the mailbox's current history id.
async fn resync(api: &ApiClient, since_ms: i64) -> Result<(Vec<String>, u64), WatchError> {
    // The profile first: mail arriving in between is reported twice at
    // worst (and dropped by the recent ids), never missed.
    let profile: Profile = api.get_json(&users_me(api, &["profile"]), &[]).await?;
    let history_id = parse_u64(&profile.history_id)?;
    let mut url = users_me(api, &["messages"]);
    url.query_pairs_mut()
        .append_pair("labelIds", "INBOX")
        .append_pair("q", &format!("after:{}", since_ms.div_euclid(1000)))
        .append_pair("maxResults", &BATCH_LIMIT.to_string());
    let list: MessageList = api.get_json(&url, &[]).await?;
    let mut ids = Vec::new();
    // Listed newest first; `after:` has one-second precision.
    for message in list.messages {
        match metadata(api, &message.id).await {
            Ok(found) if found.internal_ms().is_some_and(|ms| ms > since_ms) => ids.push(found.id),
            Ok(_) => break,
            Err(WatchError::Api(err)) if err.status() == Some(StatusCode::NOT_FOUND) => {}
            Err(err) => return Err(err),
        }
    }
    ids.reverse();
    Ok((ids, history_id))
}

/// What a pass learned from reading the messages it was told of.
struct Found {
    /// The newest message that passes the rules, which the event describes.
    newest: Option<Metadata>,
    /// How many messages pass.
    count: usize,
    /// The newest `internalDate` of the messages read, passing or not (Unix
    /// milliseconds), or 0.
    newest_ms: i64,
}

/// Without rules every message passes, so the newest one that is still there
/// describes the event, and it is the only one read.
async fn newest_present(api: &ApiClient, fresh: &[String]) -> Result<Found, WatchError> {
    for message in fresh.iter().rev() {
        if let Some(newest) = present(api, message).await? {
            let newest_ms = newest.internal_ms().unwrap_or(0);
            let count = fresh.len();
            return Ok(Found {
                newest: Some(newest),
                count,
                newest_ms,
            });
        }
    }
    Ok(Found {
        newest: None,
        count: 0,
        newest_ms: 0,
    })
}

/// With rules every message is read, oldest first and one request at a time,
/// and judged, so that a message that passes is not hidden behind a newer one
/// that does not.
async fn judge(api: &ApiClient, rules: &Rules, fresh: &[String]) -> Result<Found, WatchError> {
    let mut read = Vec::with_capacity(fresh.len());
    for message in fresh {
        read.extend(present(api, message).await?);
    }
    let newest_ms = read.iter().filter_map(Metadata::internal_ms).max();
    let mut passing = rules.keep(read).await;
    Ok(Found {
        count: passing.len(),
        newest: passing.pop(),
        newest_ms: newest_ms.unwrap_or(0),
    })
}

/// The headers of `message`, or `None` if it is gone.
async fn present(api: &ApiClient, message: &str) -> Result<Option<Metadata>, WatchError> {
    match metadata(api, message).await {
        Ok(found) => Ok(Some(found)),
        Err(WatchError::Api(err)) if err.status() == Some(StatusCode::NOT_FOUND) => Ok(None),
        Err(err) => Err(err),
    }
}

/// One `messages.get` for the headers the watcher uses. A failure a later try
/// may get past is tried again after each of [`METADATA_RETRY_DELAYS`]; any other
/// error, a 404 among them, is returned at once.
async fn metadata(api: &ApiClient, message: &str) -> Result<Metadata, WatchError> {
    let mut url = users_me(api, &["messages", message]);
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("format", "metadata");
        for name in METADATA_HEADERS {
            query.append_pair("metadataHeaders", name);
        }
    }
    let mut waits = METADATA_RETRY_DELAYS.into_iter();
    loop {
        let result = api.get_json(&url, &[]).await;
        if let Err(err) = &result
            && api_is_transient(err)
            && let Some(wait) = waits.next()
        {
            tokio::time::sleep(wait).await;
            continue;
        }
        return Ok(result?);
    }
}

fn new_mail_event(email: &str, newest: &Metadata, count: usize) -> postkeep_webhook::NewMailEvent {
    let date = newest
        .header("Date")
        .and_then(|date| chrono::DateTime::parse_from_rfc2822(date.trim()).ok())
        .or_else(|| {
            chrono::DateTime::from_timestamp_millis(newest.internal_ms()?)
                .map(|date| date.fixed_offset())
        })
        .map(|date| date.to_rfc3339());
    let from_values: Vec<String> = newest.values("From").map(str::to_owned).collect();
    let sender = postkeep_mail::mime::sender_of_values(&from_values);
    let (from, from_unclear) = invisible::senders(sender.as_ref(), sender.is_some(), &from_values);
    postkeep_webhook::NewMailEvent {
        event: postkeep_webhook::NEW_MAIL,
        test: false,
        account: email.to_owned(),
        folder: FOLDER.to_owned(),
        id: id::provider_id(GMAIL_PREFIX, &newest.id),
        uid: None,
        message_id: newest
            .header("Message-ID")
            .map(|id| invisible::visible(id.trim().trim_start_matches('<').trim_end_matches('>'))),
        from: from.into_iter().next(),
        from_unclear,
        subject: newest.header("Subject").map(invisible::visible),
        date,
        count: u32::try_from(count).unwrap_or(u32::MAX),
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
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};

    use postkeep_store::{Provider, PushSubscription};
    use postkeep_webhook::filter::{Action, CompiledRules, Field, Kind, Rule};
    use serde_json::json;
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::harness::{
        self, HISTORY_PATH, Hold, STOP_PATH, WATCH_PATH, provider_setup, watch_response,
    };
    use super::*;

    #[test]
    fn positions_round_trip_and_remember_a_bounded_tail() {
        let mut position = GmailPosition {
            history_id: 12_345,
            since_ms: 1_791_000_000_000,
            recent: Vec::new(),
        };
        position.remember((0..RECENT_IDS + 5).map(|n| n.to_string()));
        assert_eq!(position.recent.len(), RECENT_IDS);
        assert_eq!(position.recent.first().map(String::as_str), Some("5"));
        assert_eq!(
            GmailPosition::parse(Some(&position.encode())),
            Some(position)
        );
        assert_eq!(GmailPosition::parse(Some("graph:{}")), None);
    }

    const SINCE_MS: i64 = 1_700_000_000_000;
    const PROFILE_PATH: &str = "/gmail/gmail/v1/users/me/profile";
    const LIST_PATH: &str = "/gmail/gmail/v1/users/me/messages";

    fn history_body(history_id: &str, message: &str, next: Option<&str>) -> serde_json::Value {
        let mut body = json!({
            "historyId": history_id,
            "history": [{
                "messagesAdded": [{
                    "message": { "id": message, "labelIds": ["INBOX"] }
                }]
            }]
        });
        if let Some(next) = next {
            body["nextPageToken"] = json!(next);
        }
        body
    }

    fn metadata_body(id: &str) -> serde_json::Value {
        json!({
            "id": id,
            "internalDate": "1700000100000",
            "payload": {
                "headers": [
                    { "name": "From", "value": "sender@example.com" },
                    { "name": "Subject", "value": "Hello" },
                    { "name": "Message-ID", "value": format!("<{id}@example.com>") }
                ]
            }
        })
    }

    async fn store_position(setup: &harness::ProviderSetup, history_id: u64) {
        let position = GmailPosition {
            history_id,
            since_ms: SINCE_MS,
            recent: Vec::new(),
        };
        setup
            .store
            .set_watch_position(&setup.account, &position.encode())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_cut_off_history_resyncs_from_the_newest_inbox_message() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 1).await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(history_body(
                "9999",
                "old-msg",
                Some("more"),
            )))
            .expect(MAX_HISTORY_PAGES as u64)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(PROFILE_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "historyId": "5000"
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(LIST_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "messages": [{ "id": "newest-msg" }]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        // Resync checks the date, then the event reads the headers again.
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/newest-msg")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body("newest-msg")))
            .expect(2)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GmailPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(got.json()["id"], "gmail.newest-msg");
        assert_eq!(stored.history_id, 5000);
        assert_eq!(stored.recent, vec!["newest-msg".to_owned()]);
        assert_eq!(hook.last_sequence, 1);
        let paths: Vec<_> = setup
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert!(!paths.iter().any(|path| path.contains("old-msg")));
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_complete_history_page_does_not_resync() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(history_body(
                "150",
                "from-history",
                None,
            )))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/from-history")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body("from-history")))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GmailPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(got.json()["id"], "gmail.from-history");
        assert_eq!(stored.history_id, 150);
        assert_eq!(hook.last_sequence, 1);
        let paths: Vec<_> = setup
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert!(!paths.iter().any(|path| path == PROFILE_PATH));
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_position_moved_during_the_pass_drops_the_batch_and_reads_again() {
        let setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        // The listing is held, so another watcher reports the same message
        // and moves the position while this pass waits for it.
        let answer = ResponseTemplate::new(200).set_body_json(history_body("150", "raced", None));
        let (mut hold, responder) = Hold::new(answer);
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(responder)
            .expect(2)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/raced")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body("raced")))
            .expect(1)
            .mount(&setup.server)
            .await;
        let moved = GmailPosition {
            history_id: 150,
            since_ms: 1_700_000_100_000,
            recent: vec!["raced".to_owned()],
        }
        .encode();
        let mut run = pin!(setup.watchers.gmail_catch_up(&setup.account));
        hold.arrived_before(&mut run).await;
        setup
            .store
            .set_watch_position(&setup.account, &moved)
            .await
            .unwrap();
        // The held listing, then the rerun's.
        hold.release();
        hold.release();
        run.await.unwrap();
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0, "the stale batch was not recorded");
        assert_eq!(hook.position.as_deref(), Some(moved.as_str()));

        // The rerun reads the moved position and finds nothing new.
        harness::wait_for_requests(&setup.server, "GET", HISTORY_PATH, 2).await;
        harness::until(async || !setup.watchers.catch_up_running(&setup.account)).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0);
        let stored = GmailPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(stored.recent, vec!["raced".to_owned()]);
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn history_messages_without_labels_are_reported() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        // Google's history entries usually carry only id and threadId.
        // An empty labelIds list is the same: the request already asked
        // for INBOX. A repeated id is reported once.
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "historyId": "150",
                "history": [{
                    "messagesAdded": [
                        { "message": { "id": "bare-old", "threadId": "t1" } },
                        { "message": { "id": "bare-old", "threadId": "t1" } },
                        { "message": { "id": "empty-labels", "threadId": "t2", "labelIds": [] } }
                    ]
                }]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/empty-labels")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body("empty-labels")))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GmailPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(got.json()["id"], "gmail.empty-labels");
        assert_eq!(got.json()["count"], 2);
        assert_eq!(stored.history_id, 150);
        assert_eq!(
            stored.recent,
            vec!["bare-old".to_owned(), "empty-labels".to_owned()]
        );
        assert_eq!(hook.last_sequence, 1);
        let requests = setup.server.received_requests().await.unwrap();
        let history = requests
            .iter()
            .find(|request| request.url.path() == HISTORY_PATH)
            .unwrap();
        let pairs: Vec<_> = history.url.query_pairs().collect();
        assert!(
            pairs
                .iter()
                .any(|(key, value)| key == "labelId" && value == "INBOX")
        );
        assert!(
            pairs
                .iter()
                .any(|(key, value)| key == "historyTypes" && value == "messageAdded")
        );
        assert!(
            !requests
                .iter()
                .any(|request| request.url.path() == PROFILE_PATH)
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn history_messages_with_another_label_are_skipped() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "historyId": "160",
                "history": [{
                    "messagesAdded": [
                        { "message": { "id": "sent-only", "threadId": "t1", "labelIds": ["SENT"] } },
                        { "message": { "id": "spam", "threadId": "t2", "labelIds": ["SPAM", "UNREAD"] } }
                    ]
                }]
            })))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        let stored = GmailPosition::parse(hook.position.as_deref()).unwrap();
        assert_eq!(stored.history_id, 160);
        assert_eq!(stored.recent, Vec::<String>::new());
        assert_eq!(hook.last_sequence, 0);
        let paths: Vec<_> = setup
            .server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|request| request.url.path().to_owned())
            .collect();
        assert!(!paths.iter().any(|path| path.contains("/messages/")));
        assert!(!paths.iter().any(|path| path == PROFILE_PATH));
        let extra =
            tokio::time::timeout(Duration::from_millis(200), setup.receiver.requests.recv()).await;
        assert!(
            extra.is_err(),
            "explicit non-inbox labels must not publish an event: {extra:?}"
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_running_catch_up_keeps_one_pending_rerun() {
        let setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "historyId": "100", "history": [] }))
                    .set_delay(Duration::from_millis(400)),
            )
            .mount(&setup.server)
            .await;

        setup.watchers.schedule_gmail_catch_up(&setup.account);
        harness::wait_for_requests(&setup.server, "GET", HISTORY_PATH, 1).await;
        for _ in 0..30 {
            setup.watchers.schedule_gmail_catch_up(&setup.account);
        }
        harness::wait_for_requests(&setup.server, "GET", HISTORY_PATH, 2).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            harness::requests(&setup.server, "GET", HISTORY_PATH).await,
            2,
            "a burst during a running catch-up schedules one rerun, not one task each"
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn a_disallowed_account_does_not_watch_or_renew() {
        let setup = harness::provider_setup_with(
            Provider::Gmail,
            Some(vec!["other@example.com".to_owned()]),
        )
        .await;
        let subscription = PushSubscription {
            provider: Provider::Gmail,
            subscription_id: None,
            client_state_hash: None,
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
            "a disallowed account must not start, renew, or refresh a token"
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

    async fn set_webhook_enabled(setup: &harness::ProviderSetup, enabled: bool) {
        let mut hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        hook.settings.enabled = enabled;
        setup
            .store
            .save_webhook(&setup.account, &hook.settings)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn replacement_watcher_waits_until_gmail_stop_finishes() {
        let setup = provider_setup(Provider::Gmail).await;
        set_webhook_enabled(&setup, false).await;
        // A stored watch is what makes the disabled session call users.stop.
        setup
            .store
            .save_push_subscription(
                &setup.account,
                &PushSubscription {
                    provider: Provider::Gmail,
                    subscription_id: None,
                    client_state_hash: None,
                    expires_at: 1,
                },
            )
            .await
            .unwrap();
        // Gmail answers users.stop this long after it arrives, so a watch
        // that waits for that answer arrives at least this long after it.
        let stop_delay = Duration::from_millis(1500);
        let (stopped, watched) = (Arc::new(OnceLock::new()), Arc::new(OnceLock::new()));
        let stop = Arc::clone(&stopped);
        Mock::given(method("POST"))
            .and(path(STOP_PATH))
            .respond_with(move |_: &wiremock::Request| {
                stop.get_or_init(Instant::now);
                ResponseTemplate::new(204).set_delay(stop_delay)
            })
            .expect(1)
            .mount(&setup.server)
            .await;
        let watch = Arc::clone(&watched);
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(move |_: &wiremock::Request| {
                watch.get_or_init(Instant::now);
                ResponseTemplate::new(200).set_body_json(watch_response("42"))
            })
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "POST", STOP_PATH, 1).await;

        // Re-enable while users.stop is still in flight. The replacement
        // must not call users.watch until that stop has finished.
        set_webhook_enabled(&setup, true).await;
        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 1).await;
        let gap = watched
            .get()
            .unwrap()
            .duration_since(*stopped.get().unwrap());
        assert!(
            gap >= stop_delay,
            "the replacement watcher started before users.stop finished: {gap:?}"
        );

        let stored = async || setup.store.push_subscription(&setup.account).await.unwrap();
        harness::until(async || stored().await.is_some()).await;
        let stored = stored().await.unwrap();
        assert!(
            stored.expires_at > 1,
            "users.stop deleted the replacement watch"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        let still = setup.store.push_subscription(&setup.account).await.unwrap();
        assert!(
            still.is_some(),
            "a late users.stop deleted the replacement watch"
        );
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1
        );
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 1);
        harness::finish(&setup).await;
    }

    /// Deleting the account stops its watcher, waits for the session that
    /// is creating the watch, and then stops that watch and forgets it.
    #[tokio::test]
    async fn deleting_the_account_stops_the_gmail_watch_being_created() {
        let setup = provider_setup(Provider::Gmail).await;
        let slow = Duration::from_millis(300);
        let watch = ResponseTemplate::new(200).set_body_json(watch_response("42"));
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(watch.set_delay(slow))
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(path(STOP_PATH))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&setup.server)
            .await;
        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 1).await;

        let limit = Duration::from_secs(10);
        setup
            .watchers
            .unsubscribe_before_delete(&setup.account, limit)
            .await;
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 1);
        let stored = setup.store.push_subscription(&setup.account).await;
        assert_eq!(stored.unwrap(), None);
        assert_eq!(setup.watchers.running(), 0);
        harness::finish(&setup).await;
    }

    /// A session stuck in a slow call and a provider that does not answer
    /// hold deleting the account up for `limit` at most, and the watch is
    /// still stopped at Gmail.
    #[tokio::test]
    async fn deleting_the_account_waits_for_a_slow_session_or_provider_only_so_long() {
        let setup = provider_setup(Provider::Gmail).await;
        let stored = PushSubscription {
            provider: Provider::Gmail,
            subscription_id: None,
            client_state_hash: None,
            expires_at: postkeep_store::now() + 3600,
        };
        setup
            .store
            .save_push_subscription(&setup.account, &stored)
            .await
            .unwrap();
        let watch = ResponseTemplate::new(200).set_body_json(watch_response("42"));
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(watch.set_delay(Duration::from_secs(3)))
            .mount(&setup.server)
            .await;
        let stop = ResponseTemplate::new(204).set_delay(Duration::from_secs(3));
        Mock::given(method("POST"))
            .and(path(STOP_PATH))
            .respond_with(stop)
            .expect(1)
            .mount(&setup.server)
            .await;
        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 1).await;

        let started = std::time::Instant::now();
        let limit = Duration::from_millis(400);
        setup
            .watchers
            .unsubscribe_before_delete(&setup.account, limit)
            .await;
        let took = started.elapsed();
        assert!(took < Duration::from_secs(2), "{took:?}");
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 1);
        harness::finish(&setup).await;
    }

    /// A `users.watch` that Gmail answers after the account's deletion
    /// committed ends the watcher's run as an account that is gone does, and
    /// is not counted as a failure.
    #[tokio::test]
    async fn a_watch_behind_the_accounts_deletion_ends_the_run() {
        let setup = provider_setup(Provider::Gmail).await;
        let metrics = crate::metrics::Metrics::default();
        setup.watchers.set_metrics(metrics.clone());
        store_position(&setup, 1).await;
        let watch = ResponseTemplate::new(200).set_body_json(watch_response("42"));
        let (mut hold, responder) = Hold::new(watch);
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(responder)
            .mount(&setup.server)
            .await;
        let (watchers, account) = (setup.watchers.clone(), setup.account.clone());
        let mut run = tokio::spawn(async move {
            let (mut failures, mut rejections) = (0, 0);
            let cancel = CancellationToken::new();
            watchers
                .run_once(&account, &cancel, &mut failures, &mut rejections)
                .await
        });
        hold.arrived_before(&mut run).await;
        assert!(setup.store.delete_account(&setup.account).await.unwrap());
        hold.release();
        let ended = run.await.unwrap();
        assert!(matches!(ended, Ok(Exit::Disabled)), "{:?}", ended.err());
        let rendered = metrics.render();
        assert!(!rendered.contains("provider=\"gmail\""), "{rendered}");
        harness::finish(&setup).await;
    }

    /// A paused webhook keeps renewing `users.watch`, holds its slot, and
    /// records a push. The new mail is not delivered before the pause
    /// interval, and the pause does not call Gmail again.
    #[tokio::test]
    async fn a_paused_gmail_webhook_keeps_renewing_and_records_without_delivering() {
        let mut setup = provider_setup(Provider::Gmail).await;
        harness::pause_webhook(&setup).await;
        store_position(&setup, 100).await;
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(watch_response("150")))
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(history_body("150", "paused-a", None)),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(history_body("160", "paused-b", None)),
            )
            .with_priority(2)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/paused-a")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body("paused-a")))
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/paused-b")))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata_body("paused-b")))
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        harness::wait_for_sequence(&setup, 1).await;
        assert_eq!(
            setup.watchers.running(),
            1,
            "a paused webhook keeps its watcher slot"
        );
        assert!(
            setup
                .store
                .push_subscription(&setup.account)
                .await
                .unwrap()
                .is_some(),
            "the Gmail watch is still stored"
        );
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1
        );
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 0);

        // A push while paused records the next message and does not deliver.
        setup.watchers.schedule_gmail_catch_up(&setup.account);
        harness::wait_for_sequence(&setup, 2).await;
        let early =
            tokio::time::timeout(Duration::from_millis(300), setup.receiver.requests.recv()).await;
        assert!(
            early.is_err(),
            "paused mail was delivered before the pause interval: {early:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1,
            "a pause must not renew users.watch in a loop"
        );
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 0);
        assert_eq!(
            harness::requests(&setup.server, "GET", HISTORY_PATH).await,
            2
        );
        assert_eq!(setup.watchers.running(), 1);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert!(hook.is_paused());
        assert!(hook.settings.enabled);
        assert_eq!(hook.last_sequence, 2);
        assert_eq!(hook.delivered_sequence, 0);
        harness::finish(&setup).await;
    }

    /// A first start with no other watcher stores the position `users.watch`
    /// gave and reads no history: the mail already there is old.
    #[tokio::test]
    async fn a_first_start_stores_the_watch_history_id_and_reads_no_history() {
        let setup = provider_setup(Provider::Gmail).await;
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(watch_response("500")))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        let hook = async || setup.store.webhook(&setup.account).await.unwrap().unwrap();
        harness::until(async || hook().await.position.is_some()).await;
        let stored = stored_position(&setup).await;
        assert_eq!((stored.history_id, stored.recent), (500, Vec::new()));
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            harness::requests(&setup.server, "GET", HISTORY_PATH).await,
            0
        );
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1
        );
        harness::finish(&setup).await;
    }

    /// Another watcher stores a position while the first `users.watch` of this
    /// session is answered. The session keeps it and reports the mail after it
    /// at once, instead of moving the position to now.
    #[tokio::test]
    async fn a_first_start_keeps_a_position_another_watcher_stored() {
        let mut setup = provider_setup(Provider::Gmail).await;
        let watch = ResponseTemplate::new(200).set_body_json(watch_response("500"));
        let (mut hold, responder) = Hold::new(watch);
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(responder)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .and(query_param("startHistoryId", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(history_of("150", &["raced"])))
            .expect(1)
            .mount(&setup.server)
            .await;
        mount_message(&setup.server, message_with("raced", at(1), &[]), 1).await;

        setup.watchers.refresh(&setup.account);
        // The session read no position and waits for users.watch.
        hold.arrived().await;
        store_position(&setup, 100).await;
        hold.release();

        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.raced");
        let stored = stored_position(&setup).await;
        assert_eq!((stored.history_id, stored.recent), (150, ids(&["raced"])));
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1
        );
        harness::finish(&setup).await;
    }

    /// Every first start loses the position, as when other watchers keep moving
    /// it first. The watcher waits longer before each new session, 20 ms and
    /// then twice as long each time, so 20 + 40 + 80 + 160 + 320 ms pass from
    /// its first `users.watch` to its sixth.
    #[tokio::test]
    async fn a_first_start_that_keeps_losing_the_position_waits_longer_each_time() {
        let setup = provider_setup(Provider::Gmail).await;
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(watch_response("500")))
            .mount(&setup.server)
            .await;
        let refuse = "CREATE TRIGGER refuse BEFORE UPDATE ON webhooks \
                      BEGIN SELECT RAISE(IGNORE); END";
        let pool = setup.store.pool();
        sqlx::query(refuse).execute(pool).await.unwrap();

        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 1).await;
        let first = std::time::Instant::now();
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 6).await;
        let waited = first.elapsed();
        let doubling = Duration::from_millis(400);
        assert!(waited >= doubling, "{waited:?} to the sixth watch");
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.position, None);
        harness::finish(&setup).await;
    }

    /// The user turning a paused webhook off, through the store call the
    /// MCP tool uses and the same notification as the account page, stops
    /// `users.watch`, drops the local watch, and frees the slot.
    #[tokio::test]
    async fn disabling_a_gmail_webhook_stops_the_watch_and_frees_the_slot() {
        let setup = provider_setup(Provider::Gmail).await;
        harness::pause_webhook(&setup).await;
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(watch_response("42")))
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(path(STOP_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(&setup.account);
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 1).await;
        let watched = async || setup.store.push_subscription(&setup.account).await.unwrap();
        harness::until(async || setup.watchers.running() == 1 && watched().await.is_some()).await;

        harness::disable_webhook_like_mcp(&setup).await;
        harness::until(async || setup.watchers.running() == 0 && watched().await.is_none()).await;
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 1);
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(setup.watchers.running(), 0);
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1,
            "a disabled webhook must not keep renewing"
        );
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 1);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert!(!hook.settings.enabled);
        assert!(hook.paused_at.is_none());
        harness::finish(&setup).await;
    }

    /// A history answer that adds `ids`, oldest first.
    fn history_of(history_id: &str, ids: &[&str]) -> serde_json::Value {
        let added = |id: &&str| json!({ "message": { "id": id, "labelIds": ["INBOX"] } });
        let added: Vec<_> = ids.iter().map(added).collect();
        json!({ "historyId": history_id, "history": [{ "messagesAdded": added }] })
    }

    /// A metadata answer with these headers.
    fn message_with(id: &str, ms: i64, headers: &[(&str, &str)]) -> serde_json::Value {
        let header = |(name, value): &(&str, &str)| json!({ "name": name, "value": value });
        let headers: Vec<_> = headers.iter().map(header).collect();
        json!({ "id": id, "internalDate": ms.to_string(), "payload": { "headers": headers } })
    }

    /// The time of the `n`th message of a test, in Unix milliseconds: all after `SINCE_MS`.
    const fn at(n: i64) -> i64 {
        SINCE_MS + n * 100_000
    }

    async fn mount_history(server: &MockServer, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(server)
            .await;
    }

    /// Answers `body` to a read of the message it describes, which should come `reads` times.
    async fn mount_message(server: &MockServer, body: serde_json::Value, reads: u64) {
        let at = format!("{LIST_PATH}/{}", body["id"].as_str().unwrap());
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(reads)
            .mount(server)
            .await;
    }

    /// Reads of the message `id`.
    async fn reads_of(server: &MockServer, id: &str) -> usize {
        harness::requests(server, "GET", &format!("{LIST_PATH}/{id}")).await
    }

    async fn stored_position(setup: &harness::ProviderSetup) -> GmailPosition {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        GmailPosition::parse(hook.position.as_deref()).unwrap()
    }

    fn ids(names: &[&str]) -> Vec<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    /// Without rules a pass reads one message, the newest, which describes the
    /// event, and the others are counted without a request.
    #[tokio::test]
    async fn without_rules_only_the_newest_message_is_read() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        mount_history(&setup.server, history_of("150", &["a", "b", "c"])).await;
        for (n, id) in [(1, "a"), (2, "b")] {
            mount_message(&setup.server, message_with(id, at(n), &[]), 0).await;
        }
        let headers = [("From", "sender@example.com"), ("Subject", "Hello")];
        mount_message(&setup.server, message_with("c", at(3), &headers), 1).await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.c");
        assert_eq!(got.json()["count"], 3);
        let stored = stored_position(&setup).await;
        assert_eq!(
            (stored.since_ms, stored.recent),
            (at(3), ids(&["a", "b", "c"]))
        );
        // The read asks for the recipients too.
        let requests = setup.server.received_requests().await.unwrap();
        let read = requests
            .iter()
            .find(|r| r.url.path().ends_with("/c"))
            .unwrap();
        let asked: Vec<_> = read
            .url
            .query_pairs()
            .filter(|(k, _)| k == "metadataHeaders")
            .collect();
        assert!(asked.iter().any(|(_, v)| v == "To") && asked.iter().any(|(_, v)| v == "Cc"));
        harness::finish(&setup).await;
    }

    /// The newest message is gone, so the one before it describes the event.
    #[tokio::test]
    async fn without_rules_a_newest_message_that_is_gone_is_skipped() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        mount_history(&setup.server, history_of("150", &["a", "b", "c"])).await;
        mount_message(&setup.server, message_with("a", at(1), &[]), 0).await;
        mount_message(
            &setup.server,
            message_with("b", at(2), &[("Subject", "Hi")]),
            1,
        )
        .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/c")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.b");
        assert_eq!(got.json()["count"], 3);
        assert_eq!(
            reads_of(&setup.server, "c").await,
            1,
            "a missing message is asked for once"
        );
        harness::finish(&setup).await;
    }

    /// Three new messages, two of which pass: one by its `From` and one only
    /// through `Cc`. The newest does not: the usage hook lets two rules count,
    /// so the third, which it matches, judges nothing. Each is read, the event
    /// counts the two and describes the newer, and the position covers all three.
    #[tokio::test]
    async fn with_rules_every_new_message_is_read_and_judged() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        setup.watchers.set_usage_hook(harness::FilterLimit::new(2));
        let (store, id) = (&setup.store, &setup.account);
        harness::allow(store, id, "from", "equals", "boss@example.com").await;
        harness::allow(store, id, "to", "equals", "team@example.com").await;
        harness::allow(store, id, "subject", "equals", "Offer").await;
        mount_history(&setup.server, history_of("150", &["a", "b", "c"])).await;
        let a = [("From", "The Boss <boss@example.com>"), ("Subject", "Plan")];
        let b = [
            ("From", "other@example.com"),
            ("To", "me@example.com"),
            ("Cc", "Team <team@example.com>"),
        ];
        let c = [("From", "stranger@example.com"), ("Subject", "Offer")];
        mount_message(&setup.server, message_with("a", at(1), &a), 1).await;
        mount_message(&setup.server, message_with("b", at(2), &b), 1).await;
        mount_message(&setup.server, message_with("c", at(3), &c), 1).await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.b");
        assert_eq!(got.json()["count"], 2);
        let stored = stored_position(&setup).await;
        assert_eq!(stored.history_id, 150);
        assert_eq!(
            (stored.since_ms, stored.recent),
            (at(3), ids(&["a", "b", "c"]))
        );
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 1);
        harness::finish(&setup).await;
    }

    /// None of the new messages passes: the position moves past them with no event.
    #[tokio::test]
    async fn a_pass_none_of_whose_messages_passes_moves_the_position_without_an_event() {
        let setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(
            &setup.store,
            &setup.account,
            "from",
            "equals",
            "boss@example.com",
        )
        .await;
        mount_history(&setup.server, history_of("150", &["a", "b", "c"])).await;
        for (n, id) in [(1, "a"), (2, "b"), (3, "c")] {
            let body = message_with(id, at(n), &[("From", "stranger@example.com")]);
            mount_message(&setup.server, body, 1).await;
        }

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let stored = stored_position(&setup).await;
        assert_eq!(stored.history_id, 150);
        assert_eq!(
            (stored.since_ms, stored.recent),
            (at(3), ids(&["a", "b", "c"]))
        );
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!((hook.last_sequence, hook.delivered_sequence), (0, 0));
        harness::finish(&setup).await;
    }

    /// Another watcher moves the position while the pass reads, and nothing passes:
    /// the position stays where that watcher put it, and the rerun, which reads from
    /// there, finds nothing new.
    #[tokio::test]
    async fn a_position_moved_while_nothing_passes_is_not_moved_back() {
        let setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(
            &setup.store,
            &setup.account,
            "from",
            "equals",
            "boss@example.com",
        )
        .await;
        // The listing is held, so the other watcher moves the position while
        // this pass waits for it. The rerun reads an empty history.
        let answer = ResponseTemplate::new(200).set_body_json(history_of("150", &["raced"]));
        let (mut hold, responder) = Hold::new(answer);
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(responder)
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "historyId": "200", "history": [] })),
            )
            .with_priority(2)
            .mount(&setup.server)
            .await;
        let stranger = [("From", "stranger@example.com")];
        mount_message(&setup.server, message_with("raced", at(1), &stranger), 1).await;
        let moved = GmailPosition {
            history_id: 200,
            since_ms: at(9),
            recent: ids(&["other"]),
        }
        .encode();
        let mut run = pin!(setup.watchers.gmail_catch_up(&setup.account));
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

        harness::wait_for_requests(&setup.server, "GET", HISTORY_PATH, 2).await;
        harness::until(async || !setup.watchers.catch_up_running(&setup.account)).await;
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.position.as_deref(), Some(moved.as_str()));
        assert_eq!(hook.last_sequence, 0);
        harness::finish(&setup).await;
    }

    /// Rules this version can't read hold the mail: Gmail is not asked, nothing is
    /// recorded, and the position stays.
    #[tokio::test]
    async fn rules_that_cannot_be_read_hold_the_mail_without_asking_gmail() {
        let setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(&setup.store, &setup.account, "body", "contains", "x").await;
        let before = stored_position(&setup).await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(history_of("150", &["a"])))
            .expect(0)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        assert_eq!(
            harness::requests(&setup.server, "GET", HISTORY_PATH).await,
            0
        );
        assert_eq!(stored_position(&setup).await, before);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0);
        harness::finish(&setup).await;
    }

    /// One read answers 500 once. It is tried again, and the pass is whole.
    #[tokio::test]
    async fn a_read_that_fails_once_is_tried_again() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(&setup.store, &setup.account, "subject", "contains", "Hello").await;
        mount_history(&setup.server, history_of("150", &["a", "b", "c"])).await;
        let hello = [("Subject", "Hello")];
        mount_message(&setup.server, message_with("a", at(1), &hello), 1).await;
        mount_message(&setup.server, message_with("c", at(3), &hello), 1).await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/b")))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/b")))
            .respond_with(ResponseTemplate::new(200).set_body_json(message_with(
                "b",
                at(2),
                &hello,
            )))
            .with_priority(2)
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.c");
        assert_eq!(got.json()["count"], 3);
        assert_eq!(reads_of(&setup.server, "b").await, 2);
        harness::finish(&setup).await;
    }

    /// Gmail's per-user rate limit, a 403 with the reason `userRateLimitExceeded`
    /// (the sample in Google's guide "Resolve errors"), is tried again like a 429,
    /// and the pass is whole.
    #[tokio::test]
    async fn a_read_gmail_rate_limits_with_a_403_is_tried_again() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(&setup.store, &setup.account, "subject", "contains", "Hello").await;
        mount_history(&setup.server, history_of("150", &["b"])).await;
        let limited = json!({ "error": {
            "errors": [{
                "domain": "usageLimits",
                "reason": "userRateLimitExceeded",
                "message": "User Rate Limit Exceeded"
            }],
            "code": 403,
            "message": "User Rate Limit Exceeded"
        }});
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/b")))
            .respond_with(ResponseTemplate::new(403).set_body_json(limited))
            .up_to_n_times(1)
            .with_priority(1)
            .expect(1)
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/b")))
            .respond_with(ResponseTemplate::new(200).set_body_json(message_with(
                "b",
                at(2),
                &[("Subject", "Hello")],
            )))
            .with_priority(2)
            .expect(1)
            .mount(&setup.server)
            .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.b");
        assert_eq!(reads_of(&setup.server, "b").await, 2);
        harness::finish(&setup).await;
    }

    /// A read that keeps answering 500 is tried three more times, after 250 ms, 1 s
    /// and 4 s, and then fails the pass, which stores nothing. The messages after it
    /// are not read.
    #[tokio::test]
    async fn a_read_that_keeps_failing_fails_the_pass() {
        let setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(&setup.store, &setup.account, "subject", "contains", "Hello").await;
        mount_history(&setup.server, history_of("150", &["a", "b", "c"])).await;
        let hello = [("Subject", "Hello")];
        mount_message(&setup.server, message_with("a", at(1), &hello), 1).await;
        mount_message(&setup.server, message_with("c", at(3), &hello), 0).await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/b")))
            .respond_with(ResponseTemplate::new(500))
            .expect(4)
            .mount(&setup.server)
            .await;
        let before = stored_position(&setup).await;

        let started = std::time::Instant::now();
        let err = setup
            .watchers
            .gmail_catch_up(&setup.account)
            .await
            .unwrap_err();
        assert!(
            matches!(err, WatchError::Api(_)) && crate::watch::is_transient(&err),
            "{err:?}"
        );
        let waited = started.elapsed();
        assert!(waited >= Duration::from_millis(5_250), "{waited:?}");
        assert_eq!(reads_of(&setup.server, "b").await, 4);
        assert_eq!(stored_position(&setup).await, before);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.last_sequence, 0);
        harness::finish(&setup).await;
    }

    /// A message that is gone is asked for once, not tried again, and is not judged.
    #[tokio::test]
    async fn with_rules_a_message_that_is_gone_is_skipped() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(&setup.store, &setup.account, "subject", "contains", "Hello").await;
        mount_history(&setup.server, history_of("150", &["a", "b"])).await;
        Mock::given(method("GET"))
            .and(path(format!("{LIST_PATH}/a")))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&setup.server)
            .await;
        mount_message(
            &setup.server,
            message_with("b", at(2), &[("Subject", "Hello")]),
            1,
        )
        .await;

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.b");
        assert_eq!(got.json()["count"], 1);
        assert_eq!(reads_of(&setup.server, "a").await, 1);
        harness::finish(&setup).await;
    }

    /// More new messages than a batch: all are read, so the oldest, the only one
    /// that passes, is not hidden behind the newer ones.
    #[tokio::test]
    async fn with_rules_more_than_a_batch_is_judged() {
        let mut setup = provider_setup(Provider::Gmail).await;
        store_position(&setup, 100).await;
        harness::allow(&setup.store, &setup.account, "subject", "equals", "Wanted").await;
        let names: Vec<String> = (0..61).map(|n| format!("m{n:02}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        mount_history(&setup.server, history_of("150", &refs)).await;
        for (n, name) in (1..).zip(&refs) {
            let subject = if n == 1 { "Wanted" } else { "Other" };
            mount_message(
                &setup.server,
                message_with(name, at(n), &[("Subject", subject)]),
                1,
            )
            .await;
        }

        setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
        let got = harness::next_event(&mut setup.receiver).await;
        assert_eq!(got.json()["id"], "gmail.m00");
        assert_eq!(got.json()["count"], 1);
        let stored = stored_position(&setup).await;
        assert_eq!((stored.since_ms, stored.recent), (at(61), names));
        harness::finish(&setup).await;
    }

    /// Rules that allow only `allowed@example.com` by `field`.
    fn allowing(field: Field, address: &str) -> Rules {
        let rule = Rule {
            action: Action::Allow,
            field,
            kind: Kind::Equals,
            pattern: address.to_owned(),
        };
        Rules::On(Arc::new(CompiledRules::new(&[rule], 10).unwrap()))
    }

    fn metadata_of(headers: &[(&str, &str)]) -> Metadata {
        serde_json::from_value(message_with("x", at(1), headers)).unwrap()
    }

    /// A value cannot add a header: a `From` hidden in the subject is not the sender.
    #[tokio::test]
    async fn a_header_value_cannot_add_a_header() {
        let rules = allowing(Field::From, "allowed@example.com");
        let injected = "x\r\nFrom: allowed@example.com";
        let message = metadata_of(&[
            ("Subject", injected),
            ("To", "me@example.com\nFrom: allowed@example.com"),
        ]);
        assert_eq!(message.fields().from, "");
        assert!(rules.keep(vec![message]).await.is_empty());
        let message = metadata_of(&[
            ("From", "Allowed <allowed@example.com>"),
            ("Subject", injected),
        ]);
        assert_eq!(
            rules.keep(vec![message]).await.len(),
            1,
            "the real sender passes"
        );
    }

    /// Of repeated `From` headers the event shows the first, whole and marked, and the rules
    /// judge it.
    #[tokio::test]
    async fn the_first_of_repeated_from_headers_is_judged() {
        let rules = allowing(Field::From, "allowed@example.com");
        let headers = [
            ("From", "attacker@example.net"),
            ("From", "allowed@example.com"),
        ];
        let message = metadata_of(&headers);
        assert_eq!(message.fields().from, "attacker@example.net");
        let event = new_mail_event("me@example.com", &message, 1);
        assert_eq!(event.from.as_deref(), Some("attacker@example.net"));
        assert!(event.from_unclear);
        assert!(rules.keep(vec![message]).await.is_empty());
    }

    /// Allow rules judge the sender's address only when the message has one
    /// `From` and its value is that one address, alone or after a name.
    #[tokio::test]
    async fn allow_rules_judge_a_sender_address_only_when_it_is_clear() {
        let rules = allowing(Field::FromDomain, "x.test");
        let cases = [
            ("alice@x.test", true),
            ("Alice <alice@x.test>", true),
            ("=?UTF-8?Q?=3Ca=40y.test=3E?= <alice@x.test>", true),
            ("<a@y.test> <alice@x.test>", false),
            ("<a@y.test> alice@x.test", false),
            ("a@y.test (b) <alice@x.test>", false),
            ("(\") <a@y.test> <alice@x.test>", false),
            ("a@y.test alice@x.test", false),
            ("boss@y.test@x.test", false),
        ];
        for (from, passes) in cases {
            let kept = rules.keep(vec![metadata_of(&[("From", from)])]).await;
            assert_eq!(kept.len(), usize::from(passes), "{from:?}");
        }
        let twice = metadata_of(&[("From", "alice@x.test"), ("From", "a@y.test")]);
        assert!(rules.keep(vec![twice]).await.is_empty(), "two From headers");
    }

    /// Block rules judge each address a mail app may show as the sender: every address in each
    /// `From` value of a sender that is not clear.
    #[tokio::test]
    async fn block_rules_judge_each_address_a_mail_app_may_show_as_the_sender() {
        let rule = Rule {
            action: Action::Block,
            field: Field::FromDomain,
            kind: Kind::Domain,
            pattern: "y.test".to_owned(),
        };
        let rules = Rules::On(Arc::new(CompiledRules::new(&[rule], 10).unwrap()));
        let padded = format!("\"{}\" <news@y.test> other@x.test", "@".repeat(100));
        let cases: [(&[(&str, &str)], usize); 11] = [
            (&[("From", "<news@y.test> other@x.test")], 0),
            (&[("From", "news @ y.test")], 0),
            (&[("From", "<news @ y.test> other@x.test")], 0),
            (&[("From", "news@\r\n y.test")], 0),
            (&[("From", "other@x.test, news@y.test")], 0),
            (&[("From", "other@x.test (news@y.test)")], 0),
            (&[("From", "boss@y.test@x.test")], 0),
            (&[("From", "other@x.test"), ("From", "news@y.test")], 0),
            (
                &[
                    ("From", "a@x.test"),
                    ("From", "news@y.test"),
                    ("From", "b@x.test"),
                ],
                0,
            ),
            (&[("From", padded.as_str())], 0),
            (&[("From", "\"news@y.test\" <other@x.test>")], 1),
        ];
        for (headers, kept) in cases {
            let message = metadata_of(headers);
            assert_eq!(rules.keep(vec![message]).await.len(), kept, "{headers:?}");
        }
    }

    #[test]
    fn events_filter_invisible_characters() {
        let message = metadata_of(&[
            ("From", "B\u{200B}ank <bo\u{200B}ss@x.test>"),
            ("Subject", "Plans\u{E0068}"),
            ("Message-ID", "<a\u{200B}b@x.test>"),
        ]);
        let event = new_mail_event("me@example.com", &message, 1);
        assert_eq!(event.message_id.as_deref(), Some("ab@x.test"));
        assert_eq!(event.from.as_deref(), Some("Bank <bo\\u{200b}ss@x.test>"));
        assert!(!event.from_unclear);
        assert_eq!(event.subject.as_deref(), Some("Plans"));
    }

    /// The event shows the first `From` value as one address with its name when
    /// it reads as one, and otherwise whole, with its brackets as escapes.
    #[test]
    fn an_event_shows_one_sender_address_or_the_whole_value() {
        let cases = [
            (
                "\"Alice <x>\" <news@example.net>",
                Some("\"Alice \\u{3c}x\\u{3e}\" \\u{3c}news@example.net\\u{3e}"),
            ),
            (
                "\"A \\\" <x> <y>\" <news@example.net>",
                Some("\"A \\\" \\u{3c}x\\u{3e} \\u{3c}y\\u{3e}\" \\u{3c}news@example.net\\u{3e}"),
            ),
            (
                "\u{2764}\u{FE0F} Shop <shop@example.net>",
                Some("\u{2764}\u{FE0F} Shop <shop@example.net>"),
            ),
            (
                "=?UTF-8?Q?Caf=C3=A9?= <cafe@example.net>",
                Some("Caf\u{00E9} <cafe@example.net>"),
            ),
            (
                "Alice <alice@x.test> <news@x.test>",
                Some("Alice \\u{3c}alice@x.test\\u{3e} \\u{3c}news@x.test\\u{3e}"),
            ),
            (
                "Bank <news@x.test\u{3009}\u{3008}bank@x.test>",
                Some("Bank \\u{3c}news@x.test\\u{3009}\\u{3008}bank@x.test\\u{3e}"),
            ),
            (
                "Shop \u{2039}shop@example.com\u{203A}, <news@x.test>",
                Some("Shop \\u{2039}shop@example.com\\u{203a}, \\u{3c}news@x.test\\u{3e}"),
            ),
            (
                "<a@y.test> alice@x.test",
                Some("\\u{3c}a@y.test\\u{3e} alice@x.test"),
            ),
            (
                "(\") <a@y.test> <alice@x.test>",
                Some("(\") \\u{3c}a@y.test\\u{3e} \\u{3c}alice@x.test\\u{3e}"),
            ),
            ("alice@x.test (Alice)", Some("alice@x.test (Alice)")),
            ("a@x.test, b@x.test", Some("a@x.test, b@x.test")),
            ("Undisclosed", Some("Undisclosed")),
            (" ", None),
        ];
        for (from, shown) in cases {
            let event = new_mail_event("me@example.com", &metadata_of(&[("From", from)]), 1);
            assert_eq!(event.from.as_deref(), shown, "{from:?}");
        }
    }

    /// Every `To` and `Cc` address counts, in however many headers they came.
    #[tokio::test]
    async fn every_to_and_cc_address_is_judged() {
        let headers = [
            ("To", "One <one@example.com>"),
            ("To", "two@example.com, Three <three@example.com>"),
            ("Cc", "four@example.com"),
            ("Cc", "five@example.com, Six <six@example.com>"),
        ];
        for address in [
            "one@example.com",
            "two@example.com",
            "three@example.com",
            "four@example.com",
            "five@example.com",
            "six@example.com",
        ] {
            let rules = allowing(Field::To, address);
            let kept = rules.keep(vec![metadata_of(&headers)]).await;
            assert_eq!(kept.len(), 1, "{address}");
        }
        let rules = allowing(Field::To, "seven@example.com");
        assert!(rules.keep(vec![metadata_of(&headers)]).await.is_empty());
    }

    /// The event names the sender and the subject when the webhook says so, and
    /// does not otherwise.
    #[tokio::test]
    async fn an_event_names_the_sender_only_when_the_webhook_says_so() {
        for include_sender in [true, false] {
            let mut setup = provider_setup(Provider::Gmail).await;
            store_position(&setup, 100).await;
            let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
            let settings = postkeep_store::WebhookSettings {
                include_sender,
                ..hook.settings
            };
            let saved = setup.store.save_webhook(&setup.account, &settings);
            saved.await.unwrap();
            mount_history(&setup.server, history_of("150", &["a"])).await;
            let headers = [
                ("From", "Sender <sender@example.com>"),
                ("Subject", "Lunch"),
            ];
            mount_message(&setup.server, message_with("a", at(1), &headers), 1).await;

            setup.watchers.gmail_catch_up(&setup.account).await.unwrap();
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

    /// Header names are matched in any case: `fRoM` is the `From` header.
    #[tokio::test]
    async fn header_names_are_matched_in_any_case() {
        let message = metadata_of(&[
            ("fRoM", "Alice <alice@example.com>"),
            ("TO", "bob@example.com"),
            ("cC", "carol@example.com"),
            ("sUBJECT", "Invoice"),
        ]);
        let fields = message.fields();
        assert_eq!(fields.from, "alice@example.com");
        assert_eq!(fields.to, ["bob@example.com", "carol@example.com"]);
        assert_eq!(fields.subject, "Invoice");
    }

    /// An encoded subject is judged as the text it stands for. A subject the
    /// parser reads as nothing, blanks for one, is judged as Gmail gave it.
    #[tokio::test]
    async fn an_encoded_subject_is_judged_decoded() {
        let rules = allowing(Field::Subject, "Invoice");
        let message = metadata_of(&[("Subject", "=?UTF-8?B?SW52b2ljZQ==?=")]);
        assert_eq!(message.fields().subject, "Invoice");
        assert_eq!(rules.keep(vec![message]).await.len(), 1);
        let blank = metadata_of(&[("From", "a@example.com"), ("Subject", "  ")]);
        assert_eq!(blank.fields().subject, "  ");
    }

    /// A message with no headers at all, or with blank ones only, is judged with
    /// empty values.
    #[tokio::test]
    async fn a_message_without_headers_is_judged_with_empty_fields() {
        let bare: Metadata = serde_json::from_value(json!({ "id": "x" })).unwrap();
        let blank = metadata_of(&[
            ("To", ""),
            ("To", " "),
            ("Cc", " "),
            ("Cc", ""),
            ("Subject", "  "),
        ]);
        for message in [&bare, &blank] {
            let fields = message.fields();
            let seen = (
                fields.from.as_str(),
                fields.subject.as_str(),
                fields.to.len(),
            );
            assert_eq!(seen, ("", "", 0));
        }
        assert!(
            allowing(Field::Subject, "Invoice")
                .keep(vec![bare])
                .await
                .is_empty()
        );
    }
}
