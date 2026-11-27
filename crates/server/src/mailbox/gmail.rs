//! Gmail mailboxes through the Gmail API.
//!
//! * Labels are shown as folders. The system labels get IMAP-like names
//!   (`INBOX`, `Sent`, `Drafts`, `Trash`, `Spam`, `Starred`) and roles;
//!   `All Mail` searches everything outside Spam and Trash.
//! * Messages are addressed by Gmail's ids, which never change.
//! * Messages are read in `raw` format and parsed with the same parser as
//!   IMAP mail; sending submits MIME, and Gmail files it under Sent.
//! * Moving adds the destination label and takes the message out of the
//!   inbox (and out of Spam or Trash); other labels stay, because Gmail
//!   labels are not exclusive. Permanent deletion needs full mailbox
//!   access (`https://mail.google.com/`), which postkeep does not request.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{Method, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use futures::StreamExt as _;
use postkeep_mail::{
    AttachmentData, EmailAddress, MessageFlags, OutgoingMessage, Paging, Reply, SendOptions,
    SentCopy, SentMessage, mime,
};
use postkeep_store::Provider;
use postkeep_upstream::http::{JSON_LIMIT, MESSAGE_LIMIT, join_segments};
use postkeep_upstream::{ApiClient, ApiError, HttpResponse};
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use super::capabilities::SelectionFilterRules;
use super::graph::{api_error_message, provider_error, provider_message_id, submit_error};
use super::id::{self, GMAIL_PREFIX};
use super::{
    Change, Criteria, Cutoff, DRAFT_UNCONFIRMED, Fetched, FolderEntry, IdsFrom, MailboxError,
    MailboxResult, Mode, Outcome, Page, SENT_NO_ANSWER, SavedDraft, Selected, Selector, SendError,
    Status, Summary, maybe_sent, provider_may_have_acted, provider_outcomes, unanswered,
};

const USER_PATH: &[&str] = &["gmail", "v1", "users", "me"];

/// Matches fetched at most for one search, since Gmail cannot skip.
const MAX_SEARCH_WINDOW: usize = 2000;
/// Message metadata requests in flight at once.
const METADATA_CONCURRENCY: usize = 10;
/// Explicit ids checked before each write.
const ACTION_CHUNK: usize = 50;
/// Name of the pseudo-folder for every message outside Spam and Trash.
const ALL_MAIL: &str = "All Mail";
/// Labels removed by a move, except the destination itself.
const MOVED_OUT: &[&str] = &["INBOX", "SPAM", "TRASH"];

/// System labels shown as folders: label id, display name, role, aliases.
const SYSTEM: &[(&str, &str, Option<&str>, &[&str])] = &[
    ("INBOX", "INBOX", Some("inbox"), &["inbox"]),
    (
        "SENT",
        "Sent",
        Some("sent"),
        &[
            "sent",
            "sent mail",
            "sent messages",
            "sent items",
            "[gmail]/sent mail",
        ],
    ),
    (
        "DRAFT",
        "Drafts",
        Some("drafts"),
        &["drafts", "draft", "[gmail]/drafts"],
    ),
    (
        "TRASH",
        "Trash",
        Some("trash"),
        &[
            "trash",
            "bin",
            "deleted messages",
            "deleted items",
            "[gmail]/trash",
        ],
    ),
    (
        "SPAM",
        "Spam",
        Some("junk"),
        &["spam", "junk", "junk email", "[gmail]/spam"],
    ),
    (
        "STARRED",
        "Starred",
        Some("flagged"),
        &["starred", "flagged", "[gmail]/starred"],
    ),
    (
        "IMPORTANT",
        "Important",
        None,
        &["important", "[gmail]/important"],
    ),
];

/// A Gmail mailbox.
#[derive(Debug)]
pub struct GmailMailbox {
    api: ApiClient,
    email: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Label {
    id: String,
    name: String,
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Labels {
    #[serde(default)]
    labels: Vec<Label>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageList {
    #[serde(default)]
    messages: Vec<MessageRef>,
    next_page_token: Option<String>,
    result_size_estimate: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct MessageRef {
    id: String,
}

#[derive(Debug, Deserialize)]
struct GmailDraft {
    message: Option<MessageRef>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GmailMessage {
    id: String,
    thread_id: Option<String>,
    #[serde(default)]
    label_ids: Vec<String>,
    internal_date: Option<String>,
    size_estimate: Option<u32>,
    payload: Option<Payload>,
    raw: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct LabelChange {
    add_label_ids: Vec<String>,
    remove_label_ids: Vec<String>,
}

impl LabelChange {
    fn already(&self, labels: &[String]) -> bool {
        self.add_label_ids
            .iter()
            .all(|label| labels.contains(label))
            && self
                .remove_label_ids
                .iter()
                .all(|label| !labels.contains(label))
    }
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

/// A resolved folder: a label, or every message.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Folder {
    Label(String),
    AllMail,
}

impl GmailMessage {
    fn flags(&self) -> MessageFlags {
        let has = |label: &str| self.label_ids.iter().any(|id| id == label);
        MessageFlags {
            seen: !has("UNREAD"),
            flagged: has("STARRED"),
            draft: has("DRAFT"),
            ..MessageFlags::default()
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.payload.as_ref().and_then(|payload| {
            payload
                .headers
                .iter()
                .find(|header| header.name.eq_ignore_ascii_case(name))
                .map(|header| header.value.as_str())
        })
    }

    fn summary(&self) -> Summary {
        // When Gmail received it, which its `after:`, `before:` and order go
        // by; the `Date` header only when Gmail gives no such time.
        let date = self
            .internal_date
            .as_deref()
            .and_then(|millis| millis.parse().ok())
            .and_then(chrono::DateTime::from_timestamp_millis)
            .map(|date| date.fixed_offset())
            .or_else(|| {
                let date = self.header("Date")?;
                chrono::DateTime::parse_from_rfc2822(date.trim()).ok()
            });
        let from_values: Vec<String> = self
            .payload
            .iter()
            .flat_map(|payload| &payload.headers)
            .filter(|header| header.name.eq_ignore_ascii_case("From"))
            .map(|header| header.value.clone())
            .collect();
        let from = mime::sender_of_values(&from_values);
        let from_clear = from.is_some();
        Summary {
            id: id::provider_id(GMAIL_PREFIX, &self.id),
            uid: None,
            from,
            from_clear,
            from_values,
            subject: self.header("Subject").map(str::to_owned),
            date,
            flags: self.flags(),
            size: self.size_estimate,
        }
    }
}

/// The operations mirror [`super::Mailbox`], where their errors are
/// documented.
#[allow(
    clippy::missing_errors_doc,
    reason = "the errors are documented on Mailbox"
)]
impl GmailMailbox {
    /// A mailbox for the account behind `api`, whose address is `email`.
    pub const fn new(api: ApiClient, email: String) -> Self {
        Self { api, email }
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut all = USER_PATH.to_vec();
        all.extend_from_slice(segments);
        join_segments(&self.api.endpoints().gmail, &all)
    }

    fn upload_url(&self, segments: &[&str]) -> Url {
        let all = [&["upload"][..], USER_PATH, segments].concat();
        let mut url = join_segments(&self.api.endpoints().gmail, &all);
        url.query_pairs_mut().append_pair("uploadType", "multipart");
        url
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &Url) -> MailboxResult<T> {
        self.api.get_json(url, &[]).await.map_err(gmail_error)
    }

    async fn labels(&self) -> MailboxResult<Vec<Label>> {
        let labels: Labels = self.fetch_json(&self.url(&["labels"])).await?;
        Ok(labels.labels)
    }

    async fn resolve(&self, name: &str) -> MailboxResult<Folder> {
        let name = name.trim().trim_matches('/');
        if let Some(folder) = system_folder(name) {
            return Ok(folder);
        }
        let labels = self.labels().await?;
        labels
            .iter()
            .filter(|label| label.kind.as_deref() == Some("user"))
            .find(|label| label.name.eq_ignore_ascii_case(name))
            .or_else(|| labels.iter().find(|label| label.id == name))
            .map(|label| Folder::Label(label.id.clone()))
            .ok_or_else(|| {
                MailboxError::Message(format!(
                    "there is no folder or label named {name:?}; use a name from list_folders"
                ))
            })
    }

    fn message_id(selector: &Selector) -> MailboxResult<&str> {
        provider_message_id(selector, GMAIL_PREFIX)
    }

    /// Lists the system folders, `All Mail` and the user's labels.
    pub async fn list_folders(&self) -> MailboxResult<Vec<FolderEntry>> {
        let labels = self.labels().await?;
        let mut entries: Vec<FolderEntry> = SYSTEM
            .iter()
            .filter(|(id, ..)| labels.iter().any(|label| label.id == *id))
            .map(|(_, name, role, _)| FolderEntry {
                name: (*name).to_owned(),
                role: role.map(str::to_owned),
                selectable: true,
            })
            .collect();
        entries.push(FolderEntry {
            name: ALL_MAIL.to_owned(),
            role: Some("all".to_owned()),
            selectable: true,
        });
        let mut user: Vec<FolderEntry> = labels
            .into_iter()
            .filter(|label| label.kind.as_deref() == Some("user"))
            .map(|label| FolderEntry {
                name: label.name,
                role: None,
                selectable: true,
            })
            .collect();
        user.sort_by_key(|entry| entry.name.to_lowercase());
        entries.extend(user);
        Ok(entries)
    }

    /// Searches a folder with a Gmail query, newest first.
    pub async fn search(
        &self,
        folder: &str,
        criteria: &Criteria,
        paging: Paging,
    ) -> MailboxResult<Page> {
        let folder = self.resolve(folder).await?;
        let window = paging.offset + paging.limit;
        if window > MAX_SEARCH_WINDOW {
            return Err(MailboxError::Message(format!(
                "Gmail searches reach the first {MAX_SEARCH_WINDOW} matches; narrow the search"
            )));
        }
        // Count up to MOST_IDS so first-page totals are exact within one selection's cap.
        let (ids, estimate, more) = self
            .list(&folder, criteria, window.max(crate::tools::MOST_IDS), &[])
            .await?;
        let has_more = ids.len() > window || more;
        let wanted: Vec<String> = ids
            .iter()
            .skip(paging.offset)
            .take(paging.limit)
            .cloned()
            .collect();
        let messages = futures::stream::iter(wanted)
            .map(|message| async move { self.metadata(&message).await })
            .buffered(METADATA_CONCURRENCY)
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter_map(|result| match result {
                Ok(message) => Some(Ok(message.summary())),
                // Deleted between listing and fetching.
                Err(MailboxError::Message(text)) if text.starts_with("no such message") => None,
                Err(err) => Some(Err(err)),
            })
            .collect::<MailboxResult<Vec<Summary>>>()?;
        let (total, estimated) = if more {
            (estimate.unwrap_or(0).max(ids.len()), true)
        } else {
            (ids.len(), false)
        };
        Ok(Page {
            cutoff: None,
            total,
            estimated,
            offset: paging.offset,
            has_more,
            messages,
        })
    }

    /// The one id listing shared by searches and selection calls.
    async fn list(
        &self,
        folder: &Folder,
        criteria: &Criteria,
        most: usize,
        extra_labels: &[&str],
    ) -> MailboxResult<(Vec<String>, Option<usize>, bool)> {
        let query = gmail_query(criteria)?;
        let mut ids: Vec<String> = Vec::new();
        let mut estimate = None;
        let mut page_token: Option<String> = None;
        let mut exhausted = false;
        while ids.len() < most {
            let mut url = self.url(&["messages"]);
            {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair("maxResults", &(most - ids.len()).min(500).to_string());
                if let Folder::Label(label) = &folder {
                    pairs.append_pair("labelIds", label);
                    if label == "TRASH" || label == "SPAM" {
                        pairs.append_pair("includeSpamTrash", "true");
                    }
                }
                if criteria.read == Some(false) {
                    pairs.append_pair("labelIds", "UNREAD");
                }
                if criteria.flagged == Some(true) {
                    pairs.append_pair("labelIds", "STARRED");
                }
                for label in extra_labels {
                    pairs.append_pair("labelIds", label);
                }
                if !query.is_empty() {
                    pairs.append_pair("q", &query);
                }
                if let Some(token) = &page_token {
                    pairs.append_pair("pageToken", token);
                }
            }
            let list: MessageList = self.fetch_json(&url).await?;
            estimate = estimate.or(list.result_size_estimate);
            ids.extend(list.messages.into_iter().map(|message| message.id));
            page_token = list.next_page_token;
            if page_token.is_none() {
                exhausted = true;
                break;
            }
        }
        Ok((ids, estimate, !exhausted))
    }

    pub(super) async fn selected(
        &self,
        folder: &str,
        criteria: &Criteria,
        change: &Change,
        most: usize,
        deadline: Instant,
    ) -> MailboxResult<Selected> {
        criteria.exact_for_selection(
            &SelectionFilterRules::for_provider(Provider::Gmail),
            "Gmail",
        )?;
        let mailbox = Self::new(self.api.until(deadline), self.email.clone());
        let source = mailbox.resolve(folder).await?;
        let destination = mailbox.destination(change).await?;
        if destination.as_ref() == Some(&source) && !keeps_source_label(&source) {
            return Ok(Selected::own_folder(folder, change, false));
        }
        let archive = destination == Some(Folder::AllMail);
        let kept = keeps_folder(&source, destination.as_ref(), change);
        let extra = if archive && keeps_source_label(&source) {
            &["INBOX"][..]
        } else {
            &[]
        };
        let (mut ids, _, more) = mailbox.list(&source, criteria, most, extra).await?;
        let more = more || ids.len() > most;
        if kept && more {
            return Err(Selected::kept_folder(folder, most));
        }
        let mut left_out = !extra.is_empty();
        if kept
            && !ids.is_empty()
            && let Some(Folder::Label(label)) = &destination
        {
            let complete = async |extra: &[&str]| {
                let (ids, _, more) = mailbox.list(&source, criteria, most, extra).await?;
                if more || ids.len() > most {
                    return Err(Selected::kept_folder(folder, most));
                }
                Ok(ids.into_iter().collect::<HashSet<_>>())
            };
            let labelled = if destination.as_ref() == Some(&source) {
                None
            } else {
                Some(complete(&[label]).await?)
            };
            let inbox = if label == "INBOX" {
                HashSet::new()
            } else if labelled.is_none() {
                complete(&["INBOX"]).await?
            } else {
                complete(&[label, "INBOX"]).await?
            };
            ids.retain(|id| {
                labelled.as_ref().is_some_and(|labels| !labels.contains(id)) || inbox.contains(id)
            });
            left_out = true;
            if ids.is_empty()
                && let Change::Move(name) = change
            {
                return Ok(Selected::own_folder(name, change, false));
            }
        }
        let mut selected = Selected::matches(
            ids.into_iter()
                .take(most)
                .map(|id| id::provider_id(GMAIL_PREFIX, &id)),
            more,
        );
        if let Selected::Matches { left_out: flag, .. } = &mut selected {
            *flag = left_out;
        }
        Ok(selected)
    }

    async fn metadata(&self, message: &str) -> MailboxResult<GmailMessage> {
        let mut url = self.url(&["messages", message]);
        url.query_pairs_mut()
            .append_pair("format", "metadata")
            .append_pair("metadataHeaders", "From")
            .append_pair("metadataHeaders", "Subject")
            .append_pair("metadataHeaders", "Date");
        self.fetch_json(&url).await
    }

    pub(super) async fn original_size(&self, selector: &Selector) -> MailboxResult<Option<usize>> {
        let mut url = self.url(&["messages", Self::message_id(selector)?]);
        url.query_pairs_mut()
            .append_pair("fields", "id,sizeEstimate");
        let message: GmailMessage = self.fetch_json(&url).await?;
        Ok(message.size_estimate.map(|size| size as usize))
    }

    pub(super) async fn original(
        &self,
        selector: &Selector,
        reserved: usize,
    ) -> MailboxResult<Vec<u8>> {
        // A Gmail raw response is base64url in JSON. Ask for only the field we need.
        let limit = (reserved.div_ceil(3) * 4 + 1024).min(MESSAGE_LIMIT);
        let (_, raw) = self
            .raw_with(
                Self::message_id(selector)?,
                Some(limit),
                |error| match error {
                    ApiError::Http(postkeep_upstream::http::HttpError::TooLarge(_))
                        if limit == MESSAGE_LIMIT =>
                    {
                        super::too_large_to_forward()
                    }
                    ApiError::Http(postkeep_upstream::http::HttpError::TooLarge(_)) => {
                        super::forward_size_error(reserved)
                    }
                    other => gmail_error(other),
                },
            )
            .await?;
        if raw.len() > reserved {
            return Err(super::forward_size_error(reserved));
        }
        Ok(raw)
    }

    async fn raw(&self, message: &str) -> MailboxResult<(GmailMessage, Vec<u8>)> {
        self.raw_with(message, None, gmail_error).await
    }

    async fn raw_with(
        &self,
        message: &str,
        raw_only: Option<usize>,
        map_error: impl FnOnce(ApiError) -> MailboxError,
    ) -> MailboxResult<(GmailMessage, Vec<u8>)> {
        let mut url = self.url(&["messages", message]);
        url.query_pairs_mut().append_pair("format", "raw");
        if raw_only.is_some() {
            url.query_pairs_mut().append_pair("fields", "id,raw");
        }
        let response = self
            .api
            .call(
                Method::GET,
                &url,
                &[],
                axum::body::Bytes::new(),
                raw_only.unwrap_or(MESSAGE_LIMIT),
            )
            .await
            .map_err(map_error)?;
        let mut message: GmailMessage = self.api.parse(&response).map_err(gmail_error)?;
        drop(response);
        let raw = message
            .raw
            .take()
            .as_deref()
            .and_then(decode_raw)
            .ok_or_else(|| {
                MailboxError::Message("Gmail returned a message without its content".to_owned())
            })?;
        Ok((message, raw))
    }

    /// Fetches a message in `raw` format.
    pub async fn get(&self, selector: &Selector) -> MailboxResult<Fetched> {
        let message = Self::message_id(selector)?;
        let (metadata, raw) = self.raw(message).await?;
        let parsed = mime::parse_message(&raw, metadata.flags()).ok_or_else(|| {
            MailboxError::Message("Gmail returned a message that could not be parsed".to_owned())
        })?;
        let folder = self.folder_of(&metadata.label_ids).await;
        Ok(Fetched {
            id: id::provider_id(GMAIL_PREFIX, &metadata.id),
            folder,
            uid: None,
            message: parsed,
        })
    }

    /// One attachment of a message, from its raw MIME.
    pub async fn attachment(
        &self,
        selector: &Selector,
        id: u32,
        max_bytes: usize,
    ) -> MailboxResult<Option<AttachmentData>> {
        let (_, raw) = self.raw(Self::message_id(selector)?).await?;
        Ok(mime::attachment(&raw, id, max_bytes))
    }

    /// The folder to report for a message with `labels`.
    async fn folder_of(&self, labels: &[String]) -> String {
        for (id, name, ..) in SYSTEM
            .iter()
            .filter(|(id, ..)| *id != "STARRED" && *id != "IMPORTANT")
        {
            if labels.iter().any(|label| label == id) {
                return (*name).to_owned();
            }
        }
        let user: Vec<&String> = labels
            .iter()
            .filter(|label| label.starts_with("Label_"))
            .collect();
        if !user.is_empty()
            && let Ok(all) = self.labels().await
        {
            let names: HashMap<&str, &str> = all
                .iter()
                .map(|label| (label.id.as_str(), label.name.as_str()))
                .collect();
            if let Some(name) = user.iter().find_map(|id| names.get(id.as_str())) {
                return (*name).to_owned();
            }
        }
        ALL_MAIL.to_owned()
    }

    async fn destination(&self, change: &Change) -> MailboxResult<Option<Folder>> {
        match change {
            Change::Move(name) => self.resolve(name).await.map(Some),
            Change::Trash => Ok(Some(Folder::Label("TRASH".to_owned()))),
            Change::Flags { .. } => Ok(None),
        }
    }

    async fn change_request(&self, change: &Change) -> MailboxResult<LabelChange> {
        let (mut add, mut remove) = (Vec::new(), Vec::new());
        match change {
            Change::Flags { read, flagged } => {
                match read {
                    Some(true) => remove.push("UNREAD".to_owned()),
                    Some(false) => add.push("UNREAD".to_owned()),
                    None => {}
                }
                match flagged {
                    Some(true) => add.push("STARRED".to_owned()),
                    Some(false) => remove.push("STARRED".to_owned()),
                    None => {}
                }
            }
            Change::Move(_) | Change::Trash => {
                if let Some(Folder::Label(label)) = self.destination(change).await? {
                    add.push(label);
                }
                remove = MOVED_OUT
                    .iter()
                    .copied()
                    .filter(|label| !add.iter().any(|added| added == label))
                    .map(str::to_owned)
                    .collect();
            }
        }
        Ok(LabelChange {
            add_label_ids: add,
            remove_label_ids: remove,
        })
    }

    /// Checks explicit ids in chunks, then modifies only the messages that still need the change.
    pub async fn apply(
        &self,
        ids: &[Selector],
        ids_from: IdsFrom,
        change: &Change,
        mode: Mode,
        deadline: Instant,
    ) -> MailboxResult<Vec<Outcome>> {
        let (mut outcomes, valid) = provider_outcomes(ids, GMAIL_PREFIX);
        if valid.is_empty() || Instant::now() >= deadline {
            return Ok(outcomes);
        }
        let mailbox = Self::new(self.api.until(deadline), self.email.clone());
        let labels = match mailbox.change_request(change).await {
            Err(MailboxError::Deadline) => return Ok(outcomes),
            result => result?,
        };
        let size = if ids_from == IdsFrom::Caller {
            ACTION_CHUNK
        } else {
            valid.len()
        };
        let mut sent = false;
        for (n, chunk) in valid.chunks(size).enumerate() {
            if Instant::now() >= deadline {
                break;
            }
            let remaining = &valid[n * size + chunk.len()..];
            let candidates;
            let write = if ids_from == IdsFrom::Caller {
                candidates = match mailbox
                    .read_changes(chunk, change, &labels, &mut outcomes)
                    .await
                {
                    Ok(ids) => ids,
                    Err(reason) => {
                        for (index, _) in chunk.iter().chain(remaining) {
                            outcomes[*index].reason.clone_from(&reason);
                        }
                        break;
                    }
                };
                &candidates
            } else {
                chunk
            };
            if mode == Mode::DryRun {
                for (index, _) in write {
                    outcomes[*index].finish(Status::Ok, "");
                }
            } else if !write.is_empty() {
                let stopped = match mailbox.write(write, &labels, &mut outcomes).await {
                    Ok(None) => {
                        sent = true;
                        continue;
                    }
                    Ok(Some(reason)) => reason,
                    Err(err) if !sent && !err.is_deadline() => return Err(gmail_error(err)),
                    Err(err) => {
                        let reason = api_error_message(&err, "Google");
                        for (index, _) in write {
                            outcomes[*index].reason.clone_from(&reason);
                        }
                        reason
                    }
                };
                for (index, _) in remaining {
                    outcomes[*index].reason.clone_from(&stopped);
                }
                break;
            }
        }
        Ok(outcomes)
    }

    /// Leave the whole chunk pending when limited or when none of its reads gets a usable answer.
    async fn read_changes(
        &self,
        chunk: &[(usize, String)],
        change: &Change,
        labels: &LabelChange,
        outcomes: &mut [Outcome],
    ) -> Result<Vec<(usize, String)>, String> {
        let mut reads = Vec::with_capacity(chunk.len());
        for group in chunk.chunks(METADATA_CONCURRENCY) {
            let answers = futures::future::join_all(group.iter().map(|(_, id)| async move {
                let mut url = self.url(&["messages", id]);
                url.query_pairs_mut()
                    .append_pair("format", "minimal")
                    .append_pair("fields", "id,labelIds");
                self.api.get_json::<GmailMessage>(&url, &[]).await
            }))
            .await;
            if let Some(err) = answers
                .iter()
                .filter_map(|result| result.as_ref().err())
                .find(|err| gmail_limited(err))
            {
                return Err(api_error_message(err, "Google"));
            }
            reads.extend(answers);
        }
        if let Some(Err(first)) = reads.first()
            && reads
                .iter()
                .all(|answer| answer.as_ref().is_err_and(|err| err.status().is_none()))
        {
            return Err(api_error_message(first, "Google"));
        }
        Ok(chunk
            .iter()
            .zip(reads)
            .filter_map(|((index, id), answer)| {
                let out = &mut outcomes[*index];
                match answer {
                    Ok(message) if labels.already(&message.label_ids) => {
                        out.finish(Status::Ok, change.already_reason(false));
                    }
                    Ok(_) => return Some((*index, id.clone())),
                    Err(err) => {
                        let status = match err.status() {
                            Some(StatusCode::NOT_FOUND) => Status::NotFound,
                            Some(_) => Status::Failed,
                            None => Status::NotReached,
                        };
                        out.finish(status, api_error_message(&err, "Google"));
                    }
                }
                None
            })
            .collect())
    }

    /// Uses modify for one id or batchModify, with the existing per-id fallback.
    /// An error means the first request was not sent; a reason means stop after this chunk.
    async fn write(
        &self,
        ids: &[(usize, String)],
        labels: &LabelChange,
        outcomes: &mut [Outcome],
    ) -> Result<Option<String>, ApiError> {
        let mut body = json!(labels);
        let url = if ids.len() == 1 {
            self.url(&["messages", &ids[0].1, "modify"])
        } else {
            body["ids"] = json!(ids.iter().map(|(_, id)| id).collect::<Vec<_>>());
            self.url(&["messages", "batchModify"])
        };
        let result = self.api.send_json(Method::POST, &url, &[], &body).await;
        let fallback = ids.len() > 1
            && result.as_ref().is_err_and(|err| {
                !gmail_limited(err)
                    && matches!(
                        err.status(),
                        Some(StatusCode::BAD_REQUEST | StatusCode::NOT_FOUND)
                    )
            });
        if !fallback {
            let result = match result {
                Err(err) if gmail_unsent(&err) => return Err(err),
                result => result,
            };
            for (index, _) in ids {
                finish_gmail(&mut outcomes[*index], &result);
            }
            return Ok(result
                .as_ref()
                .err()
                .filter(|err| stop_after_gmail_write(err))
                .map(|err| api_error_message(err, "Google")));
        }
        let body = json!(labels);
        // Join each bounded group in input order; stop scheduling if the write stops.
        for (group_index, group) in ids.chunks(METADATA_CONCURRENCY).enumerate() {
            let results = futures::future::join_all(group.iter().map(|(_, id)| {
                let url = self.url(&["messages", id, "modify"]);
                let body = &body;
                async move { self.api.send_json(Method::POST, &url, &[], body).await }
            }))
            .await;
            for ((index, _), answer) in group.iter().zip(&results) {
                finish_gmail(&mut outcomes[*index], answer);
            }
            // A repeated 400 can reject the change itself; 404s still need per-id checks.
            let refusal = result.as_ref().err().filter(|err| {
                group_index == 0
                    && matches!(err, ApiError::Status { status: StatusCode::BAD_REQUEST, message, .. }
                        if results.iter().all(|answer| matches!(answer,
                            Err(ApiError::Status { status: StatusCode::BAD_REQUEST, message: own_message, .. })
                                if own_message == message)))
            });
            let errors = || results.iter().filter_map(|answer| answer.as_ref().err());
            let stop = refusal.or_else(|| errors().find(|err| stop_after_gmail_write(err)));
            if let Some(err) = stop.or_else(|| errors().find(|err| gmail_unsent(err))) {
                let reason = api_error_message(err, "Google");
                for (index, _) in ids {
                    let out = &mut outcomes[*index];
                    if out.status == Status::NotReached {
                        out.finish(
                            if refusal.is_some() {
                                Status::Failed
                            } else {
                                Status::NotReached
                            },
                            reason.clone(),
                        );
                    }
                }
                return Ok(Some(reason));
            }
        }
        Ok(None)
    }

    /// Refuses permanent deletion, which needs full mailbox access.
    pub fn delete(&self, selector: &Selector) -> MailboxResult<String> {
        Self::message_id(selector)?;
        Err(MailboxError::Message(
            "Gmail accounts cannot delete messages permanently through this server (that \
             would need full access to the mailbox). Delete without `permanent` to move it \
             to Trash; Gmail empties Trash after 30 days."
                .to_owned(),
        ))
    }

    /// Creates a label; `Parent/Child` nests it under `Parent`.
    pub async fn create_folder(&self, name: &str) -> MailboxResult<()> {
        let name = name.trim().trim_matches('/');
        if name.is_empty() {
            return Err(MailboxError::Message("the folder name is empty".to_owned()));
        }
        match self
            .api
            .send_json(
                Method::POST,
                &self.url(&["labels"]),
                &[],
                &json!({
                    "name": name,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show",
                }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(err) if err.status() == Some(StatusCode::CONFLICT) => Err(MailboxError::Message(
                format!("a label named {name:?} already exists"),
            )),
            Err(err) => Err(gmail_error(err)),
        }
    }

    async fn submit(&self, raw: &[u8], thread: Option<&str>) -> MailboxResult<()> {
        let metadata = thread.map_or_else(|| json!({}), |id| json!({ "threadId": id }));
        let (content_type, body) = multipart_body(&metadata, raw);
        self.api
            .call_status(
                Method::POST,
                &self.upload_url(&["messages", "send"]),
                &[(header::CONTENT_TYPE, content_type)],
                body,
                || true,
            )
            .await
            .map_err(|err| maybe_sent(SendError::Api(err, "Google")))
    }

    async fn upload_draft(
        &self,
        composed: mime::Composed,
        thread: Option<&str>,
    ) -> MailboxResult<SavedDraft> {
        let metadata =
            json!({ "message": thread.map_or_else(|| json!({}), |id| json!({ "threadId": id })) });
        let (content_type, body) = multipart_body(&metadata, &composed.raw);
        let answer = self
            .api
            .call(
                Method::POST,
                &self.upload_url(&["drafts"]),
                &[(header::CONTENT_TYPE, content_type)],
                body,
                JSON_LIMIT,
            )
            .await
            .map_err(|error| {
                if provider_may_have_acted(&error) {
                    DRAFT_UNCONFIRMED.to_owned().into()
                } else {
                    submit_error(&error, "Google")
                }
            })?;
        let id = self
            .api
            .parse::<GmailDraft>(&answer)
            .ok()
            .and_then(|draft| draft.message)
            .map(|message| id::provider_id(GMAIL_PREFIX, &message.id))
            .filter(|candidate| id::parse_provider_id(GMAIL_PREFIX, candidate).is_some())
            .ok_or_else(|| {
                "Google did not return a valid draft id. Check Drafts before trying again."
                    .to_owned()
            })?;
        Ok(SavedDraft {
            id: Some(id),
            message_id: composed.message_id,
            folder: "Drafts".to_owned(),
        })
    }

    /// Gmail always files sent mail under Sent.
    fn sent(message_id: String, _options: SendOptions) -> SentMessage {
        SentMessage {
            message_id,
            sent_copy: SentCopy::AlreadyPresent {
                folder: "Sent".to_owned(),
            },
        }
    }

    /// Sends a new message.
    pub async fn send(
        &self,
        message: &OutgoingMessage,
        options: SendOptions,
    ) -> MailboxResult<SentMessage> {
        let composed = mime::compose(&EmailAddress::new(self.email.clone()), message)?;
        self.submit(&composed.raw, None).await?;
        Ok(Self::sent(composed.message_id, options))
    }

    /// Replies to a message, in the same Gmail thread.
    pub async fn reply(
        &self,
        selector: &Selector,
        reply: &Reply,
        options: SendOptions,
    ) -> MailboxResult<SentMessage> {
        let (composed, thread) = self.compose_reply(selector, reply).await?;
        self.submit(&composed.raw, thread.as_deref()).await?;
        Ok(Self::sent(composed.message_id, options))
    }

    /// Saves a new message to Drafts without sending it.
    pub async fn create_draft(&self, message: &OutgoingMessage) -> MailboxResult<SavedDraft> {
        let composed = mime::compose(&EmailAddress::new(self.email.clone()), message)?;
        self.upload_draft(composed, None).await
    }

    /// Saves a reply to Drafts, in the same Gmail thread, without sending it.
    pub async fn create_reply_draft(
        &self,
        selector: &Selector,
        reply: &Reply,
    ) -> MailboxResult<SavedDraft> {
        let (composed, thread) = self.compose_reply(selector, reply).await?;
        self.upload_draft(composed, thread.as_deref()).await
    }

    async fn compose_reply(
        &self,
        selector: &Selector,
        reply: &Reply,
    ) -> MailboxResult<(mime::Composed, Option<String>)> {
        let message = Self::message_id(selector)?;
        let (metadata, raw) = self.raw(message).await?;
        let original = mime::parse_headers(&raw).ok_or_else(|| {
            MailboxError::Message("the original message could not be parsed".to_owned())
        })?;
        let composed =
            mime::compose_reply(&EmailAddress::new(self.email.clone()), &original, reply)?;
        Ok((composed, metadata.thread_id))
    }
}

fn multipart_body(metadata: &Value, raw: &[u8]) -> (String, Bytes) {
    let boundary = loop {
        let boundary = uuid::Uuid::new_v4().simple().to_string();
        if !raw
            .windows(boundary.len())
            .any(|w| w == boundary.as_bytes())
        {
            break boundary;
        }
    };
    let start = format!(
        "--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{metadata}\r\n\
         --{boundary}\r\nContent-Type: message/rfc822\r\n\r\n"
    );
    let end = format!("\r\n--{boundary}--\r\n");
    let mut body = Vec::with_capacity(start.len() + raw.len() + end.len());
    body.extend_from_slice(start.as_bytes());
    body.extend_from_slice(raw);
    body.extend_from_slice(end.as_bytes());
    (
        format!("multipart/related; boundary={boundary}"),
        Bytes::from(body),
    )
}

/// Decodes Gmail's `raw` field (base64url, with or without padding).
fn decode_raw(raw: &str) -> Option<Vec<u8>> {
    let trimmed = raw.trim();
    URL_SAFE_NO_PAD
        .decode(trimmed.trim_end_matches('='))
        .ok()
        .or_else(|| URL_SAFE.decode(trimmed).ok())
}

fn gmail_limited(err: &ApiError) -> bool {
    err.is_rate_limited()
        || matches!(err, ApiError::Status { reason: Some(reason), .. } if reason == "dailyLimitExceeded")
}

fn stop_after_gmail_write(err: &ApiError) -> bool {
    gmail_limited(err) || unanswered(err)
}

const fn gmail_unsent(err: &ApiError) -> bool {
    err.status().is_none() && !unanswered(err)
}

fn finish_gmail(out: &mut Outcome, result: &Result<HttpResponse, ApiError>) {
    match result {
        Ok(_) => out.finish(Status::Ok, ""),
        Err(err) if unanswered(err) => out.finish(Status::Failed, SENT_NO_ANSWER),
        Err(err) => out.finish(
            if gmail_unsent(err) || gmail_limited(err) {
                Status::NotReached
            } else if err.status() == Some(StatusCode::NOT_FOUND) {
                Status::NotFound
            } else {
                Status::Failed
            },
            api_error_message(err, "Google"),
        ),
    }
}

/// The folder for a well-known name, or `None` for a user label.
fn system_folder(name: &str) -> Option<Folder> {
    let lower = name.to_lowercase();
    if ["all mail", "[gmail]/all mail", "archive", "all"].contains(&lower.as_str()) {
        return Some(Folder::AllMail);
    }
    SYSTEM
        .iter()
        .find(|(id, _, _, aliases)| {
            aliases.contains(&lower.as_str()) || id.eq_ignore_ascii_case(&lower)
        })
        .map(|(id, ..)| Folder::Label((*id).to_owned()))
}

fn keeps_source_label(source: &Folder) -> bool {
    match source {
        Folder::AllMail => true,
        Folder::Label(label) => !MOVED_OUT.contains(&label.as_str()),
    }
}

fn keeps_folder(source: &Folder, destination: Option<&Folder>, change: &Change) -> bool {
    matches!(change, Change::Move(_))
        && keeps_source_label(source)
        && matches!(destination, Some(Folder::Label(label)) if !matches!(label.as_str(), "SPAM" | "TRASH"))
}

/// The Gmail query: one quoted phrase per text filter, intersected by space.
fn gmail_query(criteria: &Criteria) -> MailboxResult<String> {
    let mut terms = Vec::new();
    for (filter, value) in criteria.text_filters() {
        let prefix = if filter == "text" {
            String::new()
        } else {
            format!("{filter}:")
        };
        let phrase = super::words(filter, value, "Gmail")?.join(" ");
        terms.push(format!("{prefix}\"{phrase}\""));
    }
    // Use Unix seconds for UTC boundaries; bare dates mean midnight Pacific.
    let since = criteria.since.map(super::day_start);
    let before = criteria.before.map(super::day_start);
    for (filter, seconds) in [("since", since), ("before", before)] {
        if seconds.is_some_and(|seconds| seconds <= 0) {
            return Err(MailboxError::Message(format!(
                "{filter} must be 1970-01-02 or later on Gmail"
            )));
        }
    }
    if let Some(after) = since {
        terms.push(format!("after:{after}"));
    }
    let until = match criteria.until {
        Some(Cutoff::Time(seconds)) => Some(seconds),
        _ => None,
    };
    if let Some(before) = before.into_iter().chain(until).min() {
        terms.push(format!("before:{}", before.max(0)));
    }
    if criteria.read == Some(true) {
        terms.push("-is:unread".to_owned());
    }
    if criteria.flagged == Some(false) {
        terms.push("-is:starred".to_owned());
    }
    Ok(terms.join(" "))
}

#[expect(clippy::needless_pass_by_value, reason = "passed to map_err by name")]
fn gmail_error(err: ApiError) -> MailboxError {
    provider_error(&err, "Google")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_imap_names_to_system_labels() {
        assert_eq!(
            system_folder("INBOX"),
            Some(Folder::Label("INBOX".to_owned()))
        );
        assert_eq!(
            system_folder("Deleted Messages"),
            Some(Folder::Label("TRASH".to_owned()))
        );
        assert_eq!(system_folder("[Gmail]/All Mail"), Some(Folder::AllMail));
        assert_eq!(system_folder("Projects"), None);
    }

    #[test]
    fn builds_queries_without_injected_operators() {
        let criteria = Criteria {
            from: Some("alice@example.com".to_owned()),
            subject: Some("-label:x OR {a b}".to_owned()),
            since: chrono::NaiveDate::from_ymd_opt(2026, 1, 2),
            before: chrono::NaiveDate::from_ymd_opt(2026, 2, 1),
            read: Some(false),
            ..Criteria::default()
        };
        assert_eq!(
            gmail_query(&criteria).unwrap(),
            "from:\"alice@example.com\" subject:\"label x or a b\" after:1767312000 before:1769904000"
        );
        assert_eq!(gmail_query(&Criteria::default()).unwrap(), "");
        let symbols = Criteria {
            subject: Some("{} --".to_owned()),
            ..Criteria::default()
        };
        assert_eq!(
            gmail_query(&symbols).unwrap_err().to_string(),
            "the subject filter has no word Gmail can search for; use other words"
        );
        let early = Criteria {
            since: chrono::NaiveDate::from_ymd_opt(1970, 1, 1),
            before: chrono::NaiveDate::from_ymd_opt(1969, 12, 31),
            ..Criteria::default()
        };
        assert_eq!(
            gmail_query(&early).unwrap_err().to_string(),
            "since must be 1970-01-02 or later on Gmail"
        );
        let before_only = Criteria {
            since: None,
            ..early
        };
        assert_eq!(
            gmail_query(&before_only).unwrap_err().to_string(),
            "before must be 1970-01-02 or later on Gmail"
        );
        let next = Criteria {
            since: chrono::NaiveDate::from_ymd_opt(1970, 1, 2),
            ..Criteria::default()
        };
        assert_eq!(gmail_query(&next).unwrap(), "after:86400");
    }

    #[test]
    fn query_uses_one_earlier_cutoff_and_renders_read_and_unstarred() {
        let mut criteria = Criteria {
            read: Some(true),
            flagged: Some(false),
            before: chrono::NaiveDate::from_ymd_opt(2026, 2, 1),
            until: Some(Cutoff::Time(1_768_003_200)),
            ..Criteria::default()
        };
        assert_eq!(
            gmail_query(&criteria).unwrap(),
            "before:1768003200 -is:unread -is:starred"
        );
        criteria.until = Some(Cutoff::Time(1_794_912_000));
        assert_eq!(
            gmail_query(&criteria).unwrap(),
            "before:1769904000 -is:unread -is:starred"
        );
        criteria.read = Some(false);
        criteria.flagged = Some(true);
        assert_eq!(gmail_query(&criteria).unwrap(), "before:1769904000");
    }

    #[test]
    fn kept_folders_share_the_move_label_rule_and_exempt_spam_trash_and_archive() {
        let move_to = Change::Move("Receipts".to_owned());
        for source in ["INBOX", "SPAM", "TRASH", "Receipts", "All Mail"] {
            let source = system_folder(source).unwrap_or_else(|| Folder::Label(source.to_owned()));
            assert_eq!(
                keeps_folder(&source, Some(&Folder::Label("other".to_owned())), &move_to),
                keeps_source_label(&source)
            );
            for destination in ["Spam", "Trash", "All Mail"] {
                assert!(!keeps_folder(
                    &source,
                    system_folder(destination).as_ref(),
                    &move_to
                ));
            }
            assert!(!keeps_folder(
                &source,
                Some(&Folder::Label("TRASH".to_owned())),
                &Change::Trash
            ));
        }
    }

    #[test]
    fn summaries_show_when_gmail_received_the_message() {
        let date =
            serde_json::json!([{ "name": "Date", "value": "Thu, 01 Oct 2026 09:00:00 +0200" }]);
        let message = |internal_date: Option<&str>| -> GmailMessage {
            serde_json::from_value(serde_json::json!({
                "id": "18c1", "internalDate": internal_date, "payload": { "headers": date },
            }))
            .unwrap()
        };
        let received = message(Some("1791450300000")).summary().date.unwrap();
        assert_eq!(received.to_rfc3339(), "2026-10-08T09:05:00+00:00");
        let dated = message(None).summary().date.unwrap();
        assert_eq!(dated.to_rfc3339(), "2026-10-01T09:00:00+02:00");
    }

    #[test]
    fn phrases_keep_operator_words_as_lowercase_text() {
        let criteria = Criteria {
            subject: Some("OR status".to_owned()),
            text: Some("holiday OR AND AROUND(2) -secret around trip NOT".to_owned()),
            ..Criteria::default()
        };
        assert_eq!(
            gmail_query(&criteria).unwrap(),
            "subject:\"or status\" \"holiday or and around 2 secret around trip not\""
        );
        assert_eq!(
            gmail_query(&Criteria {
                text: Some("OR AND AROUND ORBIT".to_owned()),
                ..Criteria::default()
            })
            .unwrap(),
            "\"or and around orbit\""
        );
    }

    #[test]
    fn decodes_raw_with_and_without_padding() {
        assert_eq!(decode_raw("aGk").as_deref(), Some(&b"hi"[..]));
        assert_eq!(decode_raw("aGk=").as_deref(), Some(&b"hi"[..]));
        assert_eq!(decode_raw("!!"), None);
    }
}
