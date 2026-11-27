//! Outlook.com and Microsoft 365 mailboxes through Microsoft Graph.
//!
//! * Messages are addressed by Graph's immutable ids (`Prefer:
//!   IdType="ImmutableId"`). `$search` answers regular ids, which `immutable`
//!   translates before they are handed out.
//! * Messages are read as MIME (`/messages/{id}/$value`) and parsed with
//!   the same parser as IMAP mail. Small messages go to `sendMail` as MIME;
//!   large messages and forwards go through a draft. Both routes store the
//!   message in Sent Items.
//! * Folders are named by their display-name path (`Inbox/Projects`); the
//!   usual IMAP names (`INBOX`, `Sent`, `Trash`, ...) map to Graph's
//!   well-known folders.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::http::{HeaderName, Method, StatusCode, header};
use base64::Engine as _;
use postkeep_auth::ToolErrorCode;
use postkeep_mail::{
    AttachmentData, EmailAddress, Message, MessageFlags, OutgoingAttachment, OutgoingMessage,
    Paging, Reply, SendOptions, SentCopy, SentMessage, holds, holds_addresses, mime,
};
use postkeep_store::Provider;
use postkeep_upstream::http::{
    HttpError, JSON_LIMIT, MAX_RETRY_AFTER_SECS, MESSAGE_LIMIT, join_segments,
    parse_retry_after_str,
};
use postkeep_upstream::{ApiClient, ApiError, OAuthError, TokenError, UpstreamProvider};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::SemaphorePermit;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::forward::{self, Forwarded};
use crate::text::prefix_html;
use crate::tools::format_address;

use super::capabilities::SelectionFilterRules;
use super::id::{self, GRAPH_PREFIX};
use super::{
    Change, Criteria, Cutoff, DRAFT_UNCONFIRMED, Fetched, FolderEntry, IdsFrom, MAY_HAVE_BEEN_SENT,
    MailboxError, MailboxResult, Mode, NOTHING_LEFT, Outcome, Page, SENT_NO_ANSWER, SavedDraft,
    Selected, Selector, SendError, Status, Summary, TIME_EXHAUSTED, account_store_code, maybe_sent,
    provider_may_have_acted, provider_outcomes, too_large_to_forward, unanswered,
};

/// Folders listed at most, against runaway hierarchies.
const MAX_FOLDERS: usize = 1000;
/// Deepest folder level listed.
const MAX_DEPTH: usize = 8;
/// Graph's largest message page; also the raw keyword window, which cannot skip.
pub const MAX_SEARCH_WINDOW: usize = 1000;
/// Raw `$search` hits past which an ended listing is treated as cut off.
///
/// Graph has been observed to end message `$search` listings near 275 hits
/// with no `@odata.nextLink` (<https://github.com/mpalermiti/outlook-mcp/issues/134>).
pub const LISTING_TRUSTED: usize = 250;
// The keyword listing uses its raw window's completeness for the action cap.
const _: () = assert!(crate::tools::MOST_IDS == MAX_SEARCH_WINDOW);
const _: () = assert!(LISTING_TRUSTED <= MAX_SEARCH_WINDOW);
/// Graph translates at most 1,000 ids in one `translateExchangeIds` call.
const TRANSLATE_MAX: usize = 1000;
const _: () = assert!(MAX_SEARCH_WINDOW <= TRANSLATE_MAX);
/// Returned when `translateExchangeIds` gives no usable immutable id for a hit.
const NO_STABLE_ID: &str = "Outlook gave no stable id for some of these messages: search again";
/// Pages followed while collecting a filtered `$search`. A next-link cycle
/// stops here instead of spinning.
const MAX_SEARCH_PAGES: usize = 20;

/// Graph accepts at most twenty requests in one JSON batch.
const BATCH_MAX: usize = 20;

#[derive(Debug, Deserialize)]
struct Batch {
    responses: Vec<BatchResponse>,
}

#[derive(Debug, Deserialize)]
struct BatchResponse {
    id: String,
    status: u16,
    #[serde(default)]
    headers: HashMap<String, serde_json::Value>,
    #[serde(default)]
    body: serde_json::Value,
}

enum BatchStage<'a> {
    Read {
        change: &'a Change,
        destination: Option<&'a str>,
        mode: Mode,
        ready: &'a mut Vec<usize>,
    },
    Write {
        moved: bool,
    },
}

fn batch_index(request: &Value) -> Option<usize> {
    request["id"].as_str()?.parse().ok()
}

impl Batch {
    fn finish(
        &self,
        requests: &[serde_json::Value],
        outcomes: &mut [Outcome],
        stage: &mut BatchStage<'_>,
    ) -> (Vec<serde_json::Value>, Duration) {
        let mut retry = Vec::new();
        let mut delay = Duration::ZERO;
        for request in requests {
            let Some(index) = batch_index(request) else {
                continue;
            };
            let out = &mut outcomes[index];
            let mut matching = self
                .responses
                .iter()
                .filter(|response| response.id == index.to_string());
            let response = matching.next().filter(|_| matching.next().is_none());
            match response {
                Some(response) if (200..300).contains(&response.status) => match stage {
                    BatchStage::Read {
                        change,
                        destination,
                        mode,
                        ready,
                    } => {
                        let is_already =
                            serde_json::from_value::<MessageState>(response.body.clone())
                                .ok()
                                .and_then(|state| already(&state, change, *destination));
                        match is_already {
                            Some(true) => out.ok(change.already_reason(true)),
                            Some(false) if *mode == Mode::DryRun => out.ok(""),
                            Some(false) => {
                                out.reset_pending();
                                ready.push(index);
                            }
                            None => out.fail(
                                Status::Failed,
                                "Microsoft's answer left out the message's state",
                                ToolErrorCode::ProviderUnavailable,
                                None,
                            ),
                        }
                    }
                    BatchStage::Write { moved } => {
                        out.ok("");
                        if *moved
                            && let Some(new) =
                                response.body["id"].as_str().filter(|id| !id.is_empty())
                        {
                            let new = id::provider_id(GRAPH_PREFIX, new);
                            if new != out.id.trim() {
                                out.new_id = Some(new);
                            }
                        }
                    }
                },
                Some(response) if response.status == 429 => {
                    let error = response.error();
                    out.fail(
                        Status::NotReached,
                        api_error_message(&error, "Microsoft"),
                        ToolErrorCode::RateLimited,
                        error.retry_after(),
                    );
                    delay = delay.max(response.retry_after());
                    retry.push(request.clone());
                }
                Some(response) => {
                    let err = response.error();
                    let (code, retry_after) = classify_api_error(&err);
                    let status = if response.status == 404 {
                        Status::NotFound
                    } else {
                        Status::Failed
                    };
                    out.fail(
                        status,
                        api_error_message(&err, "Microsoft"),
                        code,
                        retry_after,
                    );
                }
                None => match stage {
                    BatchStage::Read { .. } => out.fail(
                        Status::NotReached,
                        "Microsoft's batch answer omitted or repeated this request",
                        ToolErrorCode::ProviderUnavailable,
                        None,
                    ),
                    BatchStage::Write { .. } => out.fail(
                        Status::Failed,
                        SENT_NO_ANSWER,
                        ToolErrorCode::SubmissionUncertain,
                        None,
                    ),
                },
            }
        }
        (retry, delay)
    }
}

fn pending_reason(
    outcomes: &mut [Outcome],
    reason: &str,
    (code, retry_after): (ToolErrorCode, Option<u64>),
) {
    for out in outcomes {
        if out.status == Status::NotReached && out.reason == TIME_EXHAUSTED {
            out.fail(Status::NotReached, reason, code, retry_after);
        }
    }
}

impl BatchResponse {
    fn error(&self) -> ApiError {
        let (code, message) =
            postkeep_upstream::api::error_details(self.body.to_string().as_bytes());
        ApiError::Status {
            provider: UpstreamProvider::Microsoft,
            status: StatusCode::from_u16(self.status).unwrap_or(StatusCode::BAD_GATEWAY),
            code,
            reason: None,
            retry_after: if matches!(self.status, 429 | 503) {
                self.retry_after_seconds()
            } else {
                None
            },
            message,
        }
    }

    fn retry_after_seconds(&self) -> Option<u64> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
            .and_then(|(_, value)| {
                value.as_str().map_or_else(
                    || {
                        value
                            .as_u64()
                            .map(|seconds| seconds.min(MAX_RETRY_AFTER_SECS))
                    },
                    parse_retry_after_str,
                )
            })
    }

    fn retry_after(&self) -> Duration {
        Duration::from_secs(self.retry_after_seconds().unwrap_or(1))
    }
}

/// Graph's well-known folders with their roles and the names that map to
/// them.
const WELL_KNOWN: &[(&str, &str, &[&str])] = &[
    ("inbox", "inbox", &["inbox"]),
    (
        "sentitems",
        "sent",
        &["sent", "sent items", "sent messages", "sentitems"],
    ),
    (
        "deleteditems",
        "trash",
        &["trash", "deleted items", "deleted messages", "deleteditems"],
    ),
    ("drafts", "drafts", &["drafts"]),
    (
        "junkemail",
        "junk",
        &["junk", "junk email", "spam", "junkemail"],
    ),
    ("archive", "archive", &["archive"]),
];

/// An Outlook mailbox.
#[derive(Debug, Clone)]
pub struct GraphMailbox {
    api: ApiClient,
    email: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphFolder {
    id: String,
    display_name: String,
    #[serde(default)]
    child_folder_count: usize,
}

#[derive(Debug, Deserialize)]
struct Collection<T> {
    value: Vec<T>,
    #[serde(rename = "@odata.count")]
    count: Option<usize>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

/// One entry in a `translateExchangeIds` response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Translated {
    source_id: String,
    target_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphMessage {
    id: String,
    subject: Option<String>,
    from: Option<Recipient>,
    to_recipients: Option<Vec<Recipient>>,
    received_date_time: Option<String>,
    #[serde(default)]
    is_read: bool,
    #[serde(default)]
    is_draft: bool,
    flag: Option<FollowUp>,
    parent_folder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recipient {
    /// Absent or `null` when Graph has none. Such a sender has no address,
    /// and does not fail the listing.
    email_address: Option<Address>,
}

#[derive(Debug, Deserialize)]
struct Address {
    name: Option<String>,
    address: Option<String>,
}

impl Recipient {
    fn email(&self) -> Option<EmailAddress> {
        let sender = self.email_address.as_ref()?;
        Some(EmailAddress {
            name: sender
                .name
                .as_ref()
                .filter(|name| !name.is_empty())
                .cloned(),
            address: sender.address.clone()?,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ForwardBody {
    content_type: String,
    content: String,
}

#[derive(Deserialize)]
struct ForwardOriginal {
    subject: Option<String>,
    from: Option<Recipient>,
    body: ForwardBody,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ForwardFile {
    name: String,
    content_type: Option<String>,
    size: usize,
    is_inline: bool,
}

#[derive(Deserialize)]
struct AttachmentName {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Draft {
    id: String,
    internet_message_id: Option<String>,
    body: Option<Value>,
}

enum DraftStart {
    New,
    Reply(String),
    Forward {
        original: String,
        files: Vec<(String, usize)>,
    },
}

const GRAPH_NEW_FILE_LIMIT: usize = 3_000_000;
// Below Graph's 4 MB ceiling, and a multiple of 320 KiB.
const UPLOAD_RANGE: usize = 12 * 320 * 1024;
const SEND_MAIL_ROOM: usize = 2 * 1024 * 1024;
const SEND_MAIL_LIMIT: usize = 4_000_000;
const DRAFT_CANCELLED: &str = "the call ended before sending";
const SAVE_CANCELLED: &str = "the call ended before the draft finished";

fn needs_draft(text: &str, html: Option<&str>, files: &[OutgoingAttachment]) -> bool {
    let size = text.len() + html.map_or(0, str::len);
    files
        .iter()
        .fold(size, |total, file| total + file.content.len())
        > SEND_MAIL_ROOM
}

fn fits_send_mail(raw_size: usize) -> bool {
    base64::encoded_len(raw_size, true).is_some_and(|len| len <= SEND_MAIL_LIMIT)
}

fn upload_ranges(size: usize) -> impl Iterator<Item = Range<usize>> {
    (0..size)
        .step_by(UPLOAD_RANGE)
        .map(move |start| start..(start + UPLOAD_RANGE).min(size))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FollowUp {
    flag_status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MessageState {
    is_read: Option<bool>,
    flag: Option<FollowUp>,
    parent_folder_id: Option<String>,
}

fn already(state: &MessageState, change: &Change, destination: Option<&str>) -> Option<bool> {
    match change {
        Change::Move(_) | Change::Trash => Some(state.parent_folder_id.as_deref()? == destination?),
        Change::Flags { read, flagged } => {
            let has_read = match read {
                Some(read) => state.is_read? == *read,
                None => true,
            };
            let has_flagged = match flagged {
                Some(flagged) => {
                    (state.flag.as_ref()?.flag_status.as_deref()? == "flagged") == *flagged
                }
                None => true,
            };
            Some(has_read && has_flagged)
        }
    }
}

impl GraphMessage {
    fn flags(&self) -> MessageFlags {
        MessageFlags {
            seen: self.is_read,
            flagged: self
                .flag
                .as_ref()
                .and_then(|flag| flag.flag_status.as_deref())
                == Some("flagged"),
            draft: self.is_draft,
            ..MessageFlags::default()
        }
    }

    fn summary(self) -> Summary {
        let flags = self.flags();
        Summary {
            id: id::provider_id(GRAPH_PREFIX, &self.id),
            uid: None,
            from: self.from.as_ref().and_then(Recipient::email),
            // Graph names the sender's address, not the header it read it from.
            from_clear: true,
            from_values: Vec::new(),
            subject: self.subject,
            date: self
                .received_date_time
                .and_then(|date| chrono::DateTime::parse_from_rfc3339(&date).ok()),
            flags,
            size: None,
        }
    }
}

const MESSAGE_FIELDS: &str = "id,subject,from,receivedDateTime,isRead,isDraft,flag,parentFolderId";

/// A folder resolved for a request: the URL segment (id or well-known name).
#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderRef(String);

/// The operations mirror [`super::Mailbox`], where their errors are
/// documented.
#[allow(
    clippy::missing_errors_doc,
    reason = "the errors are documented on Mailbox"
)]
impl GraphMailbox {
    /// A mailbox for the account behind `api`, whose address is `email`.
    pub const fn new(api: ApiClient, email: String) -> Self {
        Self { api, email }
    }

    fn url(&self, segments: &[&str]) -> Url {
        let mut all = vec!["me"];
        all.extend_from_slice(segments);
        join_segments(&self.api.endpoints().graph, &all)
    }

    fn headers() -> Vec<(HeaderName, String)> {
        vec![(
            HeaderName::from_static("prefer"),
            "IdType=\"ImmutableId\"".to_owned(),
        )]
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &Url) -> MailboxResult<T> {
        self.api
            .get_json(url, &Self::headers())
            .await
            .map_err(graph_error)
    }

    /// Every folder as `(path, folder)`, parents before children.
    async fn all_folders(&self) -> MailboxResult<Vec<(String, GraphFolder)>> {
        let mut out: Vec<(String, GraphFolder)> = Vec::new();
        let mut queue: Vec<(Option<String>, String, usize)> = vec![(None, String::new(), 0)];
        while let Some((parent, prefix, depth)) = queue.pop() {
            let mut url = parent.as_ref().map_or_else(
                || self.url(&["mailFolders"]),
                |id| self.url(&["mailFolders", id, "childFolders"]),
            );
            url.query_pairs_mut()
                .append_pair("$top", "250")
                .append_pair("$select", "id,displayName,childFolderCount");
            let mut next = Some(url);
            while let Some(url) = next.take() {
                let page: Collection<GraphFolder> = self.fetch_json(&url).await?;
                next = self.next_page(page.next_link.as_deref());
                for folder in page.value {
                    if out.len() >= MAX_FOLDERS {
                        return Ok(out);
                    }
                    let path = if prefix.is_empty() {
                        folder.display_name.clone()
                    } else {
                        format!("{prefix}/{}", folder.display_name)
                    };
                    if folder.child_folder_count > 0 && depth + 1 < MAX_DEPTH {
                        queue.push((Some(folder.id.clone()), path.clone(), depth + 1));
                    }
                    out.push((path, folder));
                }
            }
        }
        Ok(out)
    }

    /// Follows an `@odata.nextLink` only if it points at the Graph endpoint.
    fn next_page(&self, link: Option<&str>) -> Option<Url> {
        validated_next_link(&self.api.endpoints().graph, link)
    }

    /// The ids of the well-known folders that exist, with their roles.
    async fn roles(&self) -> HashMap<String, &'static str> {
        let lookups = WELL_KNOWN.iter().map(|(name, role, _)| async move {
            self.folder_id(name).await.ok().map(|id| (id, *role))
        });
        futures::future::join_all(lookups)
            .await
            .into_iter()
            .flatten()
            .collect()
    }

    /// Resolves a folder name from a tool call.
    async fn resolve(&self, name: &str) -> MailboxResult<FolderRef> {
        let name = name.trim().trim_matches('/');
        if let Some(well_known) = well_known(name) {
            return Ok(FolderRef(well_known.to_owned()));
        }
        let folders = self.all_folders().await?;
        folders
            .iter()
            .find(|(path, _)| path.eq_ignore_ascii_case(name))
            .or_else(|| folders.iter().find(|(_, folder)| folder.id == name))
            .map(|(_, folder)| FolderRef(folder.id.clone()))
            .ok_or_else(|| {
                MailboxError::coded(
                    ToolErrorCode::NotFound,
                    format!("there is no folder named {name:?}; use a name from list_folders"),
                )
            })
    }

    async fn folder_id(&self, name: &str) -> MailboxResult<String> {
        if WELL_KNOWN
            .iter()
            .any(|(well_known, _, _)| *well_known == name)
        {
            let mut url = self.url(&["mailFolders", name]);
            url.query_pairs_mut().append_pair("$select", "id");
            let folder: IdOnly = self.fetch_json(&url).await?;
            Ok(folder.id)
        } else {
            Ok(name.to_owned())
        }
    }

    fn message_id(selector: &Selector) -> MailboxResult<&str> {
        provider_message_id(selector, GRAPH_PREFIX)
    }

    /// Lists the folders, with roles from the well-known folders.
    pub async fn list_folders(&self) -> MailboxResult<Vec<FolderEntry>> {
        let (folders, roles) = tokio::join!(self.all_folders(), self.roles());
        let mut entries: Vec<FolderEntry> = folders?
            .into_iter()
            .map(|(path, folder)| FolderEntry {
                role: roles.get(&folder.id).map(|role| (*role).to_owned()),
                name: path,
                selectable: true,
            })
            .collect();
        entries.sort_by(|a, b| {
            (a.role.as_deref() != Some("inbox"), a.name.to_lowercase())
                .cmp(&(b.role.as_deref() != Some("inbox"), b.name.to_lowercase()))
        });
        Ok(entries)
    }

    /// Searches a folder: `$filter` without keywords, `$search` with them.
    pub async fn search(
        &self,
        folder: &str,
        criteria: &Criteria,
        paging: Paging,
    ) -> MailboxResult<Page> {
        let folder = self.resolve(folder).await?;
        if let Some(kql) = keyword_query(criteria)? {
            return self.search_keywords(&folder, criteria, &kql, paging).await;
        }
        let mut url = self.filter_url(&folder, criteria, paging.limit.max(1), MESSAGE_FIELDS);
        url.query_pairs_mut()
            .append_pair("$count", "true")
            .append_pair("$skip", &paging.offset.to_string());
        let page: Collection<GraphMessage> = self.fetch_json(&url).await?;
        let messages: Vec<Summary> = page
            .value
            .into_iter()
            .take(paging.limit)
            .map(GraphMessage::summary)
            .collect();
        let seen = paging.offset + messages.len();
        let (total, estimated) = page.count.map_or_else(
            || (seen + usize::from(page.next_link.is_some()), true),
            |count| (count, false),
        );
        Ok(Page {
            cutoff: None,
            total,
            estimated,
            offset: paging.offset,
            has_more: seen < total || page.next_link.is_some() && messages.len() == paging.limit,
            messages,
        })
    }

    fn filter_url(&self, folder: &FolderRef, criteria: &Criteria, top: usize, fields: &str) -> Url {
        let mut url = self.url(&["mailFolders", &folder.0, "messages"]);
        url.query_pairs_mut()
            .append_pair("$filter", &filter_query(criteria))
            .append_pair("$orderby", "receivedDateTime desc")
            .append_pair("$top", &top.to_string())
            .append_pair("$select", fields);
        url
    }

    fn keyword_url(&self, folder: &FolderRef, kql: &str, top: usize, fields: &str) -> Url {
        let mut url = self.url(&["mailFolders", &folder.0, "messages"]);
        url.query_pairs_mut()
            .append_pair("$search", &format!("\"{kql}\""))
            .append_pair("$top", &top.to_string())
            .append_pair("$select", fields);
        url
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
            &SelectionFilterRules::for_provider(Provider::Graph),
            "Outlook",
        )?;
        let kql = keyword_query(criteria)?;
        let mailbox = Self::new(self.api.until(deadline), self.email.clone());
        let source = mailbox.resolve(folder).await?;
        let destination = mailbox.destination(change).await?;
        if let Some(destination) = &destination
            && (*destination == source
                || mailbox.folder_id(&source.0).await? == mailbox.folder_id(&destination.0).await?)
        {
            return Ok(Selected::own_folder(folder, change, true));
        }
        let fields = "id,isRead,flag,receivedDateTime";
        let mut url = kql.as_ref().map_or_else(
            || mailbox.filter_url(&source, criteria, MAX_SEARCH_WINDOW, fields),
            |kql| mailbox.keyword_url(&source, kql, MAX_SEARCH_WINDOW, &keyword_fields(criteria)),
        );
        let (mut messages, more) = if kql.is_some() {
            mailbox.collect_keyword_matches(url, criteria, most).await?
        } else {
            let mut messages = Vec::new();
            let mut more = false;
            for _ in 0..MAX_SEARCH_PAGES {
                let page: Collection<GraphMessage> = mailbox.fetch_json(&url).await?;
                let next =
                    validated_next_link(&mailbox.api.endpoints().graph, page.next_link.as_deref());
                more = page.value.len() > most - messages.len() || next.is_some();
                messages.extend(page.value.into_iter().take(most - messages.len()));
                if messages.len() >= most {
                    break;
                }
                match next {
                    Some(next) => url = next,
                    None => break,
                }
            }
            (messages, more)
        };
        let window = kql.is_some() && more;
        if window && matches!(change, Change::Flags { .. }) {
            return Err(MailboxError::coded(ToolErrorCode::InvalidInput,
                "a change of read or flagged can't be sure to reach every message Outlook finds by sender, recipient, subject or text; narrow the search with since or before"
                    .to_owned(),
            ));
        }
        if messages.is_empty() && window {
            return Ok(Selected::Done(window_ending()));
        }
        if kql.is_some() {
            mailbox.immutable(&mut messages).await?;
        }
        Ok(Selected::matches(
            messages
                .into_iter()
                .map(|message| id::provider_id(GRAPH_PREFIX, &message.id)),
            more,
        ))
    }

    /// `$search` cannot be combined with `$filter`, `$skip` or `$count`.
    ///
    /// Raw hits are read up to [`MAX_SEARCH_WINDOW`] (following validated next
    /// links within [`MAX_SEARCH_PAGES`]), checked against sender, recipient,
    /// subject, date, unread and flagged filters, and paged locally so the
    /// window's count is known and a short, empty or non-matching Graph page
    /// cannot hide later matches.
    async fn search_keywords(
        &self,
        folder: &FolderRef,
        criteria: &Criteria,
        kql: &str,
        paging: Paging,
    ) -> MailboxResult<Page> {
        if paging.offset >= MAX_SEARCH_WINDOW {
            return Err(MailboxError::coded(
                ToolErrorCode::InvalidInput,
                format!(
                    "keyword searches on Outlook reach the first {MAX_SEARCH_WINDOW} matches; narrow the search"
                ),
            ));
        }
        let url = self.keyword_url(folder, kql, MAX_SEARCH_WINDOW, &keyword_fields(criteria));
        let (mut matching, further) = self
            .collect_keyword_matches(url, criteria, usize::MAX)
            .await?;
        let range = page_range(matching.len(), paging);
        self.immutable(&mut matching[range]).await?;
        Ok(keyword_page(matching, paging, further))
    }

    /// Raw `$search` hits that pass `criteria`.
    ///
    /// Stops once `target` matches are collected, or at [`MAX_SEARCH_WINDOW`]
    /// raw hits or [`MAX_SEARCH_PAGES`]. The bool is true when more hits may
    /// follow: at either cap, when an unconsumed hit or a validated next link
    /// was left behind, or once [`LISTING_TRUSTED`] raw hits have been seen.
    async fn collect_keyword_matches(
        &self,
        mut url: Url,
        criteria: &Criteria,
        target: usize,
    ) -> MailboxResult<(Vec<GraphMessage>, bool)> {
        let mut matching = Vec::new();
        let mut seen = 0usize;
        let mut pages = 0usize;
        loop {
            if pages >= MAX_SEARCH_PAGES {
                return Ok((matching, true));
            }
            pages += 1;
            // Omit `Prefer` so every hit is a `restId` for `immutable`.
            let page: Collection<GraphMessage> =
                self.api.get_json(&url, &[]).await.map_err(graph_error)?;
            let next = validated_next_link(&self.api.endpoints().graph, page.next_link.as_deref());
            let count = page.value.len();
            for (index, message) in page.value.into_iter().enumerate() {
                seen += 1;
                if message_matches(&message, criteria) {
                    matching.push(message);
                }
                if seen >= MAX_SEARCH_WINDOW || matching.len() >= target {
                    let more_on_page = index + 1 < count;
                    return Ok((
                        matching,
                        seen >= LISTING_TRUSTED || more_on_page || next.is_some(),
                    ));
                }
            }
            match next {
                Some(next) => url = next,
                None => return Ok((matching, seen >= LISTING_TRUSTED)),
            }
        }
    }

    async fn raw(&self, message: &str) -> MailboxResult<Bytes> {
        let url = self.url(&["messages", message, "$value"]);
        let response = self
            .api
            .call(
                Method::GET,
                &url,
                &Self::headers(),
                Bytes::new(),
                MESSAGE_LIMIT,
            )
            .await
            .map_err(graph_error)?;
        Ok(response.body)
    }

    async fn metadata(&self, message: &str) -> MailboxResult<GraphMessage> {
        let mut url = self.url(&["messages", message]);
        url.query_pairs_mut().append_pair("$select", MESSAGE_FIELDS);
        self.fetch_json(&url).await
    }

    /// Fetches a message as MIME plus its flags and folder.
    pub async fn get(&self, selector: &Selector) -> MailboxResult<Fetched> {
        let message = Self::message_id(selector)?;
        let (metadata, raw) = tokio::join!(self.metadata(message), self.raw(message));
        let metadata = metadata?;
        let raw = raw?;
        let parsed: Message = mime::parse_message(&raw, metadata.flags()).ok_or_else(|| {
            MailboxError::coded(
                ToolErrorCode::Unsupported,
                "Microsoft returned a message that could not be parsed".to_owned(),
            )
        })?;
        let folder = match &metadata.parent_folder_id {
            Some(parent) => self.folder_name(parent).await,
            None => String::new(),
        };
        Ok(Fetched {
            id: id::provider_id(GRAPH_PREFIX, &metadata.id),
            folder,
            uid: None,
            message: parsed,
        })
    }

    /// One attachment of a message, from its MIME.
    pub async fn attachment(
        &self,
        selector: &Selector,
        id: u32,
        max_bytes: usize,
    ) -> MailboxResult<Option<AttachmentData>> {
        let raw = self.raw(Self::message_id(selector)?).await?;
        Ok(mime::attachment(&raw, id, max_bytes))
    }

    /// The display path of a folder id, or the id if it is not listed.
    async fn folder_name(&self, folder_id: &str) -> String {
        self.all_folders()
            .await
            .ok()
            .and_then(|folders| {
                folders
                    .into_iter()
                    .find(|(_, folder)| folder.id == folder_id)
            })
            .map_or_else(|| folder_id.to_owned(), |(path, _)| path)
    }

    /// Translates regular `$search` ids to Graph immutable ids in place.
    ///
    /// Fails before changing any id if Graph leaves an id out or answers one
    /// that cannot become a message id.
    async fn immutable(&self, messages: &mut [GraphMessage]) -> MailboxResult<()> {
        if messages.is_empty() {
            return Ok(());
        }
        let mut asked = HashSet::with_capacity(messages.len());
        let input_ids: Vec<&str> = messages
            .iter()
            .map(|message| message.id.as_str())
            .filter(|id| asked.insert(*id))
            .collect();
        let body = json!({
            "inputIds": input_ids,
            "sourceIdType": "restId",
            "targetIdType": "restImmutableEntryId",
        });
        drop(input_ids);
        let response = self
            .api
            .send_json(
                Method::POST,
                &self.url(&["translateExchangeIds"]),
                &[],
                &body,
            )
            .await
            .map_err(graph_error)?;
        let answer: Collection<Translated> = self.api.parse(&response).map_err(graph_error)?;
        let no_stable_id = || MailboxError::coded(ToolErrorCode::ProviderUnavailable, NO_STABLE_ID);
        let mut translated = HashMap::with_capacity(asked.len());
        for entry in answer.value {
            let Some(target) = entry.target_id else {
                return Err(no_stable_id());
            };
            if !asked.remove(entry.source_id.as_str())
                || id::parse_provider_id(GRAPH_PREFIX, &id::provider_id(GRAPH_PREFIX, &target))
                    .is_none()
            {
                return Err(no_stable_id());
            }
            translated.insert(entry.source_id, target);
        }
        if !asked.is_empty()
            || translated.values().collect::<HashSet<_>>().len() != translated.len()
        {
            return Err(no_stable_id());
        }
        drop(asked);
        for message in messages {
            message
                .id
                .clone_from(translated.get(&message.id).ok_or_else(no_stable_id)?);
        }
        Ok(())
    }

    async fn batch(
        &self,
        requests: &[serde_json::Value],
        deadline: Instant,
    ) -> Result<Option<Batch>, ApiError> {
        let response = self
            .api
            .call_batch(
                &join_segments(&self.api.endpoints().graph, &["$batch"]),
                &[(header::CONTENT_TYPE, "application/json".to_owned())],
                Bytes::from(json!({ "requests": requests }).to_string()),
                MESSAGE_LIMIT,
                deadline,
            )
            .await?;
        response
            .as_ref()
            .map(|response| self.api.parse(response))
            .transpose()
    }

    async fn destination(&self, change: &Change) -> MailboxResult<Option<FolderRef>> {
        match change {
            Change::Move(name) => self.resolve(name).await.map(Some),
            Change::Trash => Ok(Some(FolderRef("deleteditems".to_owned()))),
            Change::Flags { .. } => Ok(None),
        }
    }

    fn change_request(
        change: &Change,
        destination: Option<&str>,
    ) -> (&'static str, Option<&'static str>, Value) {
        match change {
            Change::Flags { read, flagged } => {
                let mut body = serde_json::Map::new();
                if let Some(read) = read {
                    body.insert("isRead".to_owned(), json!(read));
                }
                if let Some(flagged) = flagged {
                    body.insert(
                        "flag".to_owned(),
                        json!({ "flagStatus": if *flagged { "flagged" } else { "notFlagged" } }),
                    );
                }
                ("PATCH", None, serde_json::Value::Object(body))
            }
            Change::Move(_) | Change::Trash => (
                "POST",
                Some("move"),
                json!({ "destinationId": destination }),
            ),
        }
    }

    fn batch_url(&self, segments: &[&str]) -> String {
        self.url(segments)
            .as_str()
            .strip_prefix(self.api.endpoints().graph.as_str().trim_end_matches('/'))
            .unwrap_or_default()
            .to_owned()
    }

    /// Applies changes through ordered JSON batches, including for one id.
    pub async fn apply(
        &self,
        ids: &[Selector],
        ids_from: IdsFrom,
        change: &Change,
        mode: Mode,
        deadline: Instant,
    ) -> MailboxResult<Vec<Outcome>> {
        let mailbox = Self::new(self.api.until(deadline), self.email.clone());
        let (mut outcomes, valid) = provider_outcomes(ids, GRAPH_PREFIX);
        if valid.is_empty() || Instant::now() >= deadline {
            return Ok(outcomes);
        }
        let destination = match async {
            let destination = mailbox.destination(change).await?;
            match (destination, ids_from) {
                (Some(folder), IdsFrom::Caller) => mailbox.folder_id(&folder.0).await.map(Some),
                (destination, _) => Ok(destination.map(|folder| folder.0)),
            }
        }
        .await
        {
            Err(MailboxError::Deadline) => return Ok(outcomes),
            result => result?,
        };
        if ids_from == IdsFrom::Selection && mode == Mode::DryRun {
            for (index, _) in valid {
                outcomes[index].ok("");
            }
            return Ok(outcomes);
        }
        let (method, action, body) = Self::change_request(change, destination.as_deref());
        let mut sent = false;
        for group in valid.chunks(BATCH_MAX) {
            if Instant::now() >= deadline {
                break;
            }
            let mut ready = Vec::new();
            if ids_from == IdsFrom::Caller {
                let requests = group.iter().map(|(index, id)| {
                    let url = mailbox.batch_url(&["messages", id]);
                    json!({ "id": index.to_string(), "method": "GET", "url": format!("{url}?$select=id,isRead,flag,parentFolderId"),
                        "headers": { "Prefer": "IdType=\"ImmutableId\"" } })
                }).collect();
                let stage = BatchStage::Read {
                    change,
                    destination: destination.as_deref(),
                    mode,
                    ready: &mut ready,
                };
                if !mailbox
                    .run_batch(requests, &mut outcomes, stage, deadline, &mut sent)
                    .await?
                {
                    break;
                }
            }
            if mode == Mode::DryRun {
                continue;
            }
            let requests: Vec<_> = group.iter().filter(|(index, _)| ids_from == IdsFrom::Selection || ready.contains(index)).map(|(index, id)| {
                let url = action.map_or_else(
                    || mailbox.batch_url(&["messages", id]),
                    |action| format!("{}?$select=id", mailbox.batch_url(&["messages", id, action])),
                );
                json!({ "id": index.to_string(), "method": method, "url": url,
                    "headers": { "Prefer": "IdType=\"ImmutableId\"", "Content-Type": "application/json" }, "body": body })
            }).collect();
            let stage = BatchStage::Write {
                moved: action.is_some(),
            };
            if !requests.is_empty()
                && !mailbox
                    .run_batch(requests, &mut outcomes, stage, deadline, &mut sent)
                    .await?
            {
                break;
            }
        }
        Ok(outcomes)
    }

    /// True when there was no reason to stop before the next batch.
    async fn run_batch(
        &self,
        mut requests: Vec<Value>,
        outcomes: &mut [Outcome],
        mut stage: BatchStage<'_>,
        deadline: Instant,
        sent: &mut bool,
    ) -> MailboxResult<bool> {
        let writing = matches!(stage, BatchStage::Write { .. });
        for attempt in 0..2 {
            if Instant::now() >= deadline {
                return Ok(false);
            }
            let batch = match self.batch(&requests, deadline).await {
                Ok(Some(batch)) => batch,
                Ok(None) => return Ok(false),
                Err(err) => {
                    let no_answer = unanswered(&err);
                    if !*sent && !no_answer && matches!(err, ApiError::Token(_) | ApiError::Http(_))
                    {
                        return Err(graph_error(err));
                    }
                    let reason = api_error_message(&err, "Microsoft");
                    let (code, retry_after) = classify_api_error(&err);
                    pending_reason(outcomes, &reason, (code, retry_after));
                    let (status, reason, code, retry_after) = if writing && no_answer {
                        (
                            Status::Failed,
                            SENT_NO_ANSWER,
                            ToolErrorCode::SubmissionUncertain,
                            None,
                        )
                    } else if err.is_rate_limited() || err.status().is_none() {
                        (Status::NotReached, reason.as_str(), code, retry_after)
                    } else {
                        (Status::Failed, reason.as_str(), code, retry_after)
                    };
                    for index in requests.iter().filter_map(batch_index) {
                        outcomes[index].fail(status, reason, code, retry_after);
                    }
                    return Ok(false);
                }
            };
            *sent |= writing;
            let (retry, delay) = batch.finish(&requests, outcomes, &mut stage);
            if retry.is_empty() {
                return Ok(true);
            }
            if attempt != 0
                || Instant::now()
                    .checked_add(delay)
                    .is_none_or(|next| next >= deadline)
            {
                if let Some(index) = retry.first().and_then(batch_index)
                    && let Some(error) = outcomes[index].error
                {
                    let reason = outcomes[index].reason.clone();
                    pending_reason(outcomes, &reason, error);
                }
                return Ok(false);
            }
            tokio::time::sleep(delay).await;
            requests = retry;
        }
        Ok(false)
    }

    /// Deletes one message for good.
    pub async fn delete(&self, selector: &Selector) -> MailboxResult<String> {
        let message = Self::message_id(selector)?;
        self.permanent_delete(message).await?;
        Ok(id::provider_id(GRAPH_PREFIX, message))
    }

    async fn permanent_delete(&self, message: &str) -> MailboxResult<()> {
        self.draft_write(
            Method::POST,
            &self.url(&["messages", message, "permanentDelete"]),
            &json!({}),
            || true,
        )
        .await
        .map_err(|err| write_error(err, "Microsoft"))
    }

    /// Creates a folder; `Parent/Child` creates a child folder.
    pub async fn create_folder(&self, name: &str) -> MailboxResult<()> {
        let name = name.trim().trim_matches('/');
        let (parent, leaf) = match name.rsplit_once('/') {
            Some((parent, leaf)) => (Some(self.resolve(parent).await?), leaf),
            None => (None, name),
        };
        if leaf.trim().is_empty() {
            return Err(MailboxError::coded(
                ToolErrorCode::InvalidInput,
                "the folder name is empty",
            ));
        }
        let url = parent.as_ref().map_or_else(
            || self.url(&["mailFolders"]),
            |parent| self.url(&["mailFolders", &parent.0, "childFolders"]),
        );
        match self
            .api
            .send_json(
                Method::POST,
                &url,
                &Self::headers(),
                &json!({ "displayName": leaf }),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(err) if err.status() == Some(StatusCode::CONFLICT) => Err(MailboxError::coded(
                ToolErrorCode::InvalidInput,
                format!("a folder named {name:?} already exists"),
            )),
            Err(err) => Err(write_error(err, "Microsoft")),
        }
    }

    fn from(&self) -> EmailAddress {
        EmailAddress::new(self.email.clone())
    }

    async fn submit_if_fits(
        &self,
        composed: mime::Composed,
        options: SendOptions,
    ) -> MailboxResult<Option<SentMessage>> {
        if !fits_send_mail(composed.raw.len()) {
            return Ok(None);
        }
        let body = base64::engine::general_purpose::STANDARD.encode(composed.raw);
        self.api
            .call(
                Method::POST,
                &self.url(&["sendMail"]),
                &[(header::CONTENT_TYPE, "text/plain".to_owned())],
                Bytes::from(body),
                JSON_LIMIT,
            )
            .await
            .map_err(|err| maybe_sent(SendError::Api(err, "Microsoft")))?;
        Ok(Some(Self::sent(composed.message_id, options)))
    }

    pub(crate) async fn forward_original(&self, selector: &Selector) -> MailboxResult<Forwarded> {
        let id = Self::message_id(selector)?;
        let mut url = self.url(&["messages", id]);
        url.query_pairs_mut()
            .append_pair("$select", "subject,from,body");
        let original: ForwardOriginal =
            self.api
                .get_json(&url, &Self::headers())
                .await
                .map_err(|error| match error {
                    ApiError::Http(HttpError::TooLarge(_)) => too_large_to_forward(),
                    other => graph_error(other),
                })?;
        let files: Vec<ForwardFile> = self
            .message_files(id, "name,contentType,size,isInline")
            .await?;
        let subject = original.subject.unwrap_or_default();
        let sender = original
            .from
            .as_ref()
            .and_then(Recipient::email)
            .as_ref()
            .map(format_address)
            .unwrap_or_default();
        let body = serde_json::to_vec(&original.body).map_err(|_| {
            MailboxError::coded(
                ToolErrorCode::ProviderUnavailable,
                "could not pin the forwarded body",
            )
        })?;
        let pinned_files = serde_json::to_vec(&files).map_err(|_| {
            MailboxError::coded(
                ToolErrorCode::ProviderUnavailable,
                "could not pin the forwarded files",
            )
        })?;
        Ok(Forwarded {
            pin: forward::pin([
                body.as_slice(),
                &pinned_files,
                subject.as_bytes(),
                sender.as_bytes(),
            ]),
            subject,
            sender,
            files: files
                .into_iter()
                .map(|file| (file.name, file.size))
                .collect(),
        })
    }

    async fn message_files<T: serde::de::DeserializeOwned>(
        &self,
        id: &str,
        fields: &str,
    ) -> MailboxResult<Vec<T>> {
        let mut url = self.url(&["messages", id, "attachments"]);
        url.query_pairs_mut().append_pair("$select", fields);
        let mut files = Vec::new();
        loop {
            let page: Collection<T> = self.fetch_json(&url).await?;
            files.extend(page.value);
            let Some(next) = page.next_link else {
                return Ok(files);
            };
            url = self.next_page(Some(&next)).ok_or_else(|| {
                MailboxError::coded(
                    ToolErrorCode::ProviderUnavailable,
                    "Outlook did not return a complete file list",
                )
            })?;
        }
    }

    pub(crate) async fn forward(
        &self,
        selector: &Selector,
        message: OutgoingMessage,
        files: Vec<(String, usize)>,
        options: SendOptions,
        request: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<SentMessage> {
        let original = Self::message_id(selector)?.to_owned();
        self.send_draft(
            DraftStart::Forward { original, files },
            message,
            options,
            request,
            room,
        )
        .await
    }

    async fn send_draft(
        &self,
        start: DraftStart,
        message: OutgoingMessage,
        options: SendOptions,
        request: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<SentMessage> {
        let draft = self.run_draft(start, message, true, request, room).await?;
        Ok(Self::sent(
            draft.internet_message_id.unwrap_or_default(),
            options,
        ))
    }

    async fn save_draft(
        &self,
        start: DraftStart,
        message: OutgoingMessage,
        request: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<SavedDraft> {
        let draft = self.run_draft(start, message, false, request, room).await?;
        Ok(SavedDraft {
            id: Some(id::provider_id(GRAPH_PREFIX, &draft.id)),
            message_id: strip_brackets(draft.internet_message_id.as_deref()).unwrap_or_default(),
            folder: "Drafts".to_owned(),
        })
    }

    /// Keep draft cleanup alive if the MCP call goes away while a request is in flight.
    /// The memory reservation, `room`, lasts as long as the task.
    async fn run_draft(
        &self,
        start: DraftStart,
        message: OutgoingMessage,
        send: bool,
        request: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<Draft> {
        let mailbox = self.clone();
        let cancel = request.child_token();
        // Also cancel if the server drops the tool future rather than signalling rmcp.
        let _on_drop = cancel.clone().drop_guard();
        tokio::spawn(async move {
            let result = mailbox.draft_task(start, message, send, &cancel).await;
            drop(room);
            result
        })
        .await
        .map_err(|_| {
            let message = if send {
                MAY_HAVE_BEEN_SENT
            } else {
                DRAFT_UNCONFIRMED
            };
            MailboxError::coded(ToolErrorCode::SubmissionUncertain, message)
        })?
    }

    async fn draft_write(
        &self,
        method: Method,
        url: &Url,
        body: &Value,
        can_start: impl Fn() -> bool + Sync,
    ) -> Result<(), ApiError> {
        let mut headers = Self::headers();
        headers.push((header::CONTENT_TYPE, "application/json".to_owned()));
        self.api
            .call_status(
                method,
                url,
                &headers,
                Bytes::from(body.to_string()),
                can_start,
            )
            .await
    }

    async fn post_draft(
        &self,
        start: &DraftStart,
        message: &OutgoingMessage,
        send: bool,
    ) -> MailboxResult<Draft> {
        let (url, body, original) = match start {
            DraftStart::New => (self.url(&["messages"]), draft_body(message), None),
            DraftStart::Reply(id) => (
                self.url(&["messages", id, "createReply"]),
                json!({}),
                Some(id.as_str()),
            ),
            DraftStart::Forward { original, .. } => (
                self.url(&["messages", original, "createForward"]),
                json!({"toRecipients": recipients(&message.to)}),
                Some(original.as_str()),
            ),
        };
        let mut headers = Self::headers();
        headers.push((header::CONTENT_TYPE, "application/json".to_owned()));
        let answer = self
            .api
            .call(
                Method::POST,
                &url,
                &headers,
                Bytes::from(body.to_string()),
                MESSAGE_LIMIT,
            )
            .await;
        let answer = answer.map_err(|error| {
            let uncertain = provider_may_have_acted(&error);
            if send {
                let draft = if uncertain {
                    " A draft may remain in Drafts."
                } else {
                    ""
                };
                submit_error(&error, "Microsoft")
                    .map_message(|message| format!("Not sent: {message}.{draft}"))
            } else if uncertain {
                MailboxError::coded(ToolErrorCode::SubmissionUncertain, DRAFT_UNCONFIRMED)
            } else {
                match submit_error(&error, "Microsoft") {
                    MailboxError::Deadline => MailboxError::Deadline,
                    other => other.map_message(|message| format!("Draft not saved: {message}.")),
                }
            }
        })?;
        let invalid = "Outlook did not return a valid draft id. Check Drafts before trying again.";
        let invalid_id = |not_sent| {
            if send {
                MailboxError::coded(ToolErrorCode::ProviderUnavailable, not_sent)
            } else {
                MailboxError::coded(ToolErrorCode::SubmissionUncertain, invalid)
            }
        };
        let draft: Draft = self.api.parse(&answer).map_err(|_| {
            invalid_id(
                "Not sent: Outlook did not return the draft's id. A draft may remain in Drafts.",
            )
        })?;
        if draft.id.is_empty()
            || original == Some(draft.id.as_str())
            || id::parse_provider_id(GRAPH_PREFIX, &id::provider_id(GRAPH_PREFIX, &draft.id))
                .is_none()
        {
            return Err(invalid_id(
                "Not sent: Outlook did not return a new draft id. A draft may remain in Drafts.",
            ));
        }
        Ok(draft)
    }

    async fn draft_task(
        &self,
        start: DraftStart,
        message: OutgoingMessage,
        send: bool,
        cancel: &CancellationToken,
    ) -> MailboxResult<Draft> {
        let cancelled = if send {
            DRAFT_CANCELLED
        } else {
            SAVE_CANCELLED
        };
        let prefix = if send { "Not sent" } else { "Draft not saved" };
        if cancel.is_cancelled() {
            return Err(MailboxError::coded(ToolErrorCode::Timeout, cancelled));
        }
        let mut draft = self.post_draft(&start, &message, send).await?;
        let draft_id = &draft.id;
        let pre_send = async {
            match start {
                DraftStart::New => {}
                DraftStart::Reply(_) => {
                    self.draft_write(
                        Method::PATCH,
                        &self.url(&["messages", draft_id]),
                        &draft_body(&message),
                        || !cancel.is_cancelled(),
                    )
                    .await
                    .map_err(|err| submit_error(&err, "Microsoft"))?;
                    // Outlook can copy inline files from the original into the reply draft.
                    let files: Vec<IdOnly> = tokio::select! {
                        () = cancel.cancelled() => return Err(MailboxError::coded(ToolErrorCode::Timeout, cancelled)),
                        files = self.message_files(draft_id, "id") => files?,
                    };
                    for file in files {
                        self.api
                            .call_status(
                                Method::DELETE,
                                &self.url(&["messages", draft_id, "attachments", &file.id]),
                                &Self::headers(),
                                Bytes::new(),
                                || !cancel.is_cancelled(),
                            )
                            .await
                            .map_err(|err| submit_error(&err, "Microsoft"))?;
                    }
                }
                DraftStart::Forward { files, .. } => {
                    self.update_forward(draft_id, draft.body.take(), &message, files, cancel)
                        .await?;
                }
            }
            self.add_files(draft_id, message.attachments, cancel, cancelled)
                .await
        }
        .await;
        let error = match pre_send {
            Ok(()) if !cancel.is_cancelled() && !send => return Ok(draft),
            Ok(()) if !cancel.is_cancelled() => {
                match self
                    .api
                    .call_status(
                        Method::POST,
                        &self.url(&["messages", draft_id, "send"]),
                        &Self::headers(),
                        Bytes::new(),
                        || !cancel.is_cancelled(),
                    )
                    .await
                {
                    Ok(()) => return Ok(draft),
                    // A gateway can fail after Exchange accepts the send. The immutable id
                    // could now name the Sent copy, so do not delete it or retry.
                    Err(error) if provider_may_have_acted(&error) => {
                        return Err(MailboxError::coded(
                            ToolErrorCode::SubmissionUncertain,
                            MAY_HAVE_BEEN_SENT,
                        ));
                    }
                    Err(error) => submit_error(&error, "Microsoft"),
                }
            }
            Ok(()) => MailboxError::coded(ToolErrorCode::Timeout, cancelled),
            Err(error) => error,
        };
        let cleanup = if self.permanent_delete(draft_id).await.is_ok() {
            ""
        } else {
            " A draft may remain in Drafts."
        };
        if !send && !cleanup.is_empty() {
            return Err(MailboxError::coded(
                ToolErrorCode::SubmissionUncertain,
                DRAFT_UNCONFIRMED,
            ));
        }
        Err(error.map_message(|message| format!("{prefix}: {message}.{cleanup}")))
    }

    async fn update_forward(
        &self,
        id: &str,
        body: Option<Value>,
        message: &OutgoingMessage,
        expected: Vec<(String, usize)>,
        cancel: &CancellationToken,
    ) -> MailboxResult<()> {
        if cancel.is_cancelled() {
            return Err(MailboxError::coded(ToolErrorCode::Timeout, DRAFT_CANCELLED));
        }
        let mut body: ForwardBody =
            serde_json::from_value(body.unwrap_or_default()).map_err(|_| {
                MailboxError::coded(
                    ToolErrorCode::ProviderUnavailable,
                    "Outlook returned a forward draft without its body",
                )
            })?;
        if body.content_type.eq_ignore_ascii_case("html") {
            body.content = prefix_html(
                &body.content,
                &format!("{}<br><br>", forward::note_html(&message.text_body)),
            );
        } else if body.content_type.eq_ignore_ascii_case("text") {
            body.content = format!("{}\n\n{}", message.text_body, body.content);
        } else {
            return Err(MailboxError::coded(
                ToolErrorCode::Unsupported,
                "Outlook returned a forward draft with an unknown body type",
            ));
        }
        self.draft_write(
            Method::PATCH,
            &self.url(&["messages", id]),
            &json!({
                "subject": message.subject, "ccRecipients": recipients(&message.cc),
                "bccRecipients": recipients(&message.bcc), "body": body,
            }),
            || !cancel.is_cancelled(),
        )
        .await
        .map_err(|error| submit_error(&error, "Microsoft"))?;
        let files: Vec<AttachmentName> = tokio::select! {
            () = cancel.cancelled() => return Err(MailboxError::coded(ToolErrorCode::Timeout, DRAFT_CANCELLED)),
            files = self.message_files(id, "name") => files?,
        };
        let mut matched = files.len() == expected.len();
        let mut present = HashMap::new();
        for file in files {
            *present.entry(file.name).or_insert(0_usize) += 1;
        }
        matched &= expected.into_iter().all(|(name, _)| {
            let Some(count) = present.get_mut(&name).filter(|count| **count > 0) else {
                return false;
            };
            *count -= 1;
            true
        });
        if !matched {
            return Err(MailboxError::coded(
                ToolErrorCode::ProviderUnavailable,
                "Outlook did not carry every file of the message into the forward; nothing was sent",
            ));
        }
        Ok(())
    }

    async fn add_files(
        &self,
        id: &str,
        files: Vec<OutgoingAttachment>,
        cancel: &CancellationToken,
        cancelled: &str,
    ) -> MailboxResult<()> {
        for file in files {
            if cancel.is_cancelled() {
                return Err(MailboxError::coded(ToolErrorCode::Timeout, cancelled));
            }
            if file.content.len() >= GRAPH_NEW_FILE_LIMIT {
                let name = forward::display_file(&file.filename);
                if let Err((code, retry_after_seconds)) = self.upload_file(id, file, cancel).await {
                    return Err(MailboxError::Coded {
                        code,
                        retry_after_seconds,
                        message: format!("Outlook did not confirm the file {name:?}"),
                    });
                }
                continue;
            }
            let body = json!({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": file.filename, "contentType": file.content_type,
                "contentBytes": base64::engine::general_purpose::STANDARD.encode(&file.content),
            });
            self.draft_write(
                Method::POST,
                &self.url(&["messages", id, "attachments"]),
                &body,
                || !cancel.is_cancelled(),
            )
            .await
            .map_err(|error| submit_error(&error, "Microsoft"))?;
        }
        Ok(())
    }

    // Do not surface session or range errors: a response can echo the upload URL's token.
    async fn upload_file(
        &self,
        id: &str,
        file: OutgoingAttachment,
        cancel: &CancellationToken,
    ) -> Result<(), (ToolErrorCode, Option<u64>)> {
        let malformed = (ToolErrorCode::ProviderUnavailable, None);
        let size = file.content.len();
        let session = self
            .api
            .send_json(
                Method::POST,
                &self.url(&["messages", id, "attachments", "createUploadSession"]),
                &Self::headers(),
                &json!({"AttachmentItem": {
                    "attachmentType": "file", "name": file.filename,
                    "size": size, "contentType": file.content_type,
                }}),
            )
            .await
            .map_err(|err| classify_api_error(&err))?;
        let answer: Value = session.json().map_err(|_| malformed)?;
        let url = answer["uploadUrl"]
            .as_str()
            .and_then(|url| Url::parse(url).ok())
            .ok_or(malformed)?;
        let data = Bytes::from(file.content);
        for range in upload_ranges(size) {
            let next = range.end;
            let header = format!("bytes {}-{}/{size}", range.start, next - 1);
            let (status, body) = self
                .api
                .put_range(&url, header, data.slice(range), || !cancel.is_cancelled())
                .await
                .map_err(|err| classify_api_error(&err))?;
            if next == size {
                return (status == StatusCode::CREATED)
                    .then_some(())
                    .ok_or(malformed);
            }
            if status != StatusCode::OK || next_expected_range(&body) != Some(next) {
                return Err(malformed);
            }
        }
        Err(malformed)
    }

    /// Outlook always stores the message in Sent Items, so `options`
    /// cannot turn that off.
    fn sent(message_id: String, _options: SendOptions) -> SentMessage {
        SentMessage {
            message_id,
            sent_copy: SentCopy::AlreadyPresent {
                folder: "Sent Items".to_owned(),
            },
        }
    }

    /// Sends a new message, through a draft if it does not fit `sendMail`.
    pub async fn send(
        &self,
        message: &OutgoingMessage,
        options: SendOptions,
    ) -> MailboxResult<SentMessage> {
        self.send_with_cancel(
            Cow::Borrowed(message),
            options,
            CancellationToken::new(),
            None,
        )
        .await
    }

    pub(crate) async fn send_with_cancel(
        &self,
        mut message: Cow<'_, OutgoingMessage>,
        options: SendOptions,
        cancel: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<SentMessage> {
        if needs_draft(
            &message.text_body,
            message.html_body.as_deref(),
            &message.attachments,
        ) {
            self.validate_headers(message.to_mut())?;
        } else if let Some(sent) = self
            .submit_if_fits(mime::compose(&self.from(), &message)?, options)
            .await?
        {
            return Ok(sent);
        }
        self.send_draft(DraftStart::New, message.into_owned(), options, cancel, room)
            .await
    }

    /// Replies to a message, through a draft if it does not fit `sendMail`.
    pub async fn reply(
        &self,
        selector: &Selector,
        reply: &Reply,
        options: SendOptions,
    ) -> MailboxResult<SentMessage> {
        self.reply_with_cancel(
            selector,
            Cow::Borrowed(reply),
            options,
            CancellationToken::new(),
            None,
        )
        .await
    }

    pub(crate) async fn reply_with_cancel(
        &self,
        selector: &Selector,
        reply: Cow<'_, Reply>,
        options: SendOptions,
        cancel: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<SentMessage> {
        let id = Self::message_id(selector)?;
        let original = self.fetch_original(id).await?;
        let large = needs_draft(
            &reply.text_body,
            reply.html_body.as_deref(),
            &reply.attachments,
        );
        if !large
            && let Some(sent) = self
                .submit_if_fits(
                    mime::compose_reply(&self.from(), &original, &reply)?,
                    options,
                )
                .await?
        {
            return Ok(sent);
        }
        let message = self.prepare_reply_draft(&original, reply.into_owned(), large)?;
        self.send_draft(
            DraftStart::Reply(id.to_owned()),
            message,
            options,
            cancel,
            room,
        )
        .await
    }

    fn prepare_reply_draft(
        &self,
        original: &postkeep_mail::MessageHeaders,
        mut reply: Reply,
        validate: bool,
    ) -> MailboxResult<OutgoingMessage> {
        let files = std::mem::take(&mut reply.attachments);
        let mut message = mime::reply_message(original, &self.email, &reply)?;
        drop(reply);
        if validate {
            self.validate_headers(&mut message)?;
        }
        message.attachments = files;
        Ok(message)
    }

    fn validate_headers(&self, message: &mut OutgoingMessage) -> MailboxResult<()> {
        let files = std::mem::take(&mut message.attachments);
        let composed = mime::compose(&self.from(), message);
        message.attachments = files;
        composed.map(drop).map_err(Into::into)
    }

    async fn fetch_original(&self, id: &str) -> MailboxResult<postkeep_mail::MessageHeaders> {
        let raw = self.raw(id).await?;
        mime::parse_headers(&raw).ok_or_else(|| {
            MailboxError::coded(
                ToolErrorCode::Unsupported,
                "the original message could not be parsed",
            )
        })
    }

    /// Saves a new message to Drafts without sending it.
    pub async fn create_draft(&self, message: &OutgoingMessage) -> MailboxResult<SavedDraft> {
        self.create_draft_with_cancel(Cow::Borrowed(message), CancellationToken::new(), None)
            .await
    }

    pub(crate) async fn create_draft_with_cancel(
        &self,
        mut message: Cow<'_, OutgoingMessage>,
        cancel: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<SavedDraft> {
        self.validate_headers(message.to_mut())?;
        self.save_draft(DraftStart::New, message.into_owned(), cancel, room)
            .await
    }

    /// Saves a threaded reply to Drafts without sending it.
    pub async fn create_reply_draft(
        &self,
        selector: &Selector,
        reply: &Reply,
    ) -> MailboxResult<SavedDraft> {
        self.create_reply_draft_with_cancel(
            selector,
            Cow::Borrowed(reply),
            CancellationToken::new(),
            None,
        )
        .await
    }

    pub(crate) async fn create_reply_draft_with_cancel(
        &self,
        selector: &Selector,
        reply: Cow<'_, Reply>,
        cancel: CancellationToken,
        room: Option<SemaphorePermit<'static>>,
    ) -> MailboxResult<SavedDraft> {
        let id = Self::message_id(selector)?;
        let original = self.fetch_original(id).await?;
        let message = self.prepare_reply_draft(&original, reply.into_owned(), true)?;
        self.save_draft(DraftStart::Reply(id.to_owned()), message, cancel, room)
            .await
    }
}

fn strip_brackets(id: Option<&str>) -> Option<String> {
    let id = id?.trim();
    Some(
        id.strip_prefix('<')
            .and_then(|inner| inner.strip_suffix('>'))
            .unwrap_or(id)
            .to_owned(),
    )
}

fn draft_body(message: &OutgoingMessage) -> Value {
    let (kind, content) = message
        .html_body
        .as_deref()
        .map_or(("text", message.text_body.as_str()), |html| ("html", html));
    json!({
        "subject": message.subject,
        "body": {"contentType": kind, "content": content},
        "toRecipients": recipients(&message.to), "ccRecipients": recipients(&message.cc),
        "bccRecipients": recipients(&message.bcc),
    })
}

fn next_expected_range(body: &[u8]) -> Option<usize> {
    let reply: Value = serde_json::from_slice(body).ok()?;
    let range = reply.get("nextExpectedRanges")?.get(0)?.as_str()?;
    let (start, end) = range.split_once('-').unwrap_or((range, ""));
    if !start.bytes().chain(end.bytes()).all(|b| b.is_ascii_digit()) {
        return None;
    }
    if !end.is_empty() {
        end.parse::<usize>().ok()?;
    }
    start.parse().ok()
}

#[derive(Debug, Deserialize)]
struct IdOnly {
    id: String,
}

/// The provider id in `selector`, which must carry an id with `prefix`.
pub(super) fn provider_message_id<'a>(
    selector: &'a Selector,
    prefix: &str,
) -> MailboxResult<&'a str> {
    let given = selector
        .id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let given = given.ok_or_else(|| {
        MailboxError::coded(ToolErrorCode::InvalidInput,
            "pass the message's id from search_messages (folder and uid only work for IMAP accounts)"
                .to_owned(),
        )
    })?;
    id::parse_provider_id(prefix, given).ok_or_else(|| {
        MailboxError::coded(
            ToolErrorCode::InvalidInput,
            "the id is not a message id of this account; take ids from search_messages".to_owned(),
        )
    })
}

/// The Graph well-known folder name for a common folder name.
fn well_known(name: &str) -> Option<&'static str> {
    let lower = name.to_lowercase();
    WELL_KNOWN
        .iter()
        .find(|(_, _, aliases)| aliases.contains(&lower.as_str()))
        .map(|(well_known, _, _)| *well_known)
}

fn recipients(addresses: &[EmailAddress]) -> Vec<Value> {
    addresses
        .iter()
        .map(|address| {
            let mut email = json!({"address": address.address});
            if let Some(name) = &address.name {
                email["name"] = json!(name);
            }
            json!({"emailAddress": email})
        })
        .collect()
}

/// An `@odata.nextLink` that stays on `base`: the same scheme, host, port
/// and a path under `base`. Anything else is treated as absent.
#[must_use]
pub(crate) fn validated_next_link(base: &Url, link: Option<&str>) -> Option<Url> {
    let url = Url::parse(link?).ok()?;
    let same = url.scheme() == base.scheme()
        && url.host_str() == base.host_str()
        && url.port_or_known_default() == base.port_or_known_default()
        && url.path().starts_with(base.path());
    same.then_some(url)
}

pub(crate) fn window_ending() -> String {
    format!(
        "{NOTHING_LEFT} among the messages Outlook's search returned; more may match: narrow the search with since or before"
    )
}

/// The fields needed to check keyword hits and show the results.
fn keyword_fields(criteria: &Criteria) -> std::borrow::Cow<'static, str> {
    if criteria.to.is_some() {
        format!("{MESSAGE_FIELDS},toRecipients").into()
    } else {
        MESSAGE_FIELDS.into()
    }
}

/// Whether `message` passes the filters checked after `$search`.
fn message_matches(message: &GraphMessage, criteria: &Criteria) -> bool {
    let flags = message.flags();
    let since = criteria.since.map(super::day_start);
    let until = match criteria.until {
        Some(Cutoff::Time(seconds)) => Some(seconds),
        _ => None,
    };
    let before = criteria
        .before
        .map(super::day_start)
        .into_iter()
        .chain(until)
        .min();
    criteria.read.is_none_or(|read| flags.seen == read)
        && criteria
            .flagged
            .is_none_or(|flagged| flags.flagged == flagged)
        && ((since.is_none() && before.is_none())
            || message
                .received_date_time
                .as_deref()
                .and_then(|time| chrono::DateTime::parse_from_rfc3339(time).ok())
                .is_some_and(|time| {
                    since.is_none_or(|since| time.timestamp() >= since)
                        && before.is_none_or(|before| time.timestamp() < before)
                }))
        && criteria.subject.as_deref().is_none_or(|value| {
            message
                .subject
                .as_deref()
                .is_some_and(|subject| holds(&postkeep_mail::invisible::visible(subject), value))
        })
        && criteria.from.as_deref().is_none_or(|value| {
            message
                .from
                .as_ref()
                .and_then(Recipient::email)
                .is_some_and(|from| holds_addresses(std::slice::from_ref(&from), value))
        })
        && criteria.to.as_deref().is_none_or(|value| {
            message.to_recipients.as_ref().is_some_and(|recipients| {
                let addresses: Vec<_> = recipients.iter().filter_map(Recipient::email).collect();
                holds_addresses(&addresses, value)
            })
        })
}

fn page_range(len: usize, paging: Paging) -> Range<usize> {
    let start = paging.offset.min(len);
    start..start.saturating_add(paging.limit).min(len)
}

/// One local page of keyword matches. `has_more` counts only matches inside the
/// window, and `estimated` reflects whether more raw hits may follow it.
fn keyword_page(mut matching: Vec<GraphMessage>, paging: Paging, estimated: bool) -> Page {
    let total = matching.len();
    let range = page_range(total, paging);
    let messages: Vec<Summary> = matching.drain(range).map(GraphMessage::summary).collect();
    let has_more = !messages.is_empty() && total > paging.offset.saturating_add(messages.len());
    Page {
        cutoff: None,
        total,
        estimated,
        offset: paging.offset,
        has_more,
        messages,
    }
}

/// The `$filter` for criteria without keywords. `receivedDateTime` comes
/// first because results are ordered by it (Graph refuses other orders).
fn filter_query(criteria: &Criteria) -> String {
    let timestamp = |seconds| {
        chrono::DateTime::from_timestamp(seconds, 0)
            .map(|time| time.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    };
    let since = criteria
        .since
        .map(super::day_start)
        .and_then(timestamp)
        .unwrap_or_else(|| "1900-01-01T00:00:00Z".to_owned());
    let mut parts = vec![format!("receivedDateTime ge {since}")];
    if let Some(Cutoff::Time(seconds)) = criteria.until
        && let Some(until) = timestamp(seconds)
    {
        parts.push(format!("receivedDateTime lt {until}"));
    }
    if let Some(before) = criteria.before.map(super::day_start).and_then(timestamp) {
        parts.push(format!("receivedDateTime lt {before}"));
    }
    if let Some(read) = criteria.read {
        parts.push(format!("isRead eq {read}"));
    }
    if let Some(flagged) = criteria.flagged {
        parts.push(format!(
            "flag/flagStatus {} 'flagged'",
            if flagged { "eq" } else { "ne" }
        ));
    }
    parts.join(" and ")
}

/// The KQL for `$search`, if a text filter was given. The date range is
/// deliberately wider than the UTC days checked on each hit.
fn keyword_query(criteria: &Criteria) -> MailboxResult<Option<String>> {
    let mut terms = Vec::new();
    for (filter, value) in criteria.text_filters() {
        for word in super::words(filter, value, "Outlook")? {
            terms.push(if filter == "text" {
                word
            } else {
                format!("{filter}:{word}")
            });
        }
    }
    if terms.is_empty() {
        return Ok(None);
    }
    if let Some(since) = criteria.since.and_then(|day| day.pred_opt()) {
        terms.push(format!("received>={}", since.format("%Y-%m-%d")));
    }
    if let Some(before) = criteria.before.and_then(|day| day.succ_opt()) {
        terms.push(format!("received<{}", before.format("%Y-%m-%d")));
    }
    Ok(Some(terms.join(" AND ")))
}

/// Phrases a Graph error for the model.
#[expect(clippy::needless_pass_by_value, reason = "passed to map_err by name")]
pub(super) fn graph_error(err: ApiError) -> MailboxError {
    provider_error(&err, "Microsoft")
}

pub(super) fn classify_api_error(err: &ApiError) -> (ToolErrorCode, Option<u64>) {
    const fn http_code(err: &HttpError) -> ToolErrorCode {
        match err {
            HttpError::Deadline | HttpError::Timeout(_) => ToolErrorCode::Timeout,
            HttpError::TooLarge(_) => ToolErrorCode::PayloadTooLarge,
            HttpError::Request(_) => ToolErrorCode::InvalidInput,
            _ => ToolErrorCode::ProviderUnavailable,
        }
    }
    let code = match err {
        ApiError::Token(
            TokenError::NotConnected(_)
            | TokenError::NeedsReauth { .. }
            | TokenError::OAuth(
                OAuthError::NeedsReauth { .. }
                | OAuthError::MissingScopes(_)
                | OAuthError::NoMailbox(_),
            ),
        ) => ToolErrorCode::AuthRequired,
        ApiError::Token(TokenError::Store(err)) => account_store_code(err),
        ApiError::Token(TokenError::OAuth(OAuthError::NotConfigured(_))) => {
            ToolErrorCode::Unsupported
        }
        ApiError::Token(TokenError::OAuth(OAuthError::Http(err))) | ApiError::Http(err) => {
            http_code(err)
        }
        ApiError::Token(TokenError::OAuth(err)) if err.is_rate_limited() => {
            return (ToolErrorCode::RateLimited, err.retry_after());
        }
        ApiError::Token(TokenError::OAuth(err)) if err.is_server_unavailable() => {
            return (ToolErrorCode::ProviderUnavailable, err.retry_after());
        }
        ApiError::Token(TokenError::OAuth(OAuthError::Rejected { status, .. }))
            if status.is_client_error() =>
        {
            ToolErrorCode::AuthRequired
        }
        ApiError::Status { .. } if err.is_any_rate_limit() => {
            return (ToolErrorCode::RateLimited, err.retry_after());
        }
        ApiError::Status { status, .. } => match *status {
            StatusCode::UNAUTHORIZED => ToolErrorCode::AuthRequired,
            StatusCode::FORBIDDEN => ToolErrorCode::PermissionDenied,
            StatusCode::NOT_FOUND => ToolErrorCode::NotFound,
            StatusCode::REQUEST_TIMEOUT => ToolErrorCode::Timeout,
            StatusCode::PAYLOAD_TOO_LARGE => ToolErrorCode::PayloadTooLarge,
            status if status.is_client_error() => ToolErrorCode::InvalidInput,
            status if status.is_server_error() => {
                return (ToolErrorCode::ProviderUnavailable, err.retry_after());
            }
            _ => ToolErrorCode::ProviderUnavailable,
        },
        _ => ToolErrorCode::ProviderUnavailable,
    };
    (code, None)
}

pub(super) fn provider_error(err: &ApiError, who: &str) -> MailboxError {
    if err.is_deadline() {
        MailboxError::Deadline
    } else {
        let (code, retry_after_seconds) = classify_api_error(err);
        MailboxError::Coded {
            code,
            retry_after_seconds,
            message: api_error_message(err, who),
        }
    }
}

pub(crate) const WRITE_UNCONFIRMED: &str =
    "The provider did not confirm the change. Check before trying again.";

#[expect(
    clippy::needless_pass_by_value,
    reason = "used to convert owned errors at write call sites"
)]
pub(super) fn write_error(err: ApiError, who: &str) -> MailboxError {
    if provider_may_have_acted(&err) {
        MailboxError::coded(ToolErrorCode::SubmissionUncertain, WRITE_UNCONFIRMED)
    } else {
        provider_error(&err, who)
    }
}

/// Phrases a provider refusal of a message being submitted.
pub(super) fn submit_error(err: &ApiError, who: &str) -> MailboxError {
    let error = provider_error(err, who);
    if err.status() == Some(StatusCode::PAYLOAD_TOO_LARGE) {
        error.map_message(|_| format!("{who} refused the message as too large"))
    } else {
        error
    }
}

/// Phrases an API error for the model. `who` names the provider.
pub(super) fn api_error_message(err: &ApiError, who: &str) -> String {
    match err {
        ApiError::Token(err) => err.to_string(),
        ApiError::Status { status, .. } if *status == StatusCode::NOT_FOUND => {
            "no such message or folder (it may have been moved or deleted); search again".to_owned()
        }
        ApiError::Status { .. } if err.is_daily_limit_exceeded() => {
            format!(
                "{who}'s daily request limit for this server is used up; try again later. \
                 Signing in again won't help"
            )
        }
        ApiError::Status { .. } if err.is_rate_limited() => {
            format!("{who} is limiting requests for this account; try again in a minute")
        }
        ApiError::Status { status, .. } if *status == StatusCode::FORBIDDEN => format!(
            "{who} refused the request ({err}). If the account's permissions changed, sign in again"
        ),
        ApiError::Status { status, .. } if status.is_server_error() => {
            format!("{who} is having trouble ({status}); try again shortly")
        }
        other => other.to_string(),
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
    use postkeep_mail::Paging;
    use postkeep_store::{MasterKey, OAuthAccount, Provider, Store, UpstreamTokens};
    use postkeep_upstream::{
        ApiClient, AppCredentials, Endpoints, Http, OAuthClient, TokenManager, UpstreamProvider,
    };
    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::mailbox::{Mailbox, SEARCH_TIME_EXHAUSTED};

    fn date(value: &str) -> Option<chrono::NaiveDate> {
        chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").ok()
    }

    #[test]
    fn strips_angle_brackets_from_internet_message_id() {
        assert_eq!(
            strip_brackets(Some("<draft@example.com>")).as_deref(),
            Some("draft@example.com")
        );
        assert_eq!(
            strip_brackets(Some("draft@example.com")).as_deref(),
            Some("draft@example.com")
        );
        assert_eq!(strip_brackets(None), None);
    }

    #[test]
    fn splits_large_files_into_ordered_aligned_ranges() {
        let size = 5_000_000;
        assert_eq!(
            upload_ranges(size).collect::<Vec<_>>(),
            [0..3_932_160, 3_932_160..size]
        );
    }

    #[test]
    fn reads_decimal_offsets_from_outlook_receipts() {
        for (range, offset) in [
            ("2097152", Some(2_097_152)),
            ("2097152-", Some(2_097_152)),
            ("2097152-3932159", Some(2_097_152)),
            ("", None),
            ("not-an-offset", None),
            ("+2097152", None),
            ("2097152garbage", None),
            ("2097152-3932159garbage", None),
            ("2097152--3932159", None),
        ] {
            let body = json!({"nextExpectedRanges": [range]}).to_string();
            assert_eq!(next_expected_range(body.as_bytes()), offset, "{range}");
        }
    }

    #[test]
    fn outlook_checks_raw_room_then_encoded_request_size() {
        let file = OutgoingAttachment {
            filename: "é".repeat(125) + ".pdf",
            content_type: "application/pdf".to_owned(),
            content: vec![0; SEND_MAIL_ROOM / 1000],
            content_id: None,
            inline: false,
        };
        let message = OutgoingMessage {
            to: vec![EmailAddress::new("recipient@example.org")],
            attachments: vec![file; 1000],
            ..OutgoingMessage::default()
        };
        assert!(!needs_draft("", None, &message.attachments));
        assert!(needs_draft(
            "text",
            Some(&"x".repeat(149)),
            &message.attachments
        ));
        let composed = mime::compose(&EmailAddress::new("sender@example.org"), &message).unwrap();
        assert!(!fits_send_mail(composed.raw.len()));
    }

    #[test]
    fn maps_common_names_to_well_known_folders() {
        assert_eq!(well_known("INBOX"), Some("inbox"));
        assert_eq!(well_known("Deleted Messages"), Some("deleteditems"));
        assert_eq!(well_known("Sent"), Some("sentitems"));
        assert_eq!(well_known("Projects"), None);
    }

    #[test]
    fn builds_filters_with_the_order_property_first() {
        let criteria = Criteria {
            since: date("2026-01-02"),
            before: date("2026-02-01"),
            until: Some(Cutoff::Time(1_768_003_200)),
            read: Some(false),
            flagged: Some(true),
            ..Criteria::default()
        };
        assert_eq!(
            filter_query(&criteria),
            "receivedDateTime ge 2026-01-02T00:00:00Z and receivedDateTime lt 2026-01-10T00:00:00Z and receivedDateTime lt 2026-02-01T00:00:00Z \
             and isRead eq false and flag/flagStatus eq 'flagged'"
        );
        assert_eq!(
            filter_query(&Criteria::default()),
            "receivedDateTime ge 1900-01-01T00:00:00Z"
        );
    }

    #[test]
    fn keyword_matches_check_both_flag_states_and_the_arrival_boundary() {
        let mut message: GraphMessage = serde_json::from_value(json!({ "id": "one", "isRead": true, "flag": { "flagStatus": "notFlagged" }, "receivedDateTime": "2026-01-09T23:59:59Z" })).unwrap();
        for state in [true, false] {
            let criteria = Criteria {
                read: Some(state),
                ..Criteria::default()
            };
            assert_eq!(message_matches(&message, &criteria), state);
            let criteria = Criteria {
                flagged: Some(state),
                ..Criteria::default()
            };
            assert_eq!(message_matches(&message, &criteria), !state);
            assert!(filter_query(&criteria).ends_with(&format!(
                "flag/flagStatus {} 'flagged'",
                if state { "eq" } else { "ne" }
            )));
        }
        let criteria = Criteria {
            until: Some(Cutoff::Time(1_768_003_200)),
            ..Criteria::default()
        };
        assert!(message_matches(&message, &criteria));
        message.received_date_time = Some("2026-01-10T00:00:00Z".to_owned());
        assert!(!message_matches(&message, &criteria));
        message.received_date_time = None;
        assert!(!message_matches(&message, &criteria));

        let mut criteria = Criteria {
            subject: Some("otter census".to_owned()),
            ..Criteria::default()
        };
        message.subject = Some("Weekly census".to_owned());
        assert!(!message_matches(&message, &criteria));
        message.subject = Some("OTTER CENSUS notes".to_owned());
        assert!(message_matches(&message, &criteria));
        message.subject = None;
        assert!(!message_matches(&message, &criteria));

        message = serde_json::from_value(json!({ "id": "one", "from": { "emailAddress": { "name": "Otter Society", "address": "otters@example.net" } },
            "toRecipients": [ { "emailAddress": { "address": "one@example.com" } }, { "emailAddress": { "address": "otters@example.net" } }, { "emailAddress": { "address": "two@example.com" } } ] })).unwrap();
        criteria.subject = None;
        for (from, matches) in [
            ("Otter Society", true),
            ("otters@example.net", true),
            ("one@example.com", false),
        ] {
            criteria.from = Some(from.to_owned());
            assert_eq!(message_matches(&message, &criteria), matches);
        }
        criteria.from = Some("otters@example.net".to_owned());
        message.from = None;
        assert!(!message_matches(&message, &criteria));
        criteria.to = criteria.from.take();
        assert!(message_matches(&message, &criteria));
        message.to_recipients = None;
        assert!(!message_matches(&message, &criteria));

        criteria = Criteria {
            since: date("2001-02-04"),
            before: date("2001-02-06"),
            ..Criteria::default()
        };
        for (time, matches) in [
            ("2001-02-03T23:59:59Z", false),
            ("2001-02-04T00:00:00Z", true),
            ("2001-02-05T23:59:59Z", true),
            ("2001-02-06T00:00:00Z", false),
        ] {
            message.received_date_time = Some(time.to_owned());
            assert_eq!(message_matches(&message, &criteria), matches, "{time}");
        }
        message.received_date_time = None;
        assert!(!message_matches(&message, &criteria));
    }

    #[test]
    fn keyword_queries_cannot_be_broken_out_of() {
        let criteria = Criteria {
            from: Some("alice@example.com".to_owned()),
            subject: Some("Q3 \"report\" (draft) OR x:y".to_owned()),
            text: Some("budget".to_owned()),
            since: date("2026-01-01"),
            ..Criteria::default()
        };
        assert_eq!(
            keyword_query(&criteria).unwrap().as_deref(),
            Some(
                "from:alice@example.com AND subject:q3 AND subject:report AND subject:draft AND subject:or \
                 AND subject:x AND subject:y AND budget AND received>=2025-12-31"
            )
        );
        assert_eq!(keyword_query(&Criteria::default()).unwrap(), None);
        let only_dates = Criteria {
            since: date("2026-01-01"),
            ..Criteria::default()
        };
        assert_eq!(keyword_query(&only_dates).unwrap(), None);
        let subject = |value: &str| Criteria {
            subject: Some(value.to_owned()),
            ..Criteria::default()
        };
        assert_eq!(
            keyword_query(&subject("{} --")).unwrap_err().to_string(),
            "the subject filter has no word Outlook can search for; use other words"
        );
        let dated = Criteria {
            since: date("2001-02-04"),
            before: date("2001-02-06"),
            ..subject("otter")
        };
        assert_eq!(
            keyword_query(&dated).unwrap().as_deref(),
            Some("subject:otter AND received>=2001-02-03 AND received<2001-02-07")
        );
    }

    #[test]
    fn words_are_lowercase_text_never_operators() {
        let criteria = Criteria {
            subject: Some("OR report".to_owned()),
            text: Some("budget OR -secret AND NOT near(3) NEAR invoice".to_owned()),
            ..Criteria::default()
        };
        assert_eq!(
            keyword_query(&criteria).unwrap().as_deref(),
            Some(
                "subject:or AND subject:report AND budget AND or AND secret AND and AND not AND near AND 3 AND near AND invoice"
            )
        );
        assert_eq!(
            keyword_query(&Criteria {
                text: Some("OR AND NOT NEAR".to_owned()),
                ..Criteria::default()
            })
            .unwrap()
            .as_deref(),
            Some("or AND and AND not AND near")
        );
        assert_eq!(
            keyword_query(&Criteria {
                from: Some("+-alice@example.com".to_owned()),
                ..Criteria::default()
            })
            .unwrap()
            .as_deref(),
            Some("from:alice@example.com")
        );
    }

    #[test]
    fn selectors_need_a_graph_id() {
        let selector = Selector {
            id: Some(id::provider_id(GRAPH_PREFIX, "AAMk")),
            ..Selector::default()
        };
        assert_eq!(
            provider_message_id(&selector, GRAPH_PREFIX).ok(),
            Some("AAMk")
        );
        let legacy = Selector {
            folder: Some("INBOX".to_owned()),
            uid: Some(4),
            ..Selector::default()
        };
        assert!(provider_message_id(&legacy, GRAPH_PREFIX).is_err());
        let imap = Selector {
            id: Some(id::imap_id("INBOX", 4, Some(7))),
            ..Selector::default()
        };
        assert!(provider_message_id(&imap, GRAPH_PREFIX).is_err());
    }

    #[test]
    fn next_links_must_stay_on_the_graph_host() {
        let base = Url::parse("https://graph.microsoft.com/v1.0").unwrap();
        let ok = validated_next_link(
            &base,
            Some("https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc"),
        );
        assert_eq!(
            ok.as_ref().map(Url::as_str),
            Some("https://graph.microsoft.com/v1.0/me/messages?$skiptoken=abc")
        );
        assert!(
            validated_next_link(&base, Some("https://evil.example/v1.0/me/messages")).is_none()
        );
        assert!(
            validated_next_link(&base, Some("http://graph.microsoft.com/v1.0/me/messages"))
                .is_none()
        );
        assert!(validated_next_link(&base, Some("https://graph.microsoft.com/beta/me")).is_none());
        assert!(validated_next_link(&base, None).is_none());
        assert!(validated_next_link(&base, Some("not a url")).is_none());
    }

    const SEARCH_PATH: &str = "/graph/v1.0/me/mailFolders/inbox/messages";
    const TRANSLATE_PATH: &str = "/graph/v1.0/me/translateExchangeIds";

    fn same_ids(request: &wiremock::Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let value: Vec<Value> = body["inputIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| json!({ "sourceId": id, "targetId": id }))
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({ "value": value }))
    }

    fn message(id: &str, read: bool, flagged: bool) -> serde_json::Value {
        json!({
            "id": id,
            "subject": "budget",
            "receivedDateTime": "2026-10-08T09:00:00Z",
            "isRead": read,
            "isDraft": false,
            "flag": { "flagStatus": if flagged { "flagged" } else { "notFlagged" } },
            "from": { "emailAddress": { "address": "sender@example.com" } }
        })
    }

    async fn outlook(server: &MockServer) -> (GraphMailbox, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("mail.db").display());
        let store = Store::connect(
            &url,
            &MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let account = store
            .upsert_oauth_account(
                &OAuthAccount {
                    provider: Provider::Graph,
                    subject: "person-subject",
                    email: "person@example.com",
                },
                &UpstreamTokens {
                    refresh_token: SecretString::from("refresh-1".to_owned()),
                    access_token: Some(SecretString::from("access-1".to_owned())),
                    access_expires_at: Some(postkeep_store::now() + 3600),
                    scope: "mail".to_owned(),
                },
            )
            .await
            .unwrap();
        let oauth = OAuthClient::new(
            Http::for_tests(),
            Endpoints::all_at(&Url::parse(&server.uri()).unwrap()),
            Url::parse("https://mail.example.com").unwrap(),
            Some(AppCredentials {
                client_id: "ms-client".to_owned(),
                client_secret: SecretString::from("shh".to_owned()),
            }),
            None,
        );
        let api = ApiClient::new(
            TokenManager::new(store, oauth),
            account.id,
            UpstreamProvider::Microsoft,
        );
        Mock::given(method("POST"))
            .and(path(TRANSLATE_PATH))
            .respond_with(same_ids)
            .mount(server)
            .await;
        (GraphMailbox::new(api, "person@example.com".to_owned()), dir)
    }

    async fn assert_listing_setup_deadline(mailbox: GraphMailbox, server: &MockServer) {
        let result = Mailbox::Graph(Box::new(mailbox))
            .selected(
                &super::super::selection::SearchSelection {
                    folder: "Parent/Target".to_owned(),
                    criteria: Criteria {
                        until: Some(Cutoff::Time(1_768_003_200)),
                        ..Criteria::default()
                    },
                },
                &Change::Flags {
                    read: Some(true),
                    flagged: None,
                },
                crate::tools::MOST_IDS,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(matches!(result, Selected::Done(text) if text == SEARCH_TIME_EXHAUSTED));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    async fn slow_setup_starts_no_late_graph_request(case: &str) {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        let delayed = |body| {
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(1500))
                .set_body_json(body)
        };
        let change = match case {
            "folder" | "page" | "listing" => {
                let body = if matches!(case, "folder" | "listing") {
                    json!({ "value": [{ "id": "parent", "displayName": "Parent", "childFolderCount": 1 }] })
                } else {
                    json!({ "value": [], "@odata.nextLink": format!("{}/graph/v1.0/me/mailFolders?$skiptoken=late", server.uri()) })
                };
                Mock::given(method("GET"))
                    .and(path("/graph/v1.0/me/mailFolders"))
                    .respond_with(delayed(body))
                    .expect(1)
                    .mount(&server)
                    .await;
                Change::Move("Parent/Target".to_owned())
            }
            "late_401" | "late_refresh" => {
                let response = if case == "late_401" {
                    ResponseTemplate::new(401).set_delay(Duration::from_millis(1500))
                } else {
                    ResponseTemplate::new(401)
                };
                Mock::given(method("POST"))
                    .and(path("/graph/v1.0/$batch"))
                    .respond_with(response)
                    .up_to_n_times(1)
                    .expect(1)
                    .mount(&server)
                    .await;
                if case == "late_refresh" {
                    Mock::given(method("POST")).and(path("/microsoft/common/oauth2/v2.0/token"))
                        .respond_with(delayed(json!({ "access_token": "renewed-access", "refresh_token": "renewed-refresh", "expires_in": 3600 })))
                        .expect(1).mount(&server).await;
                }
                Change::Flags {
                    read: Some(true),
                    flagged: None,
                }
            }
            _ => panic!("unknown deadline case"),
        };
        if case == "listing" {
            assert_listing_setup_deadline(mailbox, &server).await;
            return;
        }
        let ids = [Selector {
            id: Some("graph.slow-setup".to_owned()),
            folder: None,
            uid: None,
        }];
        let outcomes = mailbox
            .apply(
                &ids,
                IdsFrom::Selection,
                &change,
                Mode::Act,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(outcomes[0].status, Status::NotReached, "{case}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            if case == "late_refresh" { 2 } else { 1 },
            "{case}"
        );
        if case == "late_refresh" {
            // A rotation already in flight finishes and is saved, even though no mutation follows it.
            Mock::given(method("POST"))
                .and(path("/graph/v1.0/$batch"))
                .and(wiremock::matchers::header(
                    "authorization",
                    "Bearer renewed-access",
                ))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(json!({ "responses": [{ "id": "0", "status": 200 }] })),
                )
                .expect(1)
                .mount(&server)
                .await;
            let next = mailbox
                .apply(
                    &ids,
                    IdsFrom::Selection,
                    &change,
                    Mode::Act,
                    Instant::now() + Duration::from_secs(5),
                )
                .await
                .unwrap();
            assert_eq!(next[0].status, Status::Ok);
        }
    }

    async fn whole_request_refusals_stop_later_batches() {
        for status in [503, 401] {
            let server = MockServer::start().await;
            let (mailbox, _dir) = outlook(&server).await;
            Mock::given(method("POST")).and(path("/graph/v1.0/$batch"))
                .respond_with(ResponseTemplate::new(status).insert_header("Retry-After", "10")
                    .set_body_json(json!({ "error": { "code": "Unavailable", "message": "Request refused" } })))
                .expect(if status == 401 { 2 } else { 1 }).mount(&server).await;
            if status == 401 {
                Mock::given(method("POST")).and(path("/microsoft/common/oauth2/v2.0/token"))
                    .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "access_token": "fresh-but-refused", "refresh_token": "rotated", "expires_in": 3600 })))
                    .expect(1).mount(&server).await;
            }
            let ids: Vec<_> = (0..1000)
                .map(|n| Selector {
                    id: Some(format!("graph.refusal-{n}")),
                    folder: None,
                    uid: None,
                })
                .collect();
            let outcomes = mailbox
                .apply(
                    &ids,
                    IdsFrom::Selection,
                    &Change::Flags {
                        read: Some(true),
                        flagged: None,
                    },
                    Mode::Act,
                    Instant::now() + Duration::from_secs(20),
                )
                .await
                .unwrap();
            assert!(
                outcomes[..20]
                    .iter()
                    .all(|out| out.status == Status::Failed)
            );
            assert!(
                outcomes[20..]
                    .iter()
                    .all(|out| out.status == Status::NotReached)
            );
            assert!(outcomes.iter().all(|out| out.reason == outcomes[0].reason));
            assert_eq!(
                server.received_requests().await.unwrap().len(),
                if status == 401 { 3 } else { 1 }
            );
        }
    }

    #[tokio::test]
    async fn actions_do_not_start_another_batch_after_the_deadline() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        let ids: Vec<_> = (0..21)
            .map(|n| Selector {
                id: Some(format!("graph.slow-{n}")),
                folder: None,
                uid: None,
            })
            .collect();
        let change = Change::Flags {
            read: Some(true),
            flagged: None,
        };
        let expired = mailbox
            .apply(&ids, IdsFrom::Selection, &change, Mode::Act, Instant::now())
            .await
            .unwrap();
        assert!(expired.iter().all(|out| out.status == Status::NotReached));
        assert!(server.received_requests().await.unwrap().is_empty());
        Mock::given(method("POST")).and(path("/graph/v1.0/$batch"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(1500)).set_body_json(json!({
                "responses": (0..20).map(|n| json!({ "id": n.to_string(), "status": 200 })).collect::<Vec<_>>()
            }))).expect(1).mount(&server).await;
        let changed = mailbox
            .apply(
                &ids,
                IdsFrom::Selection,
                &change,
                Mode::Act,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(changed[..20].iter().all(|out| out.status == Status::Ok));
        assert_eq!(changed[20].status, Status::NotReached);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].body_json::<serde_json::Value>().unwrap()["requests"]
                .as_array()
                .unwrap()
                .len(),
            20
        );
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        Mock::given(method("POST")).and(path("/graph/v1.0/$batch"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(1500)).set_body_json(json!({
                "responses": (0..20).map(|n| json!({ "id": n.to_string(), "status": 200, "body": { "isRead": false } })).collect::<Vec<_>>()
            }))).expect(1).mount(&server).await;
        let pending = mailbox
            .apply(
                &ids,
                IdsFrom::Caller,
                &change,
                Mode::Act,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(pending.iter().all(|out| out.status == Status::NotReached));
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        for case in ["folder", "page", "listing", "late_401", "late_refresh"] {
            slow_setup_starts_no_late_graph_request(case).await;
        }
        whole_request_refusals_stop_later_batches().await;
    }

    #[tokio::test]
    async fn inner_throttles_that_cannot_fit_are_not_retried() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        Mock::given(method("POST")).and(path("/graph/v1.0/$batch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "responses": [
                { "id": "0", "status": 429, "headers": { "Retry-After": "60" }, "body": { "error": { "code": "TooManyRequests", "message": "Wait" } } }
            ] }))).expect(1).mount(&server).await;
        let ids = [Selector {
            id: Some("graph.AAMk+/=".to_owned()),
            folder: None,
            uid: None,
        }];
        let changed = mailbox
            .apply(
                &ids,
                IdsFrom::Selection,
                &Change::Move("Archive".to_owned()),
                Mode::Act,
                Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert_eq!(changed[0].status, Status::NotReached);
        let requests = server.received_requests().await.unwrap();
        let inner = &requests[0].body_json::<serde_json::Value>().unwrap()["requests"][0];
        assert_eq!(inner["url"], "/me/messages/AAMk+%2F=/move?$select=id");
        assert_eq!(inner["headers"]["Prefer"], "IdType=\"ImmutableId\"");
        assert_eq!(inner["headers"]["Content-Type"], "application/json");
    }

    fn budget(unread: bool, flagged: bool) -> Criteria {
        Criteria {
            text: Some("budget".to_owned()),
            read: unread.then_some(false),
            flagged: flagged.then_some(true),
            ..Criteria::default()
        }
    }

    #[tokio::test]
    async fn filtered_keyword_search_pages_past_non_matching_hits() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        let next = format!(
            "{}/graph/v1.0/me/mailFolders/inbox/messages?$skiptoken=page-2",
            server.uri()
        );
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"budget\""))
            .and(query_param("$top", "1000"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("read-1", true, false), message("read-2", true, false)],
                "@odata.nextLink": next,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$skiptoken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("unread-1", false, false), message("unread-2", false, true)]
            })))
            .mount(&server)
            .await;

        let criteria = budget(true, false);
        let first = mailbox
            .search("inbox", &criteria, Paging::new(0, 1))
            .await
            .unwrap();
        assert_eq!(first.messages.len(), 1);
        assert_eq!(first.messages[0].id, "graph.unread-1");
        assert!(first.has_more);
        assert_eq!(first.total, 2);
        assert!(!first.estimated);
        let second = mailbox
            .search("inbox", &criteria, Paging::new(1, 1))
            .await
            .unwrap();
        assert_eq!(second.messages.len(), 1);
        assert_eq!(second.messages[0].id, "graph.unread-2");
        assert!(!second.has_more);
        let past = mailbox
            .search("inbox", &criteria, Paging::new(2, 1))
            .await
            .unwrap();
        assert_eq!(past.messages.len(), 0);
        assert!(!past.has_more);

        let flagged = mailbox
            .search("inbox", &budget(false, true), Paging::new(0, 1))
            .await
            .unwrap();
        assert_eq!(flagged.messages.len(), 1);
        assert_eq!(flagged.messages[0].id, "graph.unread-2");
        assert!(!flagged.has_more);
    }

    #[tokio::test]
    async fn filtered_keyword_search_stops_when_the_next_link_leaves_the_host() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$top", "1000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("read-1", true, false)],
                "@odata.nextLink": "https://evil.example/graph/v1.0/me/messages?$skiptoken=x",
            })))
            .expect(1)
            .mount(&server)
            .await;
        let page = mailbox
            .search("inbox", &budget(true, false), Paging::new(0, 20))
            .await
            .unwrap();
        assert_eq!(page.messages.len(), 0);
        assert!(!page.has_more);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    /// A sender without an `emailAddress`, or with a `null` one, is listed
    /// as no sender; the rest of the listing is unchanged.
    #[tokio::test]
    async fn a_sender_without_an_email_address_does_not_fail_the_listing() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        let mut empty = message("empty", true, false);
        empty["from"] = json!({});
        let mut null = message("null", true, false);
        null["from"] = json!({ "emailAddress": null });
        let value = [empty, null, message("named", true, false)];
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": value })))
            .mount(&server)
            .await;
        let page = mailbox
            .search("inbox", &Criteria::default(), Paging::new(0, 20))
            .await
            .unwrap();
        let senders: Vec<_> = page
            .messages
            .iter()
            .map(|summary| summary.from.as_ref().map(|from| from.address.as_str()))
            .collect();
        assert_eq!(senders, [None, None, Some("sender@example.com")]);
    }

    #[tokio::test]
    async fn text_searches_count_the_window() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"budget\""))
            .and(query_param("$top", "1000"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("hit-1", true, false)],
                "@odata.nextLink": format!(
                    "{}/graph/v1.0/me/mailFolders/inbox/messages?$skiptoken=more",
                    server.uri()
                ),
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$skiptoken", "more"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("hit-2", true, false)]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"other\""))
            .and(query_param("$top", "1000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/messages?$skiptoken=more",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let hit = mailbox
            .search("inbox", &budget(false, false), Paging::new(0, 1))
            .await
            .unwrap();
        assert_eq!(hit.messages.len(), 1);
        assert_eq!(hit.messages[0].id, "graph.hit-1");
        assert_eq!(hit.total, 2);
        assert!(!hit.estimated);
        assert!(hit.has_more);
        let empty = mailbox
            .search(
                "inbox",
                &Criteria {
                    text: Some("other".to_owned()),
                    ..Criteria::default()
                },
                Paging::new(0, 1),
            )
            .await
            .unwrap();
        assert_eq!(empty.messages.len(), 0);
        assert_eq!(empty.total, 0);
        assert!(!empty.estimated);
        assert!(!empty.has_more);
    }

    fn search_next(server: &MockServer, token: &str) -> String {
        format!(
            "{}/graph/v1.0/me/mailFolders/inbox/messages?$skiptoken={token}",
            server.uri()
        )
    }

    #[tokio::test]
    async fn unfiltered_keyword_search_follows_a_short_first_page() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"budget\""))
            .and(query_param("$top", "1000"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("hit-1", true, false)],
                "@odata.nextLink": search_next(&server, "page-2"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$skiptoken", "page-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("hit-2", false, false), message("hit-3", true, true)]
            })))
            .mount(&server)
            .await;

        let criteria = budget(false, false);
        let first = mailbox
            .search("inbox", &criteria, Paging::new(0, 1))
            .await
            .unwrap();
        assert_eq!(ids(&first), vec!["graph.hit-1"]);
        assert!(first.has_more);
        let second = mailbox
            .search("inbox", &criteria, Paging::new(1, 1))
            .await
            .unwrap();
        assert_eq!(ids(&second), vec!["graph.hit-2"]);
        assert!(second.has_more);
        let third = mailbox
            .search("inbox", &criteria, Paging::new(2, 1))
            .await
            .unwrap();
        assert_eq!(ids(&third), vec!["graph.hit-3"]);
        assert!(!third.has_more);
        let past = mailbox
            .search("inbox", &criteria, Paging::new(3, 1))
            .await
            .unwrap();
        assert_eq!(past.messages.len(), 0);
        assert!(!past.has_more);

        let requests = server.received_requests().await.unwrap();
        assert!(
            requests.iter().any(|request| request
                .url
                .query()
                .is_some_and(|query| query.contains("skiptoken=page-2"))),
            "a short page must be followed"
        );
        assert_eq!(first.total, 3);
        assert!(!first.estimated);
        let first_top = requests[0]
            .url
            .query_pairs()
            .find_map(|(key, value)| (key == "$top").then(|| value.into_owned()));
        assert_eq!(first_top.as_deref(), Some("1000"));
    }

    #[tokio::test]
    async fn unfiltered_keyword_search_follows_an_empty_first_page() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"budget\""))
            .and(query_param("$top", "1000"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [],
                "@odata.nextLink": search_next(&server, "budget-2"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$skiptoken", "budget-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("hit-1", true, false), message("hit-2", true, false)]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"lone\""))
            .and(query_param("$top", "1000"))
            .and(query_param_is_missing("$skiptoken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [],
                "@odata.nextLink": search_next(&server, "lone-2"),
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$skiptoken", "lone-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("only-1", true, false)]
            })))
            .mount(&server)
            .await;

        let criteria = budget(false, false);
        let first = mailbox
            .search("inbox", &criteria, Paging::new(0, 1))
            .await
            .unwrap();
        assert_eq!(ids(&first), vec!["graph.hit-1"]);
        assert!(
            first.has_more,
            "the match after the empty page is not the last"
        );
        let second = mailbox
            .search("inbox", &criteria, Paging::new(1, 1))
            .await
            .unwrap();
        assert_eq!(ids(&second), vec!["graph.hit-2"]);
        assert!(!second.has_more);

        let lone = mailbox
            .search(
                "inbox",
                &Criteria {
                    text: Some("lone".to_owned()),
                    ..Criteria::default()
                },
                Paging::new(0, 1),
            )
            .await
            .unwrap();
        assert_eq!(ids(&lone), vec!["graph.only-1"]);
        assert!(
            !lone.has_more,
            "a consumed next link is not another page of results"
        );
    }

    #[tokio::test]
    async fn unfiltered_keyword_search_rejects_a_window_past_the_cap() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        for criteria in [
            budget(false, false),
            Criteria {
                from: Some("otters@example.net".to_owned()),
                ..Criteria::default()
            },
        ] {
            let err = mailbox
                .search("inbox", &criteria, Paging::new(MAX_SEARCH_WINDOW, 1))
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains(&MAX_SEARCH_WINDOW.to_string()),
                "{err}"
            );
        }
        assert!(server.received_requests().await.unwrap().is_empty());

        let matches: Vec<_> = (0..MAX_SEARCH_WINDOW)
            .map(|index| message(&format!("m{index}"), false, false))
            .collect();
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"budget\""))
            .and(query_param("$top", "1000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": matches })))
            .mount(&server)
            .await;
        let crossing = mailbox
            .search("inbox", &budget(false, false), Paging::new(975, 75))
            .await
            .unwrap();
        assert_eq!(crossing.messages.len(), 25);
        assert_eq!(crossing.messages[0].id, "graph.m975");
        assert_eq!(crossing.messages[24].id, "graph.m999");
        assert_eq!(crossing.total, MAX_SEARCH_WINDOW);
        assert!(crossing.estimated);
        assert!(!crossing.has_more);
    }

    #[tokio::test]
    async fn unfiltered_keyword_search_accepts_a_page_that_ends_on_the_window() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        let matches: Vec<_> = (0..MAX_SEARCH_WINDOW)
            .map(|index| message(&format!("m{index}"), false, false))
            .collect();
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"budget\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": matches,
                "@odata.nextLink": format!(
                    "{}/graph/v1.0/me/mailFolders/inbox/messages?$skiptoken=past-window",
                    server.uri()
                ),
            })))
            .mount(&server)
            .await;

        let criteria = budget(false, false);
        let at_800 = mailbox
            .search("inbox", &criteria, Paging::new(800, 100))
            .await
            .unwrap();
        assert_eq!(at_800.messages.len(), 100);
        assert_eq!(at_800.messages[0].id, "graph.m800");
        assert_eq!(at_800.messages[99].id, "graph.m899");
        assert!(at_800.has_more);
        assert_eq!(
            at_800.offset + at_800.messages.len(),
            900,
            "the next page is still inside the window"
        );

        let at_900 = mailbox
            .search("inbox", &criteria, Paging::new(900, 100))
            .await
            .unwrap();
        assert_eq!(at_900.messages.len(), 100);
        assert_eq!(at_900.messages[0].id, "graph.m900");
        assert_eq!(at_900.messages[99].id, "graph.m999");
        assert_eq!(at_900.total, MAX_SEARCH_WINDOW);
        assert!(at_900.estimated);
        assert!(
            !at_900.has_more,
            "a page that ends on the window has no next offset"
        );

        let at_999 = mailbox
            .search("inbox", &criteria, Paging::new(999, 1))
            .await
            .unwrap();
        assert_eq!(at_999.messages.len(), 1);
        assert_eq!(at_999.messages[0].id, "graph.m999");
        assert!(!at_999.has_more);

        let past = mailbox
            .search("inbox", &criteria, Paging::new(MAX_SEARCH_WINDOW, 1))
            .await
            .unwrap_err();
        assert!(
            past.to_string().contains(&MAX_SEARCH_WINDOW.to_string()),
            "{past}"
        );

        let requests = server.received_requests().await.unwrap();
        let tops: Vec<_> = requests
            .iter()
            .filter(|request| request.url.path() == SEARCH_PATH)
            .map(|request| {
                request
                    .url
                    .query_pairs()
                    .find_map(|(key, value)| (key == "$top").then(|| value.into_owned()))
                    .unwrap_or_default()
            })
            .collect();
        assert_eq!(tops, ["1000", "1000", "1000"]);
        assert!(
            requests.iter().all(|request| !request
                .url
                .query()
                .is_some_and(|query| query.contains("skiptoken"))),
            "the window read must not request a match past the window"
        );
    }

    #[tokio::test]
    async fn keyword_totals_trust_short_listings_and_mark_cut_windows_estimated() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        for (term, count, expected_estimated) in [
            ("short", LISTING_TRUSTED - 1, false),
            ("trusted", LISTING_TRUSTED, true),
        ] {
            let value: Vec<_> = (0..count)
                .map(|i| message(&format!("{term}-{i}"), false, false))
                .collect();
            Mock::given(method("GET"))
                .and(path(SEARCH_PATH))
                .and(query_param("$search", format!("\"{term}\"")))
                .and(query_param("$top", "1000"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": value })))
                .mount(&server)
                .await;
            let page = mailbox
                .search(
                    "inbox",
                    &Criteria {
                        text: Some(term.to_owned()),
                        ..Criteria::default()
                    },
                    Paging::new(0, 1),
                )
                .await
                .unwrap();
            assert_eq!(page.total, count);
            assert_eq!(page.estimated, expected_estimated, "{term}");
        }

        let cut: Vec<_> = (0..MAX_SEARCH_WINDOW)
            .map(|i| message(&format!("cut-{i}"), i >= 2, false))
            .collect();
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"budget\""))
            .and(query_param("$top", "1000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "value": cut })))
            .mount(&server)
            .await;
        let page = mailbox
            .search("inbox", &budget(true, false), Paging::new(0, 20))
            .await
            .unwrap();
        assert_eq!(page.total, 2);
        assert!(page.estimated);
        assert!(!page.has_more);
    }

    fn ids(page: &Page) -> Vec<&str> {
        page.messages
            .iter()
            .map(|message| message.id.as_str())
            .collect()
    }

    #[tokio::test]
    async fn keyword_pages_hand_out_immutable_ids() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"subject:budget\""))
            .and(|req: &wiremock::Request| !req.headers.contains_key("prefer"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    message("reg-1", false, false),
                    message("reg-2", false, false),
                    message("reg-3", false, false),
                ]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(TRANSLATE_PATH))
            .and(|req: &wiremock::Request| !req.headers.contains_key("prefer"))
            .and(body_json(json!({
                "inputIds": ["reg-2", "reg-3"],
                "sourceIdType": "restId",
                "targetIdType": "restImmutableEntryId",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    { "sourceId": "reg-3", "targetId": "imm-3" },
                    { "sourceId": "reg-2", "targetId": "imm-2" },
                ]
            })))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;

        let criteria = Criteria {
            subject: Some("budget".to_owned()),
            ..Criteria::default()
        };
        let page = mailbox
            .search("inbox", &criteria, Paging::new(1, 2))
            .await
            .unwrap();
        assert_eq!(ids(&page), ["graph.imm-2", "graph.imm-3"]);
    }

    #[tokio::test]
    async fn keyword_selections_translate_what_they_list() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        for (name, id) in [("inbox", "inbox-id"), ("archive", "archive-id")] {
            Mock::given(method("GET"))
                .and(path(format!("/graph/v1.0/me/mailFolders/{name}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": id })))
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path(SEARCH_PATH))
            .and(query_param("$search", "\"subject:budget\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [message("reg-1", false, false), message("reg-2", false, false)]
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(TRANSLATE_PATH))
            .and(body_json(json!({
                "inputIds": ["reg-1", "reg-2"],
                "sourceIdType": "restId",
                "targetIdType": "restImmutableEntryId",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "value": [
                    { "sourceId": "reg-1", "targetId": "imm-1" },
                    { "sourceId": "reg-2", "targetId": "imm-2" },
                ]
            })))
            .with_priority(1)
            .expect(1)
            .mount(&server)
            .await;

        let criteria = Criteria {
            subject: Some("budget".to_owned()),
            ..Criteria::default()
        };
        let selected = mailbox
            .selected(
                "inbox",
                &criteria,
                &Change::Move("Archive".to_owned()),
                10,
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .unwrap();
        let Selected::Matches { ids, .. } = selected else {
            panic!("expected matches, got {selected:?}");
        };
        let got: Vec<_> = ids.iter().map(|s| s.id.as_deref().unwrap()).collect();
        assert_eq!(got, ["graph.imm-1", "graph.imm-2"]);
    }

    #[tokio::test]
    async fn untranslatable_hits_fail_the_call() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        let pair = |s: &str, t: &str| json!({ "sourceId": s, "targetId": t });
        let ok = pair("reg-1", "imm-1");
        let reply = |entries: Vec<Value>| {
            ResponseTemplate::new(200).set_body_json(json!({ "value": entries }))
        };
        let no_stable = "Outlook gave no stable id for some of these messages: search again";
        let cases = [
            (
                "error-details",
                reply(vec![
                    ok.clone(),
                    json!({ "sourceId": "reg-2", "errorDetails": { "code": "ErrorItemNotFound" } }),
                ]),
                no_stable,
            ),
            ("omitted", reply(vec![ok.clone()]), no_stable),
            (
                "duplicate-source",
                reply(vec![
                    ok.clone(),
                    pair("reg-2", "imm-2"),
                    pair("reg-2", "imm-3"),
                ]),
                no_stable,
            ),
            (
                "empty-target",
                reply(vec![ok.clone(), pair("reg-2", "")]),
                no_stable,
            ),
            (
                "duplicate-target",
                reply(vec![ok.clone(), pair("reg-2", "imm-1")]),
                no_stable,
            ),
            (
                "space-in-target",
                reply(vec![ok, pair("reg-2", "imm 2")]),
                no_stable,
            ),
            (
                "503",
                ResponseTemplate::new(503).set_body_raw(
                    include_str!("../../tests/data/graph/unavailable.json"),
                    "application/json",
                ),
                "Microsoft is having trouble (503 Service Unavailable); try again shortly",
            ),
        ];
        let criteria = Criteria {
            subject: Some("budget".to_owned()),
            ..Criteria::default()
        };
        let flags = Change::Flags {
            read: Some(true),
            flagged: None,
        };
        for (name, response, expected) in cases {
            server.reset().await;
            Mock::given(method("GET"))
                .and(path(SEARCH_PATH))
                .and(query_param("$search", "\"subject:budget\""))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "value": [message("reg-1", false, false), message("reg-2", false, false)]
                })))
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(TRANSLATE_PATH))
                .respond_with(response)
                .expect(2)
                .mount(&server)
                .await;
            let page_err = mailbox
                .search("inbox", &criteria, Paging::new(0, 10))
                .await
                .unwrap_err();
            assert_eq!(page_err.to_string(), expected, "page: {name}");
            let sel_err = mailbox
                .selected(
                    "inbox",
                    &criteria,
                    &flags,
                    10,
                    Instant::now() + Duration::from_secs(30),
                )
                .await
                .unwrap_err();
            assert_eq!(sel_err.to_string(), expected, "selection: {name}");
            server.verify().await;
        }
    }

    /// Microsoft's throttling response and an outage read as advice to wait;
    /// a 413 when listing folders keeps the generic provider error.
    #[tokio::test]
    async fn folder_read_errors_keep_action_specific_meaning() {
        let server = MockServer::start().await;
        let (mailbox, _dir) = outlook(&server).await;
        let recorded = [
            (
                413,
                "0",
                r#"{"error":{"message":"too large for this request"}}"#,
                "microsoft answered 413 Payload Too Large: too large for this request",
            ),
            (
                429,
                "10",
                include_str!("../../tests/data/graph/throttled.json"),
                "Microsoft is limiting requests for this account; try again in a minute",
            ),
            (
                503,
                "5",
                include_str!("../../tests/data/graph/unavailable.json"),
                "Microsoft is having trouble (503 Service Unavailable); try again shortly",
            ),
        ];
        for (status, retry_after, body, advice) in recorded {
            server.reset().await;
            Mock::given(method("GET"))
                .and(path("/graph/v1.0/me/mailFolders"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .insert_header("retry-after", retry_after)
                        .set_body_raw(body, "application/json"),
                )
                .mount(&server)
                .await;
            let err = mailbox.list_folders().await.unwrap_err();
            assert_eq!(err.to_string(), advice, "{status}");
            assert!(!err.code().outcome_uncertain());
        }
    }

    #[test]
    fn classifies_redirect_and_token_errors() {
        use postkeep_store::StoreError;

        let redirect = ApiError::Status {
            provider: UpstreamProvider::Microsoft,
            status: StatusCode::FOUND,
            code: None,
            reason: None,
            message: "redirect".into(),
            retry_after: None,
        };
        assert_eq!(
            classify_api_error(&redirect),
            (ToolErrorCode::ProviderUnavailable, None)
        );
        for (status, code, expected) in [
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                ToolErrorCode::ProviderUnavailable,
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                "slow_down",
                ToolErrorCode::RateLimited,
            ),
        ] {
            let err = ApiError::Token(TokenError::OAuth(OAuthError::Rejected {
                provider: UpstreamProvider::Microsoft,
                status,
                code: code.into(),
                description: None,
                retry_after: Some(13),
            }));
            assert_eq!(classify_api_error(&err), (expected, Some(13)));
        }
        for (err, code) in [
            (StoreError::Decrypt, ToolErrorCode::AuthRequired),
            (StoreError::KeysDestroyed, ToolErrorCode::AuthRequired),
            (StoreError::AccountDeleted, ToolErrorCode::AuthRequired),
            (
                StoreError::KeyWrap("unavailable".into()),
                ToolErrorCode::ProviderUnavailable,
            ),
        ] {
            let err = ApiError::Token(TokenError::Store(err));
            assert_eq!(classify_api_error(&err), (code, None));
        }
    }

    #[test]
    fn batch_retry_after_is_bounded_and_only_used_on_eligible_statuses() {
        let mut response: BatchResponse =
            serde_json::from_value(json!({"id":"0","status":503})).unwrap();
        for (value, expected) in [
            (json!(" 0 "), Some(0)),
            (json!("+1"), None),
            (json!("18446744073709551616"), Some(86_400)),
            (json!(90_000), Some(86_400)),
            (json!(-1), None),
        ] {
            response.headers.insert("ReTrY-AfTeR".to_owned(), value);
            assert_eq!(response.retry_after_seconds(), expected);
            assert_eq!(
                response.retry_after(),
                Duration::from_secs(expected.unwrap_or(1))
            );
            response.status = 503;
            assert_eq!(response.error().retry_after(), expected);
            response.status = 413;
            assert_eq!(response.error().retry_after(), None);
        }
    }

    #[test]
    fn a_retried_read_that_is_ready_does_not_keep_its_old_rate_limit() {
        let mut outcomes = [Outcome::pending("graph.message".into())];
        outcomes[0].fail(
            Status::NotReached,
            "limited",
            ToolErrorCode::RateLimited,
            Some(3),
        );
        let mut ready = Vec::new();
        let stage = &mut BatchStage::Read {
            change: &Change::Flags {
                read: Some(true),
                flagged: None,
            },
            destination: None,
            mode: Mode::Act,
            ready: &mut ready,
        };
        let batch: Batch = serde_json::from_value(json!({"responses":[{
            "id":"0", "status":200, "body":{"id":"message","isRead":false}
        }]}))
        .unwrap();
        batch.finish(&[json!({"id":"0"})], &mut outcomes, stage);
        assert_eq!(ready, [0]);
        assert_eq!(outcomes[0].reason, TIME_EXHAUSTED);
        assert_eq!(outcomes[0].error, Some((ToolErrorCode::Timeout, None)));
    }

    /// Gmail's rate limits that come as a 403 read as advice to wait, not as a
    /// refusal, and so does its daily limit, without the advice to sign in
    /// again. A 403 for another reason still reads as a refusal.
    #[test]
    fn google_rate_limits_sent_as_403_read_as_advice_to_wait() {
        let forbidden = |reason: &str| ApiError::Status {
            provider: UpstreamProvider::Google,
            status: StatusCode::FORBIDDEN,
            code: Some("PERMISSION_DENIED".to_owned()),
            reason: Some(reason.to_owned()),
            retry_after: None,
            message: "no".to_owned(),
        };
        for reason in ["userRateLimitExceeded", "rateLimitExceeded"] {
            assert_eq!(
                api_error_message(&forbidden(reason), "Google"),
                "Google is limiting requests for this account; try again in a minute",
                "{reason}"
            );
        }
        assert_eq!(
            api_error_message(&forbidden("dailyLimitExceeded"), "Google"),
            "Google's daily request limit for this server is used up; try again later. \
             Signing in again won't help"
        );
        let refused = api_error_message(&forbidden("domainPolicy"), "Google");
        assert!(
            refused.starts_with("Google refused the request"),
            "{refused}"
        );
    }
}
