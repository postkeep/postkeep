//! The provider abstraction behind the MCP tools.
//!
//! A [`Mailbox`] is the caller's mailbox at one provider. Tools call its
//! provider-neutral operations and never touch IMAP, Microsoft Graph or
//! Gmail directly. Messages are addressed by opaque ids (see [`id`]);
//! IMAP accounts also accept the older folder plus UID form.

pub mod capabilities;
pub mod gmail;
pub mod graph;
pub mod id;
pub mod selection;

use std::time::Instant;

use postkeep_auth::ToolErrorCode;
use postkeep_mail::{
    AttachmentData, Check, DeleteMode, EmailAddress, Error as MailError, Flag, Folder, ImapSession,
    InFlight, MailClient, Message, MessageFlags, OutgoingMessage, Paging, Progress,
    ProtocolErrorKind, Reply, SearchQuery, SendOptions, SentMessage, SpecialUse, UID_SET_MAX, Uid,
    already_in_trash, same_folder,
};
use postkeep_store::{AccountId, Provider, Store, StoreError};
use postkeep_upstream::{ApiError, http::HttpError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use self::selection::SearchSelection;

use capabilities::SelectionFilterRules;
pub use capabilities::{
    AttachmentCapabilities, AuthType, IdStabilityOnMove, MailboxCapabilities, MailboxProtocol,
    MailboxProvider, OperationCapabilities, SearchCapabilities, ServerFeatures, TextMatching,
};

use crate::metrics::Metrics;
use crate::pool::{Fingerprint, ImapPool};
use crate::tools::WebhookControl;

/// A folder of the mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntry {
    /// Name to pass to other tools.
    pub name: String,
    /// Special role: inbox, sent, trash, drafts, junk, archive, all, flagged.
    pub role: Option<String>,
    /// Whether it can contain messages.
    pub selectable: bool,
}

/// Provider-neutral search criteria. Empty fields do not restrict.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Criteria {
    /// Text in the `From` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Text in the `To` header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Text in the subject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Text anywhere in the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// On or after this day, by the date that the results show.
    /// On IMAP a missing `Date` header never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<chrono::NaiveDate>,
    /// Before this day, by the date that the results show.
    /// On IMAP a missing `Date` header never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<chrono::NaiveDate>,
    /// Required read state, or either when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    /// Required flagged state, or either when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flagged: Option<bool>,
    /// Arrival boundary captured by the search.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<Cutoff>,
}

/// A search's arrival boundary; IMAP also checks the folder's identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Cutoff {
    /// Highest matching UID and the folder's UIDVALIDITY.
    Imap {
        /// Highest matching UID.
        uid: Uid,
        /// UIDVALIDITY at the search.
        uid_validity: u32,
    },
    /// Whole Unix seconds, rounded down before dispatching the search.
    Time(i64),
}

impl Criteria {
    fn to_imap(&self) -> SearchQuery {
        let mut query = SearchQuery::new();
        if let Some(value) = &self.from {
            query = query.from(value.clone());
        }
        if let Some(value) = &self.to {
            query = query.to(value.clone());
        }
        if let Some(value) = &self.subject {
            query = query.subject(value.clone());
        }
        if let Some(value) = &self.text {
            query = query.text(value.clone());
        }
        if let Some(date) = self.since {
            query = query.since(date);
        }
        if let Some(date) = self.before {
            query = query.before(date);
        }
        if let Some(read) = self.read {
            query = query.unread(!read);
        }
        if let Some(flagged) = self.flagged {
            query = query.flagged(flagged);
        }
        if let Some(Cutoff::Imap { uid, .. }) = self.until {
            query = query.uid_at_most(uid);
        }
        query
    }

    /// The text filters supplied to the search, with their provider query names.
    pub(super) fn text_filters(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("from", self.from.as_deref()),
            ("to", self.to.as_deref()),
            ("subject", self.subject.as_deref()),
            ("text", self.text.as_deref()),
        ]
        .into_iter()
        .filter_map(|(filter, value)| value.map(|value| (filter, value)))
    }

    /// Refuses filters that the provider cannot match exactly in a selection.
    fn exact_for_selection(
        &self,
        rules: &SelectionFilterRules,
        provider: &str,
    ) -> MailboxResult<()> {
        for (filter, value) in self.text_filters() {
            let hint = if !rules.allows(filter) {
                "narrow with other filters instead"
            } else if rules.one_word.contains(&filter) {
                let clean = words(filter, value, provider)?.join(" ");
                if clean == value.trim().to_lowercase()
                    && (clean.chars().all(char::is_alphanumeric)
                        || filter == "from" && is_address(&clean))
                    && !(filter == "from" && clean == "me")
                {
                    continue;
                }
                if rules.one_word.contains(&"from") {
                    "use one word of letters and digits (one address in from)"
                } else {
                    "use one word of letters and digits"
                }
            } else {
                continue;
            };
            return Err(MailboxError::coded(
                ToolErrorCode::InvalidInput,
                format!(
                    "{provider} can't match the {filter} filter exactly as given, so a selection can't use it; {hint}"
                ),
            ));
        }
        Ok(())
    }

    fn leaving_out(&self, change: &Change) -> Option<Self> {
        let mut criteria = self.clone();
        if let Change::Flags { read, flagged } = change {
            for (wanted, changed) in [(&mut criteria.read, read), (&mut criteria.flagged, flagged)]
            {
                if let Some(changed) = changed {
                    if *wanted == Some(*changed) {
                        return None;
                    }
                    *wanted = Some(!changed);
                }
            }
        }
        Some(criteria)
    }
}

fn is_address(value: &str) -> bool {
    value.split_once('@').is_some_and(|address| {
        <[&str; 2]>::from(address)
            .into_iter()
            .flat_map(|side| side.split(['.', '-', '_', '+']))
            .all(|part| !part.is_empty() && part.chars().all(char::is_alphanumeric))
    })
}

/// The literal words that Gmail and Outlook can search for. Lowercase words
/// are text, not operators; unsupported punctuation separates words.
fn words(filter: &str, value: &str, provider: &str) -> MailboxResult<Vec<String>> {
    let words: Vec<_> = value
        .split(|c: char| !c.is_alphanumeric() && !"@.-_+'".contains(c))
        .map(|word| word.trim_start_matches(['-', '+']))
        .filter(|word| word.chars().any(char::is_alphanumeric))
        .map(str::to_lowercase)
        .collect();
    if words.is_empty() {
        return Err(MailboxError::coded(
            ToolErrorCode::InvalidInput,
            format!("the {filter} filter has no word {provider} can search for; use other words"),
        ));
    }
    Ok(words)
}

/// The start of `day` in UTC, in Unix seconds.
const fn day_start(day: chrono::NaiveDate) -> i64 {
    day.and_time(chrono::NaiveTime::MIN).and_utc().timestamp()
}

/// A message in search results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Opaque message id.
    pub id: String,
    /// IMAP UID, for IMAP accounts only.
    pub uid: Option<Uid>,
    /// First sender.
    pub from: Option<EmailAddress>,
    /// Whether a mail client shows `from` as the sender's address, as
    /// [`mime::sender`](postkeep_mail::mime::sender) finds.
    pub from_clear: bool,
    /// The value of each `From` header as sent, in their order, where the provider gives them.
    pub from_values: Vec<String>,
    /// Subject.
    pub subject: Option<String>,
    /// Date.
    pub date: Option<chrono::DateTime<chrono::FixedOffset>>,
    /// Flags.
    pub flags: MessageFlags,
    /// Size in bytes.
    pub size: Option<u32>,
}

/// One page of search results, newest first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// Arrival boundary for acting on this search, when the provider can check it.
    pub cutoff: Option<Cutoff>,
    /// Number of matches. An estimate when `estimated` is set.
    pub total: usize,
    /// Whether `total` is the provider's estimate rather than an exact count.
    pub estimated: bool,
    /// Offset of the first message.
    pub offset: usize,
    /// The messages.
    pub messages: Vec<Summary>,
    /// Whether more matches follow this page.
    pub has_more: bool,
}

/// The next search matches, or a final answer that needs no action.
#[derive(Debug)]
pub enum Selected {
    /// Current source ids and whether more matches remain.
    Matches {
        /// Current source ids, newest first.
        ids: Vec<Selector>,
        /// Whether matches remain beyond these ids.
        more: bool,
        /// Whether the listing left out messages already as asked.
        left_out: bool,
    },
    /// Final answer, with no messages to act on.
    Done(String),
}

impl Selected {
    fn own_folder(folder: &str, change: &Change, permanent_delete: bool) -> Self {
        Self::Done(match change {
            Change::Trash => format!("{}; {NOTHING_LEFT}", already_in_trash(permanent_delete)),
            _ => format!("the matches are already in {folder}; {NOTHING_LEFT}"),
        })
    }

    fn kept_folder(folder: &str, most: usize) -> MailboxError {
        MailboxError::coded(
            ToolErrorCode::InvalidInput,
            format!(
                "this move keeps the messages in {folder} too, so a selection moves at most {most} of them; narrow the search"
            ),
        )
    }

    fn matches(ids: impl IntoIterator<Item = String>, more: bool) -> Self {
        Self::Matches {
            ids: ids
                .into_iter()
                .map(|id| Selector {
                    id: Some(id),
                    ..Selector::default()
                })
                .collect(),
            more,
            left_out: false,
        }
    }
}

/// A fetched message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// Opaque message id.
    pub id: String,
    /// Folder the message is in.
    pub folder: String,
    /// IMAP UID, for IMAP accounts only.
    pub uid: Option<Uid>,
    /// The parsed message. Its `uid` is meaningless for other providers.
    pub message: Message,
}

/// A message addressed by a tool call: an opaque `id`, or the legacy
/// `folder` plus `uid` pair of IMAP accounts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Selector {
    /// Opaque id from `search_messages`.
    pub id: Option<String>,
    /// Folder, with `uid`.
    pub folder: Option<String>,
    /// IMAP UID, with `folder`.
    pub uid: Option<Uid>,
}

/// A resolved IMAP message address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapTarget {
    /// Folder.
    pub folder: String,
    /// UID within `folder`.
    pub uid: Uid,
    /// The folder's `UIDVALIDITY` that the id carries; `None` for an id
    /// from an earlier version and for the `folder` plus `uid` pair.
    pub uid_validity: Option<u32>,
}

impl Selector {
    /// Resolves the selector for an IMAP account.
    ///
    /// # Errors
    ///
    /// Returns a message for the model when neither a valid id nor a
    /// folder and UID were given.
    pub fn imap(&self) -> Result<ImapTarget, String> {
        let id = self
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty());
        if let Some(id) = id {
            let (folder, uid, uid_validity) = id::parse_imap_id(id).ok_or_else(|| {
                "the id is not a message id of this account; take ids from search_messages"
                    .to_owned()
            })?;
            return Ok(ImapTarget {
                folder,
                uid,
                uid_validity,
            });
        }
        let folder = self
            .folder
            .as_deref()
            .map(str::trim)
            .filter(|folder| !folder.is_empty());
        match (folder, self.uid) {
            (Some(_), Some(0)) => Err("uid must be greater than 0".to_owned()),
            (Some(folder), Some(uid)) => Ok(ImapTarget {
                folder: folder.to_owned(),
                uid,
                uid_validity: None,
            }),
            _ => Err(
                "say which message: pass its id from search_messages (or folder and uid)"
                    .to_owned(),
            ),
        }
    }
}

/// The reason for a set not started before the call's deadline.
pub(crate) const TIME_EXHAUSTED: &str = postkeep_upstream::http::DEADLINE_REASON;
/// A write may have left without a usable answer.
const SENT_NO_ANSWER: &str = "sent, no answer: check before repeating";
/// An IMAP All folder cannot always show what the destination already held.
pub(crate) const ALREADY_UNSEEN: &str =
    "the source folder doesn't show what the destination already held";

/// A change that may have been made, or whose success answer could not be read.
fn unanswered(error: &ApiError) -> bool {
    provider_may_have_acted(error) || matches!(error, ApiError::Malformed { .. })
}

const TOO_LARGE_TO_FORWARD: &str = "the message to forward is too large for postkeep to read";
pub(crate) const MAY_HAVE_BEEN_SENT: &str = "The message may have been sent. Check Sent before trying again, but no copy there does not prove it was not sent.";
pub(crate) const DRAFT_UNCONFIRMED: &str =
    "The provider did not confirm the draft. Check Drafts before trying again.";

/// No usable answer, or a server error (5xx): the provider may have acted.
fn provider_may_have_acted(error: &ApiError) -> bool {
    matches!(
        error,
        ApiError::Http(
            HttpError::Timeout(_) | HttpError::Transport { .. } | HttpError::TooLarge(_)
        )
    ) || error
        .status()
        .is_some_and(|status| status.is_server_error())
}

enum SendError {
    Api(ApiError, &'static str),
    Mail(postkeep_mail::Error),
}

fn maybe_sent(error: SendError) -> MailboxError {
    match error {
        SendError::Api(error, who) if !provider_may_have_acted(&error) => {
            graph::submit_error(&error, who)
        }
        SendError::Mail(error) if !matches!(error, postkeep_mail::Error::SubmissionUnconfirmed) => {
            error.into()
        }
        _ => MailboxError::coded(ToolErrorCode::SubmissionUncertain, MAY_HAVE_BEEN_SENT),
    }
}

fn too_large_to_forward() -> MailboxError {
    MailboxError::coded(ToolErrorCode::PayloadTooLarge, TOO_LARGE_TO_FORWARD)
}

/// A forward whose original and uploads together are over the memory budget.
fn beyond_budget(original: usize, uploads: usize) -> MailboxError {
    use crate::limits::megabytes;
    MailboxError::coded(
        ToolErrorCode::PayloadTooLarge,
        format!(
            "Not sent: the forwarded message ({}) and the uploaded files ({}), with the room an \
         original needs, are {}. Forward it with fewer files, and send the rest in another message.",
            megabytes(original),
            megabytes(uploads),
            crate::limits::beyond_budget()
        ),
    )
}

fn forward_size_error(reserved: usize) -> MailboxError {
    if reserved < postkeep_upstream::http::MESSAGE_LIMIT {
        MailboxError::coded(
            ToolErrorCode::PayloadTooLarge,
            "The message to forward was larger than the provider reported; nothing was sent.",
        )
    } else {
        too_large_to_forward()
    }
}

/// Final answer or ending when no matches remain to change.
pub const NOTHING_LEFT: &str = "nothing left to change";
/// Final answer or ending when a listing consumed the action's time budget.
pub const SEARCH_TIME_EXHAUSTED: &str = "searching took all the time: narrow the search";

/// A change applied to one or many messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Set or clear the read and flagged state.
    Flags {
        /// Read state, left unchanged when absent.
        read: Option<bool>,
        /// Flagged state, left unchanged when absent.
        flagged: Option<bool>,
    },
    /// Move to this folder.
    Move(String),
    /// Move to the trash.
    Trash,
}

impl Change {
    fn already_reason(&self, permanent_delete: bool) -> String {
        match self {
            Self::Move(_) => "already there".to_owned(),
            Self::Trash => already_in_trash(permanent_delete).to_owned(),
            Self::Flags { read, flagged } => {
                let states: Vec<_> = [
                    read.map(|read| if read { "read" } else { "unread" }),
                    flagged.map(|on| if on { "flagged" } else { "unflagged" }),
                ]
                .into_iter()
                .flatten()
                .collect();
                format!("already {}", states.join(" and "))
            }
        }
    }
}

/// Whether the caller named the ids or this call listed them for the change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdsFrom {
    /// Explicit ids: the provider must check the requested state.
    Caller,
    /// The selection listing already checked the requested state where it could.
    Selection,
}

/// Whether to apply a change or only check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Apply the change.
    Act,
    /// Check without changing mail.
    DryRun,
}

/// The result for one requested message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Changed or already in the requested state.
    Ok,
    /// Refused, or sent without a usable answer.
    Failed,
    /// No message matched the id in this mailbox.
    NotFound,
    /// Not started before the call stopped.
    NotReached,
}

/// One message's outcome, in the caller's order.
#[derive(Debug)]
pub struct Outcome {
    /// Requested id (a current source id for a legacy folder and UID).
    pub id: String,
    /// Whether the message was changed, failed, absent, or not reached.
    pub status: Status,
    /// New id after a move, where the server reports it.
    pub new_id: Option<String>,
    /// Advice or the error, already worded for the caller.
    pub reason: String,
    pub(crate) error: Option<(ToolErrorCode, Option<u64>)>,
}

impl Outcome {
    /// Whether the call changed the message, or would change it in a dry run.
    #[must_use]
    pub fn changed(&self) -> bool {
        self.status == Status::Ok && (self.reason.is_empty() || self.reason == ALREADY_UNSEEN)
    }

    fn pending(id: String) -> Self {
        Self {
            id,
            status: Status::NotReached,
            new_id: None,
            reason: TIME_EXHAUSTED.to_owned(),
            error: Some((ToolErrorCode::Timeout, None)),
        }
    }

    fn ok(&mut self, reason: impl Into<String>) {
        self.status = Status::Ok;
        self.reason = reason.into();
        self.error = None;
    }

    fn fail(
        &mut self,
        status: Status,
        reason: impl Into<String>,
        code: ToolErrorCode,
        retry_after: Option<u64>,
    ) {
        assert!(
            status != Status::Ok,
            "successful outcomes must clear their error"
        );
        self.status = status;
        self.reason = reason.into();
        self.error = Some((code, retry_after));
    }

    fn sent_no_answer(&mut self) {
        self.fail(
            Status::Failed,
            SENT_NO_ANSWER,
            ToolErrorCode::SubmissionUncertain,
            None,
        );
    }

    fn reset_pending(&mut self) {
        self.fail(
            Status::NotReached,
            TIME_EXHAUSTED,
            ToolErrorCode::Timeout,
            None,
        );
    }
}

/// Prepare API ids once, retaining a failed outcome for every bad selector.
fn provider_outcomes(ids: &[Selector], prefix: &str) -> (Vec<Outcome>, Vec<(usize, String)>) {
    let mut valid = Vec::new();
    let outcomes = ids
        .iter()
        .enumerate()
        .map(|(index, selector)| {
            let mut out = Outcome::pending(selector.id.clone().unwrap_or_default());
            match graph::provider_message_id(selector, prefix) {
                Ok(raw) => {
                    valid.push((index, raw.to_owned()));
                }
                Err(err) => out.fail(
                    Status::Failed,
                    err.to_string(),
                    ToolErrorCode::InvalidInput,
                    None,
                ),
            }
            out
        })
        .collect();
    (outcomes, valid)
}

/// An IMAP mailbox: a client for new connections plus the session pool.
#[derive(Debug)]
pub struct ImapMailbox {
    account: AccountId,
    client: MailClient,
    fingerprint: Fingerprint,
    pool: ImapPool,
    /// Where the news of its logins goes, if anywhere.
    passwords: Option<Box<PasswordNotes>>,
    /// Where its logins and sends are counted, under its server's id.
    counted: Option<(Metrics, &'static str)>,
}

/// Where an IMAP mailbox writes down what its logins say about the stored
/// password, and whom it tells when one clears a record.
#[derive(Debug)]
struct PasswordNotes {
    store: Store,
    webhooks: Option<WebhookControl>,
}

/// The caller's mailbox.
#[derive(Debug)]
pub enum Mailbox {
    /// An IMAP account (iCloud, Fastmail, Yahoo or a custom server).
    Imap(ImapMailbox),
    /// An Outlook.com or Microsoft 365 account, through Microsoft Graph.
    Graph(Box<graph::GraphMailbox>),
    /// A Gmail account, through the Gmail API.
    Gmail(Box<gmail::GmailMailbox>),
}

/// Errors from mailbox operations, already phrased for the model.
pub type MailboxResult<T> = Result<T, MailboxError>;

/// A mailbox error.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// No new request was started after the action's time budget was used up.
    #[error("{TIME_EXHAUSTED}")]
    Deadline,

    /// A new IMAP session could not be opened; do not reconnect for later sets.
    #[error(transparent)]
    Connect(postkeep_mail::Error),

    /// An IMAP or SMTP error.
    #[error(transparent)]
    Mail(#[from] postkeep_mail::Error),
    /// A classified failure, already phrased for the model.
    #[error("{message}")]
    Coded {
        /// Machine-readable error code.
        code: ToolErrorCode,
        /// Suggested retry delay in seconds, if any.
        retry_after_seconds: Option<u64>,
        /// What the caller is told.
        message: String,
    },
}

impl MailboxError {
    /// Creates a mailbox error with a code and no retry delay.
    #[must_use]
    pub fn coded(code: ToolErrorCode, message: impl Into<String>) -> Self {
        Self::Coded {
            code,
            retry_after_seconds: None,
            message: message.into(),
        }
    }

    /// The machine-readable error code.
    #[must_use]
    pub fn code(&self) -> ToolErrorCode {
        match self {
            Self::Coded { code, .. } => *code,
            Self::Deadline => ToolErrorCode::Timeout,
            Self::Connect(err) | Self::Mail(err) => mail_code(err),
        }
    }

    /// The suggested retry delay in seconds, if any.
    #[must_use]
    pub const fn retry_after_seconds(&self) -> Option<u64> {
        match self {
            Self::Coded {
                retry_after_seconds,
                ..
            } => *retry_after_seconds,
            _ => None,
        }
    }

    /// Classifies the error and returns its optional retry delay.
    #[must_use]
    pub fn classify(&self) -> (ToolErrorCode, Option<u64>) {
        (self.code(), self.retry_after_seconds())
    }

    /// Changes only the caller-facing message, preserving the classification.
    #[must_use]
    pub fn map_message(self, map: impl FnOnce(String) -> String) -> Self {
        let (code, retry_after_seconds) = self.classify();
        let message = match self {
            Self::Coded { message, .. } => message,
            other => other.to_string(),
        };
        Self::Coded {
            code,
            retry_after_seconds,
            message: map(message),
        }
    }
}

pub(crate) const fn account_store_code(error: &StoreError) -> ToolErrorCode {
    match error {
        StoreError::Decrypt | StoreError::KeysDestroyed | StoreError::AccountDeleted => {
            ToolErrorCode::AuthRequired
        }
        _ => ToolErrorCode::ProviderUnavailable,
    }
}

pub(crate) fn mail_code(err: &MailError) -> ToolErrorCode {
    match err {
        MailError::Authentication => ToolErrorCode::AuthRequired,
        MailError::InvalidInput(_) | MailError::Build(_) => ToolErrorCode::InvalidInput,
        MailError::FolderNotFound(_) | MailError::MessageNotFound { .. } => ToolErrorCode::NotFound,
        MailError::MessageTooLarge => ToolErrorCode::PayloadTooLarge,
        MailError::StaleId { .. } => ToolErrorCode::StaleId,
        MailError::Unsupported(_) | MailError::Parse(_) => ToolErrorCode::Unsupported,
        MailError::Timeout | MailError::TimeExhausted => ToolErrorCode::Timeout,
        MailError::SubmissionUnconfirmed | MailError::WriteUnconfirmed => {
            ToolErrorCode::SubmissionUncertain
        }
        MailError::Imap(_) | MailError::Smtp(_) => match err.protocol_error_kind() {
            Some(ProtocolErrorKind::Rejected) => ToolErrorCode::InvalidInput,
            Some(ProtocolErrorKind::TooLarge) => ToolErrorCode::PayloadTooLarge,
            Some(ProtocolErrorKind::Timeout) => ToolErrorCode::Timeout,
            _ => ToolErrorCode::ProviderUnavailable,
        },
        _ => ToolErrorCode::ProviderUnavailable,
    }
}

impl From<crate::limits::LargeMessageError> for MailboxError {
    fn from(err: crate::limits::LargeMessageError) -> Self {
        let code = match err {
            crate::limits::LargeMessageError::TooLarge(_) => ToolErrorCode::PayloadTooLarge,
            crate::limits::LargeMessageError::Busy => ToolErrorCode::Busy,
        };
        Self::coded(code, err.to_string())
    }
}

/// Every operation fails with a [`MailboxError`]: the provider's error, or
/// a message for the model when the request does not fit the account.
#[expect(
    clippy::missing_errors_doc,
    reason = "the errors are documented once on the impl block"
)]
impl Mailbox {
    /// An IMAP mailbox.
    #[must_use]
    pub const fn imap(
        account: AccountId,
        client: MailClient,
        fingerprint: Fingerprint,
        pool: ImapPool,
    ) -> Self {
        Self::Imap(ImapMailbox {
            account,
            client,
            fingerprint,
            pool,
            passwords: None,
            counted: None,
        })
    }

    /// An IMAP mailbox that records in `store` when its login is rejected and
    /// clears the record when one works, and then tells `webhooks`, if there
    /// are any, that the account changed, so that a watcher which stopped on
    /// the record starts again. Other mailboxes stay as they are.
    #[must_use]
    pub(crate) fn noting_password(
        mut self,
        store: Store,
        webhooks: Option<WebhookControl>,
    ) -> Self {
        if let Self::Imap(imap) = &mut self {
            imap.passwords = Some(Box::new(PasswordNotes { store, webhooks }));
        }
        self
    }

    /// An IMAP mailbox that counts its logins and sends into `metrics`,
    /// under the id of its mail server, `server`. Other mailboxes stay as
    /// they are.
    #[must_use]
    pub(crate) fn counting(mut self, metrics: Metrics, server: &'static str) -> Self {
        if let Self::Imap(imap) = &mut self {
            imap.counted = Some((metrics, server));
        }
        self
    }

    /// An Outlook mailbox through Microsoft Graph.
    #[must_use]
    pub fn graph(api: postkeep_upstream::ApiClient, email: String) -> Self {
        Self::Graph(Box::new(graph::GraphMailbox::new(api, email)))
    }

    /// A Gmail mailbox through the Gmail API.
    #[must_use]
    pub fn gmail(api: postkeep_upstream::ApiClient, email: String) -> Self {
        Self::Gmail(Box::new(gmail::GmailMailbox::new(api, email)))
    }

    /// Lists the folders.
    pub async fn list_folders(&self) -> MailboxResult<Vec<FolderEntry>> {
        match self {
            Self::Graph(graph) => graph.list_folders().await,
            Self::Gmail(gmail) => gmail.list_folders().await,
            Self::Imap(imap) => {
                let folders = imap
                    .session(async |session| session.list_folders().await)
                    .await?;
                Ok(folders
                    .into_iter()
                    .map(|folder| {
                        let role = if folder.name.eq_ignore_ascii_case("INBOX") {
                            Some("inbox".to_owned())
                        } else {
                            folder.special_use.map(|role| role.as_str().to_owned())
                        };
                        FolderEntry {
                            name: folder.name,
                            role,
                            selectable: folder.selectable,
                        }
                    })
                    .collect())
            }
        }
    }

    /// Searches `folder`.
    pub async fn search(
        &self,
        folder: &str,
        criteria: &Criteria,
        paging: Paging,
    ) -> MailboxResult<Page> {
        let cutoff = Cutoff::Time(chrono::Utc::now().timestamp());
        match self {
            Self::Graph(graph) => {
                let mut page = graph.search(folder, criteria, paging).await?;
                page.cutoff = Some(cutoff);
                Ok(page)
            }
            Self::Gmail(gmail) => {
                let mut page = gmail.search(folder, criteria, paging).await?;
                page.cutoff = Some(cutoff);
                Ok(page)
            }
            Self::Imap(imap) => {
                let query = criteria.to_imap();
                let results = imap
                    .session(async |session| session.search(folder, &query, paging).await)
                    .await?;
                let end = results.offset + results.messages.len();
                Ok(Page {
                    cutoff: results
                        .last_uid
                        .zip(results.uid_validity)
                        .map(|(uid, uid_validity)| Cutoff::Imap { uid, uid_validity }),
                    total: results.total,
                    estimated: results.estimated,
                    offset: results.offset,
                    has_more: end < results.total,
                    messages: results
                        .messages
                        .into_iter()
                        .map(|message| Summary {
                            id: id::imap_id(folder, message.uid, results.uid_validity),
                            uid: Some(message.uid),
                            from: message.from,
                            from_clear: message.from_clear,
                            from_values: message.from_values,
                            subject: message.subject,
                            date: message.date,
                            flags: message.flags,
                            size: message.size,
                        })
                        .collect(),
                })
            }
        }
    }

    /// Resolves a search to its next matches, leaving out changes already made.
    /// Listings share the action's deadline and never read message bodies.
    pub async fn selected(
        &self,
        selection: &SearchSelection,
        change: &Change,
        most: usize,
        deadline: Instant,
    ) -> MailboxResult<Selected> {
        let Some(criteria) = selection.criteria.leaving_out(change) else {
            return Ok(Selected::Done(format!(
                "every match is {}; {NOTHING_LEFT}",
                change.already_reason(false)
            )));
        };
        let narrowed = criteria != selection.criteria;
        let result = match (self, criteria.until) {
            (Self::Graph(graph), Some(Cutoff::Time(_))) => {
                graph
                    .selected(&selection.folder, &criteria, change, most, deadline)
                    .await
            }
            (Self::Gmail(gmail), Some(Cutoff::Time(_))) => {
                gmail
                    .selected(&selection.folder, &criteria, change, most, deadline)
                    .await
            }
            (Self::Imap(imap), Some(Cutoff::Imap { .. })) => {
                imap.selected(&selection.folder, &criteria, change, most, deadline)
                    .await
            }
            _ => {
                return Err(MailboxError::coded(
                    ToolErrorCode::InvalidInput,
                    selection::REFUSAL,
                ));
            }
        };
        match result {
            Err(MailboxError::Deadline) => Ok(Selected::Done(SEARCH_TIME_EXHAUSTED.to_owned())),
            Ok(Selected::Matches {
                ids,
                more,
                left_out,
            }) => Ok(Selected::Matches {
                ids,
                more,
                left_out: left_out || narrowed,
            }),
            result => result,
        }
    }

    /// Fetches one message.
    pub async fn get(&self, selector: &Selector) -> MailboxResult<Fetched> {
        match self {
            Self::Graph(graph) => graph.get(selector).await,
            Self::Gmail(gmail) => gmail.get(selector).await,
            Self::Imap(imap) => {
                let target = selector
                    .imap()
                    .map_err(|message| MailboxError::coded(ToolErrorCode::InvalidInput, message))?;
                let (message, seen) = imap
                    .session(async |session| {
                        session
                            .fetch_message(&target.folder, target.uid, target.uid_validity)
                            .await
                    })
                    .await?;
                Ok(Fetched {
                    id: id::imap_id(&target.folder, target.uid, seen),
                    uid: Some(target.uid),
                    folder: target.folder,
                    message,
                })
            }
        }
    }

    /// Reads a Gmail or IMAP original, reserving memory until its forward
    /// finishes, in one reservation with the `uploads` bytes it sends beside.
    pub(crate) async fn original(
        &self,
        selector: &Selector,
        uploads: usize,
    ) -> MailboxResult<(Vec<u8>, tokio::sync::SemaphorePermit<'static>)> {
        use postkeep_upstream::http::MESSAGE_LIMIT;
        let size = match self {
            Self::Gmail(gmail) => gmail.original_size(selector).await?,
            Self::Imap(imap) => {
                let target = selector
                    .imap()
                    .map_err(|message| MailboxError::coded(ToolErrorCode::InvalidInput, message))?;
                let size = imap.session(async |session| {
                    session
                        .message_size(&target.folder, target.uid, target.uid_validity)
                        .await
                });
                Some(size.await? as usize)
            }
            Self::Graph(_) => {
                return Err(MailboxError::coded(
                    ToolErrorCode::Unsupported,
                    "Outlook forwards its own messages",
                ));
            }
        };
        if size.is_some_and(|size| size > MESSAGE_LIMIT) {
            return Err(too_large_to_forward());
        }
        // Some providers only estimate size. Reserve a margin before fetching;
        // with no size, the whole budget, and the uploads are checked once read.
        let reserved = size.map_or(MESSAGE_LIMIT, |size| {
            (size + size / 8 + 1024).min(MESSAGE_LIMIT)
        });
        let room = if size.is_some() {
            reserved + uploads
        } else {
            reserved
        };
        if room > MESSAGE_LIMIT {
            return Err(beyond_budget(size.unwrap_or(reserved), uploads));
        }
        let permit = crate::limits::large_message(room).await?;
        let raw = match self {
            Self::Gmail(gmail) => gmail.original(selector, reserved).await?,
            Self::Imap(imap) => {
                let target = selector
                    .imap()
                    .map_err(|message| MailboxError::coded(ToolErrorCode::InvalidInput, message))?;
                imap.session(async |session| {
                    session
                        .fetch_raw(&target.folder, target.uid, target.uid_validity, reserved)
                        .await
                })
                .await
                .map_err(|error| match error {
                    MailboxError::Mail(postkeep_mail::Error::MessageTooLarge) => {
                        forward_size_error(reserved)
                    }
                    other => other,
                })?
            }
            Self::Graph(_) => {
                return Err(MailboxError::coded(
                    ToolErrorCode::Unsupported,
                    "Outlook forwards its own messages",
                ));
            }
        };
        if size.is_none() && raw.len() + uploads > MESSAGE_LIMIT {
            return Err(beyond_budget(raw.len(), uploads));
        }
        Ok((raw, permit))
    }

    /// One attachment of a message, by its 1-based id, with its content
    /// when it is at most `max_bytes` long. `None` when the message has no
    /// attachment `id`. Does not mark the message as read.
    pub async fn attachment(
        &self,
        selector: &Selector,
        id: u32,
        max_bytes: usize,
    ) -> MailboxResult<Option<AttachmentData>> {
        match self {
            Self::Graph(graph) => graph.attachment(selector, id, max_bytes).await,
            Self::Gmail(gmail) => gmail.attachment(selector, id, max_bytes).await,
            Self::Imap(imap) => {
                let target = selector
                    .imap()
                    .map_err(|message| MailboxError::coded(ToolErrorCode::InvalidInput, message))?;
                imap.session(async |session| {
                    session
                        .fetch_attachment(
                            &target.folder,
                            target.uid,
                            target.uid_validity,
                            id,
                            max_bytes,
                        )
                        .await
                })
                .await
            }
        }
    }

    /// Applies a change in provider-sized sets, in the given order. No new
    /// set starts after `deadline`; one already in flight may finish later.
    /// Individual failures are outcomes; setup failures fail the call.
    pub async fn apply(
        &self,
        ids: &[Selector],
        ids_from: IdsFrom,
        change: &Change,
        mode: Mode,
        deadline: Instant,
    ) -> MailboxResult<Vec<Outcome>> {
        match self {
            Self::Graph(graph) => graph.apply(ids, ids_from, change, mode, deadline).await,
            Self::Gmail(gmail) => gmail.apply(ids, ids_from, change, mode, deadline).await,
            Self::Imap(imap) => imap.apply(ids, ids_from, change, mode, deadline).await,
        }
    }

    /// Deletes one message for good, subject to the account's policy.
    pub async fn delete(&self, selector: &Selector) -> MailboxResult<String> {
        match self {
            Self::Graph(graph) => graph.delete(selector).await,
            Self::Gmail(gmail) => gmail.delete(selector),
            Self::Imap(imap) => {
                let target = selector
                    .imap()
                    .map_err(|message| MailboxError::coded(ToolErrorCode::InvalidInput, message))?;
                if target.uid_validity.is_none() && imap.client.config().permanent_delete {
                    return Err(MailboxError::coded(
                        ToolErrorCode::StaleId,
                        "this message can't be checked against its folder's UIDVALIDITY, so it \
                         isn't deleted for good; call search_messages again and use the id it \
                         gives"
                            .to_owned(),
                    ));
                }
                let seen = imap
                    .session(async |session| {
                        session
                            .delete_message(
                                &target.folder,
                                target.uid,
                                target.uid_validity,
                                DeleteMode::Permanent,
                            )
                            .await
                    })
                    .await?;
                Ok(id::imap_id(&target.folder, target.uid, seen))
            }
        }
    }

    /// Creates a folder.
    pub async fn create_folder(&self, name: &str) -> MailboxResult<()> {
        match self {
            Self::Graph(graph) => graph.create_folder(name).await,
            Self::Gmail(gmail) => gmail.create_folder(name).await,
            Self::Imap(imap) => {
                imap.session(async |session| session.create_folder(name).await)
                    .await
            }
        }
    }

    /// Sends a new message.
    pub async fn send(
        &self,
        message: &OutgoingMessage,
        options: SendOptions,
    ) -> MailboxResult<SentMessage> {
        match self {
            Self::Imap(imap) => imap.count_send(imap.client.send(message, options).await),
            Self::Graph(graph) => graph.send(message, options).await,
            Self::Gmail(gmail) => gmail.send(message, options).await,
        }
    }

    /// Replies to a message.
    pub async fn reply(
        &self,
        selector: &Selector,
        reply: &Reply,
        options: SendOptions,
    ) -> MailboxResult<SentMessage> {
        match self {
            Self::Graph(graph) => graph.reply(selector, reply, options).await,
            Self::Gmail(gmail) => gmail.reply(selector, reply, options).await,
            Self::Imap(imap) => {
                let target = selector
                    .imap()
                    .map_err(|message| MailboxError::coded(ToolErrorCode::InvalidInput, message))?;
                let sent = imap
                    .client
                    .reply(
                        &target.folder,
                        target.uid,
                        target.uid_validity,
                        reply,
                        options,
                    )
                    .await;
                imap.count_send(sent)
            }
        }
    }

    /// Saves a new draft.
    pub async fn create_draft(&self, message: &OutgoingMessage) -> MailboxResult<SavedDraft> {
        match self {
            Self::Imap(imap) => imap
                .session(async |session| imap.client.save_draft(session, message).await)
                .await
                .map(imap_saved_draft)
                .map_err(imap_draft_error),
            Self::Graph(graph) => graph.create_draft(message).await,
            Self::Gmail(gmail) => gmail.create_draft(message).await,
        }
    }

    /// Saves a reply to a message as a draft.
    pub async fn create_reply_draft(
        &self,
        selector: &Selector,
        reply: &Reply,
    ) -> MailboxResult<SavedDraft> {
        match self {
            Self::Imap(imap) => {
                let target = selector
                    .imap()
                    .map_err(|message| MailboxError::coded(ToolErrorCode::InvalidInput, message))?;
                imap.session(async |session| {
                    imap.client
                        .save_draft_reply(
                            session,
                            &target.folder,
                            target.uid,
                            target.uid_validity,
                            reply,
                        )
                        .await
                })
                .await
                .map(imap_saved_draft)
                .map_err(imap_draft_error)
            }
            Self::Graph(graph) => graph.create_reply_draft(selector, reply).await,
            Self::Gmail(gmail) => gmail.create_reply_draft(selector, reply).await,
        }
    }
}

/// A draft saved without sending it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
pub struct SavedDraft {
    /// Opaque message id of the saved draft for immediate `get_message` readback, when the provider returns one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Message-ID of the draft, without angle brackets.
    pub message_id: String,
    /// The Drafts folder the draft was saved to.
    pub folder: String,
}

fn imap_draft_error(err: MailboxError) -> MailboxError {
    match err {
        MailboxError::Mail(MailError::WriteUnconfirmed) => {
            MailboxError::coded(ToolErrorCode::SubmissionUncertain, DRAFT_UNCONFIRMED)
        }
        other => other,
    }
}

fn imap_saved_draft(saved: postkeep_mail::SavedDraft) -> SavedDraft {
    SavedDraft {
        id: imap_draft_id(&saved.folder, saved.append_uid),
        message_id: saved.message_id,
        folder: saved.folder,
    }
}

fn imap_draft_id(folder: &str, append_uid: Option<(u32, Uid)>) -> Option<String> {
    let (uid_validity, uid) = append_uid?;
    let candidate = id::imap_id(folder, uid, Some(uid_validity));
    id::parse_imap_id(&candidate).is_some().then_some(candidate)
}

fn imap_run_end(
    ids: &[Selector],
    targets: &[Option<ImapTarget>],
    start: usize,
    target: &ImapTarget,
) -> usize {
    (start + 1..targets.len())
        .find(|&i| {
            targets[i].as_ref().is_none_or(|next| {
                next.folder != target.folder
                    || next.uid_validity != target.uid_validity
                    || ids[i].id.is_some() != ids[start].id.is_some()
            })
        })
        .unwrap_or(targets.len())
}

fn imap_targets(ids: &[Selector]) -> (Vec<Option<ImapTarget>>, Vec<Outcome>) {
    let mut outcomes = Vec::with_capacity(ids.len());
    let targets: Vec<_> = ids
        .iter()
        .map(|selector| {
            let target = selector.imap();
            let mut out = Outcome::pending(selector.id.clone().unwrap_or_default());
            match &target {
                Ok(target) => {
                    out.id = id::imap_id(&target.folder, target.uid, target.uid_validity);
                }
                Err(err) => out.fail(Status::Failed, err, ToolErrorCode::InvalidInput, None),
            }
            outcomes.push(out);
            target.ok()
        })
        .collect();
    (targets, outcomes)
}

fn finish_imap(
    outcomes: &mut [Outcome],
    target: &ImapTarget,
    uids: &[Uid],
    destination: Option<&str>,
    (already_reason, changed_reason): (&str, &str),
    progress: Option<Progress>,
    result: MailboxResult<postkeep_mail::Changed>,
) {
    let (changed, failure) = match (result, progress) {
        (Ok(changed), _) => (changed, None),
        (Err(err), Some(progress)) => {
            let (code, retry_after) = err.classify();
            let reason = err.to_string();
            let in_flight = match progress.in_flight {
                InFlight::Unanswered => SENT_NO_ANSWER.to_owned(),
                InFlight::Refused => reason.clone(),
                _ => format!(
                    "{reason}; part of the change may have been made: check before repeating"
                ),
            };
            let in_flight_error = if matches!(progress.in_flight, InFlight::Refused) {
                (code, retry_after)
            } else {
                (ToolErrorCode::SubmissionUncertain, None)
            };
            (
                progress.changed,
                Some((
                    progress.confirmed,
                    progress.carried,
                    reason,
                    (code, retry_after),
                    in_flight,
                    in_flight_error,
                )),
            )
        }
        (Err(err), None) => {
            let reason = err.to_string();
            let (code, retry_after) = err.classify();
            for out in outcomes {
                out.fail(Status::Failed, &reason, code, retry_after);
            }
            return;
        }
    };
    for (out, uid) in outcomes.iter_mut().zip(uids) {
        out.id = id::imap_id(&target.folder, *uid, changed.uid_validity);
        if changed.missing.contains(uid) {
            out.fail(
                Status::NotFound,
                format!(
                    "no such message in {}; it may have been moved{}",
                    target.folder,
                    destination.map_or_else(String::new, |d| format!(": search {d}")),
                ),
                ToolErrorCode::NotFound,
                None,
            );
        } else if changed.already.contains(uid) {
            out.ok(already_reason);
        } else if let Some((confirmed, carried, reason, error, in_flight, in_flight_error)) =
            &failure
            && let Some(index) = changed.done.iter().position(|done| done == uid)
            && index >= *confirmed
        {
            let (status, reason, (code, retry_after)) = if *carried == 0 && *confirmed == 0 {
                (Status::Failed, reason, *error)
            } else if index < confirmed + carried {
                (Status::Failed, in_flight, *in_flight_error)
            } else {
                (Status::NotReached, reason, *error)
            };
            out.fail(status, reason, code, retry_after);
        } else {
            out.ok(changed_reason);
            if let Some(destination) = destination
                && let Some(new) = changed.new_uids.get(uid)
            {
                out.new_id = Some(id::imap_id(
                    destination,
                    *new,
                    changed.destination_uid_validity,
                ));
            }
        }
    }
}

/// Stop on a failed connection, not on an operation that reached an open session.
fn stop_imap_on_connect<T>(
    outcomes: &mut [Outcome],
    failed: std::ops::Range<usize>,
    result: &MailboxResult<T>,
) -> bool {
    let Err(MailboxError::Connect(err)) = result else {
        return false;
    };
    let reason = err.to_string();
    let code = mail_code(err);
    for out in &mut outcomes[failed] {
        out.fail(Status::Failed, &reason, code, None);
    }
    for out in outcomes
        .iter_mut()
        .filter(|out| out.status == Status::NotReached)
    {
        out.fail(Status::NotReached, &reason, code, None);
    }
    true
}

fn imap_flags(change: &Change) -> Vec<(Flag, bool)> {
    match change {
        Change::Flags { read, flagged } => [(Flag::Seen, *read), (Flag::Flagged, *flagged)]
            .into_iter()
            .filter_map(|(flag, value)| value.map(|value| (flag, value)))
            .collect(),
        _ => Vec::new(),
    }
}

fn imap_keeps_folder(
    source: Option<SpecialUse>,
    destination: Option<SpecialUse>,
    change: &Change,
) -> bool {
    source == Some(SpecialUse::All)
        && matches!(change, Change::Move(_))
        && !matches!(destination, Some(SpecialUse::Trash | SpecialUse::Junk))
}

fn gmail_label<'a>(destination: &'a str, all: &Folder) -> Option<&'a str> {
    let gmail_folder = all.delimiter.as_deref().is_some_and(|delimiter| {
        all.name.rsplit_once(delimiter).is_some_and(|(parent, _)| {
            destination
                .strip_prefix(parent)
                .is_some_and(|tail| tail.starts_with(delimiter))
        })
    });
    (!same_folder(destination, "INBOX") && !gmail_folder).then_some(destination)
}

/// Resolve a change once, before any message changes, retaining LIST's roles.
async fn imap_destination(
    session: &mut ImapSession,
    change: &Change,
) -> postkeep_mail::Result<(Option<String>, Vec<Folder>, bool)> {
    let is_gmail = session.is_gmail();
    match change {
        Change::Flags { .. } => Ok((None, Vec::new(), is_gmail)),
        Change::Trash => Ok((Some(session.trash_folder().await?), Vec::new(), is_gmail)),
        Change::Move(name) => {
            let folders = session.list_folders().await?;
            let folder = folders
                .iter()
                .find(|folder| same_folder(&folder.name, name))
                .ok_or_else(|| postkeep_mail::Error::FolderNotFound(name.clone()))?;
            Ok((Some(folder.name.clone()), folders, is_gmail))
        }
    }
}

impl ImapMailbox {
    async fn selected(
        &self,
        folder: &str,
        criteria: &Criteria,
        change: &Change,
        most: usize,
        deadline: Instant,
    ) -> MailboxResult<Selected> {
        criteria
            .exact_for_selection(&SelectionFilterRules::for_provider(Provider::Imap), "IMAP")?;
        let Some(Cutoff::Imap { uid_validity, .. }) = criteria.until else {
            return Err(MailboxError::coded(
                ToolErrorCode::InvalidInput,
                selection::REFUSAL,
            ));
        };
        let result = self
            .session_until(Some(deadline), async |session| {
                let (destination, folders, _) = imap_destination(session, change).await?;
                let role = |name: &str| {
                    folders
                        .iter()
                        .find(|entry| entry.name == name)
                        .and_then(|entry| entry.special_use)
                };
                let kept =
                    imap_keeps_folder(role(folder), destination.as_deref().and_then(role), change);
                if destination
                    .as_deref()
                    .is_some_and(|name| same_folder(name, folder))
                {
                    return Ok(Ok(Selected::own_folder(
                        folder,
                        change,
                        self.client.config().permanent_delete,
                    )));
                }
                if Instant::now() >= deadline {
                    return Ok(Err(MailboxError::Deadline));
                }
                let query = criteria.to_imap();
                let want = most.saturating_add(1);
                let uids = match session
                    .matching(folder, &query, uid_validity, want, deadline)
                    .await
                {
                    Err(postkeep_mail::Error::TimeExhausted) => {
                        return Ok(Err(MailboxError::Deadline));
                    }
                    result => result?,
                };
                if Instant::now() >= deadline {
                    return Ok(Err(MailboxError::Deadline));
                }
                let more = uids.len() > most;
                if more && kept {
                    return Ok(Err(Selected::kept_folder(folder, most)));
                }
                Ok(Ok(Selected::matches(
                    uids.into_iter()
                        .take(most)
                        .map(|uid| id::imap_id(folder, uid, Some(uid_validity))),
                    more,
                )))
            })
            .await;
        match result {
            Ok(result) => result,
            Err(MailboxError::Mail(postkeep_mail::Error::StaleId { .. })) => {
                Err(MailboxError::coded(
                    ToolErrorCode::StaleId,
                    "this folder was renumbered since the search; search again",
                ))
            }
            Err(err) => Err(err),
        }
    }

    async fn check_old_id(&self, target: &ImapTarget, deadline: Instant) -> MailboxResult<()> {
        let seen = self
            .session_until(Some(deadline), async |session| {
                session
                    .find_messages(&target.folder, &[], None, Check::Exists)
                    .await
            })
            .await?;
        if seen.uid_validity.is_some() {
            return Err(MailboxError::coded(
                ToolErrorCode::StaleId,
                "invalid input: this message can't be checked against its folder's UIDVALIDITY; call search_messages again and use the id it gives",
            ));
        }
        Ok(())
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the action deadline, reconnect guard and outcome ledger share one ordered loop"
    )]
    async fn apply(
        &self,
        ids: &[Selector],
        ids_from: IdsFrom,
        change: &Change,
        mode: Mode,
        deadline: Instant,
    ) -> MailboxResult<Vec<Outcome>> {
        let (targets, mut outcomes) = imap_targets(ids);
        if Instant::now() >= deadline || targets.iter().all(Option::is_none) {
            return Ok(outcomes);
        }
        let (destination, folders, is_gmail) = match self
            .session_until(Some(deadline), async |session| {
                imap_destination(session, change).await
            })
            .await
        {
            Err(MailboxError::Deadline) => return Ok(outcomes),
            result => result?,
        };
        let destination = destination.as_deref();
        let folder = |name: &str| {
            folders
                .iter()
                .find(|folder| same_folder(&folder.name, name))
        };
        let role = |name: &str| folder(name).and_then(|folder| folder.special_use);
        let flags = imap_flags(change);
        let already_reason = change.already_reason(self.client.config().permanent_delete);
        let mut sent = false;
        let mut start = 0;
        while start < targets.len() {
            if Instant::now() >= deadline {
                break;
            }
            let Some(target) = &targets[start] else {
                start += 1;
                continue;
            };
            let end = imap_run_end(ids, &targets, start, target);
            let own = destination.is_some_and(|name| same_folder(name, &target.folder));
            let kept =
                !own && imap_keeps_folder(role(&target.folder), destination.and_then(role), change);
            let label = if kept && is_gmail {
                destination
                    .zip(folder(&target.folder))
                    .and_then(|(dest, all)| gmail_label(dest, all))
            } else {
                None
            };
            let check = match label {
                Some(label) => Check::Label(label),
                None if destination.is_none() && ids_from == IdsFrom::Caller => {
                    Check::Flags(&flags)
                }
                None => Check::Exists,
            };
            let changed_reason = if kept && label.is_none() {
                ALREADY_UNSEEN
            } else {
                ""
            };
            if target.uid_validity.is_none() && ids[start].id.is_some() {
                let checked = self.check_old_id(target, deadline).await;
                if matches!(checked, Err(MailboxError::Deadline)) {
                    break;
                }
                let first_set = start..(start + UID_SET_MAX).min(end);
                if stop_imap_on_connect(&mut outcomes, first_set, &checked) {
                    return Ok(outcomes);
                }
                if let Err(err) = checked {
                    let (code, retry_after) = err.classify();
                    for out in &mut outcomes[start..end] {
                        out.fail(Status::Failed, err.to_string(), code, retry_after);
                    }
                    start = end;
                    continue;
                }
            }
            for offset in (start..end).step_by(UID_SET_MAX) {
                let stop = (offset + UID_SET_MAX).min(end);
                let uids: Vec<_> = targets[offset..stop]
                    .iter()
                    .flatten()
                    .map(|t| t.uid)
                    .collect();
                let mut progress = None;
                let result = self
                    .session_until(Some(deadline), async |session| {
                        match (own, mode, destination) {
                            (true, _, _) | (_, Mode::DryRun, _) => {
                                let mut changed = session
                                    .find_messages(
                                        &target.folder,
                                        &uids,
                                        target.uid_validity,
                                        check,
                                    )
                                    .await?;
                                if own {
                                    changed.already = std::mem::take(&mut changed.done);
                                }
                                Ok(changed)
                            }
                            (false, Mode::Act, Some(destination)) => {
                                session
                                    .move_messages(
                                        &target.folder,
                                        &uids,
                                        target.uid_validity,
                                        destination,
                                        check,
                                        &mut progress,
                                    )
                                    .await
                            }
                            (false, Mode::Act, None) => {
                                session
                                    .set_flags(
                                        &target.folder,
                                        &uids,
                                        target.uid_validity,
                                        &flags,
                                        check,
                                        &mut progress,
                                    )
                                    .await
                            }
                        }
                    })
                    .await;
                if matches!(result, Err(MailboxError::Deadline)) {
                    break;
                }
                if stop_imap_on_connect(&mut outcomes, offset..stop, &result) {
                    return Ok(outcomes);
                }
                sent |= progress
                    .as_ref()
                    .is_some_and(|progress| progress.confirmed > 0 || progress.carried > 0);
                let stopped = result
                    .as_ref()
                    .err()
                    .filter(|_| sent)
                    .map(|err| (err.to_string(), err.classify()));
                finish_imap(
                    &mut outcomes[offset..stop],
                    target,
                    &uids,
                    destination,
                    (&already_reason, changed_reason),
                    progress,
                    result,
                );
                if let Some((reason, (code, retry_after))) = stopped {
                    for out in &mut outcomes[stop..] {
                        if out.status == Status::NotReached {
                            out.fail(Status::NotReached, &reason, code, retry_after);
                        }
                    }
                    return Ok(outcomes);
                }
            }
            start = end;
        }
        Ok(outcomes)
    }

    /// Runs an ordinary operation without an action deadline.
    async fn session<T>(
        &self,
        op: impl AsyncFnOnce(&mut ImapSession) -> postkeep_mail::Result<T>,
    ) -> MailboxResult<T> {
        self.session_until(None, op).await
    }

    /// Checks admission before setup and after its waits, not in the middle
    /// of an IMAP set (COPY/STORE/EXPUNGE must finish without cancellation).
    async fn session_until<T>(
        &self,
        deadline: Option<Instant>,
        op: impl AsyncFnOnce(&mut ImapSession) -> postkeep_mail::Result<T>,
    ) -> MailboxResult<T> {
        let check = || {
            postkeep_upstream::http::check_deadline(deadline).map_err(|_| MailboxError::Deadline)
        };
        check()?;
        let mut session = if let Some(session) = self
            .pool
            .take_until(&self.account, self.fingerprint, deadline)
            .await
        {
            session
        } else {
            check()?;
            self.noting(self.client.connect_imap().await)
                .await
                .map_err(MailboxError::Connect)?
        };
        if let Err(err) = check() {
            self.pool
                .give_back(&self.account, self.fingerprint, session, true);
            return Err(err);
        }
        let result = op(&mut session).await;
        let usable = result
            .as_ref()
            .map_or_else(postkeep_mail::Error::leaves_session_usable, |_| true);
        self.pool
            .give_back(&self.account, self.fingerprint, session, usable);
        Ok(result?)
    }

    /// Passes on the result of a send after counting it, if this mailbox
    /// counts.
    fn count_send<T>(&self, result: postkeep_mail::Result<T>) -> MailboxResult<T> {
        if let Some((metrics, server)) = &self.counted {
            metrics.smtp_send(server, &result);
        }
        result.map_err(|error| maybe_sent(SendError::Mail(error)))
    }

    /// Passes on the result of a login after counting it, if this mailbox
    /// counts, and writing down what it says about the stored password: a
    /// rejection is recorded; a login that works clears a record and, if
    /// there was one, tells the watchers, so that one which stopped on it
    /// starts again. A write that fails is logged, not the tool's error.
    async fn noting<T>(&self, result: postkeep_mail::Result<T>) -> postkeep_mail::Result<T> {
        if let Some((metrics, server)) = &self.counted {
            metrics.imap_login(server, &result);
        }
        let Some(notes) = &self.passwords else {
            return result;
        };
        let store = &notes.store;
        let done = match &result {
            Err(postkeep_mail::Error::Authentication) => {
                tracing::warn!(account_id = %self.account, "the mail server rejected the stored password");
                store.mark_password_rejected(&self.account).await
            }
            Ok(_) => store
                .clear_password_rejected(&self.account)
                .await
                .map(|cleared| {
                    if let (true, Some(control)) = (cleared, &notes.webhooks) {
                        (control.changed)(&self.account);
                    }
                }),
            Err(_) => Ok(()),
        };
        if let Err(err) = done {
            tracing::warn!(account_id = %self.account, error = %err, "could not update the record of the stored password");
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imap_unconfirmed_draft_has_safe_prose_and_metadata() {
        let err = imap_draft_error(MailError::WriteUnconfirmed.into());
        let result = crate::tools::mailbox_error(err).into_result();
        assert_eq!(result.is_error, Some(true));
        let [prose, meta] = result.content.as_slice() else {
            panic!("expected two blocks");
        };
        assert_eq!(prose.as_text().unwrap().text, DRAFT_UNCONFIRMED);
        let meta: serde_json::Value = serde_json::from_str(&meta.as_text().unwrap().text).unwrap();
        assert_eq!(
            meta,
            serde_json::json!({
                "code": "submission_uncertain", "outcome_uncertain": true, "retryable": false
            })
        );
    }

    #[test]
    fn imap_saved_draft_omits_unusable_or_absent_id() {
        assert_eq!(
            imap_draft_id("Drafts", Some((42, 7))).as_deref(),
            Some("imap.7.RHJhZnRz.42")
        );
        assert_eq!(imap_draft_id("Drafts", None), None);
        assert_eq!(
            imap_draft_id(&"d".repeat(id::MAX_ID_LEN), Some((42, 7))),
            None
        );
    }

    #[test]
    fn imap_outcomes_keep_the_check_and_confirmed_writes_on_error() {
        use postkeep_mail::Error;

        let uids = [1, 2, 3, 4, 5, 6];
        let target = ImapTarget {
            folder: "INBOX".to_owned(),
            uid: 1,
            uid_validity: Some(7),
        };
        for (flight, error, failure, confirmed, carried) in [
            (
                InFlight::Unanswered,
                Error::Timeout,
                "sent, no answer: check before repeating",
                1,
                2,
            ),
            (
                InFlight::Refused,
                Error::Timeout,
                "operation timed out",
                1,
                2,
            ),
            (
                InFlight::Partial,
                Error::Timeout,
                "operation timed out; part of the change may have been made: check before repeating",
                1,
                2,
            ),
            (
                InFlight::Unanswered,
                Error::Unsupported("move"),
                "move",
                0,
                0,
            ),
            (InFlight::Partial, Error::Unsupported("move"), "move", 1, 0),
        ] {
            let error = MailboxError::from(error);
            let code = error.code();
            let mut progress = Progress::default();
            progress.changed.done = vec![1, 4, 5, 6];
            progress.changed.already = vec![2];
            progress.changed.missing = vec![3];
            progress.changed.new_uids.insert(1, 8);
            progress.changed.destination_uid_validity = Some(11);
            progress.confirmed = confirmed;
            progress.carried = carried;
            progress.in_flight = flight;
            let mut outcomes = uids.map(|uid| Outcome::pending(uid.to_string()));
            let reason = error.to_string();
            finish_imap(
                &mut outcomes,
                &target,
                &uids,
                Some("Archive"),
                ("already there", ""),
                Some(progress),
                Err(error),
            );
            let [one, already, missing, four, five, six] = outcomes;
            assert_eq!(
                (already.status, already.reason.as_str()),
                (Status::Ok, "already there")
            );
            assert_eq!(already.error, None);
            assert_eq!(missing.status, Status::NotFound);
            assert_eq!(missing.error, Some((ToolErrorCode::NotFound, None)));
            if confirmed != 0 {
                assert!(one.changed());
                assert_eq!(one.new_id, Some(id::imap_id("Archive", 8, Some(11))));
                assert_eq!((six.status, &six.reason), (Status::NotReached, &reason));
            } else {
                assert_eq!((one.status, &one.reason), (Status::Failed, &reason));
                assert_eq!((six.status, &six.reason), (Status::Failed, &reason));
            }
            for out in [four, five] {
                let expected = if carried != 0 {
                    (Status::Failed, failure)
                } else if confirmed != 0 {
                    (Status::NotReached, reason.as_str())
                } else {
                    (Status::Failed, reason.as_str())
                };
                assert_eq!((out.status, out.reason.as_str()), expected);
                let cause = if carried > 0 && !matches!(flight, InFlight::Refused) {
                    ToolErrorCode::SubmissionUncertain
                } else {
                    code
                };
                assert_eq!(out.error, Some((cause, None)));
            }
        }
    }

    #[test]
    fn timeout_before_imap_progress_classifies_the_entire_set() {
        let uids = [1, 2];
        let target = ImapTarget {
            folder: "INBOX".into(),
            uid: 1,
            uid_validity: Some(7),
        };
        let mut outcomes = uids.map(|uid| Outcome::pending(uid.to_string()));
        finish_imap(
            &mut outcomes,
            &target,
            &uids,
            Some("Archive"),
            ("already there", ""),
            None,
            Err(MailError::Timeout.into()),
        );
        assert!(outcomes.iter().all(|out| out.status == Status::Failed
            && out.reason == "operation timed out"
            && out.error == Some((ToolErrorCode::Timeout, None))));
    }

    #[test]
    fn connection_failure_and_new_outcome_states_carry_the_correct_cause() {
        let mut outcomes = [
            Outcome::pending("first".into()),
            Outcome::pending("second".into()),
        ];
        let result: MailboxResult<()> = Err(MailboxError::Connect(MailError::Authentication));
        assert!(stop_imap_on_connect(&mut outcomes, 0..1, &result));
        assert_eq!(outcomes[0].status, Status::Failed);
        assert_eq!(outcomes[1].status, Status::NotReached);
        for out in &mut outcomes {
            assert_eq!(out.error, Some((ToolErrorCode::AuthRequired, None)));
            out.ok("done");
            assert_eq!(
                (out.status, out.reason.as_str(), out.error),
                (Status::Ok, "done", None)
            );
            out.reset_pending();
            assert_eq!(
                (out.status, out.reason.as_str(), out.error),
                (
                    Status::NotReached,
                    TIME_EXHAUSTED,
                    Some((ToolErrorCode::Timeout, None))
                )
            );
        }
    }

    #[test]
    fn only_unconfirmed_submissions_warn_that_the_message_may_have_been_sent() {
        use axum::http::StatusCode;
        use postkeep_mail::Error;
        use postkeep_upstream::{TokenError, UpstreamProvider};

        let host = "mail.example.com";
        let status = |status| ApiError::Status {
            provider: UpstreamProvider::Microsoft,
            status,
            code: None,
            reason: None,
            retry_after: None,
            message: String::new(),
        };
        for error in [
            HttpError::Timeout(host.to_owned()).into(),
            HttpError::TooLarge(host.to_owned()).into(),
            HttpError::Transport {
                host: host.to_owned(),
                reason: "exchange failed".to_owned(),
            }
            .into(),
            status(StatusCode::BAD_GATEWAY),
        ] {
            assert_eq!(
                maybe_sent(SendError::Api(error, "Microsoft")).to_string(),
                MAY_HAVE_BEEN_SENT
            );
        }
        for error in [
            HttpError::Deadline.into(),
            HttpError::Connect(host.to_owned()).into(),
            HttpError::Request("invalid header".to_owned()).into(),
            TokenError::NotConnected(UpstreamProvider::Microsoft).into(),
            status(StatusCode::PAYLOAD_TOO_LARGE),
            status(StatusCode::TOO_MANY_REQUESTS),
        ] {
            let refusal = graph::submit_error(&error, "Microsoft");
            assert_eq!(
                maybe_sent(SendError::Api(error, "Microsoft")).to_string(),
                refusal.to_string()
            );
        }
        assert_eq!(
            maybe_sent(SendError::Mail(Error::SubmissionUnconfirmed)).to_string(),
            MAY_HAVE_BEEN_SENT
        );
        for error in [Error::Timeout, Error::Authentication] {
            let refusal = error.to_string();
            assert_eq!(maybe_sent(SendError::Mail(error)).to_string(), refusal);
        }
    }

    #[test]
    fn selection_leaves_out_changed_flags_and_stops_on_contradictions() {
        for flagged in [false, true] {
            for state in [false, true] {
                let change = if flagged {
                    Change::Flags {
                        read: None,
                        flagged: Some(state),
                    }
                } else {
                    Change::Flags {
                        read: Some(state),
                        flagged: None,
                    }
                };
                let criteria = Criteria::default().leaving_out(&change).unwrap();
                assert_eq!(
                    if flagged {
                        criteria.flagged
                    } else {
                        criteria.read
                    },
                    Some(!state)
                );
                let mut matching = Criteria::default();
                if flagged {
                    matching.flagged = Some(state);
                } else {
                    matching.read = Some(state);
                }
                assert!(matching.leaving_out(&change).is_none());
                assert_eq!(criteria.leaving_out(&change), Some(criteria));
            }
        }
        for change in [Change::Move("Archive".to_owned()), Change::Trash] {
            let criteria = Criteria {
                read: Some(false),
                flagged: Some(true),
                ..Criteria::default()
            };
            assert_eq!(criteria.leaving_out(&change), Some(criteria));
        }
    }

    #[test]
    fn selection_rule_requires_the_filter_as_given() {
        let rules = SelectionFilterRules::for_provider(Provider::Gmail);
        for (filter, value, allowed) in [
            ("subject", "otter", true),
            ("subject", "Otter", true),
            ("subject", "otter census", false),
            ("subject", "-otter", false),
            ("subject", "+otter", false),
            ("subject", "otter-census", false),
            ("subject", "[otter]", false),
            ("subject", "otters@example.net", false),
            ("text", "me", true),
            ("from", "otters@example.net", true),
            ("from", "-otters@example.net", false),
            ("from", "+otters@example.net", false),
            ("from", "otters@...", false),
            ("from", "me", false),
            ("to", "otters@example.net", false),
        ] {
            let mut criteria = Criteria::default();
            *match filter {
                "subject" => &mut criteria.subject,
                "from" => &mut criteria.from,
                "to" => &mut criteria.to,
                _ => &mut criteria.text,
            } = Some(value.to_owned());
            let result = criteria.exact_for_selection(&rules, "Gmail");
            assert_eq!(result.is_ok(), allowed, "{filter}: {value}");
            if value == "otter census" {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    "Gmail can't match the subject filter exactly as given, so a selection can't use it; use one word of letters and digits (one address in from)"
                );
            }
        }
        for (provider, name) in [
            (Provider::Imap, "IMAP"),
            (Provider::Graph, "Outlook"),
            (Provider::Gmail, "Gmail"),
        ] {
            let rules = SelectionFilterRules::for_provider(provider);
            let caps = MailboxCapabilities::for_account(
                provider,
                None,
                &postkeep_mail::ImapServers::default(),
                ServerFeatures::default(),
            )
            .search;
            let text = Criteria {
                text: Some("otter".to_owned()),
                ..Criteria::default()
            };
            let to = Criteria {
                to: Some("otters@example.net".to_owned()),
                ..Criteria::default()
            };
            assert_eq!(
                text.exact_for_selection(&rules, name).is_ok(),
                caps.selection_supports_text,
                "{name}"
            );
            assert_eq!(
                to.exact_for_selection(&rules, name).is_ok(),
                caps.selection_supports_to,
                "{name}"
            );
            let phrase = Criteria {
                text: Some("otter census".to_owned()),
                ..Criteria::default()
            };
            assert!(phrase.exact_for_selection(&rules, name).is_err(), "{name}");
        }
    }

    #[test]
    fn imap_all_is_kept_for_moves_but_not_for_trash_or_junk() {
        let change = Change::Move("Archive".to_owned());
        assert!(imap_keeps_folder(
            Some(SpecialUse::All),
            Some(SpecialUse::Archive),
            &change
        ));
        assert!(!imap_keeps_folder(None, Some(SpecialUse::Archive), &change));
        assert!(!imap_keeps_folder(
            Some(SpecialUse::All),
            Some(SpecialUse::Trash),
            &change
        ));
        assert!(!imap_keeps_folder(
            Some(SpecialUse::All),
            Some(SpecialUse::Junk),
            &change
        ));
        assert!(!imap_keeps_folder(
            Some(SpecialUse::All),
            Some(SpecialUse::Trash),
            &Change::Trash
        ));
    }

    fn selector(id: Option<&str>, folder: Option<&str>, uid: Option<Uid>) -> Selector {
        Selector {
            id: id.map(str::to_owned),
            folder: folder.map(str::to_owned),
            uid,
        }
    }

    #[test]
    fn imap_runs_preserve_folder_validity_and_input_order() {
        let ids: Vec<_> = [
            ("INBOX", Some(7)),
            ("INBOX", Some(7)),
            ("Archive", Some(7)),
            ("INBOX", Some(7)),
            ("INBOX", Some(8)),
            ("INBOX", None),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, (folder, validity))| {
            selector(
                Some(&id::imap_id(
                    folder,
                    u32::try_from(i + 1).unwrap(),
                    validity,
                )),
                None,
                None,
            )
        })
        .collect();
        let (targets, outcomes) = imap_targets(&ids);
        assert!(outcomes.iter().all(|out| out.status == Status::NotReached));
        let mut start = 0;
        let mut ranges = Vec::new();
        while start < targets.len() {
            let end = imap_run_end(&ids, &targets, start, targets[start].as_ref().unwrap());
            ranges.push(start..end);
            start = end;
        }
        assert_eq!(ranges, vec![0..2, 2..3, 3..4, 4..5, 5..6]);
        let (_, bad) = imap_targets(&[
            selector(Some("garbled"), None, None),
            selector(Some("gmail.123"), None, None),
        ]);
        assert!(bad.iter().all(|out| out.status == Status::Failed));
    }

    #[test]
    fn imap_set_results_keep_missing_new_ids_and_errors_separate() {
        let target = ImapTarget {
            folder: "INBOX".to_owned(),
            uid: 1,
            uid_validity: Some(7),
        };
        let mut outcomes: Vec<_> = (1..=3)
            .map(|uid| Outcome::pending(id::imap_id("INBOX", uid, Some(7))))
            .collect();
        let mut changed = postkeep_mail::Changed::default();
        changed.uid_validity = Some(7);
        changed.done = vec![1, 3];
        changed.missing = vec![2];
        changed.new_uids.insert(1, 9);
        changed.destination_uid_validity = Some(8);
        finish_imap(
            &mut outcomes,
            &target,
            &[1, 2, 3],
            Some("Archive"),
            ("already there", ""),
            None,
            Ok(changed),
        );
        assert_eq!(
            outcomes.iter().map(|out| out.status).collect::<Vec<_>>(),
            vec![Status::Ok, Status::NotFound, Status::Ok]
        );
        assert_eq!(outcomes[0].new_id, Some(id::imap_id("Archive", 9, Some(8))));
        assert_eq!(
            outcomes[1].reason,
            "no such message in INBOX; it may have been moved: search Archive"
        );
        finish_imap(
            &mut outcomes[..1],
            &target,
            &[1],
            None,
            ("", ""),
            None,
            Err(MailboxError::coded(
                ToolErrorCode::ProviderUnavailable,
                "set failed",
            )),
        );
        assert_eq!(outcomes[0].status, Status::Failed);
        assert_eq!(outcomes[2].status, Status::Ok);
    }

    #[test]
    fn resolves_ids_and_legacy_uids() {
        let by_id = selector(Some(&id::imap_id("Archive", 9, Some(77))), None, None);
        assert_eq!(
            by_id.imap(),
            Ok(ImapTarget {
                folder: "Archive".to_owned(),
                uid: 9,
                uid_validity: Some(77),
            })
        );
        let old = selector(Some(&id::imap_id("Archive", 9, None)), None, None);
        assert_eq!(old.imap().map(|target| target.uid_validity), Ok(None));
        // The id wins over a stale folder and uid.
        let both = selector(
            Some(&id::imap_id("INBOX", 3, Some(77))),
            Some("Archive"),
            Some(9),
        );
        assert_eq!(both.imap().map(|target| target.uid), Ok(3));
        let legacy = selector(None, Some(" INBOX "), Some(5));
        assert_eq!(
            legacy.imap(),
            Ok(ImapTarget {
                folder: "INBOX".to_owned(),
                uid: 5,
                uid_validity: None,
            })
        );
    }

    #[test]
    fn rejects_incomplete_or_foreign_selectors() {
        assert!(selector(None, None, None).imap().is_err());
        assert!(selector(None, Some("INBOX"), None).imap().is_err());
        assert!(selector(None, None, Some(5)).imap().is_err());
        assert!(selector(None, Some("INBOX"), Some(0)).imap().is_err());
        assert!(
            selector(Some("AAMkAGI2THVSAAA="), None, None)
                .imap()
                .is_err()
        );
        // A blank id falls back to folder and uid.
        assert!(selector(Some("  "), Some("INBOX"), Some(5)).imap().is_ok());
    }

    #[test]
    fn flag_already_reason_names_requested_states() {
        for (read, flagged, expected) in [
            (None, Some(true), "already flagged"),
            (None, Some(false), "already unflagged"),
            (Some(true), Some(true), "already read and flagged"),
            (Some(true), Some(false), "already read and unflagged"),
            (Some(false), Some(true), "already unread and flagged"),
            (Some(false), Some(false), "already unread and unflagged"),
        ] {
            let change = Change::Flags { read, flagged };
            assert_eq!(change.already_reason(false), expected);
        }
    }
}
