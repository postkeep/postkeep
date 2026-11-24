//! What an embedding's checks see before a tool call runs, and how they
//! refuse it.

use std::future::Future;
use std::pin::Pin;

use postkeep_store::AccountId;
use serde_json::{Map, Value};

use crate::Authenticated;

/// What a check answers: `Ok(())` lets the call run.
pub type CheckFuture<'a> = Pin<Box<dyn Future<Output = Result<(), Refusal>> + Send + 'a>>;

/// A tool call about to run, after the bearer check and the mailbox
/// selector and before the tool does anything.
#[non_exhaustive]
#[derive(Clone, Copy)]
pub struct ToolCall<'a> {
    /// The tool's name.
    pub name: &'a str,
    /// Whether the tool says it only reads (its `readOnlyHint`).
    pub read_only: bool,
    /// The call's arguments, without `mailbox` or the resolver's tenant argument
    /// when selection is on. The hold question gets outgoing attachments as
    /// names, MIME types, sizes and SHA-256 digests; other hooks get those
    /// arguments as sent, including file bytes as base64 or text.
    pub arguments: Option<&'a Map<String, Value>>,
    /// Who is calling.
    pub caller: &'a Authenticated,
    /// The mailbox the call's `mailbox` argument named, one of the
    /// caller's. `None` when it named none, in which case the server's own
    /// tools act on [`Authenticated::account_id`].
    pub mailbox: Option<&'a AccountId>,
}

impl<'a> ToolCall<'a> {
    /// A call to `name` by `caller`, without arguments, that names no
    /// mailbox and may change something.
    #[must_use]
    pub const fn new(name: &'a str, caller: &'a Authenticated) -> Self {
        Self {
            name,
            read_only: false,
            arguments: None,
            caller,
            mailbox: None,
        }
    }

    /// The same call to a tool that does or does not only read.
    #[must_use]
    pub const fn with_read_only(mut self, read_only: bool) -> Self {
        self.read_only = read_only;
        self
    }

    /// The same call with `arguments`.
    #[must_use]
    pub const fn with_arguments(mut self, arguments: Option<&'a Map<String, Value>>) -> Self {
        self.arguments = arguments;
        self
    }

    /// The same call naming `mailbox`.
    #[must_use]
    pub const fn with_mailbox(mut self, mailbox: Option<&'a AccountId>) -> Self {
        self.mailbox = mailbox;
        self
    }
}

/// Leaves out the arguments, which can hold a message body.
impl std::fmt::Debug for ToolCall<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolCall")
            .field("name", &self.name)
            .field("read_only", &self.read_only)
            .field("caller", self.caller)
            .field("mailbox", &self.mailbox)
            .finish_non_exhaustive()
    }
}

/// Why a check refused a call. The caller gets the message as the call's
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    message: String,
}

impl Refusal {
    /// A refusal that tells the caller `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// What the caller is told.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}
