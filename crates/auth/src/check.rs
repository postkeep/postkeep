//! What an embedding's checks see before a tool call runs, and how they
//! refuse it.

use std::future::Future;
use std::pin::Pin;

use postkeep_store::AccountId;
use postkeep_upstream::http::MAX_RETRY_AFTER_SECS;
use serde::Serialize;
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

/// Machine-readable classification of an MCP tool error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolErrorCode {
    /// The arguments were invalid or the operation was definitively refused.
    InvalidInput,
    /// The requested item does not exist or is not visible to the caller.
    NotFound,
    /// The message ID is stale; search for a current one.
    StaleId,
    /// Sign in or reconnect the mailbox before trying again.
    AuthRequired,
    /// The operation requires an unavailable feature or capability.
    Unsupported,
    /// The caller or mailbox does not have permission for the operation.
    PermissionDenied,
    /// Server policy has paused the mailbox.
    MailboxPaused,
    /// A message or attachment exceeds an allowed size.
    PayloadTooLarge,
    /// The confirmed arguments differ from those of the held send.
    HoldMismatch,
    /// The hold is missing, expired, or already used.
    HoldExpired,
    /// A provider or server rate or quota limit was reached.
    RateLimited,
    /// A provider or supporting service did not complete the request.
    ProviderUnavailable,
    /// The operation ran out of time before a change could take effect.
    Timeout,
    /// A local concurrency or queue limit was reached.
    Busy,
    /// A change may have taken effect; inspect its outcome before retrying.
    SubmissionUncertain,
}

impl ToolErrorCode {
    /// Whether the operation may be retried, with fresh one-shot inputs if needed.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited | Self::ProviderUnavailable | Self::Timeout | Self::Busy
        )
    }

    /// Whether the operation may have changed state without confirmation.
    #[must_use]
    pub const fn outcome_uncertain(self) -> bool {
        matches!(self, Self::SubmissionUncertain)
    }
}

/// Why a check refused a call. The caller gets the message as the call's
/// error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    message: String,
    code: Option<ToolErrorCode>,
    retry_after_seconds: Option<u64>,
}

impl Refusal {
    /// A refusal that tells the caller `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            code: None,
            retry_after_seconds: None,
        }
    }

    /// Sets the machine-readable code, clearing any earlier delay if not retryable.
    #[must_use]
    pub const fn with_code(mut self, code: ToolErrorCode) -> Self {
        self.code = Some(code);
        if !code.retryable() {
            self.retry_after_seconds = None;
        }
        self
    }

    /// Sets a retry delay in seconds, clamped to 24 hours.
    /// A non-retryable code discards the delay; an uncoded refusal can keep
    /// it until a retryable code is set.
    #[must_use]
    pub fn with_retry_after(mut self, secs: u64) -> Self {
        if self.code.is_none_or(ToolErrorCode::retryable) {
            self.retry_after_seconds = Some(secs.min(MAX_RETRY_AFTER_SECS));
        }
        self
    }

    /// The machine-readable code, if supplied by the check.
    #[must_use]
    pub const fn code(&self) -> Option<ToolErrorCode> {
        self.code
    }

    /// The suggested delay in seconds, if supplied with a retryable code.
    #[must_use]
    pub fn retry_after_seconds(&self) -> Option<u64> {
        self.retry_after_seconds
            .filter(|_| self.code.is_some_and(ToolErrorCode::retryable))
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

#[cfg(test)]
mod tests {
    use super::{Refusal, ToolErrorCode};
    use ToolErrorCode::*;

    #[test]
    fn tool_error_codes_serialize_with_fixed_retry_invariants() {
        for (code, wire, retryable, uncertain) in [
            (InvalidInput, "invalid_input", false, false),
            (NotFound, "not_found", false, false),
            (StaleId, "stale_id", false, false),
            (AuthRequired, "auth_required", false, false),
            (Unsupported, "unsupported", false, false),
            (PermissionDenied, "permission_denied", false, false),
            (MailboxPaused, "mailbox_paused", false, false),
            (PayloadTooLarge, "payload_too_large", false, false),
            (HoldMismatch, "hold_mismatch", false, false),
            (HoldExpired, "hold_expired", false, false),
            (RateLimited, "rate_limited", true, false),
            (ProviderUnavailable, "provider_unavailable", true, false),
            (Timeout, "timeout", true, false),
            (Busy, "busy", true, false),
            (SubmissionUncertain, "submission_uncertain", false, true),
        ] {
            assert_eq!(serde_json::to_value(code).ok(), Some(wire.into()));
            assert_eq!(
                (code.retryable(), code.outcome_uncertain()),
                (retryable, uncertain)
            );
        }
    }

    #[test]
    fn refusal_only_exposes_delays_for_retryable_codes() {
        let refusal = Refusal::new("not now");
        let delayed = refusal.clone().with_retry_after(u64::MAX);
        assert_eq!(
            (delayed.code(), delayed.retry_after_seconds()),
            (None, None)
        );
        assert_ne!(refusal, delayed);
        let limited = delayed.with_code(RateLimited);
        assert_eq!(limited.retry_after_seconds(), Some(86_400));
        assert_eq!(
            limited,
            refusal
                .clone()
                .with_code(RateLimited)
                .with_retry_after(u64::MAX)
        );
        let denied = limited.with_code(PermissionDenied);
        assert_eq!(
            denied,
            refusal
                .clone()
                .with_retry_after(60)
                .with_code(PermissionDenied)
        );
        let denied_first = refusal.with_code(PermissionDenied).with_retry_after(60);
        assert_eq!(denied, denied_first);
        assert_eq!(denied_first.with_code(Busy).retry_after_seconds(), None);
    }
}
