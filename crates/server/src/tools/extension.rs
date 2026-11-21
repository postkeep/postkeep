//! An embedding's own tools and checks on the MCP endpoint.

use std::future::Future;
use std::pin::Pin;

use postkeep_auth::{Authenticated, CheckFuture, ToolCall, UnreadableRules};
use postkeep_store::AccountId;
use rmcp::ErrorData;
use rmcp::model::{CallToolResult, Implementation, JsonObject, Tool};

/// What one of a [`ToolExtension`]'s tools answers: its result, which can
/// be a tool error, or a protocol error such as invalid arguments.
pub type ToolFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CallToolResult, ErrorData>> + Send + 'a>>;

/// Tools, instructions and checks an embedding adds to the MCP endpoint,
/// installed with
/// [`Extensions::tool_extension`](crate::app::Extensions::tool_extension).
///
/// Every method has a default that adds nothing, so an extension can add
/// tools without checks or checks without tools. Tools are described with
/// the `rmcp` types of the version this crate uses.
pub trait ToolExtension: Send + Sync + 'static {
    /// The tools `caller` may use besides the server's own, listed after
    /// them in this order. A tool named like one of the server's is left
    /// out. When the mailbox selector is on, a tool whose input schema has
    /// no `mailbox` property gets the optional one the server's tools have,
    /// and the server checks the name before [`call`](Self::call). The
    /// default lists none.
    fn tools(&self, caller: &Authenticated) -> Vec<Tool> {
        let _ = caller;
        Vec::new()
    }

    /// Runs a tool that [`tools`](Self::tools) listed for the caller, once
    /// [`check`](Self::check) allowed the call. The default answers that
    /// the tool does not exist.
    fn call<'a>(&'a self, call: ExtensionCall<'a>) -> ToolFuture<'a> {
        let _ = call;
        Box::pin(std::future::ready(Err(ErrorData::invalid_params(
            "tool not found",
            None,
        ))))
    }

    /// A paragraph added to the end of the server's instructions. The
    /// default adds none.
    fn instructions(&self) -> Option<String> {
        None
    }

    /// The `serverInfo` sent in the answer to `initialize`, given the server's own.
    /// An extension sets its website and icons and keeps the name, version and
    /// title. The default changes nothing.
    fn server_info(&self, info: Implementation) -> Implementation {
        info
    }

    /// Runs before every tool call, the server's tools and the extension's,
    /// once the `mailbox` argument names one of the caller's mailboxes. A
    /// call naming any other mailbox fails before this runs. A
    /// [`Refusal`](postkeep_auth::Refusal) becomes the call's error and
    /// the tool does not run. The default allows every call.
    fn check<'a>(&'a self, call: ToolCall<'a>) -> CheckFuture<'a> {
        let _ = call;
        Box::pin(std::future::ready(Ok(())))
    }

    /// The `message` of the webhook tools when the mail server rejected the
    /// mailbox's stored password (`state` `needs_password`): what the agent
    /// tells the person to do. The default, `None`, keeps the server's
    /// sentence, which names the account page; an embedding that turns that
    /// page off says where else to go.
    fn password_rejected(&self, rejected: RejectedPassword<'_>) -> Option<String> {
        let _ = rejected;
        None
    }

    /// What a webhook tool tells the agent to do about `problem`: the tool's
    /// error, or the `message` of `get_webhook_status` and
    /// `set_webhook_enabled`. The default, `None`, keeps the server's
    /// sentence, which names the account page and, for rules that can't be
    /// decrypted, the operator's previous master key; an embedding that turns
    /// that page off, or whose callers don't run the server, says what they
    /// can do instead.
    fn webhook_problem(&self, problem: WebhookProblem<'_>) -> Option<String> {
        let _ = problem;
        None
    }
}

/// A mailbox whose stored password the mail server rejected, when a tool is
/// about to say so.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RejectedPassword<'a> {
    /// Who is asking.
    pub caller: &'a Authenticated,
    /// The mailbox, one of the caller's.
    pub mailbox: &'a AccountId,
}

/// A problem with a mailbox's webhook or its filter rules, when a tool is
/// about to say what fixes it.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct WebhookProblem<'a> {
    /// Who is asking.
    pub caller: &'a Authenticated,
    /// The mailbox, one of the caller's.
    pub mailbox: &'a AccountId,
    /// What is wrong.
    pub kind: &'a WebhookProblemKind,
}

/// What is wrong with a mailbox's webhook or its filter rules.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebhookProblemKind {
    /// No webhook is saved, and the tool needs one.
    NoWebhook,
    /// The saved settings can't be decrypted: the `unreadable` state, or,
    /// with `turning_on`, `set_webhook_enabled` refusing to turn them on.
    Unreadable {
        /// Whether the caller asked to turn the webhook on.
        turning_on: bool,
    },
    /// `set_webhook_enabled` refused to turn on a webhook whose saved URL is
    /// empty or not one it delivers to.
    NoEndpoint,
    /// The filter rules can't be decrypted, so new mail waits.
    RulesUndecryptable,
    /// The filter rules that judge mail can't, so new mail waits.
    Rules(UnreadableRules),
}

/// A call to one of a [`ToolExtension`]'s tools.
#[non_exhaustive]
pub struct ExtensionCall<'a> {
    /// The tool's name.
    pub name: &'a str,
    /// The call's arguments, without `mailbox` when the mailbox selector
    /// is on.
    pub arguments: Option<JsonObject>,
    /// Who is calling.
    pub caller: &'a Authenticated,
    /// The mailbox the `mailbox` argument named, one of the caller's.
    /// `None` when it named none or the mailbox selector is off.
    pub mailbox: Option<&'a AccountId>,
}

/// Leaves out the arguments, which belong to the embedding.
impl std::fmt::Debug for ExtensionCall<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionCall")
            .field("name", &self.name)
            .field("caller", self.caller)
            .field("mailbox", &self.mailbox)
            .finish_non_exhaustive()
    }
}
