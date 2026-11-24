//! The [`UsageHook`]: limits an embedding puts on how its tenants use the
//! server, such as how many mailboxes a plan includes, how many messages a
//! mailbox may send, or how long its new-mail events may be kept.

use std::future::Future;
use std::pin::Pin;

use postkeep_store::{AccountId, Provider, Store, StoreError};
use postkeep_webhook::filter::MAX_RULES;

use crate::Authenticated;
use crate::check::{CheckFuture, Refusal, ToolCall};
use crate::state::AuthState;

/// A sign-in about to add a mailbox to a tenant that has no account with
/// its address.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct NewMailbox<'a> {
    /// The tenant the mailbox would be added to.
    pub tenant: &'a str,
    /// The mailbox's address, in lower case.
    pub email: &'a str,
    /// How the server would reach the mailbox.
    pub provider: Provider,
}

/// A message that `send_message` or `reply_to_message` is about to send.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Sending<'a> {
    /// Who is sending.
    pub caller: &'a Authenticated,
    /// The mailbox the message goes out from, one of the caller's.
    pub mailbox: &'a AccountId,
    /// The tool sending the message. A reply's recipients come from `to`,
    /// which [`UsageHook::before_call`] sees, or from the original, which
    /// the provider has not read yet.
    pub tool: &'a str,
}

impl<'a> Sending<'a> {
    /// A message that `caller` sends from `mailbox` through `tool`.
    #[must_use]
    pub const fn new(caller: &'a Authenticated, mailbox: &'a AccountId, tool: &'a str) -> Self {
        Self {
            caller,
            mailbox,
            tool,
        }
    }
}

/// A mailbox's outbox of new-mail events, whose limits are being shown or
/// set.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Outbox<'a> {
    /// The tenant the mailbox belongs to.
    pub tenant: &'a str,
    /// The mailbox.
    pub mailbox: &'a AccountId,
}

impl<'a> Outbox<'a> {
    /// The outbox of `mailbox`, in `tenant`.
    #[must_use]
    pub const fn new(tenant: &'a str, mailbox: &'a AccountId) -> Self {
        Self { tenant, mailbox }
    }
}

/// The most a mailbox may keep in its outbox, and how many of its webhook
/// filter rules count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OutboxCeilings {
    /// Longest retention the mailbox may set, in seconds.
    pub max_retention_secs: i64,
    /// Most events the mailbox may keep.
    pub max_events_limit: i64,
    /// How many of the mailbox's filter rules count, oldest first, in place
    /// of the server's setting; `None` keeps the setting. See
    /// [`with_max_filter_rules`](Self::with_max_filter_rules).
    pub max_filter_rules: Option<usize>,
}

impl OutboxCeilings {
    /// At most `max_retention_secs` seconds and `max_events_limit` events.
    #[must_use]
    pub const fn new(max_retention_secs: i64, max_events_limit: i64) -> Self {
        Self {
            max_retention_secs,
            max_events_limit,
            max_filter_rules: None,
        }
    }

    /// The same ceilings, with `max_filter_rules` of the mailbox's filter
    /// rules counting, oldest first, in place of the server's setting. The
    /// newer rules judge nothing and no rule can be added past it. The
    /// server never counts more than 2,000.
    ///
    /// The MCP tools and the account page use the number on each request.
    /// The watchers ask once per batch of new mail and judge that batch with
    /// the answer, so a lower number than the mailbox's real one makes its
    /// newer rules judge nothing for that batch, and mail that only a newer
    /// allow rule matches is dropped for good. When the number can't be
    /// worked out, for example because the mailbox's plan can't be read,
    /// answer `None`, or ceilings without this number, which keeps the
    /// server's setting: never a fallback number.
    #[must_use]
    pub const fn with_max_filter_rules(mut self, max_filter_rules: usize) -> Self {
        self.max_filter_rules = Some(max_filter_rules);
        self
    }
}

/// How a tool call ended, as [`UsageHook::after_call`] hears it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// The tool answered with a result.
    Done,
    /// [`UsageHook::before_send`] refused the message the call was to send,
    /// and the caller got that refusal as the tool's error.
    Refused,
    /// The tool answered with an error, the call failed with a protocol
    /// error, or it stopped before it answered.
    Failed,
}

/// The end of a tool call that the checks allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct CallEnd {
    /// How it ended.
    pub outcome: Outcome,
    /// For a search that answered, how many messages matched: its `total`,
    /// which can be the provider's estimate. `None` for other calls.
    pub found: Option<usize>,
    /// The call held a message without sending it.
    pub held: bool,
}

impl CallEnd {
    /// A call that ended with `outcome`.
    #[must_use]
    pub const fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            found: None,
            held: false,
        }
    }

    /// The same end, marked as having held a message without sending it.
    #[must_use]
    pub const fn with_held(mut self) -> Self {
        self.held = true;
        self
    }

    /// The same end of a search that matched `found` messages.
    #[must_use]
    pub const fn with_found(mut self, found: usize) -> Self {
        self.found = Some(found);
        self
    }
}

/// How many filter rules count for a mailbox unless the operator or the usage
/// hook says otherwise.
pub const DEFAULT_MAX_FILTER_RULES: usize = 1_000;

/// How many of a mailbox's filter rules count: the usage hook's `answer` for
/// it, else the server's `setting`, and never more than [`MAX_RULES`].
#[must_use]
pub fn filter_rule_limit(answer: Option<OutboxCeilings>, setting: usize) -> usize {
    let limit = answer.and_then(|ceilings| ceilings.max_filter_rules);
    limit.unwrap_or(setting).min(MAX_RULES)
}

/// What [`UsageHook::outbox_ceilings`] answers.
pub type CeilingsFuture<'a> = Pin<Box<dyn Future<Output = Option<OutboxCeilings>> + Send + 'a>>;

/// What [`UsageHook::holds`] answers.
pub type HoldFuture<'a> = Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

/// Limits an embedding puts on use. [`AuthState::set_usage_hook`] installs
/// it for sign-ins and the account page; the `postkeep` server's
/// `Extensions::usage_hook` installs it there and for the MCP tools.
///
/// Every method has a default that allows everything or does nothing, so
/// a server without a hook has no limits.
pub trait UsageHook: Send + Sync + 'static {
    /// Runs before a sign-in stores a mailbox that its tenant doesn't have:
    /// an app password sign-in at `/authorize` or on the account page, or a
    /// Microsoft or Google sign-in, including one an embedding started for
    /// one of its tenants. It runs once the password or the provider's
    /// answer has been checked. Signing in again to a mailbox the tenant
    /// has doesn't run it.
    ///
    /// A [`Refusal`] stops the sign-in before anything is stored, and the
    /// person sees its message. The check and the insert are not atomic:
    /// two sign-ins at the same moment can both pass. The default allows
    /// every mailbox.
    fn before_connect<'a>(&'a self, mailbox: NewMailbox<'a>) -> CheckFuture<'a> {
        let _ = mailbox;
        Box::pin(std::future::ready(Ok(())))
    }

    /// Runs before every tool call on the MCP endpoint, the server's tools
    /// and an embedding's own, after the embedding's tool extension checked
    /// it. An unknown tenant or mailbox or an ambiguous address stops the
    /// call first. A [`Refusal`] becomes the call's error and the tool doesn't
    /// run. The default allows every call.
    fn before_call<'a>(&'a self, call: ToolCall<'a>) -> CheckFuture<'a> {
        let _ = call;
        Box::pin(std::future::ready(Ok(())))
    }

    /// Whether to hold this call for the user's yes rather than act at once.
    /// Only tools that can hold a call ask: `send_message` and
    /// `reply_to_message`, after checking their addresses and without a
    /// `hold_id`. A confirming call takes its hold before `before_send`;
    /// a holding call never asks `before_send` and ends with [`CallEnd::held`].
    /// Arguments are parsed parameters, including defaults, without `hold_id`.
    /// The default is no.
    ///
    /// A hold instructs the agent to show the exact message and ask, not
    /// proof of the user's yes: an agent can make both calls. Keep the
    /// app's own confirmation prompt on.
    fn holds<'a>(&'a self, call: ToolCall<'a>) -> HoldFuture<'a> {
        let _ = call;
        Box::pin(std::future::ready(false))
    }

    /// Runs once for each tool call that the tool extension's check and
    /// [`before_call`](Self::before_call) allowed, the server's tools and an
    /// embedding's own: after the tool ends and before its answer goes. It
    /// never runs for a call refused by a check or the mailbox selector.
    ///
    /// `end` says [`Outcome::Done`]; [`Outcome::Refused`] when
    /// [`before_send`](Self::before_send) refused the call's message, a
    /// refusal this hook has already seen; or [`Outcome::Failed`] for a
    /// tool error or a protocol error. A search that answered gives how
    /// many messages it matched ([`CallEnd::found`]). The server learns of
    /// a refused message and of the count through its request log, which
    /// its router and `ServerBuilder` install. A call that held a message
    /// ends `Done` with [`CallEnd::held`], also through that log. Without
    /// it, a refused message ends `Failed`, a search gives no count and
    /// a held call has no held mark.
    ///
    /// A call that stops before it answers, such as one whose tool panics
    /// or that the server drops as it shuts down, also ends `Failed`, and
    /// its tool may have done some or all of its work. A call whose request
    /// timed out, or whose client went away, keeps running to its end, and
    /// this hears that end, after the client got its answer.
    ///
    /// It runs on the call's task, so it is synchronous and must not block:
    /// a hook that writes somewhere spawns the write. The default does
    /// nothing.
    fn after_call(&self, call: ToolCall<'_>, end: CallEnd) {
        let _ = (call, end);
    }

    /// Runs before `send_message` or `reply_to_message` sends a message,
    /// after [`before_call`](Self::before_call) allowed the call and before
    /// the mailbox is opened. A new message without recipients, or with
    /// one that doesn't parse, fails before this runs, and so does a reply
    /// whose `to` names one that doesn't parse. A [`Refusal`] becomes the
    /// tool's error and nothing is sent. The provider can still fail to
    /// send a message this allowed, and a reply whose call names no `to`
    /// is refused after this when the original's sender does not read as
    /// one address, or its `Reply-To` (or, for the mailbox's own message,
    /// its `To`) does not read as addresses, each alone or after a name, as
    /// is one with `reply_all` when its `To` or `Cc` does not. The default
    /// allows every message.
    fn before_send<'a>(&'a self, sending: Sending<'a>) -> CheckFuture<'a> {
        let _ = sending;
        Box::pin(std::future::ready(Ok(())))
    }

    /// The ceilings of a mailbox's outbox: the longest retention and the
    /// most events `set_webhook_outbox_limits` accepts for it, which
    /// `get_webhook_status` and the account page report. The server's own
    /// ceilings still apply, and a ceiling below the server's default
    /// counts as that default.
    ///
    /// Lower ceilings don't change limits a mailbox already set, and
    /// pruning keeps using those. An embedding that lowers a mailbox's
    /// ceilings, for example when its plan changes, resets the limits it
    /// set with [`Store::set_webhook_outbox_limits`]. `None`, the default,
    /// keeps the server's ceilings.
    ///
    /// The ceilings can also say how many of the mailbox's webhook filter
    /// rules count ([`OutboxCeilings::with_max_filter_rules`]). The tools and
    /// the account page ask once per request, and the watchers once per
    /// batch of new mail, which they judge with the answer. When the hook
    /// can't work out a mailbox's numbers, it answers `None`, or ceilings
    /// without a filter number, never a fallback number: `None` and a
    /// missing number keep the server's setting.
    fn outbox_ceilings<'a>(&'a self, outbox: Outbox<'a>) -> CeilingsFuture<'a> {
        let _ = outbox;
        Box::pin(std::future::ready(None))
    }
}

/// The usage hook's refusal of a sign-in that would store the mailbox
/// `email` in `store`'s tenant. `None` without a hook, when the tenant
/// already has an account with that address or, for a Microsoft or Google
/// mailbox, with the provider's `subject`, or when the hook allows it.
pub async fn refusal(
    state: &AuthState,
    store: &Store,
    email: &str,
    provider: Provider,
    subject: Option<&str>,
) -> Result<Option<Refusal>, StoreError> {
    let Some(hook) = state.usage_hook() else {
        return Ok(None);
    };
    let email = email.trim().to_lowercase();
    if store.find_account(&email).await?.is_some() {
        return Ok(None);
    }
    if let Some(subject) = subject
        && store.account_by_subject(provider, subject).await?.is_some()
    {
        return Ok(None);
    }
    let mailbox = NewMailbox {
        tenant: store.tenant(),
        email: &email,
        provider,
    };
    let refusal = hook.before_connect(mailbox).await.err();
    if refusal.is_some() {
        tracing::info!(
            provider = provider.as_str(),
            "the usage hook refused a new mailbox"
        );
    }
    Ok(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hook_s_number_replaces_the_setting_up_to_the_most_rules() {
        let ceilings = OutboxCeilings::new(60, 10);
        assert_eq!(filter_rule_limit(None, 7), 7);
        assert_eq!(
            filter_rule_limit(Some(ceilings), 7),
            7,
            "no number keeps the setting"
        );
        assert_eq!(
            filter_rule_limit(Some(ceilings.with_max_filter_rules(2)), 7),
            2
        );
        let many = ceilings.with_max_filter_rules(5_000);
        assert_eq!(filter_rule_limit(Some(many), 7), 2_000);
        assert_eq!(filter_rule_limit(None, 5_000), 2_000);
    }
}
