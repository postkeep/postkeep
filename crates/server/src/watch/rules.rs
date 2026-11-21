//! The filter rules of each mailbox, compiled once, off the async runtime, and kept
//! while its mail is judged. A compiled set can grow a search cache of up to 2 MiB,
//! so rules unused for [`IDLE`] are dropped whenever any mailbox's rules are looked up.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use postkeep_auth::{Outbox, filter_rule_limit, parse_filter_rules};
use postkeep_mail::{EmailAddress, NewMessage, invisible};
use postkeep_store::{AccountId, StoreError, Webhook};
use postkeep_webhook::filter::{CompiledRules, MessageForms};
use tokio::time::Instant;

use super::{WatchError, Watchers};

/// How long compiled rules are kept after the last batch they judged.
const IDLE: Duration = Duration::from_mins(10);

/// The most addresses block rules pick out of a sender: as many as the recipients they judge.
/// A sender with more matches every block rule on the sender.
const MAX_PICKED: usize = 100;

/// What kept rules were for: the webhook's creation time, its count of rule
/// changes (0 again for a webhook deleted and saved again) and the limit.
type Stamp = (i64, i64, usize);

/// The kept rules of the mailboxes in use, and when each was last used.
#[derive(Default)]
pub(super) struct RuleCache(Mutex<HashMap<AccountId, (Stamp, Rules, Instant)>>);

impl RuleCache {
    fn kept(&self) -> MutexGuard<'_, HashMap<AccountId, (Stamp, Rules, Instant)>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The rules kept for `account` if they are for `stamp`, which counts as
    /// using them. The rules of any mailbox that judged nothing for [`IDLE`]
    /// are dropped first.
    fn find(&self, account: &AccountId, stamp: Stamp) -> Option<Rules> {
        let now = Instant::now();
        let mut kept = self.kept();
        kept.retain(|_, (.., used)| now - *used < IDLE);
        kept.get_mut(account)
            .filter(|(s, ..)| *s == stamp)
            .map(|(_, rules, used)| {
                *used = now;
                rules.clone()
            })
    }
}

/// What a mailbox's rules make of its new mail.
#[derive(Clone)]
pub(super) enum Rules {
    /// No rule is active: every message passes.
    Off,
    /// A message must pass these.
    On(Arc<CompiledRules>),
}

/// What the rules look at in one message, as text that does not borrow the
/// message, so that it can be judged off the async runtime. What a provider does
/// not give is empty. It has no `Debug`, so addresses and subjects stay out of logs.
#[derive(Default)]
pub(super) struct Fields {
    /// The sender's bare address, such as `alice@example.com`.
    pub(super) from: String,
    /// Whether a mail app shows `from` as the sender's address. When it may show another, allow
    /// rules judge the message as one without a sender address, and block rules also judge the
    /// addresses in each of `from_values`: a sender with more than [`MAX_PICKED`] matches every
    /// block rule on the sender.
    pub(super) from_clear: bool,
    /// The value of each `From` header as sent, in their order.
    pub(super) from_values: Vec<String>,
    /// The bare addresses in `To` and `Cc`.
    pub(super) to: Vec<String>,
    /// The decoded subject.
    pub(super) subject: String,
}

/// A new message of any provider, which the rules can judge.
pub(super) trait Judged: Send + 'static {
    /// What the rules look at in this message.
    fn fields(&self) -> Fields;
}

impl Judged for NewMessage {
    fn fields(&self) -> Fields {
        let address = |a: &EmailAddress| a.address.clone();
        Fields {
            from: self.from.as_ref().map(address).unwrap_or_default(),
            from_clear: self.from_clear,
            from_values: self.from_values.clone(),
            to: self.recipients.iter().map(address).collect(),
            subject: self.subject.clone().unwrap_or_default(),
        }
    }
}

impl Rules {
    /// The messages that pass, in the order given.
    pub(super) async fn keep<T: Judged>(&self, messages: Vec<T>) -> Vec<T> {
        let Self::On(rules) = self else {
            return messages;
        };
        let rules = Arc::clone(rules);
        let judge = move || {
            let passing = |message: &T| passes(&rules, &message.fields());
            messages.into_iter().filter(passing).collect()
        };
        blocking(judge).await
    }
}

/// Whether `rules` let a message with these `fields` wake the agent.
///
/// Allow rules match the fields as received, and as `get_message` shows them:
/// each address through [`invisible::email_address`], without a name, and the
/// subject through [`invisible::visible`]. Block rules match the fields as
/// received, and stripped: each address through [`address_without_hidden`],
/// the subject through [`without_hidden`]. Allow rules match the subject
/// stripped too, but not an address: an address with a character left out
/// is another address. Block rules are not given the shown text: its `\u{…}`
/// escapes are text the message does not hold. Allow rules take a sender address
/// that is not clear as an empty one, as for a message without a sender. Block
/// rules also judge the [`picked_addresses`] of the [`sender_texts`], any of which
/// a mail app may show as the sender. A sender with more than [`MAX_PICKED`] of
/// them matches every block rule on `from` and `from_domain`.
fn passes(rules: &CompiledRules, fields: &Fields) -> bool {
    let shown = form(
        fields,
        |address| invisible::email_address(None, address),
        invisible::visible,
    );
    let stripped = form(fields, address_without_hidden, without_hidden);
    let to: Vec<_> = fields.to.iter().map(String::as_str).collect();
    let shown_to: Vec<_> = shown.to.iter().map(String::as_str).collect();
    let stripped_to: Vec<_> = stripped.to.iter().map(String::as_str).collect();
    let from = [fields.from.as_str(), shown.from.as_str()];
    let allow = MessageForms {
        from: if fields.from_clear { &from } else { &[""] },
        to: &[to.as_slice(), shown_to.as_slice()],
        subject: &[
            fields.subject.as_str(),
            shown.subject.as_str(),
            stripped.subject.as_str(),
        ],
    };
    let texts = sender_texts(fields);
    let picked: Vec<_> = texts
        .iter()
        .flat_map(|text| picked_addresses(text))
        .take(MAX_PICKED + 1)
        .collect();
    if picked.len() > MAX_PICKED && rules.blocks_by_sender() {
        return false;
    }
    let block_from: Vec<_> = [fields.from.as_str(), stripped.from.as_str()]
        .into_iter()
        .chain(picked.iter().map(String::as_str))
        .collect();
    let block = MessageForms {
        from: &block_from,
        to: &[to.as_slice(), stripped_to.as_slice()],
        subject: &[fields.subject.as_str(), stripped.subject.as_str()],
    };
    rules.passes_forms(&allow, &block)
}

/// `fields` with each address written by `address` and the subject by
/// `subject`.
fn form(fields: &Fields, address: fn(&str) -> String, subject: fn(&str) -> String) -> Fields {
    Fields {
        from: address(&fields.from),
        from_clear: fields.from_clear,
        from_values: Vec::new(),
        to: fields.to.iter().map(String::as_str).map(address).collect(),
        subject: subject(&fields.subject),
    }
}

/// The texts block rules pick sender addresses out of: `from` and, when it is not clear, each
/// `From` value, as received and, where that differs, through [`address_without_hidden`]; and
/// each of these, where that differs, through [`unquoted_without_comments`].
fn sender_texts(fields: &Fields) -> Vec<String> {
    let values: &[String] = if fields.from_clear {
        &[]
    } else {
        &fields.from_values
    };
    let mut texts = Vec::new();
    for text in std::iter::once(&fields.from).chain(values) {
        let stripped = address_without_hidden(text);
        texts.push(text.clone());
        if stripped != *text {
            texts.push(stripped);
        }
    }
    let read: Vec<_> = texts
        .iter()
        .filter_map(|text| {
            let read = unquoted_without_comments(text);
            (read != *text).then_some(read)
        })
        .collect();
    texts.extend(read);
    texts
}

/// `text` as a mail app may read the addresses in it: without its comments, the text in
/// parentheses outside quoted strings, nested comments and escaped characters included, and
/// with each quoted string unquoted.
fn unquoted_without_comments(text: &str) -> String {
    let mut read = String::with_capacity(text.len());
    let (mut depth, mut quoted, mut escaped) = (0_usize, false, false);
    for c in text.chars() {
        if escaped {
            escaped = false;
            if depth == 0 {
                read.push(c);
            }
        } else if c == '\\' && (quoted || depth > 0) {
            escaped = true;
        } else if c == '"' && depth == 0 {
            quoted = !quoted;
        } else if c == '(' && !quoted {
            depth += 1;
        } else if c == ')' && depth > 0 {
            depth -= 1;
        } else if depth == 0 {
            read.push(c);
        }
    }
    read
}

/// The addresses a mail app may pick out of `text`: each `@` with the characters an address
/// may hold before it and the domain after it, without the dots that end it, as `a@x.test`
/// out of `<a@x.test.>b@y.test`. Spaces and line breaks next to the `@` are left out, as
/// mail apps read `a @ x.test` as `a@x.test`.
fn picked_addresses(text: &str) -> impl Iterator<Item = String> + '_ {
    const SPACE: [char; 4] = [' ', '\t', '\r', '\n'];
    let local = |c: char| c.is_alphanumeric() || ".!#$%&'*+-/=?^_`{|}~".contains(c);
    let domain = |c: char| c.is_alphanumeric() || "-_.".contains(c);
    text.match_indices('@').filter_map(move |(at, _)| {
        let before = text.get(..at)?.trim_end_matches(SPACE);
        let after = text.get(at + 1..)?.trim_start_matches(SPACE);
        let user = before.get(before.trim_end_matches(local).len()..)?;
        let host = after.get(..after.len() - after.trim_start_matches(domain).len())?;
        Some(format!("{user}@{}", host.trim_end_matches('.')))
    })
}

/// `text` without the characters of [`invisible::hidden`] and the control
/// characters, whitespace aside, so that a word holding one of them reads
/// as the word.
fn without_hidden(text: &str) -> String {
    text.chars()
        .filter(|&c| c.is_whitespace() || !(invisible::hidden(c) || c.is_control()))
        .collect()
}

/// `address` without the characters of [`invisible::hidden`] and the control
/// characters, whitespace among them: an address holds no word break.
fn address_without_hidden(address: &str) -> String {
    address
        .chars()
        .filter(|&c| !(invisible::hidden(c) || c.is_control()))
        .collect()
}

/// Runs `work` where it may take a while, off the async runtime.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> T {
    let done = tokio::task::spawn_blocking(work).await;
    done.unwrap_or_else(|error| std::panic::resume_unwind(error.into_panic()))
}

impl Watchers {
    /// The server's setting of how many filter rules count for a mailbox.
    #[must_use]
    pub fn max_filter_rules(&self) -> usize {
        self.inner.config.max_filter_rules
    }

    /// How many of `account`'s filter rules count ([`filter_rule_limit`]): the
    /// usage hook is asked once, unless there is none or the account is gone.
    pub(super) async fn filter_rule_limit(&self, account: &AccountId) -> Result<usize, WatchError> {
        let setting = self.max_filter_rules();
        let Some(usage) = self.inner.usage.get() else {
            return Ok(filter_rule_limit(None, setting));
        };
        let Some(tenant) = self.inner.store.account_tenant(account).await? else {
            return Ok(filter_rule_limit(None, setting));
        };
        let answer = usage.outbox_ceilings(Outbox::new(&tenant, account)).await;
        Ok(filter_rule_limit(answer, setting))
    }

    /// The rules that judge `account`'s new mail as `hook` has them, at the
    /// mailbox's limit ([`Self::filter_rule_limit`]). `None` when they can't be
    /// read (logged): the caller holds the mail. A failure a later try may get
    /// past is an error.
    pub(super) async fn rules(
        &self,
        account: &AccountId,
        hook: &Webhook,
    ) -> Result<Option<Rules>, WatchError> {
        let limit = self.filter_rule_limit(account).await?;
        self.rules_at(account, hook, limit).await
    }

    /// [`Self::rules`] with the oldest `limit` counting.
    pub(super) async fn rules_at(
        &self,
        account: &AccountId,
        hook: &Webhook,
        limit: usize,
    ) -> Result<Option<Rules>, WatchError> {
        let stamp = (hook.created_at, hook.filter_rules_version, limit);
        if let Some(rules) = self.inner.rules.find(account, stamp) {
            return Ok(Some(rules));
        }
        let unreadable = |why: &str| {
            tracing::warn!(account_id = %account, "the filter rules {why}; its mail waits");
            Ok(None)
        };
        let stored = match self.inner.store.webhook_filter_rules(account, limit).await {
            Ok(stored) => stored,
            Err(StoreError::Decrypt) => return unreadable("can't be decrypted"),
            Err(error) => return Err(error.into()),
        };
        let Some(active) = parse_filter_rules(&stored) else {
            return unreadable("have a name this version does not know");
        };
        let rules = if active.is_empty() {
            Rules::Off
        } else if let Ok(compiled) = blocking(move || CompiledRules::new(&active, limit)).await {
            Rules::On(Arc::new(compiled))
        } else {
            return unreadable("can't be compiled");
        };
        let kept = (stamp, rules.clone(), Instant::now());
        self.inner.rules.kept().insert(account.clone(), kept);
        Ok(Some(rules))
    }
}

#[cfg(test)]
mod tests {
    use postkeep_webhook::filter::Action::{Allow, Block};
    use postkeep_webhook::filter::Field::{From as Sender, FromDomain, Subject, To};
    use postkeep_webhook::filter::Kind::{Contains, Domain, Equals, Regex};
    use postkeep_webhook::filter::{Action, Field, Kind, Rule};

    use super::*;

    /// Whether a lone rule lets a message with `text` in every field wake the agent.
    fn judge(action: Action, field: Field, kind: Kind, pattern: &str, text: &str) -> bool {
        let pattern = pattern.to_owned();
        let rule = Rule {
            action,
            field,
            kind,
            pattern,
        };
        let fields = Fields {
            from: text.to_owned(),
            from_clear: true,
            from_values: Vec::new(),
            to: vec![text.to_owned()],
            subject: text.to_owned(),
        };
        passes(&CompiledRules::new(&[rule], 1).unwrap(), &fields)
    }

    #[tokio::test(start_paused = true)]
    async fn rules_unused_for_ten_minutes_are_dropped() {
        let cache = RuleCache::default();
        let [a, b] = ["a", "b"].map(|id| AccountId(id.to_owned()));
        let (stamp, half) = ((1, 2, 3), IDLE / 2);
        for id in [&a, &b] {
            let entry = (stamp, Rules::Off, Instant::now());
            cache.kept().insert(id.clone(), entry);
        }
        tokio::time::advance(half).await;
        assert!(cache.find(&a, stamp).is_some(), "using rules keeps them");
        tokio::time::advance(half).await;
        assert!(cache.find(&a, stamp).is_some() && cache.find(&b, stamp).is_none());
    }

    #[test]
    fn block_rules_judge_the_subject_as_received_and_stripped() {
        let drops = |pattern, subject| !judge(Block, Subject, Contains, pattern, subject);
        // Stripped: whitespace stays, so words stay apart.
        for subject in [
            "Weekly news\u{200B}let\u{200B}ter",
            "news\u{200D}letter",
            "news\u{FE0F}letter",
            "news\u{200E}letter",
            "news\u{1}letter",
        ] {
            assert!(drops("newsletter", subject), "{subject:?}");
        }
        assert!(!drops("newsletter", "news\u{2028}letter"));
        // As received.
        assert!(drops("news\u{200B}letter", "Weekly news\u{200B}letter"));
        assert!(!judge(Block, Subject, Regex, r"\u{202e}", "a\u{202E}b"));
        // Not as shown: the escapes are not text of the subject.
        let hebrew = "\u{5E9}\u{5DC}\u{5D5}\u{5DD}\u{200F}";
        assert!(!drops("200", hebrew));
        assert!(judge(Block, Subject, Regex, r"\d{3}", hebrew));
        assert!(!drops("\\u{202e}", "a\u{202E}b"));
    }

    #[test]
    fn allow_rules_judge_the_subject_as_received_shown_and_stripped() {
        let allows = |pattern, subject| judge(Allow, Subject, Contains, pattern, subject);
        assert!(allows("invoice 42", "Inv\u{E0041}oice 42"));
        assert!(allows("newsletter", "news\u{FE0F}letter"));
        assert!(allows("\\u{202e}", "a\u{202E}b"));
        assert!(allows("news\u{200B}letter", "news\u{200B}letter"));
    }

    #[test]
    fn block_rules_see_addresses_stripped_and_allow_rules_as_shown() {
        let spaced = "news\u{200B}@x.test";
        let drops = |field, kind, pattern| !judge(Block, field, kind, pattern, spaced);
        let allows = |pattern| judge(Allow, Sender, Equals, pattern, spaced);
        // Block rules: as received and stripped, never as shown.
        assert!(drops(Sender, Equals, "news@x.test"));
        assert!(drops(To, Equals, "news@x.test"));
        let dotted = "a@x\u{200B}.test";
        assert!(!judge(Block, FromDomain, Domain, "x.test", dotted));
        assert!(drops(Sender, Regex, r"\x{200b}"));
        assert!(drops(To, Regex, r"\x{200b}"));
        assert!(!drops(Sender, Contains, "\\u{200b}"));
        assert!(!drops(To, Contains, "\\u{200b}"));
        // An address loses whitespace that is hidden or a control too.
        let broken = "news\u{2028}@x.test";
        assert!(!judge(Block, Sender, Equals, "news@x.test", broken));
        assert!(!judge(
            Block,
            FromDomain,
            Domain,
            "x.test",
            "a@x.test\u{2028}"
        ));
        assert!(!judge(
            Block,
            To,
            Equals,
            "news@x.test",
            "news\u{85}@x.test"
        ));
        assert!(!judge(Allow, Sender, Equals, "news@x.test", broken));
        // Allow rules: as received and shown, never stripped.
        assert!(!allows("news@x.test"));
        assert!(allows("news\\u{200b}@x.test"));
        assert!(judge(Allow, Sender, Equals, "news@x.test", "news@x.test"));
    }

    /// Block rules also judge each address picked out of the sender's address: the
    /// characters of an address around each `@`, without the dots that end its domain.
    #[test]
    fn block_rules_judge_each_address_picked_out_of_the_sender_address() {
        let drops = |field, kind, pattern, from| !judge(Block, field, kind, pattern, from);
        for from in [
            "boss@y.test@x.test",
            "boss@y\u{200B}.test@x.test",
            "news@y.test.",
        ] {
            assert!(drops(FromDomain, Domain, "y.test", from), "{from:?}");
        }
        assert!(drops(Sender, Equals, "boss@y.test", "boss@y.test@x.test"));
        assert!(drops(FromDomain, Domain, "x.test", "boss@y.test@x.test"));
        assert!(!drops(FromDomain, Domain, "z.test", "boss@y.test@x.test"));
    }

    /// Allow rules judge a sender address that is not clear as none, as for a
    /// message without a sender; block rules still judge it.
    #[test]
    fn allow_rules_judge_a_sender_address_that_is_not_clear_as_none() {
        let judged = |action, field, kind, pattern: &str, from_clear| {
            let pattern = pattern.to_owned();
            let rule = Rule {
                action,
                field,
                kind,
                pattern,
            };
            let message = NewMessage {
                uid: 1,
                message_id: None,
                from: Some(EmailAddress::new("news@x.test")),
                from_clear,
                from_values: Vec::new(),
                recipients: Vec::new(),
                subject: None,
                date: None,
            };
            passes(&CompiledRules::new(&[rule], 1).unwrap(), &message.fields())
        };
        assert!(judged(Allow, Sender, Equals, "news@x.test", true));
        assert!(!judged(Allow, Sender, Equals, "news@x.test", false));
        assert!(!judged(Allow, FromDomain, Domain, "x.test", false));
        assert!(judged(Allow, Sender, Regex, "^$", false));
        assert!(!judged(Block, Sender, Equals, "news@x.test", false));
    }

    /// When the sender is not clear, block rules also judge each address picked out of every
    /// `From` value, as received and stripped. A sender with more than 100 picked addresses
    /// matches every block rule on the sender.
    #[test]
    fn block_rules_judge_the_addresses_in_a_sender_that_is_not_clear() {
        let drops = |field, pattern: &str, values: &[&str], from_clear| {
            let rule = Rule {
                action: Block,
                field,
                kind: Equals,
                pattern: pattern.to_owned(),
            };
            let message = NewMessage {
                uid: 1,
                message_id: None,
                from: Some(EmailAddress::new("other@x.test")),
                from_clear,
                from_values: values.iter().map(|value| (*value).to_owned()).collect(),
                recipients: Vec::new(),
                subject: None,
                date: None,
            };
            !passes(&CompiledRules::new(&[rule], 1).unwrap(), &message.fields())
        };
        let news = |values: &[&str], from_clear| drops(Sender, "news@y.test", values, from_clear);
        let padded = format!("\"{}\" <news@y.test> other@x.test", "@".repeat(100));
        let cases: [&[&str]; 11] = [
            &["<news@y.test> other@x.test"],
            &["news @ y.test"],
            &["<news @ y.test> other@x.test"],
            &["news@\r\n y.test"],
            &["other@x.test, news@y.test"],
            &["news@y.test\tother@x.test"],
            &["<news@y\u{200B}.test> other@x.test"],
            &["news@y.test", "other@x.test"],
            &["other@x.test", "a@x.test", "news@y.test"],
            &["a@x.test", "news@y.test", "b@x.test"],
            &[padded.as_str()],
        ];
        for values in cases {
            assert!(news(values, false), "{values:?}");
        }
        assert!(!news(&["\"news@y.test\" <other@x.test>"], true));
        let many = |n| {
            let addresses: Vec<_> = (0..n).map(|i| format!("a{i}@x.test")).collect();
            addresses.join(", ")
        };
        assert!(!news(&[&many(99)], false));
        assert!(news(&[&many(100)], false));
        assert!(!drops(Subject, "hi", &[&many(100)], false));
    }

    /// Block rules also find the sender's addresses as a mail app may read them: without
    /// comments, nested or with escapes, and with quoted strings unquoted. A clear sender's name
    /// is still not judged.
    #[test]
    fn block_rules_judge_the_sender_without_comments_and_quotes() {
        let drops = |field, kind, pattern: &str, from: &str| {
            let raw = format!("From: {from}\r\n\r\n");
            let headers = postkeep_mail::mime::parse_headers(raw.as_bytes()).unwrap();
            let message = NewMessage {
                uid: 1,
                message_id: None,
                from: headers.from.into_iter().next(),
                from_clear: headers.from_clear,
                from_values: headers.from_values,
                recipients: Vec::new(),
                subject: None,
                date: None,
            };
            let rule = Rule {
                action: Block,
                field,
                kind,
                pattern: pattern.to_owned(),
            };
            !passes(&CompiledRules::new(&[rule], 1).unwrap(), &message.fields())
        };
        for from in [
            "news@(c)y.test",
            "news (c) @ (d) y.test",
            "news@y(c).test",
            "news@(a(b\\)c))y.test",
            "news@(c\")y(d).test",
            "\"(c\" news@(d)y.test",
            "\"a\\\"(b\" news@(c)y.test",
            "\"news\"@y.test",
            "\"ne\\ws\"@y.test",
            "Alice <\"news\"@y.test>",
        ] {
            assert!(drops(Sender, Equals, "news@y.test", from), "{from:?}");
            assert!(drops(FromDomain, Domain, "y.test", from), "{from:?}");
        }
        let named = "\"news@y.test\" <other@x.test>";
        assert!(!drops(Sender, Equals, "news@y.test", named));
    }
}
