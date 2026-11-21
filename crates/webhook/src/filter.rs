//! Filter rules: which new mail wakes the agent.
//!
//! A mailbox without active rules reports every message. With rules, a message
//! must match an `allow` rule, if there is one, and no `block` rule: block wins.
//!
//! A rule's pattern becomes an expression for the [`regex`] crate, which
//! matches in time linear in the text (no backtracking, look-around or
//! back-references). Matching ignores case with Unicode folding, and `.` also
//! matches a line break. A pattern has at most [`MAX_PATTERN_LEN`] bytes. The
//! patterns of one action and field compile to about 4 MiB at most, and all of
//! a mailbox's patterns to about 10 MiB; the reverse automaton and the search
//! caches of each thread come on top.
//!
//! What a sender controls is cut before it is searched, so that a search stays
//! short however many rules there are: a message is judged on the first 2 KiB
//! of its subject, the last 320 bytes of each address (the domain stays) and
//! its first 100 recipients.
//!
//! Compiling takes time that grows roughly with the square of the patterns in a
//! set (under a second for 1,000 rules in a release build), so a mailbox may
//! have 2,000 active rules at most. Compile off the async runtime.

use std::fmt;

use regex::{RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};

/// The longest pattern a rule may have, in bytes.
pub const MAX_PATTERN_LEN: usize = 512;
/// Compiled size of one action and field: room for 1,000 realistic rules (under 3 MiB).
const SET_SIZE_LIMIT: usize = 4 << 20;
/// Compiled size of all of a mailbox's patterns (the reverse automaton and caches come on top).
const TOTAL_SIZE_LIMIT: usize = 10 << 20;
/// Cache of the lazy DFA that searches one set, per thread: the default, enough for 1,000 rules.
const DFA_SIZE_LIMIT: usize = 2 << 20;
/// The most active rules compiled for a mailbox: compile time grows with their square in a set.
pub const MAX_RULES: usize = 2_000;
/// The most of a subject that is searched, in bytes: its start says what a mail is.
const MAX_SUBJECT_LEN: usize = 2048;
/// The most of an address that is searched, in bytes, from its end: the standard allows 254.
const MAX_ADDRESS_LEN: usize = 320;
/// The most recipients that are searched.
const MAX_RECIPIENTS: usize = 100;

/// What a rule does to a message that matches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Report only messages that match an allow rule, if there is one.
    Allow,
    /// Never report a message that matches, whatever else matches.
    Block,
}

/// The part of a message a rule looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// The sender's address.
    From,
    /// The sender's domain: what follows the last `@`.
    FromDomain,
    /// The addresses in `To` and `Cc`; the rule matches if any does.
    To,
    /// The decoded subject.
    Subject,
}

/// How a rule's pattern is compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The whole text is the pattern.
    Equals,
    /// The text contains the pattern.
    Contains,
    /// The domain of the address, or the domain itself, is the pattern or a
    /// subdomain of it. The pattern is a plain domain such as `example.com`.
    Domain,
    /// The pattern is a regular expression, used as written.
    Regex,
}

/// Why a rule, or the rules of a mailbox, were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RuleError {
    /// The pattern is empty or longer than [`MAX_PATTERN_LEN`].
    #[error("the pattern must be 1 to {} bytes", MAX_PATTERN_LEN)]
    Length,
    /// A domain is compared with addresses, not with a subject.
    #[error("a domain rule cannot look at the subject")]
    DomainOfSubject,
    /// A domain rule with a pattern that no domain can match, such as `@example.com`.
    #[error(
        "a domain rule needs a plain domain such as example.com: no @, * or spaces, no dot at either end"
    )]
    NotADomain,
    /// The `regex` crate refuses the pattern. The text is the parser's message
    /// without the pattern, which it repeats.
    #[error("{0}")]
    Syntax(String),
    /// The compiled patterns would be larger than allowed, or there are too many rules.
    #[error("the rules of this mailbox are too large to compile; remove some or simplify them")]
    TooLarge,
}

/// One filter rule: `action` applies to a message whose `field` matches
/// `pattern` the way `kind` says. `Debug` leaves the pattern out, as it can
/// hold addresses and names.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// What a match does.
    pub action: Action,
    /// The part of the message that is compared.
    pub field: Field,
    /// How it is compared.
    pub kind: Kind,
    /// 1 to [`MAX_PATTERN_LEN`] bytes.
    pub pattern: String,
}

impl fmt::Debug for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (a, b, c) = (self.action, self.field, self.kind);
        write!(f, "Rule({a:?} {b:?} {c:?}: {} bytes)", self.pattern.len())
    }
}

impl Rule {
    /// Checks a rule before it is stored: a pattern of 1 to [`MAX_PATTERN_LEN`]
    /// bytes that compiles on its own within the limits.
    ///
    /// # Errors
    ///
    /// The [`RuleError`] that says what is wrong. For a regular expression it
    /// carries the parser's message.
    pub fn validate(&self) -> Result<(), RuleError> {
        if !(1..=MAX_PATTERN_LEN).contains(&self.pattern.len()) {
            return Err(RuleError::Length);
        }
        if self.kind == Kind::Domain && self.field == Field::Subject {
            return Err(RuleError::DomainOfSubject);
        }
        if self.kind == Kind::Domain && !is_domain(&self.pattern) {
            return Err(RuleError::NotADomain);
        }
        compile(&[self.source()], SET_SIZE_LIMIT).map(drop)
    }

    /// The regular expression the rule stands for. A domain follows the `@` of
    /// an address or the dot of a subdomain, or is the whole bare domain.
    fn source(&self) -> String {
        let text = regex::escape(&self.pattern);
        match self.kind {
            Kind::Equals => format!("^{text}$"),
            Kind::Contains => text,
            Kind::Domain => format!("(^|[@.]){text}$"),
            Kind::Regex => self.pattern.clone(),
        }
    }
}

/// Whether `text` is a plain domain: labels of letters, digits, `-` and `_`, none of them empty.
fn is_domain(text: &str) -> bool {
    let plain = |c: char| c.is_alphanumeric() || c == '-' || c == '_';
    text.split('.')
        .all(|label| !label.is_empty() && label.chars().all(plain))
}

/// The rules that count: the oldest `limit` of `rules`, which are listed oldest
/// first. The newer ones are disabled, not deleted: a higher limit brings them
/// back.
#[must_use]
pub fn active<T>(rules: &[T], limit: usize) -> &[T] {
    rules.get(..limit).unwrap_or(rules)
}

/// The patterns as one set that takes at most `size_limit` bytes compiled.
fn compile(patterns: &[String], size_limit: usize) -> Result<RegexSet, RuleError> {
    RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .dot_matches_new_line(true)
        .size_limit(size_limit)
        .dfa_size_limit(DFA_SIZE_LIMIT)
        .build()
        .map_err(|error| match error {
            regex::Error::CompiledTooBig(_) => RuleError::TooLarge,
            other => RuleError::Syntax(syntax_message(&other.to_string())),
        })
}

/// The parser's message without the pattern it repeats: the text after its last `error: `.
fn syntax_message(text: &str) -> String {
    let message = text
        .rsplit_once("error: ")
        .map_or("not a valid pattern", |(_, m)| m);
    message.to_owned()
}

/// The first `max` bytes of `text`, cut at a character boundary.
fn head(text: &str, max: usize) -> &str {
    &text[..text.floor_char_boundary(max)]
}

/// The last `max` bytes of `text`, cut at a character boundary.
fn tail(text: &str, max: usize) -> &str {
    &text[text.ceil_char_boundary(text.len().saturating_sub(max))..]
}

/// What the rules look at in one message. A missing value is left empty. It has
/// no `Debug`, so addresses and subjects stay out of logs.
#[derive(Clone, Copy, Default)]
pub struct MessageFields<'a> {
    /// The sender's bare address, such as `alice@example.com`.
    pub from: &'a str,
    /// The bare addresses in `To` and `Cc`.
    pub to: &'a [&'a str],
    /// The decoded subject.
    pub subject: &'a str,
}

/// One message given in several forms, for [`CompiledRules::passes_forms`].
///
/// Each field has its own list of forms, such as the text as received and as
/// shown, and an empty list is not searched. It has no `Debug`, so addresses
/// and subjects stay out of logs.
#[derive(Clone, Copy, Default)]
pub struct MessageForms<'a> {
    /// The sender's bare address, in each form.
    pub from: &'a [&'a str],
    /// The bare addresses in `To` and `Cc`, one list per form.
    pub to: &'a [&'a [&'a str]],
    /// The decoded subject, in each form.
    pub subject: &'a [&'a str],
}

/// The active rules of a mailbox, compiled: one set of patterns per action and
/// field. Compile again when the rules or the limit change.
#[derive(Clone)]
pub struct CompiledRules(Vec<(Action, Field, RegexSet)>);

impl fmt::Debug for CompiledRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledRules").finish_non_exhaustive()
    }
}

impl CompiledRules {
    /// Compiles the [`active`] rules, given oldest first.
    ///
    /// # Errors
    ///
    /// [`RuleError::Syntax`] for a pattern the `regex` crate refuses, and
    /// [`RuleError::TooLarge`] when there are more than 2,000 active rules, or
    /// the patterns of an action and field, or of the whole mailbox, are too
    /// big together though each may be fine alone.
    pub fn new(rules: &[Rule], limit: usize) -> Result<Self, RuleError> {
        let (mut sets, rules) = (Vec::new(), active(rules, limit));
        if rules.len() > MAX_RULES {
            return Err(RuleError::TooLarge);
        }
        for action in [Action::Allow, Action::Block] {
            for field in [Field::From, Field::FromDomain, Field::To, Field::Subject] {
                let patterns: Vec<_> = rules
                    .iter()
                    .filter(|r| r.action == action && r.field == field)
                    .map(Rule::source)
                    .collect();
                sets.push((action, field, compile(&patterns, SET_SIZE_LIMIT)?));
            }
        }
        // Two sets cannot reach the total, so only more are compiled together.
        let used = sets.iter().filter(|(.., set)| !set.is_empty()).count();
        if used * SET_SIZE_LIMIT > TOTAL_SIZE_LIMIT {
            let all: Vec<_> = rules.iter().map(Rule::source).collect();
            compile(&all, TOTAL_SIZE_LIMIT)?;
        }
        Ok(Self(sets))
    }

    /// Whether the message wakes the agent: it matches an allow rule, if there
    /// is one, and no block rule.
    #[must_use]
    pub fn passes(&self, message: &MessageFields<'_>) -> bool {
        let forms = MessageForms {
            from: &[message.from],
            to: &[message.to],
            subject: &[message.subject],
        };
        self.passes_forms(&forms, &forms)
    }

    /// Whether one message given in several forms wakes the agent.
    ///
    /// As for [`Self::passes`], where an allow rule counts when it matches one
    /// of the forms in `allow`, and a block rule one of those in `block`.
    #[must_use]
    pub fn passes_forms(&self, allow: &MessageForms<'_>, block: &MessageForms<'_>) -> bool {
        let allows = self
            .0
            .iter()
            .any(|(a, _, set)| *a == Action::Allow && !set.is_empty());
        !self.matches(Action::Block, block) && (!allows || self.matches(Action::Allow, allow))
    }

    /// Whether an active block rule judges the sender: one on `from` or `from_domain`.
    #[must_use]
    pub fn blocks_by_sender(&self) -> bool {
        self.0.iter().any(|(action, field, set)| {
            *action == Action::Block
                && matches!(field, Field::From | Field::FromDomain)
                && !set.is_empty()
        })
    }

    /// Whether a rule of `action` matches a form of the message, each form cut
    /// first.
    fn matches(&self, action: Action, message: &MessageForms<'_>) -> bool {
        self.0
            .iter()
            .filter(|(a, ..)| *a == action)
            .any(|(_, field, set)| match field {
                Field::From => message
                    .from
                    .iter()
                    .any(|from| set.is_match(tail(from, MAX_ADDRESS_LEN))),
                Field::FromDomain => message.from.iter().any(|from| {
                    let domain = from.rsplit_once('@').map_or("", |(_, d)| d);
                    set.is_match(tail(domain, MAX_ADDRESS_LEN))
                }),
                Field::To => message.to.iter().any(|to| {
                    to.iter()
                        .take(MAX_RECIPIENTS)
                        .any(|address| set.is_match(tail(address, MAX_ADDRESS_LEN)))
                }),
                Field::Subject => message
                    .subject
                    .iter()
                    .any(|subject| set.is_match(head(subject, MAX_SUBJECT_LEN))),
            })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use Action::{Allow, Block};
    use Field::{From as Sender, FromDomain, Subject, To};
    use Kind::{Contains, Domain, Equals, Regex};

    use super::*;

    fn rule(action: Action, field: Field, kind: Kind, pattern: &str) -> Rule {
        let pattern = pattern.to_owned();
        Rule {
            action,
            field,
            kind,
            pattern,
        }
    }

    fn passes(rules: &[Rule], from: &str, subject: &str) -> bool {
        let all = CompiledRules::new(rules, usize::MAX).unwrap();
        all.passes(&MessageFields {
            from,
            subject,
            ..Default::default()
        })
    }

    /// Whether `all` passes a message that has `text` in every field.
    fn everywhere(all: &CompiledRules, text: &str) -> bool {
        all.passes(&MessageFields {
            from: text,
            to: &[text],
            subject: text,
        })
    }

    /// Whether a lone block rule drops a message with `text` in every field.
    fn drops(field: Field, kind: Kind, pattern: &str, text: &str) -> bool {
        let all = CompiledRules::new(&[rule(Block, field, kind, pattern)], 1).unwrap();
        !everywhere(&all, text)
    }

    #[test]
    fn allow_and_block_combine() {
        let invoice = rule(Allow, Subject, Contains, "invoice");
        let github = rule(Allow, Sender, Domain, "github.com");
        let spam = rule(Block, Sender, Domain, "spam.example");
        let both = [invoice.clone(), spam.clone()];
        assert!(passes(&[], "a@x.example", "hello"));
        assert!(passes(std::slice::from_ref(&invoice), "", "Your invoice"));
        assert!(!passes(std::slice::from_ref(&invoice), "", "hello"));
        assert!(passes(&[spam], "a@x.example", "re: a@spam.example"));
        assert!(passes(&both, "a@x.example", "invoice"));
        assert!(!passes(&both, "a@spam.example", "invoice"));
        assert!(!passes(&both, "a@x.example", "hello"));
        assert!(passes(
            &[invoice.clone(), github.clone()],
            "a@github.com",
            "hello"
        ));
        assert!(passes(&[invoice, github], "a@x.example", "invoice"));
    }

    #[test]
    fn each_kind_compares_as_documented() {
        assert!(drops(Subject, Equals, "hello", "HELLO"));
        assert!(!drops(Subject, Equals, "hello", "hello world"));
        assert!(!drops(Subject, Equals, "hello", "say hello"));
        assert!(!drops(Subject, Equals, "a.c", "abc"));
        assert!(drops(Subject, Contains, "a.c", "xa.cx"));
        assert!(!drops(Subject, Contains, "a.c", "xabcx"));
        assert!(drops(Subject, Contains, "(urgent)", "re: (URGENT)!"));
        assert!(drops(Subject, Regex, r"^\[(urgent|asap)\]", "[ASAP] now"));
        assert!(!drops(Subject, Regex, r"^\[(urgent|asap)\]", "re: [asap]"));
        assert!(drops(Subject, Regex, "^.*invoice.*$", "a\nINVOICE\0b"));
        assert!(drops(Subject, Regex, "^$", ""));
        assert!(drops(Sender, Domain, "github.com", "ALICE@GITHUB.COM"));
        assert!(drops(Sender, Domain, "github.com", "n@mail.github.com"));
        assert!(!drops(Sender, Domain, "github.com", "n@evilgithub.com"));
        assert!(!drops(Sender, Domain, "github.com", "n@githubxcom"));
        assert!(!drops(
            Sender,
            Domain,
            "github.com",
            "github.com@evil.example"
        ));
        assert!(drops(FromDomain, Equals, "github.com", "a@github.com"));
        assert!(drops(FromDomain, Equals, "github.com", "a@b@github.com"));
        assert!(drops(FromDomain, Domain, "github.com", "a@github.com"));
        assert!(drops(FromDomain, Regex, "^$", "postmaster"));
        assert!(!drops(
            FromDomain,
            Equals,
            "github.com",
            "a@mail.github.com"
        ));
        assert!(!drops(FromDomain, Contains, "a@", "a@github.com"));
        assert!(drops(To, Domain, "example.com", "x@Example.com"));
        // Case folds the Unicode way. U+FFFD is what a header that is not valid
        // UTF-8 turns into.
        assert!(drops(Subject, Contains, "ÉCOLE", "à l'école"));
        assert!(drops(Subject, Contains, "k", "\u{212A}elvin"));
        assert!(drops(Subject, Equals, "ΟΔΟΣ", "οδος"));
        assert!(drops(Subject, Equals, "straße", "STRAẞE"));
        assert!(drops(
            Subject,
            Contains,
            "caf\u{FFFD}",
            "caf\u{FFFD} \u{FFFD}"
        ));
    }

    #[test]
    fn any_recipient_counts() {
        let team = [rule(Allow, To, Domain, "example.com")];
        let all = CompiledRules::new(&team, 1).unwrap();
        let to = |to: &[&str]| {
            all.passes(&MessageFields {
                to,
                ..Default::default()
            })
        };
        assert!(to(&["x@other.org", "y@EXAMPLE.com"]));
        assert!(!to(&["x@other.org"]));
        assert!(!to(&[]));
    }

    #[test]
    fn each_action_judges_its_own_forms() {
        const fn forms<'a>(
            from: &'a [&'a str],
            to: &'a [&'a [&'a str]],
            subject: &'a [&'a str],
        ) -> MessageForms<'a> {
            MessageForms { from, to, subject }
        }
        let rules = [
            rule(Allow, Subject, Contains, "invoice"),
            rule(Block, Sender, Equals, "spam@x.test"),
            rule(Block, To, Equals, "spam@x.test"),
        ];
        let all = CompiledRules::new(&rules, 3).unwrap();
        let none = MessageForms::default();
        let invoice = forms(&[], &[], &["hello", "Invoice"]);
        let from_spam = forms(&["a@x.test", "spam@x.test"], &[], &[]);
        let to_spam = forms(&[], &[&["a@x.test"], &["a@x.test", "spam@x.test"]], &[]);
        let spam = forms(&["spam@x.test"], &[&["spam@x.test"]], &["Invoice"]);
        // An allow rule counts on any allow form, and sees no block form.
        assert!(all.passes_forms(&invoice, &none));
        assert!(!all.passes_forms(&none, &invoice));
        // A block rule counts on any block form, and sees no allow form.
        assert!(!all.passes_forms(&invoice, &from_spam));
        assert!(!all.passes_forms(&invoice, &to_spam));
        assert!(all.passes_forms(&spam, &none));
    }

    #[test]
    fn what_a_sender_controls_is_cut() {
        // A subject is searched up to 2,048 bytes, and whole characters only.
        let subject = |a: usize| format!("{}needle", "a".repeat(a));
        assert!(drops(Subject, Contains, "needle", &subject(2042)));
        assert!(!drops(Subject, Contains, "needle", &subject(2043)));
        let wide = format!("a{}", "é".repeat(1100));
        assert!(drops(Subject, Regex, "^a(é){1023}$", &wide));
        // An address is searched up to 320 bytes of its end, so its domain stays.
        let address = |a: usize| format!("{}@x.example", "a".repeat(a));
        assert!(drops(Sender, Equals, &address(310), &address(310)));
        assert!(!drops(Sender, Equals, &address(311), &address(311)));
        let hostile = format!("{}@spam.example", "x".repeat(400));
        assert!(drops(Sender, Domain, "spam.example", &hostile));
        assert!(drops(FromDomain, Equals, "spam.example", &hostile));
        let deep = format!("a@{}spam.example", "d.".repeat(200));
        assert!(drops(FromDomain, Domain, "spam.example", &deep));
        let long = format!("marker{}", "d".repeat(400));
        assert!(!drops(FromDomain, Contains, "marker", &format!("x@{long}")));
        assert!(!drops(To, Contains, "marker", &format!("{long}@x.example")));
        assert!(drops(To, Domain, "x.example", &format!("{long}@x.example")));
        assert!(drops(
            Sender,
            Domain,
            "x.example",
            &format!("{}a@x.example", "é".repeat(200))
        ));
        // Only the first 100 recipients are searched.
        let all = CompiledRules::new(&[rule(Allow, To, Equals, "boss@example.com")], 1).unwrap();
        let others: Vec<String> = (0..100).map(|i| format!("u{i}@x.example")).collect();
        let seen = |before: usize| {
            let first = others.iter().take(before).map(String::as_str);
            let to: Vec<&str> = first.chain(["boss@example.com"]).collect();
            all.passes(&MessageFields {
                to: &to,
                ..Default::default()
            })
        };
        assert!(seen(99));
        assert!(!seen(100));
    }

    #[test]
    fn refuses_what_cannot_be_a_rule() {
        let check = |field, kind, pattern: &str| rule(Allow, field, kind, pattern).validate();
        let paren = "(".repeat(512);
        assert_eq!(
            check(Subject, Domain, "example.com"),
            Err(RuleError::DomainOfSubject)
        );
        assert_eq!(check(Sender, Domain, ""), Err(RuleError::Length));
        // A domain that no address can match would, as an allow rule, drop every message.
        let bad = "@github.com,*.github.com,github.com.,.github.com, github.com,github.com ,git hub.com,a@github.com,github..com";
        for pattern in bad.split(',') {
            let error = check(Sender, Domain, pattern);
            assert_eq!(error, Err(RuleError::NotADomain), "{pattern:?}");
        }
        let good = "github.com,mail.github.com,example-1.co.uk,a_b.example,bücher.de,localhost";
        for pattern in good.split(',') {
            assert_eq!(check(To, Domain, pattern), Ok(()), "{pattern:?}");
        }
        assert_eq!(check(Subject, Contains, ""), Err(RuleError::Length));
        assert_eq!(
            check(Subject, Contains, &"a".repeat(513)),
            Err(RuleError::Length)
        );
        assert_eq!(
            check(Subject, Contains, &"é".repeat(257)),
            Err(RuleError::Length)
        );
        // Escaped, so only a regular expression can be bad syntax.
        assert_eq!(check(Subject, Contains, &paren), Ok(()));
        assert_eq!(check(Sender, Equals, &paren), Ok(()));
        assert_eq!(check(Subject, Regex, &"a".repeat(512)), Ok(()));
        let nested = format!("{}a{}", "(".repeat(251), ")".repeat(251));
        for (pattern, message) in [
            ("(?=x)", "look-around"),
            (r"(a)\1", "backreferences"),
            ("[a", "unclosed character class"),
            (&nested, "nested"),
        ] {
            let error = check(Subject, Regex, pattern);
            assert!(matches!(&error, Err(RuleError::Syntax(m)) if m.contains(message)));
        }
        for pattern in ["(a{1000}){1000}", "a{100000}", r"\w{100}"] {
            assert_eq!(check(Subject, Regex, pattern), Err(RuleError::TooLarge));
        }
        // The parser repeats the pattern in its message; the error must not.
        let lookahead = "look-around, including look-ahead and look-behind, is not supported";
        assert_eq!(
            check(Subject, Regex, "(?=x)"),
            Err(RuleError::Syntax(lookahead.to_owned()))
        );
        for pattern in ["(?=zebra)", "(?=error: zebra)", "[zebra"] {
            let error = check(Subject, Regex, pattern).unwrap_err();
            let set = CompiledRules::new(&[rule(Allow, Subject, Regex, pattern)], 1).unwrap_err();
            assert_eq!(error, set);
            assert!(!format!("{error} {error:?}").contains("zebra"), "{error}");
        }
        assert_eq!(syntax_message("zebra"), "not a valid pattern");
    }

    /// Rule `i` of one of four shapes: domains of about 14 and 25 bytes, an
    /// address, and a phrase.
    fn shape(n: usize, i: usize) -> Rule {
        match n {
            0 => rule(Allow, Sender, Domain, &format!("a{i}.example.io")),
            1 => rule(Allow, Sender, Domain, &format!("mail{i}.example-{i}.co.uk")),
            2 => rule(Allow, Sender, Equals, &format!("user{i}@example-{i}.co.uk")),
            _ => rule(
                Allow,
                Subject,
                Contains,
                &format!("your verification code number {i:04} is"),
            ),
        }
    }

    #[test]
    fn a_thousand_realistic_rules_fit_in_one_action_and_field() {
        for n in 0..4 {
            let rules: Vec<_> = (0..1000).map(|i| shape(n, i)).collect();
            let all = CompiledRules::new(&rules, 1000).unwrap();
            let Rule { kind, pattern, .. } = &rules[500];
            let text = if *kind == Domain {
                format!("x@{pattern}")
            } else {
                pattern.clone()
            };
            assert!(everywhere(&all, &text), "shape {n}");
            assert!(!everywhere(&all, "x@other.example"), "shape {n}");
        }
    }

    #[test]
    fn a_set_over_4_mib_and_a_total_over_10_mib_are_refused() {
        // A copy of the pattern takes about 0.6 MiB compiled.
        let heavy = |sets: &[(Action, Field)], n: usize| {
            let copies = |&(a, f): &(Action, Field)| {
                (0..n).map(move |i| rule(a, f, Regex, &format!(r"\w{{12}}-{i}")))
            };
            sets.iter().flat_map(copies).collect::<Vec<_>>()
        };
        let fields = [Sender, FromDomain, To, Subject];
        let sets: Vec<_> = [Allow, Block]
            .iter()
            .flat_map(|&a| fields.map(|f| (a, f)))
            .collect();
        let new = |rules: &[Rule]| CompiledRules::new(rules, 99);
        assert_eq!(heavy(&sets[..1], 1)[0].validate(), Ok(()));
        assert!(new(&heavy(&sets[..1], 6)).is_ok());
        assert!(matches!(
            new(&heavy(&sets[..1], 8)),
            Err(RuleError::TooLarge)
        ));
        assert!(new(&heavy(&sets[..3], 4)).is_ok());
        assert!(matches!(
            new(&heavy(&sets[..4], 6)),
            Err(RuleError::TooLarge)
        ));
        assert!(matches!(new(&heavy(&sets, 3)), Err(RuleError::TooLarge)));
        // Only the oldest rules count: here the six of the first set.
        assert!(CompiledRules::new(&heavy(&sets[..4], 6), 6).is_ok());
    }

    #[test]
    fn a_thousand_rules_across_the_eight_sets_are_judged() {
        let fields = [Sender, FromDomain, To, Subject];
        let rules: Vec<_> = (0..1000)
            .map(|i| {
                let pattern = format!("mail-{i}.example.com");
                rule([Allow, Block][i % 2], fields[i / 2 % 4], Contains, &pattern)
            })
            .collect();
        let all = CompiledRules::new(&rules, 1000).unwrap();
        assert!(everywhere(&all, "n@MAIL-998.example.com"));
        assert!(!everywhere(&all, "n@mail-3.example.com"));
        assert!(!everywhere(&all, "n@mail-4000.example.com"));
        assert!(!format!("{all:?}{:?}", rules[0]).contains("example"));
    }

    #[test]
    fn crafted_text_cannot_make_matching_slow() {
        let alternation = (1..170).fold("00".to_owned(), |a, i| format!("{a}|{i:02x}"));
        let rules: Vec<_> = [
            "(a+)+$",
            "(a|aa)+$",
            "(a*)*b",
            "(x+x+)+y",
            "(.*)*z",
            &alternation,
        ]
        .iter()
        .map(|pattern| rule(Allow, Subject, Regex, pattern))
        .collect();
        // A thousand phrases on the subject and on the recipients, and text that is nothing but their start.
        let phrases: Vec<_> = [Subject, To]
            .into_iter()
            .flat_map(|field| {
                (0..1000).map(move |i| {
                    let phrase = format!("your verification code number {i:04} is");
                    rule(Allow, field, Contains, &phrase)
                })
            })
            .collect();
        let phrases = CompiledRules::new(&phrases, 2000).unwrap();
        let start = Instant::now();
        assert!(!passes(&rules, "", &format!("{}!", "a".repeat(997))));
        assert!(!passes(&rules, "", &"ac".repeat(50_000)));
        assert!(passes(&rules, "", "aaa"));
        assert!(start.elapsed() < Duration::from_secs(5));
        let start = Instant::now();
        let crafted = "your verification code number 9".repeat(3300);
        assert!(!everywhere(&phrases, &crafted));
        let address = format!("x@{}", &crafted[..300]);
        let to = vec![address.as_str(); 100];
        assert!(!phrases.passes(&MessageFields {
            to: &to,
            ..Default::default()
        }));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_mailbox_has_at_most_2000_active_rules() {
        let rules: Vec<_> = (0..2001)
            .map(|i| rule(Allow, Subject, Contains, &format!("w{i}")))
            .collect();
        assert!(matches!(
            CompiledRules::new(&rules, 2001),
            Err(RuleError::TooLarge)
        ));
        assert!(CompiledRules::new(&rules, 2000).is_ok());
    }

    #[test]
    fn disabled_rules_do_not_count_and_rules_are_json() {
        assert_eq!(active(&[1, 2, 3], 2), [1, 2]);
        assert!(active(&[1, 2, 3], 0).is_empty() && active(&[1, 2, 3], 9).len() == 3);
        let rules = [
            rule(Allow, Subject, Contains, "code"),
            rule(Block, Subject, Contains, "code"),
        ];
        let on = |limit| CompiledRules::new(&rules, limit).unwrap();
        assert!(on(1).passes(&MessageFields {
            subject: "your code",
            ..Default::default()
        }));
        assert!(!on(2).passes(&MessageFields {
            subject: "your code",
            ..Default::default()
        }));

        let json =
            r#"{"action":"block","field":"from_domain","kind":"domain","pattern":"x.example"}"#;
        let parsed: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(parsed, rule(Block, FromDomain, Domain, "x.example"));
        assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
        assert!(serde_json::from_str::<Rule>(&json.replace("from_domain", "body")).is_err());
        assert!(!format!("{parsed:?}").contains("x.example"));
    }

    #[test]
    fn blocks_by_sender_is_whether_an_active_block_rule_judges_the_sender() {
        let blocks =
            |rules: &[Rule], limit| CompiledRules::new(rules, limit).unwrap().blocks_by_sender();
        let sender = rule(Block, Sender, Equals, "a@x.example");
        assert!(blocks(std::slice::from_ref(&sender), 1));
        assert!(blocks(&[rule(Block, FromDomain, Domain, "x.example")], 1));
        assert!(!blocks(&[sender], 0));
        assert!(!blocks(&[rule(Block, To, Equals, "a@x.example")], 1));
        assert!(!blocks(&[rule(Block, Subject, Contains, "a")], 1));
        assert!(!blocks(&[rule(Allow, Sender, Equals, "a@x.example")], 1));
    }
}
