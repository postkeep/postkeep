//! A typed IMAP `SEARCH` query builder.
//!
//! Every user-supplied string is validated and emitted either as an IMAP
//! quoted string or, for non-ASCII text, as a length-prefixed literal, so
//! values can never break out of their search key and inject additional IMAP
//! syntax or commands.

use chrono::NaiveDate;

use crate::{EmailAddress, Error, MessageHeaders, Result, Uid, invisible};

/// Criteria for [`ImapSession::search`](crate::ImapSession::search).
///
/// All criteria are combined with AND. An empty query matches every message.
///
/// ```
/// use chrono::NaiveDate;
/// use postkeep_mail::SearchQuery;
///
/// let query = SearchQuery::new()
///     .from("alice@example.com")
///     .subject("launch checklist")
///     .since(NaiveDate::from_ymd_opt(2026, 1, 1).unwrap())
///     .unread(true);
/// # let _ = query;
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchQuery {
    criteria: Vec<Criterion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Criterion {
    From(String),
    To(String),
    Subject(String),
    Text(String),
    MessageId(String),
    Since(NaiveDate),
    Before(NaiveDate),
    UidAtMost(Uid),
    Seen(bool),
    Flagged(bool),
}

/// Which non-synchronizing literals (RFC 7888) the server accepts. They are
/// used to send non-ASCII search text, which quoted strings cannot carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Literals {
    /// `LITERAL+`: literals of any size.
    Unlimited,
    /// `LITERAL-`: literals of up to 4096 bytes.
    UpTo4096,
    /// Neither; non-ASCII text is sent as a quoted string, which many (but
    /// not all) servers accept.
    Unsupported,
}

impl Literals {
    /// Picks the literal support advertised in `capabilities`.
    pub fn from_capabilities(capabilities: &async_imap::types::Capabilities) -> Self {
        if capabilities.has_str("LITERAL+") {
            Self::Unlimited
        } else if capabilities.has_str("LITERAL-") {
            Self::UpTo4096
        } else {
            Self::Unsupported
        }
    }

    const fn allows(self, len: usize) -> bool {
        match self {
            Self::Unlimited => true,
            Self::UpTo4096 => len <= 4096,
            Self::Unsupported => false,
        }
    }
}

/// Whether the field holds the non-blank trimmed value, ignoring case.
#[must_use]
pub fn holds(field: &str, value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty() && field.to_lowercase().contains(&trimmed.to_lowercase())
}

/// Whether the addresses as results show them, joined with commas, hold the value.
#[must_use]
pub fn holds_addresses(addresses: &[EmailAddress], value: &str) -> bool {
    let shown = addresses
        .iter()
        .map(|address| invisible::email_address(address.name.as_deref(), &address.address))
        .collect::<Vec<_>>()
        .join(", ");
    holds(&shown, value)
}

impl SearchQuery {
    /// Creates an empty query that matches every message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Matches messages whose `From` header contains `value`.
    #[must_use]
    pub fn from(self, value: impl Into<String>) -> Self {
        self.with(Criterion::From(value.into()))
    }

    /// Matches messages whose `To` header contains `value`.
    #[must_use]
    pub fn to(self, value: impl Into<String>) -> Self {
        self.with(Criterion::To(value.into()))
    }

    /// Matches messages whose subject contains `value`.
    #[must_use]
    pub fn subject(self, value: impl Into<String>) -> Self {
        self.with(Criterion::Subject(value.into()))
    }

    /// Matches messages whose headers or body contain `value`.
    #[must_use]
    pub fn text(self, value: impl Into<String>) -> Self {
        self.with(Criterion::Text(value.into()))
    }

    /// Matches messages whose `Message-ID` header contains `value`
    /// (with or without angle brackets).
    #[must_use]
    pub fn message_id(self, value: impl Into<String>) -> Self {
        self.with(Criterion::MessageId(value.into()))
    }

    /// Matches messages whose `Date` header falls on or after `date`: the
    /// day as the header writes it, whatever its time and zone (`SENTSINCE`).
    #[must_use]
    pub fn since(self, date: NaiveDate) -> Self {
        self.with(Criterion::Since(date))
    }

    /// Matches messages whose `Date` header falls before `date`
    /// (`SENTBEFORE`).
    #[must_use]
    pub fn before(self, date: NaiveDate) -> Self {
        self.with(Criterion::Before(date))
    }

    /// Matches unread messages when `true`, read messages when `false`.
    #[must_use]
    pub fn unread(self, unread: bool) -> Self {
        self.with(Criterion::Seen(!unread))
    }

    /// Matches flagged messages when `true`, unflagged messages when `false`.
    #[must_use]
    pub fn flagged(self, flagged: bool) -> Self {
        self.with(Criterion::Flagged(flagged))
    }

    /// Matches UIDs from 1 through `uid`, including both ends.
    #[must_use]
    pub fn uid_at_most(self, uid: Uid) -> Self {
        self.with(Criterion::UidAtMost(uid))
    }

    /// Whether the parsed headers hold every header criterion.
    ///
    /// Body text, message ID, UID and flags are not checked here.
    #[must_use]
    pub fn matches(&self, headers: &MessageHeaders) -> bool {
        self.criteria.iter().all(|criterion| match criterion {
            Criterion::From(value) => invisible::senders(
                headers.from.first(),
                headers.from_clear,
                &headers.from_values,
            )
            .0
            .first()
            .is_some_and(|from| holds(from, value)),
            Criterion::To(value) => headers.to_clear && holds_addresses(&headers.to, value),
            Criterion::Subject(value) => headers
                .subject
                .as_deref()
                .is_some_and(|subject| holds(&invisible::visible(subject), value)),
            Criterion::Since(day) => headers.date.is_some_and(|date| date.date_naive() >= *day),
            Criterion::Before(day) => headers.date.is_some_and(|date| date.date_naive() < *day),
            Criterion::Text(_)
            | Criterion::MessageId(_)
            | Criterion::UidAtMost(_)
            | Criterion::Seen(_)
            | Criterion::Flagged(_) => true,
        })
    }

    /// Whether any criterion must be checked against the parsed headers.
    #[must_use]
    pub fn checks_headers(&self) -> bool {
        !self.matches(&MessageHeaders::default())
    }

    /// Whether `uid` is within every UID cutoff in the query.
    #[must_use]
    pub fn allows_uid(&self, uid: Uid) -> bool {
        !self
            .criteria
            .iter()
            .any(|criterion| matches!(criterion, Criterion::UidAtMost(cutoff) if uid > *cutoff))
    }

    fn with(mut self, criterion: Criterion) -> Self {
        self.criteria.push(criterion);
        self
    }

    /// Renders the query as the argument of an IMAP `UID SEARCH` command.
    pub(crate) fn to_imap(&self, literals: Literals) -> Result<String> {
        let (keys, utf8) = self.keys(literals)?;
        Ok(if utf8 {
            format!("CHARSET UTF-8 {keys}")
        } else {
            keys
        })
    }

    /// Renders the query as the arguments of an IMAP `UID SORT` command
    /// (RFC 5256) that lists the oldest `Date` header first, or `None` when
    /// a value is not ASCII: GreenMail's `SORT`, for one, finds no non-ASCII
    /// text that its `SEARCH` finds.
    pub(crate) fn to_imap_sort(&self) -> Result<Option<String>> {
        let (keys, utf8) = self.keys(Literals::Unsupported)?;
        Ok((!utf8).then(|| format!("(DATE) US-ASCII {keys}")))
    }

    /// The search keys, and whether any of them carries non-ASCII text.
    fn keys(&self, literals: Literals) -> Result<(String, bool)> {
        let mut keys = Vec::with_capacity(self.criteria.len());
        let mut utf8 = false;
        let mut string = |value: &str| -> Result<String> {
            let rendered = imap_string(value, literals)?;
            utf8 |= !value.is_ascii();
            Ok(rendered)
        };
        // Leave control characters for imap_string to reject, even at the edges.
        let space = |c: char| c.is_whitespace() && !c.is_control();
        for criterion in &self.criteria {
            let key = match criterion {
                Criterion::From(value) => format!("FROM {}", string(value.trim_matches(space))?),
                Criterion::To(value) => format!("TO {}", string(value.trim_matches(space))?),
                Criterion::Subject(value) => {
                    format!("SUBJECT {}", string(value.trim_matches(space))?)
                }
                Criterion::Text(value) => format!("TEXT {}", string(value)?),
                Criterion::MessageId(value) => {
                    let id = value.trim().trim_start_matches('<').trim_end_matches('>');
                    format!("HEADER Message-ID {}", string(id)?)
                }
                Criterion::Since(date) => format!("SENTSINCE {}", imap_date(*date)),
                Criterion::Before(date) => format!("SENTBEFORE {}", imap_date(*date)),
                Criterion::UidAtMost(uid) => {
                    if *uid == 0 {
                        return Err(Error::invalid("UID must be greater than 0"));
                    }
                    format!("UID 1:{uid}")
                }
                Criterion::Seen(true) => "SEEN".to_owned(),
                Criterion::Seen(false) => "UNSEEN".to_owned(),
                Criterion::Flagged(true) => "FLAGGED".to_owned(),
                Criterion::Flagged(false) => "UNFLAGGED".to_owned(),
            };
            keys.push(key);
        }
        if keys.is_empty() {
            keys.push("ALL".to_owned());
        }
        Ok((keys.join(" "), utf8))
    }
}

/// Emits `value` as an IMAP string.
///
/// Control characters (including CR, LF and NUL) are always rejected. ASCII
/// text becomes a quoted string with `"` and `\` escaped. Non-ASCII text
/// becomes a non-synchronizing literal (`{len+}` CRLF bytes) when the server
/// supports it, because quoted strings are limited to 7-bit characters.
pub fn imap_string(value: &str, literals: Literals) -> Result<String> {
    if value.is_empty() {
        return Err(Error::invalid("search values must not be empty"));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::invalid(
            "search values must not contain control characters",
        ));
    }
    if !value.is_ascii() && literals.allows(value.len()) {
        return Ok(format!("{{{}+}}\r\n{value}", value.len()));
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for c in value.chars() {
        if matches!(c, '"' | '\\') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    Ok(quoted)
}

/// Formats a date as an IMAP `date` (`1-Feb-2026`).
fn imap_date(date: NaiveDate) -> String {
    date.format("%-d-%b-%Y").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn empty_query_matches_all() {
        assert_eq!(
            SearchQuery::new().to_imap(Literals::Unlimited).unwrap(),
            "ALL"
        );
    }

    #[test]
    fn combines_all_criteria() {
        let query = SearchQuery::new()
            .from("alice@example.com")
            .to("bob")
            .subject("Invoice 42")
            .text("hello")
            .since(date(2026, 2, 1))
            .before(date(2026, 10, 15))
            .unread(true)
            .flagged(false);
        assert_eq!(
            query.to_imap(Literals::Unlimited).unwrap(),
            "FROM \"alice@example.com\" TO \"bob\" SUBJECT \"Invoice 42\" TEXT \"hello\" \
             SENTSINCE 1-Feb-2026 SENTBEFORE 15-Oct-2026 UNSEEN UNFLAGGED"
        );
    }

    #[test]
    fn header_keys_hold_as_the_standard_reads_them() {
        use crate::{MessageHeaders, parse::parse_headers};
        let headers = parse_headers(
            b"From: Otter Society <otters@example.net>\r\n\
            To: a@example.com, b@example.com\r\nCc: otters@example.net\r\n\
            Subject: Re: Otter Census notes\r\nDate: Sat, 3 Feb 2001 23:30:00 -0800\r\n\r\n",
        )
        .unwrap();
        let (third, fourth) = (date(2001, 2, 3), date(2001, 2, 4));
        let query = SearchQuery::new;
        for (rule, holds) in [
            (query().from("otter society"), true),
            (query().from("OTTERS@example.net"), true),
            (query().from("Otter Society <otters@example.net>"), true),
            (query().from("beavers@example.net"), false),
            (query().to("b@example.com"), true),
            (query().to("otters@example.net"), false),
            (query().subject(" otter census "), true),
            (query().subject("census otter"), false),
            (query().subject("otter  census"), false),
            (query().since(third), true),
            (query().since(fourth), false),
            (query().before(fourth), true),
            (query().before(third), false),
        ] {
            assert_eq!(rule.matches(&headers), holds, "{rule:?}");
            assert!(rule.checks_headers(), "{rule:?}");
        }
        for rule in [
            query().text("beavers"),
            query().unread(true),
            query().uid_at_most(5),
        ] {
            assert!(rule.matches(&headers) && !rule.checks_headers(), "{rule:?}");
        }
        let missing = MessageHeaders::default();
        assert!(!query().subject("otter census").matches(&missing));
        assert!(!query().since(third).matches(&missing));
        let unclear = parse_headers(
            b"From: <a@example.com> b@example.net\r\n\
            To: a@example.com b@example.com\r\n\r\n",
        )
        .unwrap();
        assert!(query().from("b@example.net").matches(&unclear));
        assert!(!query().from("a@example.comb@example.net").matches(&unclear));
        assert!(!query().to("a@example.com").matches(&unclear));
        let two =
            parse_headers(b"From: a@example.com\r\nFrom: otters@example.net\r\n\r\n").unwrap();
        assert!(query().from("a@example.com").matches(&two));
        assert!(!query().from("otters@example.net").matches(&two));
        assert!(!query().from("com, otters").matches(&two));
        assert!(!query().uid_at_most(5).allows_uid(6));
        assert!(query().allows_uid(6));
    }

    #[test]
    fn header_keys_trim_edges_but_reject_blank_values_and_controls() {
        let query = SearchQuery::new()
            .from(" otter ")
            .to(" a@example.com ")
            .subject(" otter  census ");
        assert_eq!(
            query.to_imap(Literals::Unlimited).unwrap(),
            r#"FROM "otter" TO "a@example.com" SUBJECT "otter  census""#
        );
        assert!(!holds("otter", "   "));
        for value in ["   ", "\notter", "otter\t"] {
            let subject = SearchQuery::new().subject(value);
            assert!(subject.checks_headers());
            assert!(matches!(
                subject.to_imap(Literals::Unlimited),
                Err(Error::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn sorts_only_ascii_queries_by_date() {
        let query = SearchQuery::new().subject("plans").before(date(2026, 3, 1));
        assert_eq!(
            query.to_imap_sort().unwrap().as_deref(),
            Some("(DATE) US-ASCII SUBJECT \"plans\" SENTBEFORE 1-Mar-2026")
        );
        let query = SearchQuery::new().from("bob").subject("Grüße");
        assert_eq!(query.to_imap_sort().unwrap(), None);
        assert!(SearchQuery::new().subject("").to_imap_sort().is_err());
    }

    #[test]
    fn read_and_flagged_filters() {
        let query = SearchQuery::new()
            .unread(false)
            .flagged(true)
            .uid_at_most(42);
        assert_eq!(
            query.to_imap(Literals::Unlimited).unwrap(),
            "SEEN FLAGGED UID 1:42"
        );
        assert!(
            SearchQuery::new()
                .uid_at_most(0)
                .to_imap(Literals::Unlimited)
                .is_err()
        );
    }

    #[test]
    fn escapes_quotes_and_backslashes() {
        let query = SearchQuery::new().subject(r#"say "hi" \o/"#);
        assert_eq!(
            query.to_imap(Literals::Unlimited).unwrap(),
            r#"SUBJECT "say \"hi\" \\o/""#
        );
    }

    #[test]
    fn injection_attempts_are_rejected() {
        for value in [
            "x\" ALL\r\nA1 DELETE INBOX",
            "line\nbreak",
            "carriage\rreturn",
            "nul\0byte",
        ] {
            let err = SearchQuery::new()
                .text(value)
                .to_imap(Literals::Unlimited)
                .unwrap_err();
            assert!(matches!(err, Error::InvalidInput(_)), "{value:?}");
        }
    }

    #[test]
    fn quote_stays_inside_string() {
        let rendered = SearchQuery::new()
            .from("a\" OR ALL \"")
            .to_imap(Literals::Unlimited)
            .unwrap();
        assert_eq!(rendered, r#"FROM "a\" OR ALL \"""#);
    }

    #[test]
    fn empty_values_are_rejected() {
        assert!(
            SearchQuery::new()
                .subject("")
                .to_imap(Literals::Unlimited)
                .is_err()
        );
    }

    #[test]
    fn non_ascii_uses_literals_and_declares_charset() {
        let query = SearchQuery::new().subject("Grüße").from("bob");
        assert_eq!(
            query.to_imap(Literals::Unlimited).unwrap(),
            "CHARSET UTF-8 SUBJECT {7+}\r\nGrüße FROM \"bob\""
        );
    }

    #[test]
    fn non_ascii_falls_back_to_quoted_strings() {
        let query = SearchQuery::new().subject("Grüße");
        assert_eq!(
            query.to_imap(Literals::Unsupported).unwrap(),
            "CHARSET UTF-8 SUBJECT \"Grüße\""
        );
        let long = "ü".repeat(2049);
        let rendered = SearchQuery::new()
            .text(long.as_str())
            .to_imap(Literals::UpTo4096)
            .unwrap();
        assert_eq!(rendered, format!("CHARSET UTF-8 TEXT \"{long}\""));
    }

    #[test]
    fn message_id_strips_angle_brackets() {
        let query = SearchQuery::new().message_id("<abc@example.com>");
        assert_eq!(
            query.to_imap(Literals::Unlimited).unwrap(),
            "HEADER Message-ID \"abc@example.com\""
        );
    }
}
