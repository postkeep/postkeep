//! Message data types returned by IMAP operations.

use std::str::FromStr;

use chrono::{DateTime, FixedOffset};

use crate::{Error, Result};

/// IMAP unique identifier of a message within a folder.
pub type Uid = u32;

/// An email address with an optional display name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailAddress {
    /// Display name, for example `Alice Example`.
    pub name: Option<String>,
    /// Address, for example `alice@example.com`.
    pub address: String,
}

impl EmailAddress {
    /// Creates an address without a display name.
    #[must_use]
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            name: None,
            address: address.into(),
        }
    }

    /// Creates an address with a display name.
    #[must_use]
    pub fn with_name(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            address: address.into(),
        }
    }

    /// Whether two addresses refer to the same mailbox (case-insensitive).
    pub(crate) fn same_mailbox(&self, address: &str) -> bool {
        self.address.eq_ignore_ascii_case(address)
    }
}

impl FromStr for EmailAddress {
    type Err = Error;

    /// Parses `alice@example.com` or `Alice Example <alice@example.com>`.
    fn from_str(value: &str) -> Result<Self> {
        let mailbox: lettre::message::Mailbox = value
            .trim()
            .parse()
            .map_err(|_| Error::invalid(format!("invalid email address: {value}")))?;
        Ok(Self {
            name: mailbox.name,
            address: mailbox.email.to_string(),
        })
    }
}

/// IMAP system flags of a message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors the independent IMAP system flags"
)]
pub struct MessageFlags {
    /// `\Seen`: the message has been read.
    pub seen: bool,
    /// `\Answered`: the message has been replied to.
    pub answered: bool,
    /// `\Flagged`: the message is flagged for attention.
    pub flagged: bool,
    /// `\Deleted`: the message is marked for removal.
    pub deleted: bool,
    /// `\Draft`: the message is a draft.
    pub draft: bool,
}

impl MessageFlags {
    pub(crate) fn from_imap<'a>(flags: impl Iterator<Item = async_imap::types::Flag<'a>>) -> Self {
        use async_imap::types::Flag as ImapFlag;
        flags.fold(Self::default(), |mut acc, flag| {
            match flag {
                ImapFlag::Seen => acc.seen = true,
                ImapFlag::Answered => acc.answered = true,
                ImapFlag::Flagged => acc.flagged = true,
                ImapFlag::Deleted => acc.deleted = true,
                ImapFlag::Draft => acc.draft = true,
                _ => {}
            }
            acc
        })
    }
}

/// A flag that can be set or cleared with
/// [`ImapSession::set_flag`](crate::ImapSession::set_flag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// `\Seen` (read).
    Seen,
    /// `\Flagged` (starred / flagged).
    Flagged,
    /// `\Answered` (replied).
    Answered,
}

impl Flag {
    pub(crate) const fn as_imap(self) -> &'static str {
        match self {
            Self::Seen => "\\Seen",
            Self::Flagged => "\\Flagged",
            Self::Answered => "\\Answered",
        }
    }
}

/// A short description of a message, as returned by searches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageSummary {
    /// UID of the message in the searched folder.
    pub uid: Uid,
    /// First `From` address.
    pub from: Option<EmailAddress>,
    /// Whether a mail client shows `from` as the sender's address, as
    /// [`mime::sender`](crate::mime::sender) finds.
    pub from_clear: bool,
    /// The value of each `From` header as sent, in their order.
    pub from_values: Vec<String>,
    /// Decoded subject.
    pub subject: Option<String>,
    /// `Date` header, falling back to the server's internal date.
    pub date: Option<DateTime<FixedOffset>>,
    /// System flags.
    pub flags: MessageFlags,
    /// Size of the raw message in bytes.
    pub size: Option<u32>,
}

/// One page of search results, newest messages first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResults {
    /// Highest UID listed by the server, before checking headers and paging.
    pub last_uid: Option<Uid>,
    /// Total number of messages matching the query, or an upper bound when estimated.
    pub total: usize,
    /// Whether `total` includes messages the server listed that postkeep has not checked.
    pub estimated: bool,
    /// Offset of the first returned message within all matches.
    pub offset: usize,
    /// The messages on this page.
    pub messages: Vec<MessageSummary>,
    /// The folder's UIDVALIDITY when it was searched, `None` if the server
    /// reported none.
    pub uid_validity: Option<u32>,
}

/// Which page of results to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Paging {
    /// Number of matches to skip, counted from the newest message.
    pub offset: usize,
    /// Maximum number of messages to return, capped at [`Paging::MAX_LIMIT`].
    pub limit: usize,
}

impl Paging {
    /// Largest accepted page size.
    pub const MAX_LIMIT: usize = 500;

    /// Creates a page specification.
    #[must_use]
    pub const fn new(offset: usize, limit: usize) -> Self {
        Self { offset, limit }
    }
}

impl Default for Paging {
    fn default() -> Self {
        Self::new(0, 25)
    }
}

/// Selected headers of a message. Message IDs are stored without angle
/// brackets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag says whether one header reads as its parsed addresses"
)]
pub struct MessageHeaders {
    /// `Message-ID`.
    pub message_id: Option<String>,
    /// `In-Reply-To` message IDs.
    pub in_reply_to: Vec<String>,
    /// `References` message IDs.
    pub references: Vec<String>,
    /// `From` addresses.
    pub from: Vec<EmailAddress>,
    /// Whether a mail client shows the one address of `from` as the sender, as
    /// [`mime::sender`](crate::mime::sender) finds.
    pub from_clear: bool,
    /// The value of each `From` header as sent, in their order.
    pub from_values: Vec<String>,
    /// `To` addresses.
    pub to: Vec<EmailAddress>,
    /// Whether a mail client shows the addresses of `to` as the `To`: there is no `To` header,
    /// or there is one and each part of its value between commas that holds an `@` is the next
    /// of them, alone or after a name.
    pub to_clear: bool,
    /// `Cc` addresses.
    pub cc: Vec<EmailAddress>,
    /// Whether a mail client shows the addresses of `cc` as the `Cc`, as for
    /// [`to_clear`](Self::to_clear).
    pub cc_clear: bool,
    /// `Reply-To` addresses.
    pub reply_to: Vec<EmailAddress>,
    /// Whether a mail client shows the addresses of `reply_to` as the `Reply-To`, as for
    /// [`to_clear`](Self::to_clear).
    pub reply_to_clear: bool,
    /// Decoded subject.
    pub subject: Option<String>,
    /// `Date` header.
    pub date: Option<DateTime<FixedOffset>>,
}

/// Metadata about an attachment. [`AttachmentData`] carries its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// Position among the message's attachments, from 1; the same raw
    /// message always gives the same ids.
    pub id: u32,
    /// File name, if the sender provided one.
    pub filename: Option<String>,
    /// MIME type, for example `application/pdf`. A part without a Content-Type is `text/plain`, or
    /// `message/rfc822` in a `multipart/digest`, as mail apps read it.
    pub content_type: String,
    /// Decoded size in bytes.
    pub size: usize,
    /// `Content-ID`, used by inline images.
    pub content_id: Option<String>,
    /// Whether the part is marked `Content-Disposition: inline`.
    pub inline: bool,
}

/// An attachment with its decoded content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentData {
    /// The attachment's metadata.
    pub attachment: Attachment,
    /// Decoded content (text parts as UTF-8), or `None` when the attachment did not decode cleanly
    /// (`decoded` is false) or is larger than the `max_bytes` the caller passed.
    pub content: Option<Vec<u8>>,
    /// Whether the attachment decoded cleanly. It did not when its base64 or quoted-printable is broken
    /// or cut off, when its transfer encoding is one the parser doesn't decode or one a mail client
    /// may read differently, when the parser read it as text in a `charset` a mail client may read
    /// otherwise, or as text mail apps may convert otherwise (from UTF-7, say, or from bytes that
    /// are not UTF-8 without a charset), when it is not text and its bytes changed when the parser
    /// could only read it as text (a file cut off at the end of the message, say), or when a mail
    /// client may read the message's parts differently before its end, as when it runs past a
    /// boundary line, a part has Content-Type headers that differ or a type a mail client may read
    /// differently, or a multipart has a `boundary` one may read differently: its bytes may then
    /// differ from what the person's mail app opens.
    pub decoded: bool,
}

/// A listed file with its bytes as sent, before any charset conversion.
pub struct SentFile {
    /// The same metadata and id as in a message's attachment list.
    pub attachment: Attachment,
    /// The file's declared charset, if any.
    pub charset: Option<String>,
    /// The transfer-decoded bytes, or `None` if a mail app may decode them differently.
    pub content: Option<Vec<u8>>,
}

/// A part of the body, as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyPart {
    /// A `text/html` part's HTML.
    Html(String),
    /// A plain-text part's text.
    Text(String),
}

/// A fully fetched and parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// UID of the message in its folder.
    pub uid: Uid,
    /// System flags.
    pub flags: MessageFlags,
    /// Parsed headers.
    pub headers: MessageHeaders,
    /// Plain-text body: the first plain-text body part a mail app shows (of an alternative,
    /// the last member it can show, one without HTML when there is one; of a
    /// `multipart/related`, its root), or else a `text/markdown` body part.
    pub text_body: Option<String>,
    /// Whether `text_body` is empty on purpose: the plain-text part a mail app shows did not
    /// decode (its base64 or quoted-printable is broken, its transfer encoding is one the parser
    /// doesn't decode, its `charset` is written in a way a mail client may read differently, its
    /// text is in a charset mail apps may convert otherwise, or mail-parser lists it as an
    /// attachment), or
    /// every plain-text body part is in a part a mail app doesn't show (an alternative member
    /// it passes over, showing an image there, say, or a part of a `multipart/related` other
    /// than its root), or a mail client may read the message's parts differently from the
    /// parser.
    pub text_body_withheld: bool,
    /// HTML body, only when the message has an HTML part; empty when that part can't be decoded,
    /// or a mail client may read the parts differently, or when the alternative member a mail
    /// app shows has no HTML part while another member does, or when a `multipart/related` part
    /// holding HTML has a `start` that names a part other than its first.
    pub html_body: Option<String>,
    /// Every part a mail app shows one after another, in that order, when there are several: the body
    /// part (`html_body`, else `text_body`) and the text and HTML parts a mail app shows with it, such as
    /// a second HTML part in `multipart/mixed`, each as sent. A part that did not decode is left out.
    /// Empty when the body part is the only one, the body is empty on purpose, or a mail client may read
    /// the parts differently from the parser.
    pub body_parts: Vec<BodyPart>,
    /// Attachment metadata.
    pub attachments: Vec<Attachment>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_addresses() {
        let plain: EmailAddress = "alice@example.com".parse().unwrap();
        assert_eq!(plain, EmailAddress::new("alice@example.com"));
        let named: EmailAddress = "Alice Example <alice@example.com>".parse().unwrap();
        assert_eq!(
            named,
            EmailAddress::with_name("Alice Example", "alice@example.com")
        );
        assert!("not-an-address".parse::<EmailAddress>().is_err());
    }

    #[test]
    fn maps_imap_flags() {
        use async_imap::types::Flag as ImapFlag;
        let flags = MessageFlags::from_imap(
            [ImapFlag::Seen, ImapFlag::Flagged, ImapFlag::Recent].into_iter(),
        );
        assert!(flags.seen && flags.flagged);
        assert!(!flags.answered && !flags.deleted && !flags.draft);
    }
}
