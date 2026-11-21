//! Raw RFC 5322 messages for providers reached over HTTP instead of IMAP
//! and SMTP, such as Microsoft Graph and the Gmail API, and for drafts
//! saved over IMAP.
//!
//! Those APIs hand out and accept whole MIME messages, so the same parser
//! and composer serve every provider and tools see identical output.

pub use crate::outgoing::reply_message;
use crate::outgoing::{self, Threading};
use crate::{
    AttachmentData, EmailAddress, Message, MessageFlags, MessageHeaders, OutgoingMessage, Reply,
    Result, SentFile,
};

/// A composed message, ready for submission or to save as a draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composed {
    /// `Message-ID`, without angle brackets.
    pub message_id: String,
    /// The raw message, including a `Bcc` header when there are blind
    /// recipients (submission APIs read and strip it; a draft keeps it).
    pub raw: Vec<u8>,
}

/// Parses a complete raw message. Its `uid` is 0: the caller addresses it
/// by the provider's id.
#[must_use]
pub fn parse_message(raw: &[u8], flags: MessageFlags) -> Option<Message> {
    crate::parse::parse_message(0, flags, raw)
}

/// Parses the original for a forward, refusing any displayed body part that could not be read.
#[must_use]
pub fn parse_for_forward(raw: &[u8]) -> Option<Message> {
    let (message, skipped_body_part) = crate::parse::parsed_parts(0, MessageFlags::default(), raw)?;
    let withheld = message
        .html_body
        .as_ref()
        .map_or(message.text_body_withheld, String::is_empty);
    (!withheld && !skipped_body_part).then_some(message)
}

/// Returns one attachment of a raw message.
///
/// `id` counts from 1, as in [`Attachment::id`](crate::Attachment::id). The
/// decoded content is included when it is at most `max_bytes` long. `None`
/// for id 0, an id past the last attachment, or a raw message that does not
/// parse.
#[must_use]
pub fn attachment(raw: &[u8], id: u32, max_bytes: usize) -> Option<AttachmentData> {
    crate::parse::attachment_data(raw, id, max_bytes)
}

/// Lists the attachments of a raw message, numbered as in [`parse_message`], with their bytes as sent.
/// Returns `None` if the message does not parse; an unreadable file is still listed, without its bytes.
#[must_use]
pub fn files(raw: &[u8]) -> Option<Vec<SentFile>> {
    crate::parse::files(raw)
}

/// Parses only the headers of a raw message.
#[must_use]
pub fn parse_headers(raw: &[u8]) -> Option<MessageHeaders> {
    crate::parse::parse_headers(raw)
}

/// The sender of a raw message's headers, when a mail client shows the same address.
///
/// The headers hold one `From`, and it is one address alone or after a name, as in
/// `alice@example.com` or `Alice <alice@example.com>`: that address, with its name. `None` for
/// any other `From`.
#[must_use]
pub fn sender(raw: &[u8]) -> Option<EmailAddress> {
    crate::parse::sender(raw)
}

/// The sender of a message whose `From` headers hold `values`, as [`sender`] finds it.
///
/// `values` are header values such as the Gmail API gives. `None` unless there is one value and
/// a mail client shows the same address. Line breaks in the value count as spaces, so it cannot
/// end its header.
#[must_use]
pub fn sender_of_values(values: &[String]) -> Option<EmailAddress> {
    let [value] = values else {
        return None;
    };
    let block = format!("From: {}\r\n\r\n", value.replace(['\r', '\n'], " "));
    sender(block.as_bytes())
}

/// Whether `address`, given alone as a provider's API gives it, reads as one address.
///
/// It must hold one `@`, with text before and after it, and no whitespace, control character or
/// any of `"(),:;<>[\]`, as the address of a [`sender`] does.
#[must_use]
pub fn clear_address(address: &str) -> bool {
    crate::parse::clear_address(address)
}

/// Whether a value can be written as an unquoted MIME parameter token (RFC 2045, section 5.1).
#[must_use]
pub fn is_parameter_token(value: &str) -> bool {
    !value.is_empty() && crate::parse::token_len(value.as_bytes()) == value.len()
}

/// Composes a new message from `from`.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`](crate::Error::InvalidInput) for a
/// message without recipients, or invalid addresses or headers.
pub fn compose(from: &EmailAddress, message: &OutgoingMessage) -> Result<Composed> {
    compose_with(from, message, None)
}

/// Composes a reply from `from` to the message with `original` headers:
/// recipients, the `Re:` subject and the threading headers are derived
/// from it, as for IMAP accounts.
///
/// # Errors
///
/// As for [`compose`], and [`Error::InvalidInput`](crate::Error::InvalidInput)
/// when `reply.to` is empty and the original's sender does not read as one
/// address, or its `Reply-To` (or, for our own message, its `To`) does not
/// read as addresses, each alone or after a name, and when `reply.reply_all`
/// is set and its `To` or `Cc` does not.
pub fn compose_reply(
    from: &EmailAddress,
    original: &MessageHeaders,
    reply: &Reply,
) -> Result<Composed> {
    let message = reply_message(original, &from.address, reply)?;
    let threading = Threading::reply_to(original);
    compose_with(from, &message, threading.as_ref())
}

fn compose_with(
    from: &EmailAddress,
    message: &OutgoingMessage,
    threading: Option<&Threading>,
) -> Result<Composed> {
    let message_id = outgoing::new_message_id(from);
    let built = outgoing::build_with(from, message, &message_id, threading, true)?;
    Ok(Composed {
        message_id,
        raw: built.formatted(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(raw: &[u8]) -> String {
        String::from_utf8_lossy(raw).into_owned()
    }

    #[test]
    fn composed_messages_keep_blind_recipients_and_parse_back() {
        let from = EmailAddress::with_name("Me", "me@example.com");
        let message = OutgoingMessage {
            to: vec![EmailAddress::new("to@example.com")],
            bcc: vec![EmailAddress::new("hidden@example.com")],
            subject: "Hello".to_owned(),
            text_body: "Body".to_owned(),
            ..OutgoingMessage::default()
        };
        let composed = compose(&from, &message).unwrap();
        let raw = text(&composed.raw);
        assert!(raw.contains("Bcc: hidden@example.com"), "{raw}");
        assert!(composed.message_id.ends_with("@example.com"));
        let parsed = parse_message(&composed.raw, MessageFlags::default()).unwrap();
        assert_eq!(parsed.headers.subject.as_deref(), Some("Hello"));
        assert_eq!(
            parsed.headers.message_id.as_deref(),
            Some(composed.message_id.as_str())
        );
        assert_eq!(parsed.text_body.as_deref().map(str::trim), Some("Body"));
    }

    #[test]
    fn replies_thread_and_address_like_imap_replies() {
        let original = parse_headers(
            b"Message-ID: <a@example.net>\r\nFrom: Friend <friend@example.net>\r\n\
              To: me@example.com\r\nSubject: Plans\r\n\r\nhi",
        )
        .unwrap();
        let from = EmailAddress::new("me@example.com");
        let reply = Reply {
            text_body: "Sure".to_owned(),
            ..Reply::default()
        };
        let composed = compose_reply(&from, &original, &reply).unwrap();
        let headers = parse_headers(&composed.raw).unwrap();
        assert_eq!(headers.subject.as_deref(), Some("Re: Plans"));
        assert_eq!(headers.in_reply_to, vec!["a@example.net".to_owned()]);
        assert_eq!(headers.to[0].address, "friend@example.net");
        assert!(!text(&composed.raw).contains("Bcc:"));
    }

    /// A reply to a sender that does not read as one address, though the parser makes one
    /// address of it, goes only where `to` says.
    #[test]
    fn replies_to_a_sender_that_does_not_read_as_one_address_need_recipients() {
        let original = parse_headers(
            b"Message-ID: <a@example.net>\r\nFrom: Bob <bob@> <example.net>\r\n\
              Subject: Plans\r\n\r\nhi",
        )
        .unwrap();
        assert_eq!(original.from[0].address, "bob@example.net");
        let from = EmailAddress::new("me@example.com");
        assert!(compose_reply(&from, &original, &Reply::default()).is_err());
        let reply = Reply {
            to: vec![EmailAddress::new("friend@example.net")],
            ..Reply::default()
        };
        let composed = compose_reply(&from, &original, &reply).unwrap();
        let headers = parse_headers(&composed.raw).unwrap();
        assert_eq!(headers.to, [EmailAddress::new("friend@example.net")]);
    }

    /// A reply to a `Reply-To`, to the `To` of our own message, or to all, with a `To` or `Cc`,
    /// that does not read as addresses, each alone or after a name, though the parser makes an
    /// address of it, goes only where `to` says.
    #[test]
    fn replies_to_addresses_that_do_not_read_as_addresses_need_recipients() {
        let from = EmailAddress::new("me@example.com");
        let named = Reply {
            to: vec![EmailAddress::new("friend@example.net")],
            ..Reply::default()
        };
        // The header, the original's sender, and whether the reply is to all.
        let cases = [
            ("Reply-To", "friend@example.net", false),
            ("To", "me@example.com", false),
            ("To", "friend@example.net", true),
            ("Cc", "friend@example.net", true),
        ];
        for (header, sender, reply_all) in cases {
            let raw = format!(
                "Message-ID: <a@example.net>\r\nFrom: {sender}\r\n\
                 {header}: Bob <bob@> <example.net>\r\n\r\nhi"
            );
            let original = parse_headers(raw.as_bytes()).unwrap();
            let read = [&original.reply_to[..], &original.to, &original.cc].concat();
            assert_eq!(read, [EmailAddress::with_name("Bob", "bob@example.net")]);
            let reply = Reply {
                reply_all,
                ..Reply::default()
            };
            assert!(compose_reply(&from, &original, &reply).is_err(), "{header}");
            let composed = compose_reply(&from, &original, &named).unwrap();
            let sent = parse_headers(&composed.raw).unwrap();
            assert_eq!(
                sent.to,
                [EmailAddress::new("friend@example.net")],
                "{header}"
            );
            assert_eq!(sent.cc, [], "{header}");
        }
    }

    /// Lists that read as addresses, each alone or after a name, still take replies: with a
    /// comma in a quoted name, an empty group and a folded line.
    #[test]
    fn replies_go_to_address_lists_that_read_as_addresses() {
        let original = parse_headers(
            b"Message-ID: <a@example.net>\r\nFrom: friend@example.net\r\n\
              Reply-To: \"Smith, John\" <john@example.net>, list@example.net\r\n\
              To: undisclosed-recipients:;\r\n\
              Cc: carol@example.net,\r\n Dave <dave@example.net>\r\n\r\nhi",
        )
        .unwrap();
        let from = EmailAddress::new("me@example.com");
        let all = Reply {
            reply_all: true,
            ..Reply::default()
        };
        let composed = compose_reply(&from, &original, &all).unwrap();
        let sent = parse_headers(&composed.raw).unwrap();
        assert_eq!(
            sent.to,
            [
                EmailAddress::with_name("Smith, John", "john@example.net"),
                EmailAddress::new("list@example.net"),
            ]
        );
        assert_eq!(
            sent.cc,
            [
                EmailAddress::new("carol@example.net"),
                EmailAddress::with_name("Dave", "dave@example.net"),
            ]
        );
    }

    #[test]
    fn messages_without_recipients_are_refused() {
        let from = EmailAddress::new("me@example.com");
        assert!(compose(&from, &OutgoingMessage::default()).is_err());
    }

    #[test]
    fn header_values_give_a_sender_when_there_is_one_clear_value() {
        let of = |values: &[&str]| {
            sender_of_values(&values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>())
        };
        assert_eq!(
            of(&["Alice <alice@x.test>"]),
            Some(EmailAddress::with_name("Alice", "alice@x.test"))
        );
        assert_eq!(of(&["<a@y.test> b@x.test"]), None);
        assert_eq!(of(&["alice@x.test", "alice@x.test"]), None);
        assert_eq!(of(&[]), None);
        assert_eq!(of(&["alice@x.test\nb@y.test"]), None);
    }
}
