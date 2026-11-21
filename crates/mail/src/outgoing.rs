//! Building outgoing messages and replies.

use std::fmt;

use lettre::message::header::{
    ContentDisposition, ContentId, ContentTransferEncoding, ContentType, Header, HeaderName,
    HeaderValue,
};
use lettre::message::{Body, Mailbox, MultiPart, SinglePart};

use crate::{EmailAddress, Error, MessageHeaders, Result};

/// Maximum number of message IDs kept in a `References` header.
const MAX_REFERENCES: usize = 20;

/// A new message to send.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OutgoingMessage {
    /// `To` recipients.
    pub to: Vec<EmailAddress>,
    /// `Cc` recipients.
    pub cc: Vec<EmailAddress>,
    /// `Bcc` recipients. They receive the message but are not listed in it.
    pub bcc: Vec<EmailAddress>,
    /// Subject line.
    pub subject: String,
    /// Plain text body.
    pub text_body: String,
    /// Optional HTML alternative of the body.
    pub html_body: Option<String>,
    /// Files to attach, in order.
    pub attachments: Vec<OutgoingAttachment>,
}

/// The content of a reply. The subject, the threading headers and, unless
/// `to` names them, the recipients are derived from the original message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reply {
    /// Plain text body.
    pub text_body: String,
    /// Optional HTML alternative of the body.
    pub html_body: Option<String>,
    /// Files to attach, in order.
    pub attachments: Vec<OutgoingAttachment>,
    /// Also reply to every `To` and `Cc` recipient of the original. Refused unless both read as
    /// addresses ([`MessageHeaders::to_clear`], [`MessageHeaders::cc_clear`]).
    pub reply_all: bool,
    /// Recipients to reply to instead of the original's sender or `Reply-To`. Needed when the
    /// sender does not read as one address ([`MessageHeaders::from_clear`]), when the `Reply-To`
    /// does not read as addresses ([`MessageHeaders::reply_to_clear`]), and for a reply to our
    /// own message when its `To` does not ([`MessageHeaders::to_clear`]).
    pub to: Vec<EmailAddress>,
}

/// A file to include as a MIME attachment.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingAttachment {
    /// The file name shown to the recipient, or empty for an unnamed file.
    pub filename: String,
    /// MIME type, such as `application/pdf`.
    pub content_type: String,
    /// The decoded file bytes.
    pub content: Vec<u8>,
    /// Content-ID, without angle brackets.
    pub content_id: Option<String>,
    /// Whether the original marked this file inline.
    pub inline: bool,
}

impl fmt::Debug for OutgoingAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutgoingAttachment")
            .field("size", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// Threading headers for a reply. IDs are stored without angle brackets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Threading {
    pub in_reply_to: String,
    pub references: Vec<String>,
}

impl Threading {
    /// Derives `In-Reply-To` and `References` for a reply to `original`
    /// (RFC 5322, section 3.6.4). Returns `None` when the original has no
    /// `Message-ID`, in which case no threading headers can be set.
    pub fn reply_to(original: &MessageHeaders) -> Option<Self> {
        let parent = original.message_id.clone()?;
        let mut references = if original.references.is_empty() {
            original.in_reply_to.clone()
        } else {
            original.references.clone()
        };
        references.retain(|id| *id != parent);
        references.push(parent.clone());
        if references.len() > MAX_REFERENCES {
            // Keep the thread root plus the most recent ancestors.
            references.drain(1..=references.len() - MAX_REFERENCES);
        }
        Some(Self {
            in_reply_to: parent,
            references,
        })
    }
}

/// Resolves the outgoing message for a reply to `original`.
///
/// The reply goes to `reply.to` when it names recipients, otherwise to the original's
/// `Reply-To` or sender, or to its recipients when the original is from `own_address`.
///
/// # Errors
///
/// Returns [`Error::InvalidInput`] when a mail app may show other addresses than the reply would
/// go to: `reply.to` is empty and the original's sender does not read as one address
/// ([`MessageHeaders::from_clear`]), its `Reply-To` does not read as addresses
/// ([`MessageHeaders::reply_to_clear`]) or, when it is our own, its `To` does not
/// ([`MessageHeaders::to_clear`]); or `reply.reply_all` is set and its `To` or `Cc` does not.
pub fn reply_message(
    original: &MessageHeaders,
    own_address: &str,
    reply: &Reply,
) -> Result<OutgoingMessage> {
    if reply.to.is_empty() && !original.from_clear {
        return Err(Error::invalid(
            "the message's sender does not read as one address, alone or after a name: \
             name the recipients in `to`",
        ));
    }
    if reply.to.is_empty() && !original.reply_to_clear {
        return Err(Error::invalid(
            "the message's Reply-To does not read as addresses, each alone or after a name: \
             name the recipients in `to`",
        ));
    }
    if reply.reply_all && !(original.to_clear && original.cc_clear) {
        return Err(Error::invalid(
            "the message's To or Cc does not read as addresses, each alone or after a name: \
             leave out reply_all and name the recipients in `to`",
        ));
    }
    let mut to: Vec<EmailAddress> = if original.reply_to.is_empty() {
        original.from.clone()
    } else {
        original.reply_to.clone()
    };
    // Replying to our own sent message goes to its original recipients.
    if to.iter().all(|addr| addr.same_mailbox(own_address)) {
        if reply.to.is_empty() && !original.to_clear {
            return Err(Error::invalid(
                "the message's To does not read as addresses, each alone or after a name: \
                 name the recipients in `to`",
            ));
        }
        to.clone_from(&original.to);
    }
    if !reply.to.is_empty() {
        to.clone_from(&reply.to);
    }
    let mut cc = Vec::new();
    if reply.reply_all {
        for addr in original.to.iter().chain(&original.cc) {
            let duplicate = to
                .iter()
                .chain(&cc)
                .any(|existing: &EmailAddress| existing.same_mailbox(&addr.address));
            if !duplicate && !addr.same_mailbox(own_address) {
                cc.push(addr.clone());
            }
        }
    }
    Ok(OutgoingMessage {
        to,
        cc,
        bcc: Vec::new(),
        subject: reply_subject(original.subject.as_deref().unwrap_or_default()),
        text_body: reply.text_body.clone(),
        html_body: reply.html_body.clone(),
        attachments: reply.attachments.clone(),
    })
}

/// Prefixes `Re: ` unless the subject already starts with it.
fn reply_subject(subject: &str) -> String {
    let trimmed = subject.trim();
    let has_prefix = trimmed
        .get(..3)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("re:"));
    if has_prefix {
        trimmed.to_owned()
    } else if trimmed.is_empty() {
        "Re:".to_owned()
    } else {
        format!("Re: {trimmed}")
    }
}

/// Assembles an RFC 5322 message ready for SMTP submission. The `Bcc`
/// header is left out; SMTP takes those recipients from the envelope.
pub fn build(
    from: &EmailAddress,
    message: &OutgoingMessage,
    message_id: &str,
    threading: Option<&Threading>,
) -> Result<lettre::Message> {
    build_with(from, message, message_id, threading, false)
}

/// Like [`build`], optionally keeping the `Bcc` header for submission
/// APIs that read recipients from the message itself.
pub fn build_with(
    from: &EmailAddress,
    message: &OutgoingMessage,
    message_id: &str,
    threading: Option<&Threading>,
    keep_bcc: bool,
) -> Result<lettre::Message> {
    if message.to.is_empty() && message.cc.is_empty() && message.bcc.is_empty() {
        return Err(Error::invalid("a message needs at least one recipient"));
    }
    reject_line_breaks("subject", &message.subject)?;
    let mut builder = lettre::Message::builder()
        .from(mailbox(from)?)
        .subject(message.subject.as_str())
        .message_id(Some(format!("<{message_id}>")));
    if keep_bcc {
        builder = builder.keep_bcc();
    }
    for addr in &message.to {
        builder = builder.to(mailbox(addr)?);
    }
    for addr in &message.cc {
        builder = builder.cc(mailbox(addr)?);
    }
    for addr in &message.bcc {
        builder = builder.bcc(mailbox(addr)?);
    }
    if let Some(threading) = threading {
        builder = builder
            .in_reply_to(format!("<{}>", threading.in_reply_to))
            .references(
                threading
                    .references
                    .iter()
                    .map(|id| format!("<{id}>"))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
    }
    let text = || {
        SinglePart::builder()
            .header(ContentType::TEXT_PLAIN)
            .body(message.text_body.clone())
    };
    let mut related = None;
    let mut attachments = Vec::new();
    for file in &message.attachments {
        if let Some(html) = &message.html_body
            && file.inline
            && file.content_id.is_some()
        {
            let part = related
                .take()
                .unwrap_or_else(|| MultiPart::related().singlepart(SinglePart::html(html.clone())));
            related = Some(part.singlepart(file.part(true)?));
        } else {
            attachments.push(file.part(false)?);
        }
    }
    let alternative = message.html_body.as_ref().map(|html| {
        let alternative = MultiPart::alternative().singlepart(text());
        match related {
            Some(related) => alternative.multipart(related),
            None => alternative.singlepart(SinglePart::html(html.clone())),
        }
    });
    Ok(if attachments.is_empty() {
        match alternative {
            Some(alternative) => builder.multipart(alternative),
            None => builder.singlepart(text()),
        }
    } else {
        let mixed = MultiPart::mixed();
        let mut mixed = match alternative {
            Some(alternative) => mixed.multipart(alternative),
            None => mixed.singlepart(text()),
        };
        for attachment in attachments {
            mixed = mixed.singlepart(attachment);
        }
        builder.multipart(mixed)
    }?)
}

/// lettre's attachment disposition constructor always writes a filename.
#[derive(Clone)]
struct UnnamedAttachment;

impl Header for UnnamedAttachment {
    fn name() -> HeaderName {
        HeaderName::new_from_ascii_str("Content-Disposition")
    }

    fn parse(s: &str) -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        (s == "attachment")
            .then_some(Self)
            .ok_or_else(|| "expected attachment disposition".into())
    }

    fn display(&self) -> HeaderValue {
        HeaderValue::new(Self::name(), "attachment".to_owned())
    }
}

impl OutgoingAttachment {
    /// Checks whether a Content-ID can be written in angle brackets without changing it.
    #[must_use]
    pub fn valid_content_id(id: &str) -> bool {
        !id.is_empty()
            && id
                .bytes()
                .all(|b| b.is_ascii_graphic() && !b"<>".contains(&b))
    }

    fn is_message(&self) -> bool {
        self.content_type
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("message/"))
    }

    fn invalid(&self, reason: &str) -> Error {
        Error::invalid(format!("attachment {:?}: {reason}", self.filename))
    }

    /// Checks whether a `message/*` file can be sent unchanged as 7bit or 8bit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for NUL, lone CR or LF, or lines longer than 998 bytes.
    pub fn validate_content(&self) -> Result<()> {
        if self.is_message()
            && self
                .content
                .split_inclusive(|&byte| byte == b'\n')
                .any(|line| {
                    let data = line.strip_suffix(b"\r\n").unwrap_or(line);
                    data.len() > 998
                        || data
                            .iter()
                            .any(|&byte| matches!(byte, b'\0' | b'\r' | b'\n'))
                })
        {
            return Err(self.invalid(
                "7bit or 8bit needs CRLF line breaks, at most 998 bytes per line and no NUL bytes",
            ));
        }
        Ok(())
    }

    /// Checks that the file has a MIME type the composer can write.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for a type that cannot be written.
    pub fn validate_content_type(&self) -> Result<()> {
        self.parsed_content_type().map(drop)
    }

    fn parsed_content_type(&self) -> Result<ContentType> {
        ContentType::parse(&self.content_type).map_err(|_| self.invalid("invalid content_type"))
    }

    fn part(&self, inline: bool) -> Result<SinglePart> {
        let content_type = self.parsed_content_type()?;
        self.validate_content()?;
        let body = if self.is_message() {
            // Pass the validated bytes unchanged; lettre's chooser uses a shorter line limit.
            let encoding = if self.content.is_ascii() {
                ContentTransferEncoding::SevenBit
            } else {
                ContentTransferEncoding::EightBit
            };
            Body::dangerous_pre_encoded(self.content.clone(), encoding)
        } else {
            Body::new_with_encoding(self.content.clone(), ContentTransferEncoding::Base64)
                .map_err(|_| self.invalid("could not encode as base64"))?
        };
        let mut part = SinglePart::builder();
        if let Some(id) = &self.content_id {
            if !Self::valid_content_id(id) {
                return Err(self.invalid("invalid Content-ID"));
            }
            part = part.header(ContentId::from(format!("<{id}>")));
        }
        part = match (inline, self.filename.is_empty()) {
            (true, true) => part.header(ContentDisposition::inline()),
            (true, false) => part.header(ContentDisposition::inline_with_name(&self.filename)),
            (false, true) => part.header(UnnamedAttachment),
            (false, false) => part.header(ContentDisposition::attachment(&self.filename)),
        };
        Ok(part.header(content_type).body(body))
    }
}

/// Creates a new globally unique message ID (without angle brackets) in the
/// sender's domain.
pub fn new_message_id(from: &EmailAddress) -> String {
    let domain = from
        .address
        .rsplit_once('@')
        .map_or("localhost", |(_, domain)| domain);
    format!("{}@{domain}", uuid::Uuid::new_v4().simple())
}

fn mailbox(addr: &EmailAddress) -> Result<Mailbox> {
    if let Some(name) = &addr.name {
        reject_line_breaks("display name", name)?;
    }
    let email = addr
        .address
        .trim()
        .parse()
        .map_err(|_| Error::invalid(format!("invalid email address: {}", addr.address)))?;
    Ok(Mailbox::new(addr.name.clone(), email))
}

fn reject_line_breaks(field: &str, value: &str) -> Result<()> {
    if value.contains(['\r', '\n']) {
        return Err(Error::invalid(format!(
            "{field} must not contain line breaks"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "me@icloud.com";

    fn original() -> MessageHeaders {
        MessageHeaders {
            message_id: Some("parent@example.com".to_owned()),
            references: vec!["root@example.com".to_owned(), "mid@example.com".to_owned()],
            in_reply_to: vec!["mid@example.com".to_owned()],
            from: vec![EmailAddress::with_name("Alice", "alice@example.com")],
            from_clear: true,
            to: vec![EmailAddress::new(ME), EmailAddress::new("bob@example.com")],
            to_clear: true,
            cc: vec![
                EmailAddress::new("carol@example.com"),
                EmailAddress::new("ALICE@example.com"),
            ],
            cc_clear: true,
            reply_to_clear: true,
            subject: Some("Plans".to_owned()),
            ..MessageHeaders::default()
        }
    }

    fn formatted(message: &lettre::Message) -> String {
        String::from_utf8(message.formatted()).unwrap()
    }

    #[test]
    fn threading_appends_parent_to_references() {
        let threading = Threading::reply_to(&original()).unwrap();
        assert_eq!(threading.in_reply_to, "parent@example.com");
        assert_eq!(
            threading.references,
            ["root@example.com", "mid@example.com", "parent@example.com"]
        );
    }

    #[test]
    fn threading_falls_back_to_in_reply_to() {
        let headers = MessageHeaders {
            references: Vec::new(),
            ..original()
        };
        let threading = Threading::reply_to(&headers).unwrap();
        assert_eq!(
            threading.references,
            ["mid@example.com", "parent@example.com"]
        );
    }

    #[test]
    fn threading_requires_message_id() {
        let headers = MessageHeaders {
            message_id: None,
            ..original()
        };
        assert_eq!(Threading::reply_to(&headers), None);
    }

    #[test]
    fn threading_caps_reference_count() {
        let headers = MessageHeaders {
            references: (0..30).map(|i| format!("id{i}@example.com")).collect(),
            ..original()
        };
        let threading = Threading::reply_to(&headers).unwrap();
        assert_eq!(threading.references.len(), MAX_REFERENCES);
        assert_eq!(threading.references[0], "id0@example.com");
        assert_eq!(
            threading.references[MAX_REFERENCES - 1],
            "parent@example.com"
        );
    }

    #[test]
    fn reply_goes_to_sender_only() {
        let reply = reply_message(&original(), ME, &Reply::default()).unwrap();
        assert_eq!(
            reply.to,
            [EmailAddress::with_name("Alice", "alice@example.com")]
        );
        assert_eq!(reply.cc, []);
        assert_eq!(reply.subject, "Re: Plans");
    }

    #[test]
    fn reply_all_excludes_self_and_duplicates() {
        let options = Reply {
            reply_all: true,
            ..Reply::default()
        };
        let reply = reply_message(&original(), ME, &options).unwrap();
        assert_eq!(
            reply.cc,
            [
                EmailAddress::new("bob@example.com"),
                EmailAddress::new("carol@example.com"),
            ]
        );
    }

    #[test]
    fn reply_prefers_reply_to() {
        let headers = MessageHeaders {
            reply_to: vec![EmailAddress::new("list@example.com")],
            ..original()
        };
        let reply = reply_message(&headers, ME, &Reply::default()).unwrap();
        assert_eq!(reply.to, [EmailAddress::new("list@example.com")]);
    }

    #[test]
    fn reply_to_own_message_targets_original_recipients() {
        let headers = MessageHeaders {
            from: vec![EmailAddress::new(ME)],
            to: vec![EmailAddress::new("bob@example.com")],
            ..original()
        };
        let reply = reply_message(&headers, ME, &Reply::default()).unwrap();
        assert_eq!(reply.to, [EmailAddress::new("bob@example.com")]);
    }

    #[test]
    fn a_reply_to_a_sender_that_does_not_read_as_one_address_needs_recipients() {
        let headers = MessageHeaders {
            from_clear: false,
            ..original()
        };
        let err = reply_message(&headers, ME, &Reply::default()).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "{err}");
        let reply = Reply {
            to: vec![EmailAddress::new("alice@example.com")],
            ..Reply::default()
        };
        let sent = reply_message(&headers, ME, &reply).unwrap();
        assert_eq!(sent.to, [EmailAddress::new("alice@example.com")]);
    }

    /// A reply to all is refused, even with `to`, unless both `To` and `Cc` read as addresses;
    /// a reply to the sender alone is not.
    #[test]
    fn a_reply_to_all_needs_a_to_and_cc_that_read_as_addresses() {
        let all = Reply {
            reply_all: true,
            ..Reply::default()
        };
        let named = Reply {
            to: vec![EmailAddress::new("alice@example.com")],
            ..all.clone()
        };
        for (to_clear, cc_clear) in [(false, true), (true, false)] {
            let headers = MessageHeaders {
                to_clear,
                cc_clear,
                ..original()
            };
            for reply in [&all, &named] {
                let err = reply_message(&headers, ME, reply).unwrap_err();
                assert!(matches!(err, Error::InvalidInput(_)), "{err}");
            }
            let sent = reply_message(&headers, ME, &Reply::default()).unwrap();
            assert_eq!(
                sent.to,
                [EmailAddress::with_name("Alice", "alice@example.com")]
            );
            assert_eq!(sent.cc, []);
        }
    }

    #[test]
    fn given_recipients_replace_the_derived_ones() {
        let reply = Reply {
            to: vec![EmailAddress::new("dave@example.com")],
            ..Reply::default()
        };
        let listed = MessageHeaders {
            reply_to: vec![EmailAddress::new("list@example.com")],
            ..original()
        };
        let own = MessageHeaders {
            from: vec![EmailAddress::new(ME)],
            ..original()
        };
        for headers in [listed, own] {
            let sent = reply_message(&headers, ME, &reply).unwrap();
            assert_eq!(sent.to, [EmailAddress::new("dave@example.com")]);
        }
    }

    #[test]
    fn reply_subject_prefix() {
        assert_eq!(reply_subject("Hello"), "Re: Hello");
        assert_eq!(reply_subject("RE: Hello"), "RE: Hello");
        assert_eq!(reply_subject("re:Hello"), "re:Hello");
        assert_eq!(reply_subject(""), "Re:");
        assert_eq!(reply_subject("Résumé"), "Re: Résumé");
    }

    #[test]
    fn builds_reply_headers() {
        let from = EmailAddress::new(ME);
        let threading = Threading::reply_to(&original()).unwrap();
        let outgoing = reply_message(
            &original(),
            ME,
            &Reply {
                text_body: "Sounds good".to_owned(),
                ..Reply::default()
            },
        )
        .unwrap();
        let message = build(&from, &outgoing, "new@icloud.com", Some(&threading)).unwrap();
        let raw = formatted(&message);
        assert!(raw.contains("Message-ID: <new@icloud.com>\r\n"), "{raw}");
        assert!(
            raw.contains("In-Reply-To: <parent@example.com>\r\n"),
            "{raw}"
        );
        assert!(
            raw.contains(
                "References: <root@example.com> <mid@example.com> <parent@example.com>\r\n"
            ),
            "{raw}"
        );
        assert!(raw.contains("Subject: Re: Plans\r\n"), "{raw}");
        assert!(raw.contains("To: Alice <alice@example.com>\r\n"), "{raw}");
        assert!(raw.contains("Sounds good"), "{raw}");
    }

    #[test]
    fn relates_only_inline_ids_and_keeps_nameless_parts() {
        let file = |filename: &str, content_type: &str, id: &str, inline| OutgoingAttachment {
            filename: filename.to_owned(),
            content_type: content_type.to_owned(),
            content: vec![1, 2, 3],
            content_id: Some(id.to_owned()),
            inline,
        };
        let message = OutgoingMessage {
            to: vec![EmailAddress::new("recipient@example.org")],
            text_body: "One".to_owned(),
            html_body: Some("<img src=\"cid:logo@example.org\">".to_owned()),
            attachments: vec![
                file("logo.png", "image/png", "logo@example.org", true),
                file("", "application/pdf", "pdf@example.org", false),
            ],
            ..OutgoingMessage::default()
        };
        let raw = crate::mime::compose(&EmailAddress::new("sender@example.org"), &message)
            .unwrap()
            .raw;
        let text = String::from_utf8(raw.clone()).unwrap();
        assert!(text.contains("multipart/mixed"));
        assert!(text.contains("multipart/related"));
        assert!(text.contains("Content-Disposition: attachment\r\n"));
        let files = crate::mime::files(&raw).unwrap();
        let [logo, pdf] = &files[..] else {
            unreachable!()
        };
        assert!(logo.attachment.inline);
        assert_eq!(
            logo.attachment.content_id.as_deref(),
            Some("logo@example.org")
        );
        assert_eq!(logo.attachment.filename.as_deref(), Some("logo.png"));
        assert!(!pdf.attachment.inline);
        assert_eq!(pdf.attachment.filename, None);
        assert_eq!(
            pdf.attachment.content_id.as_deref(),
            Some("pdf@example.org")
        );
        assert_eq!(pdf.content.as_deref(), Some([1, 2, 3].as_slice()));
    }

    #[test]
    fn builds_html_alternative() {
        let message = OutgoingMessage {
            to: vec![EmailAddress::new("bob@example.com")],
            subject: "Hi".to_owned(),
            text_body: "plain".to_owned(),
            html_body: Some("<b>html</b>".to_owned()),
            ..OutgoingMessage::default()
        };
        let built = build(&EmailAddress::new(ME), &message, "x@icloud.com", None).unwrap();
        let raw = formatted(&built);
        assert!(raw.contains("multipart/alternative"), "{raw}");
        assert!(!raw.contains("In-Reply-To"), "{raw}");
    }

    #[test]
    fn builds_attachments_without_changing_bytes() {
        let message = OutgoingMessage {
            attachments: [
                ("test.pdf", "application/pdf", &b"%PDF-1.4\n\xff"[..]),
                ("faktúra.pdf", "application/pdf", &b"%PDF-1.4"[..]),
                ("empty", "application/octet-stream", &b""[..]),
                ("data.csv", "text/csv", &b"a,b\n1,2\n"[..]),
            ]
            .into_iter()
            .map(|(filename, content_type, content)| OutgoingAttachment {
                filename: filename.to_owned(),
                content_type: content_type.to_owned(),
                content: content.to_vec(),
                content_id: None,
                inline: false,
            })
            .collect(),
            to: vec![EmailAddress::new("recipient@example.com")],
            text_body: "plain".to_owned(),
            html_body: Some("<b>html</b>".to_owned()),
            ..OutgoingMessage::default()
        };
        let raw = crate::mime::compose(&EmailAddress::new(ME), &message)
            .unwrap()
            .raw;
        let text = std::str::from_utf8(&raw).unwrap();
        assert!(text.contains("multipart/mixed") && text.contains("multipart/alternative"));
        assert!(text.contains("fakt%C3%BAra.pdf"), "{text}");
        assert_eq!(text.matches("Content-Transfer-Encoding: base64").count(), 4);
        let parsed = crate::mime::parse_message(&raw, crate::MessageFlags::default()).unwrap();
        assert_eq!(parsed.attachments.len(), message.attachments.len());
        for (actual, expected) in parsed.attachments.iter().zip(message.attachments) {
            assert_eq!(actual.filename.as_deref(), Some(expected.filename.as_str()));
            assert_eq!(actual.content_type, expected.content_type);
            assert_eq!(
                crate::mime::attachment(&raw, actual.id, 100)
                    .unwrap()
                    .content,
                Some(expected.content)
            );
        }
    }

    #[test]
    fn message_files_use_7bit_or_8bit_and_bad_files_fail_by_name() {
        let mut message = OutgoingMessage {
            attachments: vec![OutgoingAttachment {
                filename: "original.eml".to_owned(),
                content_id: None,
                inline: false,
                content_type: "message/rfc822".to_owned(),
                content:
                    b"From: sender@example.com\r\nSubject: Old mail\r\n\r\nAn original message.\r\n"
                        .to_vec(),
            }],
            to: vec![EmailAddress::new("recipient@example.com")],
            ..OutgoingMessage::default()
        };
        let compose =
            |message: &OutgoingMessage| crate::mime::compose(&EmailAddress::new(ME), message);
        let raw = compose(&message).unwrap().raw;
        let nested = crate::mime::attachment(&raw, 1, 100).unwrap();
        assert_eq!(nested.attachment.content_type, "message/rfc822");
        let parsed =
            crate::mime::parse_message(&nested.content.unwrap(), crate::MessageFlags::default())
                .unwrap();
        assert_eq!(parsed.headers.subject.as_deref(), Some("Old mail"));

        let prefix = message.attachments[0].content.clone();
        for (line, encoding) in [
            (vec![b'x'; 76], &b"7bit"[..]),
            (vec![b'x'; 120], &b"7bit"[..]),
            (vec![b'x'; 998], &b"7bit"[..]),
            (b"caf\xe9".to_vec(), &b"8bit"[..]),
        ] {
            let content = [&prefix[..], &line, b"\r\n"].concat();
            let part = [
                &b"Content-Transfer-Encoding: "[..],
                encoding,
                b"\r\n\r\n",
                &content,
            ]
            .concat();
            message.attachments[0].content = content;
            let raw = compose(&message).unwrap().raw;
            assert!(
                raw.windows(part.len()).any(|window| window == part),
                "{} octets, {encoding:?}",
                line.len()
            );
        }
        for bad in [
            &[b'x'; 999][..],
            b"lone\rCR",
            b"lone\nLF",
            b"NUL\0",
            b"final\r",
        ] {
            message.attachments[0].content = [&prefix[..], bad].concat();
            assert!(
                compose(&message)
                    .unwrap_err()
                    .to_string()
                    .contains("attachment \"original.eml\": 7bit or 8bit needs")
            );
        }
        message.attachments[0].content_type = "not a type".to_owned();
        assert!(
            compose(&message)
                .unwrap_err()
                .to_string()
                .contains("attachment \"original.eml\": invalid content_type")
        );
    }

    #[test]
    fn rejects_header_injection_and_missing_recipients() {
        let from = EmailAddress::new(ME);
        let mut message = OutgoingMessage {
            to: vec![EmailAddress::new("bob@example.com")],
            subject: "Hi\r\nBcc: evil@example.com".to_owned(),
            ..OutgoingMessage::default()
        };
        assert!(build(&from, &message, "x@icloud.com", None).is_err());
        message.subject = "Hi".to_owned();
        message.to = vec![EmailAddress::with_name("Bob\r\nX: y", "bob@example.com")];
        assert!(build(&from, &message, "x@icloud.com", None).is_err());
        message.to.clear();
        assert!(build(&from, &message, "x@icloud.com", None).is_err());
    }

    #[test]
    fn message_ids_use_sender_domain() {
        let id = new_message_id(&EmailAddress::new(ME));
        assert!(id.ends_with("@icloud.com"));
        assert_ne!(id, new_message_id(&EmailAddress::new(ME)));
    }
}
