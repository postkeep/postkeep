//! Entry points for the `cargo-fuzz` targets in `fuzz/`.
//!
//! Only compiled with the `fuzzing` feature. Each function feeds untrusted
//! input to an internal parser or encoder and panics if an invariant the
//! rest of the crate relies on is broken.

#![allow(clippy::missing_panics_doc, clippy::panic, clippy::expect_used)]

use crate::outgoing::{self, Threading};
use crate::query::Literals;
use crate::{
    EmailAddress, MessageFlags, OutgoingAttachment, OutgoingMessage, SearchQuery, parse, utf7,
};

/// Folder names: decoding never panics, and encoding round-trips.
pub fn utf7(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = utf7::decode(text);
        let encoded = utf7::encode(text);
        assert!(encoded.is_ascii(), "encoded folder names are ASCII");
        assert_eq!(utf7::decode(&encoded).as_deref(), Some(text));
    }
}

/// Raw messages from the server: parsing never panics.
pub fn parse_message(data: &[u8]) {
    let _ = parse::parse_headers(data);
    let _ = parse::parse_message(1, MessageFlags::default(), data);
}

/// Search criteria from a tool call: a rendered command never carries a
/// line break or NUL outside a declared literal, so a value cannot end the
/// command and start another.
pub fn search(values: &[String; 5]) {
    let query = SearchQuery::new()
        .from(values[0].clone())
        .to(values[1].clone())
        .subject(values[2].clone())
        .text(values[3].clone())
        .message_id(values[4].clone());
    for literals in [
        Literals::Unlimited,
        Literals::UpTo4096,
        Literals::Unsupported,
    ] {
        let Ok(command) = query.to_imap(literals) else {
            continue;
        };
        let mut rest = command.as_str();
        // Strip each `{n+}\r\n` literal and its n bytes before checking.
        while let Some(start) = rest.find("+}\r\n") {
            let open = rest[..start].rfind('{').expect("literal opens with {");
            let len: usize = rest[open + 1..start].parse().expect("literal length");
            let before = &rest[..open];
            assert!(!before.contains(['\r', '\n', '\0']), "{command:?}");
            let body = start + 4;
            assert!(rest.len() >= body + len, "literal is truncated");
            assert!(!rest[body..body + len].contains(['\r', '\n', '\0']));
            rest = &rest[body + len..];
        }
        assert!(!rest.contains(['\r', '\n', '\0']), "{command:?}");
    }
}

/// Replies to a raw (untrusted) message: whatever its headers contain, the
/// reply has no header lines besides the ones this crate sets.
pub fn reply(raw: &[u8], subject: &str, name: &str) {
    let Some(original) = parse::parse_headers(raw) else {
        return;
    };
    let threading = Threading::reply_to(&original);
    let message = OutgoingMessage {
        to: vec![EmailAddress::with_name(
            if name.contains(['\r', '\n']) {
                "Recipient"
            } else {
                name
            },
            "to@example.com",
        )],
        cc: Vec::new(),
        bcc: vec![EmailAddress::new("hidden@example.com")],
        subject: subject.to_owned(),
        text_body: "body".to_owned(),
        html_body: None,
        attachments: vec![OutgoingAttachment {
            filename: name.to_owned(),
            content_type: "application/octet-stream".to_owned(),
            content: vec![0],
            content_id: None,
            inline: false,
        }],
    };
    let from = EmailAddress::new("me@example.com");
    let Ok(built) = outgoing::build(&from, &message, "id@example.com", threading.as_ref()) else {
        return;
    };
    let formatted = built.formatted();
    let text = String::from_utf8_lossy(&formatted);
    let head = text.split("\r\n\r\n").next().unwrap_or_default();
    check_headers(head);
    for part in text.split("\r\n--").skip(1) {
        if let Some((_, rest)) = part.split_once("\r\n")
            && let Some((head, _)) = rest.split_once("\r\n\r\n")
        {
            check_headers(head);
        }
    }
}

fn check_headers(head: &str) {
    for line in head.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let name = line.split_once(':').map_or(line, |(name, _)| name);
        assert!(
            matches!(
                name,
                "From"
                    | "To"
                    | "Subject"
                    | "Message-ID"
                    | "In-Reply-To"
                    | "References"
                    | "Date"
                    | "MIME-Version"
                    | "Content-Type"
                    | "Content-Transfer-Encoding"
                    | "Content-Disposition"
            ),
            "unexpected header line {line:?} in {head:?}"
        );
    }
}
