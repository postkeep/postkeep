//! Forwarding uses only the mailbox's copy of the original. Outlook builds its
//! own draft; for Gmail and IMAP we build a text alternative, preserve the
//! original HTML when it is one part, and carry its listed files.

use std::collections::HashMap;

use postkeep_mail::invisible::{escape_name, senders, visible};
use postkeep_mail::{OutgoingAttachment, OutgoingMessage, mime};
use sha2::{Digest as _, Sha256};

use crate::text::prefix_html;
use crate::tools::{FileDigest, RequestedBodyFormat, format_address, shown_body};

/// Data from the original that is pinned and described in a held forward.
pub struct Forwarded {
    pub pin: String,
    pub sender: String,
    pub subject: String,
    pub files: Vec<(String, usize)>,
}

const UNREADABLE: &str =
    "The body of the message to forward cannot be read safely; nothing was sent.";

pub fn build(raw: Vec<u8>, message: &mut OutgoingMessage) -> Result<Forwarded, String> {
    let original = mime::parse_for_forward(&raw).ok_or(UNREADABLE)?;
    let (body, truncated, _, _, complete) = shown_body(
        &original,
        RequestedBodyFormat::Markdown,
        &HashMap::new(),
        usize::MAX,
    );
    if truncated || !complete {
        return Err(UNREADABLE.to_owned());
    }
    let headers = original.headers;
    let sender = senders(
        headers.from.first(),
        headers.from_clear,
        &headers.from_values,
    )
    .0
    .join(", ");
    let subject = headers.subject.as_deref().map(visible).unwrap_or_default();
    let date = headers
        .date
        .map(|date| date.to_rfc3339())
        .unwrap_or_default();
    let to = headers
        .to
        .iter()
        .map(format_address)
        .collect::<Vec<_>>()
        .join(", ");
    let cc = headers
        .cc
        .iter()
        .map(format_address)
        .collect::<Vec<_>>()
        .join(", ");
    let mut block = format!(
        "---------- Forwarded message ---------\nFrom: {sender}\nDate: {date}\nSubject: {subject}\nTo: {to}"
    );
    if !cc.is_empty() {
        block.push_str("\nCc: ");
        block.push_str(&cc);
    }
    let note = std::mem::take(&mut message.text_body);
    message.text_body = format!("{note}\n\n{block}\n\n{body}");
    if original.body_parts.is_empty()
        && let Some(html) = original.html_body
    {
        message.html_body = Some(prefix_html(
            &html,
            &format!("{}<br><br>{}<br><br>", note_html(&note), note_html(&block)),
        ));
    }

    let sent_files = mime::files(&raw).ok_or(UNREADABLE)?;
    drop(raw);
    let first = message.attachments.len();
    for file in sent_files {
        message
            .attachments
            .push(forwarded_file(file, message.html_body.is_some())?);
    }
    let files = &message.attachments[first..];
    let digests = files
        .iter()
        .map(|file| (FileDigest::new(file), &file.content_id, file.inline))
        .collect::<Vec<_>>();
    let digests = serde_json::to_vec(&digests).map_err(|_| "could not pin the forwarded files")?;
    Ok(Forwarded {
        pin: pin([
            message.text_body.as_bytes(),
            message.html_body.as_deref().unwrap_or_default().as_bytes(),
            &digests,
        ]),
        sender,
        subject,
        files: files
            .iter()
            .map(|file| (file.filename.clone(), file.content.len()))
            .collect(),
    })
}

fn forwarded_file(
    file: postkeep_mail::SentFile,
    has_html: bool,
) -> Result<OutgoingAttachment, String> {
    let attachment = file.attachment;
    let name = display_file(attachment.filename.as_deref().unwrap_or_default());
    let refusal = |reason: &str| {
        format!(
            "Attachment {}, {name}, of the message to forward {reason}; nothing was sent.",
            attachment.id
        )
    };
    let content = file.content.ok_or_else(|| {
        refusal("did not decode cleanly, so its bytes may differ from what a mail app opens")
    })?;
    if attachment
        .content_id
        .as_deref()
        .is_some_and(|id| !OutgoingAttachment::valid_content_id(id))
    {
        return Err(refusal("has an invalid Content-ID"));
    }
    let mut content_type = attachment.content_type;
    if let Some(charset) = file.charset {
        if !mime::is_parameter_token(&charset) {
            return Err(refusal("has a charset that cannot be forwarded safely"));
        }
        content_type.push_str("; charset=");
        content_type.push_str(&charset);
    }
    let inline = has_html && attachment.inline && attachment.content_id.is_some();
    let file = OutgoingAttachment {
        filename: attachment.filename.unwrap_or_default(),
        content_type,
        content,
        content_id: attachment.content_id,
        inline,
    };
    file.validate_content_type()
        .map_err(|_| refusal("has an invalid content_type"))?;
    file.validate_content()
        .map_err(|error| refusal(&format!("cannot be sent unchanged ({error})")))?;
    Ok(file)
}

/// Hash each field with its length so different field splits cannot share a pin.
pub fn pin(parts: impl IntoIterator<Item = impl AsRef<[u8]>>) -> String {
    let mut hash = Sha256::new();
    for part in parts {
        let bytes = part.as_ref();
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
    }
    hex::encode(hash.finalize())
}

pub fn note_html(note: &str) -> String {
    note.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace("\r\n", "\n")
        .replace(['\r', '\n'], "<br>")
}

pub fn display_file(name: &str) -> String {
    if name.is_empty() {
        "(unnamed file)".to_owned()
    } else {
        escape_name(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADERS: &str = "From: Sender <sender@example.org>\r\nTo: recipient@example.org\r\nCc: copy@example.org\r\nDate: Thu, 08 Oct 2026 09:00:00 +0000\r\nSubject: Original\r\nMIME-Version: 1.0\r\n";

    fn build_from(raw: &str) -> Result<(OutgoingMessage, Forwarded), String> {
        let mut message = OutgoingMessage {
            text_body: "Hi,\n\nTerms < 30 & more".to_owned(),
            ..OutgoingMessage::default()
        };
        let info = build(format!("{HEADERS}{raw}").into_bytes(), &mut message)?;
        Ok((message, info))
    }

    #[test]
    fn builds_the_block_and_preserves_html() {
        let original = "Content-Type: text/html; charset=utf-8\r\n\r\n<html><!-- <body> --><head><title><body></title><template><template><body>inert</body></template></template></head><BoDy data-x=\">\"><b>Original body</b></BoDy></html>";
        let (message, info) = build_from(original).unwrap();
        assert_eq!(info.subject, "Original");
        assert!(message.text_body.contains("\n\n---------- Forwarded message ---------\nFrom: Sender <sender@example.org>\nDate: 2026-10-08T09:00:00+00:00\nSubject: Original\nTo: recipient@example.org\nCc: copy@example.org\n\n**Original body**"));
        assert!(message.html_body.unwrap().contains("<BoDy data-x=\">\">Hi,<br><br>Terms &lt; 30 &amp; more<br><br>---------- Forwarded message"));
        let original = format!(
            "Content-Type: text/html\r\n\r\n<p>{}End of long body.</p>",
            "x".repeat(25_000)
        );
        assert!(
            build_from(&original)
                .unwrap()
                .0
                .text_body
                .ends_with("End of long body.")
        );
        let (text, _) = build_from("Content-Type: text/plain\r\n\r\nPlain original").unwrap();
        assert!(text.text_body.ends_with("Plain original"));
        assert!(text.html_body.is_none());
    }

    fn mixed(first: &str, file: &str, last: &str) -> String {
        format!(
            "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/html\r\n\r\n{first}\r\n--x\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename=logo.png\r\n{file}\r\n--x\r\nContent-Type: text/plain\r\n\r\n{last}\r\n--x--\r\n"
        )
    }

    #[test]
    fn carries_all_shown_parts_or_refuses_the_join() {
        let file =
            "Content-ID: <logo@example.org>\r\nContent-Transfer-Encoding: base64\r\n\r\nYQ==";
        let (message, _) = build_from(&mixed("<p>One</p>", file, "Two")).unwrap();
        assert!(message.text_body.ends_with("One\n\nTwo"));
        assert!(message.html_body.is_none());
        assert!(!message.attachments[0].inline);
        assert_eq!(message.attachments[0].content, b"a");
        assert!(
            matches!(build_from(&mixed("<div>Open", file, "Two")), Err(error) if error == UNREADABLE)
        );
        assert!(
            matches!(build_from("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!"), Err(error) if error == UNREADABLE)
        );
    }

    #[test]
    fn refuses_an_unreadable_sibling_but_not_an_unshown_alternative() {
        let multipart = |kind, first| {
            format!(
                "Content-Type: multipart/{kind}; boundary=x\r\n\r\n--x\r\n{first}\r\n--x\r\nContent-Type: text/plain; charset=utf-7\r\n\r\nDo not approve.\r\n--x--\r\n"
            )
        };
        let original = multipart("mixed", "Content-Type: text/plain\r\n\r\nPart one.");
        assert!(matches!(build_from(&original), Err(error) if error == UNREADABLE));
        let original = "Content-Type: multipart/alternative; boundary=x\r\n\r\n\
--x\r\nContent-Type: text/plain; charset=utf-7\r\n\r\nHidden fallback.\r\n\
--x\r\nContent-Type: text/html\r\n\r\n<p>Part one.</p>\r\n--x--\r\n";
        let (forward, _) = build_from(original).unwrap();
        assert!(forward.text_body.ends_with("Part one."));
    }

    #[test]
    fn refuses_unreadable_files_and_unsafe_ids_by_number_and_name() {
        for (headers, reason) in [
            (
                "Content-Transfer-Encoding: base64\r\n\r\n!",
                "did not decode cleanly",
            ),
            ("Content-ID: <has space>\r\n\r\nimage", "invalid Content-ID"),
        ] {
            let error = build_from(&mixed("<p>One</p>", headers, "Two"))
                .err()
                .unwrap();
            assert!(error.contains("Attachment 1, logo.png"));
            assert!(error.contains(reason), "{error}");
        }
    }

    #[test]
    fn checks_the_forwarded_type_with_the_composer_before_a_hold() {
        let original = mixed("<p>One</p>", "\r\nimage", "Two");
        let mut file = mime::files(original.as_bytes()).unwrap().remove(0);
        file.attachment.content_type = "not a mime type".to_owned();
        let error = forwarded_file(file, true).unwrap_err();
        assert!(error.contains("Attachment 1, logo.png"));
        assert!(error.contains("invalid content_type"), "{error}");
    }

    #[test]
    fn hashes_each_sent_field_and_the_decoded_files() {
        let original = |html, data| {
            mixed(
                html,
                &format!("Content-Transfer-Encoding: base64\r\n\r\n{data}"),
                "Two",
            )
        };
        let pin = |raw: &str| build_from(raw).unwrap().1.pin;
        let first = pin(&original("<p>One</p>", "YQ=="));
        assert_ne!(first, pin(&original("<p>Won</p>", "YQ==")));
        assert_ne!(first, pin(&original("<p>One</p>", "Yg==")));
        let raw = |attr| format!("Content-Type: text/html\r\n\r\n<p id='{attr}'>One</p>");
        assert_ne!(pin(&raw("a")), pin(&raw("b")));
        assert_ne!(super::pin(["ab", "c"]), super::pin(["a", "bc"]));
    }
}
