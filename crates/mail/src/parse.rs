//! Conversion of raw RFC 5322 messages into this crate's types.

use std::collections::HashMap;

use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
use mail_parser::{
    HeaderName, HeaderValue, MessageParser, MimeHeaders, PartType,
    decoders::charsets::map::charset_decoder,
};

use crate::{
    Attachment, AttachmentData, BodyPart, EmailAddress, Message, MessageFlags, MessageHeaders, Uid,
};

/// Parses only the headers of a raw message.
pub fn parse_headers(raw: &[u8]) -> Option<MessageHeaders> {
    let message = MessageParser::default().parse_headers(raw)?;
    Some(headers(&message, raw))
}

/// The sender of a raw message's headers, when a mail client shows the same address.
///
/// The headers hold one `From`, and it is one address alone or after a name, as in
/// `alice@example.com` or `Alice <alice@example.com>`: that address, with its name. `None` for
/// any other `From`.
pub fn sender(raw: &[u8]) -> Option<EmailAddress> {
    let message = MessageParser::default().parse_headers(raw)?;
    sender_of(&message, raw)
}

/// [`sender`] of a message parsed from `raw`.
fn sender_of(message: &mail_parser::Message<'_>, raw: &[u8]) -> Option<EmailAddress> {
    let mut values = message
        .headers()
        .iter()
        .filter(|header| header.name == HeaderName::From)
        .map(|header| header_text(raw, header));
    let (Some(Some(value)), None) = (values.next(), values.next()) else {
        return None;
    };
    let [from] = <[EmailAddress; 1]>::try_from(addresses(message.from())).ok()?;
    shows_only(&String::from_utf8_lossy(value), &from.address).then_some(from)
}

/// The value of each `From` header of a message parsed from `raw` as sent, in their order,
/// without the spaces and line breaks around it.
fn from_values(message: &mail_parser::Message<'_>, raw: &[u8]) -> Vec<String> {
    message
        .headers()
        .iter()
        .filter(|header| header.name == HeaderName::From)
        .filter_map(|header| header_text(raw, header))
        .map(|value| String::from_utf8_lossy(value).into_owned())
        .collect()
}

/// Parses a complete raw message. Both bodies come back empty when a mail client may read
/// the message's parts differently from this parser.
pub fn parse_message(uid: Uid, flags: MessageFlags, raw: &[u8]) -> Option<Message> {
    parsed_parts(uid, flags, raw).map(|(message, _)| message)
}

/// Parses the message and reports whether a displayed sibling body part was unreadable.
pub fn parsed_parts(uid: Uid, flags: MessageFlags, raw: &[u8]) -> Option<(Message, bool)> {
    let message = MessageParser::default().parse(raw)?;
    let cut_off = read_differently_from(&message).is_some();
    let holds = holds_html(&message);
    let html = html_body_of(&message, &holds);
    let (text_body, text_body_withheld, text_part) = text_body_of(&message, &holds);
    // The part get_message shows, HTML first, when it can be read.
    let body = match &html {
        Some((part, _)) => part.filter(|&id| {
            message
                .part(id)
                .is_some_and(|part| decoded_alike(raw, part))
        }),
        None => text_part.filter(|_| !text_body_withheld),
    };
    let (body_parts, skipped_body_part) = match body {
        Some(body) if !cut_off => body_parts(&message, &holds, body),
        _ => (Vec::new(), false),
    };
    let html_body = html.map(|(_, html)| if cut_off { String::new() } else { html });
    let (text_body, text_body_withheld) = if cut_off {
        (Some(""), true)
    } else {
        (text_body, text_body_withheld)
    };
    Some((
        Message {
            uid,
            flags,
            headers: headers(&message, raw),
            text_body: text_body.map(str::to_owned),
            text_body_withheld,
            html_body,
            body_parts,
            attachments: listed_attachments(&message)
                .zip(1..)
                .map(|((part, in_digest), id)| attachment(part, id, in_digest))
                .collect(),
        },
        skipped_body_part,
    ))
}

/// Parses a raw message and returns attachment `id` (from 1), with its content only when it decoded
/// cleanly and is at most `max_bytes` long. A part counts as decoded only when it ends before the
/// place where a mail client may start to read the message's parts differently
/// (`read_differently_from`): one that runs past a boundary line, or that comes after it, may hold
/// what a mail app shows as another part or hides. A part that is not text but that mail-parser
/// held as text counts as decoded only when that text is the part's bytes as sent, and a file
/// without a Content-Type only when its bytes are UTF-8 (`changed_as_text`).
pub fn attachment_data(raw: &[u8], id: u32, max_bytes: usize) -> Option<AttachmentData> {
    let message = MessageParser::default().parse(raw)?;
    let (part, in_digest) =
        listed_attachments(&message).nth(usize::try_from(id.checked_sub(1)?).ok()?)?;
    let decoded = file_decoded(raw, part, read_differently_from(&message))
        && !changed_as_text(raw, part, in_digest);
    Some(AttachmentData {
        attachment: attachment(part, id, in_digest),
        content: (decoded && part.len() <= max_bytes).then(|| part.contents().to_vec()),
        decoded,
    })
}

fn file_decoded(raw: &[u8], part: &mail_parser::MessagePart<'_>, differing: Option<usize>) -> bool {
    decoded_alike(raw, part)
        && differing
            .is_none_or(|from| usize::try_from(part.offset_end).is_ok_and(|end| end <= from))
}

/// Lists numbered files with transfer-decoded bytes, without converting their charsets.
pub fn files(raw: &[u8]) -> Option<Vec<crate::SentFile>> {
    let message = MessageParser::default().parse(raw)?;
    let differing = read_differently_from(&message);
    Some(
        listed_attachments(&message)
            .zip(1..)
            .map(|((part, in_digest), id)| crate::SentFile {
                attachment: attachment(part, id, in_digest),
                charset: part
                    .content_type()
                    .and_then(|kind| kind.attribute("charset"))
                    .map(str::to_owned),
                content: file_decoded(raw, part, differing)
                    .then(|| decoded_body(raw, part))
                    .flatten(),
            })
            .collect(),
    )
}

fn decoded_body(raw: &[u8], part: &mail_parser::MessagePart<'_>) -> Option<Vec<u8>> {
    let body = sent_body(raw, part)?;
    match part.encoding {
        mail_parser::Encoding::Base64 => mail_parser::decoders::base64::base64_decode(body),
        mail_parser::Encoding::QuotedPrintable => {
            mail_parser::decoders::quoted_printable::quoted_printable_decode(body)
        }
        mail_parser::Encoding::None => Some(body.to_vec()),
    }
}

/// The `text/markdown` part that is the message's body, when mail-parser
/// listed it as an attachment: it only takes `text/plain` and `text/html` as
/// bodies, while RFC 2046 4.1.4 has mail apps show unknown text subtypes as
/// plain text.
///
/// Only in a message with no body part (anywhere in mail-parser's lists) and
/// no `multipart/alternative` or `multipart/related` at any depth: mail apps
/// show one member of an alternative, and only the root of a related part
/// (RFC 2387), so the person may never see a Markdown part in one. The part
/// must be text that decoded cleanly, with no file name and no `attachment`
/// disposition.
fn markdown_body(message: &mail_parser::Message<'_>) -> Option<u32> {
    if message
        .text_bodies()
        .any(|part| matches!(part.body, PartType::Text(_)))
        || message
            .html_bodies()
            .any(|part| matches!(part.body, PartType::Html(_)))
        || message.parts.iter().any(|part| {
            part.is_content_type("multipart", "alternative")
                || part.is_content_type("multipart", "related")
        })
    {
        return None;
    }
    message.attachments.iter().copied().find(|&id| {
        message.part(id).is_some_and(|part| {
            part.is_content_type("text", "markdown")
                && matches!(part.body, PartType::Text(_))
                && !part.is_encoding_problem
                && decoded_alike(&message.raw_message, part)
                && part.attachment_name().is_none()
                && !part
                    .content_disposition()
                    .is_some_and(mail_parser::ContentType::is_attachment)
        })
    })
}

/// The attachments that tools number from 1: mail-parser's list without the
/// Markdown body, so listing and download agree on ids. Each comes with
/// whether it is a member of a `multipart/digest` (`digest_members`).
fn listed_attachments<'a>(
    message: &'a mail_parser::Message<'a>,
) -> impl Iterator<Item = (&'a mail_parser::MessagePart<'a>, bool)> {
    let body = markdown_body(message);
    let members = digest_members(message);
    message
        .attachments
        .iter()
        .filter(move |&&id| Some(id) != body)
        .map_while(move |&id| {
            let member = usize::try_from(id).ok().and_then(|id| members.get(id)) == Some(&true);
            Some((message.part(id)?, member))
        })
}

/// For each part, whether it is a member of a `multipart/digest`, where mail-parser reads a
/// part without a Content-Type as a message (`media_type`).
fn digest_members(message: &mail_parser::Message<'_>) -> Vec<bool> {
    let mut members = vec![false; message.parts.len()];
    for part in &message.parts {
        if let PartType::Multipart(children) = &part.body
            && part.is_content_type("multipart", "digest")
        {
            for &child in children {
                if let Some(member) = usize::try_from(child)
                    .ok()
                    .and_then(|child| members.get_mut(child))
                {
                    *member = true;
                }
            }
        }
    }
    members
}

/// The HTML body, with its part (`None` when the body is `""` because mail apps
/// differ on the part they show): the HTML part a mail app shows. Parts are read in MIME
/// order, except that of a `multipart/alternative` only the last member a mail
/// app can show as a body (`shows_as_body`) is read, as mail apps show the last
/// member they can display (RFC 2046 5.1.4), and of a `multipart/related` only
/// its root (`related_root`); when it has none and holds HTML, the body is `""`.
/// When that member holds no HTML part, the body is `""`: the person sees its
/// text or image, and an earlier member may hold text they never see.
/// Inside an alternative every HTML part counts, as mail apps pick by type.
/// Elsewhere an HTML part mail-parser lists as an attachment, with a file name
/// or an `attachment` disposition, is a file (still listed, so downloadable);
/// one it reads as a body stays the body, even with a name.
///
/// Read here rather than from mail-parser's HTML list, whose first entry can
/// be another inline part, and which leaves out some nested HTML parts. A part
/// that did not decode is listed as an attachment by mail-parser, while mail
/// apps decode it leniently and show it (RFC 2045 6.7, 6.8), so the plain-text
/// part must not stand in for it. Without a transfer encoding (or with 7bit,
/// 8bit or binary) the recovered text is the HTML as sent, as when only the
/// closing boundary is missing. A failed base64 or quoted-printable part, or one
/// in a transfer encoding mail-parser does not decode, gives `""`: raw letters read as text could differ from what the person's client
/// shows. Whether a mail client may read the parts differently is decided once
/// in `parse_message`, so this walk does not repeat it.
fn html_body_of(
    message: &mail_parser::Message<'_>,
    holds: &[bool],
) -> Option<(Option<u32>, String)> {
    // Depth first from the root, with a stack: pop order is the reading order.
    // `None` marks the end of an alternative's shown member.
    let mut stack = vec![Some((0, false))];
    while let Some(entry) = stack.pop() {
        let Some((id, enclosed)) = entry else {
            return Some((None, String::new()));
        };
        let Some(part) = message.part(id) else {
            continue;
        };
        if let PartType::Multipart(children) = &part.body {
            if part.is_content_type("multipart", "alternative") {
                let shown = children
                    .iter()
                    .rev()
                    .find(|&&child| message.part(child).is_some_and(shows_as_body));
                if let Some(&shown) = shown {
                    // Only a hidden HTML member makes an HTML-less shown member an empty body
                    // (a shown member with HTML returns before its marker).
                    if any_holds(holds, children) {
                        stack.push(None);
                    }
                    stack.push(Some((shown, true)));
                }
            } else if part.is_content_type("multipart", "related") {
                match related_root(message, part, children) {
                    Some(root) => stack.push(Some((root, enclosed))),
                    // Mail apps differ on the part they show, so the body is "", as for an alternative.
                    None if any_holds(holds, children) => return Some((None, String::new())),
                    None => {}
                }
            } else {
                stack.extend(children.iter().rev().map(|&child| Some((child, enclosed))));
            }
        } else if part.is_content_type("text", "html") && (enclosed || !is_file(message, id, part))
        {
            match &part.body {
                PartType::Html(html) => {
                    return Some((
                        Some(id),
                        readable_text(&message.raw_message, part, html)
                            .unwrap_or_default()
                            .to_owned(),
                    ));
                }
                PartType::Text(text) if part.is_encoding_problem => {
                    return Some((
                        Some(id),
                        readable_text(&message.raw_message, part, text)
                            .unwrap_or_default()
                            .to_owned(),
                    ));
                }
                _ => {}
            }
        }
    }
    None
}

/// For each part, whether it is, or encloses at any depth, a `text/html` part.
/// mail-parser stores each multipart before its children, so one pass from the
/// end suffices: the walk stays linear however deep a sender nests parts.
fn holds_html(message: &mail_parser::Message<'_>) -> Vec<bool> {
    let mut holds = vec![false; message.parts.len()];
    for (index, part) in message.parts.iter().enumerate().rev() {
        let html = part.is_content_type("text", "html")
            || matches!(&part.body, PartType::Multipart(children) if any_holds(&holds, children));
        if let Some(slot) = holds.get_mut(index) {
            *slot = html;
        }
    }
    holds
}

/// Whether any of `children` holds an HTML part, per `holds_html`.
fn any_holds(holds: &[bool], children: &[u32]) -> bool {
    children.iter().any(|&child| {
        usize::try_from(child)
            .ok()
            .and_then(|child| holds.get(child))
            == Some(&true)
    })
}

/// Whether a mail app can show this alternative member as the body: a multipart, an image, or by
/// `media_type` text/plain, text/html, text/enriched, text/richtext or text/markdown. Mail apps
/// differ on the last three: some show such a last member (RFC 2046 4.1.4 has a text subtype they
/// don't know shown as plain text), others the member before it. mail-parser lists such a member
/// as an attachment, so when it is the member shown the body is empty, as no other member stands
/// in for it. Other text subtypes, such as text/calendar, don't count. A member of an alternative
/// is never one of a digest.
fn shows_as_body(part: &mail_parser::MessagePart<'_>) -> bool {
    matches!(part.body, PartType::Multipart(_))
        || media_type(part, false).0.eq_ignore_ascii_case("image")
        || ["plain", "html", "enriched", "richtext", "markdown"]
            .iter()
            .any(|subtype| is_media_type(part, false, "text", subtype))
}

/// The root of a `multipart/related` part, the only part of it a mail app shows (RFC 2387): its first
/// part, when it has no `start` parameter or `start` names that part's Content-ID. `None` when `start`
/// names another part or none: mail apps that follow `start` and those that show the first part
/// differ, and mail-parser ignores it. `None` too when mail-parser and a mail client may read
/// `start` differently (`start_reads_differently`).
fn related_root(
    message: &mail_parser::Message<'_>,
    part: &mail_parser::MessagePart<'_>,
    children: &[u32],
) -> Option<u32> {
    let first = *children.first()?;
    let mut starts = part
        .content_type()
        .and_then(mail_parser::ContentType::attributes)
        .unwrap_or_default()
        .iter()
        .filter(|attribute| attribute.name == "start");
    let Some(start) = starts.next() else {
        return Some(first);
    };
    // mail-parser reads the first copy of a repeated parameter, a mail client may read another.
    if starts.next().is_some()
        || part
            .headers
            .iter()
            .filter(|header| header.name == HeaderName::ContentType)
            .any(|header| {
                header_text(&message.raw_message, header).is_none_or(start_reads_differently)
            })
    {
        return None;
    }
    let start = start.value.trim();
    let start = start
        .strip_prefix('<')
        .and_then(|start| start.strip_suffix('>'))
        .unwrap_or(start)
        .trim();
    let root = message.part(first)?;
    // mail-parser reads the last copy of a repeated header, a mail client may read another.
    let ids = root
        .headers
        .iter()
        .filter(|header| header.name == HeaderName::ContentId);
    (ids.count() == 1 && root.content_id() == Some(start)).then_some(first)
}

/// Whether a Content-Type value as sent may give mail-parser another `start` than a mail client
/// reads: it holds a `*`, with which mail-parser joins RFC 2231 pieces (`start*1`) to `start` or
/// reads an extended value, even with spaces, quotes or backslashes between the name and the `*`,
/// or an encoded word (`=?`), which mail-parser decodes in a value. A mail client may do neither.
fn start_reads_differently(value: &[u8]) -> bool {
    value.contains(&b'*') || value.windows(2).any(|pair| pair == b"=?")
}

/// Whether mail-parser lists part `id` as an attachment and it names a file
/// (`names_a_file`). The list is in part order, so sorted.
fn is_file(
    message: &mail_parser::Message<'_>,
    id: u32,
    part: &mail_parser::MessagePart<'_>,
) -> bool {
    message.attachments.binary_search(&id).is_ok() && names_a_file(part)
}

/// Whether the part has a file name or an `attachment` disposition.
fn names_a_file(part: &mail_parser::MessagePart<'_>) -> bool {
    part.attachment_name().is_some()
        || part
            .content_disposition()
            .is_some_and(mail_parser::ContentType::is_attachment)
}

/// Whether a part's transfer encoding was undone, or it had none, as mail apps read it: it has no
/// Content-Transfer-Encoding, or every copy of that header is the same one word, base64 or
/// quoted-printable when mail-parser decoded the part (it keeps `encoding` set only then), else
/// 7bit, 8bit, binary or nothing. mail-parser reads the last copy, and decodes an encoded word in
/// the value (`=?us-ascii?q?base64?=`), while a mail client may read another copy and takes the
/// value as a word (RFC 2047 5). mail-parser passes any other value through as sent,
/// `x-uuencode` or `base64 (comment)` say, which some mail apps decode. The offsets of a header of
/// a part of the top-level message index `raw`, its input.
fn transfer_decoded(raw: &[u8], part: &mail_parser::MessagePart<'_>) -> bool {
    let words: &[&str] = if part.encoding == mail_parser::Encoding::None {
        &["", "7bit", "8bit", "binary"]
    } else {
        &["base64", "quoted-printable"]
    };
    let mut values = part
        .headers
        .iter()
        .filter(|header| header.name == HeaderName::ContentTransferEncoding)
        .map(|header| header_text(raw, header));
    let Some(first) = values.next() else {
        return true;
    };
    values.all(|value| value == first)
        && first.is_some_and(|value| {
            words
                .iter()
                .any(|word| value.eq_ignore_ascii_case(word.as_bytes()))
        })
}

/// Whether mail-parser decoded a part as mail apps do: its transfer encoding was undone, or it
/// had none (`transfer_decoded`), and when mail-parser holds the part as text, which it converts
/// from the part's `charset`, a mail client reads the same charset (`parameter_differs`) and
/// converts the bytes to the same text (`converted_alike`).
fn decoded_alike(raw: &[u8], part: &mail_parser::MessagePart<'_>) -> bool {
    transfer_decoded(raw, part)
        && match &part.body {
            PartType::Text(text) | PartType::Html(text) => {
                !parameter_differs(raw, part, "charset") && converted_alike(raw, part, text)
            }
            _ => true,
        }
}

/// The labels of the Encoding Standard (encoding.spec.whatwg.org) that name UTF-8. mail-parser
/// has no converter for them and reads the text as UTF-8, as for a label it doesn't know.
const UTF8_LABELS: &str = "\
    unicode-1-1-utf-8 unicode11utf8 unicode20utf8 utf-8 utf8 x-unicode20utf8";

/// The Encoding Standard's labels of the single-byte charsets that mail-parser converts with a
/// table of its own. Like the standard's index for the label, each table reads the bytes below
/// 0x80 as ASCII and no other byte as ASCII; the two read some of the other bytes as different
/// characters, U+FFFD or a control character among them.
const TABLE_LABELS: &str = "\
    csisolatin2 iso-8859-2 iso-ir-101 iso8859-2 iso88592 iso_8859-2 iso_8859-2:1987 l2 latin2 \
    csisolatin3 iso-8859-3 iso-ir-109 iso8859-3 iso88593 iso_8859-3 iso_8859-3:1988 l3 latin3 \
    csisolatin4 iso-8859-4 iso-ir-110 iso8859-4 iso88594 iso_8859-4 iso_8859-4:1988 l4 latin4 \
    csisolatincyrillic cyrillic iso-8859-5 iso-ir-144 iso8859-5 iso88595 iso_8859-5 \
    iso_8859-5:1988 arabic asmo-708 csiso88596e csiso88596i csisolatinarabic ecma-114 \
    iso-8859-6 iso-8859-6-e iso-8859-6-i iso-ir-127 iso8859-6 iso88596 iso_8859-6 \
    iso_8859-6:1987 csisolatingreek ecma-118 elot_928 greek greek8 iso-8859-7 iso-ir-126 \
    iso8859-7 iso88597 iso_8859-7 iso_8859-7:1987 sun_eu_greek csiso88598e csisolatinhebrew \
    hebrew iso-8859-8 iso-8859-8-e iso-ir-138 iso8859-8 iso88598 iso_8859-8 iso_8859-8:1988 \
    visual csiso88598i iso-8859-8-i logical csisolatin6 iso-8859-10 iso-ir-157 iso8859-10 \
    iso885910 l6 latin6 iso-8859-13 iso8859-13 iso885913 iso-8859-14 iso8859-14 iso885914 \
    csisolatin9 iso-8859-15 iso8859-15 iso885915 iso_8859-15 l9 iso-8859-16 cskoi8r koi koi8 \
    koi8-r koi8_r koi8-ru koi8-u csmacintosh mac macintosh x-mac-roman iso-8859-11 iso8859-11 \
    iso885911 tis-620 cp1250 windows-1250 x-cp1250 cp1251 windows-1251 x-cp1251 ansi_x3.4-1968 \
    ascii cp1252 cp819 csisolatin1 ibm819 iso-8859-1 iso-ir-100 iso8859-1 iso88591 iso_8859-1 \
    iso_8859-1:1987 l1 latin1 us-ascii windows-1252 x-cp1252 cp1253 windows-1253 x-cp1253 \
    cp1254 csisolatin5 iso-8859-9 iso-ir-148 iso8859-9 iso88599 iso_8859-9 iso_8859-9:1989 l5 \
    latin5 windows-1254 x-cp1254 cp1255 windows-1255 x-cp1255 cp1256 windows-1256 x-cp1256 \
    cp1257 windows-1257 x-cp1257 cp1258 windows-1258 x-cp1258";

/// The Encoding Standard's other labels: those of the East Asian charsets, and of the single-byte
/// ones mail-parser has no table for. With its `full_encoding` feature, as here, mail-parser
/// converts them with the standard's own decoders, from `encoding_rs`, as Thunderbird does, but
/// follows a byte order mark at the start of the bytes, as browsers do and Thunderbird doesn't.
const DECODER_LABELS: &str = "\
    866 cp866 csibm866 ibm866 dos-874 windows-874 x-mac-cyrillic x-mac-ukrainian chinese \
    csgb2312 csiso58gb231280 gb2312 gb_2312 gb_2312-80 gbk iso-ir-58 x-gbk gb18030 big5 \
    big5-hkscs cn-big5 csbig5 x-x-big5 cseucpkdfmtjapanese euc-jp x-euc-jp csiso2022jp \
    iso-2022-jp csshiftjis ms932 ms_kanji shift-jis shift_jis sjis windows-31j x-sjis cseuckr \
    csksc56011987 euc-kr iso-ir-149 korean ks_c_5601-1987 ks_c_5601-1989 ksc5601 ksc_5601 \
    windows-949 x-user-defined";

/// The byte order marks of UTF-8, UTF-16BE and UTF-16LE.
const MARKS: [&[u8]; 3] = [b"\xEF\xBB\xBF", b"\xFE\xFF", b"\xFF\xFE"];

/// Whether mail apps convert a text part's bytes to `text`, as mail-parser did from its `charset`.
/// Mail apps convert with the Encoding Standard's decoders: browsers support no other charsets
/// (HTML Standard 13.2.3.3), and Thunderbird uses them through `encoding_rs`, besides a UTF-7
/// decoder and a few labels of its own. So the text counts as converted alike only: without a
/// charset, when it holds no U+FFFD (its bytes were UTF-8) and no ISO-2022 escape (`ESC $`,
/// `ESC (`), as Thunderbird then guesses UTF-8, as mail-parser reads it; with a UTF-8 label,
/// unless it starts with the two U+FFFD of a UTF-16 byte order mark; with a table's label
/// (`TABLE_LABELS`), unless it starts with what the table makes of a byte order mark; and with
/// another label of the standard (`DECODER_LABELS`), unless it holds U+FFFD, which the standard's
/// decoder gives for bytes the charset has no character for, a broken byte pair say, and other
/// converters may read otherwise; holds ESC, SO or SI, which ISO-2022 converters read as switches
/// to other characters (the standard's ISO-2022-JP decoder reads its own escapes and gives U+FFFD
/// for any other); or the part's bytes start with a byte order mark (`starts_with_a_mark`), which
/// mail-parser's decoders follow, reading UTF-8 or UTF-16 instead. Browsers follow a byte order
/// mark over the charset (Encoding Standard, "decode"), and Thunderbird doesn't. Any other label
/// counts as converted otherwise: UTF-7, which browsers don't decode; UTF-16, which text parts
/// may not use (RFC 2781, appendix A) and whose byte order mark mail-parser follows and
/// Thunderbird doesn't; the standard's replacement labels, ISO-2022-KR or HZ say, whose ASCII
/// bytes stand for other characters; and a label outside the standard, which a mail app may read
/// as a charset it knows, as Thunderbird reads `unicode-1-1-utf-7` as UTF-7.
fn converted_alike(raw: &[u8], part: &mail_parser::MessagePart<'_>, text: &str) -> bool {
    let Some(label) = part
        .content_type()
        .and_then(|content_type| content_type.attribute("charset"))
    else {
        return !text.contains('\u{FFFD}')
            && !text.contains("\u{1b}$")
            && !text.contains("\u{1b}(");
    };
    let listed = |labels: &str| {
        labels
            .split(' ')
            .any(|name| name.eq_ignore_ascii_case(label))
    };
    if listed(UTF8_LABELS) {
        return !text.starts_with("\u{FFFD}\u{FFFD}");
    }
    if listed(TABLE_LABELS) {
        return charset_decoder(label.as_bytes())
            .is_some_and(|decode| !MARKS.iter().any(|mark| text.starts_with(&decode(mark))));
    }
    listed(DECODER_LABELS)
        && !text.contains(['\u{FFFD}', '\u{e}', '\u{f}', '\u{1b}'])
        && !starts_with_a_mark(raw, part)
}

/// Whether the part's bytes start with a byte order mark (`MARKS`), once its transfer encoding is
/// undone as mail-parser undid it, with its own decoders. A part whose offsets fall outside `raw`
/// counts as one.
fn starts_with_a_mark(raw: &[u8], part: &mail_parser::MessagePart<'_>) -> bool {
    let Some(body) = sent_body(raw, part) else {
        return true;
    };
    let mut stream = mail_parser::parsers::MessageStream::new(body);
    let bytes = match part.encoding {
        mail_parser::Encoding::Base64 => stream.decode_base64_mime(b"").1,
        mail_parser::Encoding::QuotedPrintable => stream.decode_quoted_printable_mime(b"").1,
        mail_parser::Encoding::None => body.into(),
    };
    MARKS.iter().any(|mark| bytes.starts_with(mark))
}

/// The part's body as sent, from `raw`, or `None` when its offsets fall outside it. The offsets
/// of a part of the top-level message index `raw`, its input.
fn sent_body<'a>(raw: &'a [u8], part: &mail_parser::MessagePart<'_>) -> Option<&'a [u8]> {
    usize::try_from(part.offset_body)
        .ok()
        .zip(usize::try_from(part.offset_end).ok())
        .and_then(|(body, end)| raw.get(body..end))
}

/// Whether mail-parser changed the bytes of a file by reading them as text. It holds a part that
/// is not text (`media_type`) as text when it can't read the part as a file: one cut off at the
/// end of the mail, a multipart whose boundary never comes, or a message it read as empty. Bytes
/// that are not UTF-8 then become U+FFFD, a `charset` converts them, or only some of them are
/// kept, so such a part counts as changed when its text is not its bytes as sent; the offsets of
/// a part of the top-level message index `raw`, its input. A part without a Content-Type outside
/// a digest is text/plain (RFC 2045 5.2), so text here; `converted_alike` takes its text only
/// when its bytes were UTF-8.
fn changed_as_text(raw: &[u8], part: &mail_parser::MessagePart<'_>, in_digest: bool) -> bool {
    let PartType::Text(_) = &part.body else {
        return false;
    };
    if media_type(part, in_digest).0.eq_ignore_ascii_case("text") {
        return false;
    }
    sent_body(raw, part) != Some(part.contents())
}

/// A part's type and subtype as mail-parser reads them, and mail apps too: without a
/// Content-Type, a member of a `multipart/digest` is `message/rfc822` (RFC 2046 5.1.5), and any
/// other part `text/plain` (RFC 2045 5.2).
fn media_type<'a>(
    part: &'a mail_parser::MessagePart<'_>,
    in_digest: bool,
) -> (&'a str, Option<&'a str>) {
    match part.content_type() {
        Some(content_type) => (content_type.ctype(), content_type.subtype()),
        None if in_digest => ("message", Some("rfc822")),
        None => ("text", Some("plain")),
    }
}

/// Whether `media_type` gives the part `ctype/subtype`, in any ASCII case.
fn is_media_type(
    part: &mail_parser::MessagePart<'_>,
    in_digest: bool,
    ctype: &str,
    subtype: &str,
) -> bool {
    let (part_type, part_subtype) = media_type(part, in_digest);
    part_type.eq_ignore_ascii_case(ctype)
        && part_subtype.is_some_and(|part_subtype| part_subtype.eq_ignore_ascii_case(subtype))
}

/// The text of a text part as a mail app shows it: `None` when mail-parser may not have decoded
/// it as mail apps do (`decoded_alike`), as raw letters can differ from what the person's client
/// decodes, leniently or at all (RFC 2045 6.7, 6.8), and text read in another charset differs. A
/// part mail-parser could not end at its boundary keeps its text as sent when it has no transfer
/// encoding, as when only the closing boundary is missing.
fn readable_text<'a>(
    raw: &[u8],
    part: &mail_parser::MessagePart<'_>,
    text: &'a str,
) -> Option<&'a str> {
    decoded_alike(raw, part).then_some(text)
}

/// For each part, whether a mail app shows it: the root, and every child of a shown
/// multipart, except that of a `multipart/alternative` only one member is shown, the last
/// member a mail app can show as a body that holds no HTML, or else the last member it can
/// show (RFC 2046 5.1.4), and of a `multipart/related` only its root, none when
/// `related_root` finds none. Passing over members with HTML keeps the plain version of an HTML
/// part as the plain-text body: the HTML body is read first, so the plain-text body matters
/// only when no HTML is shown, and then no alternative on the way has a member with HTML.
/// With `html_view`, the parts shown with an HTML body, which is how `get_message` picks
/// the body: of an alternative, its last showable member, or none when that member holds no
/// HTML while another member does, as mail apps differ there. When no member holds HTML,
/// both choices give the same member.
/// mail-parser stores each multipart before its children, so one pass in order suffices.
fn shown_parts(message: &mail_parser::Message<'_>, holds: &[bool], html_view: bool) -> Vec<bool> {
    let mut shown = vec![false; message.parts.len()];
    if let Some(root) = shown.first_mut() {
        *root = true;
    }
    for (index, part) in message.parts.iter().enumerate() {
        let PartType::Multipart(children) = &part.body else {
            continue;
        };
        let visible = shown.get(index) == Some(&true);
        let only = if part.is_content_type("multipart", "alternative") {
            let mut members = children
                .iter()
                .rev()
                .copied()
                .filter(|&child| message.part(child).is_some_and(shows_as_body));
            let last = members.clone().next();
            Some(if html_view {
                last.filter(|&last| any_holds(holds, &[last]) || !any_holds(holds, children))
            } else {
                members.find(|&child| !any_holds(holds, &[child])).or(last)
            })
        } else if part.is_content_type("multipart", "related") {
            Some(related_root(message, part, children))
        } else {
            None
        };
        for &child in children {
            if let Some(slot) = usize::try_from(child)
                .ok()
                .and_then(|child| shown.get_mut(child))
            {
                *slot = visible && only.is_none_or(|member| member == Some(child));
            }
        }
    }
    shown
}

/// The plain-text body, whether it is `""` on purpose, and the part it comes from when that is
/// a text-list part (else `None`). In this order: the first part of
/// mail-parser's text list that a mail app shows (`readable_text` of it, `""` withheld when
/// that is `None`); else the Markdown body; else `""` withheld when the text list has only
/// parts a mail app hides, or a shown plain-text part did not decode and mail-parser lists it
/// as an attachment without being a file; else `None`. A hidden part never stands in for
/// what the person sees, and a part that did not decode can run on through later parts that
/// a mail app shows separately or hides, as mail-parser ends a part only at its own boundary.
/// The Markdown body comes before the fallback because the person sees it: it is only taken
/// in a message with no alternative or related part, so never in place of a hidden part.
/// Whether a mail client may read the parts differently is decided once in `parse_message`,
/// so this walk does not repeat it. Whether a part is plain text is read from `media_type`.
fn text_body_of<'a>(
    message: &'a mail_parser::Message<'a>,
    holds: &[bool],
) -> (Option<&'a str>, bool, Option<u32>) {
    let shown = shown_parts(message, holds, false);
    let is_shown = |id: u32| usize::try_from(id).ok().and_then(|id| shown.get(id)) == Some(&true);
    let mut hidden = false;
    for &id in &message.text_body {
        let Some(part) = message.part(id) else {
            continue;
        };
        let PartType::Text(text) = &part.body else {
            continue;
        };
        if is_shown(id) {
            let readable = readable_text(&message.raw_message, part, text);
            return (
                Some(readable.unwrap_or_default()),
                readable.is_none(),
                Some(id),
            );
        }
        hidden = true;
    }
    if let Some(markdown) = markdown_body(message).and_then(|id| message.part(id)?.text_contents())
    {
        return (Some(markdown), false, None);
    }
    let members = digest_members(message);
    let withheld = hidden
        || message
            .parts
            .iter()
            .zip(&members)
            .zip(0..)
            .any(|((part, &in_digest), id)| {
                matches!(part.body, PartType::Text(_))
                    && part.is_encoding_problem
                    && is_shown(id)
                    && is_media_type(part, in_digest, "text", "plain")
                    && message.attachments.binary_search(&id).is_ok()
                    && !is_file(message, id, part)
            });
    (withheld.then_some(""), withheld, None)
}

/// The parts a mail app shows one after another, in part order: part `body`, and each text or
/// HTML part in mail-parser's body lists that a mail app shows with an HTML body (`shown_parts` with
/// `html_view`), each as `readable_text` reads it; a part it gives no text for is
/// left out. Empty unless two or more are left. A part counts as HTML by its content type, so an HTML
/// part read as text after a missing boundary is still HTML.
fn body_parts(
    message: &mail_parser::Message<'_>,
    holds: &[bool],
    body: u32,
) -> (Vec<BodyPart>, bool) {
    let shown = shown_parts(message, holds, true);
    let mut in_lists = vec![false; message.parts.len()];
    for &id in message.text_body.iter().chain(&message.html_body) {
        if let Some(slot) = usize::try_from(id).ok().and_then(|id| in_lists.get_mut(id)) {
            *slot = true;
        }
    }
    let mut skipped = false;
    let parts: Vec<_> = message
        .parts
        .iter()
        .zip(0..)
        .zip(in_lists.iter().zip(&shown))
        .filter(|&((_, id), (&in_list, &shown))| id == body || (in_list && shown))
        .filter_map(|((part, _), _)| {
            let (PartType::Text(text) | PartType::Html(text)) = &part.body else {
                return None;
            };
            let Some(text) = readable_text(&message.raw_message, part, text) else {
                skipped = true;
                return None;
            };
            Some(if part.is_content_type("text", "html") {
                BodyPart::Html(text.to_owned())
            } else {
                BodyPart::Text(text.to_owned())
            })
        })
        .collect();
    (if parts.len() > 1 { parts } else { Vec::new() }, skipped)
}

/// Distinct boundary prefixes the check keeps: far more than real mail has (boundaries are at
/// most 70 characters), few enough to keep its memory small. Past it the body is withheld.
const MAX_BOUNDARY_PREFIXES: usize = 1 << 18;

/// The message's boundaries in ASCII lowercase, as a byte trie: `(node, byte)` gives the next
/// node, and node 0 is the root.
type Trie = HashMap<(usize, u8), usize>;

/// Where a part lies in the raw message, from its headers to its end; for a multipart, also its
/// boundary as mail-parser matches it and the boundary's node in the trie.
struct Span<'a> {
    header: usize,
    body: usize,
    end: usize,
    boundary: Option<(&'a [u8], usize)>,
}

/// Where a mail client may start to read the message's parts differently from this parser, so
/// what it shows from there on would differ, or `None` when it reads them alike: the first part
/// whose Content-Type headers differ (`content_types_differ`), whose type a mail client may read
/// differently (`type_differs`), or that is a multipart whose `boundary` a mail client may read
/// differently (`parameter_differs`), or the first place its boundary lines do
/// (`boundaries_differ_from`).
fn read_differently_from(message: &mail_parser::Message<'_>) -> Option<usize> {
    let raw: &[u8] = &message.raw_message;
    let typed = message
        .parts
        .iter()
        .find(|part| {
            content_types_differ(raw, part)
                || type_differs(raw, part)
                || part
                    .content_type()
                    .is_some_and(|content_type| content_type.ctype() == "multipart")
                    && parameter_differs(raw, part, "boundary")
        })
        .map(|part| usize::try_from(part.offset_header).unwrap_or_default());
    typed
        .into_iter()
        .chain(boundaries_differ_from(message))
        .min()
}

/// Whether the part has Content-Type headers whose values differ: mail-parser reads the last
/// copy, and a mail client may read another, as another type or with another boundary. The
/// offsets of a header of a part of the top-level message index `raw`, its input.
fn content_types_differ(raw: &[u8], part: &mail_parser::MessagePart<'_>) -> bool {
    let mut values = part
        .headers
        .iter()
        .filter(|header| header.name == HeaderName::ContentType)
        .map(|header| header_text(raw, header));
    let first = values.next();
    values.any(|value| Some(value) != first)
}

/// Whether a copy of the part's Content-Type header may give a mail client another type than
/// mail-parser read (`type_reads_alike`); a copy whose offsets fall outside `raw` counts as one.
fn type_differs(raw: &[u8], part: &mail_parser::MessagePart<'_>) -> bool {
    let parsed = part.content_type();
    part.headers
        .iter()
        .filter(|header| header.name == HeaderName::ContentType)
        .any(|header| header_text(raw, header).is_none_or(|value| !type_reads_alike(value, parsed)))
}

/// Whether a Content-Type value as sent starts with the type in the one form mail clients read
/// alike, and mail-parser read that type (`parsed`, from the last copy): a type and a subtype that
/// are tokens (RFC 2045 5.1) around a `/`, then only spaces up to a `;` or the end. mail-parser
/// drops quotes, backslashes, comments and spaces around the type and the subtype
/// (`"text"/plain`, `text/(x)plain`) but keeps other bytes in them, a form feed say, reads a
/// subtype on through a space, `/` or `,`, and reads a value without a type (`/plain`) as no
/// Content-Type, so as text/plain. A mail client may not: Thunderbird ends the type at its first
/// white space, `;` or `,`, and Python's `email` package trims white space around it, keeps quotes
/// and comments in it and reads one with a second `/` as text/plain. Either may then read another
/// type than mail-parser, and show the part otherwise or not at all.
fn type_reads_alike(value: &[u8], parsed: Option<&mail_parser::ContentType<'_>>) -> bool {
    let ctype = token_len(value);
    let Some(rest) = value[ctype..].strip_prefix(b"/") else {
        return false;
    };
    let subtype = token_len(rest);
    let next = rest[subtype..].trim_ascii_start();
    let read = |word: &str, sent: &[u8]| word.as_bytes().eq_ignore_ascii_case(sent);
    (next.is_empty() || next.starts_with(b";"))
        && parsed.is_some_and(|parsed| {
            read(parsed.ctype(), &value[..ctype])
                && parsed
                    .subtype()
                    .is_some_and(|word| read(word, &rest[..subtype]))
        })
}

/// Whether a copy of the part's Content-Type header may give a mail client another parameter
/// `name` than mail-parser read (`parameter_reads_alike`); a copy whose offsets fall outside `raw`
/// counts as one.
fn parameter_differs(raw: &[u8], part: &mail_parser::MessagePart<'_>, name: &str) -> bool {
    let parsed = part
        .content_type()
        .and_then(|content_type| content_type.attribute(name));
    part.headers
        .iter()
        .filter(|header| header.name == HeaderName::ContentType)
        .any(|header| {
            header_text(raw, header)
                .is_none_or(|value| !parameter_reads_alike(value, name.as_bytes(), parsed))
        })
}

/// Whether a Content-Type value as sent gives parameter `name` the value mail-parser read
/// (`parsed`) in the one form mail clients read alike, or holds no `name` when mail-parser read
/// none. That form is the name once (`name_at`), in any ASCII case, after a `;` that ends the
/// parameters before it (`ends_parameters`), as a parameter in the form `parameter` reads whose
/// value is quoted, with no space at either end, or a token (RFC 2045 5.1) without the `*` and `'`
/// of RFC 2231. mail-parser joins RFC 2231 pieces (`name*0`), even with a space before the `*`,
/// decodes an encoded word in a value (`=?us-ascii?q?b?=`), reads the first copy of a repeated
/// parameter, skips comments and, outside values, quotes and backslashes, and reads an unquoted
/// value on through spaces and `=`. A mail client may do none of these: Python's `email` package,
/// say, reads on through a `;` while a quote is open, keeps what follows a value in it and drops
/// the spaces that end a boundary, and its newer parser ends an unquoted value at a `*` or a byte
/// a token can't hold and reads none with a `'`. So the name anywhere else `name_at` finds it, in
/// a comment say, counts as read differently too.
fn parameter_reads_alike(value: &[u8], name: &[u8], parsed: Option<&str>) -> bool {
    let Some(at) = name_at(value, name) else {
        return parsed.is_none();
    };
    let Some((named, written, len)) = parameter(&value[at..]) else {
        return false;
    };
    let quoted = written
        .strip_prefix(b"\"")
        .and_then(|quoted| quoted.strip_suffix(b"\""));
    let given = quoted.unwrap_or(written);
    let token = |byte: &u8| byte.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=*'".contains(byte);
    named.eq_ignore_ascii_case(name)
        && ends_parameters(&value[..at])
        && given.trim_ascii() == given
        && (quoted.is_some() || given.iter().all(token))
        && name_at(&value[at + len..], name).is_none()
        && parsed.map(str::as_bytes) == Some(given)
}

/// Whether the text before a parameter's name, `before`, ends the parameters before it, so that
/// mail-parser and mail clients read the name outside every comment and quoted value: each
/// parameter after the type (whose form `type_reads_alike` checks) is in the form `parameter`
/// reads, the last `;` has only spaces, tabs and line breaks after it, and a CR stands only right
/// before an LF. Outside a quoted value, mail-parser reads a `(` as opening a comment and a `\` as
/// an escape where a mail client may not, and a `\` right before the `"` that ends a quoted value
/// escapes that `"` for some readers only.
fn ends_parameters(before: &[u8]) -> bool {
    // RFC 5322 allows a CR only right before an LF.
    if before
        .split(|&byte| byte == b'\r')
        .skip(1)
        .any(|after| !after.starts_with(b"\n"))
    {
        return false;
    }
    let start = before.iter().take_while(|&&byte| byte != b';').count();
    let mut rest = &before[start..];
    while let Some(after) = rest.strip_prefix(b";") {
        let Some((_, _, len)) = parameter(after) else {
            return after.iter().all(|byte| b" \t\r\n".contains(byte));
        };
        rest = &after[len..];
    }
    false
}

/// The parameter at the start of `bytes`, text after a `;`, when it is in the form of RFC 2045
/// 5.1 up to the next `;` or the end: its name, its value as written (a quoted one with its
/// quotes) and its length. That form is a name (a token), `=` and a value, with spaces, tabs and
/// line breaks allowed around each: a quoted value that doesn't end in a `\` and has no byte but
/// `quoted_text`, or an unquoted one with no space, control byte, `"`, `(`, `)`, `\` or `;`, such
/// as a token, `café.txt` or `text/html`.
fn parameter(bytes: &[u8]) -> Option<(&[u8], &[u8], usize)> {
    let space = |bytes: &[u8]| {
        bytes
            .iter()
            .position(|byte| !b" \t\r\n".contains(byte))
            .unwrap_or(bytes.len())
    };
    let start = space(bytes);
    let name = &bytes[start..start + token_len(&bytes[start..])];
    let after = &bytes[start + name.len()..];
    let after = after[space(after)..]
        .strip_prefix(b"=")
        .filter(|_| !name.is_empty())?;
    let after = &after[space(after)..];
    let (value, rest) = if let Some(quoted) = after.strip_prefix(b"\"") {
        let end = quoted.iter().position(|&byte| byte == b'"')?;
        let value = &quoted[..end];
        if value.ends_with(b"\\") || !value.iter().copied().all(quoted_text) {
            return None;
        }
        (&after[..end + 2], &quoted[end + 1..])
    } else {
        after.split_at(
            after
                .iter()
                .position(|byte| byte.is_ascii_control() || b" \"()\\;".contains(byte))
                .unwrap_or(after.len()),
        )
    };
    let rest = &rest[space(rest)..];
    (rest.is_empty() || rest.starts_with(b";")).then_some((name, value, bytes.len() - rest.len()))
}

/// Whether `byte` may stand in a quoted value: quoted text holds no control byte but a tab, or a
/// fold's CR and LF (RFC 5322 3.2.4).
const fn quoted_text(byte: u8) -> bool {
    !byte.is_ascii_control() || matches!(byte, b'\t' | b'\r' | b'\n')
}

/// Where parameter `name` first stands in `bytes`, a Content-Type value or the text after a
/// parameter's value, in any ASCII case. Past the first `;`, the search skips one parameter after
/// another while each is in the form `parameter` reads, with a name that doesn't hold `name` and
/// a value with no `=`; so `name` may stand in such a value, as in `name="charset.txt"`.
fn name_at(bytes: &[u8], name: &[u8]) -> Option<usize> {
    let find = |bytes: &[u8]| {
        bytes
            .windows(name.len())
            .position(|word| word.eq_ignore_ascii_case(name))
    };
    let first = bytes
        .iter()
        .position(|&byte| byte == b';')
        .unwrap_or(bytes.len());
    let mut start = first;
    while let Some((named, value, len)) = bytes[start..].strip_prefix(b";").and_then(parameter) {
        if find(named).is_some() || value.contains(&b'=') {
            break;
        }
        start += 1 + len;
    }
    find(&bytes[..first]).or_else(|| find(&bytes[start..]).map(|at| start + at))
}

/// The length of the token (RFC 2045 5.1) at the start of `bytes`.
pub fn token_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| !byte.is_ascii_graphic() || b"()<>@,;:\\\"/[]?=".contains(byte))
        .unwrap_or(bytes.len())
}

/// A header's value as sent, without the spaces and line breaks around it; `None` when its
/// offsets fall outside `raw`.
fn header_text<'a>(raw: &'a [u8], header: &mail_parser::Header<'_>) -> Option<&'a [u8]> {
    let start = usize::try_from(header.offset_start).ok()?;
    let end = usize::try_from(header.offset_end).ok()?;
    raw.get(start..end).map(<[u8]>::trim_ascii)
}

/// Where a mail client may start to read the message's parts differently from this parser by
/// their boundary lines, 0 when that can't be placed. mail-parser ends a part only at the
/// boundary of its own multipart and may start or end a part at a boundary match that is not a
/// whole line, while a mail client ends a part at any enclosing boundary line and starts or ends
/// one only at a whole boundary line. One scan of the raw bytes compares the boundary lines, in
/// any ASCII case, with the parts the parser built; a line is normal only when it is the
/// innermost open multipart's own delimiter as this parser reads it and no other open boundary
/// matches it. Parts that do not sit between boundary lines, offsets that do not nest, and more
/// boundary text than `MAX_BOUNDARY_PREFIXES` count as read differently from the start.
fn boundaries_differ_from(message: &mail_parser::Message<'_>) -> Option<usize> {
    let raw: &[u8] = &message.raw_message;
    let mut trie = Trie::new();
    let Some(spans) = spans(message, raw.len(), &mut trie) else {
        return Some(0);
    };
    if spans.iter().all(|span| span.boundary.is_none()) {
        return None;
    }
    if !parts_sit_between_boundary_lines(message, raw, &spans) {
        return Some(0);
    }
    first_differing_line(raw, &spans, &trie)
}

/// Each part's span, in mail-parser's order, with every multipart's boundary added to `trie`.
/// `None` when the offsets do not nest in order, a multipart has no boundary, or the trie
/// would pass `MAX_BOUNDARY_PREFIXES` nodes.
fn spans<'a>(
    message: &'a mail_parser::Message<'_>,
    len: usize,
    trie: &mut Trie,
) -> Option<Vec<Span<'a>>> {
    let mut spans: Vec<Span<'a>> = Vec::with_capacity(message.parts.len());
    for part in &message.parts {
        let header = usize::try_from(part.offset_header).ok()?;
        let body = usize::try_from(part.offset_body).ok()?;
        let end = usize::try_from(part.offset_end).ok()?;
        if header > body
            || body > end
            || end > len
            || spans.last().is_some_and(|last| header < last.header)
        {
            return None;
        }
        let boundary = if matches!(part.body, PartType::Multipart(_)) {
            let boundary = part.content_type()?.attribute("boundary")?.as_bytes();
            if boundary.is_empty() {
                return None;
            }
            Some((boundary, insert(trie, boundary)?))
        } else {
            None
        };
        spans.push(Span {
            header,
            body,
            end,
            boundary,
        });
    }
    Some(spans)
}

/// Adds `boundary` in ASCII lowercase and returns its node, or `None` past the cap.
fn insert(trie: &mut Trie, boundary: &[u8]) -> Option<usize> {
    let mut node = 0;
    for &byte in boundary {
        let next = trie.len() + 1;
        node = *trie
            .entry((node, byte.to_ascii_lowercase()))
            .or_insert(next);
        if trie.len() >= MAX_BOUNDARY_PREFIXES {
            return None;
        }
    }
    Some(node)
}

/// Whether every part of every multipart starts right after a whole line of `--`, that
/// multipart's exact boundary, then only spaces or tabs, and ends right before a line of `--`
/// and that boundary, as a strict client needs.
fn parts_sit_between_boundary_lines(
    message: &mail_parser::Message<'_>,
    raw: &[u8],
    spans: &[Span<'_>],
) -> bool {
    message.parts.iter().zip(spans).all(|(part, span)| {
        let (PartType::Multipart(children), Some((boundary, _))) = (&part.body, span.boundary)
        else {
            return true;
        };
        children.iter().all(|&child| {
            usize::try_from(child)
                .ok()
                .and_then(|child| spans.get(child))
                .is_some_and(|child| {
                    starts_after_boundary_line(raw, child.header, boundary)
                        && ends_before_boundary_line(raw, child.end, boundary)
                })
        })
    })
}

/// Whether the line ending just before `header` is `--` and `boundary`, then only spaces or
/// tabs, then CRLF or LF, and starts the input or follows an LF.
fn starts_after_boundary_line(raw: &[u8], header: usize, boundary: &[u8]) -> bool {
    let Some(line) = raw.get(..header).and_then(|line| line.strip_suffix(b"\n")) else {
        return false;
    };
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let kept = line
        .iter()
        .rposition(|&byte| byte != b' ' && byte != b'\t')
        .map_or(0, |last| last + 1);
    line.get(..kept)
        .and_then(|line| line.strip_suffix(boundary))
        .and_then(|line| line.strip_suffix(b"--"))
        .is_some_and(|before| before.is_empty() || before.ends_with(b"\n"))
}

/// Whether the part ending at `end` is followed by a line of `--` and `boundary`: after a line
/// break, or right at `end` when the part is empty and `end` starts a line. A part that runs
/// to the end of the input only lacks its closing boundary, which mail clients accept.
fn ends_before_boundary_line(raw: &[u8], end: usize, boundary: &[u8]) -> bool {
    if end == raw.len() {
        return true;
    }
    let Some(rest) = raw.get(end..) else {
        return false;
    };
    let at_line_start = end
        .checked_sub(1)
        .is_none_or(|before| raw.get(before) == Some(&b'\n'));
    rest.strip_prefix(b"\r\n")
        .or_else(|| rest.strip_prefix(b"\n"))
        .or_else(|| at_line_start.then_some(rest))
        .and_then(|line| line.strip_prefix(b"--"))
        .is_some_and(|line| line.starts_with(boundary))
}

/// Where the first line starting with `--` and an open boundary, in any ASCII case, that is
/// anything but the innermost open multipart's own delimiter past its headers, as mail-parser
/// matches it and with no other open boundary matching, starts; 0 when a part runs past the part
/// that holds it. Lines end at CR or LF; parts open and close as the scan passes their spans.
fn first_differing_line(raw: &[u8], spans: &[Span<'_>], trie: &Trie) -> Option<usize> {
    let mut open = vec![0_u32; trie.len() + 1];
    let mut stack: Vec<&Span<'_>> = Vec::new();
    let mut parts = spans.iter().peekable();
    let mut start = 0;
    for line in raw.split(|&byte| byte == b'\r' || byte == b'\n') {
        let offset = start;
        start += line.len() + 1;
        let Some(rest) = line.strip_prefix(b"--") else {
            continue;
        };
        while let Some(part) = parts.next_if(|part| part.header <= offset) {
            close(&mut stack, &mut open, part.header);
            if stack.last().is_some_and(|top| part.end > top.end) {
                return Some(0);
            }
            if let Some(count) = part.boundary.and_then(|(_, node)| open.get_mut(node)) {
                *count += 1;
            }
            stack.push(part);
        }
        close(&mut stack, &mut open, offset);
        let Some((node, opens)) = longest_open(trie, &open, rest) else {
            continue;
        };
        let own = opens == 1
            && open.get(node) == Some(&1)
            && stack.last().is_some_and(|top| {
                offset >= top.body
                    && top
                        .boundary
                        .is_some_and(|(boundary, own)| own == node && rest.starts_with(boundary))
            });
        if !own {
            return Some(offset);
        }
    }
    None
}

/// Pops the parts that end at or before `offset`.
fn close(stack: &mut Vec<&Span<'_>>, open: &mut [u32], offset: usize) {
    while let Some(top) = stack.pop_if(|top| top.end <= offset) {
        if let Some(count) = top.boundary.and_then(|(_, node)| open.get_mut(node)) {
            *count = count.saturating_sub(1);
        }
    }
}

/// The deepest open boundary node that `rest` starts with, in any ASCII case, and how many
/// open nodes the walk passed.
fn longest_open(trie: &Trie, open: &[u32], rest: &[u8]) -> Option<(usize, usize)> {
    let mut node = 0;
    let mut longest = None;
    let mut opens = 0;
    for &byte in rest {
        let Some(&next) = trie.get(&(node, byte.to_ascii_lowercase())) else {
            break;
        };
        node = next;
        if open.get(node).is_some_and(|&count| count > 0) {
            longest = Some(node);
            opens += 1;
        }
    }
    longest.map(|node| (node, opens))
}

fn headers(message: &mail_parser::Message<'_>, raw: &[u8]) -> MessageHeaders {
    let to = addresses(message.to());
    let cc = addresses(message.cc());
    let reply_to = addresses(message.reply_to());
    MessageHeaders {
        message_id: message.message_id().map(str::to_owned),
        in_reply_to: id_list(message.in_reply_to()),
        references: id_list(message.references()),
        from: addresses(message.from()),
        from_clear: sender_of(message, raw).is_some(),
        from_values: from_values(message, raw),
        to_clear: list_clear(message, raw, &HeaderName::To, &to),
        cc_clear: list_clear(message, raw, &HeaderName::Cc, &cc),
        reply_to_clear: list_clear(message, raw, &HeaderName::ReplyTo, &reply_to),
        to,
        cc,
        reply_to,
        subject: message.subject().map(str::to_owned),
        date: message.date().and_then(to_chrono),
    }
}

fn id_list(value: &HeaderValue<'_>) -> Vec<String> {
    match value {
        HeaderValue::Text(id) => vec![id.to_string()],
        HeaderValue::TextList(ids) => ids.iter().map(ToString::to_string).collect(),
        _ => Vec::new(),
    }
}

fn addresses(value: Option<&mail_parser::Address<'_>>) -> Vec<EmailAddress> {
    value
        .map(|list| {
            list.iter()
                .filter_map(|addr| {
                    Some(EmailAddress {
                        name: addr.name().map(str::to_owned),
                        address: addr.address()?.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the `name` headers of a message parsed from `raw` read as `parsed`, the addresses
/// this parser made of them: there is no such header, or there is one and each part of its value
/// between commas that holds an `@` shows the next of them only, as [`shows_only`] finds. A part
/// without one, such as a name alone or an empty group, adds no address.
fn list_clear(
    message: &mail_parser::Message<'_>,
    raw: &[u8],
    name: &HeaderName<'_>,
    parsed: &[EmailAddress],
) -> bool {
    let mut values = message
        .headers()
        .iter()
        .filter(|header| header.name == *name)
        .map(|header| header_text(raw, header));
    let value = match (values.next(), values.next()) {
        (None, _) => return true,
        (Some(Some(value)), None) => String::from_utf8_lossy(value),
        _ => return false,
    };
    let written: Vec<&str> = value
        .split(',')
        .map(str::trim)
        .filter(|part| part.contains('@'))
        .collect();
    written.len() == parsed.len()
        && written
            .iter()
            .zip(parsed)
            .all(|(part, address)| shows_only(part, &address.address))
}

/// Whether a `From` value, or a part of an address list, is `address` alone, or ends with it
/// between the value's only `<` and a `>`, where `address` is [`clear_address`].
fn shows_only(value: &str, address: &str) -> bool {
    let written = match value.split_once('<') {
        Some((_, rest)) => rest.strip_suffix('>'),
        None => Some(value),
    };
    written == Some(address) && clear_address(address)
}

/// Whether `address` holds one `@`, with text before and after it, and no whitespace, control
/// character or any of `"(),:;<>[\]`, which mark out the parts of an address header.
pub fn clear_address(address: &str) -> bool {
    address.matches('@').count() == 1
        && !address.starts_with('@')
        && !address.ends_with('@')
        && !address
            .contains(|c: char| c.is_whitespace() || c.is_control() || "\"(),:;<>[\\]".contains(c))
}

fn attachment(part: &mail_parser::MessagePart<'_>, id: u32, in_digest: bool) -> Attachment {
    let content_type = match media_type(part, in_digest) {
        (ctype, Some(subtype)) => format!("{ctype}/{subtype}"),
        (ctype, None) => ctype.to_owned(),
    };
    Attachment {
        id,
        filename: part.attachment_name().map(str::to_owned),
        content_type: content_type.to_ascii_lowercase(),
        size: part.len(),
        content_id: part.content_id().map(str::to_owned),
        inline: part
            .content_disposition()
            .is_some_and(|cd| cd.ctype().eq_ignore_ascii_case("inline")),
    }
}

fn to_chrono(date: &mail_parser::DateTime) -> Option<DateTime<FixedOffset>> {
    let sign = if date.tz_before_gmt { -1 } else { 1 };
    let offset = sign * (i32::from(date.tz_hour) * 3600 + i32::from(date.tz_minute) * 60);
    let naive = NaiveDate::from_ymd_opt(
        i32::from(date.year),
        u32::from(date.month),
        u32::from(date.day),
    )?
    .and_hms_opt(
        u32::from(date.hour),
        u32::from(date.minute),
        u32::from(date.second),
    )?;
    FixedOffset::east_opt(offset)?
        .from_local_datetime(&naive)
        .single()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MULTIPART: &str = "From: \"Alice Example\" <alice@example.com>\r\n\
To: bob@example.com, Carol <carol@example.com>\r\n\
Cc: dave@example.com\r\n\
Reply-To: replies@example.com\r\n\
Subject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?=\r\n\
Date: Tue, 06 Oct 2026 14:30:00 -0700\r\n\
Message-ID: <msg-2@example.com>\r\n\
In-Reply-To: <msg-1@example.com>\r\n\
References: <msg-0@example.com> <msg-1@example.com>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=\"inner\"\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Hello Bob\r\n\
--inner\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p>Hello Bob</p>\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--outer--\r\n";

    #[test]
    fn parses_headers_bodies_and_attachments() {
        let message = parse_message(7, MessageFlags::default(), MULTIPART.as_bytes()).unwrap();
        let headers = &message.headers;
        assert_eq!(message.uid, 7);
        assert_eq!(headers.message_id.as_deref(), Some("msg-2@example.com"));
        assert_eq!(headers.in_reply_to, ["msg-1@example.com"]);
        assert_eq!(
            headers.references,
            ["msg-0@example.com", "msg-1@example.com"]
        );
        assert_eq!(
            headers.from,
            [EmailAddress::with_name(
                "Alice Example",
                "alice@example.com"
            )]
        );
        assert_eq!(
            headers.to,
            [
                EmailAddress::new("bob@example.com"),
                EmailAddress::with_name("Carol", "carol@example.com"),
            ]
        );
        assert_eq!(headers.cc, [EmailAddress::new("dave@example.com")]);
        assert_eq!(headers.reply_to, [EmailAddress::new("replies@example.com")]);
        assert_eq!(headers.subject.as_deref(), Some("Grüße"));
        assert_eq!(
            headers.date.unwrap().to_rfc3339(),
            "2026-10-06T14:30:00-07:00"
        );
        assert_eq!(
            message.text_body.as_deref().map(str::trim),
            Some("Hello Bob")
        );
        assert_eq!(
            message.html_body.as_deref().map(str::trim),
            Some("<p>Hello Bob</p>")
        );
        assert_eq!(
            message.attachments,
            [Attachment {
                id: 1,
                filename: Some("invoice.pdf".to_owned()),
                content_type: "application/pdf".to_owned(),
                size: 9,
                content_id: None,
                inline: false,
            }]
        );
    }

    #[test]
    fn plain_text_message_has_no_html_body() {
        let raw = "From: a@example.com\r\nSubject: hi\r\n\r\njust text\r\n";
        let message = parse_message(1, MessageFlags::default(), raw.as_bytes()).unwrap();
        assert_eq!(
            message.text_body.as_deref().map(str::trim),
            Some("just text")
        );
        assert_eq!(message.html_body, None);
        assert_eq!(message.attachments, []);
        assert_eq!(message.headers.message_id, None);
    }

    #[test]
    fn html_only_message_has_no_text_body() {
        let raw =
            "From: a@example.com\r\nSubject: hi\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n";
        let message = parse_message(1, MessageFlags::default(), raw.as_bytes()).unwrap();
        assert_eq!(message.text_body, None);
        assert_eq!(
            message.html_body.as_deref().map(str::trim),
            Some("<p>Hi</p>")
        );
    }

    fn parse(raw: &str) -> Message {
        parse_message(1, MessageFlags::default(), raw.as_bytes()).unwrap()
    }

    fn listed(message: &Message) -> Vec<(u32, Option<&str>, &str)> {
        message
            .attachments
            .iter()
            .map(|a| (a.id, a.filename.as_deref(), a.content_type.as_str()))
            .collect()
    }

    #[test]
    fn a_markdown_only_message_has_it_as_text_body() {
        let raw = "From: a@example.com\r\nSubject: hi\r\n\
Content-Type: text/markdown; charset=\"utf-8\"\r\n\r\n# Heading\r\n\r\n- item *one*\r\n";
        let message = parse(raw);
        assert_eq!(
            message.text_body.as_deref().map(str::trim),
            Some("# Heading\r\n\r\n- item *one*")
        );
        assert_eq!(message.html_body, None);
        assert_eq!(message.attachments, []);
        assert_eq!(attachment_data(raw.as_bytes(), 1, 1 << 20), None);
    }

    #[test]
    fn a_markdown_body_leaves_the_attachment_ids_in_order() {
        let raw = "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
--outer\r\n\
Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK\r\n\
--outer\r\n\
Content-Type: text/markdown\r\n\
Content-Disposition: attachment\r\n\
\r\n\
kept\r\n\
--outer\r\n\
Content-Type: text/markdown; name=\"notes.md\"\r\n\
\r\n\
named\r\n\
--outer\r\n\
Content-Type: text/markdown; charset=utf-8\r\n\
\r\n\
# Notes\r\n\
--outer--\r\n";
        let message = parse(raw);
        assert_eq!(message.text_body.as_deref().map(str::trim), Some("# Notes"));
        assert_eq!(
            listed(&message),
            [
                (1, Some("invoice.pdf"), "application/pdf"),
                (2, None, "text/markdown"),
                (3, Some("notes.md"), "text/markdown"),
            ]
        );
        let pdf = attachment_data(raw.as_bytes(), 1, 1 << 20).unwrap();
        assert_eq!(pdf.content.as_deref(), Some(&b"%PDF-1.4\n"[..]));
        assert_eq!(pdf.attachment, message.attachments[0]);
        let named = attachment_data(raw.as_bytes(), 3, 1 << 20).unwrap();
        assert_eq!(named.attachment.filename.as_deref(), Some("notes.md"));
        assert_eq!(attachment_data(raw.as_bytes(), 4, 1 << 20), None);
    }

    #[test]
    fn markdown_beside_a_body_or_in_an_alternative_stays_an_attachment() {
        let multipart = |kind: &str, parts: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/{kind}; boundary=\"b\"\r\n\r\n{parts}--b--\r\n"
            )
        };
        let markdown = "--b\r\nContent-Type: text/markdown\r\n\r\n# Notes\r\n";

        let beside = parse(&multipart(
            "mixed",
            &format!("--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n{markdown}"),
        ));
        assert_eq!(beside.text_body.as_deref().map(str::trim), Some("Hello"));
        assert_eq!(listed(&beside), [(1, None, "text/markdown")]);

        let with_html = parse(&multipart(
            "alternative",
            &format!("{markdown}--b\r\nContent-Type: text/html\r\n\r\n<p>Notes</p>\r\n"),
        ));
        assert_eq!(
            with_html.html_body.as_deref().map(str::trim),
            Some("<p>Notes</p>")
        );
        assert_eq!(with_html.text_body, None);
        assert_eq!(listed(&with_html), [(1, None, "text/markdown")]);

        let with_image = parse(&multipart(
            "alternative",
            &format!(
                "{markdown}--b\r\nContent-Type: image/png\r\n\
Content-Transfer-Encoding: base64\r\n\r\nUE5H\r\n"
            ),
        ));
        assert_eq!(with_image.text_body, None);
        assert_eq!(with_image.html_body, None);
        assert_eq!(
            listed(&with_image),
            [(1, None, "text/markdown"), (2, None, "image/png")]
        );

        let after_image = parse(&multipart(
            "mixed",
            &format!(
                "--b\r\nContent-Type: image/gif\r\nContent-Disposition: inline\r\n\
Content-Transfer-Encoding: base64\r\n\r\nR0lGODlh\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n{markdown}"
            ),
        ));
        assert_eq!(
            after_image.text_body.as_deref().map(str::trim),
            Some("Hello")
        );
        assert_eq!(
            listed(&after_image),
            [(1, None, "image/gif"), (2, None, "text/markdown")]
        );

        let beside_html = parse(&multipart(
            "mixed",
            &format!("--b\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n{markdown}"),
        ));
        assert_eq!(beside_html.text_body, None);
        assert_eq!(
            beside_html.html_body.as_deref().map(str::trim),
            Some("<p>Hi</p>")
        );
        assert_eq!(listed(&beside_html), [(1, None, "text/markdown")]);

        let in_related = parse(&multipart(
            "related",
            &format!(
                "--b\r\nContent-Type: image/png\r\n\
Content-Transfer-Encoding: base64\r\n\r\nUE5H\r\n{markdown}"
            ),
        ));
        assert_eq!(in_related.text_body, None);
        assert_eq!(
            listed(&in_related),
            [(1, None, "image/png"), (2, None, "text/markdown")]
        );
    }

    #[test]
    fn a_markdown_part_that_does_not_decode_stays_an_attachment() {
        let message = parse(
            "From: a@example.com\r\nSubject: hi\r\nContent-Type: text/markdown\r\n\
Content-Transfer-Encoding: base64\r\n\r\nIyBOb3Rlcw.\r\n",
        );
        assert_eq!(message.text_body, None);
        assert_eq!(listed(&message), [(1, None, "text/markdown")]);
    }

    #[test]
    fn another_text_subtype_stays_an_attachment() {
        let message =
            parse("From: a@example.com\r\nSubject: hi\r\nContent-Type: text/csv\r\n\r\na,b\r\n");
        assert_eq!(message.text_body, None);
        assert_eq!(listed(&message), [(1, None, "text/csv")]);
    }

    /// Inline PNG (id 1), a quoted-printable iso-8859-1 CSV (2), a PDF that
    /// is not UTF-8 (3) and a "PNG" that is not one (4).
    const ATTACHMENTS: &str = "From: a@example.com\r\n\
Subject: files\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
--outer\r\n\
Content-Type: multipart/related; boundary=\"inner\"\r\n\
\r\n\
--inner\r\n\
Content-Type: text/html; charset=utf-8\r\n\
\r\n\
<p><img alt=\"Logo\" src=\"cid:logo@example.com\"></p>\r\n\
--inner\r\n\
Content-Type: image/png; name=\"logo.png\"\r\n\
Content-Disposition: inline; filename=\"logo.png\"\r\n\
Content-ID: <logo@example.com>\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
iVBORw0KGgr7/78=\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: text/csv; charset=iso-8859-1; name=\"prices.csv\"\r\n\
Content-Disposition: attachment; filename=\"prices.csv\"\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
caf=E9,1\r\n\
tea,2\r\n\
--outer\r\n\
Content-Type: application/pdf; name=\"invoice.pdf\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0xLjQK+/8=\r\n\
--outer\r\n\
Content-Type: image/png; name=\"fake.png\"\r\n\
Content-Disposition: attachment; filename=\"fake.png\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
bm90IGEgcG5n\r\n\
--outer--\r\n";

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\xfb\xff\xbf";

    #[test]
    fn attachment_ids_follow_mime_order() {
        let message = parse_message(1, MessageFlags::default(), ATTACHMENTS.as_bytes()).unwrap();
        let listed: Vec<_> = message
            .attachments
            .iter()
            .map(|a| (a.id, a.filename.as_deref(), a.content_id.as_deref()))
            .collect();
        assert_eq!(
            listed,
            [
                (1, Some("logo.png"), Some("logo@example.com")),
                (2, Some("prices.csv"), None),
                (3, Some("invoice.pdf"), None),
                (4, Some("fake.png"), None),
            ]
        );
    }

    #[test]
    fn files_keep_charsets_bytes_names_and_numbers() {
        let raw = b"From: sender@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n\
--outer\r\nContent-Type: multipart/related; boundary=inner\r\n\r\n\
--inner\r\nContent-Type: text/html\r\n\r\n<p>First</p>\r\n\
--inner\r\nContent-Type: image/png\r\nContent-Disposition: inline\r\nContent-ID: <logo@example.org>\r\n\r\nimage\r\n--inner--\r\n\
--outer\r\nContent-Type: text/csv; charset=iso-8859-1\r\nContent-Disposition: attachment; filename=data.csv\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=E9\r\n\
--outer\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=data.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERg==\r\n\
--outer\r\nContent-Type: multipart/alternative; boundary=alt\r\n\r\n\
--alt\r\nContent-Type: text/plain\r\n\r\nSecond\r\n\
--alt\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\n--alt--\r\n\
--outer\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n!\r\n--outer--\r\n";
        let parsed = MessageParser::default().parse(raw).unwrap();
        for (part, id) in parsed.parts.iter().zip(0..) {
            if !matches!(part.body, PartType::Multipart(_)) {
                assert!(
                    parsed.text_body.contains(&id)
                        || parsed.html_body.contains(&id)
                        || parsed.attachments.contains(&id)
                );
            }
        }
        let files = files(raw).unwrap();
        assert_eq!(files.len(), 5);
        let [png, csv, pdf, ics, broken] = &files[..] else {
            unreachable!()
        };
        assert!(png.attachment.inline);
        assert_eq!(png.attachment.filename, None);
        assert_eq!(
            png.attachment.content_id.as_deref(),
            Some("logo@example.org")
        );
        assert_eq!(png.content.as_deref(), Some(b"image".as_slice()));
        assert_eq!(csv.charset.as_deref(), Some("iso-8859-1"));
        assert_eq!(csv.content.as_deref(), Some(b"caf\xe9".as_slice()));
        assert_eq!(pdf.content.as_deref(), Some(b"%PDF".as_slice()));
        assert_eq!(ics.attachment.content_type, "text/calendar");
        assert!(broken.content.is_none());
        let message = parse_message(0, MessageFlags::default(), raw).unwrap();
        assert!(
            files
                .iter()
                .map(|file| &file.attachment)
                .eq(&message.attachments)
        );
    }

    #[test]
    fn attachment_data_returns_decoded_content() {
        let raw = ATTACHMENTS.as_bytes();
        let content = |id| attachment_data(raw, id, 1 << 20).unwrap().content.unwrap();
        assert_eq!(content(1), PNG);
        let csv = String::from_utf8(content(2)).unwrap();
        assert!(csv.starts_with("café,1"), "{csv:?}");
        assert_eq!(content(3), b"%PDF-1.4\n\xfb\xff");
        assert_eq!(content(4), b"not a png");
        let logo = attachment_data(raw, 1, 1 << 20).unwrap().attachment;
        assert_eq!(
            logo,
            parse_message(1, MessageFlags::default(), raw)
                .unwrap()
                .attachments[0]
        );
    }

    #[test]
    fn attachment_data_leaves_out_content_over_max_bytes() {
        let raw = ATTACHMENTS.as_bytes();
        let size = PNG.len();
        let at_limit = attachment_data(raw, 1, size).unwrap();
        assert_eq!(at_limit.content.as_deref(), Some(PNG));
        let over = attachment_data(raw, 1, size - 1).unwrap();
        assert_eq!(over.content, None);
        assert_eq!(over.attachment.size, size);
    }

    #[test]
    fn attachment_data_refuses_unknown_ids() {
        let raw = ATTACHMENTS.as_bytes();
        assert_eq!(attachment_data(raw, 0, 1 << 20), None);
        assert_eq!(attachment_data(raw, 5, 1 << 20), None);
        assert_eq!(attachment_data(b"", 1, 1 << 20), None);
    }

    #[test]
    fn an_attachment_that_does_not_decode_has_no_content() {
        let part = |headers: &str, body: &str| format!("--b\r\n{headers}\r\n\r\n{body}\r\n");
        let base64 = |name: &str| {
            format!(
                "Content-Type: application/pdf; name=\"{name}\"\r\nContent-Transfer-Encoding: base64"
            )
        };
        let raw = mime(
            "mixed",
            &[
                part("Content-Type: text/plain", "Hello"),
                part(&base64("a.pdf"), "JVBERi0="),
                part(&base64("b.pdf"), "JVBER.i0="),
                part(
                    "Content-Type: text/plain; name=\"c.txt\"\r\nContent-Transfer-Encoding: quoted-printable",
                    "x==",
                ),
                part(
                    "Content-Type: application/octet-stream; name=\"d.bin\"\r\nContent-Transfer-Encoding: x-uuencode",
                    "begin 644 d.bin",
                ),
                part("Content-Type: text/plain; name=\"e.txt\"", "cut off"),
            ]
            .concat(),
            "",
        );
        let listed_attachments = parse(&raw).attachments;
        let names: Vec<_> = listed_attachments
            .iter()
            .map(|a| a.filename.as_deref())
            .collect();
        assert_eq!(
            names,
            ["a.pdf", "b.pdf", "c.txt", "d.bin", "e.txt"].map(Some)
        );
        for (listed, id) in listed_attachments.iter().zip(1..) {
            assert_eq!(
                &attachment_data(raw.as_bytes(), id, 1 << 20)
                    .unwrap()
                    .attachment,
                listed
            );
        }
        let data = |raw: &str, id, max_bytes| {
            let data = attachment_data(raw.as_bytes(), id, max_bytes).unwrap();
            let content = data
                .content
                .map(|content| String::from_utf8_lossy(&content).trim().to_owned());
            (data.decoded, content)
        };
        let decoded = |content: &str| (true, Some(content.to_owned()));
        assert_eq!(data(&raw, 1, 1 << 20), decoded("%PDF-"));
        assert_eq!(data(&raw, 1, 4), (true, None));
        for id in 2..=4 {
            assert_eq!(data(&raw, id, 1 << 20), (false, None), "{id}");
        }
        // A part cut off at the end without a transfer encoding is read as sent.
        assert_eq!(data(&raw, 5, 1 << 20), decoded("cut off"));
        assert_eq!(
            data(&mime("mixed", RUNS_ON, "--b--\r\n"), 1, 1 << 20),
            (false, None)
        );
        // Only the part that runs on is refused, not every part of that message.
        let before = mime(
            "mixed",
            &(part(&base64("a.pdf"), "JVBERi0=") + RUNS_ON),
            "--b--\r\n",
        );
        assert_eq!(data(&before, 1, 1 << 20), decoded("%PDF-"));
        assert_eq!(data(&before, 2, 1 << 20), (false, None));
        // Complete base64, but the mail ends without its closing boundary.
        let last = mime(
            "mixed",
            &(part("Content-Type: text/plain", "Hello") + &part(&base64("f.pdf"), "JVBERi0xLjQK")),
            "",
        );
        assert_eq!(
            listed(&parse(&last)),
            [(1, Some("f.pdf"), "application/pdf")]
        );
        assert_eq!(data(&last, 1, 1 << 20), (false, None));
    }

    #[test]
    fn a_file_the_parser_changed_into_text_has_no_content() {
        // A text part, then `last`, the part under test.
        let mail = |last: &[u8]| {
            let first = mime(
                "mixed",
                "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n",
                "",
            );
            [first.as_bytes(), last].concat()
        };
        let data = |raw: &[u8]| {
            let data = attachment_data(raw, 1, 1 << 20).unwrap();
            (data.decoded, data.content)
        };
        // A PNG cut off at the end is read as text, so its 0x89 becomes U+FFFD.
        let png = mail(b"--b\r\nContent-Type: image/png; name=\"a.png\"\r\n\r\n\x89PNG\r\n\x1a\n");
        assert_eq!(data(&png), (false, None));
        // Cut-off JSON reads as text unchanged, so it still downloads byte for byte.
        let json = mail(b"--b\r\nContent-Type: application/json\r\n\r\n{\"a\":1}");
        assert_eq!(data(&json), (true, Some(b"{\"a\":1}".to_vec())));
        // A multipart whose boundary never comes is read as text, to its parent's next boundary.
        let unbounded = mail(
            b"--b\r\nContent-Type: multipart/mixed; boundary=\"c\"\r\n\r\nno \xff parts\r\n--b--\r\n",
        );
        let multipart = attachment_data(&unbounded, 1, 1 << 20).unwrap();
        assert_eq!(multipart.attachment.content_type, "multipart/mixed");
        assert_eq!((multipart.decoded, multipart.content), (false, None));
        // A message read as empty at the end of the mail keeps only "x", the text before the last
        // match of the boundary: valid UTF-8, but not the part's bytes.
        let trimmed = mail(b"--b\r\nContent-Type: message/rfc822\r\n\r\nx--b\r\n");
        let nested = attachment_data(&trimmed, 1, 1 << 20).unwrap();
        assert_eq!(nested.attachment.size, 1);
        assert_eq!((nested.decoded, nested.content), (false, None));
        // Text stays text, as UTF-8: without a Content-Type (text/plain) when it is UTF-8, and in
        // a charset.
        let untyped = mail("--b\r\n\r\ncafé".as_bytes());
        assert_eq!(data(&untyped), (true, Some("café".into())));
        let latin = mail(b"--b\r\nContent-Type: text/csv; charset=iso-8859-1\r\n\r\ncaf\xe9");
        assert_eq!(data(&latin), (true, Some("caf\u{e9}".into())));
        // A message the parser can't read keeps its decoded bytes, problem flag or not.
        let eml = mail(
            b"--b\r\nContent-Type: message/rfc822\r\nContent-Transfer-Encoding: base64\r\n\r\n\r\n--b--\r\n",
        );
        assert_eq!(data(&eml), (true, Some(Vec::new())));
    }

    #[test]
    fn a_part_without_a_content_type_is_listed_as_mail_apps_read_it() {
        // Plain text (RFC 2045 5.2), as attachment_data returns it.
        let notes = mime(
            "mixed",
            "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n\
--b\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n\r\ncafé\r\n",
            "--b--\r\n",
        );
        assert_eq!(
            listed(&parse(&notes)),
            [(1, Some("notes.txt"), "text/plain")]
        );
        let data = attachment_data(notes.as_bytes(), 1, 1 << 20).unwrap();
        assert_eq!(data.attachment.content_type, "text/plain");
        assert_eq!(data.content.as_deref(), Some("café".as_bytes()));
        // In a digest, a message (RFC 2046 5.1.5), served as sent.
        let message = "From: b@example.com\r\nSubject: one\r\n\r\nHello";
        let digest = mime("digest", &format!("--b\r\n\r\n{message}\r\n"), "--b--\r\n");
        assert_eq!(listed(&parse(&digest)), [(1, None, "message/rfc822")]);
        let data = attachment_data(digest.as_bytes(), 1, 1 << 20).unwrap();
        assert_eq!(data.content.as_deref(), Some(message.as_bytes()));
    }

    #[test]
    fn a_digest_member_the_parser_changed_into_text_has_no_content() {
        let data = |raw: &[u8]| {
            let data = attachment_data(raw, 1, 1 << 20).unwrap();
            (data.attachment.content_type, data.decoded, data.content)
        };
        let digest = |members: &[u8]| [mime("digest", "", "").as_bytes(), members].concat();
        let refused = ("message/rfc822".to_owned(), false, None);
        // A member the parser read as an empty message is kept as text: only the text before the
        // last match of the boundary, or its bytes with U+FFFD for those that are not UTF-8.
        assert_eq!(data(&digest(b"--b\r\n\r\nx--b\r\n")), refused);
        assert_eq!(
            data(&digest(
                b"--b\r\nContent-Disposition: attachment; filename=\"a.eml\"\r\n\r\ncaf\xe9"
            )),
            refused
        );
        // A digest inside another multipart too.
        let nested = mime(
            "mixed",
            "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n\
--b\r\nContent-Type: multipart/digest; boundary=\"d\"\r\n\r\n--d\r\n\r\nx--d\r\n",
            "",
        );
        assert_eq!(data(nested.as_bytes()), refused);
        // Text kept as sent still downloads byte for byte.
        assert_eq!(
            data(&digest(b"--b\r\n\r\nHello")),
            ("message/rfc822".to_owned(), true, Some(b"Hello".to_vec()))
        );
    }

    #[test]
    fn a_file_without_a_content_type_that_is_not_utf8_has_no_content() {
        // A text part, then `last`, the part under test, in a multipart of `kind`.
        let mail = |kind: &str, last: &[u8]| {
            let first = mime(kind, "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n", "");
            [first.as_bytes(), last, b"--b--\r\n".as_slice()].concat()
        };
        let data = |raw: &[u8]| {
            let data = attachment_data(raw, 1, 1 << 20).unwrap();
            (data.decoded, data.content)
        };
        // mail-parser reads a PDF sent without a Content-Type as text/plain, with U+FFFD for its
        // bytes that are not UTF-8.
        let pdf = mail(
            "mixed",
            b"--b\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQKJeLjz9MK\r\n",
        );
        assert_eq!(data(&pdf), (false, None));
        // An attachment disposition is a file without a name, and so is a name with an inline one.
        let attached = mail(
            "mixed",
            b"--b\r\nContent-Disposition: attachment\r\n\r\n\x89PNG\r\n\x1a\n\r\n",
        );
        assert_eq!(data(&attached), (false, None));
        let named = mail(
            "related",
            b"--b\r\nContent-Disposition: inline; filename=\"a.bin\"\r\n\r\n\x89PNG\r\n\x1a\n\r\n",
        );
        assert_eq!(data(&named), (false, None));
        // A file whose bytes are UTF-8 still downloads as sent, in base64 too.
        let notes = mail(
            "mixed",
            b"--b\r\nContent-Disposition: attachment; filename=\"notes.txt\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8=\r\n",
        );
        assert_eq!(data(&notes), (true, Some(b"Hello".to_vec())));
        // So does a file typed as text without a charset: a mail app may read it in another one.
        let typed = mail(
            "mixed",
            b"--b\r\nContent-Type: text/plain; name=\"a.txt\"\r\n\r\ncaf\xe9\r\n",
        );
        assert_eq!(data(&typed), (false, None));
    }

    #[test]
    fn a_part_whose_offsets_give_no_span_counts_as_changed() {
        let part = mail_parser::MessagePart {
            headers: vec![mail_parser::Header {
                name: HeaderName::ContentType,
                value: HeaderValue::ContentType(mail_parser::ContentType {
                    c_type: "application".into(),
                    c_subtype: Some("octet-stream".into()),
                    attributes: None,
                }),
                offset_field: 0,
                offset_start: 0,
                offset_end: 0,
            }],
            is_encoding_problem: false,
            body: PartType::Text("abc".into()),
            encoding: mail_parser::Encoding::None,
            offset_header: 0,
            offset_body: 0,
            offset_end: 4,
        };
        assert!(changed_as_text(b"abc", &part, false));
    }

    #[test]
    fn parses_header_block_only() {
        let headers = parse_headers(
            b"From: Alice <alice@example.com>\r\nSubject: Status\r\nDate: Thu, 08 Oct 2026 09:00:00 +0800\r\n\r\n",
        )
        .unwrap();
        assert_eq!(headers.subject.as_deref(), Some("Status"));
        assert_eq!(headers.from[0].address, "alice@example.com");
        assert_eq!(
            headers.date.unwrap().to_rfc3339(),
            "2026-10-08T09:00:00+08:00"
        );
    }

    /// The sender is the one address of the only `From`, alone or after a name.
    #[test]
    fn the_sender_is_one_address_alone_or_after_a_name() {
        let cases = [
            ("alice@example.com", Some("alice@example.com")),
            ("Alice <alice@example.com>", Some("alice@example.com")),
            ("\"Alice\" <alice@example.com>", Some("alice@example.com")),
            (
                "Alice (Work) <alice@example.com>",
                Some("alice@example.com"),
            ),
            ("<alice@example.com>", Some("alice@example.com")),
            ("=?UTF-8?Q?=3Ca=40x.test=3E?= <b@x.test>", Some("b@x.test")),
            ("a@x.test, Alice <alice@example.com>", None),
            ("<a@x.test> <b@x.test>", None),
            ("<a@x.test> b@x.test", None),
            ("a@x.test (c) <b@x.test>", None),
            ("(\") <a@x.test> <b@x.test>", None),
            ("a b@x.test", None),
            ("a\u{7}b@x.test", None),
            ("boss@y.test@x.test", None),
            ("<boss@y.test@x.test>", None),
            ("<a@y.test<boss@x.test>", None),
            ("<y.test<boss@x.test>", None),
            ("alice <@y.test>", None),
            ("Bob <bob@>", None),
            ("Alice <alice@example.com", None),
            ("\"Alice <x>\" <alice@example.com>", None),
            ("alice@example.com (Alice)", None),
            ("Alice <=?UTF-8?Q?a?=@example.com>", None),
            ("Alice <\"alice\"@example.com>", None),
            ("Undisclosed", None),
        ];
        for (from, address) in cases {
            let got = sender(format!("From: {from}\r\nSubject: hi\r\n\r\n").as_bytes());
            assert_eq!(
                got.as_ref().map(|a| a.address.as_str()),
                address,
                "{from:?}"
            );
        }
        for c in "\"(),:;<>[\\]".chars() {
            for from in [
                format!("a@y.test{c}.x.test"),
                format!("A <a@y.test{c}.x.test>"),
            ] {
                let got = sender(format!("From: {from}\r\n\r\n").as_bytes());
                assert_eq!(got, None, "{from:?}");
            }
        }
        let named = sender(b"From: =?UTF-8?Q?Caf=C3=A9?= <cafe@example.com>\r\n\r\n");
        assert_eq!(
            named,
            Some(EmailAddress::with_name("Caf\u{e9}", "cafe@example.com"))
        );
        let twice = "From: alice@example.com\r\nFrom: alice@example.com\r\n\r\n";
        assert_eq!(sender(twice.as_bytes()), None);
        assert_eq!(sender(b"Subject: hi\r\n\r\n"), None);
    }

    #[test]
    fn from_values_are_each_from_header_as_sent() {
        let raw =
            b"From: Alice\r\n <a@x.test>\r\nSubject: hi\r\nfrom : <b@y.test> c@x.test\r\n\r\n";
        assert_eq!(
            parse_headers(raw).unwrap().from_values,
            ["Alice\r\n <a@x.test>", "<b@y.test> c@x.test"]
        );
        let none = parse_headers(b"Subject: hi\r\n\r\n").unwrap();
        assert_eq!(none.from_values, Vec::<String>::new());
    }

    /// Headers say whether a mail client shows the one `From` address as the sender, as
    /// [`sender`] finds: not when the parser joins the parts of a value into one address.
    #[test]
    fn headers_say_whether_the_sender_is_clear() {
        let joined = parse_headers(b"From: <a@y.test> b@x.test\r\n\r\n").unwrap();
        assert_eq!(joined.from, [EmailAddress::new("a@y.testb@x.test")]);
        assert!(!joined.from_clear);
        let raw = b"From: Alice\r\n <a@x.test>\r\n\r\nhi";
        assert!(parse_headers(raw).unwrap().from_clear);
        let message = parse_message(1, MessageFlags::default(), raw).unwrap();
        assert!(message.headers.from_clear);
        assert_eq!(message.headers.from_values, ["Alice\r\n <a@x.test>"]);
    }

    /// Headers say whether a mail client shows the addresses of `Reply-To`, `To` and `Cc`:
    /// when each is one header, each part of it between commas that holds an `@` is the next
    /// address the parser makes, alone or after a name.
    #[test]
    fn headers_say_whether_each_address_list_is_clear() {
        let cases = [
            ("", [true, true, true]),
            (
                "Reply-To: \"Smith, John\" <john@x.test>, list@x.test\r\n",
                [true, true, true],
            ),
            (
                "To: undisclosed-recipients:;\r\nCc: a@x.test,\r\n\tAlice <alice@x.test>\r\n",
                [true, true, true],
            ),
            (
                "reply-to: Bob <bob@> <example.net>\r\n",
                [false, true, true],
            ),
            (
                "Reply-To: a@x.test\r\nReply-To: b@y.test\r\n",
                [false, true, true],
            ),
            ("Reply-To: a@x.test, \"b@y.test\"\r\n", [false, true, true]),
            ("To: Friends: a@x.test, b@y.test;\r\n", [true, false, true]),
            ("To: a@x.test; b@y.test\r\n", [true, false, true]),
            ("Cc: a@x.test (Alice)\r\n", [true, true, false]),
            ("Cc: Alice <alice@x.test\r\n", [true, true, false]),
            ("Cc: a@x.test, alice <@y.test>\r\n", [true, true, false]),
        ];
        for (lines, clear) in cases {
            let raw = format!("From: me@x.test\r\n{lines}Subject: s\r\n\r\nhi");
            let headers = parse_headers(raw.as_bytes()).unwrap();
            let read = [headers.reply_to_clear, headers.to_clear, headers.cc_clear];
            assert_eq!(read, clear, "{lines}");
        }
    }

    fn mime(kind: &str, parts: &str, end: &str) -> String {
        format!(
            "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/{kind}; boundary=\"b\"\r\n\r\n{parts}{end}"
        )
    }

    /// `mime_a(body)`: a message whose root is `multipart/mixed` with boundary `a`.
    fn mime_a(body: &str) -> String {
        format!(
            "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"a\"\r\n\r\n{body}--a--\r\n"
        )
    }

    #[test]
    fn an_html_part_that_does_not_decode_still_counts_as_html() {
        let plain = "--b\r\nContent-Type: text/plain\r\n\r\nNot shown\r\n";
        // Base64 or quoted-printable that failed gives "", a cut-off part sent as is its text.
        for (html, end, body) in [
            (
                "Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPHA+SGk8L3A+.\r\n",
                "--b--\r\n",
                "",
            ),
            (
                "Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>Hi==</p>\r\n",
                "--b--\r\n",
                "",
            ),
            (
                "Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPHA+SGk8L3A+\r\n",
                "",
                "",
            ),
            (
                "Content-Type: text/html\r\n\r\n<p>Hi</p>\r\n",
                "",
                "<p>Hi</p>",
            ),
            (
                "Content-Type: text/html\r\nContent-Transfer-Encoding: 8bit\r\n\r\n<p>Hi</p>\r\n",
                "",
                "<p>Hi</p>",
            ),
            // The same as an encoded word, which mail-parser decodes and a mail app may not.
            (
                "Content-Type: text/html\r\n\
Content-Transfer-Encoding: =?us-ascii?q?8bit?=\r\n\r\n<p>Hi</p>\r\n",
                "",
                "",
            ),
            (
                "Content-Type: text/html; name=\"x.html\"\r\nContent-Transfer-Encoding: base64\r\n\r\nPHA+SGk8L3A+.\r\n",
                "--b--\r\n",
                "",
            ),
        ] {
            let message = parse(&mime("alternative", &format!("{plain}--b\r\n{html}"), end));
            assert_eq!(
                message.html_body.as_deref().map(str::trim),
                Some(body),
                "{html}"
            );
            assert_eq!(
                message.text_body.as_deref().map(str::trim),
                Some("Not shown"),
                "{html}"
            );
            assert!(
                message
                    .attachments
                    .iter()
                    .any(|a| a.content_type == "text/html"),
                "{html}"
            );
        }
    }

    #[test]
    fn an_unknown_transfer_encoding_is_not_read_as_text() {
        let single = |content_type: &str, encoding: &str, body: &str| {
            parse(&format!(
                "From: a@example.com\r\nSubject: hi\r\nContent-Type: {content_type}\r\n\
Content-Transfer-Encoding: {encoding}\r\n\r\n{body}\r\n"
            ))
        };
        for (encoding, body, text, withheld) in [
            ("x-uuencode", "Not shown", "", true),
            ("base64 (comment)", "U2hvd24=", "", true),
            ("7BIT", "Shown", "Shown", false),
            ("8Bit", "Shown", "Shown", false),
            ("Binary", "Shown", "Shown", false),
            ("BASE64", "U2hvd24=", "Shown", false),
            ("Quoted-Printable", "Sh=6Fwn", "Shown", false),
            // mail-parser decodes an encoded word and reads the last copy, and a mail app may do
            // neither.
            ("=?us-ascii?q?base64?=", "U2hvd24=", "", true),
            (
                "quoted-printable\r\nContent-Transfer-Encoding: base64",
                "U2hvd24=",
                "",
                true,
            ),
            // A fold before the word, an empty value and copies that are the same read alike; a
            // word folded in two is no encoding mail apps know.
            ("\r\n base64", "U2hvd24=", "Shown", false),
            ("", "Shown", "Shown", false),
            (
                "base64\r\nContent-Transfer-Encoding: base64",
                "U2hvd24=",
                "Shown",
                false,
            ),
            ("base\r\n 64", "U2hvd24=", "", true),
        ] {
            let message = single("text/plain", encoding, body);
            assert_eq!(
                message.text_body.as_deref().map(str::trim),
                Some(text),
                "{encoding}"
            );
            assert_eq!(message.text_body_withheld, withheld, "{encoding}");
        }
        let message = parse(&mime(
            "alternative",
            "--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n\
--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\n<p>Not shown</p>\r\n",
            "--b--\r\n",
        ));
        assert_eq!(message.html_body.as_deref(), Some(""));
        assert_eq!(message.text_body.as_deref().map(str::trim), Some("Plain"));
        let markdown = single("text/markdown", "x-uuencode", "# Notes");
        assert_eq!(markdown.text_body, None);
        assert!(!markdown.text_body_withheld);
        assert_eq!(listed(&markdown), [(1, None, "text/markdown")]);
        // The same encoding as an encoded word, in an HTML part, a markdown part and the parts a
        // mail app shows with the body.
        let word = "Content-Transfer-Encoding: =?us-ascii?q?base64?=\r\n\r\n";
        let message = parse(&mime(
            "alternative",
            &format!(
                "--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n\
--b\r\nContent-Type: text/html\r\n{word}PHA+Tm90IHNob3duPC9wPg==\r\n"
            ),
            "--b--\r\n",
        ));
        assert_eq!(message.html_body.as_deref(), Some(""));
        assert_eq!(message.text_body.as_deref().map(str::trim), Some("Plain"));
        let markdown = single("text/markdown", "=?us-ascii?q?base64?=", "IyBOb3Rlcw==");
        assert_eq!(markdown.text_body, None);
        assert_eq!(listed(&markdown), [(1, None, "text/markdown")]);
        let beside = parse(&mixed(&[
            text("b", "One"),
            format!("--b\r\nContent-Type: text/plain\r\n{word}VHdv\r\n"),
            text("b", "Three"),
        ]));
        assert_eq!(parts(&beside), [(false, "One"), (false, "Three")]);
        let html_first = parse(&mixed(&[
            format!("--b\r\nContent-Type: text/html\r\n{word}PHA+T25lPC9wPg==\r\n"),
            text("b", "Two"),
            text("b", "Three"),
        ]));
        assert_eq!(html_first.html_body.as_deref(), Some(""));
        assert_eq!(parts(&html_first), Vec::new());
        let file = mime(
            "mixed",
            "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n\
--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Transfer-Encoding: =?us-ascii?q?base64?=\r\n\r\nJVBERi0=\r\n",
            "--b--\r\n",
        );
        let data = attachment_data(file.as_bytes(), 1, 1 << 20).unwrap();
        assert_eq!((data.decoded, data.content), (false, None));
    }

    #[test]
    fn an_attached_html_file_leaves_the_text_body_alone() {
        for (header, name) in [
            (
                "Content-Type: text/html\r\nContent-Disposition: attachment; filename=\"report.html\"\r\n",
                Some("report.html"),
            ),
            (
                "Content-Type: text/html; name=\"report.html\"\r\n",
                Some("report.html"),
            ),
            (
                "Content-Type: text/html\r\nContent-Disposition: attachment\r\n",
                None,
            ),
        ] {
            let message = parse(&mime(
                "mixed",
                &format!(
                    "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n--b\r\n{header}\
Content-Transfer-Encoding: base64\r\n\r\nPHA+SGk8L3A+.\r\n"
                ),
                "--b--\r\n",
            ));
            assert_eq!(message.html_body, None, "{header}");
            assert_eq!(
                message.text_body.as_deref().map(str::trim),
                Some("Hello"),
                "{header}"
            );
            assert_eq!(listed(&message), [(1, name, "text/html")], "{header}");
        }
    }

    #[test]
    fn the_html_body_is_the_first_html_part_a_mail_app_shows() {
        let html = "Content-Type: text/html\r\n\r\n<p>Shown</p>\r\n";
        let hidden = "--b\r\nContent-Type: text/plain\r\n\r\nNot shown\r\n";
        let nested = |first: &str| {
            format!(
                "{hidden}--b\r\nContent-Type: multipart/mixed; boundary=\"m\"\r\n\r\n\
--m\r\n{first}--m\r\n{html}--m--\r\n"
            )
        };
        for (kind, parts) in [
            (
                "alternative",
                nested(
                    "Content-Type: image/gif\r\nContent-Disposition: inline\r\n\
Content-Transfer-Encoding: base64\r\n\r\nR0lGODlhAQABAAAAACw=\r\n",
                ),
            ),
            (
                "alternative",
                nested("Content-Type: text/plain\r\n\r\n \r\n"),
            ),
            (
                "mixed",
                format!("--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n--b\r\n{html}"),
            ),
            (
                "alternative",
                format!(
                    "{hidden}--b\r\nContent-Type: text/html\r\nContent-Disposition: attachment\r\n\
\r\n<p>Shown</p>\r\n"
                ),
            ),
            (
                "alternative",
                nested("Content-Type: text/plain\r\n\r\n \r\n").replace(
                    html,
                    "Content-Type: text/html; name=\"x.html\"\r\n\r\n<p>Shown</p>\r\n",
                ),
            ),
        ] {
            let message = parse(&mime(kind, &parts, "--b--\r\n"));
            assert_eq!(
                message.html_body.as_deref().map(str::trim),
                Some("<p>Shown</p>"),
                "{parts}"
            );
        }
    }

    #[test]
    fn an_alternative_is_read_from_its_last_member() {
        let html = |text: &str| format!("Content-Type: text/html\r\n\r\n<p>{text}</p>\r\n");
        let plain = "Content-Type: text/plain\r\n\r\nNot shown\r\n";
        let inner = |kind: &str, parts: &[String]| {
            let parts: String = parts.iter().flat_map(|part| ["--i\r\n", part]).collect();
            format!("Content-Type: multipart/{kind}; boundary=\"i\"\r\n\r\n{parts}--i--\r\n")
        };
        let deep = |parts: &[String]| {
            format!(
                "Content-Type: multipart/mixed; boundary=\"m\"\r\n\r\n--m\r\nContent-Type: text/plain\r\n\r\n \r\n\
--m\r\n{}--m--\r\n",
                inner("alternative", parts)
            )
        };
        for (parts, shown) in [
            (vec![plain.to_owned(), html("A"), html("B")], "<p>B</p>"),
            (vec![html("A"), deep(&[html("C"), html("B")])], "<p>B</p>"),
            (
                vec![
                    html("A"),
                    inner(
                        "alternative",
                        &[
                            plain.to_owned(),
                            "Content-Type: image/gif\r\nContent-Transfer-Encoding: base64\r\n\r\n\
R0lGODlhAQABAAAAACw=\r\n"
                                .to_owned(),
                        ],
                    ),
                ],
                "",
            ),
            (
                vec![
                    html("A"),
                    "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n"
                        .to_owned(),
                ],
                "",
            ),
            (vec![html("A"), plain.to_owned()], ""),
            (vec![inner("mixed", &[html("A")]), plain.to_owned()], ""),
            (vec![html("A"), "\r\nNo Content-Type: plain text\r\n".to_owned()], ""),
            (
                vec![
                    plain.to_owned(),
                    html("A"),
                    "Content-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".to_owned(),
                ],
                "<p>A</p>",
            ),
        ] {
            let parts: String = parts.iter().flat_map(|part| ["--b\r\n", part]).collect();
            let message = parse(&mime("alternative", &parts, "--b--\r\n"));
            assert_eq!(
                message.html_body.as_deref().map(str::trim),
                Some(shown),
                "{parts}"
            );
        }
    }

    #[test]
    fn a_named_html_body_stays_the_body() {
        let single = "From: a@example.com\r\nSubject: hi\r\n\
Content-Type: text/html; name=\"receipt.html\"\r\n\r\n<p>Receipt</p>\r\n";
        let first = mime(
            "mixed",
            "--b\r\nContent-Type: text/html; name=\"x.html\"\r\n\r\n<p>Receipt</p>\r\n\
--b\r\nContent-Type: application/pdf; name=\"invoice.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n",
            "--b--\r\n",
        );
        let inline = mime(
            "mixed",
            "--b\r\nContent-Type: text/plain\r\n\r\nHello\r\n\
--b\r\nContent-Type: text/html\r\nContent-Disposition: inline; filename=\"x.html\"\r\n\r\n<p>Receipt</p>\r\n",
            "--b--\r\n",
        );
        for (raw, attachments) in [
            (single.to_owned(), vec![]),
            (first, vec![(1, Some("invoice.pdf"), "application/pdf")]),
            (inline, vec![]),
        ] {
            let message = parse(&raw);
            assert_eq!(
                message.html_body.as_deref().map(str::trim),
                Some("<p>Receipt</p>"),
                "{raw}"
            );
            assert_eq!(listed(&message), attachments, "{raw}");
        }
    }

    /// (is HTML, trimmed text) of each of `message.body_parts`.
    fn parts(message: &Message) -> Vec<(bool, &str)> {
        message
            .body_parts
            .iter()
            .map(|part| match part {
                BodyPart::Html(html) => (true, html.trim()),
                BodyPart::Text(text) => (false, text.trim()),
            })
            .collect()
    }

    /// A text/plain part at boundary `b`.
    fn text(b: &str, body: &str) -> String {
        format!("--{b}\r\nContent-Type: text/plain\r\n\r\n{body}\r\n")
    }

    /// A text/html part at boundary `b`.
    fn html(b: &str, body: &str) -> String {
        format!("--{b}\r\nContent-Type: text/html\r\n\r\n{body}\r\n")
    }

    /// A `multipart/mixed` message of `parts` at boundary `b`.
    fn mixed(parts: &[String]) -> String {
        mime("mixed", &parts.concat(), "--b--\r\n")
    }

    #[test]
    fn the_parts_a_mail_app_shows_one_after_another_are_collected() {
        let encoded = |b: &str, kind: &str, body: &str| {
            format!(
                "--{b}\r\nContent-Type: {kind}\r\nContent-Transfer-Encoding: base64\r\n\r\n{body}\r\n"
            )
        };
        let named = "--b\r\nContent-Type: text/html\r\nContent-Disposition: inline; filename=\"x.html\"\r\n\r\n\
<p>Two</p>\r\n"
            .to_owned();
        let png = encoded(
            "b\r\nContent-Disposition: inline",
            "image/png",
            "iVBORw0KGgo=",
        );
        let pdf = |b: &str| encoded(b, "application/pdf; name=\"a.pdf\"", "JVBERi0=");
        let broken = |b: &str| encoded(b, "text/plain", "SGk.");
        let alternative = |parts: &[String]| mime("alternative", &parts.concat(), "--b--\r\n");
        let issue = mixed(&[html("b", "<p>One</p>"), named]);
        let with_image = mixed(&[text("b", "One"), png, text("b", "Two")]);
        let member = alternative(&[
            text("b", "Plain"),
            inner(
                "mixed",
                &[html("c", "<p>One</p>"), pdf("c"), html("c", "<p>Two</p>")].concat(),
            ),
        ]);
        let not_shown = inner("alternative", &(text("c", "Not shown") + &broken("c")));
        let withheld = mixed(&[not_shown, text("b", "Two"), text("b", "Three")]);
        let broken_html = mixed(&[
            encoded("b", "text/html", "PHA+."),
            text("b", "Two"),
            text("b", "Three"),
        ]);
        let mid_preamble = mixed(&[
            "xx".to_owned(),
            html("b", "<p>Hidden</p>"),
            text("b", "Shown"),
        ]);
        let rows = [
            (&issue, vec![(true, "<p>One</p>"), (true, "<p>Two</p>")]),
            (
                &mixed(&[text("b", "Plain"), html("b", "<p>Two</p>")]),
                vec![(false, "Plain"), (true, "<p>Two</p>")],
            ),
            (
                &mixed(&[text("b", "One"), text("b", "Two")]),
                vec![(false, "One"), (false, "Two")],
            ),
            (&with_image, vec![(false, "One"), (false, "Two")]),
            (&member, vec![(true, "<p>One</p>"), (true, "<p>Two</p>")]),
            (
                &mixed(&[
                    text("b", "One"),
                    inner("alternative", &broken("c")),
                    text("b", "Three"),
                ]),
                vec![(false, "One"), (false, "Three")],
            ),
            (
                &alternative(&[text("b", "Plain"), html("b", "<p>Html</p>")]),
                vec![],
            ),
            (
                &alternative(&[html("b", "<p>A</p>"), text("b", "B")]),
                vec![],
            ),
            (&mid_preamble, vec![]),
            (&withheld, vec![]),
            (&broken_html, vec![]),
            (
                &"From: a@example.com\r\nSubject: hi\r\n\r\nHi\r\n".to_owned(),
                vec![],
            ),
        ];
        for (raw, expected) in rows {
            assert_eq!(parts(&parse(raw)), expected, "{raw}");
        }
        let message = parse(&issue);
        assert_eq!(listed(&message), Vec::new());
        assert_eq!(
            message.html_body.as_deref().map(str::trim),
            Some("<p>One</p>")
        );
        assert_eq!(listed(&parse(&with_image)), [(1, None, "image/png")]);
        assert_eq!(
            listed(&parse(&member)),
            [(1, Some("a.pdf"), "application/pdf")]
        );
        let message = parse(&withheld);
        assert_eq!(message.text_body.as_deref(), Some(""));
        assert!(message.text_body_withheld);
        assert_eq!(parse(&broken_html).html_body.as_deref(), Some(""));
    }

    #[test]
    fn a_part_is_collected_only_as_a_mail_app_shows_it_with_the_body() {
        let rows = [
            // Mail apps differ on an alternative whose last member has no HTML while another does.
            (
                &mixed(&[
                    html("b", "<p>One</p>"),
                    inner("alternative", &(html("c", "<p>X</p>") + &text("c", "B"))),
                ]),
                vec![],
            ),
            // Without HTML in it, an alternative's last member is shown.
            (
                &mixed(&[
                    html("b", "<p>One</p>"),
                    inner("alternative", &text("c", "Two")),
                ]),
                vec![(true, "<p>One</p>"), (false, "Two")],
            ),
            // The HTML body is cut off at the end, so mail-parser keeps it out of its lists.
            (
                &mime("mixed", &(text("b", "One") + &html("b", "<p>Two</p>")), ""),
                vec![(false, "One"), (true, "<p>Two</p>")],
            ),
            // A named text part is an attachment, outside the body lists.
            (
                &mixed(&[
                    html("b", "<p>One</p>"),
                    "--b\r\nContent-Type: text/plain; name=\"c.txt\"\r\n\r\nFile\r\n".to_owned(),
                ]),
                vec![],
            ),
        ];
        for (raw, expected) in rows {
            assert_eq!(parts(&parse(raw)), expected, "{raw}");
        }
    }

    #[test]
    fn an_alternative_without_html_keeps_its_plain_text() {
        for parts in [
            "--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n\
--b\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            "--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n",
        ] {
            let message = parse(&mime("alternative", parts, "--b--\r\n"));
            assert_eq!(message.html_body, None, "{parts}");
            assert_eq!(
                message.text_body.as_deref().map(str::trim),
                Some("Plain"),
                "{parts}"
            );
        }
    }

    #[test]
    fn only_the_root_of_a_related_part_is_shown() {
        let part = |kind: &str, id: &str, body: &str| {
            format!("--b\r\nContent-Type: {kind}\r\nContent-ID: <{id}>\r\n\r\n{body}\r\n")
        };
        let png = "--b\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n\
iVBORw0KGgo=\r\n";
        let two_html = part("text/html", "a@x", "<p>A</p>") + &part("text/html", "b@x", "<p>B</p>");
        let alternative = inner(
            "alternative",
            "--c\r\nContent-Type: text/plain\r\n\r\nPlain\r\n\
--c\r\nContent-Type: text/html\r\n\r\n<p>Shown</p>\r\n",
        );
        let rows = [
            (
                "",
                png.to_owned() + &part("text/html", "a@x", "<p>Not shown</p>"),
                None,
                None,
                false,
            ),
            ("; start=\"<b@x>\"", two_html.clone(), Some(""), None, false),
            (
                "; start=\"<a@x>\"",
                two_html.clone(),
                Some("<p>A</p>"),
                None,
                false,
            ),
            (
                "; start=\"a@x\"",
                two_html.clone(),
                Some("<p>A</p>"),
                None,
                false,
            ),
            // A repeated `start` or Content-ID: mail-parser and mail clients may read different copies.
            (
                "; start=\"<a@x>\"; start=\"<b@x>\"",
                two_html,
                Some(""),
                None,
                false,
            ),
            (
                "; start=\"<b@x>\"",
                "--b\r\nContent-Type: text/html\r\nContent-ID: <a@x>\r\nContent-ID: <b@x>\r\n\r\n\
<p>A</p>\r\n"
                    .to_owned()
                    + &part("text/html", "b@x", "<p>B</p>"),
                Some(""),
                None,
                false,
            ),
            (
                "; start=\"<b@x>\"",
                part("text/plain", "a@x", "Not shown") + &part("text/plain", "b@x", "Shown"),
                None,
                Some(""),
                true,
            ),
            (
                "",
                part("text/plain", "a@x", "Shown") + png,
                None,
                Some("Shown"),
                false,
            ),
            (
                "",
                png.to_owned()
                    + "--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n\
SGk.\r\n",
                None,
                None,
                false,
            ),
            (
                "",
                alternative + png,
                Some("<p>Shown</p>"),
                Some("Plain"),
                false,
            ),
        ];
        for (start, parts, html, text, withheld) in rows {
            let message = parse(&mime(&format!("related{start}"), &parts, "--b--\r\n"));
            assert_eq!(message.html_body.as_deref(), html, "{parts}");
            assert_eq!(message.text_body.as_deref().map(str::trim), text, "{parts}");
            assert_eq!(message.text_body_withheld, withheld, "{parts}");
        }
    }

    #[test]
    fn a_start_a_mail_client_may_read_differently_gives_no_root() {
        let part = |id: &str, body: &str| {
            format!("--b\r\nContent-Type: text/html\r\nContent-ID: <{id}>\r\n\r\n{body}\r\n")
        };
        let parts = part("a@x", "<p>A</p>") + &part("b@x", "<p>B</p>");
        for (start, html) in [
            // mail-parser joins RFC 2231 pieces, also with a space or quotes before the `*`, and
            // decodes an encoded word, and a mail client may read `start="a"` or the word as sent.
            // They follow the boundary, which a parameter in another form before it would withhold.
            ("; start=\"a\"; Start*1=\"@x\"", ""),
            ("; start=\"a\"; start *1=\"@x\"", ""),
            ("; start=\"a\"; \"start\"*1=\"@x\"", ""),
            ("; start=\"=?us-ascii?q?a@x?=\"", ""),
            // Without `start`, an encoded word in another parameter changes nothing.
            ("; type=\"=?us-ascii?q?text/html?=\"", "<p>A</p>"),
        ] {
            let message = parse(&format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/related; boundary=\"b\"{start}\r\n\r\n{parts}--b--\r\n"
            ));
            assert_eq!(message.html_body.as_deref(), Some(html), "{start}");
            assert!(!message.text_body_withheld, "{start}");
        }
    }

    #[test]
    fn a_nested_related_part_shows_only_its_root() {
        // The related part holds HTML, so the alternative shows it, and its root is the image.
        let message = parse(&mime(
            "alternative",
            &("--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n".to_owned()
                + &inner(
                    "related",
                    "--c\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n\
iVBORw0KGgo=\r\n--c\r\nContent-Type: text/html\r\n\r\n<p>Not shown</p>\r\n",
                )),
            "--b--\r\n",
        ));
        assert_eq!(message.html_body.as_deref(), Some(""));
        assert_eq!(message.text_body.as_deref().map(str::trim), Some("Plain"));

        // A related part with no root gives the body none of its parts, and a later part still is.
        let message = parse(&mime(
            "mixed",
            &(inner(
                "related; start=\"<b@x>\"",
                "--c\r\nContent-Type: text/plain\r\nContent-ID: <a@x>\r\n\r\nA\r\n\
--c\r\nContent-Type: text/plain\r\nContent-ID: <b@x>\r\n\r\nB\r\n",
            ) + "--b\r\nContent-Type: text/plain\r\n\r\nC\r\n"),
            "--b--\r\n",
        ));
        assert_eq!(message.html_body, None);
        assert_eq!(message.text_body.as_deref().map(str::trim), Some("C"));
        assert!(!message.text_body_withheld);
    }

    #[test]
    fn deeply_nested_alternatives_stay_fast() {
        use std::fmt::Write as _;

        // Deep enough that a walk quadratic in the depth takes many seconds.
        let depth = 20_000;
        let mut raw = String::from("From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n");
        for level in (0..depth).rev() {
            write!(
                raw,
                "Content-Type: multipart/alternative; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"
            )
            .unwrap();
        }
        raw.push_str("Content-Type: text/plain\r\n\r\nPlain\r\n");
        for level in 0..depth {
            write!(raw, "--b{level}--\r\n").unwrap();
        }
        let started = std::time::Instant::now();
        let message = parse(&raw);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(message.html_body, None);
        assert_eq!(message.text_body.as_deref().map(str::trim), Some("Plain"));
    }

    /// `inner(kind, parts)`: a multipart member of `b` with boundary `c`.
    fn inner(kind: &str, parts: &str) -> String {
        format!("--b\r\nContent-Type: multipart/{kind}; boundary=\"c\"\r\n\r\n{parts}--c--\r\n")
    }

    /// mail-parser runs the cut-off part on to the end, so its text holds the alternative a
    /// mail app shows as a separate part, with the member the app hides: taken as sent, it
    /// would give the agent "Hidden".
    const RUNS_ON: &str = "--b\r\nContent-Type: multipart/mixed; boundary=\"c\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nShown\r\n\
--b\r\nContent-Type: multipart/alternative; boundary=\"d\"\r\n\r\n\
--d\r\nContent-Type: text/plain\r\n\r\nHidden\r\n\
--d\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--d--\r\n";

    #[test]
    fn the_plain_text_body_is_the_part_a_mail_app_shows() {
        let text =
            |b: &str, body: &str| format!("--{b}\r\nContent-Type: text/plain\r\n\r\n{body}\r\n");
        let alternative = |parts: String| mime("alternative", &parts, "--b--\r\n");
        let image =
            "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n";
        let html = "Content-Type: text/html\r\n\r\n<p>Shown</p>\r\n";
        let gif = "--c\r\nContent-Type: image/gif\r\nContent-Disposition: inline\r\n\
Content-Transfer-Encoding: base64\r\n\r\nR0lGODlhAQABAAAAACw=\r\n";
        // #44: the person sees the image, not the plain part.
        let shows_image = alternative(format!("{}--b\r\n{image}", text("b", "Not shown")));
        let shown = Some("<p>Shown</p>");
        for (raw, text, withheld, html_body) in [
            (shows_image.clone(), Some(""), true, None),
            (
                alternative(text("b", "Not shown") + &text("b", "Shown")),
                Some("Shown"),
                false,
                None,
            ),
            (
                alternative(
                    text("b", "Not shown")
                        + &inner("mixed", &(gif.to_owned() + &text("c", "Shown"))),
                ),
                Some("Shown"),
                false,
                None,
            ),
            // A hidden part counts only when no shown one exists.
            (
                mime(
                    "mixed",
                    &(inner(
                        "alternative",
                        &format!("{}--c\r\n{image}", text("c", "Not shown")),
                    ) + &text("b", "Shown")),
                    "--b--\r\n",
                ),
                Some("Shown"),
                false,
                None,
            ),
            (
                alternative(format!("{}--b\r\n{html}", text("b", "Plain"))),
                Some("Plain"),
                false,
                shown,
            ),
            (
                alternative(
                    text("b", "Plain")
                        + &inner(
                            "related",
                            &format!("--c\r\n{html}--c\r\nContent-ID: <logo>\r\n{image}"),
                        ),
                ),
                Some("Plain"),
                false,
                shown,
            ),
            // Every member a mail app can show holds HTML, so the last one counts.
            (
                alternative(inner(
                    "mixed",
                    &format!("{}--c\r\n{html}", text("c", "Plain")),
                )),
                Some("Plain"),
                false,
                shown,
            ),
        ] {
            let message = parse(&raw);
            assert_eq!(message.text_body.as_deref().map(str::trim), text, "{raw}");
            assert_eq!(message.text_body_withheld, withheld, "{raw}");
            assert_eq!(
                message.html_body.as_deref().map(str::trim),
                html_body,
                "{raw}"
            );
        }
        assert_eq!(listed(&parse(&shows_image)), [(1, None, "image/png")]);
    }

    #[test]
    fn a_plain_text_part_that_does_not_decode_is_withheld() {
        let single = |headers: &str| format!("From: a@example.com\r\nSubject: hi\r\n{headers}");
        let encoded = |encoding: &str, body: &str| {
            format!(
                "Content-Type: text/plain\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n{body}\r\n"
            )
        };
        let cut_off = |part: String| mime("alternative", &format!("--b\r\n{part}"), "");
        let mixed = |parts: String| mime("mixed", &parts, "--b--\r\n");
        let broken = format!("--b\r\n{}", encoded("base64", "SGk."));
        let shown = "--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n";
        let pdf = "--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n";
        let plain_file: &[_] = &[(1, None, "text/plain")];
        for (raw, text, withheld, attachments) in [
            (
                single(&encoded("base64", "Tm90IHNob3du.")),
                Some(""),
                true,
                Some(&[][..]),
            ),
            (
                single(&encoded("quoted-printable", "Not shown==")),
                Some(""),
                true,
                None,
            ),
            // The shown member is the broken one, and the hidden one isn't used.
            (
                mime(
                    "alternative",
                    &format!("--b\r\nContent-Type: text/plain\r\n\r\nNot shown\r\n{broken}"),
                    "--b--\r\n",
                ),
                Some(""),
                true,
                None,
            ),
            (mime("alternative", shown, ""), Some("Shown"), false, None),
            (
                cut_off(encoded("8bit", "Shown")),
                Some("Shown"),
                false,
                None,
            ),
            (cut_off(encoded("base64", "U2hvd24=")), Some(""), true, None),
            // The readable shown part is the body.
            (
                mixed(broken.clone() + shown),
                Some("Shown"),
                false,
                Some(plain_file),
            ),
            (
                mixed(broken.clone() + pdf),
                Some(""),
                true,
                Some(
                    &[
                        (1, None, "text/plain"),
                        (2, Some("a.pdf"), "application/pdf"),
                    ][..],
                ),
            ),
            (mixed(RUNS_ON.to_owned()), Some(""), true, Some(plain_file)),
            // The Markdown body comes first, as before.
            (
                mixed(broken + "--b\r\nContent-Type: text/markdown\r\n\r\n# Notes\r\n"),
                Some("# Notes"),
                false,
                Some(plain_file),
            ),
            // No blank line, no body: mail-parser's empty root is in neither list.
            (single(""), None, false, Some(&[][..])),
        ] {
            let message = parse(&raw);
            assert_eq!(message.text_body.as_deref().map(str::trim), text, "{raw}");
            assert_eq!(message.text_body_withheld, withheld, "{raw}");
            if let Some(attachments) = attachments {
                assert_eq!(listed(&message), attachments, "{raw}");
            }
        }
    }

    #[test]
    fn only_a_shown_plain_part_that_does_not_decode_withholds_the_body() {
        let png =
            "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n";
        let broken = "Content-Transfer-Encoding: base64\r\n\r\nSGk.\r\n";
        for (raw, text, withheld) in [
            // Base64 that decodes is read.
            (
                "From: a@example.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\
Content-Transfer-Encoding: base64\r\n\r\nU2hvd24=\r\n"
                    .to_owned(),
                Some("Shown"),
                false,
            ),
            // The children of a hidden member are hidden too.
            (
                mime(
                    "alternative",
                    &format!(
                        "{}--b\r\n{png}",
                        inner(
                            "mixed",
                            "--c\r\nContent-Type: text/plain\r\n\r\nNot shown\r\n"
                        )
                    ),
                    "--b--\r\n",
                ),
                Some(""),
                true,
            ),
            // A readable part that mail-parser lists as an attachment withholds nothing.
            (
                mime(
                    "related",
                    &format!("--b\r\n{png}--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n"),
                    "--b--\r\n",
                ),
                None,
                false,
            ),
            // Nor does a hidden part that did not decode, or a file.
            (
                mime(
                    "alternative",
                    &format!(
                        "{}--b\r\n{png}",
                        inner(
                            "mixed",
                            &format!("--c\r\n{png}--c\r\nContent-Type: text/plain\r\n{broken}")
                        )
                    ),
                    "--b--\r\n",
                ),
                None,
                false,
            ),
            (
                mime(
                    "mixed",
                    &format!("--b\r\nContent-Type: text/plain; name=\"a.txt\"\r\n{broken}"),
                    "--b--\r\n",
                ),
                None,
                false,
            ),
            // Nor does an untyped digest member (message/rfc822) left as binary data, one whose
            // base64 is broken, or one read as an empty message.
            (
                mime(
                    "digest",
                    "--b\r\nContent-Transfer-Encoding: base64\r\n\r\n\r\n",
                    "--b--\r\n",
                ),
                None,
                false,
            ),
            (
                mime("digest", &format!("--b\r\n{broken}"), "--b--\r\n"),
                None,
                false,
            ),
            (mime("digest", "--b\r\n\r\nx--b\r\n", ""), None, false),
            // Elsewhere an untyped part is plain text (RFC 2045 5.2), so it does.
            (
                mime("mixed", &format!("--b\r\n{broken}"), "--b--\r\n"),
                Some(""),
                true,
            ),
        ] {
            let message = parse(&raw);
            assert_eq!(message.text_body.as_deref().map(str::trim), text, "{raw}");
            assert_eq!(message.text_body_withheld, withheld, "{raw}");
        }
    }

    #[test]
    fn a_boundary_line_around_the_body_part_empties_it() {
        let img =
            "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n";
        // A `--b` line in an earlier member of alternative `c`; the shown member is the later one.
        let earlier = mime(
            "mixed",
            &format!(
                "--b\r\nContent-Type: multipart/alternative; boundary=\"c\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nShown\r\n--b\r\n{img}\
--c\r\nContent-Type: text/plain\r\n\r\nHidden\r\n--c--\r\n"
            ),
            "--b--\r\n",
        );
        // A `--b` line in c's preamble; the parser keeps only the later member.
        let preamble = mime(
            "mixed",
            &format!(
                "--b\r\nContent-Type: multipart/alternative; boundary=\"c\"\r\n\r\n--b\r\n{img}\
--c\r\nContent-Type: text/plain\r\n\r\nLast\r\n--c--\r\n"
            ),
            "--b--\r\n",
        );
        // A `--a` line after child `c` closes, before `b`'s next part.
        let after_close = mime_a(&format!(
            "--a\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: multipart/mixed; boundary=\"c\"\r\n\r\n--c\r\n{img}--c--\r\n\
--a\r\n--b\r\nContent-Type: text/plain\r\n\r\nHidden\r\n--b--\r\n"
        ));
        // A `--b` line inside a part's headers, and inside a multipart part's headers: the parser
        // reads the later Content-Type, or the multipart's HTML part.
        let headers = mime(
            "mixed",
            "--b\r\nContent-Type: text/plain\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>Hidden</p>\r\n",
            "--b--\r\n",
        );
        let multipart_headers = mime(
            "mixed",
            "--b\r\nContent-Type: multipart/mixed; boundary=\"c\"\r\n--b\r\n\r\n\
--c\r\nContent-Type: text/html\r\n\r\n<p>Hidden</p>\r\n--c--\r\n",
            "--b--\r\n",
        );
        // A `--bZZZ` line where `bZZZ` is another, closed, multipart's boundary.
        let bzzz = mime(
            "mixed",
            "--b\r\nContent-Type: multipart/mixed; boundary=\"bZZZ\"\r\n\r\n\
--bZZZ\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n--bZZZ--\r\n\
--b\r\nContent-Type: multipart/alternative; boundary=\"c\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nShown\r\n--bZZZ\r\nContent-Type: text/html\r\n\r\n<p>Hidden</p>\r\n",
            "",
        );
        // A `--b` line in the preamble of alternative `B`: the parser skips it, as its boundary
        // differs in case.
        let case = mime(
            "mixed",
            &format!(
                "--b\r\nContent-Type: multipart/alternative; boundary=\"B\"\r\n\r\n--b\r\n{img}\
--B\r\nContent-Type: text/plain\r\n\r\nHidden\r\n--B--\r\n"
            ),
            "--b--\r\n",
        );
        // A nested boundary that starts with, or equals, the enclosing one.
        let shared_prefix = mime(
            "mixed",
            "--b\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n\
--b1\r\nContent-Type: text/plain\r\n\r\nHidden\r\n--b1--\r\n",
            "--b--\r\n",
        );
        let same = shared_prefix.replace("b1", "b");
        // A `--B` line in the preamble of `b`, and a `--c` line in the headers of `c` itself.
        let own_case = mime(
            "mixed",
            "--B\r\nContent-Type: text/html\r\n\r\n<p>Hidden</p>\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n",
            "--b--\r\n",
        );
        let own_headers = mime(
            "mixed",
            "--b\r\n--c\r\nContent-Type: multipart/mixed; boundary=\"c\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nHidden\r\n--c--\r\n",
            "--b--\r\n",
        );
        for (raw, html_body) in [
            (own_case, None),
            (own_headers, None),
            (case, None),
            (shared_prefix, None),
            (same, None),
            (earlier, None),
            (preamble, None),
            (after_close, None),
            (headers, Some("")),
            (multipart_headers, Some("")),
            (bzzz, None),
        ] {
            let message = parse(&raw);
            assert_eq!(message.text_body.as_deref(), Some(""), "{raw}");
            assert!(message.text_body_withheld, "{raw}");
            assert_eq!(
                message.html_body.as_deref().map(str::trim),
                html_body,
                "{raw}"
            );
        }
    }

    #[test]
    fn a_shown_member_that_runs_past_a_boundary_line_empties_it() {
        let img =
            "Content-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n";
        // A shown member that runs on: its boundary missing, or after the `--b` line; also
        // quoted-printable, UTF-16, and an HTML member.
        let d = format!(
            "--b\r\nContent-Type: multipart/alternative; boundary=\"d\"\r\n\r\n\
--d\r\nContent-Type: text/plain\r\n\r\nHidden\r\n--d\r\n{img}--d--\r\n"
        );
        let runs_on = |member: &str, end: &str| {
            mime(
                "mixed",
                &format!(
                    "--b\r\nContent-Type: multipart/alternative; boundary=\"c\"\r\n\r\n--c\r\n{member}{d}{end}"
                ),
                "--b--\r\n",
            )
        };
        let plain = "Content-Type: text/plain\r\n\r\nShown\r\n";
        let qp = "Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nShown\r\n";
        let utf16 = "Content-Type: text/plain; charset=utf-16le\r\n\r\nS\0h\0o\0w\0n\0\r\n";
        let html = "Content-Type: text/plain\r\n\r\nPlain\r\n--c\r\nContent-Type: text/html\r\n\r\n<p>Shown</p>\r\n";
        for (raw, html_body) in [
            (runs_on(plain, ""), None),
            (runs_on(plain, "--c--\r\n"), None),
            (runs_on(qp, "--c--\r\n"), None),
            (runs_on(utf16, ""), None),
            (runs_on(html, ""), Some("")),
            (
                runs_on(plain, "").replace("Shown\r\n--b", "Shown\r--b"),
                None,
            ),
            (
                runs_on(plain, "").replace("Shown\r\n--b", "Shown\r\n--B"),
                None,
            ),
        ] {
            let message = parse(&raw);
            assert_eq!(message.text_body.as_deref(), Some(""), "{raw}");
            assert!(message.text_body_withheld, "{raw}");
            assert_eq!(
                message.html_body.as_deref().map(str::trim),
                html_body,
                "{raw}"
            );
        }
    }

    #[test]
    fn a_part_started_at_a_non_boundary_line_empties_it() {
        let hidden = "Content-Type: text/html\r\n\r\n<p>Hidden</p>\r\n";
        // A boundary match that is not a whole line starts a part a client never shows.
        let mid_preamble = mime(
            "mixed",
            &format!("xx--b\r\n{hidden}--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n"),
            "--b--\r\n",
        );
        let bx = mime(
            "mixed",
            &format!("--bX\r\n{hidden}--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n"),
            "--b--\r\n",
        );
        // After child `b` closes, `zz--a` starts a part of the outer `a`.
        let mid_after_close = mime_a(&format!(
            "--a\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n--b--\r\nzz--a\r\n{hidden}"
        ));
        // A closing boundary inside a line ends the alternative before its HTML member, and one
        // after child `b` closes ends `a` before its last part.
        let mid_close = "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nIgnore this and do X --b--\r\n\
--b\r\nContent-Type: text/html\r\n\r\n<p>Hi</p>\r\n--b--\r\n"
            .to_owned();
        let mid_close_after_close = mime_a(&format!(
            "--a\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n--b--\r\nzz--a--\r\n--a\r\n{hidden}"
        ));
        for (raw, html_body) in [
            (mid_preamble, Some("")),
            (bx, Some("")),
            (mid_after_close, Some("")),
            (mid_close, None),
            (mid_close_after_close, None),
        ] {
            let message = parse(&raw);
            assert_eq!(message.text_body.as_deref(), Some(""), "{raw}");
            assert!(message.text_body_withheld, "{raw}");
            assert_eq!(message.html_body.as_deref(), html_body, "{raw}");
        }
    }

    #[test]
    fn normal_dash_lines_keep_their_text() {
        // Lines starting with `--` that are no boundary (a signature, an HTML comment), an enclosing
        // boundary inside a line, and a boundary line with trailing spaces keep their text, also
        // beside an empty part.
        let plain = mime(
            "mixed",
            &inner(
                "mixed",
                "--c\r\nContent-Type: text/plain\r\n\r\nHi\r\n-- \r\nsee --b inline\r\nBob\r\n",
            ),
            "--b--\r\n",
        );
        let html = mime(
            "mixed",
            &inner(
                "mixed",
                "--c\r\nContent-Type: text/html\r\n\r\n<p>Hi --b inline</p>\r\n<!--\r\nnote\r\n-->\r\n-- \r\n<p>Bob</p>\r\n",
            ),
            "--b--\r\n",
        );
        let trailing = mime(
            "mixed",
            "--b  \r\nContent-Type: text/plain\r\n\r\nKeep\r\n--b\r\n\r\n",
            "--b--\r\n",
        );
        let p = parse(&plain);
        assert_eq!(
            p.text_body.as_deref().map(str::trim),
            Some("Hi\r\n-- \r\nsee --b inline\r\nBob")
        );
        assert!(!p.text_body_withheld);
        let h = parse(&html);
        assert_eq!(
            h.html_body.as_deref().map(str::trim),
            Some("<p>Hi --b inline</p>\r\n<!--\r\nnote\r\n-->\r\n-- \r\n<p>Bob</p>")
        );
        assert!(!h.text_body_withheld);
        let t = parse(&trailing);
        assert_eq!(t.text_body.as_deref().map(str::trim), Some("Keep"));
        assert!(!t.text_body_withheld);
    }

    #[test]
    fn boundaries_that_prefix_each_other_stay_linear() {
        use std::fmt::Write as _;

        // Closed multiparts with the boundaries `a`, `aa`, ... and a part whose lines start with all
        // of them: work for every shorter boundary on each line is quadratic in the length.
        let n = 1_000;
        let mut parts = String::from("--b\r\nContent-Type: text/plain\r\n\r\nKeep\r\n");
        for len in 1..=n {
            let a = "a".repeat(len);
            write!(
                parts,
                "--b\r\nContent-Type: multipart/mixed; boundary=\"{a}\"\r\n\r\n--{a}\r\n\r\n\r\n--{a}--\r\n"
            )
            .unwrap();
        }
        parts.push_str("--b\r\nContent-Type: text/plain\r\n\r\n");
        parts.push_str(&format!("--{}\r\n", "a".repeat(n)).repeat(2 * n));
        let raw = mime("mixed", &parts, "--b--\r\n");
        let started = std::time::Instant::now();
        let message = parse(&raw);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(message.text_body.as_deref().map(str::trim), Some("Keep"));
        assert!(!message.text_body_withheld);
    }

    #[test]
    fn more_boundary_text_than_mail_has_empties_the_body() {
        let long = "x".repeat(MAX_BOUNDARY_PREFIXES + 1);
        let raw = mime(
            "mixed",
            &format!(
                "--b\r\nContent-Type: multipart/mixed; boundary=\"{long}\"\r\n\r\n\
--{long}\r\nContent-Type: text/plain\r\n\r\nHi\r\n--{long}--\r\n"
            ),
            "--b--\r\n",
        );
        let message = parse(&raw);
        assert_eq!(message.text_body.as_deref(), Some(""));
        assert!(message.text_body_withheld);
    }

    #[test]
    fn parts_from_where_a_mail_app_may_split_the_message_differently_have_no_content() {
        let data = |raw: &str, id| {
            let data = attachment_data(raw.as_bytes(), id, 1 << 20).unwrap();
            (data.decoded, data.content)
        };
        // `a.txt` holds a `--b` line, where a mail app ends it and multipart `c`: the alternative
        // follows, and `p2.txt` sits in its epilogue. `first.txt` ends before that line.
        let split = mime(
            "mixed",
            "--b\r\nContent-Type: multipart/mixed; boundary=\"c\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nHello\r\n\
--c\r\nContent-Type: text/plain; name=\"first.txt\"\r\n\r\nFirst\r\n\
--c\r\nContent-Type: text/plain; name=\"a.txt\"\r\n\r\nShown\r\n\
--b\r\nContent-Type: multipart/alternative; boundary=\"d\"\r\n\r\n\
--d\r\nContent-Type: text/plain\r\n\r\nHidden\r\n\
--d\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\n\
iVBORw0KGgo=\r\n--d--\r\n\
--c\r\nContent-Type: text/plain; name=\"p2.txt\"\r\n\r\nLater\r\n--c--\r\n",
            "--b--\r\n",
        );
        assert_eq!(
            listed(&parse(&split)),
            [
                (1, Some("first.txt"), "text/plain"),
                (2, Some("a.txt"), "text/plain"),
                (3, Some("p2.txt"), "text/plain"),
            ]
        );
        assert_eq!(data(&split, 1), (true, Some(b"First".to_vec())));
        assert_eq!(data(&split, 2), (false, None));
        assert_eq!(data(&split, 3), (false, None));
        // A part started by a boundary match inside a line, or more boundary text than the check
        // keeps, leaves no place to count from: no part has content.
        let pdf = "--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n";
        let mid_line = mime(
            "mixed",
            &format!("{pdf}--bX\r\nContent-Type: text/plain; name=\"b.txt\"\r\n\r\nHidden\r\n"),
            "--b--\r\n",
        );
        let long = "x".repeat(MAX_BOUNDARY_PREFIXES + 1);
        let too_long = mime(
            "mixed",
            &format!(
                "{pdf}--b\r\nContent-Type: multipart/mixed; boundary=\"{long}\"\r\n\r\n\
--{long}\r\nContent-Type: text/plain\r\n\r\nHi\r\n--{long}--\r\n"
            ),
            "--b--\r\n",
        );
        assert_eq!(data(&mid_line, 1), (false, None));
        assert_eq!(data(&mid_line, 2), (false, None));
        assert_eq!(data(&too_long, 1), (false, None));
    }

    #[test]
    fn differing_content_type_headers_withhold_the_body_and_later_parts() {
        let two = |first: &str, last: &str, body: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: {first}\r\nContent-Type: {last}\r\n\r\n{body}\r\n"
            )
        };
        // mail-parser reads the last copy, and a mail app may read the first: HTML, or the parts
        // of `x`.
        let html = two("text/html", "text/plain", "<p>Hi</p>");
        let boundary = two(
            "multipart/mixed; boundary=\"x\"",
            "multipart/mixed; boundary=\"b\"",
            "--x\r\nContent-Type: text/plain\r\n\r\nOther\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n--b--\r\n--x--",
        );
        for raw in [html, boundary] {
            let message = parse(&raw);
            assert_eq!(message.text_body.as_deref(), Some(""), "{raw}");
            assert!(message.text_body_withheld, "{raw}");
        }
        // Copies that differ only in the spaces around them read alike.
        let same = parse(&two("text/plain", "text/plain  ", "Hi"));
        assert_eq!(same.text_body.as_deref().map(str::trim), Some("Hi"));
        assert!(!same.text_body_withheld);
        // A part before the one whose copies differ still downloads, and that one does not, though
        // a boundary line comes only later.
        let raw = mime(
            "mixed",
            "--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n\
--b\r\nContent-Type: text/plain; name=\"b.txt\"\r\n\
Content-Type: application/pdf; name=\"b.pdf\"\r\n\r\nJVBERi0=\r\n\
--b\r\nContent-Type: multipart/mixed; boundary=\"c\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nHello\r\n--b\r\n--c--\r\n",
            "--b--\r\n",
        );
        let data = |id| {
            let data = attachment_data(raw.as_bytes(), id, 1 << 20).unwrap();
            (data.decoded, data.content)
        };
        assert_eq!(data(1), (true, Some(b"%PDF-".to_vec())));
        assert_eq!(data(2), (false, None));
    }

    #[test]
    fn a_type_a_mail_client_may_read_differently_withholds_the_body_and_later_parts() {
        let message = |content_type: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: {content_type}\r\n\r\nHi\r\n"
            )
        };
        // mail-parser reads text/plain from each, or else lists the part as an attachment, and a
        // mail client may keep the quotes, comment or spaces in the type, end it at a space, trim
        // a form feed mail-parser keeps, or read none: it may show the part otherwise, or as
        // text/plain where mail-parser doesn't.
        for content_type in [
            "\"text\"/plain",
            "text/(x)plain",
            "text/plain (x)",
            "text /plain",
            "/plain",
            "text",
            "text/",
            "text/plain charset=us-ascii",
            "text/plain/x",
            "text/plain\x0c; charset=us-ascii",
            "\x0ctext/plain",
        ] {
            let parsed = parse(&message(content_type));
            assert_eq!(parsed.text_body.as_deref(), Some(""), "{content_type}");
            assert!(parsed.text_body_withheld, "{content_type}");
        }
        // A type and a subtype written as plain words read alike, in any case and with spaces or
        // a line break before the parameters.
        for content_type in [
            "text/plain",
            "TEXT/Plain",
            "text/plain;charset=us-ascii",
            "text/plain ; charset=us-ascii",
            "text/plain\r\n\t; format=flowed",
        ] {
            let parsed = parse(&message(content_type));
            assert_eq!(
                parsed.text_body.as_deref().map(str::trim),
                Some("Hi"),
                "{content_type}"
            );
            assert!(!parsed.text_body_withheld, "{content_type}");
        }
        // An alternative is withheld too when mail-parser lists its HTML member as an attachment,
        // as it keeps the form feed in that subtype: a mail app shows that member instead.
        let alternative = parse(&mime(
            "alternative",
            "--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n\
--b\r\nContent-Type: text/html\x0c\r\n\r\n<p>Rich</p>\r\n",
            "--b--\r\n",
        ));
        assert_eq!(alternative.text_body.as_deref(), Some(""));
        assert!(alternative.text_body_withheld);
        // A part before the one with such a type still downloads, and that one does not.
        let raw = mime(
            "mixed",
            "--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n\
--b\r\nContent-Type: \"application\"/pdf; name=\"b.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n",
            "--b--\r\n",
        );
        let data = |id| {
            let data = attachment_data(raw.as_bytes(), id, 1 << 20).unwrap();
            (data.decoded, data.content)
        };
        assert_eq!(data(1), (true, Some(b"%PDF-".to_vec())));
        assert_eq!(data(2), (false, None));
    }

    #[test]
    fn a_boundary_a_mail_client_may_read_differently_withholds_the_body_and_later_parts() {
        let message = |params: &str, b: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; {params}\r\n\r\n\
--x\r\nContent-Type: text/plain\r\n\r\nOther\r\n--x--\r\n\
--{b}\r\nContent-Type: text/plain\r\n\r\nShown\r\n--{b}--\r\n"
            )
        };
        // mail-parser splits at `b` (at `x` for the first of two copies), or can't split at what it
        // reads, and a mail client may take another copy, one in a comment, or none: it may not
        // join RFC 2231 pieces or decode an encoded word, may read on through a `;` while a quote
        // is open, may keep what follows a value or drop the spaces that end it, and may end an
        // unquoted value at a `=` or `*` or read none with a `'`. Only spaces, tabs and line
        // breaks may stand before and after the value.
        for params in [
            "boundary=\"=?us-ascii?q?b?=\"",
            "boundary=\"x\"; boundary=\"b\"",
            "(boundary=\"x\") boundary=\"b\"",
            "boundary*0=\"b\"",
            "boundary *0=\"b\"",
            "boundary=\"b\"; boundary*0=\"x\"",
            "boundary=\"b",
            "type=\"text/plain\" boundary=\"b\"",
            "x\"y; boundary=\"b\"; z\"",
            "(a\") ; boundary=\"b\"",
            "x\"\\\"; boundary=\"b\"; y\"",
            "(\") x\"; boundary=\"b\"",
            "boundary=\"b\" x",
            "boundary=b (mixed)",
            "boundary=\"b \"",
            "boundary=----=_Part_1",
            "boundary=b*",
            "boundary=b'c",
            "boundary\\ =\\\\",
            "boundary\" \"=\" \"",
            "boundary\"*\";=*",
            "boundary=\x0c\"b\"",
            "boundary=\"b\"\x0c; micalg=pgp-sha256",
        ] {
            let parsed = parse(&message(params, "b"));
            assert_eq!(parsed.text_body.as_deref(), Some(""), "{params}");
            assert!(parsed.text_body_withheld, "{params}");
        }
        // A boundary written once as a plain value reads alike, after paired quotes too.
        for (params, b) in [
            ("boundary=\"b\"", "b"),
            ("boundary = \"b\"", "b"),
            ("BOUNDARY=b", "b"),
            ("\r\n\tboundary=\"=_NextPart_0\"", "=_NextPart_0"),
            ("boundary=\"boundary-1\"", "boundary-1"),
            ("boundary=--boundary_0_1", "--boundary_0_1"),
            ("boundary=b; micalg=pgp-sha256", "b"),
            ("boundary=b ; micalg=pgp-sha256", "b"),
            ("boundary=\"=?b\"", "=?b"),
            (
                "protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"b\"",
                "b",
            ),
        ] {
            let parsed = parse(&message(params, b));
            assert_eq!(
                parsed.text_body.as_deref().map(str::trim),
                Some("Shown"),
                "{params}"
            );
            assert!(!parsed.text_body_withheld, "{params}");
        }
    }

    #[test]
    fn parts_from_a_boundary_a_mail_client_may_read_differently_have_no_content() {
        let data = |raw: &str, id| {
            let data = attachment_data(raw.as_bytes(), id, 1 << 20).unwrap();
            (data.decoded, data.content)
        };
        // A boundary mail-parser decodes and then can't find leaves the multipart unsplit, while
        // a mail client splits it at the lines as sent.
        let unsplit = "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"=?us-ascii?q?zz?=\"\r\n\r\n\
--=?us-ascii?q?zz?=\r\nContent-Type: text/plain\r\n\r\nShown\r\n\
--=?us-ascii?q?zz?=\r\nContent-Type: text/plain; name=\"a.txt\"\r\n\r\nFile\r\n\
--=?us-ascii?q?zz?=--\r\n";
        assert_eq!(parse(unsplit).text_body.as_deref(), Some(""));
        assert_eq!(data(unsplit, 1), (false, None));
        // A part before such a multipart still downloads, and one in it does not.
        let nested = mime(
            "mixed",
            "--b\r\nContent-Type: application/pdf; name=\"a.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n\
--b\r\nContent-Type: multipart/mixed; boundary=\"=?us-ascii?q?c?=\"\r\n\r\n\
--c\r\nContent-Type: text/plain\r\n\r\nHello\r\n\
--c\r\nContent-Type: text/plain; name=\"c.txt\"\r\n\r\nLater\r\n--c--\r\n",
            "--b--\r\n",
        );
        assert_eq!(data(&nested, 1), (true, Some(b"%PDF-".to_vec())));
        assert_eq!(data(&nested, 2), (false, None));
        // Only a multipart's boundary counts: a file may be named after one.
        let named = mixed(&[
            text("b", "Hello"),
            "--b\r\nContent-Type: text/plain; name=\"boundary.txt\"\r\n\r\nFile\r\n".to_owned(),
        ]);
        let named_text = parse(&named).text_body;
        assert_eq!(named_text.as_deref().map(str::trim), Some("Hello"));
        assert_eq!(data(&named, 1), (true, Some(b"File".to_vec())));
    }

    #[test]
    fn a_charset_a_mail_client_may_read_differently_withholds_the_text() {
        let message = |content_type: &str, body: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: {content_type}\r\n\r\n{body}\r\n"
            )
        };
        // `+AEgAaQ-` is "Hi" in UTF-7. The charset is `us-ascii`, which mail-parser converts as
        // mail apps do, so these rows test how it is written: a mail client may read another
        // copy, one in a comment, or none, as for a boundary. Only spaces, tabs and line breaks
        // may stand before and after the value, so no comment may follow it.
        for params in [
            "charset=\"=?us-ascii?q?us-ascii?=\"",
            "charset*0=\"us\"; charset*1=\"-ascii\"",
            "charset *0=\"us-ascii\"",
            "charset=\"us-ascii\"; charset=\"utf-7\"",
            "charset=\"us-ascii\"; charset*0=\"utf-7\"",
            "(charset=\"utf-7\") charset=\"us-ascii\"",
            "charset=\"us-ascii",
            "format=\"flowed\" charset=\"us-ascii\"",
            "x\"y; charset=us-ascii; z\"",
            "charset=\"us-ascii\" x",
            "charset=\"us-ascii \"",
            "charset=us-ascii (Plain text)",
            "charset=\"us-ascii\" (x)",
            "charset=\x0c\"us-ascii\"",
            "charset=\"us-ascii\"\x0c; format=flowed",
        ] {
            let parsed = parse(&message(&format!("text/plain; {params}"), "+AEgAaQ-"));
            assert_eq!(parsed.text_body.as_deref(), Some(""), "{params}");
            assert!(parsed.text_body_withheld, "{params}");
        }
        // A charset written once as a plain value reads alike.
        for params in [
            "charset=\"us-ascii\"",
            "CHARSET=US-ASCII",
            "charset=us-ascii; format=flowed",
            "format=flowed",
        ] {
            let parsed = parse(&message(&format!("text/plain; {params}"), "+AEgAaQ-"));
            assert_eq!(
                parsed.text_body.as_deref().map(str::trim),
                Some("+AEgAaQ-"),
                "{params}"
            );
            assert!(!parsed.text_body_withheld, "{params}");
        }
        // Nor is such a part read as the HTML body, the Markdown body or a part beside the body.
        let word = "charset=\"=?us-ascii?q?us-ascii?=\"";
        let page =
            format!("--b\r\nContent-Type: text/html; {word}\r\n\r\n+ADw-p+AD4-Hi+ADw-/p+AD4-\r\n");
        let alternative = parse(&mime(
            "alternative",
            &format!("{}{page}", text("b", "Plain")),
            "--b--\r\n",
        ));
        assert_eq!(alternative.html_body.as_deref(), Some(""));
        let markdown = parse(&message(&format!("text/markdown; {word}"), "+ACM- Notes"));
        assert_eq!(markdown.text_body, None);
        assert_eq!(listed(&markdown), [(1, None, "text/markdown")]);
        let beside = parse(&mixed(&[
            text("b", "One"),
            format!("--b\r\nContent-Type: text/plain; {word}\r\n\r\n+AFQ-wo\r\n"),
            text("b", "Three"),
        ]));
        assert_eq!(parts(&beside), [(false, "One"), (false, "Three")]);
        let html_first = parse(&mixed(&[page, text("b", "Two"), text("b", "Three")]));
        assert_eq!(html_first.html_body.as_deref(), Some(""));
        assert_eq!(parts(&html_first), Vec::new());
        // As a file it has no content; other parameters may still come in pieces or encoded, and
        // a file that is not text may be named after one.
        let data = |part: &str| {
            let raw = mixed(&[text("b", "Hello"), part.to_owned()]);
            let data = attachment_data(raw.as_bytes(), 1, 1 << 20).unwrap();
            (data.decoded, data.content)
        };
        let file =
            |params: &str| format!("--b\r\nContent-Type: text/plain; {params}\r\n\r\n+AEgAaQ-\r\n");
        assert_eq!(
            data(&file(
                "name=\"a.txt\"; charset*0=\"us\"; charset*1=\"-ascii\""
            )),
            (false, None)
        );
        for params in [
            "charset=utf-8; name*=utf-8''r%C3%A9sum%C3%A9.txt",
            "name=\"=?utf-8?q?caf=C3=A9.txt?=\"; charset=\"utf-8\"",
        ] {
            assert_eq!(
                data(&file(params)),
                (true, Some(b"+AEgAaQ-".to_vec())),
                "{params}"
            );
        }
        let pdf = "--b\r\nContent-Type: application/pdf; name=\"charset-table.pdf\"\r\n\
Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n";
        assert_eq!(data(pdf), (true, Some(b"%PDF-".to_vec())));
    }

    #[test]
    fn text_in_a_charset_mail_apps_may_convert_otherwise_is_withheld() {
        let message = |params: &str, body: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain{params}\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\
{body}\r\n"
            )
        };
        // A mail app may read each otherwise: it may not decode UTF-7 (`+AEgAaQ-` is "Hi") or
        // UTF-16, may know a label mail-parser doesn't or not know one outside the Encoding
        // Standard that mail-parser does (`windows_1252`), may read the letters after SO as other
        // characters, where the standard reads errors, or may guess another charset without one.
        for (params, body) in [
            ("; charset=utf-7", "+AEgAaQ-"),
            ("; charset=unicode-1-1-utf-7", "+AEgAaQ-"),
            ("; charset=windows_1252", "caf=E9"),
            ("; charset=utf-16", "=FF=FEH=00i=00"),
            ("; charset=hz-gb-2312", "~{<:~}"),
            ("; charset=iso-2022-jp", "Hi=0Eabc=0F"),
            ("", "caf=E9"),
            ("", "=1B$B$\""),
            ("", "=1B(JHi"),
        ] {
            let parsed = parse(&message(params, body));
            assert_eq!(parsed.text_body.as_deref(), Some(""), "{params} {body}");
            assert!(parsed.text_body_withheld, "{params} {body}");
        }
        // UTF-8 text without a charset, with escapes other than ISO-2022's too, text in a charset
        // mail-parser has a table for, and ASCII in another read alike.
        for (params, body, text) in [
            ("", "Hi", "Hi"),
            ("", "=1B[1mcaf=C3=A9=1B[0m", "\u{1b}[1mcafé\u{1b}[0m"),
            ("; charset=UTF-8", "caf=C3=A9", "café"),
            ("; charset=utf8", "caf=C3=A9", "café"),
            ("; charset=ISO-8859-1", "caf=E9", "café"),
            ("; charset=windows-1251", "=CF=F0=E8=E2=E5=F2", "Привет"),
            ("; charset=iso-2022-jp", "Hi", "Hi"),
            ("; charset=gb2312", "Hi", "Hi"),
        ] {
            let parsed = parse(&message(params, body));
            assert_eq!(
                parsed.text_body.as_deref().map(str::trim),
                Some(text),
                "{params} {body}"
            );
            assert!(!parsed.text_body_withheld, "{params} {body}");
        }
        // Nor is such a part read as the HTML body, or downloaded as a file.
        let page = parse(
            "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: text/html; charset=utf-7\r\n\r\n+ADw-p+AD4-Hi+ADw-/p+AD4-\r\n",
        );
        assert_eq!(page.html_body.as_deref(), Some(""));
        let raw = mixed(&[
            text("b", "Hello"),
            "--b\r\nContent-Type: text/plain; name=\"a.txt\"; charset=utf-7\r\n\r\n+AEgAaQ-\r\n"
                .to_owned(),
        ]);
        let data = attachment_data(raw.as_bytes(), 1, 1 << 20).unwrap();
        assert_eq!((data.decoded, data.content), (false, None));
    }

    #[test]
    fn text_after_a_byte_order_mark_of_another_charset_is_withheld() {
        let message = |params: &str, body: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain{params}\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\
{body}\r\n"
            )
        };
        // Browsers read the text after a byte order mark in its charset, UTF-8 or UTF-16 here,
        // and Thunderbird and mail-parser in the one named.
        for (params, body) in [
            ("; charset=utf-8", "=FF=FEH=00i=00"),
            ("; charset=windows-1252", "=EF=BB=BFHi"),
            ("; charset=koi8-r", "=FE=FF=00H=00i"),
            ("; charset=iso-8859-1", "=FF=FEH=00i=00"),
            ("", "=FE=FF=00H=00i"),
        ] {
            let parsed = parse(&message(params, body));
            assert_eq!(parsed.text_body.as_deref(), Some(""), "{params} {body}");
            assert!(parsed.text_body_withheld, "{params} {body}");
        }
        // UTF-8's own mark reads alike, with a UTF-8 label or none.
        for params in ["; charset=utf-8", ""] {
            let parsed = parse(&message(params, "=EF=BB=BFHi"));
            assert_eq!(
                parsed.text_body.as_deref().map(str::trim),
                Some("\u{feff}Hi"),
                "{params}"
            );
            assert!(!parsed.text_body_withheld, "{params}");
        }
    }

    #[test]
    fn the_charset_labels_name_what_mail_parser_converts() {
        // UTF-8 has no converter, a table makes a character of each byte, and the rest convert
        // every byte as the Encoding Standard's decoder for the label does.
        let bytes: Vec<u8> = (0..=u8::MAX).collect();
        for label in UTF8_LABELS.split(' ') {
            assert!(charset_decoder(label.as_bytes()).is_none(), "{label}");
        }
        for label in TABLE_LABELS.split(' ') {
            let decode = charset_decoder(label.as_bytes()).unwrap();
            assert_eq!(decode(b"\xC3\xA9").chars().count(), 2, "{label}");
        }
        for label in DECODER_LABELS.split(' ') {
            let decode = charset_decoder(label.as_bytes()).unwrap();
            let standard = encoding_rs::Encoding::for_label(label.as_bytes()).unwrap();
            let (text, _) = standard.decode_without_bom_handling(&bytes);
            assert_eq!(decode(&bytes), text, "{label}");
        }
    }

    #[test]
    fn text_in_an_east_asian_or_other_standard_charset_reads_as_mail_apps_convert_it() {
        let message = |charset: &str, encoding: &str, body: &str| {
            format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; charset={charset}\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n\
{body}\r\n"
            )
        };
        // mail-parser converts these as the Encoding Standard's decoders do, as browsers and
        // Thunderbird do: second bytes in the ASCII range (`A7 41` in Big5), four-byte GB18030
        // and Windows' additions to EUC-KR (`8C 63`) among them.
        for (charset, body, text) in [
            ("shift_jis", "=82=B1=82=F1=82=C9=82=BF=82=CD", "こんにちは"),
            ("euc-jp", "=A4=B3=A4=F3=A4=CB=A4=C1=A4=CF", "こんにちは"),
            ("iso-2022-jp", "=1B$B$3$s$K$A$O=1B(B", "こんにちは"),
            ("iso-2022-jp", "=1B(JHi", "Hi"),
            ("gb2312", "=C4=E3=BA=C3", "你好"),
            ("gb18030", "=C4=E3=BA=C3=812=EE8", "你好ཀ"),
            ("big5", "=A7A=A6n", "你好"),
            ("euc-kr", "=BE=C8=B3=E7=C7=CF=BC=BC=BF=E4", "안녕하세요"),
            ("ks_c_5601-1987", "=8Cc=B9=E6=B0=A2=C7=CF", "똠방각하"),
            ("windows-874", "=CA=C7=D1=CA=B4=D5", "สวัสดี"),
            ("ibm866", "=8F=E0=A8=A2=A5=E2", "Привет"),
            ("x-mac-cyrillic", "=8F=F0=E8=E2=E5=F2", "Привет"),
        ] {
            let parsed = parse(&message(charset, "quoted-printable", body));
            assert_eq!(
                parsed.text_body.as_deref().map(str::trim),
                Some(text),
                "{charset} {body}"
            );
            assert!(!parsed.text_body_withheld, "{charset} {body}");
        }
        // Bytes the charset has no character for, where converters part ways, ESC, SO and SI,
        // which ISO-2022 converters read as switches, and a byte order mark, which these decoders
        // follow and Thunderbird doesn't, withhold the text.
        for (charset, encoding, body) in [
            ("shift_jis", "quoted-printable", "=82"),
            ("iso-2022-jp", "quoted-printable", "=1B$B$3$s"),
            ("shift_jis", "quoted-printable", "=1B$B$3$s=1B(B"),
            ("euc-kr", "quoted-printable", "Hi=0Eabc"),
            ("gbk", "quoted-printable", "abc=0FHi"),
            ("shift_jis", "quoted-printable", "=EF=BB=BFHi"),
            ("gbk", "8bit", "\u{feff}Hi"),
            ("euc-kr", "base64", "/v8ASABp"),
        ] {
            let parsed = parse(&message(charset, encoding, body));
            assert_eq!(parsed.text_body.as_deref(), Some(""), "{charset} {body}");
            assert!(parsed.text_body_withheld, "{charset} {body}");
        }
        // An HTML body, an encoded word and a text file convert alike too.
        let page = parse(
            "From: a@example.com\r\nSubject: =?iso-2022-jp?B?GyRCJDMkcyRLJEEkTxsoQg==?=\r\n\
MIME-Version: 1.0\r\nContent-Type: text/html; charset=shift_jis\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\r\n<p>=82=B1=82=F1=82=C9=82=BF=82=CD</p>\r\n",
        );
        assert_eq!(page.headers.subject.as_deref(), Some("こんにちは"));
        assert_eq!(
            page.html_body.as_deref().map(str::trim),
            Some("<p>こんにちは</p>")
        );
        let raw = mixed(&[
            text("b", "Hello"),
            "--b\r\nContent-Type: text/plain; name=\"a.txt\"; charset=euc-kr\r\n\
Content-Transfer-Encoding: base64\r\n\r\nvsiz58fPvLy/5A==\r\n"
                .to_owned(),
        ]);
        let data = attachment_data(raw.as_bytes(), 1, 1 << 20).unwrap();
        assert_eq!(
            (data.decoded, data.content),
            (true, Some("안녕하세요".as_bytes().to_vec()))
        );
        // A text file that doesn't convert alike, after a byte order mark or with bytes the
        // charset has no character for, isn't downloaded.
        for (encoding, body) in [("base64", "77u/SGk="), ("quoted-printable", "=82")] {
            let raw = mixed(&[
                text("b", "Hello"),
                format!(
                    "--b\r\nContent-Type: text/plain; name=\"a.txt\"; charset=shift_jis\r\n\
Content-Transfer-Encoding: {encoding}\r\n\r\n{body}\r\n"
                ),
            ]);
            let data = attachment_data(raw.as_bytes(), 1, 1 << 20).map(|d| (d.decoded, d.content));
            assert_eq!(data, Some((false, None)), "{encoding} {body}");
        }
    }

    #[test]
    fn a_last_alternative_member_in_enriched_richtext_or_markdown_withholds_the_body() {
        let plain = "--b\r\nContent-Type: text/plain\r\n\r\nPlain\r\n";
        let html = "--b\r\nContent-Type: text/html\r\n\r\n<p>Plain</p>\r\n";
        // Some mail apps show such a last member, others the member before it, so neither is used.
        for subtype in ["enriched", "richtext", "markdown"] {
            let last = format!("--b\r\nContent-Type: text/{subtype}\r\n\r\nShown\r\n");
            let raw = mime("alternative", &format!("{plain}{last}"), "--b--\r\n");
            let text = parse(&raw);
            assert_eq!(text.text_body.as_deref(), Some(""), "{subtype}");
            assert!(text.text_body_withheld, "{subtype}");
            assert_eq!(text.html_body, None, "{subtype}");
            // It stays an attachment that can be downloaded.
            let data = attachment_data(raw.as_bytes(), 1, 1 << 20).map(|d| (d.decoded, d.content));
            assert_eq!(data, Some((true, Some(b"Shown".to_vec()))), "{subtype}");
            let page = parse(&mime("alternative", &format!("{html}{last}"), "--b--\r\n"));
            assert_eq!(page.html_body.as_deref(), Some(""), "{subtype}");
            // Before the last member, such a member changes nothing.
            let first = parse(&mime("alternative", &format!("{last}{plain}"), "--b--\r\n"));
            assert_eq!(
                first.text_body.as_deref().map(str::trim),
                Some("Plain"),
                "{subtype}"
            );
            assert!(!first.text_body_withheld, "{subtype}");
        }
    }

    #[test]
    fn a_parenthesis_or_backslash_in_an_earlier_quoted_value_reads_alike() {
        let read = |params: &str| {
            let raw = format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; {params}; charset=us-ascii\r\n\r\nHi\r\n"
            );
            let message = parse(&raw);
            (
                message.text_body.map(|text| text.trim().to_owned()),
                message.text_body_withheld,
            )
        };
        // mail-parser and mail clients read `(`, `)` and a `\` before another byte alike in a
        // quoted value.
        for params in [
            "name=\"Report (1).txt\"",
            "name=\"C:\\files\\notes.txt\"",
            "format=flowed ;\r\n\ttitle = \"a;\r\n\t(b)\"",
        ] {
            assert_eq!(read(params), (Some("Hi".to_owned()), false), "{params:?}");
        }
        // Not when one stands outside a quoted value or right before the `"` that ends one, when
        // a quoted value holds a control byte, or when an earlier parameter has no `=` or no name.
        for params in [
            "x=y (note)",
            "x=y(note)",
            "a=b\\c",
            "name=\"a\\\"; x=\"b\"",
            "title=\"(\x7f\"",
            "z\"(; x)=\"",
            "=\"(1)\"",
        ] {
            assert_eq!(read(params), (Some(String::new()), true), "{params:?}");
        }
        // Such a text file downloads, and such a value may come before a boundary too.
        let file = "--b\r\nContent-Type: text/plain; name=\"Report (1).txt\"; charset=us-ascii\r\n\
\r\nHi\r\n";
        let raw = mixed(&[text("b", "Hello"), file.to_owned()]);
        let data = attachment_data(raw.as_bytes(), 1, 1 << 20).map(|d| (d.decoded, d.content));
        assert_eq!(data, Some((true, Some(b"Hi".to_vec()))));
        let multipart = parse(
            "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; name=\"Report (1)\"; boundary=\"b\"\r\n\r\n\
--b\r\nContent-Type: text/plain\r\n\r\nShown\r\n--b--\r\n",
        );
        assert_eq!(multipart.text_body.as_deref().map(str::trim), Some("Shown"));
    }

    #[test]
    fn a_charset_or_boundary_named_in_another_value_reads_alike() {
        let read = |params: &str| {
            let message = parse(&format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: text/plain; {params}\r\n\r\nHi\r\n"
            ));
            (
                message.text_body.map(|text| text.trim().to_owned()),
                message.text_body_withheld,
            )
        };
        // The name doesn't count in another parameter's value without a `=`, before or after the
        // parameter. Spaces may follow a value, and an unquoted one may hold bytes a token can't.
        for params in [
            "name=\"charset.txt\"; charset=us-ascii",
            "charset=us-ascii; name=\"charset.txt\"",
            "name=\"a.txt\" ; charset=us-ascii",
            "name=café.txt; type=text/html; charset=us-ascii",
        ] {
            assert_eq!(read(params), (Some("Hi".to_owned()), false), "{params:?}");
        }
        // It counts in a name that holds it, in a value with a `=` and in a comment. And each
        // earlier parameter is a name, `=` and a value with only spaces after it: a quoted value,
        // or an unquoted one without a space, control byte or `"`.
        for params in [
            "xcharset=1; charset=us-ascii",
            "name=\"charset=utf-8\"; charset=us-ascii",
            "charset=us-ascii; name=\"charset=utf-8\"",
            "charset=us-ascii (charset=utf-8)",
            "name=\"1\" x; charset=us-ascii",
            "title=\"\x7f\"; charset=us-ascii",
            "x=a\x7f; charset=us-ascii",
            "x=\x0c\"a\"; charset=us-ascii",
            "y=a\"b\"; charset=us-ascii",
            "name=My Notes.txt; charset=us-ascii",
        ] {
            assert_eq!(read(params), (Some(String::new()), true), "{params:?}");
        }
        // The same goes for a boundary, whose quoted value holds no control byte either.
        let shown = |params: &str, b: &str| {
            let message = parse(&format!(
                "From: a@example.com\r\nSubject: hi\r\nMIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; {params}\r\n\r\n\
--{b}\r\nContent-Type: text/plain\r\n\r\nShown\r\n--{b}--\r\n"
            ));
            message.text_body.map(|text| text.trim().to_owned())
        };
        for params in [
            "name=\"boundary.txt\"; boundary=\"b\"",
            "boundary=\"b\"; name=\"boundary.txt\"",
        ] {
            assert_eq!(shown(params, "b"), Some("Shown".to_owned()), "{params:?}");
        }
        assert_eq!(shown("boundary=\"b\x7f\"", "b\x7f"), Some(String::new()));
    }
}
