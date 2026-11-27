//! Files handed in with outgoing mail, and the `download_attachment` tool.

use std::fmt;

use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use postkeep_mail::OutgoingAttachment;
use postkeep_mail::invisible::{escape_name, visible};
use rmcp::model::{CallToolResult, ContentBlock};
use schemars::JsonSchema;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use postkeep_auth::Authenticated;
use postkeep_store::{AccountId, DataKey, PIECE_TAG, UploadLookup, UploadOwner, open_piece};

use super::{AttachmentInfo, DEFAULT_MAX_CHARS, MAX_MAX_CHARS, MailTools, mailbox_error};
use crate::bucket::Bucket;
use crate::mailbox::Selector;
use crate::text;
use crate::upload::{
    MAX_UPLOAD_BYTES, MAX_UPLOAD_MIB, UPLOAD_PIECE, UPLOAD_TIME, UPLOADS_OFF, delete_pieces,
    piece_name, pieces,
};

#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct NewAttachmentWire {
    /// File name, not a path (at most 255 bytes).
    filename: String,
    /// MIME type, e.g. `application/pdf`. Defaults to `application/octet-stream`, or `text/plain; charset=utf-8` for `text`.
    content_type: Option<String>,
    /// File bytes as standard padded base64, with no line breaks. Give one of `content`, `text` and `upload_id`.
    content: Option<String>,
    /// A UTF-8 file. Give one of `text`, `content` and `upload_id`.
    text: Option<String>,
    /// The `upload_id` from `upload_attachment`, once its file is sent. Give one of `upload_id`, `content` and `text`.
    upload_id: Option<String>,
}

/// An outgoing file with its name and type checked, and its decoded bytes
/// checked or its upload looked up.
#[derive(Deserialize)]
#[serde(try_from = "NewAttachmentWire")]
pub struct NewAttachment(File);

enum File {
    /// Its bytes came in the call.
    Typed(OutgoingAttachment),
    /// Its bytes wait in the bucket, looked up by `resolve` and read by `load`.
    Uploaded(Uploaded),
}

pub(super) struct Uploaded {
    id: String,
    filename: String,
    content_type: String,
    stored: Option<Stored>,
}

struct Stored {
    object: String,
    key: DataKey,
    digest: [u8; 32],
    size: usize,
    expires_at: i64,
}

/// The uploaded files of a message, each with its place among the message's
/// files.
pub(super) struct Uploads(Vec<(usize, Uploaded)>);

#[expect(
    clippy::redundant_pub_crate,
    reason = "re-exported with crate visibility for capability reporting"
)]
pub(crate) const MAX_ATTACHMENTS: usize = 1_000;

/// Checks the count before parsing or decoding individual items.
pub(super) fn read_attachments<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Vec<NewAttachment>, D::Error> {
    let files = Vec::<Value>::deserialize(d)?;
    if files.len() > MAX_ATTACHMENTS {
        return Err(de::Error::custom(format_args!(
            "give at most {MAX_ATTACHMENTS} attachments per call"
        )));
    }
    files
        .into_iter()
        .enumerate()
        .map(|(i, file)| {
            let wire = NewAttachmentWire::deserialize(file).map_err(|_| {
                de::Error::custom(format_args!(
                    "attachment {}: invalid fields; check the attachment schema",
                    i + 1
                ))
            })?;
            wire.try_into().map_err(de::Error::custom)
        })
        .collect()
}

impl TryFrom<NewAttachmentWire> for NewAttachment {
    type Error = String;

    fn try_from(wire: NewAttachmentWire) -> Result<Self, Self::Error> {
        let NewAttachmentWire {
            filename,
            content_type,
            content,
            text,
            upload_id,
        } = wire;
        let invalid = |reason: &str| format!("attachment {filename:?}: {reason}");
        if filename.is_empty()
            || filename.len() > 255
            || filename.contains(['/', '\\'])
            || filename.contains("=?")
            || matches!(filename.as_str(), "." | "..")
            || escape_name(&filename) != filename
        {
            return Err(invalid(
                "give a file name of 1 to 255 bytes without paths, invisible characters or MIME encoded words",
            ));
        }
        let as_text = text.is_some();
        let mut content_type = content_type.unwrap_or_else(|| {
            if as_text {
                "text/plain; charset=utf-8"
            } else {
                "application/octet-stream"
            }
            .to_owned()
        });
        if !content_type
            .bytes()
            .all(|byte| (b' '..=b'~').contains(&byte))
        {
            return Err(invalid("content_type must be printable ASCII"));
        }
        // This is the same MIME parser that lettre's ContentType::parse uses.
        let parsed = content_type
            .parse::<mime::Mime>()
            .map_err(|_| invalid("invalid content_type"))?;
        if parsed.subtype().as_str().is_empty() {
            return Err(invalid("invalid content_type"));
        }
        if parsed.type_() == mime::MULTIPART {
            return Err(invalid("multipart is not a file content_type"));
        }
        let mut has_charset = false;
        for (name, value) in parsed.params() {
            if name != mime::CHARSET || has_charset {
                return Err(invalid("content_type can have only a charset parameter"));
            }
            if !postkeep_mail::mime::is_parameter_token(value.as_str()) {
                return Err(invalid("charset must be a nonempty MIME token"));
            }
            if as_text && value != mime::UTF_8 {
                return Err(invalid("text must have charset=utf-8"));
            }
            has_charset = true;
        }
        if as_text && !has_charset {
            content_type = format!(
                "{}; charset=utf-8",
                content_type.trim_end_matches([' ', ';'])
            );
        }
        let content = match (content, text, upload_id) {
            (Some(encoded), None, None) => STANDARD
                .decode(encoded)
                .map_err(|_| invalid("content is not base64"))?,
            (None, Some(text), None) => text.into_bytes(),
            (None, None, Some(id)) => {
                return Ok(Self(File::Uploaded(Uploaded {
                    id,
                    filename,
                    content_type,
                    stored: None,
                })));
            }
            _ => return Err(invalid("give exactly one of content, text and upload_id")),
        };
        let file = OutgoingAttachment {
            filename,
            content_type,
            content,
            content_id: None,
            inline: false,
        };
        checked(&file)?;
        Ok(Self(File::Typed(file)))
    }
}

impl NewAttachment {
    /// The file's name, and its size, which is 0 for an upload not looked up.
    fn named(&self) -> (&str, usize) {
        match &self.0 {
            File::Typed(file) => (&file.filename, file.content.len()),
            File::Uploaded(file) => (&file.filename, file.stored.as_ref().map_or(0, |s| s.size)),
        }
    }
}

impl fmt::Debug for NewAttachment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (filename, size) = self.named();
        f.debug_struct("NewAttachment")
            .field("filename", &filename)
            .field("size", &size)
            .finish()
    }
}

/// The only attachment data in the arguments fingerprinted for a held send.
#[derive(Deserialize, Serialize)]
pub struct FileDigest<'a> {
    pub(super) filename: &'a str,
    content_type: &'a str,
    pub(super) size: usize,
    sha256: String,
}

impl<'a> FileDigest<'a> {
    pub(crate) fn new(file: &'a OutgoingAttachment) -> Self {
        Self {
            filename: &file.filename,
            content_type: &file.content_type,
            size: file.content.len(),
            sha256: hex::encode(Sha256::digest(&file.content)),
        }
    }

    /// An uploaded file's, by the size and digest taken as its bytes arrived.
    fn uploaded(file: &'a Uploaded, stored: &Stored) -> Self {
        Self {
            filename: &file.filename,
            content_type: &file.content_type,
            size: stored.size,
            sha256: hex::encode(stored.digest),
        }
    }
}

impl Serialize for NewAttachment {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            File::Typed(file) => FileDigest::new(file),
            File::Uploaded(file) => {
                let stored = file.stored.as_ref();
                let stored =
                    stored.ok_or_else(|| serde::ser::Error::custom("an upload not looked up"))?;
                FileDigest::uploaded(file, stored)
            }
        }
        .serialize(serializer)
    }
}

/// The typed files of a message, for it now, and its uploads with their
/// places among its files, to read at the send.
pub(super) fn split(files: Vec<NewAttachment>) -> (Vec<OutgoingAttachment>, Uploads) {
    let (mut typed, mut uploads) = (Vec::new(), Vec::new());
    for (place, file) in files.into_iter().enumerate() {
        match file.0 {
            File::Typed(file) => typed.push(file),
            File::Uploaded(file) => uploads.push((place, file)),
        }
    }
    (typed, Uploads(uploads))
}

/// When the first of the looked-up uploads among `files` ends (Unix seconds).
pub(super) fn uploads_end(files: &[NewAttachment]) -> Option<i64> {
    let stored = files.iter().filter_map(|file| match &file.0 {
        File::Uploaded(file) => file.stored.as_ref(),
        File::Typed(_) => None,
    });
    stored.map(|stored| stored.expires_at).min()
}

fn grouped(n: usize) -> String {
    if n < 1_000 {
        n.to_string()
    } else {
        format!("{},{:03}", grouped(n / 1_000), n % 1_000)
    }
}

pub(super) fn files_named<'a>(files: impl IntoIterator<Item = (&'a str, usize)>) -> String {
    files
        .into_iter()
        .map(|(name, size)| format!("{name} ({} bytes)", grouped(size)))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn files_line(files: &[NewAttachment]) -> String {
    if files.is_empty() {
        return String::new();
    }
    let names = files_named(files.iter().map(NewAttachment::named));
    format!("\nAttachments in this message: {names}.")
}

/// `error` with `files` (the message's files line, or a hold's sentence),
/// kept ahead of the line that says its uploads went with the try, so that
/// line stays last.
pub(super) fn with_files(error: &str, files: &str) -> String {
    error.strip_suffix(WENT).map_or_else(
        || format!("{error}{files}"),
        |words| format!("{}{files}\n{WENT}", words.trim_end()),
    )
}

/// MR 1's check of a file's bytes: a `message/*` file's lines.
fn checked(file: &OutgoingAttachment) -> Result<(), String> {
    file.validate_content().map_err(|error| match error {
        postkeep_mail::Error::InvalidInput(message) => message,
        other => other.to_string(),
    })
}

const NO_UPLOAD: &str = "no upload has this id here. It may have been used on a message \
    already, have ended, or belong to another mailbox or app. Ask for a new one with \
    upload_attachment.";
const NOT_ARRIVED: &str = "the file for this upload hasn't arrived. Send it with its token, or \
    let its upload finish, then call again.";
const NOT_USED: &str =
    "Not sent: postkeep couldn't use the uploaded files just now. Try again in a minute.";
const WENT: &str = "Its uploaded files went with this try: upload them again to send them.";

/// The mailbox and the caller of a call, whose uploads it makes and attaches.
pub(super) fn caller(parts: &Parts) -> Result<(AccountId, &Authenticated), String> {
    let account = MailTools::require_account(parts)?;
    let caller = parts.extensions.get::<Authenticated>();
    Ok((account, caller.ok_or("not authenticated")?))
}

/// Only this mailbox, principal and app attach an upload.
pub(super) fn owner<'a>(account: &'a AccountId, caller: &'a Authenticated) -> UploadOwner<'a> {
    UploadOwner {
        account,
        principal: &caller.principal,
        app: &caller.client_id,
    }
}

impl Uploads {
    /// The bytes the uploads hold together.
    pub(super) fn total(&self) -> usize {
        let stored = self.0.iter().filter_map(|(_, file)| file.stored.as_ref());
        stored.map(|stored| stored.size).sum()
    }

    /// The send's one memory reservation for them, when there are any.
    pub(super) async fn reserve(
        &self,
    ) -> Result<Option<tokio::sync::SemaphorePermit<'static>>, String> {
        if self.0.is_empty() {
            return Ok(None);
        }
        crate::limits::large_message(self.total()).await.map(Some)
    }

    /// Reads each upload from `bucket` into its place among `files`, in list
    /// order, and checks it as a typed file is checked.
    pub(super) async fn load(
        &self,
        bucket: Option<&dyn Bucket>,
        files: &mut Vec<OutgoingAttachment>,
    ) -> Result<(), String> {
        for (place, upload) in &self.0 {
            let unreadable = || {
                format!(
                    "attachment {:?}: the uploaded file could not be read; nothing was sent. \
                     Try again in a minute, or upload it again.",
                    upload.filename
                )
            };
            let (Some(bucket), Some(stored)) = (bucket, &upload.stored) else {
                return Err(unreadable());
            };
            let file = OutgoingAttachment {
                filename: upload.filename.clone(),
                content_type: upload.content_type.clone(),
                content: read(bucket, stored).await.ok_or_else(unreadable)?,
                content_id: None,
                inline: false,
            };
            checked(&file)?;
            files.insert((*place).min(files.len()), file);
        }
        Ok(())
    }
}

/// An upload's bytes: each piece got at its exact length with its tag and
/// opened under its number, then the whole file checked against its digest. A
/// piece swapped, dropped, cut short, added or taken from another upload fails.
async fn read(bucket: &dyn Bucket, stored: &Stored) -> Option<Vec<u8>> {
    let mut content = Vec::with_capacity(stored.size);
    for number in 0..pieces(i64::try_from(stored.size).ok()?) {
        let start = usize::try_from(number).ok()?.checked_mul(UPLOAD_PIECE)?;
        let length = stored.size.saturating_sub(start).min(UPLOAD_PIECE) + PIECE_TAG;
        let name = piece_name(&stored.object, number);
        let piece = bucket.get(&name, length).await.ok()?;
        if piece.len() != length {
            return None;
        }
        let mut piece = Vec::from(piece);
        open_piece(&stored.key, number, &mut piece).ok()?;
        content.extend_from_slice(&piece);
    }
    (Sha256::digest(&content)[..] == stored.digest).then_some(content)
}

impl MailTools {
    /// Looks up each upload among `files` for the caller before the arguments
    /// are fingerprinted, so a hold pins its stored size and digest: only its
    /// row is read, never the bucket. Without a bucket nothing is looked up.
    pub(super) async fn resolve(
        &self,
        parts: &Parts,
        files: &mut [NewAttachment],
    ) -> Result<(), String> {
        let mut total = 0_usize;
        for (number, file) in files.iter_mut().enumerate() {
            let File::Uploaded(upload) = &mut file.0 else {
                continue;
            };
            let place = format!("attachment {} ({:?})", number + 1, upload.filename);
            if self.context.bucket.is_none() {
                return Err(format!("{place}: {UPLOADS_OFF}"));
            }
            let (account, caller) = caller(parts)?;
            let found =
                self.context
                    .store
                    .upload_for(owner(&account, caller), &upload.id, UPLOAD_TIME);
            let (object, key, digest, size, expires_at) = match found.await {
                Ok(UploadLookup::Stored {
                    object,
                    key,
                    digest,
                    size,
                    expires_at,
                }) => (object, key, digest, size, expires_at),
                Ok(UploadLookup::Arriving) => return Err(format!("{place}: {NOT_ARRIVED}")),
                Ok(UploadLookup::Missing) => return Err(format!("{place}: {NO_UPLOAD}")),
                Err(err) => {
                    tracing::error!(error = %err, "could not look up an upload");
                    return Err(NOT_USED.to_owned());
                }
            };
            let size = usize::try_from(size).unwrap_or(usize::MAX);
            total = total.saturating_add(size);
            upload.stored = Some(Stored {
                object,
                key,
                digest,
                size,
                expires_at,
            });
        }
        if total > MAX_UPLOAD_BYTES {
            let uploaded = files
                .iter()
                .filter(|file| matches!(file.0, File::Uploaded(_)));
            let names = files_named(uploaded.map(NewAttachment::named));
            return Err(format!(
                "The uploaded files of one message may total {MAX_UPLOAD_MIB} MiB; these total {} \
                 bytes: {names}.",
                grouped(total)
            ));
        }
        Ok(())
    }

    /// Runs `call`, the provider call of a message with `uploads`, once they
    /// are all used up, all or none: one used or ended meanwhile refuses the
    /// message by name before the call. Whatever the call answers, they are
    /// used; their pieces' deletes start at once, and a failure says so.
    pub(super) async fn using_uploads<T>(
        &self,
        parts: &Parts,
        uploads: &Uploads,
        call: impl Future<Output = Result<T, String>>,
    ) -> Result<T, String> {
        if uploads.0.is_empty() {
            return call.await;
        }
        let (account, caller) = caller(parts)?;
        // The same upload twice in a message is one upload, used once.
        let mut named: Vec<(usize, &Uploaded)> = Vec::new();
        for (place, upload) in &uploads.0 {
            if !named.iter().any(|(_, seen)| seen.id == upload.id) {
                named.push((*place, upload));
            }
        }
        let ids: Vec<&str> = named.iter().map(|(_, upload)| upload.id.as_str()).collect();
        let used = match self
            .context
            .store
            .use_uploads(owner(&account, caller), &ids)
            .await
        {
            Ok(Ok(used)) => used,
            Ok(Err(gone)) => {
                let (place, upload) = named.get(gone).copied().ok_or(NOT_USED)?;
                let name = &upload.filename;
                return Err(format!("attachment {} ({name:?}): {NO_UPLOAD}", place + 1));
            }
            Err(err) => {
                tracing::error!(error = %err, "could not use the uploaded files");
                return Err(NOT_USED.to_owned());
            }
        };
        let (store, bucket) = (self.context.store.clone(), self.context.bucket.clone());
        tokio::spawn(async move { delete_pieces(&store, bucket.as_deref(), &used).await });
        call.await.map_err(|error| format!("{error} {WENT}"))
    }
}

/// Largest decoded attachment returned, for every kind: its base64 (4 MiB)
/// stays under the 5 MB per-image limit model APIs commonly set, and it
/// bounds each response and the memory a call holds.
pub(super) const MAX_ATTACHMENT_MIB: usize = MAX_ATTACHMENT_BYTES / (1024 * 1024);
#[expect(
    clippy::redundant_pub_crate,
    reason = "re-exported with crate visibility for capability reporting"
)]
pub(crate) const MAX_ATTACHMENT_BYTES: usize = 3 * 1024 * 1024;

/// Shown for an `attachment_id` that is not a positive whole number.
const BAD_ATTACHMENT_ID: &str =
    "attachment_id must be an attachment id from get_message, such as \"1\".";

/// Schema stand-in: an attachment id as a number or a string.
#[derive(JsonSchema)]
#[serde(untagged)]
#[allow(
    dead_code,
    reason = "the variants exist so the MCP schema accepts a number or a string"
)]
enum AttachmentIdWire {
    Number(u32),
    Text(String),
}

/// Parameters for `download_attachment`.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownloadAttachmentParams {
    #[doc = id_doc!()]
    pub id: String,
    /// The attachment id from `get_message`, such as "1".
    #[schemars(with = "AttachmentIdWire")]
    pub attachment_id: Value,
    /// Maximum length in characters when the attachment is text (default 20000, maximum 200000).
    #[serde(default)]
    pub max_chars: Option<usize>,
    /// `true` returns the attachment as base64 whatever it is, never cut at `max_chars` and with
    /// nothing left out or escaped. It can hold hidden text, so read a text attachment without it.
    /// A text attachment comes as its text in UTF-8, which differs from the file as sent when it
    /// was sent in another charset.
    #[serde(default)]
    pub base64: bool,
}

/// How the content block carries the attachment.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Encoding {
    Image,
    Text,
    Base64,
}

/// The details block of a download.
#[derive(Debug, Serialize)]
struct DownloadedAttachment {
    #[serde(flatten)]
    attachment: AttachmentInfo,
    encoding: Encoding,
    truncated: bool,
}

/// The attachment id in `value`: a whole number from 1, as a JSON number or
/// a string of decimal digits.
fn attachment_number(value: &Value) -> Option<u32> {
    let number = match value {
        Value::Number(number) => u32::try_from(number.as_u64()?).ok()?,
        Value::String(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => {
            text.parse().ok()?
        }
        _ => return None,
    };
    (number >= 1).then_some(number)
}

/// The MIME type of an image the model can read, by its signature. The
/// declared type is not trusted.
fn image_type(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(&b"WEBP"[..]) {
        Some("image/webp")
    } else {
        None
    }
}

/// The attachment's `bytes` as `params` ask for them: how the content block carries them, whether
/// it was cut, and the block. With `base64`, the bytes as base64, whatever they are. Otherwise an
/// image the model can read ([`image_type`]) as image content, UTF-8 text as `get_message` gives a
/// plain-text body ([`visible`], which leaves out what mail apps draw as nothing and escapes
/// controls) cut at `max_chars`, and anything else as base64.
fn content_of(bytes: Vec<u8>, params: &DownloadAttachmentParams) -> (Encoding, bool, ContentBlock) {
    if params.base64 {
        return (
            Encoding::Base64,
            false,
            ContentBlock::text(STANDARD.encode(bytes)),
        );
    }
    let max_chars = params
        .max_chars
        .unwrap_or(DEFAULT_MAX_CHARS)
        .clamp(100, MAX_MAX_CHARS);
    match image_type(&bytes) {
        Some(mime_type) => (
            Encoding::Image,
            false,
            ContentBlock::image(STANDARD.encode(&bytes), mime_type),
        ),
        None => match String::from_utf8(bytes) {
            Ok(content) => {
                let (content, truncated) = text::truncate_chars(visible(&content), max_chars);
                (Encoding::Text, truncated, ContentBlock::text(content))
            }
            Err(err) => (
                Encoding::Base64,
                false,
                ContentBlock::text(STANDARD.encode(err.into_bytes())),
            ),
        },
    }
}

impl MailTools {
    /// Downloads one attachment. The mailbox opens before the arguments are
    /// checked, so mailbox errors come first, as for every mail tool.
    pub(super) async fn download(
        &self,
        parts: &Parts,
        params: DownloadAttachmentParams,
    ) -> Result<CallToolResult, String> {
        let mailbox = self.mailbox(parts).await?;
        let number =
            attachment_number(&params.attachment_id).ok_or_else(|| BAD_ATTACHMENT_ID.to_owned())?;
        let selector = Selector {
            id: Some(params.id.clone()),
            ..Selector::default()
        };
        let data = mailbox
            .attachment(&selector, number, MAX_ATTACHMENT_BYTES)
            .await
            .map_err(mailbox_error)?
            .ok_or_else(|| {
                format!(
                    "This message has no attachment {number}. get_message lists its attachments and their ids."
                )
            })?;
        let Some(bytes) = data.content else {
            return Err(if data.decoded {
                format!(
                    "Attachment {number} is {} bytes; download_attachment returns attachments of at most {MAX_ATTACHMENT_BYTES} bytes ({MAX_ATTACHMENT_MIB} MiB). Use send_message with forward to send this file on.",
                    data.attachment.size
                )
            } else {
                format!(
                    "Attachment {number} did not decode cleanly (its base64 or quoted-printable is broken or cut off, its transfer encoding is unknown, its transfer encoding or charset is written in a way mail apps may read differently, its text is in a charset mail apps may convert otherwise, it is a file whose bytes changed when read as text, or a mail app may read the message's parts differently before its end), so download_attachment doesn't return it: its bytes may differ from what the person's mail app opens."
                )
            });
        };
        let (encoding, truncated, content) = content_of(bytes, &params);
        let details = serde_json::to_string(&DownloadedAttachment {
            attachment: data.attachment.into(),
            encoding,
            truncated,
        })
        .map_err(|err| err.to_string())?;
        Ok(CallToolResult::success(vec![
            ContentBlock::text(details),
            content,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn file(value: Value) -> NewAttachment {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn the_line_that_uploads_went_stays_last() {
        let held = with_files(&format!("Not sent.\n{WENT}"), " Hold used.");
        let error = with_files(&held, "\nAttachments in this message: a.pdf.");
        let lines = "Not sent. Hold used.\nAttachments in this message: a.pdf.\n";
        assert_eq!(error, format!("{lines}{WENT}"));
        assert_eq!(
            with_files("Not sent.", " Hold used."),
            "Not sent. Hold used."
        );
    }

    #[test]
    fn outgoing_files_decode_without_guessing_a_type_from_the_name() {
        for (value, name, kind, bytes) in [
            (
                json!({"filename":"faktúra.pdf", "content":"+/8="}),
                "faktúra.pdf",
                "application/octet-stream",
                &b"\xfb\xff"[..],
            ),
            (
                json!({"filename":"my notes", "text":"été\n"}),
                "my notes",
                "text/plain; charset=utf-8",
                "été\n".as_bytes(),
            ),
            (
                json!({"filename":"data", "content":"", "content_type":"text/csv; charset=iso-8859-1"}),
                "data",
                "text/csv; charset=iso-8859-1",
                &b""[..],
            ),
            (
                json!({"filename":"data", "text":"a", "content_type":"application/json"}),
                "data",
                "application/json; charset=utf-8",
                &b"a"[..],
            ),
            (
                json!({"filename":"a..b", "text":"x", "content_type":"text/plain; CHARSET=\"UTF-8\""}),
                "a..b",
                "text/plain; CHARSET=\"UTF-8\"",
                &b"x"[..],
            ),
        ] {
            let file = split(vec![file(value)]).0.remove(0);
            assert_eq!(
                (
                    file.filename.as_str(),
                    file.content_type.as_str(),
                    file.content.as_slice()
                ),
                (name, kind, bytes)
            );
        }
    }

    #[test]
    fn invalid_outgoing_files_name_the_file_in_the_error() {
        for name in [
            "",
            "a/b",
            "a\\b",
            ".",
            "..",
            "a\n",
            "a\u{202e}",
            "a\u{200b}",
            "=?utf-8?q?invoice=E2=80=AEfdp.exe?=",
            &"é".repeat(128),
        ] {
            let err = serde_json::from_value::<NewAttachment>(json!({"filename":name, "text":""}))
                .unwrap_err();
            assert!(
                err.to_string().contains(&format!("attachment {name:?}:")),
                "{err}"
            );
        }
        for (extra, why) in [
            (json!({"content":"YQ==\n"}), "not base64"),
            (json!({"content":"YQ"}), "not base64"),
            (json!({"content":"-_8="}), "not base64"),
            (json!({"content":"YR=="}), "not base64"),
            (json!({"content":"", "text":""}), "exactly one"),
            (json!({}), "exactly one"),
            (
                json!({"text":"", "content_type":"not a type"}),
                "invalid content_type",
            ),
            (
                json!({"text":"", "content_type":"text/"}),
                "invalid content_type",
            ),
            (
                json!({"text":"", "content_type":"text/plain; name=x"}),
                "only a charset",
            ),
            (
                json!({"text":"", "content_type":"text/pläin"}),
                "printable ASCII",
            ),
            (
                json!({"text":"", "content_type":"text/plain\t"}),
                "printable ASCII",
            ),
            (
                json!({"content":"", "content_type":"application/pdf; charset=\"x; name=payload.exe\""}),
                "charset must be a nonempty MIME token",
            ),
            (
                json!({"text":"", "content_type":"multipart/mixed"}),
                "multipart",
            ),
            (
                json!({"text":"", "content_type":"text/plain; charset=iso-8859-1"}),
                "charset=utf-8",
            ),
        ] {
            let mut extra = extra;
            extra["filename"] = json!("sample");
            let err = serde_json::from_value::<NewAttachment>(extra)
                .unwrap_err()
                .to_string();
            assert!(
                err.starts_with("attachment \"sample\":") && err.contains(why),
                "{err}"
            );
        }
        let invalid_message = json!({
            "filename": "original.eml", "content_type": "message/rfc822",
            "text": "Subject: old mail\n\nBody\n"
        });
        let err = serde_json::from_value::<NewAttachment>(invalid_message)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("attachment \"original.eml\": 7bit or 8bit needs CRLF"),
            "{err}"
        );

        for malformed in [
            json!({"filename":"sample", "text":"", "path":"placeholder-value"}),
            json!({"filename":"sample", "text":"", "url":"placeholder-value"}),
            json!("placeholder-value"),
        ] {
            let err = serde_json::from_value::<super::super::SendParams>(json!({
                "to": ["x@example.com"], "subject": "s", "body": "b",
                "attachments": [{"filename":"first", "text":""}, malformed]
            }))
            .unwrap_err()
            .to_string();
            assert!(err.starts_with("attachment 2:"), "{err}");
            assert!(!err.contains("placeholder-value"), "{err}");
        }
    }

    #[test]
    fn upload_items_follow_the_rules_of_every_item() {
        for (item, why) in [
            (
                json!({"filename":"a", "upload_id":"u", "content":""}),
                "exactly one",
            ),
            (
                json!({"filename":"a", "upload_id":"u", "text":""}),
                "exactly one",
            ),
            (
                json!({"filename":"a", "upload_id":"u", "content_type":"text/"}),
                "invalid content_type",
            ),
            (
                json!({"filename":"a/b", "upload_id":"u"}),
                "attachment \"a/b\":",
            ),
            (json!({"upload_id":"u"}), "filename"),
        ] {
            let err = serde_json::from_value::<NewAttachment>(item)
                .unwrap_err()
                .to_string();
            assert!(err.contains(why), "{err}");
        }
    }

    #[test]
    fn attachment_count_is_checked_before_inspecting_items() {
        let parse = |file, count| {
            serde_json::from_value::<super::super::SendParams>(json!({
                "to": ["x@example.com"], "subject": "s", "body": "b",
                "attachments": vec![file; count]
            }))
        };
        let valid = json!({"filename":"sample", "text":""});
        assert_eq!(
            parse(valid, MAX_ATTACHMENTS).unwrap().attachments.len(),
            MAX_ATTACHMENTS
        );
        let err = parse(Value::Null, MAX_ATTACHMENTS + 1)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(&format!("at most {MAX_ATTACHMENTS} attachments")),
            "{err}"
        );
    }

    #[test]
    fn outgoing_files_only_put_metadata_and_a_digest_in_holds() {
        let input = |name, text| json!({"filename":name, "text":text});
        let a = file(input("note", "abc"));
        let digest = serde_json::to_value(&a).unwrap();
        assert_eq!(
            format!("{a:?}"),
            "NewAttachment { filename: \"note\", size: 3 }"
        );
        assert_eq!(
            digest,
            json!({
                "filename":"note", "content_type":"text/plain; charset=utf-8", "size":3,
                "sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            })
        );
        let equivalent = file(
            json!({"filename":"note", "content":"YWJj", "content_type":"text/plain; charset=utf-8"}),
        );
        assert_eq!(serde_json::to_value(equivalent).unwrap(), digest);
        for different in [
            input("note", "abd"),
            input("note.txt", "abc"),
            json!({"filename":"note", "text":"abc", "content_type":"text/csv"}),
        ] {
            assert_ne!(serde_json::to_value(file(different)).unwrap(), digest);
        }
        let params: super::super::SendParams = serde_json::from_value(
            json!({"to":["x@example.com"], "subject":"s", "body":"b", "attachments":[]}),
        )
        .unwrap();
        assert!(
            serde_json::to_value(params)
                .unwrap()
                .get("attachments")
                .is_none()
        );
    }

    /// `ascii` as tag characters, the invisible twin of each character.
    fn tags(ascii: &str) -> String {
        ascii
            .chars()
            .map(|c| char::from_u32(0xE0000 + u32::from(c)).unwrap())
            .collect()
    }

    /// `download_attachment` arguments as an agent sends them, with `extra` added.
    fn params(extra: Value) -> DownloadAttachmentParams {
        let Value::Object(extra) = extra else {
            panic!("extra must be an object: {extra}");
        };
        let mut arguments = json!({ "id": "m1", "attachment_id": "1" });
        arguments.as_object_mut().unwrap().extend(extra);
        serde_json::from_value(arguments).unwrap()
    }

    const PNG: &[u8] = b"\x89PNG\r\n\x1a\nrest";

    #[test]
    fn text_reads_as_get_message_reads_a_plain_text_body() {
        let england = "\u{1F3F4}\u{E0067}\u{E0062}\u{E0065}\u{E006E}\u{E0067}\u{E007F}";
        let kept = format!(
            "caf\u{E9},1\r\n\tx\u{C}y \u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} {england} \u{5E9}\u{5DC}\u{5D5}\u{5DD}"
        );
        for (sent, max_chars, expected, truncated) in [
            (
                format!("Hi{}", tags("see the note")),
                20000,
                "Hi".to_owned(),
                false,
            ),
            (
                "\u{FEFF}name,ad\u{200B}min\r\n".to_owned(),
                20000,
                "name,admin\r\n".to_owned(),
                false,
            ),
            (
                "a\u{202E}b\u{2066}c\u{7}d\u{0}".to_owned(),
                20000,
                "a\\u{202e}b\\u{2066}c\\u{7}d\\u{0}".to_owned(),
                false,
            ),
            (kept.clone(), 20000, kept, false),
            (
                tags("x").repeat(200) + &"a".repeat(150),
                100,
                "a".repeat(100),
                true,
            ),
            (
                "a".repeat(100) + &tags("x").repeat(50),
                100,
                "a".repeat(100),
                false,
            ),
            (
                "\u{202E}".repeat(20),
                100,
                "\\u{202e}".repeat(20).chars().take(100).collect(),
                true,
            ),
        ] {
            assert_eq!(
                content_of(
                    sent.clone().into_bytes(),
                    &params(json!({ "max_chars": max_chars }))
                ),
                (Encoding::Text, truncated, ContentBlock::text(expected)),
                "{sent:?}"
            );
        }
    }

    #[test]
    fn base64_returns_any_attachment_unfiltered() {
        let asked = params(json!({ "base64": true, "max_chars": 100 }));
        for bytes in [
            PNG.to_vec(),
            format!("Hi{}\u{202E}", tags("see the note")).into_bytes(),
            "a".repeat(500).into_bytes(),
            vec![0xFF, 0xFE, 0x00],
        ] {
            assert_eq!(
                content_of(bytes.clone(), &asked),
                (
                    Encoding::Base64,
                    false,
                    ContentBlock::text(STANDARD.encode(&bytes))
                ),
                "{bytes:?}"
            );
        }
        assert_eq!(
            content_of(PNG.to_vec(), &params(json!({}))),
            (
                Encoding::Image,
                false,
                ContentBlock::image(STANDARD.encode(PNG), "image/png")
            )
        );
        assert_eq!(
            content_of(vec![0xFF, 0xFE, 0x00], &params(json!({}))),
            (Encoding::Base64, false, ContentBlock::text("//4A"))
        );
    }

    #[test]
    fn base64_is_off_unless_asked() {
        assert!(!params(json!({})).base64);
        assert!(params(json!({ "base64": true })).base64);
        assert!(!params(json!({ "base64": false })).base64);
        assert!(
            serde_json::from_value::<DownloadAttachmentParams>(
                json!({ "id": "m1", "attachment_id": "1", "base64": "true" })
            )
            .is_err()
        );
    }

    #[test]
    fn attachment_ids_are_whole_numbers_from_one() {
        for (value, expected) in [
            (json!("1"), Some(1)),
            (json!(1), Some(1)),
            (json!("4294967295"), Some(u32::MAX)),
            (json!(0), None),
            (json!("0"), None),
            (json!(-1), None),
            (json!(1.5), None),
            (json!(4_294_967_296_u64), None),
            (json!("4294967296"), None),
            (json!(""), None),
            (json!("x"), None),
            (json!("+1"), None),
            (json!(" 1"), None),
            (Value::Null, None),
        ] {
            assert_eq!(attachment_number(&value), expected, "{value}");
        }
    }

    #[test]
    fn images_are_known_by_their_signature() {
        for (bytes, expected) in [
            (&b"\x89PNG\r\n\x1a\nrest"[..], Some("image/png")),
            (b"\xFF\xD8\xFF\xE0", Some("image/jpeg")),
            (b"GIF87a..", Some("image/gif")),
            (b"GIF89a..", Some("image/gif")),
            (b"RIFF\0\0\0\0WEBPVP8 ", Some("image/webp")),
            (b"RIFF\0\0\0\0WAVE", None),
            (b"RIFF", None),
            (b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>", None),
            (b"II*\0", None),
            (b"", None),
        ] {
            assert_eq!(image_type(bytes), expected, "{bytes:?}");
        }
    }
}
