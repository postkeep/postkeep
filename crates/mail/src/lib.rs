//! Async IMAP and SMTP mail client, with presets for iCloud Mail, Fastmail,
//! Yahoo Mail and Gmail.
//!
//! This crate is the mail layer of [postkeep], an MCP server that lets agents
//! read and answer mail. It can also be used on its own.
//!
//! * IMAP via `async-imap` over TLS with `rustls` (no OpenSSL).
//! * SMTP via `lettre`, over TLS or with mandatory `STARTTLS`.
//! * Credentials are kept in [`SecretString`] and are never logged.
//! * Defaults target iCloud; every host, port and TLS mode can be changed,
//!   for example to test against a local server.
//!
//! ```no_run
//! use postkeep_mail::{Credentials, MailClient, MailConfig, Paging, SearchQuery, SecretString};
//!
//! # async fn run() -> postkeep_mail::Result<()> {
//! let password = SecretString::from("abcd-efgh-ijkl-mnop".to_owned());
//! let credentials = Credentials::new("alice@example.com", &password)?;
//! let client = MailClient::new(MailConfig::default(), credentials)?;
//!
//! let mut imap = client.connect_imap().await?;
//! let unread = imap
//!     .search("INBOX", &SearchQuery::new().unread(true), Paging::default())
//!     .await?;
//! for summary in &unread.messages {
//!     let _subject = summary.subject.as_deref().unwrap_or("(no subject)");
//! }
//! imap.logout().await?;
//! # Ok(())
//! # }
//! ```
//!
//! [postkeep]: https://github.com/postkeep/postkeep

mod client;
mod config;
mod credentials;
mod error;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
mod imap;
pub mod invisible;
mod message;
pub mod mime;
mod outgoing;
mod parse;
mod presets;
mod query;
mod smtp;
mod tls;
mod utf7;

/// Maximum raw MIME size in bytes for a full-message IMAP read (48 MiB).
pub const IMAP_MESSAGE_LIMIT: usize = 48 * 1024 * 1024;

pub use chrono::NaiveDate;
pub use secrecy::SecretString;

pub use client::{MailClient, SavedDraft, SendOptions, SentCopy, SentMessage};
pub use config::{
    DEFAULT_TIMEOUT, ICLOUD_IMAP_HOST, ICLOUD_IMAP_PORT, ICLOUD_SMTP_HOST, ICLOUD_SMTP_PORT,
    ImapConfig, ImapSecurity, MailConfig, SmtpConfig, SmtpSecurity,
};
pub use credentials::{Credentials, normalize_app_password};
pub use error::{Error, ProtocolErrorKind, Result};
pub use imap::{
    Changed, Check, DeleteMode, Folder, FolderState, IdleEvent, ImapSession, InFlight,
    MessageBatch, NewMessage, Progress, SpecialUse, UID_SET_MAX, already_in_trash, same_folder,
};
pub use message::{
    Attachment, AttachmentData, BodyPart, EmailAddress, Flag, Message, MessageFlags,
    MessageHeaders, MessageSummary, Paging, SearchResults, SentFile, Uid,
};
pub use outgoing::{OutgoingAttachment, OutgoingMessage, Reply};
pub use presets::{ImapPreset, ImapServer, ImapServerId, ImapServers};
pub use query::{SearchQuery, holds, holds_addresses};
