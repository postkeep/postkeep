//! Server configuration, defaulting to iCloud Mail.

use std::time::Duration;

/// iCloud IMAP host.
pub const ICLOUD_IMAP_HOST: &str = "imap.mail.me.com";
/// iCloud IMAP port (implicit TLS).
pub const ICLOUD_IMAP_PORT: u16 = 993;
/// iCloud SMTP host.
pub const ICLOUD_SMTP_HOST: &str = "smtp.mail.me.com";
/// iCloud SMTP submission port (STARTTLS).
pub const ICLOUD_SMTP_PORT: u16 = 587;

/// Default timeout applied to every network operation.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Transport security for the IMAP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ImapSecurity {
    /// TLS from the first byte (port 993). Used by iCloud.
    #[default]
    Tls,
    /// No encryption at all. Only for local test servers.
    Plaintext,
}

/// Transport security for the SMTP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SmtpSecurity {
    /// TLS from the first byte (usually port 465).
    Tls,
    /// Plain connection upgraded with a mandatory `STARTTLS` (port 587). Used by iCloud.
    #[default]
    StartTls,
    /// No encryption at all. Only for local test servers.
    Plaintext,
}

/// IMAP server address and security mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImapConfig {
    /// Host name, also used for TLS certificate verification.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Transport security.
    pub security: ImapSecurity,
}

impl Default for ImapConfig {
    fn default() -> Self {
        Self {
            host: ICLOUD_IMAP_HOST.to_owned(),
            port: ICLOUD_IMAP_PORT,
            security: ImapSecurity::Tls,
        }
    }
}

/// SMTP server address and security mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpConfig {
    /// Host name, also used for TLS certificate verification.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Transport security.
    pub security: SmtpSecurity,
}

impl Default for SmtpConfig {
    fn default() -> Self {
        Self {
            host: ICLOUD_SMTP_HOST.to_owned(),
            port: ICLOUD_SMTP_PORT,
            security: SmtpSecurity::StartTls,
        }
    }
}

/// Complete client configuration.
///
/// [`MailConfig::default`] targets iCloud Mail; override fields to point at
/// another server (for example a local test server).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailConfig {
    /// IMAP server.
    pub imap: ImapConfig,
    /// SMTP server.
    pub smtp: SmtpConfig,
    /// Timeout for connecting, logging in and mail operations. IMAP searches
    /// get separate budgets for listing candidates and reading each fetch set.
    pub timeout: Duration,
    /// Explicit Sent folder name. When `None`, the folder is detected from
    /// the server's special-use attributes or common names.
    pub sent_folder: Option<String>,
    /// Explicit Trash folder name. When `None`, the folder is detected from
    /// the server's special-use attributes or common names.
    pub trash_folder: Option<String>,
    /// Explicit Drafts folder name. When `None`, the folder is detected
    /// from the server's special-use attributes or common names.
    pub drafts_folder: Option<String>,
    /// Whether the server files mail submitted over SMTP in the Sent folder
    /// itself, as Gmail does. Then [`MailClient::send`](crate::MailClient::send)
    /// and [`MailClient::reply`](crate::MailClient::reply) never append a
    /// copy, even when
    /// [`SendOptions::save_to_sent`](crate::SendOptions::save_to_sent) is
    /// `true`: the check for the server's copy could run before it appears,
    /// and appending one as well could double it. They report
    /// [`SentCopy::ByServer`](crate::SentCopy::ByServer) instead. The default
    /// is `false`: `save_to_sent` decides.
    pub server_files_sent: bool,
    /// Whether a permanent delete
    /// ([`DeleteMode::Permanent`](crate::DeleteMode::Permanent)) is allowed.
    /// Set it to `false` for a server where `\Deleted` and `EXPUNGE` only take
    /// a message out of the folder it is in, as Gmail does (the message stays
    /// in All Mail): nothing is deleted then.
    /// [`ImapSession::delete_message`](crate::ImapSession::delete_message)
    /// refuses with [`Error::InvalidInput`](crate::Error::InvalidInput)
    /// before it sends anything, and still moves a message to Trash. The
    /// default is `true`.
    pub permanent_delete: bool,
}

impl Default for MailConfig {
    fn default() -> Self {
        Self {
            imap: ImapConfig::default(),
            smtp: SmtpConfig::default(),
            timeout: DEFAULT_TIMEOUT,
            sent_folder: None,
            trash_folder: None,
            drafts_folder: None,
            server_files_sent: false,
            permanent_delete: true,
        }
    }
}
