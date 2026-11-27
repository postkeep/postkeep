//! The crate-wide error type.

use crate::Uid;

/// Convenient result alias used throughout this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Classification of a failure reported by an IMAP or SMTP operation.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolErrorKind {
    /// The command was definitively rejected.
    Rejected,
    /// The server rejected a message for exceeding its size limit.
    TooLarge,
    /// The operation timed out.
    Timeout,
    /// A server or connection failure that may pass.
    Transient,
}

/// Errors returned by this crate.
///
/// Error values never contain credentials or message bodies, so they are safe
/// to log or to return to an MCP client.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The server rejected the email address or app-specific password.
    ///
    /// That is the answer to a login that shows no sign of a passing cause:
    /// an IMAP `NO` without a temporary response code, or SMTP reply 535.
    /// A server may send a `NO` without a code for a passing refusal too
    /// (RFC 5530, section 3), so a caller that gives up on the account, as
    /// the new-mail watcher does, should wait for several in a row. A
    /// refusal that says it may pass is [`Error::Unavailable`].
    #[error("authentication failed: check the email address and password")]
    Authentication,

    /// The server refused for a reason that may pass, and not because of the
    /// password. At an IMAP login: part of the server is down, it reached a
    /// limit such as too many connections, or it hit a bug of its own. In
    /// SMTP: reply 454, a temporary server failure, whichever command got it.
    /// The same request can work later. The message holds the code only, never
    /// the server's text, which can name the user.
    #[error("the mail server refused for now ({code}); try again later")]
    Unavailable {
        /// The IMAP response code (RFC 5530) or SMTP reply code (RFC 4954,
        /// RFC 3207) that said so.
        code: &'static str,
    },

    /// A caller-supplied value was rejected before anything was sent to the server.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The requested folder does not exist or could not be identified.
    #[error("folder not found: {0}")]
    FolderNotFound(String),

    /// No message with the given UID exists in the folder.
    #[error("message with UID {uid} not found in folder {folder:?}")]
    MessageNotFound {
        /// Folder that was searched.
        folder: String,
        /// UID that was requested.
        uid: Uid,
    },

    /// The message is larger than the caller's read limit.
    #[error("the message exceeds the read limit")]
    MessageTooLarge,

    /// The folder's UIDVALIDITY is not the one the caller expected: the
    /// server renumbered the folder since the message id was made, so the
    /// UID could name another message now. Nothing was changed.
    #[error(
        "the message id is out of date: the mail server renumbered folder {folder:?} since the \
         id was made, so it could name another message now; search the folder again for a \
         current id"
    )]
    StaleId {
        /// Folder whose UIDVALIDITY changed.
        folder: String,
    },

    /// The server lacks a capability required for the operation.
    #[error("server does not support {0}")]
    Unsupported(&'static str),

    /// The operation did not complete within the configured timeout.
    #[error("operation timed out")]
    Timeout,

    /// The search ran out of time between two commands.
    #[error("the search ran out of time between two commands")]
    TimeExhausted,

    /// SMTP submission started sending DATA, but the server did not confirm the outcome.
    #[error("SMTP submission was not confirmed")]
    SubmissionUnconfirmed,

    /// An IMAP change started but the server did not confirm its outcome.
    #[error("the mail server did not confirm the change")]
    WriteUnconfirmed,

    /// A network-level failure.
    #[error("network error: {0}")]
    Io(#[from] std::io::Error),

    /// A TLS configuration or handshake failure.
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    /// The IMAP server returned an error or an unexpected response.
    #[error("IMAP error: {0}")]
    Imap(#[from] async_imap::error::Error),

    /// The SMTP server returned an error.
    #[error("SMTP error: {0}")]
    Smtp(#[from] lettre::transport::smtp::Error),

    /// An outgoing message could not be assembled.
    #[error("could not build message: {0}")]
    Build(#[from] lettre::error::Error),

    /// A fetched message could not be parsed.
    #[error("could not parse message with UID {0}")]
    Parse(Uid),
}

impl Error {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidInput(message.into())
    }

    /// Classifies an IMAP or SMTP error, or returns `None` for other errors.
    #[must_use]
    pub fn protocol_error_kind(&self) -> Option<ProtocolErrorKind> {
        use async_imap::error::Error as ImapError;
        Some(match self {
            Self::Imap(ImapError::No(_) | ImapError::Bad(_) | ImapError::Validate(_)) => {
                ProtocolErrorKind::Rejected
            }
            Self::Smtp(err) if err.is_timeout() => ProtocolErrorKind::Timeout,
            Self::Smtp(err) if err.status().is_some_and(|code| code.to_string() == "552") => {
                ProtocolErrorKind::TooLarge
            }
            Self::Smtp(err) if err.is_permanent() || err.is_client() => ProtocolErrorKind::Rejected,
            Self::Imap(_) | Self::Smtp(_) => ProtocolErrorKind::Transient,
            _ => return None,
        })
    }

    /// Whether the IMAP session that produced this error is still in a
    /// known-good state and may be reused: the request was refused (bad
    /// input, missing folder or message, a `NO` answer) or stopped between
    /// commands, rather than losing or desynchronizing the connection.
    #[must_use]
    pub const fn leaves_session_usable(&self) -> bool {
        matches!(
            self,
            Self::InvalidInput(_)
                | Self::FolderNotFound(_)
                | Self::MessageNotFound { .. }
                | Self::MessageTooLarge
                | Self::StaleId { .. }
                | Self::Unsupported(_)
                | Self::TimeExhausted
                | Self::Parse(_)
                | Self::Imap(async_imap::error::Error::No(_))
        )
    }
}
