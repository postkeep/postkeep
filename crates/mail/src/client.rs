//! The high-level client tying IMAP and SMTP together.

use std::fmt;
use std::sync::Arc;

use tokio_rustls::TlsConnector;

use crate::outgoing::{self, Threading};
use crate::{
    Credentials, EmailAddress, Flag, ImapSession, MailConfig, OutgoingMessage, Reply, Result, Uid,
    mime, smtp, tls,
};

/// Entry point of the crate: an iCloud (or other IMAP/SMTP) account.
///
/// The client is cheap to clone and holds no open connections. IMAP work
/// happens on an [`ImapSession`] from [`MailClient::connect_imap`]; sending
/// opens a short-lived SMTP connection per message.
#[derive(Clone)]
pub struct MailClient {
    config: Arc<MailConfig>,
    credentials: Credentials,
    display_name: Option<String>,
    tls: TlsConnector,
}

impl fmt::Debug for MailClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MailClient")
            .field("config", &self.config)
            .field("credentials", &self.credentials)
            .field("display_name", &self.display_name)
            .finish_non_exhaustive()
    }
}

/// Options for [`MailClient::send`] and [`MailClient::reply`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOptions {
    /// Append a copy of the sent message to the Sent folder over IMAP,
    /// skipping it if the server already stored one. Defaults to `true`
    /// because iCloud does not reliably store SMTP-submitted mail itself.
    /// Ignored when [`MailConfig::server_files_sent`] is set.
    pub save_to_sent: bool,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self { save_to_sent: true }
    }
}

/// Outcome of a successful send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    /// `Message-ID` of the sent message, without angle brackets.
    pub message_id: String,
    /// What happened with the copy in the Sent folder.
    pub sent_copy: SentCopy,
}

/// What happened with the Sent folder copy of a sent message.
///
/// The message itself has always been delivered to the SMTP server when this
/// value is returned, even for [`SentCopy::Failed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SentCopy {
    /// No copy was requested.
    NotRequested,
    /// A copy was appended to `folder`.
    Saved {
        /// The Sent folder.
        folder: String,
    },
    /// `folder` already contained the message (the server stored it).
    AlreadyPresent {
        /// The Sent folder.
        folder: String,
    },
    /// The server files sent mail itself
    /// ([`MailConfig::server_files_sent`]), so no copy was appended,
    /// whatever [`SendOptions::save_to_sent`] says.
    ByServer,
    /// Saving the copy failed.
    Failed {
        /// Description of the failure.
        reason: String,
    },
}

impl From<Result<Self>> for SentCopy {
    fn from(result: Result<Self>) -> Self {
        result.unwrap_or_else(|err| {
            // A provider's APPEND error can echo private parts of the message.
            tracing::warn!("message sent but saving the Sent copy failed");
            Self::Failed {
                reason: err.to_string(),
            }
        })
    }
}

/// A draft saved by [`MailClient::save_draft`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SavedDraft {
    /// `Message-ID` of the draft, without angle brackets.
    pub message_id: String,
    /// The Drafts folder the draft was appended to.
    pub folder: String,
    /// `(UIDVALIDITY, UID)` reported by RFC 4315 `APPENDUID`, when both are nonzero.
    pub append_uid: Option<(u32, Uid)>,
}

impl MailClient {
    /// Creates a client for the given server configuration and account.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tls`](crate::Error::Tls) if the TLS configuration
    /// cannot be built.
    pub fn new(config: MailConfig, credentials: Credentials) -> Result<Self> {
        Ok(Self {
            config: Arc::new(config),
            credentials,
            display_name: None,
            tls: tls::connector()?,
        })
    }

    /// Sets the display name used in the `From` header of sent messages.
    #[must_use]
    pub fn with_display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// The configuration this client uses.
    #[must_use]
    pub fn config(&self) -> &MailConfig {
        &self.config
    }

    /// The account credentials.
    #[must_use]
    pub const fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    /// Checks the credentials by logging in to IMAP and logging out again.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Authentication`](crate::Error::Authentication) if the
    /// server rejects the credentials, [`Error::Unavailable`](crate::Error::Unavailable)
    /// if it declines the login for now, or a network error.
    pub async fn verify_credentials(&self) -> Result<()> {
        self.connect_imap().await?.logout().await
    }

    /// Opens an authenticated IMAP session.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Authentication`](crate::Error::Authentication) if the
    /// server rejects the credentials, [`Error::Unavailable`](crate::Error::Unavailable)
    /// if it declines the login for now, [`Error::Timeout`](crate::Error::Timeout),
    /// or a network error.
    pub async fn connect_imap(&self) -> Result<ImapSession> {
        ImapSession::connect(&self.config, &self.credentials, &self.tls).await
    }

    /// Sends a new message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`](crate::Error::InvalidInput) for
    /// invalid addresses or headers, or an SMTP error. Returns
    /// [`Error::SubmissionUnconfirmed`](crate::Error::SubmissionUnconfirmed) when
    /// the server may have accepted the message but did not confirm it. Failing to
    /// save the Sent copy is reported in [`SentMessage::sent_copy`], not as an error.
    pub async fn send(
        &self,
        message: &OutgoingMessage,
        options: SendOptions,
    ) -> Result<SentMessage> {
        let (message_id, raw) = self.submit(message, None).await?;
        let sent_copy = if self.config.server_files_sent {
            SentCopy::ByServer
        } else if options.save_to_sent {
            self.save_sent_copy(&message_id, &raw).await.into()
        } else {
            SentCopy::NotRequested
        };
        Ok(SentMessage {
            message_id,
            sent_copy,
        })
    }

    /// Replies to the message `uid` in `folder`.
    ///
    /// Recipients, the `Re:` subject and the `In-Reply-To` / `References`
    /// headers are derived from the original, which is then marked as
    /// answered. With `uid_validity` set, the folder's UIDVALIDITY must
    /// equal it, or nothing is sent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleId`](crate::Error::StaleId) if the UIDVALIDITY
    /// differs, [`Error::MessageNotFound`](crate::Error::MessageNotFound) if
    /// the original does not exist, [`Error::MessageTooLarge`](crate::Error::MessageTooLarge)
    /// if it exceeds [`crate::IMAP_MESSAGE_LIMIT`], or [`Error::InvalidInput`](crate::Error::InvalidInput)
    /// if the original's addresses do not allow the reply, in the cases that
    /// [`mime::compose_reply`](crate::mime::compose_reply) lists. IMAP or SMTP can also
    /// fail. Returns [`Error::SubmissionUnconfirmed`](crate::Error::SubmissionUnconfirmed)
    /// when the server may have accepted the reply but did not confirm it.
    pub async fn reply(
        &self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
        reply: &Reply,
        options: SendOptions,
    ) -> Result<SentMessage> {
        let mut session = self.connect_imap().await?;
        let (original, seen) = session.fetch_message(folder, uid, uid_validity).await?;
        let message = outgoing::reply_message(&original.headers, self.credentials.email(), reply)?;
        let threading = Threading::reply_to(&original.headers);
        let (message_id, raw) = self.submit(&message, threading.as_ref()).await?;
        if let Err(err) = session
            .set_flag(folder, uid, seen, Flag::Answered, true)
            .await
        {
            tracing::warn!(error = %err, "reply sent but marking the original as answered failed");
        }
        let sent_copy = if self.config.server_files_sent {
            SentCopy::ByServer
        } else if options.save_to_sent {
            session.save_sent_copy(&message_id, &raw).await.into()
        } else {
            SentCopy::NotRequested
        };
        if let Err(err) = session.logout().await {
            tracing::debug!(error = %err, "IMAP logout failed");
        }
        Ok(SentMessage {
            message_id,
            sent_copy,
        })
    }

    /// Saves `message` as a new draft in the Drafts folder of `session`,
    /// without sending it. The draft keeps its Bcc recipients, as a mail
    /// app's draft does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`](crate::Error::InvalidInput) for a
    /// message without recipients, or invalid addresses or headers,
    /// [`Error::FolderNotFound`](crate::Error::FolderNotFound) if no Drafts
    /// folder can be identified, or an IMAP error. Returns
    /// [`Error::WriteUnconfirmed`](crate::Error::WriteUnconfirmed) if the draft was transmitted but its save
    /// was not confirmed; check Drafts before trying again.
    pub async fn save_draft(
        &self,
        session: &mut ImapSession,
        message: &OutgoingMessage,
    ) -> Result<SavedDraft> {
        session
            .save_draft(mime::compose(&self.from(), message)?)
            .await
    }

    /// Saves a reply to the message `uid` in `folder` as a draft, with the
    /// recipients and threading headers [`MailClient::reply`] would use. The
    /// original is not marked as answered, as nothing is sent.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`MailClient::reply`] that precede sending, or
    /// those of [`MailClient::save_draft`].
    pub async fn save_draft_reply(
        &self,
        session: &mut ImapSession,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
        reply: &Reply,
    ) -> Result<SavedDraft> {
        let (original, _) = session.fetch_message(folder, uid, uid_validity).await?;
        let draft = mime::compose_reply(&self.from(), &original.headers, reply)?;
        session.save_draft(draft).await
    }

    fn from(&self) -> EmailAddress {
        EmailAddress {
            name: self.display_name.clone(),
            address: self.credentials.email().to_owned(),
        }
    }

    /// Builds and submits a message, returning its ID and raw bytes.
    async fn submit(
        &self,
        message: &OutgoingMessage,
        threading: Option<&Threading>,
    ) -> Result<(String, Vec<u8>)> {
        let from = self.from();
        let message_id = outgoing::new_message_id(&from);
        let built = outgoing::build(&from, message, &message_id, threading)?;
        let raw = smtp::submit(
            &self.config.smtp,
            &self.credentials,
            self.config.timeout,
            &built,
        )
        .await?;
        Ok((message_id, raw))
    }

    async fn save_sent_copy(&self, message_id: &str, raw: &[u8]) -> Result<SentCopy> {
        let mut session = self.connect_imap().await?;
        let result = session.save_sent_copy(message_id, raw).await;
        if let Err(err) = session.logout().await {
            tracing::debug!(error = %err, "IMAP logout failed");
        }
        result
    }
}
