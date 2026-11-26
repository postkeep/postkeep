//! IMAP sessions.

mod folders;
mod messages;
mod search;
mod watch;

use std::time::{Duration, Instant};

use async_imap::types::Capabilities;
use secrecy::ExposeSecret;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

pub use folders::{Folder, SpecialUse, same_folder};
pub use messages::{Changed, Check, DeleteMode, InFlight, Progress, already_in_trash};
pub use search::UID_SET_MAX;
pub use watch::{FolderState, IdleEvent, MessageBatch, NewMessage};

use crate::mime::Composed;
use crate::query::Literals;
use crate::tls::{self, MaybeTlsStream};
use crate::{
    AttachmentData, Credentials, Error, Flag, ImapSecurity, MailConfig, Message, Paging, Result,
    SavedDraft, SearchQuery, SearchResults, SentCopy, Uid, utf7,
};

/// The underlying async-imap session type.
type Conn = async_imap::Session<MaybeTlsStream>;

/// An authenticated IMAP connection.
///
/// Obtain one with [`MailClient::connect_imap`](crate::MailClient::connect_imap).
/// The configured timeout bounds each operation, except search and matching:
/// their listing and each fetch set have separate timeouts. Call
/// [`ImapSession::logout`] when done to close the connection cleanly.
pub struct ImapSession {
    conn: Conn,
    capabilities: Capabilities,
    timeout: Duration,
    sent_folder: Option<String>,
    trash_folder: Option<String>,
    drafts_folder: Option<String>,
    permanent_delete: bool,
}

impl std::fmt::Debug for ImapSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapSession")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl ImapSession {
    /// Connects, performs the TLS handshake if configured, and logs in.
    pub(crate) async fn connect(
        config: &MailConfig,
        credentials: &Credentials,
        connector: &TlsConnector,
    ) -> Result<Self> {
        let imap = &config.imap;
        with_timeout(config.timeout, async {
            tracing::debug!(host = %imap.host, port = imap.port, "connecting to IMAP server");
            let tcp = TcpStream::connect((imap.host.as_str(), imap.port)).await?;
            let stream = match imap.security {
                ImapSecurity::Tls => tls::handshake(connector, &imap.host, tcp).await?,
                ImapSecurity::Plaintext => MaybeTlsStream::Plain(tcp),
            };
            let mut client = async_imap::Client::new(stream);
            client
                .read_response()
                .await?
                .ok_or(async_imap::error::Error::ConnectionLost)?;
            let mut conn = login(client, credentials).await?;
            let capabilities = conn.capabilities().await?;
            tracing::debug!("IMAP login succeeded");
            Ok(Self {
                conn,
                capabilities,
                timeout: config.timeout,
                sent_folder: config.sent_folder.clone(),
                trash_folder: config.trash_folder.clone(),
                drafts_folder: config.drafts_folder.clone(),
                permanent_delete: config.permanent_delete,
            })
        })
        .await
    }

    /// Lists all folders of the account.
    ///
    /// # Errors
    ///
    /// Returns an error if the server rejects the command or the connection fails.
    pub async fn list_folders(&mut self) -> Result<Vec<Folder>> {
        with_timeout(self.timeout, folders::list(&mut self.conn)).await
    }

    /// Creates a folder. Use the server's hierarchy delimiter (see
    /// [`Folder::delimiter`]) to create nested folders.
    ///
    /// # Errors
    ///
    /// Returns an error if the folder already exists, the name is invalid, or
    /// the connection fails.
    pub async fn create_folder(&mut self, name: &str) -> Result<()> {
        with_timeout(self.timeout, folders::create(&mut self.conn, name)).await
    }

    /// Searches `folder` and returns one page of summaries, newest first: by
    /// the date the summaries show where the server offers `SORT` (RFC 5256)
    /// and the query's text is ASCII, else by arrival.
    ///
    /// Listing candidates and fetching each set use separate mail timeouts.
    /// A header-filtered search starts no more fetches after one mail timeout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for invalid query values,
    /// [`Error::FolderNotFound`] if the folder does not exist,
    /// [`Error::TimeExhausted`] if the search runs out of time between commands,
    /// or a protocol error.
    pub async fn search(
        &mut self,
        folder: &str,
        query: &SearchQuery,
        paging: Paging,
    ) -> Result<SearchResults> {
        // An unrepresentably distant deadline does not limit the walk.
        let until = Instant::now().checked_add(self.timeout);
        search::search(
            &mut self.conn,
            &self.capabilities,
            folder,
            query,
            paging,
            self.timeout,
            until,
        )
        .await
    }

    /// Fetches and parses a complete message without marking it as read,
    /// with the folder's UIDVALIDITY.
    ///
    /// With `uid_validity` set, the folder's UIDVALIDITY must equal it, or
    /// the call fails with [`Error::StaleId`] and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleId`] if the UIDVALIDITY differs,
    /// [`Error::MessageNotFound`] if no message has this UID,
    /// [`Error::MessageTooLarge`] if the raw message exceeds [`crate::IMAP_MESSAGE_LIMIT`],
    /// or a protocol error.
    pub async fn fetch_message(
        &mut self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
    ) -> Result<(Message, Option<u32>)> {
        with_timeout(
            self.timeout,
            messages::fetch(&mut self.conn, folder, uid, uid_validity),
        )
        .await
    }

    /// Fetches a message and returns its attachment `id` (from 1, as in
    /// [`Attachment::id`](crate::Attachment::id)), with its decoded content
    /// when it is at most `max_bytes` long, without marking the message as
    /// read. `None` when the message has no attachment `id`.
    ///
    /// With `uid_validity` set, the folder's UIDVALIDITY must equal it, or
    /// the call fails with [`Error::StaleId`] and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleId`] if the UIDVALIDITY differs,
    /// [`Error::MessageNotFound`] if no message has this UID,
    /// [`Error::MessageTooLarge`] if the raw message exceeds [`crate::IMAP_MESSAGE_LIMIT`],
    /// or a protocol error.
    pub async fn fetch_attachment(
        &mut self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
        id: u32,
        max_bytes: usize,
    ) -> Result<Option<AttachmentData>> {
        with_timeout(
            self.timeout,
            messages::fetch_attachment(&mut self.conn, folder, uid, uid_validity, id, max_bytes),
        )
        .await
    }

    /// Reads a message's `RFC822.SIZE` without fetching its body or marking it read.
    ///
    /// # Errors
    ///
    /// Returns an error if the id is stale, the size is missing, or the server refuses the read.
    pub async fn message_size(
        &mut self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
    ) -> Result<u32> {
        with_timeout(
            self.timeout,
            messages::message_size(&mut self.conn, folder, uid, uid_validity),
        )
        .await
    }

    /// Reads the message's raw MIME without marking it read.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MessageTooLarge`] if the reported or actual size exceeds the smaller
    /// of `max` and [`crate::IMAP_MESSAGE_LIMIT`]. Either read can also fail.
    pub async fn fetch_raw(
        &mut self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
        max: usize,
    ) -> Result<Vec<u8>> {
        with_timeout(
            self.timeout,
            messages::fetch_raw(&mut self.conn, folder, uid, uid_validity, max),
        )
        .await
    }

    /// Lists matching UIDs, newest arrival first, without reading bodies.
    ///
    /// Queries with header criteria return at most `want` matches.
    /// Queries without header criteria return all matching UIDs without fetching.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleId`] if the folder's UIDVALIDITY changed,
    /// [`Error::FolderNotFound`] for a missing folder, [`Error::TimeExhausted`]
    /// if `until` has passed before a header fetch, or a protocol error.
    pub async fn matching(
        &mut self,
        folder: &str,
        query: &SearchQuery,
        uid_validity: u32,
        want: usize,
        until: Instant,
    ) -> Result<Vec<Uid>> {
        let criteria = query.to_imap(Literals::from_capabilities(&self.capabilities))?;
        let mut uids = with_timeout(self.timeout, async {
            select(&mut self.conn, folder, Some(uid_validity)).await?;
            search::matching(&mut self.conn, &criteria).await
        })
        .await?;
        uids.retain(|&uid| query.allows_uid(uid));
        if query.checks_headers() {
            let walk = search::held(
                &mut self.conn,
                &uids,
                query,
                0,
                want,
                self.timeout,
                Some(until),
            )
            .await?;
            Ok(walk.kept.into_iter().map(|summary| summary.uid).collect())
        } else {
            Ok(uids)
        }
    }

    /// Finds requested UIDs without changing messages. `check` identifies which are already as asked.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] for more than [`UID_SET_MAX`] UIDs or
    /// UID zero, [`Error::FolderNotFound`] for a missing folder,
    /// [`Error::StaleId`] for a different UIDVALIDITY, or a protocol error.
    pub async fn find_messages(
        &mut self,
        folder: &str,
        uids: &[Uid],
        uid_validity: Option<u32>,
        check: Check<'_>,
    ) -> Result<Changed> {
        with_timeout(
            self.timeout,
            messages::find_messages(&mut self.conn, folder, uids, uid_validity, check),
        )
        .await
    }

    /// Sets or clears flags on existing UIDs; missing UIDs are reported separately.
    ///
    /// Flags are `(flag, enabled)` pairs, applied in order. At most
    /// [`UID_SET_MAX`] UIDs are accepted, with one timeout for the whole operation.
    /// `check` can skip UIDs already as asked. `progress` records the check and
    /// writes even if that timeout expires.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::find_messages`], or a protocol error.
    pub async fn set_flags(
        &mut self,
        folder: &str,
        uids: &[Uid],
        uid_validity: Option<u32>,
        flags: &[(Flag, bool)],
        check: Check<'_>,
        progress: &mut Option<Progress>,
    ) -> Result<Changed> {
        *progress = None;
        with_timeout(
            self.timeout,
            messages::set_flags(
                &mut self.conn,
                folder,
                uids,
                uid_validity,
                flags,
                check,
                progress,
            ),
        )
        .await
    }

    /// Moves existing UIDs to another folder, reporting missing and new UIDs.
    ///
    /// Uses MOVE if available, else COPY followed by selective expunge where
    /// UIDPLUS is available. Without UIDPLUS, concurrent deletions can still
    /// race a plain EXPUNGE. A failed move must not be retried blindly: search
    /// the destination first, since a copy may have succeeded before the error.
    /// Accepts at most [`UID_SET_MAX`] UIDs, bounded by one operation timeout.
    /// `check` can skip UIDs already as asked. `progress` records the check and
    /// writes even if that timeout expires.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`Self::find_messages`], [`Error::FolderNotFound`]
    /// for a missing destination, [`Error::InvalidInput`] for equal folders or
    /// an overlong command, or [`Error::Unsupported`] if expunge is unsafe.
    pub async fn move_messages(
        &mut self,
        folder: &str,
        uids: &[Uid],
        uid_validity: Option<u32>,
        destination: &str,
        check: Check<'_>,
        progress: &mut Option<Progress>,
    ) -> Result<Changed> {
        *progress = None;
        with_timeout(
            self.timeout,
            messages::move_messages(
                &mut self.conn,
                &self.capabilities,
                folder,
                uids,
                uid_validity,
                destination,
                check,
                progress,
            ),
        )
        .await
    }

    /// Resolves the configured or detected Trash folder, without changing mail.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FolderNotFound`] if no Trash folder is identified,
    /// or a protocol error.
    pub async fn trash_folder(&mut self) -> Result<String> {
        with_timeout(
            self.timeout,
            folders::resolve(
                &mut self.conn,
                SpecialUse::Trash,
                self.trash_folder.as_deref(),
            ),
        )
        .await
    }

    /// Sets (`enabled = true`) or clears a flag on a message, and returns
    /// the folder's UIDVALIDITY.
    ///
    /// With `uid_validity` set, the folder's UIDVALIDITY must equal it, or
    /// the call fails with [`Error::StaleId`] and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleId`] if the UIDVALIDITY differs,
    /// [`Error::MessageNotFound`] if no message has this UID, or a protocol
    /// error.
    pub async fn set_flag(
        &mut self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
        flag: Flag,
        enabled: bool,
    ) -> Result<Option<u32>> {
        let flags = [(flag, enabled)];
        self.set_flags(
            folder,
            &[uid],
            uid_validity,
            &flags,
            Check::Flags(&flags),
            &mut None,
        )
        .await?
        .single(folder, uid)
    }

    /// Moves a message to `destination`, using `MOVE` when the server
    /// supports it and `COPY` + `\Deleted` + `UID EXPUNGE` otherwise, and
    /// returns the source folder's UIDVALIDITY.
    ///
    /// With `uid_validity` set, the folder's UIDVALIDITY must equal it, or
    /// the call fails with [`Error::StaleId`] and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::FolderNotFound`] if `destination` does not exist,
    /// [`Error::StaleId`] if the UIDVALIDITY differs,
    /// [`Error::MessageNotFound`] if no message has this UID, or a protocol
    /// error.
    pub async fn move_message(
        &mut self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
        destination: &str,
    ) -> Result<Option<u32>> {
        self.move_messages(
            folder,
            &[uid],
            uid_validity,
            destination,
            Check::Exists,
            &mut None,
        )
        .await?
        .single(folder, uid)
    }

    /// Deletes a message: moves it to Trash by default, or removes it
    /// permanently with [`DeleteMode::Permanent`], and returns the folder's
    /// UIDVALIDITY.
    ///
    /// With `uid_validity` set, the folder's UIDVALIDITY must equal it, or
    /// the call fails with [`Error::StaleId`] and changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidInput`] when moving a message that is already
    /// in Trash, or for [`DeleteMode::Permanent`] when
    /// [`MailConfig::permanent_delete`] is `false`,
    /// [`Error::FolderNotFound`] if no Trash folder can be identified,
    /// [`Error::StaleId`] if the UIDVALIDITY differs,
    /// [`Error::MessageNotFound`] if no message has this UID, or a protocol
    /// error.
    pub async fn delete_message(
        &mut self,
        folder: &str,
        uid: Uid,
        uid_validity: Option<u32>,
        mode: DeleteMode,
    ) -> Result<Option<u32>> {
        with_timeout(self.timeout, async {
            match mode {
                DeleteMode::Trash => {
                    let trash = self.trash_folder().await?;
                    if same_folder(&trash, folder) {
                        return Err(Error::invalid(already_in_trash(self.permanent_delete)));
                    }
                    messages::transfer(
                        &mut self.conn,
                        &self.capabilities,
                        folder,
                        &[uid],
                        uid_validity,
                        &trash,
                        Check::Exists,
                        &mut None,
                    )
                    .await?
                    .single(folder, uid)
                }
                DeleteMode::Permanent => {
                    messages::delete(
                        &mut self.conn,
                        &self.capabilities,
                        self.permanent_delete,
                        folder,
                        uid,
                        uid_validity,
                    )
                    .await
                }
            }
        })
        .await
    }

    /// Appends a sent message to the Sent folder unless a message with the
    /// same `Message-ID` is already there.
    pub(crate) async fn save_sent_copy(
        &mut self,
        message_id: &str,
        raw: &[u8],
    ) -> Result<SentCopy> {
        with_timeout(
            self.timeout,
            messages::save_sent_copy(&mut self.conn, self.sent_folder.as_deref(), message_id, raw),
        )
        .await
    }

    /// Appends a composed draft to the Drafts folder.
    pub(crate) async fn save_draft(&mut self, draft: Composed) -> Result<SavedDraft> {
        let folder = with_timeout(
            self.timeout,
            messages::save_draft(&mut self.conn, self.drafts_folder.as_deref(), &draft.raw),
        )
        .await?;
        let message_id = draft.message_id;
        Ok(SavedDraft { message_id, folder })
    }

    /// Whether the server supports `IDLE` (RFC 2177).
    #[must_use]
    pub fn supports_idle(&self) -> bool {
        self.capabilities.has_str("IDLE")
    }

    /// Whether the server advertises Gmail's IMAP extension.
    #[must_use]
    pub fn is_gmail(&self) -> bool {
        self.capabilities.has_str("X-GM-EXT-1")
    }

    /// Opens `folder` read-only and returns its UID state. Use it before
    /// [`ImapSession::messages_after`] and [`ImapSession::idle`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::FolderNotFound`] if the folder does not exist,
    /// [`Error::Unsupported`] if the server reports no `UIDVALIDITY`, or a
    /// protocol error.
    pub async fn examine(&mut self, folder: &str) -> Result<FolderState> {
        with_timeout(self.timeout, watch::examine(&mut self.conn, folder)).await
    }

    /// Returns up to `limit` messages of the folder opened with
    /// [`ImapSession::examine`] whose UID is above `after`, oldest first.
    ///
    /// When more than `limit` arrived, this is the oldest chunk. Advance
    /// `after` to its highest UID for the next one. Messages are not marked
    /// as read.
    ///
    /// An empty vector does not say whether the search found nothing or the
    /// fetch came back empty. Use [`ImapSession::message_batch_after`] when
    /// that difference matters.
    ///
    /// # Errors
    ///
    /// Returns an error if the server rejects the command or the connection
    /// fails.
    pub async fn messages_after(&mut self, after: Uid, limit: usize) -> Result<Vec<NewMessage>> {
        Ok(self.message_batch_after(after, limit).await?.messages)
    }

    /// [`ImapSession::messages_after`], plus how far the search looked.
    ///
    /// [`MessageBatch::selected_through`] is the highest UID selected for
    /// this chunk, including when the fetch returned none of them because
    /// they were expunged after the search. It is `None` when the search
    /// found nothing above `after`.
    ///
    /// # Errors
    ///
    /// Returns an error if the server rejects the command or the connection
    /// fails.
    pub async fn message_batch_after(&mut self, after: Uid, limit: usize) -> Result<MessageBatch> {
        with_timeout(
            self.timeout,
            watch::messages_after(&mut self.conn, after, limit),
        )
        .await
    }

    /// Waits with `IDLE` on the folder opened with [`ImapSession::examine`]
    /// until the server reports a change, `wait` passes (servers drop idle
    /// connections after 30 minutes, so keep it below that), or `stop`
    /// completes. Returns the session for further commands.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Unsupported`] if the server lacks `IDLE`, or an
    /// error if the connection fails; the session is gone then.
    pub async fn idle(
        self,
        wait: Duration,
        stop: impl Future<Output = ()>,
    ) -> Result<(Self, IdleEvent)> {
        if !self.supports_idle() {
            return Err(Error::Unsupported("IDLE"));
        }
        let Self {
            conn,
            capabilities,
            timeout,
            sent_folder,
            trash_folder,
            drafts_folder,
            permanent_delete,
        } = self;
        let (conn, event) = watch::idle(conn, wait, timeout, stop).await?;
        Ok((
            Self {
                conn,
                capabilities,
                timeout,
                sent_folder,
                trash_folder,
                drafts_folder,
                permanent_delete,
            },
            event,
        ))
    }

    /// Sends `NOOP` to check that the connection is still usable.
    ///
    /// # Errors
    ///
    /// Returns an error if the server does not answer in time or the
    /// connection is broken.
    pub async fn noop(&mut self) -> Result<()> {
        with_timeout(self.timeout, async {
            self.conn.noop().await?;
            Ok(())
        })
        .await
    }

    /// Logs out and closes the connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the server does not acknowledge the logout.
    pub async fn logout(mut self) -> Result<()> {
        with_timeout(self.timeout, async {
            self.conn.logout().await?;
            Ok(())
        })
        .await
    }
}

/// Runs `operation`, failing with [`Error::Timeout`] if it takes too long.
pub async fn with_timeout<T>(
    timeout: Duration,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| Error::Timeout)?
}

/// Selects `folder`, mapping a `NO` response to [`Error::FolderNotFound`],
/// and returns its UIDVALIDITY (`None` when the server reports none or 0,
/// which RFC 3501 does not allow).
///
/// With `expected` set, any other UIDVALIDITY fails with [`Error::StaleId`].
/// Commands that act by UID after this on the same connection are safe:
/// RFC 3501, section 2.3.1.1, says a UID "MUST NOT change during the
/// session", so a reset after the check cannot renumber this selection.
async fn select(conn: &mut Conn, folder: &str, expected: Option<u32>) -> Result<Option<u32>> {
    let found = match conn.select(utf7::encode(folder)).await {
        Ok(mailbox) => mailbox.uid_validity.filter(|&value| value != 0),
        Err(async_imap::error::Error::No(_)) => {
            return Err(Error::FolderNotFound(folder.to_owned()));
        }
        Err(err) => return Err(err.into()),
    };
    if expected.is_some_and(|value| found != Some(value)) {
        return Err(Error::StaleId {
            folder: folder.to_owned(),
        });
    }
    Ok(found)
}

/// Domains whose IMAP login name is documented as the address's local part.
const ICLOUD_DOMAINS: [&str; 3] = ["icloud.com", "me.com", "mac.com"];

/// Response codes (RFC 5530, section 3) that a `NO` to `LOGIN` carries when
/// the server and not the password is at fault, and a later login may work:
/// a subsystem is down, a limit was reached, a resource is in use, or the
/// server hit a bug. Any other `NO` is a rejected password, as RFC 3501
/// defines the answer to `LOGIN` (section 6.2.3).
const TEMPORARY_REFUSALS: [&str; 4] = ["UNAVAILABLE", "LIMIT", "INUSE", "SERVERBUG"];

/// The [`TEMPORARY_REFUSALS`] code that the `NO` answer starts with, if any.
///
/// `async-imap` renders a `NO` as `code: <code>, info: <text>`, and its
/// parser only knows the codes of RFC 3501, so an RFC 5530 code stays at the
/// start of the text: `code: None, info: Some("[LIMIT] ...")`. The codes are
/// case-insensitive (RFC 5530, section 4).
fn temporary_refusal(no: &str) -> Option<&'static str> {
    let text = no.strip_prefix("code: None, info: Some(\"[")?;
    let (code, _) = text.split_once([' ', ']'])?;
    TEMPORARY_REFUSALS
        .into_iter()
        .find(|known| known.eq_ignore_ascii_case(code))
}

/// Logs in, trying each candidate user name from [`login_names`] in turn.
///
/// A `NO` is [`Error::Authentication`], unless it carries a code from
/// [`TEMPORARY_REFUSALS`]: that is [`Error::Unavailable`], and no other name
/// is tried, because the server would refuse it as well.
async fn login(
    mut client: async_imap::Client<MaybeTlsStream>,
    credentials: &Credentials,
) -> Result<Conn> {
    let password = credentials.password().expose_secret();
    let mut rejected = false;
    for name in login_names(credentials.email()) {
        match client.login(name, password).await {
            Ok(conn) => return Ok(conn),
            Err((async_imap::error::Error::No(answer), returned)) => {
                if let Some(code) = temporary_refusal(&answer) {
                    return Err(Error::Unavailable { code });
                }
                rejected = true;
                client = returned;
            }
            // A server may drop the connection after a rejected login; the
            // rejection is the meaningful error then.
            Err(_) if rejected => break,
            Err((err, _)) => return Err(err.into()),
        }
    }
    Err(Error::Authentication)
}

/// IMAP user names to try for `email`.
///
/// Apple documents the IMAP user name as the part before the `@` for
/// iCloud addresses, falling back to the full address; SMTP always uses the
/// full address. Other domains (custom domains, test servers) use the full
/// address only.
fn login_names(email: &str) -> Vec<&str> {
    match email.rsplit_once('@') {
        Some((local, domain))
            if ICLOUD_DOMAINS
                .iter()
                .any(|known| domain.eq_ignore_ascii_case(known)) =>
        {
            vec![local, email]
        }
        _ => vec![email],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icloud_addresses_try_local_part_first() {
        assert_eq!(login_names("john@icloud.com"), ["john", "john@icloud.com"]);
        assert_eq!(login_names("john@Me.com"), ["john", "john@Me.com"]);
    }

    #[test]
    fn other_domains_use_full_address() {
        assert_eq!(login_names("john@example.com"), ["john@example.com"]);
    }
}
