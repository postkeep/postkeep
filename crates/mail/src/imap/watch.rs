//! Watching a folder for new messages: UID tracking and IMAP `IDLE`.

use std::time::Duration;

use async_imap::extensions::idle::IdleResponse;
use async_imap::types::{Fetch, UnsolicitedResponse};
use futures::TryStreamExt;

use super::Conn;
use crate::{EmailAddress, Error, Result, Uid, parse, utf7};

/// Data items fetched for each new message. `BODY.PEEK` leaves `\Seen`
/// untouched.
const NEW_MESSAGE_ITEMS: &str = "(UID INTERNALDATE BODY.PEEK[HEADER])";

/// The UID state of a folder, from `EXAMINE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FolderState {
    /// `UIDVALIDITY`: when it changes, earlier UIDs mean nothing anymore.
    pub uid_validity: u32,
    /// `UIDNEXT`: the UID the next message will get, at least. Messages
    /// with a lower UID already existed.
    pub uid_next: Uid,
    /// Number of messages in the folder.
    pub exists: u32,
}

/// One chunk of messages newer than a cursor.
///
/// [`MessageBatch::selected_through`] tells an empty search apart from an
/// empty fetch. A fetch can return nothing when the messages the search
/// selected are expunged before it runs; the search still saw them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageBatch {
    /// Messages the fetch returned, oldest first.
    pub messages: Vec<NewMessage>,
    /// Highest UID the search selected for this chunk.
    ///
    /// `None` when the search found nothing above the cursor. `Some` when
    /// UIDs were selected, including when [`Self::messages`] is empty.
    pub selected_through: Option<Uid>,
}

/// A message that arrived after a known UID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewMessage {
    /// UID in the watched folder.
    pub uid: Uid,
    /// `Message-ID` header.
    pub message_id: Option<String>,
    /// First `From` address.
    pub from: Option<EmailAddress>,
    /// Whether a mail client shows `from` as the sender's address, as
    /// [`mime::sender`](crate::mime::sender) finds.
    pub from_clear: bool,
    /// The value of each `From` header as sent, in their order.
    pub from_values: Vec<String>,
    /// The `To` addresses, then the `Cc` addresses.
    pub recipients: Vec<EmailAddress>,
    /// Decoded subject.
    pub subject: Option<String>,
    /// `Date` header, falling back to the server's internal date.
    pub date: Option<chrono::DateTime<chrono::FixedOffset>>,
}

/// Why [`ImapSession::idle`](super::ImapSession::idle) returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdleEvent {
    /// The server reported a change (for example a new message).
    Changed,
    /// Nothing happened within the wait time.
    Timeout,
    /// The caller's stop signal fired.
    Stopped,
}

/// Opens `folder` read-only and returns its UID state.
pub(super) async fn examine(conn: &mut Conn, folder: &str) -> Result<FolderState> {
    let mailbox = match conn.examine(utf7::encode(folder)).await {
        Ok(mailbox) => mailbox,
        Err(async_imap::error::Error::No(_)) => {
            return Err(Error::FolderNotFound(folder.to_owned()));
        }
        Err(err) => return Err(err.into()),
    };
    let uid_validity = mailbox
        .uid_validity
        .ok_or(Error::Unsupported("UIDVALIDITY"))?;
    Ok(FolderState {
        uid_validity,
        // Without UIDNEXT, assume nothing newer than what is there.
        uid_next: mailbox.uid_next.unwrap_or(1),
        exists: mailbox.exists,
    })
}

/// UIDs strictly above `after`, oldest first, at most `limit`.
///
/// A `limit` of zero keeps nothing. A longer backlog is walked by advancing
/// `after` to the highest UID of each chunk; keeping the newest chunk would
/// drop the rest.
fn select_oldest(uids: impl IntoIterator<Item = Uid>, after: Uid, limit: usize) -> Vec<Uid> {
    let mut uids: Vec<Uid> = uids.into_iter().filter(|uid| *uid > after).collect();
    uids.sort_unstable();
    uids.truncate(limit);
    uids
}

/// Returns up to `limit` messages of the selected folder with a UID above
/// `after`, oldest first.
///
/// When more arrived, the oldest `limit` are returned. Advance `after` to
/// the highest returned UID, or to [`MessageBatch::selected_through`] when
/// the fetch returned nothing, to read the next chunk. `selected_through`
/// is `None` only when the search itself found nothing above `after`.
pub(super) async fn messages_after(
    conn: &mut Conn,
    after: Uid,
    limit: usize,
) -> Result<MessageBatch> {
    let Some(first) = after.checked_add(1) else {
        return Ok(MessageBatch {
            messages: Vec::new(),
            selected_through: None,
        });
    };
    // `UID SEARCH` first: a `n:*` fetch always returns the last message,
    // even when its UID is below `n`.
    let found = conn.uid_search(format!("UID {first}:*")).await?;
    // Oldest `limit`, not the newest. Dropping the oldest would skip mail
    // with no gap in the event sequence.
    let uids = select_oldest(found, after, limit);
    let Some(selected_through) = uids.iter().copied().max() else {
        return Ok(MessageBatch {
            messages: Vec::new(),
            selected_through: None,
        });
    };
    let set = super::search::uid_set(&uids);
    let fetches: Vec<Fetch> = conn
        .uid_fetch(set, NEW_MESSAGE_ITEMS)
        .await?
        .try_collect()
        .await?;
    // The server may interleave unsolicited FETCH responses (for example
    // flag changes) for other messages; keep only the requested ones.
    let mut messages: Vec<NewMessage> = fetches
        .iter()
        .filter_map(new_message)
        .filter(|message| uids.binary_search(&message.uid).is_ok())
        .collect();
    messages.sort_unstable_by_key(|message| message.uid);
    messages.dedup_by_key(|message| message.uid);
    Ok(MessageBatch {
        messages,
        selected_through: Some(selected_through),
    })
}

fn new_message(fetch: &Fetch) -> Option<NewMessage> {
    let uid = fetch.uid?;
    let headers = fetch
        .header()
        .and_then(parse::parse_headers)
        .unwrap_or_default();
    Some(NewMessage {
        uid,
        message_id: headers.message_id,
        from: headers.from.into_iter().next(),
        from_clear: headers.from_clear,
        from_values: headers.from_values,
        recipients: headers.to.into_iter().chain(headers.cc).collect(),
        subject: headers.subject,
        date: headers.date.or_else(|| fetch.internal_date()),
    })
}

/// Runs `IDLE` on the selected folder until the server reports a change,
/// `wait` passes, or `stop` completes. Returns the connection afterwards.
pub(super) async fn idle(
    conn: Conn,
    wait: Duration,
    command_timeout: Duration,
    stop: impl Future<Output = ()>,
) -> Result<(Conn, IdleEvent)> {
    // The server may announce new mail in untagged responses to other
    // commands: during the caller's search and fetch, or between sending
    // IDLE and its continuation. async-imap queues those on the session's
    // unsolicited channel rather than reporting them from the IDLE wait, so
    // check the channel before and after starting IDLE; otherwise such a
    // message would only be noticed at the next change or IDLE renewal.
    let unsolicited = conn.unsolicited_responses.clone();
    if take_changes(&unsolicited) {
        return Ok((conn, IdleEvent::Changed));
    }
    let mut handle = conn.idle();
    tokio::time::timeout(command_timeout, handle.init())
        .await
        .map_err(|_| Error::Timeout)??;
    let event = if take_changes(&unsolicited) {
        IdleEvent::Changed
    } else {
        let (response, interrupt) = handle.wait_with_timeout(wait);
        tokio::pin!(response);
        tokio::pin!(stop);
        tokio::select! {
            result = &mut response => match result? {
                IdleResponse::NewData(_) => IdleEvent::Changed,
                IdleResponse::Timeout => IdleEvent::Timeout,
                IdleResponse::ManualInterrupt => IdleEvent::Stopped,
            },
            () = &mut stop => {
                drop(interrupt);
                // Let the stream notice the interrupt before sending DONE.
                let _ = tokio::time::timeout(command_timeout, response).await;
                IdleEvent::Stopped
            }
        }
    };
    let conn = tokio::time::timeout(command_timeout, handle.done())
        .await
        .map_err(|_| Error::Timeout)??;
    Ok((conn, event))
}

/// Drains queued unsolicited responses and returns whether any of them
/// reported new messages (`EXISTS` or `RECENT`).
fn take_changes(queue: &async_channel::Receiver<UnsolicitedResponse>) -> bool {
    let mut changed = false;
    while let Ok(response) = queue.try_recv() {
        changed |= matches!(
            response,
            UnsolicitedResponse::Exists(_) | UnsolicitedResponse::Recent(_)
        );
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_oldest_chunks_a_backlog_oldest_first() {
        let arrived: Vec<Uid> = (1..=120).collect();
        let first = select_oldest(arrived.iter().copied(), 0, 50);
        let second = select_oldest(arrived.iter().copied(), 50, 50);
        let third = select_oldest(arrived.iter().copied(), 100, 50);
        let done = select_oldest(arrived.iter().copied(), 120, 50);
        assert_eq!(first, (1..=50).collect::<Vec<_>>());
        assert_eq!(second, (51..=100).collect::<Vec<_>>());
        assert_eq!(third, (101..=120).collect::<Vec<_>>());
        assert_eq!(done.len(), 0);

        // Unsorted input, a limit past the end, and a limit of zero.
        assert_eq!(select_oldest(vec![8, 3, 5], 2, 2), vec![3, 5]);
        assert_eq!(select_oldest(vec![4, 9], 3, 10), vec![4, 9]);
        assert_eq!(select_oldest(vec![1, 2, 3], 0, 0).len(), 0);
    }
}
