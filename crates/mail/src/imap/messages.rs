//! Message operations: fetch, flags, move, delete and append.

use std::collections::HashMap;

use async_imap::imap_proto::rfc4315::UidSetMember;
use async_imap::imap_proto::{AttributeValue, Response, ResponseCode, Status};
use async_imap::types::{Capabilities, Fetch, Flag as ImapFlag};
use futures::TryStreamExt;

use super::folders::{self, SpecialUse, same_folder};
use super::search::{UID_SET_MAX, run_until_done, search_uids, uid_chunks, uid_set, uid_sets};
use super::{Conn, select};
use crate::query::{self, Literals};
use crate::{
    AttachmentData, Error, Flag, Message, MessageFlags, Result, SearchQuery, SentCopy, Uid, parse,
    utf7,
};

/// How [`ImapSession::delete_message`](crate::ImapSession::delete_message)
/// removes a message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeleteMode {
    /// Move the message to the Trash folder (recoverable).
    #[default]
    Trash,
    /// Remove the message immediately with `\Deleted` + `EXPUNGE`
    /// (not recoverable). Refused where
    /// [`MailConfig::permanent_delete`](crate::MailConfig::permanent_delete)
    /// is `false`.
    Permanent,
}

/// UIDs found or changed in one source folder, and move results when reported.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Changed {
    /// Source folder's UIDVALIDITY, absent when the server reports none.
    pub uid_validity: Option<u32>,
    /// Requested UIDs needing the change, or acted on successfully.
    pub done: Vec<Uid>,
    /// Requested UIDs that already met the check; nothing was sent for them.
    pub already: Vec<Uid>,
    /// Requested UIDs absent at the check, before any changes.
    pub missing: Vec<Uid>,
    /// Old-to-new UID pairs from COPYUID; empty when the server reports none.
    pub new_uids: HashMap<Uid, Uid>,
    /// Destination folder's UIDVALIDITY from COPYUID.
    pub destination_uid_validity: Option<u32>,
}

impl Changed {
    pub(super) fn single(&self, folder: &str, uid: Uid) -> Result<Option<u32>> {
        if self.done.contains(&uid) || self.already.contains(&uid) {
            Ok(self.uid_validity)
        } else {
            Err(not_found(folder, uid))
        }
    }
}

/// The state to check before acting on requested UIDs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Check<'a> {
    /// Check whether the UIDs exist.
    #[default]
    Exists,
    /// Also check whether every requested flag already has the given value.
    Flags(&'a [(Flag, bool)]),
    /// Also check whether the message carries this label (Gmail IMAP only).
    Label(&'a str),
}

/// What an interrupted write can report after its initial check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Progress {
    /// The check and any new UIDs from confirmed commands.
    pub changed: Changed,
    /// Number of leading `changed.done` UIDs with every write confirmed.
    pub confirmed: usize,
    /// Number of following UIDs carried by the command in flight.
    pub carried: usize,
    /// What the command in flight may have done to those UIDs.
    pub in_flight: InFlight,
}

/// What happened to the UIDs of a write that did not complete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum InFlight {
    /// A write was started but got no answer.
    #[default]
    Unanswered,
    /// A COPY was definitely refused.
    Refused,
    /// A previous step was confirmed, or a refusal could have changed only part of the set.
    Partial,
}

/// Advice for a message already in Trash, respecting permanent-delete policy.
#[must_use]
pub const fn already_in_trash(permanent_delete: bool) -> &'static str {
    if permanent_delete {
        "the message is already in Trash; use permanent deletion to remove it"
    } else {
        "the message is already in Trash; Gmail empties Trash after 30 days"
    }
}

pub(super) async fn fetch(
    conn: &mut Conn,
    folder: &str,
    uid: Uid,
    uid_validity: Option<u32>,
) -> Result<(Message, Option<u32>)> {
    let (fetch, seen) = fetch_whole(conn, folder, uid, uid_validity).await?;
    let raw = fetch.body().ok_or(Error::Parse(uid))?;
    let message = parse::parse_message(uid, MessageFlags::from_imap(fetch.flags()), raw)
        .ok_or(Error::Parse(uid))?;
    Ok((message, seen))
}

pub(super) async fn fetch_attachment(
    conn: &mut Conn,
    folder: &str,
    uid: Uid,
    uid_validity: Option<u32>,
    id: u32,
    max_bytes: usize,
) -> Result<Option<AttachmentData>> {
    let (fetch, _) = fetch_whole(conn, folder, uid, uid_validity).await?;
    let raw = fetch.body().ok_or(Error::Parse(uid))?;
    Ok(parse::attachment_data(raw, id, max_bytes))
}

/// Reads the provider's `RFC822.SIZE` for the message without fetching its body.
pub(super) async fn message_size(
    conn: &mut Conn,
    folder: &str,
    uid: Uid,
    uid_validity: Option<u32>,
) -> Result<u32> {
    select(conn, folder, uid_validity).await?;
    let fetches: Vec<Fetch> = conn
        .uid_fetch(uid.to_string(), "(UID RFC822.SIZE)")
        .await?
        .try_collect()
        .await?;
    fetches
        .into_iter()
        .find(|fetch| fetch.uid == Some(uid))
        .ok_or_else(|| not_found(folder, uid))?
        .size
        .ok_or(Error::Parse(uid))
}

/// Fetches raw MIME after checking its reported size against `max`.
pub(super) async fn fetch_raw(
    conn: &mut Conn,
    folder: &str,
    uid: Uid,
    uid_validity: Option<u32>,
    max: usize,
) -> Result<Vec<u8>> {
    if message_size(conn, folder, uid, uid_validity).await? as usize > max {
        return Err(Error::MessageTooLarge);
    }
    let (fetch, _) = fetch_whole(conn, folder, uid, uid_validity).await?;
    let bytes = fetch.body().ok_or(Error::Parse(uid))?;
    if bytes.len() > max {
        return Err(Error::MessageTooLarge);
    }
    Ok(bytes.to_vec())
}

/// Fetches the whole raw message without setting `\Seen`, with the folder's UIDVALIDITY.
async fn fetch_whole(
    conn: &mut Conn,
    folder: &str,
    uid: Uid,
    uid_validity: Option<u32>,
) -> Result<(Fetch, Option<u32>)> {
    let seen = select(conn, folder, uid_validity).await?;
    let fetches: Vec<Fetch> = conn
        .uid_fetch(uid.to_string(), "(UID FLAGS BODY.PEEK[])")
        .await?
        .try_collect()
        .await?;
    let fetch = fetches
        .into_iter()
        .find(|fetch| fetch.uid == Some(uid))
        .ok_or_else(|| not_found(folder, uid))?;
    Ok((fetch, seen))
}

pub(super) async fn find_messages(
    conn: &mut Conn,
    folder: &str,
    uids: &[Uid],
    uid_validity: Option<u32>,
    check: Check<'_>,
) -> Result<Changed> {
    if uids.len() > UID_SET_MAX || uids.contains(&0) {
        return Err(Error::invalid(format!(
            "give at most {UID_SET_MAX} nonzero UIDs"
        )));
    }
    let seen = select(conn, folder, uid_validity).await?;
    let (found, already) = if let Check::Flags(flags) = check {
        checked_flags(conn, uids, flags).await?
    } else {
        let found = existing(conn, uids).await?;
        let mut already = Vec::new();
        if let Check::Label(label) = check {
            let label = query::imap_string(&utf7::encode(label), Literals::Unsupported)?;
            let filter = format!("X-GM-LABELS {label}");
            for set in uid_sets(uids, "UID SEARCH UID  ".len() + filter.len())? {
                already.extend(search_uids(conn, &format!("UID SEARCH UID {set} {filter}")).await?);
            }
        }
        (found, already)
    };
    let mut changed = Changed {
        uid_validity: seen,
        ..Changed::default()
    };
    for uid in uids {
        let into = if !found.contains(uid) {
            &mut changed.missing
        } else if already.contains(uid) {
            &mut changed.already
        } else {
            &mut changed.done
        };
        if !into.contains(uid) {
            into.push(*uid);
        }
    }
    Ok(changed)
}

async fn checked_flags(
    conn: &mut Conn,
    uids: &[Uid],
    asked: &[(Flag, bool)],
) -> Result<(Vec<Uid>, Vec<Uid>)> {
    let (mut found, mut already) = (Vec::new(), Vec::new());
    let mut incomplete = Vec::new();
    for set in uid_sets(uids, "UID FETCH  (UID FLAGS)".len())? {
        run_until_done(conn, &format!("UID FETCH {set} (UID FLAGS)"), |response| {
            if let Response::Fetch(_, attrs) = response
                && let Some(uid) = attrs.iter().find_map(|attr| match attr {
                    AttributeValue::Uid(uid) if uids.contains(uid) => Some(*uid),
                    _ => None,
                })
            {
                let Some(flags) = attrs.iter().find_map(|attr| match attr {
                    AttributeValue::Flags(flags) => Some(MessageFlags::from_imap(
                        flags.iter().map(|flag| ImapFlag::from(flag.as_ref())),
                    )),
                    _ => None,
                }) else {
                    if !incomplete.contains(&uid) {
                        incomplete.push(uid);
                    }
                    return;
                };
                found.push(uid);
                if asked.iter().all(|(flag, enabled)| {
                    *enabled
                        == match flag {
                            Flag::Seen => flags.seen,
                            Flag::Flagged => flags.flagged,
                            Flag::Answered => flags.answered,
                        }
                }) {
                    already.push(uid);
                }
            }
        })
        .await?;
    }
    if let Some(uid) = incomplete.into_iter().find(|uid| !found.contains(uid)) {
        return Err(Error::Parse(uid));
    }
    Ok((found, already))
}

pub(super) async fn set_flags(
    conn: &mut Conn,
    folder: &str,
    uids: &[Uid],
    uid_validity: Option<u32>,
    flags: &[(Flag, bool)],
    check: Check<'_>,
    progress: &mut Option<Progress>,
) -> Result<Changed> {
    let changed = find_messages(conn, folder, uids, uid_validity, check).await?;
    let progress = progress.insert(Progress {
        changed,
        ..Progress::default()
    });
    let queries: Vec<_> = flags
        .iter()
        .map(|(flag, enabled)| store_query(flag.as_imap(), *enabled))
        .collect();
    if let Some(longest) = queries.iter().map(String::len).max() {
        for chunk in uid_chunks(&progress.changed.done, "UID STORE  ".len() + longest)? {
            let set = uid_set(chunk);
            progress.carried = chunk.len();
            progress.in_flight = InFlight::Unanswered;
            for query in &queries {
                let result =
                    run_until_done(conn, &format!("UID STORE {set} {query}"), |_| {}).await;
                if result.is_ok() || result.as_ref().is_err_and(refusal) {
                    progress.in_flight = InFlight::Partial;
                }
                result?;
            }
            progress.confirmed += chunk.len();
            progress.carried = 0;
        }
    }
    Ok(progress.changed.clone())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the source, destination, check and write slot are separate"
)]
pub(super) async fn move_messages(
    conn: &mut Conn,
    capabilities: &Capabilities,
    folder: &str,
    uids: &[Uid],
    uid_validity: Option<u32>,
    destination: &str,
    check: Check<'_>,
    progress: &mut Option<Progress>,
) -> Result<Changed> {
    if same_folder(folder, destination) {
        return Err(Error::invalid(
            "source and destination folders are the same",
        ));
    }
    if !folders::exists(conn, destination).await? {
        return Err(Error::FolderNotFound(destination.to_owned()));
    }
    transfer(
        conn,
        capabilities,
        folder,
        uids,
        uid_validity,
        destination,
        check,
        progress,
    )
    .await
}

pub(super) async fn delete(
    conn: &mut Conn,
    capabilities: &Capabilities,
    permanent_delete: bool,
    folder: &str,
    uid: Uid,
    uid_validity: Option<u32>,
) -> Result<Option<u32>> {
    if !permanent_delete {
        return Err(Error::invalid(
            "On Gmail, a permanent delete would only remove this folder's label and keep the \
             message in All Mail. Delete without `permanent` to move it to the trash, which \
             Gmail empties after 30 days.",
        ));
    }
    let changed = find_messages(conn, folder, &[uid], uid_validity, Check::Exists).await?;
    let seen = changed.single(folder, uid)?;
    ensure_single_expunge(conn, capabilities, &[uid]).await?;
    expunge(conn, capabilities, &[uid]).await?;
    Ok(seen)
}

pub(super) async fn save_sent_copy(
    conn: &mut Conn,
    sent_folder: Option<&str>,
    message_id: &str,
    raw: &[u8],
) -> Result<SentCopy> {
    let folder = folders::resolve(conn, SpecialUse::Sent, sent_folder).await?;
    select(conn, &folder, None).await?;
    // Message IDs are ASCII, so no literals are ever needed.
    let criteria = SearchQuery::new()
        .message_id(message_id)
        .to_imap(Literals::Unsupported)?;
    if !conn.uid_search(&criteria).await?.is_empty() {
        return Ok(SentCopy::AlreadyPresent { folder });
    }
    conn.append(utf7::encode(&folder), Some("(\\Seen)"), None, raw)
        .await?;
    Ok(SentCopy::Saved { folder })
}

pub(super) async fn save_draft(
    conn: &mut Conn,
    drafts_folder: Option<&str>,
    raw: &[u8],
) -> Result<String> {
    let folder = folders::resolve(conn, SpecialUse::Drafts, drafts_folder).await?;
    conn.append(utf7::encode(&folder), Some("(\\Seen \\Draft)"), None, raw)
        .await?;
    Ok(folder)
}

/// Moves existing UIDs to `destination`, pairing COPYUIDs across confirmed chunks.
#[expect(
    clippy::too_many_arguments,
    reason = "the source, destination, check and write slot are separate"
)]
pub(super) async fn transfer(
    conn: &mut Conn,
    capabilities: &Capabilities,
    folder: &str,
    uids: &[Uid],
    uid_validity: Option<u32>,
    destination: &str,
    check: Check<'_>,
    progress: &mut Option<Progress>,
) -> Result<Changed> {
    let changed = find_messages(conn, folder, uids, uid_validity, check).await?;
    let progress = progress.insert(Progress {
        changed,
        ..Progress::default()
    });
    let target = query::imap_string(&utf7::encode(destination), Literals::Unsupported)?;
    let moving = capabilities.has_str("MOVE");
    let verb = if moving { "MOVE" } else { "COPY" };
    let done = &progress.changed.done;
    let mut overhead = format!("UID {verb}  {target}").len();
    if !moving {
        overhead = overhead.max("UID STORE  ".len() + store_query("\\Deleted", true).len());
    }
    let chunks = uid_chunks(done, overhead)?;
    let mut codes = Vec::new();
    for chunk in chunks {
        if !moving {
            ensure_single_expunge(conn, capabilities, chunk).await?;
        }
        let set = uid_set(chunk);
        progress.carried = chunk.len();
        progress.in_flight = InFlight::Unanswered;
        let result = run_until_done(conn, &format!("UID {verb} {set} {target}"), |response| {
            if let Response::Data {
                status: Status::Ok,
                outcome,
            } = response
            {
                collect_copy_uid(&mut codes, outcome.code.take());
            }
        })
        .await;
        if result.as_ref().is_err_and(refusal) {
            progress.in_flight = if moving {
                InFlight::Partial
            } else {
                InFlight::Refused
            };
        }
        collect_copy_uid(&mut codes, result?);
        if !moving {
            progress.in_flight = InFlight::Partial;
            expunge(conn, capabilities, chunk).await.map_err(|error| match error {
                Error::Unsupported(_) => Error::Unsupported(
                    "UIDPLUS; copies may now be in the destination; search it before calling again",
                ),
                error => error,
            })?;
        }
        progress.confirmed += chunk.len();
        progress.carried = 0;
        (
            progress.changed.destination_uid_validity,
            progress.changed.new_uids,
        ) = copy_uids(&codes);
        progress
            .changed
            .new_uids
            .retain(|uid, _| done[..progress.confirmed].contains(uid));
    }
    Ok(progress.changed.clone())
}

fn collect_copy_uid(codes: &mut Vec<ResponseCode<'static>>, code: Option<ResponseCode<'_>>) {
    if let Some(ResponseCode::CopyUid(validity, old, new)) = code
        && codes.len() <= UID_SET_MAX
    {
        // Fresh bounded vectors must not retain server-sized allocations.
        let [old, new] =
            [old, new].map(|members| members[..members.len().min(UID_SET_MAX + 1)].to_vec());
        codes.push(ResponseCode::CopyUid(validity, old, new));
    }
}

const fn refusal(error: &Error) -> bool {
    matches!(
        error,
        Error::Imap(async_imap::error::Error::No(_) | async_imap::error::Error::Bad(_))
    )
}

/// Expands at most one operation's worth of UIDs, even for a malformed response.
fn expand_uids(set: &[UidSetMember]) -> Vec<Uid> {
    set.iter()
        .flat_map(|member| match member {
            UidSetMember::Uid(uid) => *uid..=*uid,
            UidSetMember::UidRange(range) => {
                (*range.start()).min(*range.end())..=(*range.start()).max(*range.end())
            }
        })
        .take(UID_SET_MAX + 1)
        .collect()
}

/// COPYUID sets pair in their listed order, not in the request's order.
fn copy_uids(codes: &[ResponseCode<'_>]) -> (Option<u32>, HashMap<Uid, Uid>) {
    if codes.len() > UID_SET_MAX {
        return (None, HashMap::new());
    }
    let mut validity = None;
    let mut pairs = HashMap::new();
    for code in codes {
        if let ResponseCode::CopyUid(seen, old, new) = code {
            let old = expand_uids(old);
            let new = expand_uids(new);
            if *seen == 0
                || validity.is_some_and(|value| value != *seen)
                || old.len() != new.len()
                || old.len() > UID_SET_MAX
                || old.contains(&0)
                || new.contains(&0)
            {
                return (None, HashMap::new());
            }
            validity = Some(*seen);
            for (old, new) in old.into_iter().zip(new) {
                if pairs.get(&old).is_some_and(|mapped| *mapped != new)
                    || pairs
                        .iter()
                        .any(|(source, target)| *source != old && *target == new)
                {
                    return (None, HashMap::new());
                }
                pairs.insert(old, new);
                if pairs.len() > UID_SET_MAX {
                    return (None, HashMap::new());
                }
            }
        }
    }
    (validity, pairs)
}

/// Marks our UIDs `\Deleted` and expunges them. Callers check
/// [`ensure_single_expunge`] first. Without UIDPLUS, a second check narrows
/// the gap to one round trip before EXPUNGE; it cannot close that race.
async fn expunge(conn: &mut Conn, capabilities: &Capabilities, uids: &[Uid]) -> Result<()> {
    store_flag(conn, uids, "\\Deleted", true).await?;
    if capabilities.has_str("UIDPLUS") {
        for set in uid_sets(uids, "UID EXPUNGE ".len())? {
            run_until_done(conn, &format!("UID EXPUNGE {set}"), |_| {}).await?;
        }
    } else {
        if let Err(error) = ensure_single_expunge(conn, capabilities, uids).await {
            store_flag(conn, uids, "\\Deleted", false).await?;
            return Err(error);
        }
        run_until_done(conn, "EXPUNGE", |_| {}).await?;
    }
    Ok(())
}

/// Without UIDPLUS, refuse a plain EXPUNGE that would remove others' UIDs.
async fn ensure_single_expunge(
    conn: &mut Conn,
    capabilities: &Capabilities,
    uids: &[Uid],
) -> Result<()> {
    if capabilities.has_str("UIDPLUS") {
        return Ok(());
    }
    let deleted = search_uids(conn, "UID SEARCH DELETED").await?;
    if deleted.iter().all(|other| uids.contains(other)) {
        Ok(())
    } else {
        Err(Error::Unsupported(
            "UIDPLUS, which is required to expunge one message while others are marked deleted",
        ))
    }
}

async fn existing(conn: &mut Conn, uids: &[Uid]) -> Result<Vec<Uid>> {
    let mut found = Vec::new();
    for set in uid_sets(uids, "UID SEARCH UID ".len())? {
        found.extend(search_uids(conn, &format!("UID SEARCH UID {set}")).await?);
    }
    Ok(found)
}

fn store_query(flag: &str, enabled: bool) -> String {
    let action = if enabled {
        "+FLAGS.SILENT"
    } else {
        "-FLAGS.SILENT"
    };
    format!("{action} ({flag})")
}

async fn store_flag(conn: &mut Conn, uids: &[Uid], flag: &str, enabled: bool) -> Result<()> {
    let query = store_query(flag, enabled);
    for set in uid_sets(uids, "UID STORE  ".len() + query.len())? {
        run_until_done(conn, &format!("UID STORE {set} {query}"), |_| {}).await?;
    }
    Ok(())
}

fn not_found(folder: &str, uid: Uid) -> Error {
    Error::MessageNotFound {
        folder: folder.to_owned(),
        uid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_copyuid_sets_in_the_responses_order() {
        let codes = [
            ResponseCode::CopyUid(11, vec![5.into()], vec![30.into()]),
            ResponseCode::CopyUid(11, vec![(1..=2).into()], vec![(8..=9).into()]),
        ];
        assert_eq!(
            copy_uids(&codes),
            (Some(11), HashMap::from([(1, 8), (2, 9), (5, 30)]))
        );
        let max = Uid::try_from(UID_SET_MAX).unwrap();
        for codes in [
            vec![ResponseCode::CopyUid(
                11,
                vec![1.into(), 1.into()],
                vec![5.into(), 6.into()],
            )],
            vec![ResponseCode::CopyUid(
                11,
                vec![1.into()],
                vec![(1..=2).into()],
            )],
            vec![ResponseCode::CopyUid(
                11,
                vec![(1..=u32::MAX).into()],
                vec![(1..=u32::MAX).into()],
            )],
            vec![ResponseCode::CopyUid(
                11,
                vec![(1..=2).into()],
                vec![5.into(), 5.into()],
            )],
            vec![
                ResponseCode::CopyUid(11, vec![1.into()], vec![5.into()]),
                ResponseCode::CopyUid(11, vec![2.into()], vec![5.into()]),
            ],
            vec![
                ResponseCode::CopyUid(11, vec![(1..=max).into()], vec![(max + 1..=max * 2).into()]),
                ResponseCode::CopyUid(11, vec![(max + 1).into()], vec![(max * 2 + 1).into()]),
            ],
            (0..=UID_SET_MAX)
                .map(|_| ResponseCode::CopyUid(11, vec![1.into()], vec![5.into()]))
                .collect(),
        ] {
            assert_eq!(copy_uids(&codes), (None, HashMap::new()));
        }
    }
}
