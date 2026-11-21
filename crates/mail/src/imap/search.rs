//! Message search with paging.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use async_imap::imap_proto::{
    AttributeValue, MailboxDatum, MessageSection, Response, ResponseCode, SectionPath, Status,
};
use async_imap::types::{Capabilities, Flag};
use chrono::DateTime;

use super::{Conn, select, with_timeout};
use crate::query::Literals;
use crate::{
    Error, MessageFlags, MessageSummary, Paging, Result, SearchQuery, SearchResults, Uid, parse,
};

/// Maximum number of UIDs accepted by one set operation, bounded by its timeout.
pub const UID_SET_MAX: usize = 100;

/// Data items fetched for each summary. `BODY.PEEK` leaves `\Seen` untouched.
const SUMMARY_ITEMS: &str =
    "(UID FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE)])";

/// With `sort` (the server offers `SORT`) and ASCII values, the newest
/// `Date` header comes first, and a message without one goes by its arrival
/// (RFC 5256's `DATE`), like the date its summary shows. Otherwise the
/// newest arrival comes first.
pub(super) async fn search(
    conn: &mut Conn,
    capabilities: &Capabilities,
    folder: &str,
    query: &SearchQuery,
    paging: Paging,
    timeout: Duration,
    until: Option<Instant>,
) -> Result<SearchResults> {
    let sort = if capabilities.has_str("SORT") {
        query.to_imap_sort()?
    } else {
        None
    };
    let criteria = query.to_imap(Literals::from_capabilities(capabilities))?;
    let (uid_validity, uids) = with_timeout(timeout, async {
        let uid_validity = select(conn, folder, None).await?;
        let uids = if let Some(arguments) = sort {
            // Oldest first, and equal dates in mailbox order: reversed, the
            // newest come first, and of equal dates the later arrival.
            let mut uids = search_uids(conn, &format!("UID SORT {arguments}")).await?;
            uids.reverse();
            uids
        } else {
            matching(conn, &criteria).await?
        };
        Ok((uid_validity, uids))
    })
    .await?;
    let last_uid = uids.iter().copied().max();
    let limit = paging.limit.min(Paging::MAX_LIMIT);
    let (messages, total, estimated) = if query.checks_headers() {
        let want = paging.offset.saturating_add(limit).saturating_add(1);
        let mut walk = held(conn, &uids, query, paging.offset, want, timeout, until).await?;
        walk.kept.truncate(limit);
        (
            walk.kept,
            walk.accepted + (uids.len() - walk.read),
            walk.read < uids.len(),
        )
    } else {
        let rest = &uids[paging.offset.min(uids.len())..];
        let page = &rest[..limit.min(rest.len())];
        let messages = fetch_summaries(conn, page, query, timeout, None).await?;
        (messages, uids.len(), false)
    };
    Ok(SearchResults {
        last_uid,
        total,
        estimated,
        offset: paging.offset,
        messages,
        uid_validity,
    })
}

#[derive(Default)]
pub(super) struct Walk {
    pub(super) kept: Vec<MessageSummary>,
    accepted: usize,
    read: usize,
}

/// Checks candidates in order, keeping matches at positions `skip..want`.
/// Counts all matches in every batch read, even if the final batch passes `want`.
/// Each batch asks for the matches still wanted, with a retry minimum of 2 UIDs
/// that doubles after each shortfall. The batch is capped at [`UID_SET_MAX`].
/// The deadline is checked before each fetch, so exhaustion leaves the session usable.
pub(super) async fn held(
    conn: &mut Conn,
    uids: &[Uid],
    query: &SearchQuery,
    skip: usize,
    want: usize,
    timeout: Duration,
    until: Option<Instant>,
) -> Result<Walk> {
    let mut walk = Walk::default();
    let mut retry = 0;
    while walk.accepted < want && walk.read < uids.len() {
        let remaining = want - walk.accepted;
        let unread = &uids[walk.read..];
        let count = remaining.max(retry).min(UID_SET_MAX).min(unread.len());
        let found = fetch_summaries(conn, &unread[..count], query, timeout, until).await?;
        let accepted = found.len();
        walk.kept.extend(
            found
                .into_iter()
                .take(remaining)
                .skip(skip.saturating_sub(walk.accepted)),
        );
        walk.accepted += accepted;
        walk.read += count;
        retry = (retry * 2).clamp(2, UID_SET_MAX);
    }
    Ok(walk)
}

/// Every matching UID, newest arrival first, failing closed on a refused SEARCH.
pub(super) async fn matching(conn: &mut Conn, criteria: &str) -> Result<Vec<Uid>> {
    let mut uids = search_uids(conn, &format!("UID SEARCH {criteria}")).await?;
    uids.sort_unstable_by(|a, b| b.cmp(a));
    Ok(uids)
}

/// UIDs listed by SEARCH or SORT, failing when the tagged answer is refused.
pub(super) async fn search_uids(conn: &mut Conn, command: &str) -> Result<Vec<Uid>> {
    let mut uids = Vec::new();
    run_until_done(conn, command, |response| {
        if let Response::MailboxData(MailboxDatum::Search(found) | MailboxDatum::Sort(found)) =
            response
        {
            uids.extend(found.iter().copied());
        }
    })
    .await?;
    Ok(uids)
}

/// Runs a command, visiting untagged responses and returning the tagged OK's code.
pub(super) async fn run_until_done(
    conn: &mut Conn,
    command: &str,
    mut on_untagged: impl FnMut(&mut Response<'_>),
) -> Result<Option<ResponseCode<'static>>> {
    let tag = conn.run_command(command).await?;
    loop {
        let mut response = conn
            .read_response()
            .await?
            .ok_or(async_imap::error::Error::ConnectionLost)?;
        let completed = response.with_dependent_mut(|_, response| match response {
            Response::Done {
                tag: done,
                status,
                outcome,
            } if *done == tag => {
                Some(if *status == Status::Ok {
                    Ok(outcome.code.take().map(ResponseCode::into_owned))
                } else {
                    // Keep async-imap's command diagnostics, including response codes.
                    let text = format!("code: {:?}, info: {:?}", outcome.code, outcome.information);
                    let error = if *status == Status::No {
                        async_imap::error::Error::No(text)
                    } else {
                        async_imap::error::Error::Bad(text)
                    };
                    Err(error.into())
                })
            }
            response => {
                on_untagged(response);
                None
            }
        });
        if let Some(result) = completed {
            return result;
        }
    }
}

async fn fetch_summaries(
    conn: &mut Conn,
    uids: &[Uid],
    query: &SearchQuery,
    timeout: Duration,
    until: Option<Instant>,
) -> Result<Vec<MessageSummary>> {
    let mut by_uid = HashMap::new();
    for set in uid_sets(uids, "UID FETCH  ".len() + SUMMARY_ITEMS.len())? {
        if until.is_some_and(|until| Instant::now() >= until) {
            return Err(Error::TimeExhausted);
        }
        // The dependency's FETCH stream ends at the tag without checking its status.
        let command = format!("UID FETCH {set} {SUMMARY_ITEMS}");
        with_timeout(
            timeout,
            run_until_done(conn, &command, |response| {
                if let Response::Fetch(_, attrs) = response
                    && let Some(summary) = summary(attrs, query)
                {
                    by_uid.insert(summary.uid, summary);
                }
            }),
        )
        .await?;
    }
    Ok(uids.iter().filter_map(|uid| by_uid.remove(uid)).collect())
}

fn summary(attrs: &[AttributeValue<'_>], query: &SearchQuery) -> Option<MessageSummary> {
    let (mut uid, mut size, mut raw, mut arrival) = (None, None, None, None);
    let mut flags = MessageFlags::default();
    for attr in attrs {
        match attr {
            AttributeValue::Uid(value) => uid = Some(*value),
            AttributeValue::Rfc822Size(value) => size = Some(*value),
            AttributeValue::InternalDate(value) => arrival = Some(value.as_ref()),
            AttributeValue::Flags(values) => {
                flags =
                    MessageFlags::from_imap(values.iter().map(|flag| Flag::from(flag.as_ref())));
            }
            AttributeValue::BodySection {
                section: Some(SectionPath::Full(MessageSection::Header)),
                data: Some(hdr),
                ..
            }
            | AttributeValue::Rfc822Header(Some(hdr)) => raw = Some(hdr.as_ref()),
            _ => {}
        }
    }
    let uid = uid?;
    let headers = raw.and_then(parse::parse_headers).unwrap_or_default();
    if !query.matches(&headers) {
        return None;
    }
    Some(MessageSummary {
        uid,
        from: headers.from.into_iter().next(),
        from_clear: headers.from_clear,
        from_values: headers.from_values,
        subject: headers.subject,
        date: headers
            .date
            .or_else(|| DateTime::parse_from_str(arrival?, "%d-%b-%Y %H:%M:%S %z").ok()),
        flags,
        size,
    })
}

/// Renders only listed UIDs, sorted and deduplicated, as consecutive ranges.
pub(super) fn uid_set(uids: &[Uid]) -> String {
    let mut uids = uids.to_vec();
    uids.sort_unstable();
    uids.dedup();
    uids.chunk_by(|a, b| a.checked_add(1) == Some(*b))
        .map(|run| match run {
            [uid] => uid.to_string(),
            _ => format!("{}:{}", run[0], run[run.len() - 1]),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Splits sets at the UID count or RFC 2683's 1,000-octet command-line limit.
/// `overhead` excludes the set, tag, separating space and CRLF.
pub(super) fn uid_sets(uids: &[Uid], overhead: usize) -> Result<Vec<String>> {
    Ok(uid_chunks(uids, overhead)?
        .into_iter()
        .map(uid_set)
        .collect())
}

pub(super) fn uid_chunks(uids: &[Uid], overhead: usize) -> Result<Vec<&[Uid]>> {
    // async-imap's tags are A0000..A9999: five bytes, a space and CRLF.
    let budget = 1_000_usize.saturating_sub(overhead.saturating_add(8));
    let mut sets = Vec::new();
    let mut rest = uids;
    while !rest.is_empty() {
        let mut end = rest.len().min(UID_SET_MAX);
        while uid_set(&rest[..end]).len() > budget {
            end -= 1;
            if end == 0 {
                return Err(Error::invalid("IMAP command exceeds 1,000 octets"));
            }
        }
        sets.push(&rest[..end]);
        rest = &rest[end..];
    }
    Ok(sets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_uid_sets() {
        assert_eq!(uid_set(&[42]), "42");
        assert_eq!(uid_set(&[9, 5, 1]), "1,5,9");
        for uids in [
            vec![],
            vec![1, 2, 2, 3, 5, 9, 10],
            vec![u32::MAX, 1, u32::MAX - 1],
        ] {
            let rendered = uid_set(&uids);
            let parsed: std::collections::BTreeSet<Uid> = rendered
                .split(',')
                .filter(|s| !s.is_empty())
                .flat_map(|part| {
                    let (first, last) = part.split_once(':').unwrap_or((part, part));
                    first.parse::<Uid>().unwrap()..=last.parse::<Uid>().unwrap()
                })
                .collect();
            assert_eq!(parsed, uids.into_iter().collect(), "{rendered}");
        }
    }

    #[test]
    fn splits_by_count_and_full_command_length() {
        let consecutive: Vec<_> = (1..=201).collect();
        assert_eq!(
            uid_sets(&consecutive, 0).unwrap(),
            ["1:100", "101:200", "201"]
        );
        let sparse: Vec<_> = (0..100).map(|n| u32::MAX - n * 2).collect();
        for overhead in [14, 500, 981] {
            let sets = uid_sets(&sparse, overhead).unwrap();
            assert!(sets.len() > 1);
            assert!(sets.iter().all(|set| set.len() + overhead + 8 <= 1_000));
            assert_eq!(
                sets.iter().map(|set| set.split(',').count()).sum::<usize>(),
                100
            );
        }
        assert!(uid_sets(&[u32::MAX], 983).is_err());
    }
}
