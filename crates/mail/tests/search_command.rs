//! Search and set commands against a scripted IMAP server.

// Helpers outside `#[test]` functions are not covered by clippy.toml's
// `allow-*-in-tests` settings, but they are still test code.
#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use postkeep_mail::{
    Check, Credentials, DeleteMode, Error, Flag, ImapConfig, ImapSecurity, ImapSession, InFlight,
    MailClient, MailConfig, NaiveDate, Paging, Result, SearchQuery, SearchResults, SecretString,
    UID_SET_MAX,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// Starts a server with command-specific replies (`TAG` is replaced by its tag).
async fn server(
    capabilities: &'static str,
    mut answer: impl FnMut(&str) -> Option<String> + Send + 'static,
) -> (ImapSession, tokio::task::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (read, mut write) = stream.into_split();
        write.write_all(b"* OK ready\r\n").await.unwrap();
        let mut lines = BufReader::new(read).lines();
        let mut commands = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let (tag, command) = line.split_once(' ').unwrap();
            commands.push(command.to_owned());
            let answer = answer(command);
            if answer.as_deref() == Some("") {
                break;
            }
            let reply = answer.map_or_else(
                || {
                    if command.starts_with("CAPABILITY") {
                        format!("* CAPABILITY {capabilities}\r\n{tag} OK done\r\n")
                    } else if command.starts_with("SELECT") {
                        format!("* 0 EXISTS\r\n* OK [UIDVALIDITY 7] ok\r\n{tag} OK [READ-WRITE] done\r\n")
                    } else if command.starts_with("LIST") {
                        format!("* LIST () \"/\" \"Archive\"\r\n{tag} OK done\r\n")
                    } else {
                        format!("{tag} OK done\r\n")
                    }
                },
                |reply| format!("{}\r\n", reply.replace("TAG", tag)),
            );
            write.write_all(reply.as_bytes()).await.unwrap();
        }
        commands
    });
    let config = MailConfig {
        imap: ImapConfig {
            host: "127.0.0.1".to_owned(),
            port,
            security: ImapSecurity::Plaintext,
        },
        timeout: Duration::from_secs(5),
        ..MailConfig::default()
    };
    let credentials =
        Credentials::new("bob@example.com", &SecretString::from("secret".to_owned())).unwrap();
    let imap = MailClient::new(config, credentials)
        .unwrap()
        .connect_imap()
        .await
        .unwrap();
    (imap, server)
}

#[tokio::test]
async fn oversized_messages_are_refused_before_fetching_the_body() {
    let (mut imap, server) = server("IMAP4rev1", |command| {
        (command == "UID FETCH 2 (UID RFC822.SIZE)")
            .then(|| format!("* 2 FETCH (UID 2 RFC822.SIZE {})\r\nTAG OK done", u32::MAX))
    })
    .await;
    assert!(matches!(
        imap.fetch_message("INBOX", 2, Some(7)).await,
        Err(Error::MessageTooLarge)
    ));
    assert!(matches!(
        imap.fetch_attachment("INBOX", 2, Some(7), 1, 1024).await,
        Err(Error::MessageTooLarge)
    ));
    drop(imap);
    let commands = server.await.unwrap();
    assert!(!commands.iter().any(|command| command.contains("BODY.PEEK")));
}

#[tokio::test]
async fn fetch_raw_checks_the_body_when_the_reported_size_is_too_small() {
    let (mut imap, _) = server("IMAP4rev1", |command| {
        let reply = match command {
            "UID FETCH 2 (UID RFC822.SIZE)" => "RFC822.SIZE 4",
            "UID FETCH 2 (UID FLAGS BODY.PEEK[])" => "FLAGS () BODY[] {6}\r\nhello!",
            _ => return None,
        };
        // An unsolicited flags update for the same UID must not hide the requested data.
        Some(format!(
            "* 2 FETCH (UID 2 FLAGS (\\Seen))\r\n* 2 FETCH (UID 2 {reply})\r\nTAG OK done"
        ))
    })
    .await;
    assert!(matches!(
        imap.fetch_raw("INBOX", 2, Some(7), 5).await,
        Err(Error::MessageTooLarge)
    ));
    assert_eq!(
        imap.fetch_raw("INBOX", 2, Some(7), 6).await.unwrap(),
        b"hello!"
    );
}

/// Fetches only the requested fixtures, using the header section the client asks for.
fn fetched(command: &str, header: impl Fn(u32) -> String) -> Option<String> {
    let (set, items) = command.strip_prefix("UID FETCH ")?.split_once(' ')?;
    let section = items.split_once("BODY.PEEK[")?.1.split_once(']')?.0;
    let mut reply = String::new();
    for part in set.split(',') {
        let (first, last) = part.split_once(':').unwrap_or((part, part));
        for uid in first.parse::<u32>().unwrap()..=last.parse().unwrap() {
            let header = header(uid);
            write!(reply, "* {uid} FETCH (UID {uid} INTERNALDATE \"04-Oct-2026 12:00:00 +0000\" BODY[{section}] {{{}}}\r\n{header})\r\n", header.len()).unwrap();
        }
    }
    Some(reply + "TAG OK done")
}

/// Searches INBOX for mail dated on or after 1 October 2026.
async fn search(
    capabilities: &'static str,
    answer: &'static str,
) -> (Result<SearchResults>, String) {
    let (mut imap, server) = server(capabilities, move |command| {
        (command.starts_with("UID SORT") || command.starts_with("UID SEARCH"))
            .then(|| answer.to_owned())
    })
    .await;
    let since = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap();
    let result = imap
        .search("INBOX", &SearchQuery::new().since(since), Paging::default())
        .await;
    drop(imap);
    let command = server
        .await
        .unwrap()
        .into_iter()
        .find(|command| command.starts_with("UID SORT") || command.starts_with("UID SEARCH"))
        .unwrap();
    (result, command)
}

#[tokio::test]
async fn searches_sort_by_date_only_where_the_server_offers_sort() {
    let (found, command) = search("IMAP4rev1 SORT", "* SORT\r\nTAG OK done").await;
    assert_eq!(command, "UID SORT (DATE) US-ASCII SENTSINCE 1-Oct-2026");
    assert_eq!(found.unwrap().total, 0);

    let (found, command) = search("IMAP4rev1", "* SEARCH\r\nTAG OK done").await;
    assert_eq!(command, "UID SEARCH SENTSINCE 1-Oct-2026");
    assert_eq!(found.unwrap().total, 0);

    let (mut imap, server) = server("IMAP4rev1 SORT", |command| {
        if command.starts_with("UID SORT") {
            Some("* SORT 3 1 2 4\r\nTAG OK done".to_owned())
        } else if command.starts_with("UID SEARCH") {
            Some("* SEARCH 1 2 3 4\r\nTAG OK done".to_owned())
        } else {
            fetched(command, |uid| match uid {
                1 => "Date: Wed, 30 Sep 2026 12:00:00 +0000\r\n\r\n".to_owned(),
                2 | 3 => format!("Date: {uid} Oct 2026 12:00:00 +0000\r\n\r\n"),
                _ => "Subject: no date\r\n\r\n".to_owned(),
            })
        }
    })
    .await;
    let query = SearchQuery::new().since(NaiveDate::from_ymd_opt(2026, 10, 1).unwrap());
    let found = imap
        .search("INBOX", &query, Paging::default())
        .await
        .unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    let selected = imap.matching("INBOX", &query, 7, 5, until).await.unwrap();
    drop(imap);
    let commands = server.await.unwrap();
    let listed: Vec<_> = found.messages.iter().map(|summary| summary.uid).collect();
    assert_eq!((listed, selected), (vec![2, 3], vec![3, 2]));
    assert_eq!((found.total, found.estimated), (2, false));
    let fetches: Vec<_> = commands
        .iter()
        .filter(|command| command.starts_with("UID FETCH"))
        .collect();
    assert_eq!(
        fetches.len(),
        2,
        "one fetch for the page and one for the selection"
    );
    assert!(fetches[0].contains("BODY.PEEK[HEADER.FIELDS (FROM TO SUBJECT DATE)]"));
}

#[tokio::test]
async fn a_set_that_overshoots_counts_all_it_holds() {
    let (mut imap, _) = server("IMAP4rev1", |command| {
        if command.starts_with("UID SEARCH") {
            Some("* SEARCH 1 2 3 4 5 6\r\nTAG OK done".to_owned())
        } else {
            fetched(command, |uid| {
                let subject = if uid == 5 { "beaver" } else { "otter" };
                format!("Subject: {subject}\r\n\r\n")
            })
        }
    })
    .await;
    let query = SearchQuery::new().subject("otter");
    let mut pages = Vec::new();
    for offset in 0..=1 {
        let found = imap
            .search("INBOX", &query, Paging { offset, limit: 1 })
            .await
            .unwrap();
        let uids: Vec<_> = found.messages.iter().map(|summary| summary.uid).collect();
        pages.push((uids, found.total, found.estimated));
    }
    assert_eq!(pages, [(vec![6], 5, true), (vec![4], 5, true)]);
}

#[tokio::test]
async fn matching_past_its_deadline_sends_no_fetch() {
    let (mut imap, server) = server("IMAP4rev1", |command| {
        command
            .starts_with("UID SEARCH")
            .then(|| "* SEARCH 1\r\nTAG OK done".to_owned())
    })
    .await;
    let until = Instant::now().checked_sub(Duration::from_secs(1)).unwrap();
    let result = imap
        .matching("INBOX", &SearchQuery::new().subject("otter"), 7, 2, until)
        .await;
    drop(imap);
    let commands = server.await.unwrap();
    assert!(commands.iter().any(|c| c.starts_with("UID SEARCH")));
    assert!(!commands.iter().any(|c| c.starts_with("UID FETCH")));
    let error = result.unwrap_err();
    assert!(
        matches!(error, Error::TimeExhausted) && error.leaves_session_usable(),
        "{error}"
    );
}

#[tokio::test]
async fn refused_summary_fetch_discards_partial_pages_and_selections() {
    let checked = SearchQuery::new().subject("otter");
    for refused in ["NO", "BAD"] {
        let (mut imap, _) = server("IMAP4rev1", move |command| {
            if command.starts_with("UID SEARCH") {
                Some("* SEARCH 1 2\r\nTAG OK done".to_owned())
            } else {
                let partial = command.replace("UID FETCH 1:2 ", "UID FETCH 1 ");
                fetched(&partial, |_| "Subject: otter\r\n\r\n".to_owned()).map(|reply| {
                    reply.replace("TAG OK done", &format!("TAG {refused} fetch refused"))
                })
            }
        })
        .await;
        let unchecked = imap
            .search("INBOX", &SearchQuery::new(), Paging::default())
            .await;
        let page = imap.search("INBOX", &checked, Paging::default()).await;
        let until = Instant::now() + Duration::from_secs(5);
        let selected = imap.matching("INBOX", &checked, 7, 2, until).await;
        let refused_fetch = |err| match err {
            Error::Imap(async_imap::error::Error::No(reason)) => {
                refused == "NO" && reason.contains("fetch refused")
            }
            Error::Imap(async_imap::error::Error::Bad(reason)) => {
                refused == "BAD" && reason.contains("fetch refused")
            }
            _ => false,
        };
        assert!(
            unchecked.is_err_and(refused_fetch)
                && page.is_err_and(refused_fetch)
                && selected.is_err_and(refused_fetch),
            "a partial FETCH ending in {refused} must fail both kinds of page and the selection"
        );
    }
}

#[tokio::test]
async fn refused_commands_fail_the_operation() {
    for (answer, bad, expected) in [
        (
            "TAG NO no sorting now",
            false,
            r#"code: None, info: Some("no sorting now")"#,
        ),
        (
            "TAG NO [TRYCREATE] destination disappeared",
            false,
            r#"code: Some(TryCreate), info: Some("destination disappeared")"#,
        ),
        (
            "TAG BAD unknown key",
            true,
            r#"code: None, info: Some("unknown key")"#,
        ),
    ] {
        let (found, _) = search("IMAP4rev1 SORT", answer).await;
        assert!(
            match &found {
                Err(Error::Imap(async_imap::error::Error::No(text))) => !bad && text == expected,
                Err(Error::Imap(async_imap::error::Error::Bad(text))) => bad && text == expected,
                _ => false,
            },
            "{found:?}"
        );
    }
    let mut incorrect = Vec::new();
    for (capabilities, refused, permanent) in [
        ("IMAP4rev1", "UID SEARCH UID ", false),
        ("IMAP4rev1", "UID SEARCH DELETED", false),
        ("IMAP4rev1", "UID SEARCH DELETED", true),
        ("IMAP4rev1", "UID STORE ", false),
        ("IMAP4rev1 UIDPLUS", "UID EXPUNGE ", false),
        ("IMAP4rev1", "EXPUNGE", false),
    ] {
        let (mut imap, server) = server(capabilities, move |command| {
            if command.starts_with(refused) {
                Some("TAG NO [SERVERBUG] try again later".to_owned())
            } else if command.starts_with("UID SEARCH UID ") {
                Some("* SEARCH 1 2\r\nTAG OK done".to_owned())
            } else if command == "UID SEARCH DELETED" {
                Some("* SEARCH\r\nTAG OK done".to_owned())
            } else {
                None
            }
        })
        .await;
        let result = if permanent {
            imap.delete_message("INBOX", 1, None, DeleteMode::Permanent)
                .await
                .map(|_| ())
        } else if refused == "UID STORE " {
            imap.set_flags(
                "INBOX",
                &[1, 2],
                None,
                &[(Flag::Seen, true)],
                Check::Exists,
                &mut None,
            )
            .await
            .map(|_| ())
        } else {
            imap.move_messages("INBOX", &[1, 2], None, "Archive", Check::Exists, &mut None)
                .await
                .map(|_| ())
        };
        let rejected = matches!(&result, Err(Error::Imap(async_imap::error::Error::No(text))) if text.contains("SERVERBUG"));
        drop(imap);
        let commands = server.await.unwrap();
        let stopped_at = commands
            .iter()
            .rposition(|command| command.starts_with(refused))
            .unwrap();
        if !rejected || commands.len() != stopped_at + 1 {
            incorrect.push(format!(
                "{refused}, permanent={permanent}: {result:?}; {commands:?}"
            ));
        }
    }
    assert_eq!(incorrect, Vec::<String>::new());
}

#[tokio::test]
async fn moves_sets_with_copyuid_from_tagged_and_untagged_answers() {
    let overflowing = "* OK [COPYUID 11 1 8] done\r\n".repeat(UID_SET_MAX + 1) + "TAG OK done";
    let unrelated = "* OK [UIDNEXT 31] next\r\n".repeat(UID_SET_MAX + 1)
        + "* OK [COPYUID 11 5 30] done\r\n* OK [COPYUID 11 1 8] done\r\nTAG OK [COPYUID 11 2 9] done";
    for (capabilities, reply, validity) in [
        (
            "IMAP4rev1 UIDPLUS",
            "TAG OK [COPYUID 11 1:2,5 8:9,30] done",
            Some(11),
        ),
        (
            "IMAP4rev1 MOVE UIDPLUS",
            "* OK [COPYUID 11 1:2,5 8:9,30] done\r\nTAG OK done",
            Some(11),
        ),
        ("IMAP4rev1 MOVE UIDPLUS", unrelated.as_str(), Some(11)),
        ("IMAP4rev1 MOVE UIDPLUS", overflowing.as_str(), None),
    ] {
        let reply = reply.to_owned();
        let (mut imap, server) = server(capabilities, move |command| {
            if command.starts_with("UID SEARCH UID") {
                Some("* SEARCH 1 2 5\r\nTAG OK done".to_owned())
            } else if command.starts_with("UID COPY") || command.starts_with("UID MOVE") {
                Some(reply.clone())
            } else {
                None
            }
        })
        .await;
        let changed = imap
            .move_messages(
                "INBOX",
                &[5, 2, 1, 99],
                Some(7),
                "Archive",
                Check::Exists,
                &mut None,
            )
            .await
            .unwrap();
        assert_eq!(changed.uid_validity, Some(7));
        assert_eq!(changed.done, [5, 2, 1]);
        assert_eq!(changed.missing, [99]);
        assert_eq!(changed.destination_uid_validity, validity);
        assert_eq!(
            changed.new_uids,
            if validity.is_some() {
                std::collections::HashMap::from([(1, 8), (2, 9), (5, 30)])
            } else {
                std::collections::HashMap::new()
            }
        );
        drop(imap);
        let commands = server.await.unwrap();
        let mutations: Vec<_> = commands
            .iter()
            .filter(|c| c.starts_with("UID ") && !c.starts_with("UID SEARCH"))
            .map(String::as_str)
            .collect();
        if capabilities.contains("MOVE") {
            assert_eq!(mutations, ["UID MOVE 1:2,5 \"Archive\""]);
        } else {
            assert_eq!(
                mutations,
                [
                    "UID COPY 1:2,5 \"Archive\"",
                    "UID STORE 1:2,5 +FLAGS.SILENT (\\Deleted)",
                    "UID EXPUNGE 1:2,5"
                ]
            );
        }
    }
}

/// The sparse sets used to force split commands are comma-separated, not ranges.
fn echo_uid_search(command: &str) -> Option<String> {
    command
        .strip_prefix("UID SEARCH UID ")
        .map(|set| format!("* SEARCH {}\r\nTAG OK done", set.replace(',', " ")))
}

#[tokio::test]
async fn without_uidplus_expunges_only_when_no_other_uid_is_deleted() {
    for uids in [vec![1], vec![1, 2]] {
        for (foreign, late) in [(true, false), (true, true), (false, false), (false, true)] {
            let mut marked = false;
            let (mut imap, server) = server("IMAP4rev1", move |command| {
                if command.starts_with("UID STORE") {
                    marked = true;
                }
                if command == "UID SEARCH DELETED" {
                    Some(
                        if !foreign && late && marked {
                            "TAG NO [SERVERBUG] try again later"
                        } else if foreign && (!late || marked) {
                            "* SEARCH 1 9\r\nTAG OK done"
                        } else {
                            "* SEARCH\r\nTAG OK done"
                        }
                        .to_owned(),
                    )
                } else if command.starts_with("UID SEARCH UID") {
                    Some("* SEARCH 1 2\r\nTAG OK done".to_owned())
                } else {
                    None
                }
            })
            .await;
            let result = imap
                .move_messages("INBOX", &uids, None, "Archive", Check::Exists, &mut None)
                .await;
            if foreign {
                assert!(
                    matches!(&result, Err(Error::Unsupported(reason))
                    if reason.contains("copies may now be in the destination; search it before calling again") == late),
                    "{result:?}"
                );
            } else if late {
                assert!(
                    matches!(&result, Err(Error::Imap(async_imap::error::Error::No(text))) if text.contains("SERVERBUG")),
                    "{result:?}"
                );
            } else {
                assert_eq!(result.unwrap().done, uids);
            }
            drop(imap);
            let commands = server.await.unwrap();
            assert_eq!(commands.iter().any(|c| c == "EXPUNGE"), !foreign && !late);
            assert_eq!(
                commands.iter().any(|c| c.starts_with("UID COPY")),
                !foreign || late
            );
            let stores: Vec<_> = commands
                .iter()
                .filter(|c| c.starts_with("UID STORE"))
                .collect();
            if late {
                let set = if uids.len() == 1 { "1" } else { "1:2" };
                assert_eq!(
                    stores,
                    [
                        &format!("UID STORE {set} +FLAGS.SILENT (\\Deleted)"),
                        &format!("UID STORE {set} -FLAGS.SILENT (\\Deleted)")
                    ]
                );
            } else if foreign {
                assert_eq!(stores, Vec::<&String>::new());
            } else {
                assert_eq!(stores.len(), 1);
                assert!(stores[0].contains("+FLAGS.SILENT (\\Deleted)"));
            }
        }
    }

    let uids: Vec<_> = (0..100).map(|n| 4_000_000_000 + n * 2).collect();
    let deleted = *uids.last().unwrap();
    let (mut imap, script) = server("IMAP4rev1", move |command| {
        if command == "UID SEARCH DELETED" {
            return Some(format!("* SEARCH {deleted}\r\nTAG OK done"));
        }
        echo_uid_search(command)
    })
    .await;
    let result = imap
        .move_messages("INBOX", &uids, None, "Archive", Check::Exists, &mut None)
        .await;
    drop(imap);
    let writes: Vec<_> = script
        .await
        .unwrap()
        .into_iter()
        .filter(|c| c.starts_with("UID COPY") || c.starts_with("UID STORE") || c == "EXPUNGE")
        .collect();
    assert!(
        writes.is_empty(),
        "a UID in the later chunk was already deleted: {writes:?}"
    );
    assert!(matches!(result, Err(Error::Unsupported(reason)) if !reason.contains("copies may")));
}

#[tokio::test]
async fn set_calls_check_limits_and_missing_uids_before_changes() {
    let (mut imap, server) = server("IMAP4rev1 MOVE UIDPLUS", |command| {
        command
            .starts_with("UID SEARCH UID")
            .then(|| "* SEARCH\r\nTAG OK done".to_owned())
    })
    .await;
    assert!(matches!(
        imap.find_messages("INBOX", &[1; UID_SET_MAX + 1], None, Check::Exists)
            .await,
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        imap.find_messages("INBOX", &[0], None, Check::Exists).await,
        Err(Error::InvalidInput(_))
    ));
    let missing = imap
        .move_messages(
            "INBOX",
            &[1, 1],
            Some(7),
            "Archive",
            Check::Exists,
            &mut None,
        )
        .await
        .unwrap();
    assert_eq!(missing.missing, [1]);
    assert_eq!(missing.done, []);
    assert!(matches!(
        imap.move_message("INBOX", 1, None, "Archive").await,
        Err(Error::MessageNotFound { uid: 1, .. })
    ));
    drop(imap);
    assert!(
        !server
            .await
            .unwrap()
            .iter()
            .any(|c| c.starts_with("UID MOVE"))
    );
}

#[tokio::test]
async fn set_calls_check_flags_and_labels() {
    let (mut imap, script) = server("IMAP4rev1 X-GM-EXT-1", |command| match command {
        "UID FETCH 1:3 (UID FLAGS)" | "UID FETCH 2 (UID FLAGS)" => Some(
            "* 1 FETCH (UID 1 FLAGS ())\r\n* 2 FETCH (UID 2)\r\n* 2 FETCH (UID 2 FLAGS (\\Seen \\Answered))\r\n* 4 FETCH (UID 99 FLAGS (\\Seen))\r\nTAG OK done".to_owned(),
        ),
        "UID FETCH 4 (UID FLAGS)" => Some("* 4 FETCH (UID 4)\r\nTAG OK done".to_owned()),
        "UID SEARCH UID 1:2 X-GM-LABELS \"Receipts\"" => Some("* SEARCH 2 99\r\nTAG OK done".to_owned()),
        cmd if cmd.starts_with("UID SEARCH UID ") => Some("* SEARCH 1 2 99\r\nTAG OK done".to_owned()),
        _ => None,
    }).await;
    let flags = [(Flag::Seen, true)];
    let check = Check::Flags(&flags);
    let changed = imap
        .set_flags("INBOX", &[1, 2, 3], Some(7), &flags, check, &mut None)
        .await
        .unwrap();
    let found = imap
        .find_messages("INBOX", &[1, 2, 3], Some(7), check)
        .await
        .unwrap();
    for result in [changed, found] {
        assert_eq!(
            (&*result.done, &*result.already, &*result.missing),
            (&[1][..], &[2][..], &[3][..])
        );
    }
    let mut progress = None;
    let missing_flags = imap
        .set_flags("INBOX", &[4], Some(7), &flags, check, &mut progress)
        .await;
    assert!(
        matches!(missing_flags, Err(Error::Parse(4))),
        "{missing_flags:?}"
    );
    assert!(progress.is_none());
    imap.set_flag("INBOX", 2, Some(7), Flag::Answered, true)
        .await
        .unwrap();
    let found = imap
        .find_messages("INBOX", &[1, 2], Some(7), Check::Label("Receipts"))
        .await
        .unwrap();
    assert_eq!((&*found.done, &*found.already), (&[1][..], &[2][..]));
    drop(imap);
    let commands = script.await.unwrap();
    assert_eq!(
        commands
            .iter()
            .filter(|c| c.starts_with("UID STORE"))
            .collect::<Vec<_>>(),
        ["UID STORE 1 +FLAGS.SILENT (\\Seen)"]
    );
}

#[tokio::test]
async fn set_flags_retains_the_check_and_the_failed_command() {
    for (cut, no, expected) in [
        ("FETCH", false, None),
        ("STORE", false, Some(InFlight::Unanswered)),
        ("STORE", true, Some(InFlight::Partial)),
    ] {
        let (mut imap, script) = server("IMAP4rev1", move |command| {
            if command.starts_with(&format!("UID {cut}")) {
                return Some(if no {
                    "TAG NO refused".to_owned()
                } else {
                    String::new()
                });
            }
            match command {
                "UID FETCH 1:3 (UID FLAGS)" => Some(
                    "* 1 FETCH (UID 1 FLAGS ())\r\n* 2 FETCH (UID 2 FLAGS (\\Seen))\r\nTAG OK done"
                        .to_owned(),
                ),
                "UID SEARCH UID 1:3" if cut == "FETCH" => Some(String::new()),
                "UID SEARCH UID 1:3" => Some("* SEARCH 1 2\r\nTAG OK done".to_owned()),
                _ => None,
            }
        })
        .await;
        let flags = [(Flag::Seen, true)];
        let mut progress = None;
        let error = imap
            .set_flags(
                "INBOX",
                &[1, 2, 3],
                Some(7),
                &flags,
                Check::Flags(&flags),
                &mut progress,
            )
            .await
            .unwrap_err();
        assert_eq!(error.leaves_session_usable(), no, "{error:?}");
        drop(imap);
        let commands = script.await.unwrap();
        assert_eq!(
            progress.as_ref().map(|p| p.in_flight),
            expected,
            "{commands:?}"
        );
        if let Some(p) = progress {
            assert_eq!((p.confirmed, p.carried), (0, 1));
            assert_eq!(
                (&*p.changed.already, &*p.changed.missing),
                (&[2][..], &[3][..])
            );
        }
    }
}

#[tokio::test]
async fn set_flags_finishes_all_pairs_per_chunk_and_resets_in_flight() {
    let uids: Vec<_> = (0..100).map(|n| 4_000_000_000 + n * 2).collect();
    let mut stores = 0;
    let (mut imap, script) = server("IMAP4rev1", move |command| {
        if let Some(reply) = echo_uid_search(command) {
            return Some(reply);
        }
        if command.starts_with("UID STORE") {
            stores += 1;
            (stores == 3).then(String::new)
        } else {
            None
        }
    })
    .await;
    let mut progress = None;
    let flags = [(Flag::Seen, true), (Flag::Flagged, true)];
    let error = imap
        .set_flags("INBOX", &uids, None, &flags, Check::Exists, &mut progress)
        .await
        .unwrap_err();
    assert!(!error.leaves_session_usable());
    drop(imap);
    let commands = script.await.unwrap();
    let stores: Vec<_> = commands
        .iter()
        .filter_map(|c| c.strip_prefix("UID STORE ")?.split_once(' '))
        .collect();
    let progress = progress.unwrap();
    assert_eq!(progress.confirmed, stores[0].0.split(',').count());
    assert_eq!(progress.carried, stores[2].0.split(',').count());
    assert_eq!(progress.confirmed + progress.carried, 100);
    assert_eq!(stores[0].0, stores[1].0);
    assert_eq!(progress.in_flight, InFlight::Unanswered);
}

#[tokio::test]
async fn set_flags_with_a_second_pair_refused_is_partial() {
    let (mut imap, script) = server("IMAP4rev1", |command| match command {
        "UID SEARCH UID 1" => Some("* SEARCH 1\r\nTAG OK done".to_owned()),
        "UID STORE 1 +FLAGS.SILENT (\\Flagged)" => Some("TAG NO refused".to_owned()),
        _ => None,
    })
    .await;
    let mut progress = None;
    let flags = [(Flag::Seen, true), (Flag::Flagged, true)];
    assert!(
        imap.set_flags("INBOX", &[1], None, &flags, Check::Exists, &mut progress)
            .await
            .is_err()
    );
    let p = progress.unwrap();
    assert_eq!(
        (p.confirmed, p.carried, p.in_flight),
        (0, 1, InFlight::Partial)
    );
    drop(imap);
    assert!(
        script
            .await
            .unwrap()
            .iter()
            .any(|c| c == "UID STORE 1 +FLAGS.SILENT (\\Seen)")
    );
}

#[tokio::test]
async fn refused_transfer_never_reports_unconfirmed_new_uids() {
    for (capabilities, uids, refused, expected) in [
        ("IMAP4rev1 UIDPLUS", &[1][..], "STORE", InFlight::Partial),
        ("IMAP4rev1 UIDPLUS", &[1][..], "COPY", InFlight::Refused),
        (
            "IMAP4rev1 MOVE UIDPLUS",
            &[1, 2][..],
            "MOVE",
            InFlight::Partial,
        ),
    ] {
        let (mut imap, script) = server(capabilities, move |command| {
            if command.starts_with(&format!("UID {refused}")) {
                Some(
                    if refused == "MOVE" {
                        "* OK [COPYUID 11 1 8] copied\r\nTAG NO refused"
                    } else {
                        "TAG NO refused"
                    }
                    .to_owned(),
                )
            } else if command.starts_with("UID COPY") {
                Some("TAG OK [COPYUID 11 1 8] copied".to_owned())
            } else if command.starts_with("UID SEARCH UID") {
                Some("* SEARCH 1 2\r\nTAG OK done".to_owned())
            } else {
                None
            }
        })
        .await;
        let mut progress = None;
        assert!(
            imap.move_messages("INBOX", uids, None, "Archive", Check::Exists, &mut progress)
                .await
                .is_err()
        );
        drop(imap);
        let commands = script.await.unwrap();
        assert!(
            commands
                .last()
                .unwrap()
                .starts_with(&format!("UID {refused}")),
            "{commands:?}"
        );
        let p = progress.unwrap();
        assert_eq!(
            (p.confirmed, p.carried, p.in_flight),
            (0, uids.len(), expected)
        );
        assert!(p.changed.new_uids.is_empty());
    }
}

#[tokio::test]
async fn conflicting_copyuids_withhold_every_new_id_across_chunks() {
    let uids: Vec<_> = (0..100).map(|n| 4_000_000_000 + n * 2).collect();
    for different_validity in [false, true] {
        let mut moves = 0;
        let (mut imap, script) = server("IMAP4rev1 MOVE UIDPLUS", move |command| {
            if let Some(reply) = echo_uid_search(command) {
                return Some(reply);
            }
            if let Some((set, _)) = command
                .strip_prefix("UID MOVE ")
                .and_then(|rest| rest.split_once(' '))
            {
                moves += 1;
                let n = set.split(',').count();
                let validity = if moves == 2 && different_validity {
                    12
                } else {
                    11
                };
                let first = if moves == 2 && different_validity {
                    200
                } else {
                    1
                };
                Some(format!(
                    "TAG OK [COPYUID {validity} {set} {first}:{}] moved",
                    first + n - 1
                ))
            } else {
                None
            }
        })
        .await;
        let changed = imap
            .move_messages("INBOX", &uids, None, "Archive", Check::Exists, &mut None)
            .await
            .unwrap();
        assert_eq!(changed.done, uids);
        assert!(changed.new_uids.is_empty());
        assert_eq!(changed.destination_uid_validity, None);
        drop(imap);
        assert_eq!(
            script
                .await
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("UID MOVE"))
                .count(),
            2
        );
    }
}
