//! A scripted IMAP server on 127.0.0.1 for the tests that need a mailbox to
//! answer.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering::SeqCst};
use std::time::Duration;

use postkeep_mail::{ImapSecurity, MailConfig, SmtpSecurity};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// A mail configuration pointing at a closed port.
pub fn unreachable_mail() -> MailConfig {
    let mut mail = MailConfig::default();
    "127.0.0.1".clone_into(&mut mail.imap.host);
    mail.imap.port = 9;
    mail.imap.security = ImapSecurity::Plaintext;
    "127.0.0.1".clone_into(&mut mail.smtp.host);
    mail.smtp.port = 9;
    mail.smtp.security = SmtpSecurity::Plaintext;
    mail.timeout = Duration::from_secs(5);
    mail
}

/// What the IMAP server of [`scripted_mail`] answers `LOGIN` with.
pub const REJECT: u8 = 0;
pub const ACCEPT: u8 = 1;
pub const BUSY: u8 = 2;

/// Accept logins but delay a pooled NOOP beyond the deadline test's budget.
pub const SLOW_NOOP: u8 = 3;

/// Advertise Gmail's extension and answer searches like `ALL_FOLDER`.
pub const GMAIL: u8 = 9;

/// Like `ALL_FOLDER`, but delay the summary fetch beyond the deadline.
pub const SLOW_FETCH: u8 = 10;

/// Drop the next UID search, then reject logins, refuse them, or accept them.
pub const DROP_AND_REJECT: u8 = 4;
pub const DROP_AND_BUSY: u8 = 5;
pub const DROP_AND_ACCEPT: u8 = 6;
/// Advertise an All folder and enough matches to exceed a selection call.
pub const ALL_FOLDER: u8 = 7;
/// Report a smaller size than the message actually has.
pub const UNDER_REPORTED_SIZE: u8 = 8;

/// A mail configuration pointing at an IMAP server on 127.0.0.1 that answers
/// `LOGIN` with `NO [AUTHENTICATIONFAILED]`, `OK` or `NO [UNAVAILABLE]`, as
/// `login` says, a search with the messages 1 to 3, and every other command
/// with `OK`. `accepted` counts the logins it takes.
///
/// With an `inbox`, its `UIDNEXT` n, it also shows an INBOX of the messages
/// with UIDs 1 to n - 1, each at the sequence number of its UID: `EXAMINE`,
/// `UID SEARCH UID a:*` and the `UID FETCH` of their headers, with a subject
/// of `message <uid>`. It has no `IDLE`, so a watcher polls.
pub async fn scripted_mail(
    login: Arc<AtomicU8>,
    accepted: Arc<AtomicUsize>,
    inbox: Option<Arc<AtomicU32>>,
) -> MailConfig {
    scripted_mail_counted(login, accepted, inbox, Arc::default()).await
}

/// Like [`scripted_mail`], with a counter for every attempted login.
pub async fn scripted_mail_counted(
    login: Arc<AtomicU8>,
    accepted: Arc<AtomicUsize>,
    inbox: Option<Arc<AtomicU32>>,
    attempts: Arc<AtomicUsize>,
) -> MailConfig {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap();
    let mut mail = unreachable_mail();
    mail.imap.port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let labels = Arc::new(AtomicUsize::new(0));
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (login, accepted) = (Arc::clone(&login), Arc::clone(&accepted));
            let inbox = inbox.clone();
            let labels = Arc::clone(&labels);
            let attempts = Arc::clone(&attempts);
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let _ = write.write_all(b"* OK ready\r\n").await;
                let mut lines = BufReader::new(read).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if line.contains(" NOOP") && login.load(SeqCst) == SLOW_NOOP {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                    }
                    if line.contains(" UID FETCH ") && login.load(SeqCst) == SLOW_FETCH {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                    }
                    if line.contains(" UID SEARCH ") || line.contains(" (UID FLAGS)") {
                        let next = match login.load(SeqCst) {
                            DROP_AND_REJECT => Some(REJECT),
                            DROP_AND_BUSY => Some(BUSY),
                            DROP_AND_ACCEPT => Some(ACCEPT),
                            _ => None,
                        };
                        if let Some(next) = next {
                            login.store(next, SeqCst);
                            break;
                        }
                    }
                    if line.contains(" LOGIN ") {
                        attempts.fetch_add(1, SeqCst);
                    }
                    let tag = line.split(' ').next().unwrap_or("*");
                    let reply = match (line.contains(" LOGIN "), login.load(SeqCst)) {
                        (true, REJECT) => format!("{tag} NO [AUTHENTICATIONFAILED] Invalid\r\n"),
                        (true, BUSY) => format!("{tag} NO [UNAVAILABLE] Try later\r\n"),
                        (true, _) => {
                            accepted.fetch_add(1, SeqCst);
                            format!("{tag} OK done\r\n")
                        }
                        (_, GMAIL) if line.contains(" CAPABILITY") => {
                            format!("* CAPABILITY IMAP4rev1 X-GM-EXT-1 MOVE\r\n{tag} OK done\r\n")
                        }
                        _ if line.contains(" CAPABILITY") => {
                            format!("* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n")
                        }
                        (_, ALL_FOLDER | GMAIL | SLOW_FETCH) if line.contains(" LIST ") => {
                            format!(
                                "* LIST (\\All) \"/\" \"All\"\r\n* LIST () \"/\" \"Archive\"\r\n* LIST () \"/\" \"INBOX\"\r\n* LIST () \"/\" \"Receipts\"\r\n{tag} OK done\r\n"
                            )
                        }
                        (_, ALL_FOLDER | GMAIL | SLOW_FETCH) if line.contains(" SELECT ") => {
                            format!("* OK [UIDVALIDITY 1] valid\r\n{tag} OK done\r\n")
                        }
                        (_, GMAIL) if line.contains(" X-GM-LABELS ") => {
                            assert!(
                                line.contains(" UID SEARCH UID 1:2 X-GM-LABELS \"Receipts\""),
                                "{line}"
                            );
                            let found = if labels.fetch_add(1, SeqCst) < 2 {
                                "2"
                            } else {
                                "1 2"
                            };
                            format!("* SEARCH {found}\r\n{tag} OK done\r\n")
                        }
                        (_, GMAIL) if line.contains(" UID MOVE ") => {
                            assert!(
                                line.contains(" UID MOVE 1 \"Receipts\"")
                                    || line.contains(" UID MOVE 1:2 \"INBOX\""),
                                "{line}"
                            );
                            format!("{tag} OK moved\r\n")
                        }
                        (_, ALL_FOLDER | GMAIL | SLOW_FETCH) if line.contains(" UID SEARCH ") => {
                            let uids = (1..=postkeep::tools::MOST_IDS + 1)
                                .map(|uid| uid.to_string())
                                .collect::<Vec<_>>()
                                .join(" ");
                            format!("* SEARCH {uids}\r\n{tag} OK done\r\n")
                        }
                        _ if login.load(SeqCst) == UNDER_REPORTED_SIZE
                            && line.contains("RFC822.SIZE") =>
                        {
                            format!("* 1 FETCH (UID 1 RFC822.SIZE 1)\r\n{tag} OK done\r\n")
                        }
                        _ if login.load(SeqCst) == UNDER_REPORTED_SIZE
                            && line.contains("BODY.PEEK[]") =>
                        {
                            // The actual body exceeds the reported size even with headroom.
                            let raw = "x".repeat(2048);
                            format!(
                                "* 1 FETCH (UID 1 FLAGS () BODY[] {{{}}}\r\n{raw})\r\n{tag} OK done\r\n",
                                raw.len()
                            )
                        }
                        _ if line.contains(" UID SEARCH ") && !line.contains(" SEARCH UID ") => {
                            format!("* SEARCH 1 2 3\r\n{tag} OK done\r\n")
                        }
                        _ => inbox.as_ref().map_or_else(
                            || format!("{tag} OK done\r\n"),
                            |next| inbox_reply(tag, &line, next.load(SeqCst)),
                        ),
                    };
                    let _ = write.write_all(reply.as_bytes()).await;
                }
            });
        }
    });
    mail
}

/// What the INBOX of [`scripted_mail`], with this `UIDNEXT`, answers `line`.
fn inbox_reply(tag: &str, line: &str, next: u32) -> String {
    let done = format!("{tag} OK done\r\n");
    if line.contains(" EXAMINE ") {
        let exists = next - 1;
        return format!(
            "* {exists} EXISTS\r\n* OK [UIDVALIDITY 1] valid\r\n* OK [UIDNEXT {next}] next\r\n\
             {tag} OK [READ-ONLY] done\r\n"
        );
    }
    if let Some((_, from)) = line.split_once(" UID SEARCH UID ") {
        let first: u32 = from.trim_end_matches(":*").parse().unwrap();
        let mut found = vec!["* SEARCH".to_owned()];
        found.extend((first..next).map(|uid| uid.to_string()));
        return format!("{}\r\n{done}", found.join(" "));
    }
    if let Some((_, rest)) = line.split_once(" UID FETCH ") {
        let (set, items) = rest.split_once(' ').unwrap();
        let section = items
            .split_once("BODY.PEEK[")
            .and_then(|(_, section)| section.split_once(']'))
            .map_or("HEADER", |(section, _)| section);
        let uids = set.split(',').flat_map(|part| {
            let (first, last) = part.split_once(':').unwrap_or((part, part));
            first.parse::<u32>().unwrap()..=last.parse::<u32>().unwrap()
        });
        let fetched = uids.map(|uid| {
            let header = format!(
                "From: sender@example.com\r\nSubject: message {uid}\r\n\
                 To: to{uid}@example.net\r\nCc: cc{uid}@example.net\r\nMessage-ID: <{uid}@example.com>\r\n\r\n"
            );
            let len = header.len();
            format!("* {uid} FETCH (UID {uid} BODY[{section}] {{{len}}}\r\n{header})\r\n")
        });
        return fetched.collect::<String>() + &done;
    }
    done
}
