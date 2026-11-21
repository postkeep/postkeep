//! Checks Gmail over IMAP with an app password, through the Gmail preset,
//! against a live account (runbook: CONTRIBUTING.md). Ignored by default, and
//! it does nothing unless `POSTKEEP_LIVE_GMAIL_ADDRESS_FILE` and
//! `POSTKEEP_LIVE_GMAIL_PASSWORD_FILE` name files with the address and the app
//! password. `POSTKEEP_LIVE_GMAIL_IDLE=1` adds the 26 minute IDLE check, and
//! `POSTKEEP_LIVE_GMAIL_GREENMAIL=1` rehearses the test on a local GreenMail.
//!
//! The account is a real mailbox, so the test touches only what it made: at
//! most three messages, two sent from the account to itself and a copy of one
//! of them appended by hand, with a random marker in the subject. Every
//! search, move, flag and delete is limited to the UIDs that the marker found
//! in this run (`Hits`); `Run::cleanup` removes them at the end and after a
//! failure. A run that was killed leaves its messages: its marker is printed
//! first, and `POSTKEEP_LIVE_GMAIL_CLEANUP_MARKER=<marker>` runs only the
//! cleanup for it. The address is printed as `<account>`, the password never.

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]
#![allow(clippy::panic, clippy::print_stdout, reason = "test code")]

use std::fmt::Debug;
use std::panic::{AssertUnwindSafe, resume_unwind};
use std::sync::atomic::{AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use async_imap::types::{Fetch, Name, NameAttribute};
use futures::{FutureExt, TryStreamExt};
use postkeep_mail::normalize_app_password;
use postkeep_mail::{Credentials, DeleteMode, EmailAddress, ImapPreset, ImapSecurity, MailClient};
use postkeep_mail::{OutgoingMessage, SecretString, SendOptions, SentCopy, SmtpSecurity};
use secrecy::ExposeSecret;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{net::TcpStream, time::sleep};

trait Io: AsyncRead + AsyncWrite + Unpin + Send + Debug {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Debug> Io for T {}
type Imap = async_imap::Session<Box<dyn Io>>;

/// `.await.unwrap()`, to keep the IMAP calls short.
macro_rules! ok {
    ($call:expr) => {
        $call.await.unwrap()
    };
}

/// Lowercase texts that are never printed, and what replaces them.
static HIDDEN: OnceLock<Vec<(String, &str)>> = OnceLock::new();

/// `text` with every hidden text replaced, whatever its case.
fn redact(text: &str) -> String {
    let mut text = text.to_owned();
    for (needle, with) in HIDDEN.get().into_iter().flatten() {
        let (lower, mut out, mut from) = (text.to_ascii_lowercase(), String::new(), 0);
        for (at, _) in lower.match_indices(needle.as_str()) {
            out = out + &text[from..at] + with;
            from = at + needle.len();
        }
        text = out + &text[from..];
    }
    text
}

macro_rules! say {
    ($($arg:tt)*) => { println!("{}", redact(&format!($($arg)*))) };
}

/// UIDs in one folder that this run's marker found. `uids` and `set` are the
/// only input of the calls that change anything. A run makes three messages
/// (two sent, one appended); even if a server filed each sent message twice, as
/// sent and as received, a folder would hold five. More than seven hits mean
/// that the search matched something else.
struct Hits {
    folder: String,
    found: Vec<u32>,
}

impl Hits {
    fn uids(&self) -> &[u32] {
        let n = self.found.len();
        assert!((1..=7).contains(&n), "{n} hits");
        &self.found
    }

    fn set(&self) -> String {
        self.uids()
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// The marker of a run: `pkl` and 32 lowercase hex digits.
fn valid_marker(text: &str) -> bool {
    let hex = text.strip_prefix("pkl").unwrap_or_default();
    hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

struct Run {
    marker: String,
    client: MailClient,
    password: String,
    local: bool,
    with_idle: bool,
    cleanup_only: bool,
    /// How many messages the run has made: sent, or appended.
    made: AtomicU8,
    /// The Message-IDs of what was sent: message A, then message B.
    sent: [OnceLock<String>; 2],
}

impl Run {
    /// `None` when the files are not named: the test then does nothing.
    fn from_env() -> Option<Self> {
        let var = |name| std::env::var_os(name);
        let (Some(address), Some(secret)) = (
            var("POSTKEEP_LIVE_GMAIL_ADDRESS_FILE"),
            var("POSTKEEP_LIVE_GMAIL_PASSWORD_FILE"),
        ) else {
            return None;
        };
        let profile = std::env::var("NEXTEST_PROFILE");
        assert_ne!(
            profile.as_deref(),
            Ok("ci"),
            "the ci profile ends a test after two minutes, and a killed run does not clean up"
        );
        std::panic::set_hook(Box::new(|info| println!("{}", redact(&info.to_string()))));
        let read = |path| std::fs::read_to_string(path).expect("a file can be read");
        let (address, secret) = (read(address), SecretString::from(read(secret)));
        let credentials = Credentials::new(&address, &secret).unwrap();
        let password = normalize_app_password(secret.expose_secret());
        let password = password.expose_secret().to_owned();

        // Hidden: the address, and, unless it is short enough to hide more than
        // the address, its local part as written and without dots, for any
        // domain: Gmail ignores dots and may answer with another form.
        let account = credentials.email();
        let local_part = account.split('@').next().unwrap_or(account);
        let dotless = local_part.replace('.', "");
        let parts = [local_part, &dotless]
            .into_iter()
            .filter(|t| t.chars().count() >= 4);
        let names = std::iter::once(account).chain(parts).map(str::to_owned);
        let mut hidden: Vec<_> = names
            .map(|t| (t.to_ascii_lowercase(), "<account>"))
            .collect();
        hidden.push((password.to_ascii_lowercase(), "<password>"));
        hidden.retain(|(text, _)| !"<account><password>".contains(text.as_str()));
        HIDDEN.set(hidden).unwrap();

        let cleanup_marker = var("POSTKEEP_LIVE_GMAIL_CLEANUP_MARKER");
        let marker = cleanup_marker.as_ref().map_or_else(
            || format!("pkl{}", uuid::Uuid::new_v4().simple()),
            |m| {
                let marker = m.to_str().filter(|m| valid_marker(m));
                marker
                    .expect("the cleanup marker is pkl and 32 lowercase hex digits")
                    .to_owned()
            },
        );
        let local = var("POSTKEEP_LIVE_GMAIL_GREENMAIL").is_some_and(|v| v == "1");
        let mut config = ImapPreset::Gmail.config();
        if local {
            (config.imap.host, config.smtp.host) = ("127.0.0.1".to_owned(), "127.0.0.1".to_owned());
            (config.imap.port, config.smtp.port) = (3143, 3025);
            config.imap.security = ImapSecurity::Plaintext;
            config.smtp.security = SmtpSecurity::Plaintext;
        }
        Some(Self {
            marker,
            client: MailClient::new(config, credentials).unwrap(),
            password,
            local,
            with_idle: var("POSTKEEP_LIVE_GMAIL_IDLE").is_some_and(|v| v == "1"),
            cleanup_only: cleanup_marker.is_some(),
            // Cleanup only: nothing may be sent, and the cleanup has work.
            made: AtomicU8::new(if cleanup_marker.is_some() { 3 } else { 0 }),
            sent: [OnceLock::new(), OnceLock::new()],
        })
    }

    /// Waits are scaled down for the rehearsal.
    const fn pause(&self, secs: u64) -> Duration {
        Duration::from_millis(secs * if self.local { 50 } else { 1000 })
    }

    /// An IMAP client that is connected, and not logged in.
    async fn connect(&self) -> async_imap::Client<Box<dyn Io>> {
        let imap = &self.client.config().imap;
        let tcp = ok!(TcpStream::connect((imap.host.as_str(), imap.port)));
        let stream: Box<dyn Io> = if imap.security == ImapSecurity::Tls {
            let roots = webpki_roots::TLS_SERVER_ROOTS.to_vec();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(rustls::RootCertStore { roots })
                .with_no_client_auth();
            let host = rustls::pki_types::ServerName::try_from(imap.host.clone()).unwrap();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            Box::new(ok!(connector.connect(host, tcp)))
        } else {
            Box::new(tcp)
        };
        let mut client = async_imap::Client::new(stream);
        ok!(client.read_response()).expect("the server greets first");
        client
    }

    async fn session(&self) -> Imap {
        let user = self.client.credentials().email();
        let session = self.connect().await.login(user, &self.password).await;
        session.map_err(|(err, _)| err).unwrap()
    }

    /// The subject of message `tag`: the marker alone is one word, the marker
    /// with the tag another, so a search finds the run or one message.
    fn subject(&self, tag: &str) -> String {
        format!("postkeep live test {} {}{tag}", self.marker, self.marker)
    }

    /// The UIDs in `folder` whose subject has the word `marker` + `tag`.
    /// Polls until `want` are there, or 90 s have passed.
    async fn find(&self, imap: &mut Imap, folder: &str, tag: &str, want: usize) -> Hits {
        let word = format!("{}{tag}", self.marker);
        let deadline = Instant::now() + self.pause(90);
        loop {
            ok!(imap.examine(folder));
            let uids = ok!(imap.uid_search(format!("SUBJECT {word}")));
            if uids.len() >= want || Instant::now() >= deadline {
                let mut uids: Vec<_> = uids.into_iter().collect();
                uids.sort_unstable();
                let folder = folder.to_owned();
                return Hits {
                    folder,
                    found: uids,
                };
            }
            sleep(self.pause(2)).await;
        }
    }

    /// Where message `tag` is now: per folder, how many, and on Gmail the
    /// system labels (X-GM-LABELS).
    async fn survey(&self, imap: &mut Imap, tag: &str) -> String {
        let mut found = Vec::new();
        for (role, name) in roles(imap, false).await {
            let hits = self.find(imap, &name, tag, 0).await;
            let labels = if self.local || hits.found.is_empty() {
                Vec::new()
            } else {
                labels(imap, &hits).await
            };
            found.push(format!("{role} {} {labels:?}", hits.found.len()));
        }
        found.join(", ")
    }

    /// Counts a message made: three at most, sent or appended.
    fn make(&self) {
        assert!(
            self.made.fetch_add(1, Relaxed) < 3,
            "at most three messages"
        );
    }

    /// Sends message `tag` ("a" or "b") to the account itself through the
    /// preset, which must not append a copy, unless a step before did, and
    /// returns its Message-ID.
    async fn send_once(&self, tag: &str) -> String {
        let slot = &self.sent[usize::from(tag == "b")];
        if let Some(id) = slot.get() {
            return id.clone();
        }
        self.make();
        let message = OutgoingMessage {
            to: vec![EmailAddress::new(self.client.credentials().email())],
            subject: self.subject(tag),
            text_body: "Sent by the postkeep live test, which deletes it again.".to_owned(),
            ..OutgoingMessage::default()
        };
        let sent = ok!(self
            .client
            .send(&message, SendOptions { save_to_sent: true }));
        assert_eq!(sent.sent_copy, SentCopy::ByServer);
        slot.set(sent.message_id.clone()).unwrap();
        sent.message_id
    }

    /// `send_once`, then waits until INBOX has the message. Returns its
    /// Message-ID and its hits in INBOX.
    async fn deliver(&self, imap: &mut Imap, tag: &str) -> (String, Hits) {
        let id = self.send_once(tag).await;
        let inbox = self.find(imap, "INBOX", tag, 1).await;
        assert!(!inbox.found.is_empty(), "message {tag} did not reach INBOX");
        (id, inbox)
    }

    /// The copies of message `tag` in `sent`, by subject and by Message-ID,
    /// 5 s and 60 s later.
    async fn copies(&self, imap: &mut Imap, sent: &str, tag: &str, id: &str) -> String {
        let mut counts = Vec::new();
        for secs in [5, 55] {
            sleep(self.pause(secs)).await;
            let by_subject = self.find(imap, sent, tag, 0).await.found.len();
            let by_id = ok!(imap.uid_search(format!("HEADER Message-ID \"{id}\""))).len();
            counts.push(format!("{by_subject} by subject, {by_id} by Message-ID"));
        }
        counts.join("; after 60 s: ")
    }

    /// Steps 1 and 2: the capabilities and the special folders.
    async fn server(&self) {
        let imap = &mut self.session().await;
        let capabilities = ok!(imap.capabilities());
        let mut names: Vec<_> = capabilities.iter().map(|c| format!("{c:?}")).collect();
        names.sort();
        say!("step 1: CAPABILITY {}", names.join(" "));
        roles(imap, true).await;
    }

    /// Step 3: the Sent copy that Gmail makes of message A.
    async fn sent_copy(&self) {
        let imap = &mut self.session().await;
        let sent = sent_folder(imap).await;
        let id = self.send_once("a").await;
        let copies = self.copies(imap, &sent, "a", &id).await;
        say!("step 3: copies of A in Sent after 5 s: {copies} (expected 1)");
    }

    /// Step 4: what Gmail does with a copy of message B appended by hand, as
    /// `save_to_sent` would have done. Step 6 comes first and takes B out of
    /// INBOX, which leaves its Sent copy as it was.
    async fn append(&self) {
        let imap = &mut self.session().await;
        let sent = sent_folder(imap).await;
        let id = self.send_once("b").await;
        let own = self.find(imap, &sent, "b", 1).await.found.len();
        let (user, date) = (
            self.client.credentials().email(),
            chrono::Utc::now().to_rfc2822(),
        );
        let subject = self.subject("b");
        let raw = format!(
            "From: {user}\r\nTo: {user}\r\nSubject: {subject}\r\nDate: {date}\r\nMessage-ID: <{id}>\r\n\r\nB\r\n"
        );
        self.make();
        ok!(imap.append(&sent, Some("(\\Seen)"), None, raw));
        let copies = self.copies(imap, &sent, "b", &id).await;
        say!("step 4: B had {own} copy in Sent; with one appended by hand, after 5 s: {copies}");
    }

    /// Step 5: a delete of message A with `Trash` through the library.
    async fn trash(&self) {
        let imap = &mut self.session().await;
        let capabilities = ok!(imap.capabilities());
        if !(capabilities.has_str("MOVE") || capabilities.has_str("UIDPLUS")) {
            // Without both, the library copies and sends a plain EXPUNGE.
            return say!("step 5: skipped, the server has neither MOVE nor UIDPLUS");
        }
        let (_, inbox) = self.deliver(imap, "a").await;
        say!("step 5: A before: {}", self.survey(imap, "a").await);
        let mut session = ok!(self.client.connect_imap());
        for uid in inbox.uids() {
            ok!(session.delete_message("INBOX", *uid, None, DeleteMode::Trash));
        }
        ok!(session.logout());
        say!(
            "step 5: A after a Trash delete: {}",
            self.survey(imap, "a").await
        );
    }

    /// Step 6: what `\Deleted` and `UID EXPUNGE` in INBOX do to message B,
    /// which is what a permanent delete sends.
    async fn permanent(&self) {
        let imap = &mut self.session().await;
        let (_, inbox) = self.deliver(imap, "b").await;
        sleep(self.pause(5)).await;
        say!("step 6: B before: {}", self.survey(imap, "b").await);
        if erase(imap, &inbox).await {
            say!(
                "step 6: B after UID EXPUNGE in INBOX: {}",
                self.survey(imap, "b").await
            );
        } else {
            say!("step 6: skipped, the server has no UIDPLUS");
        }
    }

    /// Step 7: what the server answers to a wrong password.
    async fn wrong_password(&self) {
        let user = self.client.credentials().email();
        match self.connect().await.login(user, "zzzzzzzzzzzzzzzz").await {
            Err((async_imap::error::Error::No(answer), _)) => say!("step 7: NO {answer}"),
            Err((err, _)) => say!("step 7: {err}"),
            Ok(_) => panic!("step 7: a wrong password was accepted"),
        }
    }

    /// Step 9: IDLE for 26 minutes, renewed after 25.
    async fn idle(&self) {
        let mut imap = ok!(self.client.connect_imap());
        ok!(imap.examine("INBOX"));
        let (start, total) = (Instant::now(), self.pause(26 * 60));
        while start.elapsed() < total {
            let wait = self
                .pause(25 * 60)
                .min(total.saturating_sub(start.elapsed()));
            let (next, event) = ok!(imap.idle(wait, std::future::pending()));
            say!(
                "step 9: IDLE returned {event:?} after {:?}",
                start.elapsed()
            );
            imap = next;
        }
        ok!(imap.logout());
    }

    /// Runs every step, which opens a session of its own, even when one fails (a
    /// login too), so that one run tells as much as possible; fails at the end
    /// if any did. Message A serves steps 3 and 5, message B steps 6 and 4, and
    /// the copy appended in step 4 is the third message.
    async fn steps(&self) {
        let mut failed = Vec::new();
        macro_rules! step {
            ($name:literal, $call:expr) => {
                if AssertUnwindSafe($call).catch_unwind().await.is_err() {
                    failed.push($name);
                }
            };
        }
        step!("1 and 2", self.server());
        step!("3", self.sent_copy());
        step!("5", self.trash());
        step!("6", self.permanent());
        step!("4", self.append());
        let left = self.cleanup(Duration::ZERO).await;
        assert!(
            left.is_empty(),
            "stopping before the checks that can lock the account"
        );
        step!("7", self.wrong_password());
        if self.with_idle {
            step!("9", self.idle());
        }
        assert!(failed.is_empty(), "failed steps: {failed:?}");
    }

    /// Removes this run's messages from every folder, and prints what it could
    /// not remove. It never panics, and tries twice. After a failure it first
    /// waits `wait` for a message that may still be on its way. Nothing is
    /// done before a message has been made.
    async fn cleanup(&self, wait: Duration) -> Vec<String> {
        if self.made.load(Relaxed) == 0 {
            return Vec::new();
        }
        sleep(wait).await;
        let mut left = Vec::new();
        for _ in 0..2 {
            let swept = AssertUnwindSafe(self.sweep()).catch_unwind().await;
            left = swept.unwrap_or_else(|_| vec!["a command failed".to_owned()]);
            if left.is_empty() {
                break;
            }
            sleep(self.pause(5)).await;
        }
        let text = left.join(", ");
        say!(
            "cleanup: could not clean up: {}",
            if text.is_empty() { "nothing" } else { &text }
        );
        left
    }

    /// Moves what the marker finds to Trash, erases it there, and looks again.
    async fn sweep(&self) -> Vec<String> {
        let mut imap = self.session().await;
        let roles = roles(&mut imap, false).await;
        let trash = roles.iter().find(|r| r.0 == "Trash").map(|r| r.1.as_str());
        let can_move = ok!(imap.capabilities()).has_str("MOVE");
        for (role, name) in roles.iter().chain(&roles) {
            // A command that fails must not stop the rest: the look below tells.
            let act = async {
                let hits = self.find(&mut imap, name, "", 0).await;
                if let (Some(trash), false) = (trash, hits.found.is_empty()) {
                    say!("cleanup: {} message(s) in {role}", hits.found.len());
                    if trash == name {
                        erase(&mut imap, &hits).await;
                    } else if can_move {
                        ok!(imap.select(name));
                        ok!(imap.uid_mv(hits.set(), trash));
                    }
                }
            };
            drop(AssertUnwindSafe(act).catch_unwind().await);
        }
        let mut left = Vec::new();
        for (role, name) in &roles {
            let n = self.find(&mut imap, name, "", 0).await.found.len();
            left.extend((n > 0).then(|| format!("{n} in {role}")));
        }
        left
    }
}

/// The folders a message of this run can be in, as `(role, name)`: INBOX, and
/// Sent, Trash, All Mail and Spam where the server has them. `show` prints
/// what the server says about them.
async fn roles(imap: &mut Imap, show: bool) -> Vec<(&'static str, String)> {
    let names: Vec<Name> = ok!(ok!(imap.list(Some(""), Some("*"))).try_collect());
    let mut roles = vec![("INBOX", "INBOX".to_owned())];
    for (role, attribute, fallback) in [
        ("Sent", NameAttribute::Sent, "Sent Messages"),
        ("Trash", NameAttribute::Trash, "Deleted Messages"),
        ("All Mail", NameAttribute::All, ""),
        ("Spam", NameAttribute::Junk, ""),
    ] {
        let found = names
            .iter()
            .find(|n| n.attributes().contains(&attribute) || n.name() == fallback);
        if show {
            say!(
                "step 2: {role}: {:?}",
                found.map(|n| (n.name(), n.attributes()))
            );
        }
        roles.extend(found.map(|n| (role, n.name().to_owned())));
    }
    roles
}

/// The name of the Sent folder, which the server must show.
async fn sent_folder(imap: &mut Imap) -> String {
    let sent = roles(imap, false).await.into_iter().find(|r| r.0 == "Sent");
    sent.expect("IMAP shows a Sent folder").1
}

/// The Gmail system labels of the hits (X-GM-LABELS).
async fn labels(imap: &mut Imap, hits: &Hits) -> Vec<String> {
    let fetched = ok!(imap.uid_fetch(hits.set(), "X-GM-LABELS"));
    let fetched: Vec<Fetch> = ok!(fetched.try_collect());
    let all = fetched.iter().filter_map(Fetch::gmail_labels).flatten();
    all.filter(|l| l.starts_with('\\'))
        .map(ToString::to_string)
        .collect()
}

/// Marks the hits `\Deleted` and expunges exactly them with `UID EXPUNGE`.
/// Without UIDPLUS it sends nothing and returns false: a plain `EXPUNGE` would
/// remove other messages as well.
async fn erase(imap: &mut Imap, hits: &Hits) -> bool {
    if !ok!(imap.capabilities()).has_str("UIDPLUS") {
        return false;
    }
    ok!(imap.select(&hits.folder));
    let _: Vec<Fetch> =
        ok!(ok!(imap.uid_store(hits.set(), "+FLAGS.SILENT (\\Deleted)")).try_collect());
    // Where the server expunges at `\Deleted` already, this finds nothing.
    let expunged = ok!(imap.uid_expunge(hits.set()));
    drop(expunged.try_collect::<Vec<u32>>().await);
    true
}

#[tokio::test]
#[ignore = "needs a Gmail account and an app password; see CONTRIBUTING.md"]
async fn gmail_over_imap_with_an_app_password() {
    let Some(run) = Run::from_env() else {
        println!("skipped: the POSTKEEP_LIVE_GMAIL_*_FILE variables are not both set");
        return;
    };
    let what = if run.cleanup_only {
        "cleanup only, nothing is sent"
    } else {
        "in the subject of every message of this run"
    };
    say!("marker {} ({what})", run.marker);
    let limit = Duration::from_secs(if run.with_idle { 50 * 60 } else { 15 * 60 });
    let outcome = if run.cleanup_only {
        Ok(Ok(()))
    } else {
        AssertUnwindSafe(tokio::time::timeout(limit, run.steps()))
            .catch_unwind()
            .await
    };
    // A message may still be on its way after a failure or a kill.
    let clean = !run.cleanup_only && matches!(outcome, Ok(Ok(())));
    let left = run.cleanup(run.pause(if clean { 0 } else { 30 })).await;
    match outcome {
        Err(panic) => resume_unwind(panic),
        Ok(Err(_)) => panic!("the run took longer than {limit:?}"),
        Ok(Ok(())) => assert!(left.is_empty(), "could not clean up: {left:?}"),
    }
}
