//! Where an IMAP session starts reading, and what it does when the mailbox
//! changes under it or the webhook is deleted meanwhile. The mail server is
//! scripted: the INBOX it shows has the `UIDVALIDITY` and `UIDNEXT` a test says,
//! and it keeps the commands it was sent. It has no `IDLE`, so a session looks
//! again every poll interval.

#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use postkeep::watch::{WatchConfig, Watchers};
use postkeep_mail::{ImapConfig, ImapSecurity, ImapServers, MailConfig};
use postkeep_store::{AccountId, MasterKey, Store, WatchCursor, WebhookSettings};
use postkeep_webhook::Deliverer;
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

/// How often a test looks, a `POLL` apart, before it gives up: five seconds.
const LOOKS: usize = 250;
const POLL: Duration = Duration::from_millis(20);

/// The scripted mail server: the INBOX it shows, a webhook to delete when it
/// is next asked to open it, and the commands it was sent.
#[derive(Default)]
struct Server {
    uid_validity: AtomicU32,
    uid_next: AtomicU32,
    vanish: Mutex<Option<(Store, AccountId)>>,
    commands: Mutex<Vec<String>>,
}

impl Server {
    /// Shows an INBOX with this `UIDVALIDITY` and `UIDNEXT` from now on.
    fn show(&self, uid_validity: u32, uid_next: u32) {
        self.uid_validity.store(uid_validity, SeqCst);
        self.uid_next.store(uid_next, SeqCst);
    }

    /// How many commands began with `prefix`.
    fn sent(&self, prefix: &str) -> usize {
        let commands = self.commands.lock().unwrap();
        commands.iter().filter(|c| c.starts_with(prefix)).count()
    }
}

/// Starts the server on 127.0.0.1 and returns its port.
async fn serve(server: Arc<Server>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(converse(stream, Arc::clone(&server)));
        }
    });
    port
}

async fn converse(stream: TcpStream, server: Arc<Server>) {
    let (read, mut write) = stream.into_split();
    let _ = write.write_all(b"* OK ready\r\n").await;
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let (tag, command) = line.split_once(' ').unwrap_or((&line, ""));
        server.commands.lock().unwrap().push(command.to_owned());
        let word = command.split(' ').next().unwrap_or("").to_ascii_uppercase();
        let reply = match word.as_str() {
            "CAPABILITY" => format!("* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n"),
            "LOGIN" => format!("{tag} OK LOGIN completed\r\n"),
            "EXAMINE" => {
                let vanish = server.vanish.lock().unwrap().take();
                if let Some((store, account)) = vanish {
                    store.delete_webhook(&account).await.unwrap();
                }
                let (validity, next) = (
                    server.uid_validity.load(SeqCst),
                    server.uid_next.load(SeqCst),
                );
                format!(
                    "* 3 EXISTS\r\n* OK [UIDVALIDITY {validity}] valid\r\n\
                     * OK [UIDNEXT {next}] next\r\n{tag} OK [READ-ONLY] done\r\n"
                )
            }
            // The only UID command is the search for mail after the cursor, and
            // nothing is found.
            "UID" => format!("* SEARCH\r\n{tag} OK done\r\n"),
            "LOGOUT" => {
                let _ = write
                    .write_all(format!("* BYE bye\r\n{tag} OK done\r\n").as_bytes())
                    .await;
                return;
            }
            _ => format!("{tag} BAD unknown\r\n"),
        };
        let _ = write.write_all(reply.as_bytes()).await;
    }
}

struct Setup {
    store: Store,
    account: AccountId,
    server: Arc<Server>,
    watchers: Watchers,
    _dir: tempfile::TempDir,
}

/// An account with an enabled webhook and no cursor, a server showing an INBOX
/// with this `UIDVALIDITY` and `UIDNEXT`, and watchers over them.
async fn setup(uid_validity: u32, uid_next: u32) -> Setup {
    let server = Arc::<Server>::default();
    server.show(uid_validity, uid_next);
    let imap = ImapConfig {
        host: "127.0.0.1".to_owned(),
        port: serve(Arc::clone(&server)).await,
        security: ImapSecurity::Plaintext,
    };
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("watch.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let password = SecretString::from("secret".to_owned());
    let account = store
        .upsert_account("person@example.com", &password)
        .await
        .unwrap();
    let settings = WebhookSettings {
        enabled: true,
        url: "https://hooks.example.com/mail".to_owned(),
        auth_header: None,
        signing: false,
        signing_secret: SecretString::from("whsec_test".to_owned()),
        include_sender: true,
    };
    store.save_webhook(&account.id, &settings).await.unwrap();
    let config = WatchConfig {
        poll_interval: Duration::from_millis(30),
        debounce: Duration::from_millis(5),
        min_backoff: Duration::from_millis(50),
        ..WatchConfig::default()
    };
    let mail = MailConfig {
        imap,
        ..MailConfig::default()
    };
    let servers = ImapServers::custom_only("scripted", mail);
    let deliverer = Deliverer::new("postkeep-test");
    let watchers = Watchers::new(
        store.clone(),
        servers,
        deliverer,
        config,
        CancellationToken::new(),
    );
    Setup {
        store,
        account: account.id,
        server,
        watchers,
        _dir: dir,
    }
}

const fn cursor_at(uid_validity: u32, last_uid: u32) -> WatchCursor {
    WatchCursor {
        uid_validity,
        last_uid,
    }
}

/// Refuses the first two moves of a cursor, as when other owners move it first.
async fn refuse_two_moves(setup: &Setup) {
    for sql in [
        "CREATE TABLE tries (n INTEGER)",
        "CREATE TRIGGER refuse BEFORE UPDATE ON webhooks \
         WHEN (SELECT COUNT(*) FROM tries) < 2 \
         BEGIN INSERT INTO tries VALUES (1); SELECT RAISE(IGNORE); END",
    ] {
        sqlx::query(sql).execute(setup.store.pool()).await.unwrap();
    }
}

impl Setup {
    async fn cursor(&self) -> Option<WatchCursor> {
        let hook = self.store.webhook(&self.account).await.unwrap();
        hook.and_then(|hook| hook.cursor)
    }

    /// Waits until the stored cursor is `want`, and then checks it is.
    async fn wait_for_cursor(&self, want: WatchCursor) {
        for _ in 0..LOOKS {
            if self.cursor().await == Some(want) {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        assert_eq!(self.cursor().await, Some(want));
    }

    /// Waits until the watcher has ended, and then checks it has.
    async fn wait_until_ended(&self) {
        for _ in 0..LOOKS {
            if self.watchers.running() == 0 {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        assert_eq!(self.watchers.running(), 0, "the watcher should have ended");
    }

    /// Waits until the server has seen `count` logins, and says when it saw
    /// them.
    async fn wait_for_logins(&self, count: usize) -> Instant {
        for _ in 0..LOOKS {
            if self.server.sent("LOGIN") >= count {
                break;
            }
            tokio::time::sleep(POLL).await;
        }
        let logins = self.server.sent("LOGIN");
        assert!(logins >= count, "{logins} of {count} logins");
        Instant::now()
    }
}

/// The webhook is deleted while the session connects, before it stores where to
/// start. The session ends the watcher and logs out.
#[tokio::test]
async fn a_webhook_deleted_as_a_session_starts_ends_the_watcher() {
    let setup = setup(7, 11).await;
    let vanish = (setup.store.clone(), setup.account.clone());
    *setup.server.vanish.lock().unwrap() = Some(vanish);
    setup.watchers.refresh(&setup.account);

    setup.wait_until_ended().await;
    assert_eq!(setup.server.sent("LOGOUT"), 1, "it logged out");
    assert_eq!(setup.cursor().await, None);
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

/// The INBOX is made again with a new `UIDVALIDITY` while the session runs. The
/// session starts from the mail that is there then, which is old, and goes on
/// from that cursor: it looks for what arrives after it.
#[tokio::test]
async fn a_new_uidvalidity_moves_the_cursor_to_the_current_position() {
    let setup = setup(7, 11).await;
    setup.watchers.refresh(&setup.account);

    // A first start begins at the newest message, with no look at the old ones.
    setup.wait_for_cursor(cursor_at(7, 10)).await;
    setup.server.show(8, 4);
    setup.wait_for_cursor(cursor_at(8, 3)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(setup.server.sent("UID SEARCH"), 0, "old mail is not read");

    // A message arrives: the session looks for it after the new cursor.
    setup.server.show(8, 5);
    setup.wait_for_cursor(cursor_at(8, 4)).await;
    assert_eq!(setup.server.sent("UID SEARCH UID 4:*"), 1);
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

/// The webhook is deleted before the INBOX gets a new `UIDVALIDITY`. The
/// session ends the watcher and logs out.
#[tokio::test]
async fn a_webhook_deleted_before_a_new_uidvalidity_ends_the_watcher() {
    let setup = setup(7, 11).await;
    setup.watchers.refresh(&setup.account);
    setup.wait_for_cursor(cursor_at(7, 10)).await;

    setup.store.delete_webhook(&setup.account).await.unwrap();
    setup.server.show(8, 4);
    setup.wait_until_ended().await;
    assert_eq!(setup.server.sent("LOGOUT"), 1, "it logged out");
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

/// Other owners move the cursor twice as a session stores where to start from,
/// over the cursor of an old `UIDVALIDITY`. The session takes its third try, with
/// no need to log in again.
#[tokio::test]
async fn a_session_takes_its_third_try_at_the_cursor_it_starts_from() {
    let setup = setup(7, 11).await;
    let old = cursor_at(6, 5);
    setup
        .store
        .set_watch_cursor(&setup.account, old)
        .await
        .unwrap();
    refuse_two_moves(&setup).await;
    setup.watchers.refresh(&setup.account);

    setup.wait_for_cursor(cursor_at(7, 10)).await;
    assert_eq!(setup.server.sent("LOGIN"), 1, "one session");
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

/// The same when the INBOX gets a new `UIDVALIDITY` while the session runs.
#[tokio::test]
async fn a_session_takes_its_third_try_at_a_new_uidvalidity() {
    let setup = setup(7, 11).await;
    setup.watchers.refresh(&setup.account);
    setup.wait_for_cursor(cursor_at(7, 10)).await;

    refuse_two_moves(&setup).await;
    setup.server.show(8, 4);
    setup.wait_for_cursor(cursor_at(8, 3)).await;
    assert_eq!(setup.server.sent("LOGIN"), 1, "one session");
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

/// Every start loses the cursor, as when other owners keep moving it first.
/// The watcher waits 50 ms before its second session and twice as long before
/// each later one: 100 ms before its third and 800 ms before its sixth. Once
/// the first has warmed up, a session takes about as long each time, so the
/// gap from the fifth login to the sixth is 700 ms longer than the one from the
/// second to the third.
#[tokio::test]
async fn a_start_that_keeps_losing_the_cursor_waits_longer_each_time() {
    let setup = setup(7, 11).await;
    let refuse = "CREATE TRIGGER refuse BEFORE UPDATE ON webhooks \
                  BEGIN SELECT RAISE(IGNORE); END";
    let pool = setup.store.pool();
    sqlx::query(refuse).execute(pool).await.unwrap();
    setup.watchers.refresh(&setup.account);

    let second = setup.wait_for_logins(2).await;
    let third = setup.wait_for_logins(3).await;
    let fifth = setup.wait_for_logins(5).await;
    let sixth = setup.wait_for_logins(6).await;
    let (shorter, longer) = (third - second, sixth - fifth);
    let grew = longer >= shorter + Duration::from_millis(350);
    assert!(grew, "{shorter:?}, then {longer:?}");
    assert_eq!(setup.cursor().await, None);
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}
