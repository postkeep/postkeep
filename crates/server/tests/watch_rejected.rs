//! The IMAP watcher stops after the mail server rejects the stored password
//! three times in a row, and records it: a restart then tries once, a new
//! password three times. The mail server is scripted, and the clock is paused:
//! a test moves it itself and lets the tasks run.

#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

use postkeep::watch::{WatchConfig, WatchSignal, Watchers};
use postkeep_mail::{ImapConfig, ImapSecurity, ImapServers, MailConfig};
use postkeep_store::{AccountId, MasterKey, Migrations, PoolSettings, Store, WebhookSettings};
use postkeep_webhook::Deliverer;
use secrecy::SecretString;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::layer::{Context, SubscriberExt};

const AUTH_BACKOFF: Duration = Duration::from_mins(15);

/// What the scripted server does with a connection: `Reject` and `Unavailable`
/// answer `LOGIN` with `NO [AUTHENTICATIONFAILED]` and `NO [UNAVAILABLE]`,
/// `Accept` takes the login and `CAPABILITY` and says `BYE` at the next
/// command, `HangUp` hangs up at once.
#[derive(Clone, Copy)]
enum Answer {
    Reject,
    Unavailable,
    Accept,
    HangUp,
}

/// How many connections the scripted server took, and how many answers the
/// watcher has decided on.
#[derive(Default)]
struct Seen {
    connections: AtomicUsize,
    decided: AtomicUsize,
}

/// Counts the watcher's decision after each answer: the warning that it waits
/// (`retry_in`), logged in the poll that sets the timer, or that it stops
/// (`rejections` alone). It is the test thread's subscriber, and that thread
/// runs every task.
struct Decisions(Arc<Seen>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Decisions {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let fields = event.metadata().fields();
        if fields.field("retry_in").is_some() || fields.field("rejections").is_some() {
            self.0.decided.fetch_add(1, SeqCst);
        }
    }
}

/// Starts the server on 127.0.0.1: connection `n` gets `script[n]`, and the
/// last answer repeats. Returns its port.
async fn serve(script: Vec<Answer>, seen: Arc<Seen>) -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let n = seen.connections.fetch_add(1, SeqCst).min(script.len() - 1);
            tokio::spawn(converse(stream, script[n]));
        }
    });
    port
}

async fn converse(stream: TcpStream, answer: Answer) {
    if matches!(answer, Answer::HangUp) {
        return;
    }
    let (read, mut write) = stream.into_split();
    let _ = write.write_all(b"* OK ready\r\n").await;
    let mut lines = BufReader::new(read).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let mut words = line.split(' ');
        let tag = words.next().unwrap_or("*");
        let reply = match (words.next().unwrap_or(""), answer) {
            ("LOGIN", Answer::Reject) => format!("{tag} NO [AUTHENTICATIONFAILED] Invalid\r\n"),
            ("LOGIN", Answer::Unavailable) => format!("{tag} NO [UNAVAILABLE] Try later\r\n"),
            ("LOGIN", _) => format!("{tag} OK LOGIN completed\r\n"),
            ("CAPABILITY", _) => format!("* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n"),
            _ => {
                let _ = write.write_all(b"* BYE Session expired\r\n").await;
                return;
            }
        };
        let _ = write.write_all(reply.as_bytes()).await;
    }
}

/// Lets the tasks run until `done`. The clock stays put: awaiting a socket or
/// the database instead would let the paused clock jump ahead by itself.
async fn until(mut done: impl FnMut() -> bool + Send) {
    let limit = Instant::now() + Duration::from_secs(30);
    while !done() {
        assert!(Instant::now() < limit, "the tasks never got there");
        tokio::task::yield_now().await;
    }
}

struct Setup {
    account: AccountId,
    store: Store,
    servers: ImapServers,
    seen: Arc<Seen>,
    _dir: tempfile::TempDir,
    _log: tracing::subscriber::DefaultGuard,
}

impl Setup {
    /// An account with an enabled webhook, a scripted server and a watcher
    /// that has been started, with a rejection of its password on record if
    /// `rejected`. The clock is paused when this returns.
    async fn new(script: Vec<Answer>, rejected: bool) -> (Self, Watchers) {
        let seen = Arc::<Seen>::default();
        let log = tracing_subscriber::registry().with(Decisions(Arc::clone(&seen)));
        let log = tracing::subscriber::set_default(log);
        let imap = ImapConfig {
            host: "127.0.0.1".to_owned(),
            port: serve(script, Arc::clone(&seen)).await,
            security: ImapSecurity::Plaintext,
        };
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("watch.db").display());
        let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
        // The clock jumps by up to a day: a pool that gave up on a query by that
        // clock would fail one that is in flight.
        let pool = PoolSettings {
            acquire_timeout: Duration::from_hours(48),
            ..PoolSettings::default()
        };
        let store = Store::connect_with(&url, &key, &[], pool, Migrations::Apply);
        let store = store.await.unwrap();
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
        if rejected {
            store.mark_password_rejected(&account.id).await.unwrap();
        }
        // The database needs the real clock to connect and to save.
        tokio::time::pause();
        let mail = MailConfig {
            imap,
            ..MailConfig::default()
        };
        let setup = Self {
            account: account.id,
            store,
            servers: ImapServers::custom_only("scripted", mail),
            seen,
            _dir: dir,
            _log: log,
        };
        let watchers = setup.watchers();
        watchers.refresh(&setup.account);
        (setup, watchers)
    }

    /// Watchers over the account, like those of a server that has just started.
    fn watchers(&self) -> Watchers {
        let config = WatchConfig {
            min_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_secs(20),
            auth_backoff: AUTH_BACKOFF,
            ..WatchConfig::default()
        };
        let deliverer = Deliverer::new("postkeep-test");
        let (store, servers) = (self.store.clone(), self.servers.clone());
        Watchers::new(store, servers, deliverer, config, CancellationToken::new())
    }

    fn connections(&self) -> usize {
        self.seen.connections.load(SeqCst)
    }

    /// Runs a database call while the tasks run, which keeps the clock put.
    async fn db<T: Send + 'static>(&self, call: impl Future<Output = T> + Send + 'static) -> T {
        let task = tokio::spawn(call);
        until(|| task.is_finished()).await;
        task.await.unwrap()
    }

    /// When the store has the password rejected, if it does.
    async fn rejected_at(&self) -> Option<i64> {
        let (store, account) = (self.store.clone(), self.account.clone());
        self.db(async move { store.password_rejected_at(&account).await.unwrap() })
            .await
    }

    /// The person stores a new password.
    async fn new_password(&self) {
        let store = self.store.clone();
        self.db(async move {
            let password = SecretString::from("a new password".to_owned());
            store
                .upsert_account("person@example.com", &password)
                .await
                .unwrap()
        })
        .await;
    }

    /// Runs the tasks until the watcher has connected again since there were
    /// `before` connections, or has stopped, and has decided on every answer:
    /// its timer is set, or it has stopped. The commands of a connection and
    /// the database take real time, which turns do not measure; a clock moved
    /// on before the timer is set would leave the timer ahead of it for good.
    async fn settle(&self, watchers: &Watchers, before: usize) {
        until(|| self.connections() > before || watchers.running() == 0).await;
        let decided = || self.seen.decided.load(SeqCst) == self.connections();
        until(|| decided() || watchers.running() == 0).await;
    }

    /// Moves the clock on by `by` and settles. A timer is due at the next
    /// whole millisecond, so the clock goes one millisecond further.
    async fn tick(&self, watchers: &Watchers, by: Duration) {
        let before = self.connections();
        tokio::time::advance(by + Duration::from_millis(1)).await;
        self.settle(watchers, before).await;
    }

    /// Follows a watcher started when there were `before` connections until
    /// it stops, for ten waits at most. Returns the connections seen by then.
    async fn follow(&self, watchers: &Watchers, before: usize) -> usize {
        self.settle(watchers, before).await;
        for _ in 0..10 {
            if watchers.running() == 0 {
                break;
            }
            self.tick(watchers, AUTH_BACKOFF).await;
        }
        self.connections()
    }
}

#[tokio::test]
async fn three_rejections_stop_the_watcher_and_are_recorded_until_a_new_password() {
    let (setup, watchers) = Setup::new(vec![Answer::Reject], false).await;
    setup.settle(&watchers, 0).await;
    assert!(
        setup.rejected_at().await.is_none(),
        "one rejection is no verdict"
    );
    assert_eq!(setup.follow(&watchers, 0).await, 3);
    assert_eq!(watchers.running(), 0, "its slot is free");
    setup.tick(&watchers, Duration::from_hours(24)).await;
    assert_eq!(setup.connections(), 3, "no fourth login comes");
    assert!(setup.rejected_at().await.is_some(), "the stop is recorded");

    // Another change to the account: the password was rejected, so one try.
    watchers.signal(WatchSignal::Changed(setup.account.clone()));
    assert_eq!(setup.follow(&watchers, 3).await, 4);

    // The server restarts and starts every watcher once more: one try.
    let restarted = setup.watchers();
    let start = restarted.clone();
    let task = tokio::spawn(async move { start.start_all().await });
    until(|| task.is_finished()).await;
    assert_eq!(setup.follow(&restarted, 4).await, 5);
    assert!(setup.rejected_at().await.is_some(), "still on record");

    // The person saves a new password: the record goes, and the account
    // listener signals a change. Three tries again, and a new record.
    setup.new_password().await;
    assert_eq!(setup.rejected_at().await, None);
    watchers.signal(WatchSignal::Changed(setup.account.clone()));
    assert_eq!(setup.follow(&watchers, 5).await, 8);
}

#[tokio::test]
async fn a_login_the_server_accepts_clears_the_record_of_a_rejection() {
    // The record stands when the watcher starts. The server takes the login
    // and ends the session with BYE at once.
    let (setup, watchers) = Setup::new(vec![Answer::Accept], true).await;
    setup.settle(&watchers, 0).await;
    assert_eq!(setup.rejected_at().await, None);
}

#[tokio::test]
async fn a_refusal_that_may_pass_takes_the_usual_backoff_and_never_stops_the_watcher() {
    let (setup, watchers) = Setup::new(vec![Answer::Unavailable], false).await;
    setup.settle(&watchers, 0).await;
    // 5 seconds, doubling up to the cap of 20. `auth_backoff` is 15 minutes.
    for (connections, wait) in (2..).zip([5, 10, 20, 20, 20]) {
        setup.tick(&watchers, Duration::from_secs(wait)).await;
        let state = (setup.connections(), watchers.running());
        assert_eq!(state, (connections, 1), "{wait} s after the last try");
    }
}

#[tokio::test]
async fn a_refusal_that_may_pass_and_a_dropped_connection_neither_count_nor_end_the_run() {
    // The third rejection comes at the fifth try. Were either of the two in
    // between counted, the watcher would stop sooner; were either to end the
    // run, it would go on to the seventh.
    let (reject, between) = (Answer::Reject, [Answer::Unavailable, Answer::HangUp]);
    let script = [&[reject, reject], &between[..], &[reject]].concat();
    let (setup, watchers) = Setup::new(script, false).await;
    assert_eq!(setup.follow(&watchers, 0).await, 5);
}

#[tokio::test]
async fn a_login_the_server_accepts_ends_the_run_of_rejections() {
    // The server takes the third login and ends the session with BYE at once.
    // Three more rejections follow before the watcher stops.
    let (reject, accept) = (Answer::Reject, Answer::Accept);
    let (setup, watchers) = Setup::new(vec![reject, reject, accept, reject], false).await;
    assert_eq!(setup.follow(&watchers, 0).await, 6);
}
