//! New-mail webhooks: one watcher task per account with an enabled webhook.
//!
//! A watcher logs in to IMAP with its own connection (not the tool pool),
//! opens `INBOX` read-only and waits with `IDLE` (or polls when the server
//! lacks it). When new messages arrive it waits a short debounce, fetches
//! their headers without marking them read, and delivers them oldest first.
//! A backlog larger than 50 messages is several events of at most 50, each
//! describing that batch's newest message, and the watcher finishes that
//! backlog before it waits again. The position (`UIDVALIDITY` and the last
//! reported UID) is stored with each event, so a restart reports what
//! arrived meanwhile — including the rest of a backlog — and a fresh
//! webhook or a changed `UIDVALIDITY` never reports existing mail.
//!
//! Events are not sent from here: they are recorded in the outbox and
//! delivered in order by a per-account pump (`outbox.rs`). A webhook paused
//! after repeated delivery failures stays enabled, so its watcher keeps
//! running, keeps its slot under [`WatchConfig::max_watchers`], and keeps
//! recording. IMAP keeps its connection. Gmail `users.watch` and the Graph
//! subscription keep renewing on their usual schedule. A pause does not
//! shorten that schedule or call the provider more often, and mail recorded
//! while paused is not delivered before the pause interval. Only the user
//! turning the webhook off, or removing it, stops the watcher, releases the
//! slot, and stops the provider watch. Failures never turn a webhook off.
//!
//! One failure does end an IMAP watcher: the mail server rejecting the stored
//! password three times in a row, [`WatchConfig::auth_backoff`] apart. The
//! webhook stays enabled and the slot is freed. The stop is recorded
//! ([`Store::password_rejected_at`]) for `get_webhook_status` and the account
//! page. A new password clears the record and gives the watcher three tries
//! again; any other change, or a restart, gives it one while the record
//! stands. A login the server accepts clears the record, and one that a tool
//! makes also starts the watcher again.
//!
//! An embedding that runs several processes on one database decides with a
//! [`WatchOwnership`] which mailboxes each process watches. A process passes
//! account changes, provider pushes and recorded events for a mailbox it
//! doesn't watch on to the process that does, instead of starting work.

mod gmail;
mod graph;
#[cfg(test)]
mod graph_fixtures;
#[cfg(test)]
mod harness;
mod outbox;
mod ownership;
mod rules;

pub use gmail::GmailPosition;
pub use graph::GraphPosition;
pub use ownership::{SharedJob, WatchOwnership, WatchSignal};
pub use postkeep_auth::DEFAULT_MAX_FILTER_RULES;

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use postkeep_auth::{DeletionListener, UsageHook};
use postkeep_mail::{IdleEvent, ImapServers, ImapSession, MessageBatch, NewMessage, invisible};
use postkeep_store::{
    AccountId, AppendOutcome, Provider, Store, StoreError, WatchAdvance, WatchCursor, Webhook,
};
use postkeep_upstream::{ApiError, HttpError, TokenError, UpstreamProvider};
use postkeep_webhook::{Deliverer, NEW_MAIL, NewMailEvent, RETRY_DELAYS};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::metrics::Metrics;

/// The folder watched.
const FOLDER: &str = "INBOX";
/// New messages fetched per event. A larger backlog is several events of
/// this many, oldest first; `count` on each event is that batch's size.
const BATCH_LIMIT: usize = 50;
/// Rejections of the stored password in a row that stop an IMAP watcher. A
/// server can refuse a correct password for a short while, so the first two
/// are retried; with the default `auth_backoff` the watcher gives up half an
/// hour after the first. Only a login the server accepts ends the run: a
/// refusal that may pass, or a connection that breaks, says nothing about the
/// password.
const STOP_AFTER_REJECTIONS: u32 = 3;
/// Tries to store the cursor or position a session starts from before the
/// session gives up. A try only fails when another owner changed it since it
/// was read, and each try reads it again.
const START_CURSOR_ATTEMPTS: usize = 3;

/// Watcher settings.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Whether webhooks are offered at all.
    pub enabled: bool,
    /// Accounts watched at once.
    ///
    /// A paused webhook stays enabled and still uses one slot. IMAP keeps
    /// its connection; Gmail and Graph do not hold a connection, but they
    /// keep renewing the provider watch. Turning the webhook off releases
    /// the slot.
    pub max_watchers: usize,
    /// Wait after a change before fetching, to batch bursts.
    pub debounce: Duration,
    /// Poll interval for servers without `IDLE`.
    pub poll_interval: Duration,
    /// How often an Outlook account with a Graph subscription is caught
    /// up without a notification, for mail whose notification Graph never
    /// sent. Sub-second values are for tests.
    pub graph_catch_up_interval: Duration,
    /// How long one `IDLE` lasts before it is renewed (servers drop idle
    /// connections after 30 minutes).
    pub idle_wait: Duration,
    /// Waits before each delivery retry.
    pub retry_delays: Vec<Duration>,
    /// First delay after a watcher error, and the floor of a provider
    /// catch-up retry; doubles up to `max_backoff`.
    pub min_backoff: Duration,
    /// Longest delay after watcher errors or between provider catch-up
    /// retries.
    pub max_backoff: Duration,
    /// Wait before the next login after the mail server rejects the stored
    /// password. The third rejection in a row stops the IMAP watcher instead.
    pub auth_backoff: Duration,
    /// First wait before an event the receiver did not accept is sent
    /// again; doubles up to `outbox_max_backoff`.
    pub outbox_min_backoff: Duration,
    /// Longest wait between attempts at one event, before the webhook is
    /// paused. The running server sets this to the same value as
    /// `webhook_retry_interval`, so a webhook that is not paused yet never
    /// waits longer than one that is.
    pub outbox_max_backoff: Duration,
    /// How long a paused webhook waits between attempts at its oldest
    /// pending event.
    ///
    /// New mail does not start an attempt early. A restart, saving the
    /// settings, turning it back on, a successful test, or signing in
    /// again may try once immediately; after that this interval applies
    /// again. Sub-second values are for tests.
    /// The `POSTKEEP_WEBHOOK_RETRY_INTERVAL` flag is a whole number of
    /// seconds from 1 to 86400.
    pub webhook_retry_interval: Duration,
    /// When set, only these addresses (compared case-insensitively) are
    /// watched: the same allow-list that gates sign-in and tokens, so
    /// removing an address also stops its notifications.
    pub allowed_emails: Option<Vec<String>>,
    /// How many filter rules count for a mailbox, oldest first; the rest
    /// judge nothing and wait. The usage hook's number for a mailbox
    /// ([`postkeep_auth::OutboxCeilings::with_max_filter_rules`]) replaces it,
    /// and more than [`MAX_RULES`](postkeep_webhook::filter::MAX_RULES) never
    /// count.
    pub max_filter_rules: usize,
}

impl WatchConfig {
    fn email_allowed(&self, email: &str) -> bool {
        self.allowed_emails.as_ref().is_none_or(|allowed| {
            allowed
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(email.trim()))
        })
    }
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_watchers: 100,
            debounce: Duration::from_secs(3),
            poll_interval: Duration::from_secs(60),
            graph_catch_up_interval: Duration::from_mins(15),
            idle_wait: Duration::from_mins(25),
            retry_delays: RETRY_DELAYS.to_vec(),
            min_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_mins(5),
            auth_backoff: Duration::from_mins(15),
            outbox_min_backoff: outbox::OUTBOX_MIN_BACKOFF,
            outbox_max_backoff: outbox::OUTBOX_MAX_BACKOFF,
            webhook_retry_interval: outbox::OUTBOX_MAX_BACKOFF,
            allowed_emails: None,
            max_filter_rules: DEFAULT_MAX_FILTER_RULES,
        }
    }
}

/// What provider watchers need: access tokens and the public URL that
/// Microsoft and Google call.
#[derive(Debug, Clone)]
pub struct PushConfig {
    /// Access tokens for Outlook and Gmail accounts.
    pub tokens: postkeep_upstream::TokenManager,
    /// The server's public origin.
    pub public_url: url::Url,
    /// Gmail push through Cloud Pub/Sub; `None` leaves Gmail unwatched.
    pub google: Option<GooglePush>,
}

/// Gmail push settings.
#[derive(Debug, Clone)]
pub struct GooglePush {
    /// The Pub/Sub topic Gmail publishes to,
    /// `projects/<project>/topics/<topic>`.
    pub topic: String,
    /// What the push subscription's OIDC token must say.
    pub expected: postkeep_upstream::PushExpectations,
    /// Verifies push tokens against Google's keys.
    pub verifier: postkeep_upstream::PushVerifier,
}

impl PushConfig {
    pub(crate) const fn graph_enabled(&self) -> bool {
        self.tokens
            .oauth()
            .is_configured(UpstreamProvider::Microsoft)
    }

    pub(crate) const fn google_enabled(&self) -> bool {
        self.google.is_some() && self.tokens.oauth().is_configured(UpstreamProvider::Google)
    }

    /// The public URL of `path`.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        let mut url = self.public_url.clone();
        url.set_path(path);
        url.to_string()
    }
}

struct Task {
    cancel: CancellationToken,
    generation: u64,
}

struct Inner {
    store: Store,
    servers: ImapServers,
    deliverer: Deliverer,
    config: WatchConfig,
    shutdown: CancellationToken,
    tracker: TaskTracker,
    tasks: Mutex<HashMap<AccountId, Task>>,
    pumps: Mutex<HashMap<AccountId, outbox::Pump>>,
    /// When a paused webhook may next be tried. In memory so a sub-second
    /// test interval is not rounded to Unix seconds. Left in place when the
    /// pump exits, so a later event waits until the slot instead of going
    /// out immediately. Cleared when the pause ends or the user turns the
    /// webhook off.
    pause_after: Mutex<HashMap<AccountId, std::time::Instant>>,
    push: OnceLock<PushConfig>,
    /// Which mailboxes this process watches; unset is all of them.
    ownership: OnceLock<Arc<dyn WatchOwnership>>,
    /// How many filter rules count for each mailbox; unset is the setting.
    usage: OnceLock<Arc<dyn UsageHook>>,
    /// Where the watchers count their logins, errors and refusals; unset is
    /// nowhere.
    metrics: OnceLock<Metrics>,
    catch_ups: Mutex<HashMap<AccountId, Weak<tokio::sync::Mutex<()>>>>,
    /// One watcher session per account. The running session holds it through
    /// its provider stop; the replacement waits on it.
    sessions: Mutex<HashMap<AccountId, Weak<tokio::sync::Mutex<()>>>>,
    /// At most one running catch-up per account, plus one requested rerun.
    catch_up_slots: Mutex<HashMap<AccountId, CatchUpSlot>>,
    next_generation: std::sync::atomic::AtomicU64,
    rules: rules::RuleCache,
    /// Test-only pause between delivery bookkeeping and a deadline change.
    ///
    /// Production leaves this empty. A test parks the pump that is about to
    /// arm a slot so a replacement can finish first.
    deadline_gate: Mutex<Option<outbox::DeadlineGate>>,
}

/// One account's catch-up task.
///
/// `running` stays set from the moment a task is spawned until that task
/// has finished and no rerun is waiting, including while it waits to retry
/// a transient failure. `again` records one more pass. It is cleared when
/// a pass is about to call the provider, so requests during the debounce
/// share the pass that follows, and a request during the pass — or a
/// continuation the pass itself asks for — causes exactly one more. A
/// request during a retry wait sets `again` and wakes [`Self::wake`], so
/// that pass does not sit out the rest of the backoff.
struct CatchUpSlot {
    running: bool,
    again: bool,
    wake: Arc<Notify>,
}

impl Default for CatchUpSlot {
    fn default() -> Self {
        Self {
            running: false,
            again: false,
            wake: Arc::new(Notify::new()),
        }
    }
}

/// Which provider a coalesced catch-up reads.
#[derive(Clone, Copy)]
enum ProviderCatchUp {
    Graph,
    Gmail,
}

impl ProviderCatchUp {
    /// The push to pass on to the process that watches `account`.
    const fn signal(self, account: AccountId) -> WatchSignal {
        match self {
            Self::Graph => WatchSignal::GraphNotification(account),
            Self::Gmail => WatchSignal::GmailPush(account),
        }
    }
}

/// Runs and restarts watcher tasks. Cheap to clone.
#[derive(Clone)]
pub struct Watchers {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Watchers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Watchers")
            .field("config", &self.inner.config)
            .field("running", &self.running())
            .finish_non_exhaustive()
    }
}

/// Why a watcher session ended.
enum Exit {
    /// Cancelled, because the settings changed or the server is stopping,
    /// or another process watches the mailbox now.
    Stopped,
    /// The webhook is gone or disabled, or its filter rules can't be read.
    Disabled,
}

/// Loads `account`'s webhook settings.
///
/// A row whose secrets no configured key can decrypt is logged and
/// reported as missing. Watchers and the delivery pump then stop, instead
/// of retrying a failure that will not clear until the user saves new
/// settings. A paused webhook is still returned: pausing keeps it enabled,
/// and the pump retries it slowly.
async fn readable_webhook(
    store: &Store,
    account: &AccountId,
) -> Result<Option<Webhook>, StoreError> {
    match store.webhook(account).await {
        Ok(hook) => Ok(hook),
        Err(StoreError::Decrypt) => {
            tracing::warn!(
                account_id = %account,
                "webhook settings can't be read with the configured keys; skipping this account"
            );
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

/// Why a watcher or catch-up failed.
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    /// IMAP failed.
    #[error(transparent)]
    Mail(#[from] postkeep_mail::Error),
    /// The store failed.
    #[error(transparent)]
    Store(#[from] postkeep_store::StoreError),
    /// A Graph or Gmail call failed.
    #[error(transparent)]
    Api(Box<postkeep_upstream::ApiError>),
    /// Provider push is not configured.
    #[error("provider push is not configured")]
    NotConfigured,
    /// A provider answered with something unexpected.
    #[error("{0}")]
    Malformed(&'static str),
    /// Another owner kept changing the stored IMAP cursor while a session
    /// was choosing where to start.
    #[error("the stored IMAP cursor keeps changing")]
    CursorMoved,
}

impl Watchers {
    /// Creates the manager. Watchers stop when `shutdown` is cancelled.
    #[must_use]
    pub fn new(
        store: Store,
        servers: ImapServers,
        deliverer: Deliverer,
        config: WatchConfig,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                store,
                servers,
                deliverer,
                config,
                shutdown,
                tracker: TaskTracker::new(),
                tasks: Mutex::new(HashMap::new()),
                pumps: Mutex::new(HashMap::new()),
                pause_after: Mutex::new(HashMap::new()),
                push: OnceLock::new(),
                ownership: OnceLock::new(),
                usage: OnceLock::new(),
                metrics: OnceLock::new(),
                catch_ups: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashMap::new()),
                catch_up_slots: Mutex::new(HashMap::new()),
                next_generation: std::sync::atomic::AtomicU64::new(0),
                rules: rules::RuleCache::default(),
                deadline_gate: Mutex::new(None),
            }),
        }
    }

    /// Lets watchers serve Outlook and Gmail accounts.
    pub fn enable_push(&self, push: PushConfig) {
        if self.inner.push.set(push).is_err() {
            tracing::warn!("provider push was already enabled");
        }
    }

    /// The provider push settings, if enabled.
    #[must_use]
    pub fn push(&self) -> Option<&PushConfig> {
        self.inner.push.get()
    }

    /// Lets `ownership` decide which mailboxes this process watches, and
    /// hands it these watchers ([`WatchOwnership::attach`]). Install it
    /// before [`Self::start_all`]; a second one is ignored.
    pub fn set_ownership(&self, ownership: Arc<dyn WatchOwnership>) {
        if self.inner.ownership.set(ownership).is_err() {
            tracing::warn!("watch ownership was already set");
            return;
        }
        if let Some(ownership) = self.inner.ownership.get() {
            ownership.attach(self);
        }
    }

    /// Lets `hook` say how many filter rules count for each mailbox
    /// ([`UsageHook::outbox_ceilings`]), asked once per batch of new mail.
    /// Install it before [`Self::start_all`]; a second one is ignored.
    pub fn set_usage_hook(&self, hook: Arc<dyn UsageHook>) {
        if self.inner.usage.set(hook).is_err() {
            tracing::warn!("the usage hook of the watchers was already set");
        }
    }

    /// Lets the watchers count their logins, errors and refusals into
    /// `metrics`. Install it before [`Self::start_all`]; a second one is
    /// ignored.
    pub(crate) fn set_metrics(&self, metrics: Metrics) {
        if self.inner.metrics.set(metrics).is_err() {
            tracing::warn!("the metrics of the watchers were already set");
        }
    }

    fn metrics(&self) -> Option<&Metrics> {
        self.inner.metrics.get()
    }

    /// Passes on the result of a login to the mail server `server` (its
    /// id) after counting it, if the watchers count.
    fn count_login<T>(
        &self,
        server: &'static str,
        result: postkeep_mail::Result<T>,
    ) -> postkeep_mail::Result<T> {
        if let Some(metrics) = self.metrics() {
            metrics.imap_login(server, &result);
        }
        result
    }

    fn owns(&self, account: &AccountId) -> bool {
        self.inner
            .ownership
            .get()
            .is_none_or(|ownership| ownership.owns(account))
    }

    fn forward(&self, signal: WatchSignal) {
        tracing::debug!(account_id = %signal.account(), "passing on a signal for a mailbox another process watches");
        if let Some(ownership) = self.inner.ownership.get() {
            ownership.forward(signal);
        }
    }

    /// Acts on `signal`, which another process passed on because this one
    /// watches the mailbox. If this process doesn't watch it either, the
    /// signal is passed on again.
    pub fn signal(&self, signal: WatchSignal) {
        match signal {
            WatchSignal::Changed(account) => self.refresh(&account),
            WatchSignal::GraphNotification(account) => self.schedule_graph_catch_up(&account),
            WatchSignal::GraphLifecycle {
                account,
                subscription_id,
                event,
            } => self.schedule_graph_lifecycle(&account, subscription_id, event),
            WatchSignal::GmailPush(account) => self.schedule_gmail_catch_up(&account),
            WatchSignal::Recorded(account) => self.wake(&account),
        }
    }

    /// Stops the watcher and the delivery pump of `account` once
    /// [`WatchOwnership::owns`] answers `false` for it, and returns when the
    /// watcher has stopped, so two processes don't watch it at once.
    ///
    /// Unlike turning the webhook off, this keeps the Graph subscription or
    /// Gmail watch, the stored position and the pending events for the next
    /// owner, which starts with [`Self::refresh`]. A catch-up waiting to run
    /// passes its push on instead. A catch-up already under way, or a
    /// delivery in flight, can still finish: positions are compare-and-set,
    /// so the next owner can't record the same mail twice, and receivers
    /// drop a repeated delivery by its `X-Webhook-Id`.
    pub async fn release(&self, account: &AccountId) {
        self.stop(account);
        let _stopped = self.session_gate(account).lock_owned().await;
    }

    /// Deletes the Graph subscription or Gmail watch of `account` at the
    /// provider and locally, for an account about to be deleted: deleting
    /// it removes the tokens and the stored subscription, and nothing can
    /// unsubscribe after that. Best effort: failures are logged, and a
    /// subscription left behind lapses within 7 days, its notifications
    /// ignored. An IMAP account has nothing to delete, and its watcher is
    /// left alone.
    ///
    /// Stops the account's watcher first and waits for its session to end,
    /// so that a subscription it is creating or renewing is the one
    /// deleted. All of it takes `limit` at most, and the wait for the
    /// session half of that. A session still under way after that wait, such
    /// as a renewal that the provider answers late or whose token refresh
    /// finds the tokens gone, ends without an error: a run that fails in the
    /// store or at the provider after the deletion committed finds the
    /// account gone. The account's change notification after the deletion,
    /// or after a deletion that failed or stopped early, starts a watcher
    /// again for an account that is still there.
    pub async fn unsubscribe_before_delete(&self, account: &AccountId, limit: Duration) {
        let unsubscribe = async {
            let provider = match self.inner.store.account(account).await {
                Ok(row) => row.map(|row| row.provider),
                Err(err) => {
                    tracing::warn!(account_id = %account, error = %err, "could not load the account to unsubscribe");
                    return;
                }
            };
            let api = match provider {
                Some(Provider::Graph) => self.graph_api(account),
                Some(Provider::Gmail) => self.gmail_api(account),
                Some(Provider::Imap) | None => None,
            };
            let Some(api) = api else {
                return;
            };
            self.stop(account);
            let gate = self.session_gate(account);
            let _session = tokio::time::timeout(limit / 2, gate.lock_owned())
                .await
                .inspect_err(|_| tracing::info!(account_id = %account, "the new-mail watcher is still busy; unsubscribing anyway"));
            if provider == Some(Provider::Graph) {
                self.graph_unsubscribe(&api).await;
            } else {
                self.gmail_stop(&api).await;
            }
        };
        if tokio::time::timeout(limit, unsubscribe).await.is_err() {
            tracing::warn!(account_id = %account, "unsubscribing took too long; a subscription left at the provider lapses within 7 days");
        }
    }

    /// The [`DeletionListener`] that runs [`Self::unsubscribe_before_delete`]
    /// with 20 seconds in all, at most 10 of them waiting for a session to
    /// end. With the Google revoke after it, a deletion stays well inside
    /// the default request timeout of two minutes.
    #[must_use]
    pub fn deletion_listener(&self) -> DeletionListener {
        let watchers = self.clone();
        Arc::new(move |account| {
            let watchers = watchers.clone();
            let limit = Duration::from_secs(20);
            Box::pin(async move { watchers.unsubscribe_before_delete(account, limit).await })
        })
    }

    /// Cancels the watcher and the pump of `account`.
    fn stop(&self, account: &AccountId) {
        let task = self
            .inner
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(account);
        if let Some(task) = task {
            task.cancel.cancel();
        }
        self.stop_pump(account);
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    fn catch_up_slots(&self) -> std::sync::MutexGuard<'_, HashMap<AccountId, CatchUpSlot>> {
        self.inner
            .catch_up_slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Spawns a catch-up unless one is already active. False when this
    /// request was recorded as the single pending rerun instead.
    fn request_catch_up(&self, account: &AccountId) -> bool {
        let mut slots = self.catch_up_slots();
        let slot = slots.entry(account.clone()).or_default();
        if slot.running {
            let wake = if slot.again {
                None
            } else {
                slot.again = true;
                Some(Arc::clone(&slot.wake))
            };
            drop(slots);
            if let Some(wake) = wake {
                wake.notify_one();
            }
            false
        } else {
            slot.running = true;
            slot.again = false;
            drop(slots);
            true
        }
    }

    /// A pass is about to call the provider. Requests from here on ask for
    /// one more pass; earlier ones are covered by this pass.
    fn catch_up_started(&self, account: &AccountId) {
        let mut slots = self.catch_up_slots();
        if let Some(slot) = slots.get_mut(account) {
            slot.again = false;
        }
    }

    /// Ends the running pass. True when one more pass was requested.
    fn catch_up_finished(&self, account: &AccountId) -> bool {
        let mut slots = self.catch_up_slots();
        let Some(slot) = slots.get_mut(account) else {
            return false;
        };
        if slot.again {
            slot.again = false;
            return true;
        }
        slots.remove(account);
        false
    }

    /// Debounces and runs one catch-up, then at most one follow-up if
    /// another request arrived while it ran.
    ///
    /// A transient failure (timeout, 429, 5xx, or the database) keeps this
    /// task pending and retries from the stored position. The wait starts
    /// at the longer of the debounce and `min_backoff`, doubles, and stops
    /// growing at `max_backoff`. It repeats until the catch-up succeeds. A
    /// new request during that wait runs the next pass immediately. The
    /// task stops on shutdown, when the webhook is disabled, when the
    /// account is removed or not allowed, and when the sign-in has to be
    /// renewed.
    ///
    /// The push is passed on when another process watches the mailbox, now
    /// or by the time a pass is about to start.
    fn schedule_provider_catch_up(&self, account: &AccountId, provider: ProviderCatchUp) {
        if !self.owns(account) {
            self.forward(provider.signal(account.clone()));
            return;
        }
        if !self.request_catch_up(account) {
            return;
        }
        let this = self.clone();
        let account = account.clone();
        self.inner.tracker.spawn(async move {
            this.provider_catch_up_loop(account, provider).await;
        });
    }

    /// Runs catch-up passes for `account` until one succeeds and nothing
    /// else is pending, or until retrying should stop.
    async fn provider_catch_up_loop(&self, account: AccountId, provider: ProviderCatchUp) {
        let mut failures = 0u32;
        loop {
            if !self.prepare_catch_up_pass(&account, failures).await
                || self.inner.shutdown.is_cancelled()
            {
                self.abandon_catch_up(&account);
                return;
            }
            if !self.owns(&account) {
                self.abandon_catch_up(&account);
                self.forward(provider.signal(account));
                return;
            }
            self.catch_up_started(&account);
            let result = match provider {
                ProviderCatchUp::Graph => self.graph_catch_up(&account).await,
                ProviderCatchUp::Gmail => self.gmail_catch_up(&account).await,
            };
            if !self
                .continue_after_catch_up(&account, provider, result, &mut failures)
                .await
            {
                return;
            }
        }
    }

    /// Waits out the debounce or the retry backoff. False when the server
    /// is shutting down. A push that arrived during a retry wait returns
    /// immediately so the next pass does not sit out the backoff.
    async fn prepare_catch_up_pass(&self, account: &AccountId, failures: u32) -> bool {
        if self.inner.shutdown.is_cancelled() {
            return false;
        }
        if self.catch_up_is_pending(account) {
            return true;
        }
        let delay = if failures == 0 {
            self.inner.config.debounce
        } else {
            catch_up_retry_delay(failures, &self.inner.config)
        };
        self.wait_for_catch_up(account, delay, failures > 0).await
    }

    /// Sleeps `delay`. False when shutdown wins. When `wake_for_push` is
    /// set, a request recorded on the slot ends the wait early.
    async fn wait_for_catch_up(
        &self,
        account: &AccountId,
        delay: Duration,
        wake_for_push: bool,
    ) -> bool {
        let wake = self.catch_up_wake(account);
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            if self.inner.shutdown.is_cancelled() {
                return false;
            }
            if wake_for_push && self.catch_up_is_pending(account) {
                return true;
            }
            tokio::select! {
                () = self.inner.shutdown.cancelled() => return false,
                () = &mut sleep => return true,
                () = wake.notified(), if wake_for_push => {}
            }
        }
    }

    /// Whether another pass was requested. The slot stays owned by the
    /// running task.
    fn catch_up_is_pending(&self, account: &AccountId) -> bool {
        self.catch_up_slots()
            .get(account)
            .is_some_and(|slot| slot.again)
    }

    /// The slot's wake signal, or a fresh one when the slot is already gone.
    fn catch_up_wake(&self, account: &AccountId) -> Arc<Notify> {
        self.catch_up_slots()
            .get(account)
            .map_or_else(|| Arc::new(Notify::new()), |slot| Arc::clone(&slot.wake))
    }

    /// Drops the slot, including a rerun recorded while the task was stopping.
    fn abandon_catch_up(&self, account: &AccountId) {
        self.catch_up_slots().remove(account);
    }

    /// True when the account should no longer be caught up: it is gone, not
    /// on the allow-list, or its webhook is missing, unreadable, or turned off.
    ///
    /// A webhook paused after delivery failures stays enabled, so catch-up
    /// continues and the new mail is kept in the outbox until delivery
    /// recovers. That mail is not sent before the pause interval. A pause
    /// does not stop Gmail or Graph renewal and does not add provider
    /// calls. Unreadable settings stop catch-up instead: the watcher
    /// cannot use them until the user saves new ones. Failures never turn
    /// the webhook off.
    async fn catch_up_no_longer_wanted(&self, account: &AccountId) -> Result<bool, WatchError> {
        if self.allow_list_blocks(account).await? {
            return Ok(true);
        }
        if self.inner.store.account(account).await?.is_none() {
            tracing::info!(account_id = %account, "account is gone; stopping the catch-up");
            return Ok(true);
        }
        let Some(hook) = readable_webhook(&self.inner.store, account).await? else {
            tracing::info!(
                account_id = %account,
                "webhook is missing or unreadable; stopping the catch-up"
            );
            return Ok(true);
        };
        if !hook.settings.enabled {
            tracing::info!(account_id = %account, "webhook is disabled; stopping the catch-up");
            return Ok(true);
        }
        Ok(false)
    }

    /// Returns whether the task should run another pass. A `false` return
    /// has already released the slot.
    async fn continue_after_catch_up(
        &self,
        account: &AccountId,
        provider: ProviderCatchUp,
        result: Result<(), WatchError>,
        failures: &mut u32,
    ) -> bool {
        if self.inner.shutdown.is_cancelled() {
            self.abandon_catch_up(account);
            return false;
        }
        let err = match result {
            Ok(()) => {
                *failures = 0;
                return self.catch_up_finished(account);
            }
            Err(err) => err,
        };
        if needs_sign_in(&err) {
            warn_catch_up(
                account,
                provider,
                &err,
                "the sign-in is no longer valid; not retrying the catch-up",
            );
            self.abandon_catch_up(account);
            return false;
        }
        if !is_transient(&err) {
            warn_catch_up(
                account,
                provider,
                &err,
                "catch-up failed and will not be retried",
            );
            self.abandon_catch_up(account);
            return false;
        }
        match self.catch_up_no_longer_wanted(account).await {
            Ok(true) => {
                self.abandon_catch_up(account);
                return false;
            }
            Ok(false) => {}
            Err(check) => {
                tracing::debug!(
                    account_id = %account,
                    error = %check,
                    "could not check whether the catch-up should stop"
                );
            }
        }
        *failures = failures.saturating_add(1);
        let delay = catch_up_retry_delay(*failures, &self.inner.config);
        match provider {
            ProviderCatchUp::Graph => tracing::warn!(
                account_id = %account,
                error = %err,
                retry_in = ?delay,
                attempt = *failures,
                "catching up on new Outlook mail failed; retrying"
            ),
            ProviderCatchUp::Gmail => tracing::warn!(
                account_id = %account,
                error = %err,
                retry_in = ?delay,
                attempt = *failures,
                "catching up on new Gmail mail failed; retrying"
            ),
        }
        true
    }

    /// Whether a catch-up task is still recorded for `account`.
    #[cfg(test)]
    fn catch_up_running(&self, account: &AccountId) -> bool {
        self.catch_up_slots().contains_key(account)
    }

    fn catch_up_lock(&self, account: &AccountId) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .inner
            .catch_ups
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(account).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(account.clone(), Arc::downgrade(&lock));
        lock
    }

    /// Mutex held for a whole watcher session of `account`, including the
    /// provider stop that runs as the session exits.
    ///
    /// Gmail has one watch per user and no subscription id, so a `users.stop`
    /// still in flight stops whatever watch replaced it and then deletes that
    /// watch's local record. Graph has the same record-deletion hazard. The
    /// replacement task waits on this mutex and does not subscribe until the
    /// previous session has finished. The map keeps the mutex alive for any
    /// session or waiter that still holds it.
    fn session_gate(&self, account: &AccountId) -> Arc<tokio::sync::Mutex<()>> {
        let mut gates = self
            .inner
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(account).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(tokio::sync::Mutex::new(()));
        gates.insert(account.clone(), Arc::downgrade(&gate));
        gate
    }

    /// Starts watchers for every account with an enabled webhook that this
    /// process watches.
    pub async fn start_all(&self) {
        if !self.inner.config.enabled {
            return;
        }
        match self.inner.store.enabled_webhooks().await {
            Ok(accounts) => {
                let owned: Vec<&AccountId> = accounts
                    .iter()
                    .filter(|account| self.owns(account))
                    .collect();
                tracing::info!(count = owned.len(), "starting new-mail watchers");
                for account in owned {
                    self.refresh(account);
                }
            }
            Err(err) => tracing::error!(error = %err, "could not list webhooks"),
        }
    }

    /// Restarts the watcher of `account` after its settings, password or
    /// existence changed. The new watcher exits at once if the webhook is
    /// now disabled or gone.
    ///
    /// The spawned task waits until the previous session of this account
    /// has finished, including a Gmail `users.stop` or a Graph unsubscribe,
    /// before it subscribes or reads a cursor. The wait does not block this
    /// call. A newer refresh or shutdown cancels it, so a queued session
    /// does not start work on the way down.
    ///
    /// For a mailbox another process watches, this stops anything still
    /// running for it here and passes the change on to that process.
    pub fn refresh(&self, account: &AccountId) {
        let inner = &self.inner;
        if !inner.config.enabled || inner.shutdown.is_cancelled() {
            return;
        }
        if !self.owns(account) {
            self.stop(account);
            self.forward(WatchSignal::Changed(account.clone()));
            return;
        }
        let generation = inner
            .next_generation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cancel = inner.shutdown.child_token();
        {
            let mut tasks = inner.tasks.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(old) = tasks.remove(account) {
                old.cancel.cancel();
            } else if tasks.len() >= inner.config.max_watchers {
                tracing::warn!(account_id = %account, max = inner.config.max_watchers, "too many new-mail watchers; not starting another");
                if let Some(metrics) = self.metrics() {
                    metrics.watcher_refused();
                }
                return;
            }
            tasks.insert(
                account.clone(),
                Task {
                    cancel: cancel.clone(),
                    generation,
                },
            );
        }
        // New settings apply to stored events too. `refresh` runs on every
        // account-change notification, so this tries once immediately: a
        // restart, saving the settings, turning the webhook back on, a
        // successful test, or signing in again (the account page or OAuth
        // authorize) does not wait out a pause. Replacing the password or
        // rotating the signing secret does the same. A webhook the user
        // turned off stops without delivering. A paused webhook stays
        // enabled, so the watcher keeps recording.
        self.wake_prompt(account);
        let this = self.clone();
        let account = account.clone();
        inner.tracker.spawn(async move {
            let gate = this.session_gate(&account);
            tokio::select! {
                () = cancel.cancelled() => {}
                guard = gate.lock_owned() => {
                    // Cancel may have won the race with the lock. Do not
                    // subscribe once this session has been replaced or the
                    // process is shutting down.
                    if !cancel.is_cancelled() {
                        this.watch(&account, &cancel).await;
                    }
                    drop(guard);
                }
            }
            let mut tasks = this
                .inner
                .tasks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if tasks
                .get(&account)
                .is_some_and(|task| task.generation == generation)
            {
                tasks.remove(&account);
            }
        });
    }

    /// The client used for deliveries.
    #[must_use]
    pub fn deliverer(&self) -> &Deliverer {
        &self.inner.deliverer
    }

    /// Number of running watchers.
    #[must_use]
    pub fn running(&self) -> usize {
        self.inner
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Stops every watcher and waits up to `grace` for them to log out.
    pub async fn shutdown(&self, grace: Duration) {
        self.inner.shutdown.cancel();
        self.inner.tracker.close();
        if tokio::time::timeout(grace, self.inner.tracker.wait())
            .await
            .is_err()
        {
            tracing::warn!("new-mail watchers did not stop in time");
        }
    }

    async fn watch(&self, account: &AccountId, cancel: &CancellationToken) {
        let config = &self.inner.config;
        let mut failures = 0u32;
        // A password already on record as rejected gets one more try, not three.
        let recorded = self.inner.store.password_rejected_at(account).await;
        let mut rejections = match recorded {
            Ok(Some(_)) => STOP_AFTER_REJECTIONS - 1,
            Ok(None) => 0,
            Err(err) => {
                tracing::warn!(account_id = %account, error = %err, "could not read the record of a rejected password");
                0
            }
        };
        loop {
            if !self.owns(account) {
                return;
            }
            let run = self
                .run_once(account, cancel, &mut failures, &mut rejections)
                .await;
            let delay = match run {
                Ok(Exit::Stopped | Exit::Disabled) => return,
                Err(WatchError::Mail(postkeep_mail::Error::Authentication)) => {
                    rejections += 1;
                    if rejections >= STOP_AFTER_REJECTIONS {
                        tracing::warn!(
                            account_id = %account,
                            rejections,
                            "the mail server rejected the stored password again; the new-mail watcher stops until the account changes or the server restarts"
                        );
                        if let Err(err) = self.inner.store.mark_password_rejected(account).await {
                            tracing::error!(account_id = %account, error = %err, "could not record the rejected password");
                        }
                        return;
                    }
                    tracing::warn!(
                        account_id = %account,
                        rejections,
                        retry_in = ?config.auth_backoff,
                        "the mail server rejected the stored password; new-mail watcher waits"
                    );
                    config.auth_backoff
                }
                Err(err) => {
                    failures = failures.saturating_add(1);
                    let delay = config
                        .min_backoff
                        .saturating_mul(2u32.saturating_pow(failures.saturating_sub(1).min(16)))
                        .min(config.max_backoff);
                    tracing::warn!(account_id = %account, error = %err, retry_in = ?delay, "new-mail watcher failed");
                    delay
                }
            };
            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// The mail server accepted the stored password: a record that it had
    /// rejected it goes.
    async fn password_accepted(&self, account: &AccountId) {
        match self.inner.store.clear_password_rejected(account).await {
            Ok(true) => {
                tracing::info!(account_id = %account, "the mail server accepts the stored password again");
            }
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(account_id = %account, error = %err, "could not clear the record of a rejected password");
            }
        }
    }

    /// Whether the allow-list refuses `account`.
    ///
    /// A missing account is not a refusal. The message names the account id
    /// and not the address. Callers stop the watcher and leave stored
    /// subscriptions and positions alone.
    async fn allow_list_blocks(&self, account: &AccountId) -> Result<bool, WatchError> {
        let blocked = self
            .inner
            .store
            .account(account)
            .await?
            .is_some_and(|row| !self.inner.config.email_allowed(&row.email));
        if blocked {
            tracing::info!(account_id = %account, "account is not on the allow-list; not watching it");
        }
        Ok(blocked)
    }

    /// One watcher run for the account's provider.
    async fn run_once(
        &self,
        account: &AccountId,
        cancel: &CancellationToken,
        failures: &mut u32,
        rejections: &mut u32,
    ) -> Result<Exit, WatchError> {
        let Some(provider) = self
            .inner
            .store
            .account(account)
            .await?
            .map(|account| account.provider)
        else {
            return Ok(Exit::Disabled);
        };
        let run = match provider {
            postkeep_store::Provider::Graph => self.graph_session(account, cancel, failures).await,
            postkeep_store::Provider::Gmail => self.gmail_session(account, cancel, failures).await,
            postkeep_store::Provider::Imap => {
                self.session(account, cancel, failures, rejections).await
            }
        };
        // The account's deletion committed while the session ran: the run
        // ends as it does for an account that is gone, and is not a failure.
        // A save says so, as when the provider answers a renewal late. After
        // another failure in the store or at the provider, such as a token
        // refresh that finds the tokens gone, the run looks for the account
        // again; a failed look keeps the run's error. A deletion changes
        // nothing at the mail server, so its failures are not looked into.
        let deleted = match &run {
            Err(WatchError::Store(StoreError::AccountDeleted)) => true,
            Err(WatchError::Store(_) | WatchError::Api(_)) => {
                matches!(self.inner.store.account(account).await, Ok(None))
            }
            _ => false,
        };
        if deleted {
            tracing::debug!(account_id = %account, "the account was deleted; the new-mail watcher stops");
            return Ok(Exit::Disabled);
        }
        // A rejected password is counted as the login's outcome, not here:
        // `watch` tries a recorded one again at every start.
        if let Err(err) = &run
            && !matches!(err, WatchError::Mail(postkeep_mail::Error::Authentication))
            && let Some(metrics) = self.metrics()
        {
            metrics.watcher_error(provider);
        }
        run
    }

    /// One IMAP session: connect, catch up, then wait for changes until
    /// cancelled or an error occurs. Once `connect_imap` has logged in,
    /// `rejections` starts again from zero, whatever the session meets next.
    async fn session(
        &self,
        account: &AccountId,
        cancel: &CancellationToken,
        failures: &mut u32,
        rejections: &mut u32,
    ) -> Result<Exit, WatchError> {
        let store = &self.inner.store;
        let Some(hook) = readable_webhook(store, account).await? else {
            return Ok(Exit::Disabled);
        };
        if !hook.settings.enabled {
            // A pause leaves the webhook enabled, so the watcher keeps
            // running and recording events. Only the user turning it off
            // stops the watcher.
            return Ok(Exit::Disabled);
        }
        let Some(stored) = store.credentials(account).await? else {
            return Ok(Exit::Disabled);
        };
        if !self.inner.config.email_allowed(&stored.email) {
            tracing::info!(account_id = %account, "account is not on the allow-list; not watching it");
            return Ok(Exit::Disabled);
        }
        let Some(server) = self.inner.servers.resolve(stored.imap_server.as_deref()) else {
            tracing::warn!(account_id = %account, "the account's mail provider is no longer offered; not watching it");
            return Ok(Exit::Disabled);
        };
        let email = stored.email.clone();
        let client = server.client(&stored.email, &stored.password)?;
        let mut session = tokio::select! {
            () = cancel.cancelled() => return Ok(Exit::Stopped),
            session = client.connect_imap() => self.count_login(server.id.id(), session)?,
        };
        *rejections = 0;
        self.password_accepted(account).await;
        let state = session.examine(FOLDER).await?;
        let fresh = WatchCursor {
            uid_validity: state.uid_validity,
            last_uid: state.uid_next.saturating_sub(1),
        };
        let Some(mut cursor) = self.start_cursor(account, hook.cursor, fresh).await? else {
            let _ = session.logout().await;
            return Ok(Exit::Disabled);
        };
        // Only now: a start that keeps losing the cursor waits longer each time.
        *failures = 0;
        let mut uid_next = state.uid_next;
        tracing::debug!(account_id = %account, idle = session.supports_idle(), "new-mail watcher started");

        loop {
            // `report` drains the whole backlog before this loop waits.
            // One IDLE wake-up is not one batch.
            if uid_next.saturating_sub(1) > cursor.last_uid {
                match self
                    .report(account, &email, &mut session, &mut cursor, uid_next, cancel)
                    .await?
                {
                    None => {}
                    Some(exit) => {
                        let _ = session.logout().await;
                        return Ok(exit);
                    }
                }
            }

            // Wait for a change.
            let changed = if session.supports_idle() {
                let (back, event) = session
                    .idle(self.inner.config.idle_wait, cancel.cancelled())
                    .await?;
                session = back;
                match event {
                    IdleEvent::Stopped => {
                        let _ = session.logout().await;
                        return Ok(Exit::Stopped);
                    }
                    IdleEvent::Changed => true,
                    IdleEvent::Timeout => false,
                }
            } else {
                tokio::select! {
                    () = cancel.cancelled() => {
                        let _ = session.logout().await;
                        return Ok(Exit::Stopped);
                    }
                    () = tokio::time::sleep(self.inner.config.poll_interval) => true,
                }
            };
            if changed {
                tokio::select! {
                    () = cancel.cancelled() => {
                        let _ = session.logout().await;
                        return Ok(Exit::Stopped);
                    }
                    () = tokio::time::sleep(self.inner.config.debounce) => {}
                }
            }
            // EXAMINE again for a fresh UIDNEXT; it also keeps the
            // connection alive after an IDLE timeout.
            let state = session.examine(FOLDER).await?;
            if state.uid_validity != cursor.uid_validity {
                let fresh = WatchCursor {
                    uid_validity: state.uid_validity,
                    last_uid: state.uid_next.saturating_sub(1),
                };
                let Some(started) = self.start_cursor(account, Some(cursor), fresh).await? else {
                    let _ = session.logout().await;
                    return Ok(Exit::Disabled);
                };
                cursor = started;
                tracing::info!(account_id = %account, "INBOX UIDVALIDITY changed; watching from the current position");
            }
            uid_next = state.uid_next;
        }
    }

    /// The cursor a session reads from: `read`, the stored one, if it is for
    /// this `UIDVALIDITY`, and else `fresh`.
    ///
    /// `fresh` is for a first start or a changed `UIDVALIDITY`, when the mail
    /// already there is old. It is stored only over the cursor that was read.
    /// When another owner changed the cursor meanwhile, it is read again: one
    /// for this `UIDVALIDITY` is taken as it is, so the mail it has not
    /// reported is not skipped, and any other is replaced in the same way, up to
    /// [`START_CURSOR_ATTEMPTS`] tries in all. Returns `None` when the webhook
    /// is gone.
    ///
    /// # Errors
    ///
    /// [`WatchError::CursorMoved`] when every try found the cursor changed,
    /// and the store's errors.
    async fn start_cursor(
        &self,
        account: &AccountId,
        read: Option<WatchCursor>,
        fresh: WatchCursor,
    ) -> Result<Option<WatchCursor>, WatchError> {
        let store = &self.inner.store;
        let mut read = read;
        for attempt in 0..START_CURSOR_ATTEMPTS {
            if attempt > 0 {
                let Some(hook) = readable_webhook(store, account).await? else {
                    return Ok(None);
                };
                read = hook.cursor;
            }
            if let Some(cursor) = read.filter(|cursor| cursor.uid_validity == fresh.uid_validity) {
                return Ok(Some(cursor));
            }
            if store.advance_watch_cursor(account, read, fresh).await? {
                return Ok(Some(fresh));
            }
        }
        Err(WatchError::CursorMoved)
    }

    /// The position a Graph or Gmail session starts from: `read`, the stored
    /// one, if `usable` accepts it, and else `fresh`.
    ///
    /// `fresh` is for a first start, when the mail already there is old. It is
    /// stored only over the position that was read. When another watcher
    /// changed the position meanwhile, it is read again: one that `usable`
    /// accepts is taken as it is, so the mail after it is not skipped, and any
    /// other is replaced in the same way, up to [`START_CURSOR_ATTEMPTS`] tries
    /// in all. Returns `None` when the webhook is gone.
    ///
    /// # Errors
    ///
    /// [`WatchError::CursorMoved`] when every try found the position changed,
    /// and the store's errors.
    async fn start_position(
        &self,
        account: &AccountId,
        read: Option<String>,
        fresh: String,
        usable: fn(Option<&str>) -> bool,
    ) -> Result<Option<String>, WatchError> {
        let store = &self.inner.store;
        let mut read = read;
        for _ in 0..START_CURSOR_ATTEMPTS {
            if usable(read.as_deref()) {
                return Ok(read);
            }
            if store
                .advance_watch_position(account, read.as_deref(), &fresh)
                .await?
            {
                return Ok(Some(fresh));
            }
            let Some(hook) = readable_webhook(store, account).await? else {
                return Ok(None);
            };
            read = hook.position;
        }
        Err(WatchError::CursorMoved)
    }

    /// Delivers the backlog after the cursor, oldest first, then returns.
    ///
    /// Each event covers at most [`BATCH_LIMIT`] messages and describes the
    /// newest that passes the rules. The cursor moves to the batch's highest UID
    /// in the same transaction as the event, and only when it is still the
    /// cursor this batch was read from. A cursor another task already moved
    /// drops the batch; the drain continues from the stored cursor, or ends
    /// when the watcher was cancelled. Returns `Some` when the watcher
    /// should end. Cancellation or a disabled webhook between batches leaves
    /// the cursor on the last stored event, so a restart reports the rest
    /// and nothing is skipped. The caller does not go back to `IDLE` until
    /// this returns.
    async fn report(
        &self,
        account: &AccountId,
        email: &str,
        session: &mut ImapSession,
        cursor: &mut WatchCursor,
        uid_next: u32,
        cancel: &CancellationToken,
    ) -> Result<Option<Exit>, WatchError> {
        self.drain(
            account,
            email,
            cursor,
            uid_next,
            cancel,
            &mut BacklogSource::Session(session),
        )
        .await
    }

    /// Same drain as [`Self::report`], reading batches from `fetch`.
    ///
    /// The closure returns one search-and-fetch: the oldest messages after
    /// the UID it is given, at most [`BATCH_LIMIT`], and the highest UID
    /// that search selected. `selected_through` is `None` when the search
    /// found nothing.
    #[cfg(test)]
    async fn report_scripted(
        &self,
        account: &AccountId,
        email: &str,
        cursor: &mut WatchCursor,
        uid_next: u32,
        cancel: &CancellationToken,
        fetch: &mut (dyn FnMut(u32) -> Result<MessageBatch, WatchError> + Send),
    ) -> Result<Option<Exit>, WatchError> {
        self.drain(
            account,
            email,
            cursor,
            uid_next,
            cancel,
            &mut BacklogSource::Scripted(fetch),
        )
        .await
    }

    /// Publishes every batch `source` returns until `uid_next` is caught up.
    ///
    /// An empty search, nothing selected above the cursor, advances the
    /// cursor to `uid_next - 1` with no event. An empty fetch after a
    /// non-empty selection advances only through that selection's highest
    /// UID and the drain continues. A fetch that returns only some of the
    /// selected messages publishes those and moves the cursor to the
    /// highest UID it returned, so a selected message the server omitted
    /// is read on the next pass. The cursor never moves past a UID this
    /// pass did not select. A batch no message of which passes the mailbox's
    /// rules moves the cursor, on the same terms, with no event. Every move
    /// is from the cursor this pass read: one that another owner moved on
    /// meanwhile is not moved back, and the drain reads on from it. One moved
    /// back is moved forward again, so nothing is read twice.
    async fn drain(
        &self,
        account: &AccountId,
        email: &str,
        cursor: &mut WatchCursor,
        uid_next: u32,
        cancel: &CancellationToken,
        source: &mut BacklogSource<'_>,
    ) -> Result<Option<Exit>, WatchError> {
        let store = &self.inner.store;
        // Mail past this examined `UIDNEXT` waits for the next `IDLE`.
        // Re-examining here could follow new mail forever.
        let caught_up_at = uid_next.saturating_sub(1);
        loop {
            if cancel.is_cancelled() {
                return Ok(Some(Exit::Stopped));
            }
            if cursor.last_uid >= caught_up_at {
                return Ok(None);
            }
            let batch = next_batch(source, cursor.last_uid).await?;
            if batch.messages.is_empty() {
                // Nothing to report, so the cursor moves with no event. Selected
                // messages that were expunged before the fetch: move through that
                // selection only, since newer UIDs the search did not put in this
                // chunk are still pending. A search that found nothing below
                // UIDNEXT: move to it, so the next pass does not search again.
                let through = match batch.selected_through {
                    Some(through) if through > cursor.last_uid => through,
                    Some(_) => return Ok(None),
                    None => caught_up_at,
                };
                if let ControlFlow::Break(exit) =
                    self.skip_to(account, cursor, through, cancel).await?
                {
                    return Ok(exit);
                }
                continue;
            }
            let Some(top) = batch.messages.iter().map(|message| message.uid).max() else {
                return Ok(None);
            };
            if top <= cursor.last_uid {
                // The server made no progress. Stop rather than spin; the
                // next IDLE cycle tries again.
                return Ok(None);
            }
            // Reload: the settings may have changed while we waited.
            let Some(hook) = readable_webhook(store, account).await? else {
                return Ok(Some(Exit::Disabled));
            };
            if !hook.settings.enabled {
                // Paused webhooks stay enabled and keep recording. See
                // [`Watchers::session`].
                return Ok(Some(Exit::Disabled));
            }
            // Rules that can't be read hold the batch where it is: nothing is skipped.
            let Some(rules) = self.rules(account, &hook).await? else {
                return Ok(Some(Exit::Disabled));
            };
            let passing = rules.keep(batch.messages).await;
            if cancel.is_cancelled() {
                // Not advancing the cursor: this batch is recorded after restart.
                return Ok(Some(Exit::Stopped));
            }
            let expected = *cursor;
            let next = WatchCursor {
                uid_validity: cursor.uid_validity,
                last_uid: top,
            };
            let count = passing.len();
            let Some(newest) = passing.into_iter().max_by_key(|message| message.uid) else {
                if let ControlFlow::Break(exit) = self.skip_to(account, cursor, top, cancel).await?
                {
                    return Ok(exit);
                }
                continue;
            };
            let event = new_mail_event(email, &newest, count, cursor.uid_validity);
            let event = if hook.settings.include_sender {
                event
            } else {
                event.without_sender_and_subject()
            };
            match self
                .publish(
                    account,
                    &event,
                    Some(WatchAdvance::Cursor { expected, next }),
                )
                .await?
            {
                AppendOutcome::Stored(_) => cursor.last_uid = top,
                AppendOutcome::NoWebhook => return Ok(Some(Exit::Disabled)),
                AppendOutcome::StaleCursor => {
                    match self.after_stale_cursor(account, cursor, cancel).await? {
                        AfterStale::Resume(last_uid) => cursor.last_uid = last_uid,
                        AfterStale::Stopped => return Ok(Some(Exit::Stopped)),
                        AfterStale::Disabled => return Ok(Some(Exit::Disabled)),
                        AfterStale::EndPass => return Ok(None),
                    }
                }
            }
        }
    }

    /// Moves the cursor to `last_uid` with no event, from where this drain read
    /// it.
    ///
    /// A cursor another owner moved on stays where that owner put it,
    /// and the drain goes on as [`Self::after_stale_cursor`] decides. `Continue`
    /// means the drain reads on from `cursor`, and `Break` carries what it
    /// returns.
    async fn skip_to(
        &self,
        account: &AccountId,
        cursor: &mut WatchCursor,
        last_uid: u32,
        cancel: &CancellationToken,
    ) -> Result<ControlFlow<Option<Exit>>, WatchError> {
        let next = WatchCursor {
            uid_validity: cursor.uid_validity,
            last_uid,
        };
        let store = &self.inner.store;
        let moved = store.advance_watch_cursor(account, Some(*cursor), next);
        if moved.await? {
            cursor.last_uid = last_uid;
            return Ok(ControlFlow::Continue(()));
        }
        let flow = match self.after_stale_cursor(account, cursor, cancel).await? {
            AfterStale::Resume(last_uid) => {
                cursor.last_uid = last_uid;
                ControlFlow::Continue(())
            }
            AfterStale::Stopped => ControlFlow::Break(Some(Exit::Stopped)),
            AfterStale::Disabled => ControlFlow::Break(Some(Exit::Disabled)),
            AfterStale::EndPass => ControlFlow::Break(None),
        };
        Ok(flow)
    }

    /// Decides how to continue after an IMAP cursor compare-and-set lost.
    ///
    /// The batch was not stored. A cancelled watcher stops. A live one
    /// adopts a stored cursor that moved on under the same `UIDVALIDITY` and
    /// drains from there, so it does not publish the batch again.
    ///
    /// A stored cursor behind this one was moved back by a writer that does
    /// not compare, as an older version can during an upgrade. This drain has
    /// reported up to `cursor`, so it moves the stored one forward to it again,
    /// only from where that writer left it, and goes on: reading from the older
    /// cursor would report that mail twice. If that move loses too, the pass
    /// ends.
    async fn after_stale_cursor(
        &self,
        account: &AccountId,
        cursor: &WatchCursor,
        cancel: &CancellationToken,
    ) -> Result<AfterStale, WatchError> {
        if cancel.is_cancelled() {
            return Ok(AfterStale::Stopped);
        }
        let Some(hook) = readable_webhook(&self.inner.store, account).await? else {
            return Ok(AfterStale::Disabled);
        };
        if !hook.settings.enabled {
            return Ok(AfterStale::Disabled);
        }
        let same_folder = |stored: &WatchCursor| stored.uid_validity == cursor.uid_validity;
        let Some(stored) = hook.cursor.filter(same_folder) else {
            return Ok(AfterStale::EndPass);
        };
        if stored.last_uid > cursor.last_uid {
            return Ok(AfterStale::Resume(stored.last_uid));
        }
        if stored.last_uid < cursor.last_uid {
            let store = &self.inner.store;
            let forward = store.advance_watch_cursor(account, Some(stored), *cursor);
            if forward.await? {
                return Ok(AfterStale::Resume(cursor.last_uid));
            }
        }
        Ok(AfterStale::EndPass)
    }
}

/// How the backlog drain continues after the cursor compare-and-set lost.
enum AfterStale {
    /// Keep draining from this last UID.
    Resume(u32),
    /// The watcher was cancelled.
    Stopped,
    /// The webhook is gone or disabled.
    Disabled,
    /// The stored cursor is for another `UIDVALIDITY` or none, is where this
    /// drain is, or is behind it and could not be moved forward.
    EndPass,
}

/// Where a backlog drain reads its next oldest batch.
enum BacklogSource<'a> {
    /// The watched IMAP folder.
    Session(&'a mut ImapSession),
    /// A stand-in used by tests.
    #[cfg(test)]
    Scripted(&'a mut (dyn FnMut(u32) -> Result<MessageBatch, WatchError> + Send)),
}

/// The oldest batch `source` has after `after`.
async fn next_batch(
    source: &mut BacklogSource<'_>,
    after: u32,
) -> Result<MessageBatch, WatchError> {
    match source {
        BacklogSource::Session(session) => session
            .message_batch_after(after, BATCH_LIMIT)
            .await
            .map_err(WatchError::from),
        #[cfg(test)]
        BacklogSource::Scripted(fetch) => fetch(after),
    }
}

/// Delay before another try after `failures` transient failures, counting
/// the failure that just happened as 1. The wait starts at the longer of
/// the debounce and `min_backoff`, doubles, and does not grow past
/// `max_backoff`.
fn catch_up_retry_delay(failures: u32, config: &WatchConfig) -> Duration {
    let base = config.debounce.max(config.min_backoff);
    let scaled = base.saturating_mul(2u32.saturating_pow(failures.saturating_sub(1).min(16)));
    scaled.min(config.max_backoff.max(base))
}

/// The provider rejected the stored sign-in, or there is nothing to refresh.
fn needs_sign_in(err: &WatchError) -> bool {
    matches!(
        err,
        WatchError::Api(err)
            if matches!(
                err.as_ref(),
                ApiError::Token(TokenError::NeedsReauth { .. } | TokenError::NotConnected(_))
            )
    )
}

/// Failures a later attempt might get past: timeouts, rate limits, 5xx,
/// transport errors, and the database. A bad sign-in and a rejected
/// request are not in this set.
fn is_transient(err: &WatchError) -> bool {
    match err {
        WatchError::Store(_) | WatchError::CursorMoved => true,
        WatchError::Mail(_) | WatchError::NotConfigured | WatchError::Malformed(_) => false,
        WatchError::Api(err) => api_is_transient(err),
    }
}

fn api_is_transient(err: &ApiError) -> bool {
    match err {
        ApiError::Http(
            HttpError::Timeout(_) | HttpError::Connect(_) | HttpError::Transport { .. },
        )
        | ApiError::Token(TokenError::Store(_) | TokenError::OAuth(_)) => true,
        ApiError::Status { status, .. } => {
            status.is_server_error() || status.as_u16() == 408 || err.is_rate_limited()
        }
        ApiError::Http(_) | ApiError::Malformed { .. } | ApiError::Token(_) => false,
    }
}

fn warn_catch_up(account: &AccountId, provider: ProviderCatchUp, err: &WatchError, detail: &str) {
    let provider = match provider {
        ProviderCatchUp::Graph => "outlook",
        ProviderCatchUp::Gmail => "gmail",
    };
    tracing::warn!(account_id = %account, provider, error = %err, "{detail}");
}

/// The event for a batch whose newest message is `newest`, read from the
/// folder whose `UIDVALIDITY` is `uid_validity`.
fn new_mail_event(
    email: &str,
    newest: &NewMessage,
    count: usize,
    uid_validity: u32,
) -> NewMailEvent {
    let (from, from_unclear) =
        invisible::senders(newest.from.as_ref(), newest.from_clear, &newest.from_values);
    NewMailEvent {
        event: NEW_MAIL,
        test: false,
        account: email.to_owned(),
        folder: FOLDER.to_owned(),
        id: crate::mailbox::id::imap_id(FOLDER, newest.uid, Some(uid_validity)),
        uid: Some(newest.uid),
        message_id: newest.message_id.as_deref().map(invisible::visible),
        from: from.into_iter().next(),
        from_unclear,
        subject: newest.subject.as_deref().map(invisible::visible),
        date: newest.date.map(|date| date.to_rfc3339()),
        count: u32::try_from(count).unwrap_or(u32::MAX),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]
mod backlog_tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use postkeep_mail::{EmailAddress, ImapServers, MessageBatch, NewMessage};
    use postkeep_store::{
        AccountId, AppendOutcome, ChangedFilterRule, MasterKey, Store, WatchAdvance, WatchCursor,
        WebhookSettings,
    };
    use postkeep_webhook::testing::{Receiver, receiver};
    use secrecy::SecretString;
    use tokio_util::sync::CancellationToken;

    use super::harness::{FilterLimit, allow, next_event};
    use super::rules::Rules;
    use super::{
        BATCH_LIMIT, Exit, WatchConfig, WatchError, Watchers, is_transient, new_mail_event,
    };

    /// First new UID. The cursor starts just below it, as a watcher does
    /// after the mailbox's existing mail.
    const FIRST_UID: u32 = 1_001;
    const TOTAL: u32 = 120;
    /// `UIDNEXT` once those messages exist: one past the last UID.
    const UID_NEXT: u32 = FIRST_UID + TOTAL;

    struct Backlog {
        store: Store,
        account: AccountId,
        watchers: Watchers,
        receiver: Receiver,
        cursor: WatchCursor,
        uid_next: u32,
        seen: Mutex<Vec<u32>>,
        _dir: tempfile::TempDir,
    }

    async fn backlog() -> Backlog {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("backlog.db").display());
        let store = Store::connect(
            &url,
            &MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap(),
        )
        .await
        .unwrap();
        let account = store
            .upsert_account(
                "backlog@example.com",
                &SecretString::from("password".to_owned()),
            )
            .await
            .unwrap();
        let receiver = receiver(&[]).await;
        store
            .save_webhook(
                &account.id,
                &WebhookSettings {
                    enabled: true,
                    url: receiver.url("/hook"),
                    auth_header: None,
                    signing: false,
                    signing_secret: SecretString::from("whsec_test".to_owned()),
                    include_sender: true,
                },
            )
            .await
            .unwrap();
        let cursor = WatchCursor {
            uid_validity: 7,
            last_uid: FIRST_UID - 1,
        };
        store.set_watch_cursor(&account.id, cursor).await.unwrap();
        let watchers = Watchers::new(
            store.clone(),
            ImapServers::default(),
            receiver.deliverer.clone(),
            WatchConfig {
                debounce: Duration::from_millis(20),
                max_filter_rules: 3,
                retry_delays: Vec::new(),
                outbox_min_backoff: Duration::from_millis(20),
                ..WatchConfig::default()
            },
            CancellationToken::new(),
        );
        Backlog {
            store,
            account: account.id,
            watchers,
            receiver,
            cursor,
            uid_next: UID_NEXT,
            seen: Mutex::default(),
            _dir: dir,
        }
    }

    /// The oldest [`BATCH_LIMIT`] scripted messages with a UID above `after`.
    fn scripted(after: u32) -> Vec<NewMessage> {
        (FIRST_UID..UID_NEXT)
            .filter(|uid| *uid > after)
            .take(BATCH_LIMIT)
            .map(|uid| NewMessage {
                uid,
                message_id: Some(format!("<{uid}@example.com>")),
                from: Some(EmailAddress::new(format!("sender{uid}@example.com"))),
                from_clear: true,
                from_values: Vec::new(),
                recipients: vec![EmailAddress::new(format!("to{uid}@example.com"))],
                subject: Some(format!("message {uid}")),
                date: None,
            })
            .collect()
    }

    /// [`scripted`], and the highest UID that batch selected. An empty batch
    /// is an empty search: nothing was selected.
    fn scripted_batch(after: u32) -> MessageBatch {
        let messages = scripted(after);
        let selected_through = messages.last().map(|message| message.uid);
        MessageBatch {
            messages,
            selected_through,
        }
    }

    struct Delivered {
        count: u64,
        uid: u64,
        sequence: String,
        subject: String,
    }

    async fn take_event(receiver: &mut Receiver) -> Delivered {
        let got = next_event(receiver).await;
        let json = got.json();
        Delivered {
            count: json["count"].as_u64().unwrap(),
            uid: json["uid"].as_u64().unwrap(),
            sequence: got
                .header("x-webhook-sequence")
                .expect("sequence header")
                .to_owned(),
            subject: json["subject"].as_str().unwrap().to_owned(),
        }
    }

    async fn no_further_event(receiver: &mut Receiver) {
        let extra =
            tokio::time::timeout(Duration::from_millis(400), receiver.requests.recv()).await;
        assert!(extra.is_err(), "unexpected extra event: {extra:?}");
    }

    #[tokio::test]
    async fn a_backlog_is_delivered_oldest_first_in_batches() {
        let mut setup = backlog().await;
        let mut cursor = setup.cursor;
        let mut fetch = |after| Ok(scripted_batch(after));
        let exit = setup
            .watchers
            .report_scripted(
                &setup.account,
                "backlog@example.com",
                &mut cursor,
                UID_NEXT,
                &CancellationToken::new(),
                &mut fetch,
            )
            .await
            .unwrap();
        assert!(exit.is_none());
        assert_eq!(cursor.last_uid, FIRST_UID + TOTAL - 1);

        let mut events = Vec::new();
        for _ in 0..3 {
            events.push(take_event(&mut setup.receiver).await);
        }
        assert_eq!(
            events.iter().map(|event| event.count).collect::<Vec<_>>(),
            vec![50, 50, 20]
        );
        assert_eq!(
            events.iter().map(|event| event.uid).collect::<Vec<_>>(),
            vec![1050, 1100, 1120]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        assert_eq!(events[0].subject, "message 1050");
        assert_eq!(events[1].subject, "message 1100");
        assert_eq!(events[2].subject, "message 1120");
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.cursor.unwrap().last_uid, 1120);
        assert_eq!(hook.last_sequence, 3);
        no_further_event(&mut setup.receiver).await;
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn cancellation_mid_backlog_resumes_without_loss() {
        let mut setup = backlog().await;
        let mut cursor = setup.cursor;
        let cancel = CancellationToken::new();
        let calls = AtomicUsize::new(0);
        let stop = cancel.clone();
        let mut fetch = |after| {
            // The second fetch is the next batch. Cancel before it is
            // published so the stored cursor stays on the first.
            if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                stop.cancel();
            }
            Ok(scripted_batch(after))
        };
        let exit = setup
            .watchers
            .report_scripted(
                &setup.account,
                "backlog@example.com",
                &mut cursor,
                UID_NEXT,
                &cancel,
                &mut fetch,
            )
            .await
            .unwrap();
        assert!(matches!(exit, Some(Exit::Stopped)));
        assert_eq!(cursor.last_uid, 1050);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.cursor.unwrap().last_uid, 1050);
        assert_eq!(hook.last_sequence, 1);

        // Restart from the persisted cursor, with cancellation cleared.
        let mut cursor = hook.cursor.unwrap();
        let mut fetch = |after| Ok(scripted_batch(after));
        let exit = setup
            .watchers
            .report_scripted(
                &setup.account,
                "backlog@example.com",
                &mut cursor,
                UID_NEXT,
                &CancellationToken::new(),
                &mut fetch,
            )
            .await
            .unwrap();
        assert!(exit.is_none());

        let mut events = Vec::new();
        for _ in 0..3 {
            events.push(take_event(&mut setup.receiver).await);
        }
        assert_eq!(
            events.iter().map(|event| event.count).collect::<Vec<_>>(),
            vec![50, 50, 20]
        );
        assert_eq!(
            events.iter().map(|event| event.uid).collect::<Vec<_>>(),
            vec![1050, 1100, 1120]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.cursor.unwrap().last_uid, 1120);
        assert_eq!(hook.last_sequence, 3);
        no_further_event(&mut setup.receiver).await;
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn an_empty_search_advances_the_cursor_without_an_event() {
        let mut setup = backlog().await;
        let mut cursor = setup.cursor;
        let mut fetch = |_after| {
            Ok(MessageBatch {
                messages: Vec::new(),
                selected_through: None,
            })
        };
        let exit = setup
            .watchers
            .report_scripted(
                &setup.account,
                "backlog@example.com",
                &mut cursor,
                1_005,
                &CancellationToken::new(),
                &mut fetch,
            )
            .await
            .unwrap();
        assert!(exit.is_none());
        assert_eq!(cursor.last_uid, 1_004);
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.cursor.unwrap().last_uid, 1_004);
        assert_eq!(hook.last_sequence, 0);
        no_further_event(&mut setup.receiver).await;
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn an_empty_fetch_does_not_skip_the_rest_of_the_backlog() {
        let mut setup = backlog().await;
        let mut cursor = setup.cursor;
        let calls = AtomicUsize::new(0);
        // The oldest batch was selected, then expunged before FETCH.
        let selected_through = FIRST_UID + u32::try_from(BATCH_LIMIT).unwrap() - 1;
        let mut fetch = |after| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                assert_eq!(after, FIRST_UID - 1);
                return Ok(MessageBatch {
                    messages: Vec::new(),
                    selected_through: Some(selected_through),
                });
            }
            Ok(scripted_batch(after))
        };
        let exit = setup
            .watchers
            .report_scripted(
                &setup.account,
                "backlog@example.com",
                &mut cursor,
                UID_NEXT,
                &CancellationToken::new(),
                &mut fetch,
            )
            .await
            .unwrap();
        assert!(exit.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(cursor.last_uid, FIRST_UID + TOTAL - 1);

        let mut events = Vec::new();
        for _ in 0..2 {
            events.push(take_event(&mut setup.receiver).await);
        }
        // 1051..=1120 is the mail the expunged chunk did not cover.
        assert_eq!(
            events.iter().map(|event| event.count).collect::<Vec<_>>(),
            vec![50, 20]
        );
        assert_eq!(
            events.iter().map(|event| event.uid).collect::<Vec<_>>(),
            vec![1100, 1120]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2"]
        );
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.cursor.unwrap().last_uid, 1120);
        assert_eq!(hook.last_sequence, 2);
        no_further_event(&mut setup.receiver).await;
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn a_partial_fetch_leaves_omitted_messages_for_the_next_batch() {
        let mut setup = backlog().await;
        let mut cursor = setup.cursor;
        let calls = AtomicUsize::new(0);
        let mut fetch = |after| {
            let mut batch = scripted_batch(after);
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                // The search selected the whole oldest chunk. The fetch
                // returned only the first 40; the rest may still be there.
                batch.messages.truncate(40);
            }
            Ok(batch)
        };
        let exit = setup
            .watchers
            .report_scripted(
                &setup.account,
                "backlog@example.com",
                &mut cursor,
                UID_NEXT,
                &CancellationToken::new(),
                &mut fetch,
            )
            .await
            .unwrap();
        assert!(exit.is_none());
        assert_eq!(cursor.last_uid, FIRST_UID + TOTAL - 1);

        let mut events = Vec::new();
        for _ in 0..3 {
            events.push(take_event(&mut setup.receiver).await);
        }
        assert_eq!(
            events.iter().map(|event| event.count).collect::<Vec<_>>(),
            vec![40, 50, 30]
        );
        assert_eq!(
            events.iter().map(|event| event.uid).collect::<Vec<_>>(),
            vec![1040, 1090, 1120]
        );
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(hook.cursor.unwrap().last_uid, 1120);
        assert_eq!(hook.last_sequence, 3);
        no_further_event(&mut setup.receiver).await;
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// One drain of the scripted backlog, from `cursor`.
    async fn drain_scripted(
        setup: &Backlog,
        cursor: &mut WatchCursor,
    ) -> Result<Option<Exit>, WatchError> {
        let mut fetch = |after| {
            setup.seen.lock().unwrap().push(after);
            Ok(scripted_batch(after))
        };
        let (email, cancel) = ("backlog@example.com", CancellationToken::new());
        let watchers = &setup.watchers;
        let account = &setup.account;
        let report =
            watchers.report_scripted(account, email, cursor, setup.uid_next, &cancel, &mut fetch);
        report.await
    }

    /// An event that the store cannot record leaves the cursor where the batch
    /// was read from and ends the drain with an error that is tried again, so
    /// the next pass reports the batch, with nothing lost or reported twice. A
    /// key wrapper that does not answer ends an append in the same way.
    #[tokio::test]
    async fn a_batch_the_store_could_not_record_is_reported_by_the_next_pass() {
        let setup = backlog().await;
        let pool = setup.store.pool();
        let refuse = "CREATE TRIGGER refuse BEFORE INSERT ON mail_events \
                      BEGIN SELECT RAISE(ABORT, 'refused'); END";
        sqlx::query(refuse).execute(pool).await.unwrap();
        let mut cursor = setup.cursor;
        let err = drain_scripted(&setup, &mut cursor).await.err().unwrap();
        assert!(matches!(err, WatchError::Store(_)), "{err:?}");
        assert!(is_transient(&err), "the watcher tries again");
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!((hook.cursor, hook.last_sequence), (Some(setup.cursor), 0));
        assert_eq!(cursor, setup.cursor);

        sqlx::query("DROP TRIGGER refuse")
            .execute(pool)
            .await
            .unwrap();
        assert!(drain_scripted(&setup, &mut cursor).await.unwrap().is_none());
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(
            (hook.cursor.unwrap().last_uid, hook.last_sequence),
            (1120, 3)
        );
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn a_stale_cursor_is_not_published_again() {
        let mut setup = backlog().await;
        // Another watcher already committed the oldest batch from the same
        // cursor. The local cursor is still where that read started.
        let claimed = FIRST_UID + u32::try_from(BATCH_LIMIT).unwrap() - 1;
        let newest = NewMessage {
            uid: claimed,
            message_id: Some(format!("<{claimed}@example.com>")),
            from: Some(EmailAddress::new("sender@example.com")),
            from_clear: true,
            from_values: Vec::new(),
            recipients: Vec::new(),
            subject: Some(format!("message {claimed}")),
            date: None,
        };
        let event = new_mail_event(
            "backlog@example.com",
            &newest,
            BATCH_LIMIT,
            setup.cursor.uid_validity,
        );
        let payload = String::from_utf8(event.to_body()).unwrap();
        let stored = setup
            .store
            .append_mail_event(
                &setup.account,
                &payload,
                Some(WatchAdvance::Cursor {
                    expected: setup.cursor,
                    next: WatchCursor {
                        uid_validity: setup.cursor.uid_validity,
                        last_uid: claimed,
                    },
                }),
            )
            .await
            .unwrap();
        assert!(matches!(stored, AppendOutcome::Stored(_)));

        let mut cursor = setup.cursor;
        let seen = Mutex::new(Vec::new());
        let mut fetch = |after| {
            seen.lock().unwrap().push(after);
            Ok(scripted_batch(after))
        };
        let exit = setup
            .watchers
            .report_scripted(
                &setup.account,
                "backlog@example.com",
                &mut cursor,
                UID_NEXT,
                &CancellationToken::new(),
                &mut fetch,
            )
            .await
            .unwrap();
        assert!(exit.is_none());
        assert_eq!(*seen.lock().unwrap(), vec![FIRST_UID - 1, claimed, 1_100]);
        assert_eq!(cursor.last_uid, FIRST_UID + TOTAL - 1);

        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        assert_eq!(
            hook.last_sequence, 3,
            "the batch already claimed must not be stored again"
        );
        assert_eq!(hook.cursor.unwrap().last_uid, 1120);

        let mut events = Vec::new();
        for _ in 0..3 {
            events.push(take_event(&mut setup.receiver).await);
        }
        assert_eq!(
            events.iter().map(|event| event.uid).collect::<Vec<_>>(),
            vec![u64::from(claimed), 1100, 1120]
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.sequence.as_str())
                .collect::<Vec<_>>(),
            vec!["1", "2", "3"]
        );
        no_further_event(&mut setup.receiver).await;
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    #[test]
    fn events_filter_invisible_characters() {
        let newest = NewMessage {
            uid: 7,
            message_id: Some("<a\u{200B}b@x.test>".to_owned()),
            from: Some(EmailAddress::with_name(
                "Bank\u{202E}knaB\u{200B}",
                "bo\u{200B}ss@x.test",
            )),
            from_clear: true,
            from_values: Vec::new(),
            recipients: Vec::new(),
            subject: Some("Plans\u{E0068}\u{E0069}".to_owned()),
            date: None,
        };
        let event = new_mail_event("me@x.test", &newest, 1, 1);
        assert_eq!(event.message_id.as_deref(), Some("<ab@x.test>"));
        assert_eq!(
            event.from.as_deref(),
            Some("Bank\\u{202e}knaB <bo\\u{200b}ss@x.test>")
        );
        assert!(!event.from_unclear);
        assert_eq!(event.subject.as_deref(), Some("Plans"));
    }

    /// A sender that does not read as one address is written whole, as an address is, and
    /// marked.
    #[test]
    fn events_write_a_sender_that_does_not_read_as_one_address_whole() {
        let newest = NewMessage {
            uid: 7,
            message_id: None,
            from: Some(EmailAddress::new("a@y.testb@x.test")),
            from_clear: false,
            from_values: vec!["<a@y.test> b@x.test".to_owned()],
            recipients: Vec::new(),
            subject: None,
            date: None,
        };
        let event = new_mail_event("me@x.test", &newest, 1, 1);
        assert_eq!(
            event.from.as_deref(),
            Some("\\u{3c}a@y.test\\u{3e} b@x.test")
        );
        assert!(event.from_unclear);
    }

    async fn sql(setup: &Backlog, sql: &'static str) {
        sqlx::query(sql).execute(setup.store.pool()).await.unwrap();
    }

    /// Of 1001..=1050 three pass, by subject, sender and recipient, and the newest
    /// of them is not the newest message. None of 1051..=1100 does and one of
    /// 1101..=1120 does, in one pass. Only three rules count, so the fourth, which
    /// this version could not read, waits.
    #[tokio::test]
    async fn only_messages_that_pass_the_rules_are_reported() {
        let mut setup = backlog().await;
        let (store, id) = (&setup.store, &setup.account);
        allow(store, id, "subject", "regex", "^message (1002|1110)$").await;
        allow(store, id, "from", "equals", "sender1033@example.com").await;
        allow(store, id, "to", "equals", "to1047@example.com").await;
        allow(store, id, "body", "contains", "x").await;
        let mut cursor = setup.cursor;
        for (uid_next, last_uid, sequence) in [(1_051, 1_050, 1), (1_121, 1_120, 2)] {
            setup.uid_next = uid_next;
            let done = drain_scripted(&setup, &mut cursor).await;
            assert!(done.unwrap().is_none());
            let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
            let stored = (hook.cursor.unwrap().last_uid, hook.last_sequence);
            assert_eq!((stored, cursor.last_uid), ((last_uid, sequence), last_uid));
        }
        for (count, uid) in [(3, 1_047), (1, 1_110)] {
            let event = take_event(&mut setup.receiver).await;
            assert_eq!((event.count, event.uid), (count, uid));
        }
        assert_eq!(*setup.seen.lock().unwrap(), [1_000, 1_050, 1_100]);
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// Another owner moved the cursor on to 1100 while this drain read from 1000. No
    /// rule passes 1001..=1050: it stays at 1100, with nothing reported. The next batch
    /// moves it on.
    #[tokio::test]
    async fn a_cursor_another_owner_moved_on_is_not_moved_back() {
        let mut setup = backlog().await;
        let (store, id, mut moved) = (&setup.store, &setup.account, setup.cursor);
        allow(store, id, "subject", "equals", "none").await;
        moved.last_uid = 1_100;
        store.set_watch_cursor(id, moved).await.unwrap();
        let mut cursor = setup.cursor;
        for (uid_next, last_uid) in [(1_051, 1_100), (1_121, 1_120)] {
            setup.uid_next = uid_next;
            assert!(drain_scripted(&setup, &mut cursor).await.unwrap().is_none());
            let hook = store.webhook(id).await.unwrap().unwrap();
            let stored = (hook.cursor.unwrap().last_uid, hook.last_sequence);
            assert_eq!((stored, cursor.last_uid), ((last_uid, 0), last_uid));
        }
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// The usage hook's number replaces the setting (3): only the oldest rule
    /// counts, so the newer one, which 1002 matches, judges nothing.
    #[tokio::test]
    async fn the_usage_hook_says_how_many_rules_count() {
        let mut setup = backlog().await;
        let hook = FilterLimit::new(1);
        setup.watchers.set_usage_hook(hook.clone());
        let (store, id) = (&setup.store, &setup.account);
        allow(store, id, "subject", "equals", "none").await;
        allow(store, id, "subject", "regex", "^message 1002$").await;
        setup.uid_next = 1_051;
        let mut cursor = setup.cursor;
        assert!(drain_scripted(&setup, &mut cursor).await.unwrap().is_none());
        let stored = store.webhook(id).await.unwrap().unwrap();
        let stored = (stored.cursor.unwrap().last_uid, stored.last_sequence);
        assert_eq!((stored, cursor.last_uid), ((1_050, 0), 1_050));
        assert_eq!(hook.asked(), [("default".to_owned(), id.clone())]);
        // A mailbox that is gone gets the setting, and the hook is not asked.
        let gone = AccountId("gone".to_owned());
        assert_eq!(setup.watchers.filter_rule_limit(&gone).await.unwrap(), 3);
        assert_eq!(hook.asked().len(), 1);
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// Rules that can't be read stop the drain where it is, and a failure that may
    /// pass is an error: either way nothing is reported and nothing is skipped.
    #[tokio::test]
    async fn rules_that_cannot_be_read_hold_the_mail_where_it_is() {
        let mut setup = backlog().await;
        let (store, id) = (&setup.store, &setup.account);
        let held = async |setup: &Backlog| {
            let mut cursor = setup.cursor;
            let exit = drain_scripted(setup, &mut cursor).await;
            assert!(matches!(exit.unwrap(), Some(Exit::Disabled)));
            let hook = store.webhook(id).await.unwrap().unwrap();
            assert_eq!((hook.cursor, hook.last_sequence), (Some(setup.cursor), 0));
        };
        // An unknown field, and a rule too large to compile.
        for (field, kind, pattern) in [
            ("body", "contains", "x"),
            ("subject", "regex", "(a{1000}){1000}"),
        ] {
            allow(store, id, field, kind, pattern).await;
            held(&setup).await;
            store.remove_webhook_filter_rules(id).await.unwrap();
        }
        allow(store, id, "subject", "contains", "x").await;
        let garble = "UPDATE webhook_filter_rules SET pattern_ciphertext = 'bad'";
        sql(&setup, garble).await;
        held(&setup).await;
        sql(&setup, "ALTER TABLE webhook_filter_rules RENAME TO moved").await;
        let mut cursor = setup.cursor;
        let err = drain_scripted(&setup, &mut cursor).await.err().unwrap();
        assert!(matches!(err, WatchError::Store(_)) && is_transient(&err));
        sql(&setup, "ALTER TABLE moved RENAME TO webhook_filter_rules").await;

        // With the rules gone, the mail is reported as it is without any.
        store.remove_webhook_filter_rules(id).await.unwrap();
        assert!(drain_scripted(&setup, &mut cursor).await.unwrap().is_none());
        assert_eq!(take_event(&mut setup.receiver).await.count, 50);
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A rule turned off is not read: the unknown field would hold the mail, and
    /// the mail is reported as it is without any rule.
    #[tokio::test]
    async fn an_off_rule_neither_holds_nor_judges_mail() {
        let mut setup = backlog().await;
        let (store, id) = (&setup.store, &setup.account);
        allow(store, id, "body", "contains", "x").await;
        let rule = store.webhook_filter_rules(id, 3).await.unwrap()[0]
            .id
            .clone();
        let off = store.set_webhook_filter_rule_enabled(id, &rule, false, 3, |_| Ok(()));
        assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);
        setup.uid_next = 1_051;
        let mut cursor = setup.cursor;
        assert!(drain_scripted(&setup, &mut cursor).await.unwrap().is_none());
        assert_eq!(take_event(&mut setup.receiver).await.count, 50);
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn rules_are_compiled_again_when_the_webhook_the_count_or_the_limit_changes() {
        let setup = backlog().await;
        let (store, id) = (&setup.store, &setup.account);
        let look = async |limit| {
            let hook = store.webhook(id).await.unwrap().unwrap();
            let rules = setup.watchers.rules_at(id, &hook, limit);
            rules.await.unwrap().unwrap()
        };
        let same = |a: &Rules, b: &Rules| matches!((a, b), (Rules::On(a), Rules::On(b)) if std::sync::Arc::ptr_eq(a, b));
        assert!(matches!(look(9).await, Rules::Off));
        allow(store, id, "subject", "contains", "a").await;
        let first = look(9).await;
        assert!(same(&first, &look(9).await), "nothing changed");
        assert!(!same(&first, &look(1).await), "another limit");
        let first = look(9).await;
        allow(store, id, "subject", "contains", "b").await;
        assert!(!same(&first, &look(9).await), "another count");
        // A webhook deleted and saved again counts from 0 again, in another second.
        let first = look(9).await;
        sql(&setup, "UPDATE webhooks SET created_at = created_at + 1").await;
        assert!(!same(&first, &look(9).await), "another webhook");
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    fn cursor_at(uid_validity: u32, last_uid: u32) -> WatchCursor {
        WatchCursor {
            uid_validity,
            last_uid,
        }
    }

    async fn stored_cursor(setup: &Backlog) -> Option<WatchCursor> {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        hook.cursor
    }

    /// The cursor a session starts from, given the one it `read` and the one a
    /// first start would make.
    async fn start(
        setup: &Backlog,
        read: Option<WatchCursor>,
        fresh: WatchCursor,
    ) -> Result<Option<WatchCursor>, WatchError> {
        let start = setup.watchers.start_cursor(&setup.account, read, fresh);
        start.await
    }

    /// The fresh cursor of a first start or a new `UIDVALIDITY` is stored over
    /// the cursor the session read, and over what another owner stored since, and
    /// no other.
    #[tokio::test]
    async fn a_session_stores_a_fresh_cursor_over_the_one_it_read() {
        let setup = backlog().await;
        let fresh = cursor_at(8, 2_000);
        sql(
            &setup,
            "UPDATE webhooks SET uid_validity = NULL, last_uid = NULL",
        )
        .await;
        assert_eq!(start(&setup, None, fresh).await.unwrap(), Some(fresh));
        assert_eq!(stored_cursor(&setup).await, Some(fresh));

        // A new UIDVALIDITY replaces the cursor of the old one.
        let (old, newer) = (cursor_at(9, 10), cursor_at(10, 5_000));
        setup
            .store
            .set_watch_cursor(&setup.account, old)
            .await
            .unwrap();
        assert_eq!(start(&setup, Some(old), newer).await.unwrap(), Some(newer));
        assert_eq!(stored_cursor(&setup).await, Some(newer));

        // The session read none, but another owner stored one for the old
        // UIDVALIDITY: it is read again and replaced.
        sql(
            &setup,
            "UPDATE webhooks SET uid_validity = 6, last_uid = 50",
        )
        .await;
        assert_eq!(start(&setup, None, fresh).await.unwrap(), Some(fresh));
        assert_eq!(stored_cursor(&setup).await, Some(fresh));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A stored cursor for the mailbox's `UIDVALIDITY` is where the session starts,
    /// untouched, so the mail past it is not skipped. That holds when another owner
    /// stored it after the session read none. A webhook that is gone has no start.
    #[tokio::test]
    async fn a_session_starts_from_a_stored_cursor_of_this_uidvalidity() {
        let setup = backlog().await;
        let (stored, fresh) = (cursor_at(8, 1_500), cursor_at(8, 2_000));
        setup
            .store
            .set_watch_cursor(&setup.account, stored)
            .await
            .unwrap();
        assert_eq!(
            start(&setup, Some(stored), fresh).await.unwrap(),
            Some(stored)
        );
        assert_eq!(start(&setup, None, fresh).await.unwrap(), Some(stored));
        assert_eq!(stored_cursor(&setup).await, Some(stored));

        let ghost = AccountId("ghost".to_owned());
        let gone = setup.watchers.start_cursor(&ghost, None, fresh).await;
        assert_eq!(gone.unwrap(), None);
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// Positions the watcher of these tests can use: those that start with `ok`.
    fn usable(stored: Option<&str>) -> bool {
        stored.is_some_and(|stored| stored.starts_with("ok"))
    }

    /// The position a session starts from, given the one it `read` and the one
    /// a first start would store.
    async fn start_from(
        setup: &Backlog,
        read: Option<&str>,
        fresh: &str,
    ) -> Result<Option<String>, WatchError> {
        let read = read.map(str::to_owned);
        let start = setup
            .watchers
            .start_position(&setup.account, read, fresh.to_owned(), usable);
        start.await
    }

    async fn stored_raw_position(setup: &Backlog) -> Option<String> {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        hook.position
    }

    /// A first start's fresh position is stored over the position the session
    /// read, and over one another watcher stored since that this watcher cannot
    /// use, and no other.
    #[tokio::test]
    async fn a_session_stores_a_fresh_position_over_the_one_it_read() {
        let setup = backlog().await;
        let started = start_from(&setup, None, "ok-1").await.unwrap();
        assert_eq!(started.as_deref(), Some("ok-1"));
        assert_eq!(stored_raw_position(&setup).await.as_deref(), Some("ok-1"));

        // One this watcher cannot use is replaced.
        sql(&setup, "UPDATE webhooks SET watch_position = 'other'").await;
        let started = start_from(&setup, Some("other"), "ok-2").await.unwrap();
        assert_eq!(started.as_deref(), Some("ok-2"));
        assert_eq!(stored_raw_position(&setup).await.as_deref(), Some("ok-2"));

        // The session read none, but another watcher stored one this watcher
        // cannot use: it is read again and replaced.
        sql(&setup, "UPDATE webhooks SET watch_position = 'other'").await;
        let started = start_from(&setup, None, "ok-3").await.unwrap();
        assert_eq!(started.as_deref(), Some("ok-3"));
        assert_eq!(stored_raw_position(&setup).await.as_deref(), Some("ok-3"));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A stored position this watcher can use is where the session starts,
    /// untouched, so the mail after it is not skipped. That holds when another
    /// watcher stored it after the session read none. A webhook that is gone has
    /// no start.
    #[tokio::test]
    async fn a_session_starts_from_a_stored_position_it_can_use() {
        let setup = backlog().await;
        sql(&setup, "UPDATE webhooks SET watch_position = 'ok-stored'").await;
        let started = start_from(&setup, Some("ok-stored"), "ok-fresh").await;
        assert_eq!(started.unwrap().as_deref(), Some("ok-stored"));
        let started = start_from(&setup, None, "ok-fresh").await;
        assert_eq!(started.unwrap().as_deref(), Some("ok-stored"));
        assert_eq!(
            stored_raw_position(&setup).await.as_deref(),
            Some("ok-stored")
        );

        let ghost = AccountId("ghost".to_owned());
        let fresh = "ok-fresh".to_owned();
        let gone = setup.watchers.start_position(&ghost, None, fresh, usable);
        assert_eq!(gone.await.unwrap(), None);
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A position that is changed again at every try ends the start with an
    /// error that is tried again, after three tries, and the position stays.
    #[tokio::test]
    async fn a_position_that_keeps_changing_fails_the_start() {
        let setup = backlog().await;
        sql(&setup, "CREATE TABLE tries (n INTEGER)").await;
        let refuse = "CREATE TRIGGER refuse BEFORE UPDATE ON webhooks \
                      BEGIN INSERT INTO tries VALUES (1); SELECT RAISE(IGNORE); END";
        sql(&setup, refuse).await;
        let err = start_from(&setup, None, "ok-fresh").await;
        assert!(matches!(err, Err(WatchError::CursorMoved)), "{err:?}");
        assert_eq!(stored_raw_position(&setup).await, None);
        let tries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tries")
            .fetch_one(setup.store.pool())
            .await
            .unwrap();
        assert_eq!(tries, 3, "three tries");
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A cursor that is changed again at every try ends the start with an error
    /// that is tried again, after three tries, and the cursor stays.
    #[tokio::test]
    async fn a_cursor_that_keeps_changing_fails_the_start() {
        let setup = backlog().await;
        // Every move is refused, as when another owner moves the cursor first,
        // and each one is counted.
        sql(&setup, "CREATE TABLE tries (n INTEGER)").await;
        let refuse = "CREATE TRIGGER refuse BEFORE UPDATE ON webhooks \
                      BEGIN INSERT INTO tries VALUES (1); SELECT RAISE(IGNORE); END";
        sql(&setup, refuse).await;
        let err = start(&setup, Some(setup.cursor), cursor_at(8, 2_000)).await;
        assert!(matches!(err, Err(WatchError::CursorMoved)), "{err:?}");
        assert_eq!(stored_cursor(&setup).await, Some(setup.cursor));
        let tries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tries")
            .fetch_one(setup.store.pool())
            .await
            .unwrap();
        assert_eq!(tries, 3, "three tries");
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// Another owner moved the cursor on to 1100 while this drain read from 1000.
    /// The selection 1001..=1050 was expunged before the fetch: the cursor stays
    /// at 1100, and the drain goes on from there, so 1051..=1100 is not reported
    /// twice.
    #[tokio::test]
    async fn an_expunged_selection_does_not_move_a_cursor_back() {
        let mut setup = backlog().await;
        let moved = cursor_at(7, 1_100);
        setup
            .store
            .set_watch_cursor(&setup.account, moved)
            .await
            .unwrap();
        let mut cursor = setup.cursor;
        let calls = AtomicUsize::new(0);
        let mut fetch = |after| {
            setup.seen.lock().unwrap().push(after);
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(MessageBatch {
                    messages: Vec::new(),
                    selected_through: Some(1_050),
                });
            }
            Ok(scripted_batch(after))
        };
        let (email, cancel) = ("backlog@example.com", CancellationToken::new());
        let drain = setup.watchers.report_scripted(
            &setup.account,
            email,
            &mut cursor,
            UID_NEXT,
            &cancel,
            &mut fetch,
        );
        assert!(drain.await.unwrap().is_none());
        assert_eq!(*setup.seen.lock().unwrap(), [1_000, 1_100]);
        let event = take_event(&mut setup.receiver).await;
        assert_eq!(
            (event.count, event.uid, event.sequence.as_str()),
            (20, 1_120, "1")
        );
        no_further_event(&mut setup.receiver).await;
        assert_eq!(stored_cursor(&setup).await, Some(cursor_at(7, 1_120)));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// One drain from `cursor` up to `uid_next` in which every search finds nothing.
    async fn drain_empty(
        setup: &Backlog,
        cursor: &mut WatchCursor,
        uid_next: u32,
    ) -> Result<Option<Exit>, WatchError> {
        let mut fetch = |after| {
            setup.seen.lock().unwrap().push(after);
            Ok(MessageBatch {
                messages: Vec::new(),
                selected_through: None,
            })
        };
        let (email, cancel) = ("backlog@example.com", CancellationToken::new());
        let (watchers, account) = (&setup.watchers, &setup.account);
        let drain = watchers.report_scripted(account, email, cursor, uid_next, &cancel, &mut fetch);
        drain.await
    }

    /// The same for a search that found nothing below `UIDNEXT` 1051: the cursor
    /// another owner moved to 1100 stays, and the drain ends there.
    #[tokio::test]
    async fn an_empty_search_does_not_move_a_cursor_back() {
        let setup = backlog().await;
        let moved = cursor_at(7, 1_100);
        setup
            .store
            .set_watch_cursor(&setup.account, moved)
            .await
            .unwrap();
        let mut cursor = setup.cursor;
        assert!(
            drain_empty(&setup, &mut cursor, 1_051)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(cursor, moved);
        assert_eq!(*setup.seen.lock().unwrap(), vec![1_000]);
        assert_eq!(stored_cursor(&setup).await, Some(moved));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A writer that does not compare, as an older version during an upgrade,
    /// moved the cursor back to 950 while this drain read from 1000. The drain
    /// moves it forward to 1000 again and reads on from there, so 951..=1000
    /// is not read twice. When that move is refused too, the pass ends.
    #[tokio::test]
    async fn a_cursor_moved_back_is_moved_forward_again() {
        let setup = backlog().await;
        let back = cursor_at(7, 950);
        let store = &setup.store;
        store.set_watch_cursor(&setup.account, back).await.unwrap();
        let mut cursor = setup.cursor;
        let drain = drain_empty(&setup, &mut cursor, 1_051).await;
        assert!(drain.unwrap().is_none());
        assert_eq!(*setup.seen.lock().unwrap(), vec![1_000, 1_000]);
        assert_eq!(cursor, cursor_at(7, 1_050));
        assert_eq!(stored_cursor(&setup).await, Some(cursor_at(7, 1_050)));

        store.set_watch_cursor(&setup.account, back).await.unwrap();
        let refuse = "CREATE TRIGGER refuse BEFORE UPDATE ON webhooks \
                      BEGIN SELECT RAISE(IGNORE); END";
        sql(&setup, refuse).await;
        let drain = drain_empty(&setup, &mut cursor, 1_101).await;
        assert!(drain.unwrap().is_none());
        assert_eq!(cursor, cursor_at(7, 1_050));
        assert_eq!(stored_cursor(&setup).await, Some(back));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A move that is refused with the cursor where this drain read it ends the pass,
    /// and one for a webhook that is gone ends the watcher. Neither spins.
    #[tokio::test]
    async fn a_move_that_is_refused_ends_the_pass() {
        let setup = backlog().await;
        let refuse = "CREATE TRIGGER refuse BEFORE UPDATE ON webhooks \
                      BEGIN SELECT RAISE(IGNORE); END";
        sqlx::query(refuse)
            .execute(setup.store.pool())
            .await
            .unwrap();
        let mut cursor = setup.cursor;
        assert!(
            drain_empty(&setup, &mut cursor, 1_051)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(cursor, setup.cursor);
        assert_eq!(stored_cursor(&setup).await, Some(setup.cursor));

        setup.store.delete_webhook(&setup.account).await.unwrap();
        let exit = drain_empty(&setup, &mut cursor, 1_051).await;
        assert!(matches!(exit.unwrap(), Some(Exit::Disabled)));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A search that selects nothing past the cursor, which a server should not
    /// answer, ends the pass: the cursor is neither moved back nor ahead.
    #[tokio::test]
    async fn a_selection_not_past_the_cursor_ends_the_pass() {
        let setup = backlog().await;
        let mut cursor = setup.cursor;
        let calls = AtomicUsize::new(0);
        let mut fetch = |_| {
            if calls.fetch_add(1, Ordering::SeqCst) > 0 {
                return Err(WatchError::Malformed("the pass went on"));
            }
            Ok(MessageBatch {
                messages: Vec::new(),
                selected_through: Some(900),
            })
        };
        let (email, cancel) = ("backlog@example.com", CancellationToken::new());
        let (watchers, account) = (&setup.watchers, &setup.account);
        let drain =
            watchers.report_scripted(account, email, &mut cursor, UID_NEXT, &cancel, &mut fetch);
        assert!(drain.await.unwrap().is_none());
        assert_eq!(cursor, setup.cursor);
        assert_eq!(stored_cursor(&setup).await, Some(setup.cursor));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// The webhook is turned off just as the cursor is to move past a batch none of
    /// which passes the rules. The move is refused, and the drain ends the watcher.
    #[tokio::test]
    async fn a_webhook_turned_off_as_a_batch_is_skipped_ends_the_watcher() {
        let mut setup = backlog().await;
        let (store, id) = (&setup.store, &setup.account);
        allow(store, id, "subject", "equals", "none").await;
        let off = "CREATE TRIGGER off BEFORE UPDATE ON webhooks \
                   BEGIN UPDATE webhooks SET enabled = 0 WHERE account_id = OLD.account_id; \
                   SELECT RAISE(IGNORE); END";
        sql(&setup, off).await;
        let mut cursor = setup.cursor;
        let exit = drain_scripted(&setup, &mut cursor).await;
        assert!(matches!(exit.unwrap(), Some(Exit::Disabled)));
        assert_eq!(cursor, setup.cursor);
        assert_eq!(stored_cursor(&setup).await, Some(setup.cursor));
        no_further_event(&mut setup.receiver).await;
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }

    /// A move that is refused while the watcher is stopped ends the drain as
    /// stopped. The cursor another owner moved to 1100 is neither moved back nor
    /// taken, since the drain is over.
    #[tokio::test]
    async fn a_move_that_is_refused_to_a_stopped_watcher_stops_it() {
        let setup = backlog().await;
        let moved = cursor_at(7, 1_100);
        let store = &setup.store;
        store.set_watch_cursor(&setup.account, moved).await.unwrap();
        let mut cursor = setup.cursor;
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        // The watcher is stopped while the server answers the search.
        let mut fetch = move |_| {
            stop.cancel();
            Ok(MessageBatch {
                messages: Vec::new(),
                selected_through: Some(1_050),
            })
        };
        let email = "backlog@example.com";
        let (watchers, account) = (&setup.watchers, &setup.account);
        let drain =
            watchers.report_scripted(account, email, &mut cursor, UID_NEXT, &cancel, &mut fetch);
        assert!(matches!(drain.await.unwrap(), Some(Exit::Stopped)));
        assert_eq!(cursor, setup.cursor);
        assert_eq!(stored_cursor(&setup).await, Some(moved));
        setup.watchers.shutdown(Duration::from_secs(2)).await;
    }
}

#[cfg(test)]
mod catch_up_retry_tests {
    use std::time::Duration;

    use axum::http::StatusCode;
    use postkeep_store::StoreError;
    use postkeep_upstream::{ApiError, HttpError, TokenError, UpstreamProvider};

    use super::{WatchConfig, WatchError, catch_up_retry_delay, is_transient, needs_sign_in};

    #[test]
    fn retry_delay_starts_at_the_longer_base_and_caps() {
        let config = WatchConfig {
            debounce: Duration::from_secs(3),
            min_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(10),
            ..WatchConfig::default()
        };
        assert_eq!(catch_up_retry_delay(1, &config), Duration::from_secs(3));
        assert_eq!(catch_up_retry_delay(2, &config), Duration::from_secs(6));
        assert_eq!(catch_up_retry_delay(3, &config), Duration::from_secs(10));
        assert_eq!(catch_up_retry_delay(10, &config), Duration::from_secs(10));
    }

    fn status(code: StatusCode) -> WatchError {
        WatchError::Api(Box::new(ApiError::Status {
            provider: UpstreamProvider::Microsoft,
            status: code,
            code: None,
            reason: None,
            message: "no".to_owned(),
        }))
    }

    #[test]
    fn only_transient_catch_up_failures_are_retried() {
        let unavailable = status(StatusCode::SERVICE_UNAVAILABLE);
        assert!(is_transient(&unavailable));
        assert!(!needs_sign_in(&unavailable));
        assert!(is_transient(&status(StatusCode::TOO_MANY_REQUESTS)));
        // Gmail also answers a rate limit with a 403 that gives the reason.
        let google_403 = |reason: Option<&str>| {
            WatchError::Api(Box::new(ApiError::Status {
                provider: UpstreamProvider::Google,
                status: StatusCode::FORBIDDEN,
                code: Some("PERMISSION_DENIED".to_owned()),
                reason: reason.map(str::to_owned),
                message: "no".to_owned(),
            }))
        };
        assert!(is_transient(&google_403(Some("userRateLimitExceeded"))));
        assert!(is_transient(&google_403(Some("rateLimitExceeded"))));
        assert!(is_transient(&WatchError::Api(Box::new(ApiError::Http(
            HttpError::Timeout("graph.example.com".to_owned())
        )))));
        assert!(is_transient(&WatchError::Store(StoreError::Decrypt)));
        let down = StoreError::KeyWrap("the key service is down".to_owned());
        assert!(is_transient(&WatchError::Store(down)));
        // A refresh whose new tokens could not be stored is the same: the
        // account is not asked to sign in again.
        let down = StoreError::KeyWrap("the key service is down".to_owned());
        let unsaved = WatchError::Api(Box::new(ApiError::Token(TokenError::Store(down))));
        assert!(is_transient(&unsaved));
        assert!(!needs_sign_in(&unsaved));

        let sign_in = WatchError::Api(Box::new(ApiError::Token(TokenError::NeedsReauth {
            provider: UpstreamProvider::Microsoft,
            reason: "invalid_grant".to_owned(),
        })));
        assert!(needs_sign_in(&sign_in));
        assert!(!is_transient(&sign_in));
        assert!(needs_sign_in(&WatchError::Api(Box::new(ApiError::Token(
            TokenError::NotConnected(UpstreamProvider::Google)
        )))));

        assert!(!is_transient(&status(StatusCode::BAD_REQUEST)));
        assert!(!is_transient(&status(StatusCode::UNAUTHORIZED)));
        assert!(!is_transient(&google_403(Some("domainPolicy"))));
        assert!(!is_transient(&google_403(None)));
        assert!(!is_transient(&WatchError::NotConfigured));
        assert!(!is_transient(&WatchError::Malformed("nope")));
        // A cursor that kept changing at a session's start is tried again.
        assert!(is_transient(&WatchError::CursorMoved));
    }
}
