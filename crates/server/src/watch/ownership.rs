//! Which mailboxes this process watches, for an embedding that runs several
//! server processes on one database.
//!
//! Without a [`WatchOwnership`], a process watches every mailbox with an
//! enabled webhook and runs every shared job, which is right for a single
//! instance. An embedding that runs several processes gives each one a
//! share of the mailboxes, for example with leases in the database, and
//! passes on what reaches a process about a mailbox another one watches.

use postkeep_store::AccountId;

use super::Watchers;

/// Decides which mailboxes this process watches and which shared jobs it
/// runs. `Extensions::watch_ownership` and `ServerBuilder::watch_ownership`
/// install it.
///
/// Every method has a default that gives this process everything, so a
/// server without one behaves as a single instance. [`owns`](Self::owns),
/// [`forward`](Self::forward) and [`runs`](Self::runs) are called from
/// request handlers and watcher tasks, so they return at once: they answer
/// from memory and start a task for anything slow.
pub trait WatchOwnership: Send + Sync + 'static {
    /// Called once, when the hook is installed, with this process's
    /// watchers. The embedding keeps them to call [`Watchers::refresh`],
    /// [`Watchers::release`] and [`Watchers::signal`]. Not called when
    /// webhooks are off.
    fn attach(&self, watchers: &Watchers) {
        let _ = watchers;
    }

    /// Whether this process watches `account`: runs its watcher, catches up
    /// after Microsoft's and Google's pushes, renews its Graph subscription
    /// or Gmail watch, and delivers its new-mail events.
    ///
    /// Asked before each of those. When the answer for a mailbox becomes
    /// `false`, the embedding calls [`Watchers::release`] after the change;
    /// when it becomes `true`, [`Watchers::refresh`].
    fn owns(&self, account: &AccountId) -> bool {
        let _ = account;
        true
    }

    /// Passes on `signal`, about a mailbox this process doesn't own, to the
    /// process that does, which hands it to its [`Watchers::signal`].
    ///
    /// The default drops it, so an embedding whose [`owns`](Self::owns)
    /// can answer `false` implements this too.
    fn forward(&self, signal: WatchSignal) {
        let _ = signal;
    }

    /// Whether this process runs `job` now. Asked before each run.
    fn runs(&self, job: SharedJob) -> bool {
        let _ = job;
        true
    }
}

/// What reached a process about a mailbox another process watches.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WatchSignal {
    /// The mailbox's webhook settings, sign-in or existence changed: its
    /// watcher restarts, and its pending events are tried once.
    Changed(AccountId),
    /// A verified Microsoft Graph change notification, or a `missed`
    /// lifecycle notification: new Outlook mail to catch up on.
    GraphNotification(AccountId),
    /// Any other verified Microsoft Graph lifecycle notification.
    GraphLifecycle {
        /// The mailbox.
        account: AccountId,
        /// The subscription the notification was verified for.
        subscription_id: String,
        /// The event, for example `reauthorizationRequired` or
        /// `subscriptionRemoved`.
        event: String,
    },
    /// A verified Gmail push: new Gmail mail to catch up on.
    GmailPush(AccountId),
    /// New-mail events were stored for the mailbox, to be delivered.
    Recorded(AccountId),
}

impl WatchSignal {
    /// The mailbox the signal is about.
    #[must_use]
    pub const fn account(&self) -> &AccountId {
        match self {
            Self::Changed(account)
            | Self::GraphNotification(account)
            | Self::GraphLifecycle { account, .. }
            | Self::GmailPush(account)
            | Self::Recorded(account) => account,
        }
    }
}

/// A job one process runs for the whole database.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SharedJob {
    /// Every 10 minutes, deletes expired sign-ins, codes and tokens,
    /// abandoned client registrations, and new-mail events past their
    /// outbox limits (`Store::purge_expired`).
    Purge,
    /// Shortly after the process starts and then every hour, moves the
    /// values still stored under the master key to data keys
    /// (`Store::reencrypt`) and wraps data keys again that another key
    /// encryption key wrapped (`Store::rewrap_data_keys`). Running it in
    /// several processes is safe, and repeats the work.
    Reencrypt,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use postkeep_store::Provider;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, ResponseTemplate};

    use super::super::harness::{
        self, HISTORY_PATH, STOP_PATH, WATCH_PATH, provider_setup, watch_response,
    };
    use super::*;

    /// Owns every mailbox while `owned` is set, and keeps what it is asked
    /// to pass on.
    #[derive(Default)]
    struct Shared {
        owned: AtomicBool,
        attached: AtomicUsize,
        forwarded: Mutex<Vec<WatchSignal>>,
    }

    impl Shared {
        fn take(&self) -> Vec<WatchSignal> {
            std::mem::take(&mut *self.forwarded.lock().unwrap())
        }
    }

    impl WatchOwnership for Shared {
        fn attach(&self, _watchers: &Watchers) {
            self.attached.fetch_add(1, Ordering::SeqCst);
        }

        fn owns(&self, _account: &AccountId) -> bool {
            self.owned.load(Ordering::SeqCst)
        }

        fn forward(&self, signal: WatchSignal) {
            self.forwarded.lock().unwrap().push(signal);
        }
    }

    #[tokio::test]
    async fn a_process_passes_on_what_reaches_it_about_a_mailbox_it_does_not_own() {
        let setup = provider_setup(Provider::Gmail).await;
        let account = &setup.account;
        let shared = Arc::new(Shared::default());
        setup.watchers.set_ownership(shared.clone());
        setup.watchers.set_ownership(shared.clone());
        assert_eq!(
            shared.attached.load(Ordering::SeqCst),
            1,
            "a second hook is ignored"
        );

        setup.watchers.start_all().await;
        assert_eq!(
            shared.take(),
            Vec::<WatchSignal>::new(),
            "start_all passes nothing on"
        );
        setup.watchers.refresh(account);
        setup.watchers.schedule_gmail_catch_up(account);
        setup.watchers.schedule_graph_catch_up(account);
        for event in ["reauthorizationRequired", "missed"] {
            setup
                .watchers
                .schedule_graph_lifecycle(account, "sub-1".to_owned(), event.to_owned());
        }
        setup.watchers.wake(account);
        assert_eq!(
            shared.take(),
            [
                WatchSignal::Changed(account.clone()),
                WatchSignal::GmailPush(account.clone()),
                WatchSignal::GraphNotification(account.clone()),
                WatchSignal::GraphLifecycle {
                    account: account.clone(),
                    subscription_id: "sub-1".to_owned(),
                    event: "reauthorizationRequired".to_owned(),
                },
                WatchSignal::GraphNotification(account.clone()),
                WatchSignal::Recorded(account.clone()),
            ]
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(setup.watchers.running(), 0);
        assert_eq!(setup.watchers.pumps(), 0);
        assert!(
            setup
                .server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty(),
            "a process that doesn't own the mailbox called Gmail"
        );

        // The owner acts on what was passed on.
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(watch_response("42")))
            .mount(&setup.server)
            .await;
        Mock::given(method("GET"))
            .and(path(HISTORY_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"historyId": "43"})))
            .mount(&setup.server)
            .await;
        shared.owned.store(true, Ordering::SeqCst);
        setup.watchers.signal(WatchSignal::Changed(account.clone()));
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 1).await;
        let hook = async || setup.store.webhook(account).await.unwrap().unwrap();
        harness::until(async || hook().await.position.is_some()).await;
        setup
            .watchers
            .signal(WatchSignal::GmailPush(account.clone()));
        harness::wait_for_requests(&setup.server, "GET", HISTORY_PATH, 1).await;
        assert_eq!(setup.watchers.running(), 1);

        // A push that waited out its debounce while the mailbox moved to
        // another process is passed on instead of read here.
        setup.watchers.schedule_gmail_catch_up(account);
        shared.owned.store(false, Ordering::SeqCst);
        harness::until(async || !shared.forwarded.lock().unwrap().is_empty()).await;
        assert_eq!(shared.take(), [WatchSignal::GmailPush(account.clone())]);
        assert_eq!(
            harness::requests(&setup.server, "GET", HISTORY_PATH).await,
            1
        );
        harness::finish(&setup).await;
    }

    #[tokio::test]
    async fn releasing_a_mailbox_stops_its_work_here_and_keeps_its_gmail_watch() {
        let setup = provider_setup(Provider::Gmail).await;
        let account = &setup.account;
        let shared = Arc::new(Shared::default());
        shared.owned.store(true, Ordering::SeqCst);
        setup.watchers.set_ownership(shared.clone());
        harness::pause_webhook(&setup).await;
        Mock::given(method("POST"))
            .and(path(WATCH_PATH))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(watch_response("42"))
                    .set_delay(Duration::from_millis(500)),
            )
            .mount(&setup.server)
            .await;
        Mock::given(method("POST"))
            .and(path(STOP_PATH))
            .respond_with(ResponseTemplate::new(204))
            .mount(&setup.server)
            .await;

        setup.watchers.refresh(account);
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 1).await;
        // The paused webhook's pump waits for its next slot.
        setup.watchers.wake(account);
        assert_eq!(setup.watchers.running(), 1);
        assert_eq!(setup.watchers.pumps(), 1);

        // users.watch is still in flight: release waits for the session.
        shared.owned.store(false, Ordering::SeqCst);
        setup.watchers.release(account).await;
        assert!(
            setup
                .store
                .push_subscription(account)
                .await
                .unwrap()
                .is_some(),
            "release returned before the watcher had stopped"
        );
        assert_eq!(setup.watchers.running(), 0);
        assert_eq!(setup.watchers.pumps(), 0);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            harness::requests(&setup.server, "POST", STOP_PATH).await,
            0,
            "the watch is left to the next owner"
        );
        assert_eq!(
            harness::requests(&setup.server, "POST", WATCH_PATH).await,
            1
        );
        let hook = setup.store.webhook(account).await.unwrap().unwrap();
        assert!(hook.settings.enabled && hook.is_paused());
        assert!(hook.position.is_some());
        assert_eq!(shared.take(), Vec::<WatchSignal>::new());

        // Owning it again renews the same watch.
        shared.owned.store(true, Ordering::SeqCst);
        setup.watchers.refresh(account);
        harness::wait_for_requests(&setup.server, "POST", WATCH_PATH, 2).await;
        assert_eq!(setup.watchers.running(), 1);
        assert_eq!(harness::requests(&setup.server, "POST", STOP_PATH).await, 0);
        harness::finish(&setup).await;
    }
}
