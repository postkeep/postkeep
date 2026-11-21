//! Shared setup for provider catch-up tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]

use std::sync::Mutex;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use postkeep_auth::{CeilingsFuture, Outbox, OutboxCeilings, UsageHook};
use postkeep_mail::ImapServers;
use postkeep_store::{
    AccountId, DeliveryEffect, DeliveryRecord, MAX_CONSECUTIVE_FAILURES, MasterKey, NewFilterRule,
    OAuthAccount, Provider, PushSubscription, Store, UpstreamTokens, WebhookSettings,
};
use postkeep_upstream::{
    AppCredentials, Endpoints, Http, OAuthClient, PushExpectations, PushVerifier, TokenManager,
};
use postkeep_webhook::testing::{Received, Receiver, receiver};
use secrecy::SecretString;
use serde_json::json;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use wiremock::{MockServer, Request, ResponseTemplate};

use super::{WatchConfig, Watchers};

/// A usage hook that lets `.0` filter rules count, and records whom it was
/// asked about.
pub(super) struct FilterLimit(pub(super) usize, pub(super) Mutex<Vec<(String, AccountId)>>);

impl FilterLimit {
    /// A hook that lets `limit` rules count.
    pub(super) fn new(limit: usize) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self(limit, Mutex::default()))
    }

    /// The tenants and mailboxes it was asked about.
    pub(super) fn asked(&self) -> Vec<(String, AccountId)> {
        self.1.lock().unwrap().clone()
    }
}

impl UsageHook for FilterLimit {
    fn outbox_ceilings<'a>(&'a self, outbox: Outbox<'a>) -> CeilingsFuture<'a> {
        let asked = (outbox.tenant.to_owned(), outbox.mailbox.clone());
        self.1.lock().unwrap().push(asked);
        let ceilings = OutboxCeilings::new(60, 10).with_max_filter_rules(self.0);
        Box::pin(std::future::ready(Some(ceilings)))
    }
}

/// One OAuth account, an enabled webhook, and watchers pointed at `server`.
pub(super) struct ProviderSetup {
    pub(super) store: Store,
    pub(super) account: AccountId,
    pub(super) watchers: Watchers,
    pub(super) receiver: Receiver,
    pub(super) server: wiremock::MockServer,
    _dir: tempfile::TempDir,
}

/// A Graph or Gmail account whose access token is still fresh.
pub(super) async fn provider_setup(provider: Provider) -> ProviderSetup {
    provider_setup_with(provider, None).await
}

/// [`provider_setup`] with an allow-list. `None` allows every address.
pub(super) async fn provider_setup_with(
    provider: Provider,
    allowed_emails: Option<Vec<String>>,
) -> ProviderSetup {
    provider_setup_config(
        provider,
        WatchConfig {
            debounce: Duration::from_millis(20),
            retry_delays: vec![Duration::from_millis(20)],
            min_backoff: Duration::from_millis(20),
            allowed_emails,
            ..WatchConfig::default()
        },
    )
    .await
}

/// [`provider_setup`] with explicit watcher settings.
pub(super) async fn provider_setup_config(
    provider: Provider,
    config: WatchConfig,
) -> ProviderSetup {
    let server = wiremock::MockServer::start().await;
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("watch.db").display());
    let store = Store::connect(
        &url,
        &MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap(),
    )
    .await
    .unwrap();
    let account = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider,
                subject: "person-subject",
                email: "person@example.com",
            },
            &UpstreamTokens {
                refresh_token: SecretString::from("refresh-1".to_owned()),
                access_token: Some(SecretString::from("access-1".to_owned())),
                access_expires_at: Some(postkeep_store::now() + 3600),
                scope: "mail".to_owned(),
            },
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
    let base = url::Url::parse(&server.uri()).unwrap();
    let endpoints = Endpoints::all_at(&base);
    let app = |id: &str| AppCredentials {
        client_id: id.to_owned(),
        client_secret: SecretString::from("shh".to_owned()),
    };
    let oauth = OAuthClient::new(
        Http::for_tests(),
        endpoints.clone(),
        url::Url::parse("https://mail.example.com").unwrap(),
        Some(app("ms-client")),
        Some(app("google-client")),
    );
    let tokens = TokenManager::new(store.clone(), oauth);
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::default(),
        receiver.deliverer.clone(),
        config,
        CancellationToken::new(),
    );
    watchers.enable_push(super::PushConfig {
        tokens,
        public_url: url::Url::parse("https://mail.example.com").unwrap(),
        google: Some(super::GooglePush {
            topic: "projects/test/topics/mail".to_owned(),
            expected: PushExpectations {
                audience: "https://mail.example.com/push/google".to_owned(),
                service_account: "push@example.iam.gserviceaccount.com".to_owned(),
            },
            verifier: PushVerifier::new(Http::for_tests(), endpoints),
        }),
    });
    ProviderSetup {
        store,
        account: account.id,
        watchers,
        receiver,
        server,
        _dir: dir,
    }
}

/// Gmail's `users.watch`, `users.stop` and `users.history.list` on the mock server.
pub(super) const WATCH_PATH: &str = "/gmail/gmail/v1/users/me/watch";
pub(super) const STOP_PATH: &str = "/gmail/gmail/v1/users/me/stop";
pub(super) const HISTORY_PATH: &str = "/gmail/gmail/v1/users/me/history";

/// A `users.watch` answer at `history_id` that expires in six days.
pub(super) fn watch_response(history_id: &str) -> serde_json::Value {
    let expiration_ms = (postkeep_store::now() + 6 * 24 * 3600) * 1000;
    json!({ "historyId": history_id, "expiration": expiration_ms.to_string() })
}

/// The next delivery.
pub(super) async fn next_event(receiver: &mut Receiver) -> Received {
    receiver.requests.recv().await.expect("the receiver closed")
}

/// Waits until `done` says so, checking every 20 ms.
pub(super) async fn until(mut done: impl AsyncFnMut() -> bool) {
    while !done().await {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The requests `server` saw to `method` `path`.
pub(super) async fn requests(server: &MockServer, method: &str, path: &str) -> usize {
    let seen = server.received_requests().await.unwrap_or_default();
    let to = |request: &&Request| request.method.as_str() == method && request.url.path() == path;
    seen.iter().filter(to).count()
}

/// Waits until `server` has seen `count` requests to `method` `path`.
pub(super) async fn wait_for_requests(server: &MockServer, method: &str, path: &str, count: usize) {
    until(async || requests(server, method, path).await >= count).await;
}

/// The stored Graph subscription once its id is `wanted`; `None` waits until
/// none is stored.
pub(super) async fn wait_for_subscription(
    setup: &ProviderSetup,
    wanted: Option<&str>,
) -> Option<PushSubscription> {
    let stored = async || setup.store.push_subscription(&setup.account).await.unwrap();
    until(async || {
        stored()
            .await
            .and_then(|stored| stored.subscription_id)
            .as_deref()
            == wanted
    })
    .await;
    stored().await
}

/// Holds each request to a mock until the test lets it through, so the test
/// can act while the request is in flight.
///
/// Each request waits for its own [`Hold::release`]; one given before the
/// request comes lets it through at once. Dropping the `Hold` lets every
/// request through, so a failing test never leaves the server blocked. A held
/// request blocks the mock server's only thread and its state, so read
/// nothing from the server (`received_requests`, counts, `verify`) while one
/// is held, and hold only where nothing else is in flight to that server.
pub(super) struct Hold {
    releases: std::sync::mpsc::Sender<()>,
    arrivals: mpsc::UnboundedReceiver<()>,
}

/// The responder of a [`Hold`]: it answers `answer` once let through.
pub(super) struct Held {
    releases: Mutex<std::sync::mpsc::Receiver<()>>,
    arrived: mpsc::UnboundedSender<()>,
    answer: ResponseTemplate,
}

impl Hold {
    /// A hold, and the responder to mount, which answers `answer`.
    pub(super) fn new(answer: ResponseTemplate) -> (Self, Held) {
        let (releases, waiting) = std::sync::mpsc::channel();
        let (arrived, arrivals) = mpsc::unbounded_channel();
        let held = Held {
            releases: Mutex::new(waiting),
            arrived,
            answer,
        };
        (Self { releases, arrivals }, held)
    }

    /// Waits until a request is held, and fails if `run` ends first.
    pub(super) async fn arrived_before(&mut self, run: &mut (impl Future + Unpin)) {
        tokio::select! {
            arrived = self.arrivals.recv() => arrived.expect("the responder keeps its sender"),
            _ = run => panic!("the run ended before the held request"),
        }
    }

    /// Waits until a request is held, for a test that holds no run.
    pub(super) async fn arrived(&mut self) {
        self.arrivals
            .recv()
            .await
            .expect("the responder keeps its sender");
    }

    /// Lets one request through: the held one, or else the next to come.
    pub(super) fn release(&self) {
        // Fails only once the mock server is gone, when nothing is held.
        let _ = self.releases.send(());
    }
}

impl wiremock::Respond for Held {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let released = self.releases.lock().unwrap();
        // A dropped `Hold` ends the wait like a release.
        if released.try_recv() == Err(TryRecvError::Empty) {
            let _ = self.arrived.send(());
            let _ = released.recv();
        }
        drop(released);
        self.answer.clone()
    }
}

/// Stops the pump started by a published event.
pub(super) async fn finish(setup: &ProviderSetup) {
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

/// Pauses the webhook the way ten real delivery failures do.
///
/// The row stays enabled. The pause time is now, so the pump waits out
/// the configured retry interval before it sends anything.
pub(super) async fn pause_webhook(setup: &ProviderSetup) {
    let now = postkeep_store::now();
    let mut effect = DeliveryEffect::None;
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        effect = setup
            .store
            .record_delivery(
                &setup.account,
                &DeliveryRecord {
                    created_at: now,
                    test: false,
                    succeeded: false,
                    summary: "HTTP 500".to_owned(),
                    elapsed_ms: None,
                },
            )
            .await
            .unwrap();
    }
    assert_eq!(effect, DeliveryEffect::Paused);
    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    assert!(hook.settings.enabled);
    assert!(hook.is_paused());
}

/// Turns the webhook off through `Store::set_webhook_enabled`, then
/// `Watchers::refresh`.
///
/// The MCP `set_webhook_enabled` tool writes the flag and then sends the
/// same account-change notification as the account page. The watcher
/// listener for that notification is `refresh`.
pub(super) async fn disable_webhook_like_mcp(setup: &ProviderSetup) {
    setup
        .store
        .set_webhook_enabled(&setup.account, false)
        .await
        .unwrap();
    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    assert!(!hook.settings.enabled, "the user turned the webhook off");
    assert!(hook.paused_at.is_none(), "turning it off clears a pause");
    setup.watchers.refresh(&setup.account);
}

/// Waits until the account's outbox has reached `sequence`.
pub(super) async fn wait_for_sequence(setup: &ProviderSetup, sequence: i64) {
    let last = async || {
        setup
            .store
            .webhook(&setup.account)
            .await
            .unwrap()
            .unwrap()
            .last_sequence
    };
    until(async || last().await >= sequence).await;
}

/// Stores an allow rule for `account`; the store checks none of the names.
pub(super) async fn allow(
    store: &Store,
    account: &AccountId,
    field: &str,
    kind: &str,
    pattern: &str,
) {
    let [action, field, kind] = ["allow", field, kind].map(str::to_owned);
    let pattern = SecretString::from(pattern.to_owned());
    let rule = NewFilterRule {
        action,
        field,
        kind,
        pattern,
    };
    let add = store.add_webhook_filter_rule(account, &rule, 99, |_| Ok(()));
    add.await.unwrap();
}
