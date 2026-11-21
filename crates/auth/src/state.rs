//! Shared state for the OAuth handlers.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use postkeep_store::{AccountId, AuthorizationRequest, Client, Store};

use crate::bearer::{PrincipalResolver, TokenResolver};
use crate::client_metadata::{MetadataClients, MetadataError};
use crate::config::AuthConfig;
use crate::continuation::ContinuationHook;
use crate::limits::{Backoff, RateLimit};
use crate::sign_in::{InvalidRequestPage, SignInHook};
use crate::usage::UsageHook;
use crate::verifier::CredentialVerifier;

/// State shared by the OAuth endpoints and [`require_bearer`](crate::require_bearer).
/// Cheap to clone.
#[derive(Clone)]
pub struct AuthState {
    inner: Arc<Inner>,
}

struct Inner {
    store: Store,
    config: AuthConfig,
    verifier: Box<dyn CredentialVerifier>,
    limits: Limits,
    account_listeners: RwLock<Vec<AccountListener>>,
    deletion_listeners: RwLock<Vec<DeletionListener>>,
    webhooks: std::sync::OnceLock<postkeep_webhook::Deliverer>,
    upstream: std::sync::OnceLock<postkeep_upstream::OAuthClient>,
    /// Clients identified by a Client ID Metadata Document URL.
    metadata_clients: MetadataClients,
    /// Who a bearer token on the MCP endpoint belongs to.
    principal_resolver: RwLock<Arc<dyn PrincipalResolver>>,
    /// Signs people in for an embedding's own resources.
    sign_in_hook: RwLock<Option<Arc<dyn SignInHook>>>,
    /// Finishes the Microsoft or Google sign-ins an embedding starts.
    continuation_hook: RwLock<Option<Arc<dyn ContinuationHook>>>,
    /// Limits an embedding puts on use.
    usage_hook: RwLock<Option<Arc<dyn UsageHook>>>,
    /// An embedding's page for the requests `/authorize` refuses.
    invalid_request_page: RwLock<Option<Arc<dyn InvalidRequestPage>>>,
    /// In-flight and recent webhook test sends, keyed by account id.
    /// Closes the gap before a test delivery row is recorded.
    webhook_tests: Mutex<HashMap<String, WebhookTestSlot>>,
    /// Pause interval in seconds, for the account page. Clamped to
    /// 1..=86400. The default matches the server's pause interval.
    webhook_retry_secs: AtomicU64,
    /// The server's setting of how many of a mailbox's filter rules count,
    /// for the account page.
    max_filter_rules: AtomicUsize,
}

/// A per-account webhook test that has started or just finished.
enum WebhookTestSlot {
    /// `deliver` has not returned yet.
    InFlight,
    /// Finished at this Unix second. Blocks another test until the interval
    /// passes, including when the delivery row is not visible yet.
    Done(i64),
}

/// In-flight webhook test reservation.
///
/// Dropping the guard cancels the reservation unless
/// [`finish`](Self::finish) recorded the cooldown. A handler that is
/// dropped (request timeout, client disconnect) therefore does not leave
/// the account unable to send another test.
#[must_use = "dropping the guard cancels the webhook test reservation"]
pub struct WebhookTestGuard {
    state: AuthState,
    account: AccountId,
    finished: bool,
}

impl WebhookTestGuard {
    /// Records that the test was sent at `now`, starting the cooldown.
    /// Dropping the guard afterwards does not cancel it.
    pub(crate) fn finish(mut self, now: i64) {
        self.state.finish_webhook_test(&self.account, now);
        self.finished = true;
    }
}

impl Drop for WebhookTestGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.state.cancel_webhook_test(&self.account);
        }
    }
}

/// Called when an account's stored data changes (new password, deletion).
pub type AccountListener = Arc<dyn Fn(&AccountId) + Send + Sync>;

/// What a [`DeletionListener`] returns.
pub type DeletionFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

/// Awaited before an account is deleted, while its tokens and stored state
/// are still there.
pub type DeletionListener = Arc<dyn Fn(&AccountId) -> DeletionFuture<'_> + Send + Sync>;

/// Abuse limits shared by the handlers.
#[derive(Debug)]
pub struct Limits {
    /// Failed sign-ins per client IP.
    pub sign_in_ip: Backoff,
    /// Failed sign-ins per iCloud address.
    pub sign_in_account: Backoff,
    /// Client registrations per client IP.
    pub registrations: RateLimit,
    /// Requests per client IP to the OAuth endpoints.
    pub requests: RateLimit,
}

impl Limits {
    fn new(config: &AuthConfig) -> Self {
        let forget_after = Duration::from_hours(24);
        Self {
            sign_in_ip: Backoff::new(
                config.free_sign_in_failures,
                config.sign_in_backoff_base,
                config.ip_backoff_max,
                forget_after,
            ),
            sign_in_account: Backoff::new(
                config.free_sign_in_failures,
                config.sign_in_backoff_base,
                config.account_backoff_max,
                forget_after,
            ),
            registrations: RateLimit::new(config.registrations_per_ip, config.registration_window),
            requests: RateLimit::new(config.requests_per_minute, Duration::from_mins(1)),
        }
    }
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

impl AuthState {
    /// Creates the state from a store, configuration and credential verifier.
    pub fn new(store: Store, config: AuthConfig, verifier: impl CredentialVerifier) -> Self {
        let limits = Limits::new(&config);
        Self {
            inner: Arc::new(Inner {
                store,
                config,
                verifier: Box::new(verifier),
                limits,
                account_listeners: RwLock::new(Vec::new()),
                deletion_listeners: RwLock::new(Vec::new()),
                webhooks: std::sync::OnceLock::new(),
                upstream: std::sync::OnceLock::new(),
                metadata_clients: MetadataClients::new(postkeep_webhook::Deliverer::new(concat!(
                    "postkeep/",
                    env!("CARGO_PKG_VERSION")
                ))),
                principal_resolver: RwLock::new(Arc::new(TokenResolver)),
                sign_in_hook: RwLock::new(None),
                continuation_hook: RwLock::new(None),
                usage_hook: RwLock::new(None),
                invalid_request_page: RwLock::new(None),
                webhook_tests: Mutex::new(HashMap::new()),
                webhook_retry_secs: AtomicU64::new(3600),
                max_filter_rules: AtomicUsize::new(crate::DEFAULT_MAX_FILTER_RULES),
            }),
        }
    }

    /// Replaces the resolver that decides who a bearer token on the MCP
    /// endpoint belongs to. The default is [`TokenResolver`].
    pub fn set_principal_resolver(&self, resolver: Arc<dyn PrincipalResolver>) {
        *self
            .inner
            .principal_resolver
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = resolver;
    }

    /// The current principal resolver.
    pub(crate) fn principal_resolver(&self) -> Arc<dyn PrincipalResolver> {
        self.inner
            .principal_resolver
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Hands authorization requests for the resources `hook` handles to it
    /// instead of the mailbox sign-in page; see [`SignInHook`]. Replaces
    /// any earlier hook.
    pub fn set_sign_in_hook(&self, hook: Arc<dyn SignInHook>) {
        *self
            .inner
            .sign_in_hook
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    /// The sign-in hook, if it handles `request`.
    pub(crate) fn sign_in_hook_for(
        &self,
        request: &AuthorizationRequest,
    ) -> Option<Arc<dyn SignInHook>> {
        let resource = request.resource.as_deref()?;
        let hook = self
            .inner
            .sign_in_hook
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        hook.handles(resource).then_some(hook)
    }

    /// Whether the sign-in hook handles `request`, so the mailbox sign-in
    /// must not finish it.
    pub(crate) fn hook_handles(&self, request: &AuthorizationRequest) -> bool {
        self.sign_in_hook_for(request).is_some()
    }

    /// Hands the Microsoft or Google sign-ins started with
    /// [`start_upstream_sign_in`](Self::start_upstream_sign_in) to `hook`
    /// when they finish; see [`ContinuationHook`]. Replaces any earlier
    /// hook.
    pub fn set_continuation_hook(&self, hook: Arc<dyn ContinuationHook>) {
        *self
            .inner
            .continuation_hook
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    /// The continuation hook, if one is installed.
    pub(crate) fn continuation_hook(&self) -> Option<Arc<dyn ContinuationHook>> {
        self.inner
            .continuation_hook
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Asks `hook` before a sign-in adds a mailbox to a tenant; see
    /// [`UsageHook`]. Replaces any earlier hook.
    pub fn set_usage_hook(&self, hook: Arc<dyn UsageHook>) {
        *self
            .inner
            .usage_hook
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    /// The usage hook, if one is installed.
    pub(crate) fn usage_hook(&self) -> Option<Arc<dyn UsageHook>> {
        self.inner
            .usage_hook
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Shows `page` for the requests `/authorize` refuses, and for the
    /// server's own pages at `/oauth/{provider}/callback`, in place of the
    /// server's own page; see [`InvalidRequestPage`]. Replaces any earlier
    /// page.
    pub fn set_invalid_request_page(&self, page: Arc<dyn InvalidRequestPage>) {
        *self
            .inner
            .invalid_request_page
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(page);
    }

    /// The page for refused requests, if one is installed.
    pub(crate) fn invalid_request_page(&self) -> Option<Arc<dyn InvalidRequestPage>> {
        self.inner
            .invalid_request_page
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replaces the HTTPS client that fetches OAuth Client ID Metadata
    /// Documents. The default trusts the Mozilla roots and refuses
    /// non-public addresses; tests pass one that trusts a local server.
    pub fn set_client_metadata_fetcher(&self, deliverer: postkeep_webhook::Deliverer) {
        self.inner.metadata_clients.set_deliverer(deliverer);
    }

    /// The client whose `client_id` is a metadata document URL, fetched
    /// and stored when its cached document is no longer fresh. Adding a
    /// client that is not stored yet counts against the registration limit
    /// of `client_key`, the requester's network.
    pub(crate) async fn metadata_client(
        &self,
        client_id: &str,
        client_key: &str,
    ) -> Result<Client, MetadataError> {
        self.inner
            .metadata_clients
            .resolve(
                &self.inner.store,
                self.inner.config.max_clients,
                client_id,
                || self.inner.limits.registrations.check(client_key).is_ok(),
            )
            .await
    }

    /// Records how often a paused webhook is retried, so the account page
    /// can show the next attempt. Values outside 1..=86400 seconds are
    /// clamped. A sub-second interval is stored as one second.
    pub fn set_webhook_retry_interval(&self, interval: Duration) {
        let secs = interval.as_secs().clamp(1, 86_400);
        self.inner.webhook_retry_secs.store(secs, Ordering::Relaxed);
    }

    /// The pause interval in seconds.
    pub(crate) fn webhook_retry_secs(&self) -> i64 {
        i64::try_from(self.inner.webhook_retry_secs.load(Ordering::Relaxed)).unwrap_or(3600)
    }

    /// Records the server's setting of how many of a mailbox's filter rules
    /// count, oldest first, for the account page. A usage hook's number
    /// replaces it per mailbox, and more than 2,000 never count.
    pub fn set_max_filter_rules(&self, max: usize) {
        self.inner.max_filter_rules.store(max, Ordering::Relaxed);
    }

    /// The server's setting of how many filter rules count.
    pub(crate) fn max_filter_rules(&self) -> usize {
        self.inner.max_filter_rules.load(Ordering::Relaxed)
    }

    /// Registers a function to call when an account signs in (its password
    /// may have changed), changes its webhook settings or is deleted, so
    /// other components (cached IMAP sessions, webhook watchers) can react.
    pub fn add_account_listener(&self, listener: AccountListener) {
        if let Ok(mut listeners) = self.inner.account_listeners.write() {
            listeners.push(listener);
        }
    }

    /// Registers a function to await before an account is deleted, so that
    /// other components can undo what they set up at its provider (webhook
    /// watchers delete a Graph subscription or stop a Gmail watch) while
    /// its tokens are still stored. The deletion waits for it, so it bounds
    /// its own work.
    pub fn add_deletion_listener(&self, listener: DeletionListener) {
        if let Ok(mut listeners) = self.inner.deletion_listeners.write() {
            listeners.push(listener);
        }
    }

    /// Offers new-mail webhooks on the account page, sending test events
    /// with `deliverer`. Without this call the webhook card is hidden and
    /// its endpoints answer `404`. Only the first call has an effect.
    pub fn enable_webhooks(&self, deliverer: postkeep_webhook::Deliverer) {
        let _ = self.inner.webhooks.set(deliverer);
    }

    /// Offers sign-in with Microsoft and Google (the providers `client`
    /// is configured for). Without this call, or for a provider without
    /// credentials, its button is hidden and its routes answer `404`. Only
    /// the first call has an effect.
    pub fn enable_upstream(&self, client: postkeep_upstream::OAuthClient) {
        let _ = self.inner.upstream.set(client);
    }

    /// The upstream OAuth client, if sign-in with a provider is enabled.
    #[must_use]
    pub fn upstream(&self) -> Option<&postkeep_upstream::OAuthClient> {
        self.inner.upstream.get()
    }

    pub(crate) fn webhook_deliverer(&self) -> Option<&postkeep_webhook::Deliverer> {
        self.inner.webhooks.get()
    }

    /// Reserves the account's webhook test slot at `now`.
    ///
    /// Returns a guard when the slot was free. Hold it until the send
    /// finishes: dropping it without [`WebhookTestGuard::finish`] cancels
    /// the reservation, and finishing starts the cooldown of `interval`
    /// seconds. Returns `None` when a test is already in flight or one
    /// finished within `interval` seconds.
    #[must_use]
    pub(crate) fn try_begin_webhook_test(
        &self,
        account: &AccountId,
        now: i64,
        interval: i64,
    ) -> Option<WebhookTestGuard> {
        let mut slots = self
            .inner
            .webhook_tests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.retain(|_, slot| match slot {
            WebhookTestSlot::InFlight => true,
            WebhookTestSlot::Done(started) => now.saturating_sub(*started) < interval,
        });
        if slots.contains_key(&account.0) {
            return None;
        }
        slots.insert(account.0.clone(), WebhookTestSlot::InFlight);
        drop(slots);
        Some(WebhookTestGuard {
            state: self.clone(),
            account: account.clone(),
            finished: false,
        })
    }

    /// Drops an in-flight reservation when no test was sent.
    pub(crate) fn cancel_webhook_test(&self, account: &AccountId) {
        let mut slots = self
            .inner
            .webhook_tests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(slots.get(&account.0), Some(WebhookTestSlot::InFlight)) {
            slots.remove(&account.0);
        }
    }

    /// Records that a test send finished at `now`, starting the interval.
    pub(crate) fn finish_webhook_test(&self, account: &AccountId, now: i64) {
        let mut slots = self
            .inner
            .webhook_tests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.insert(account.0.clone(), WebhookTestSlot::Done(now));
    }

    /// Tells listeners that `account` changed.
    ///
    /// The account page and the MCP webhook tools both call this, so
    /// watchers and the outbox pump react the same way either way.
    pub fn notify_account_changed(&self, account: &AccountId) {
        let listeners = self
            .inner
            .account_listeners
            .read()
            .map(|listeners| listeners.clone())
            .unwrap_or_default();
        for listener in listeners {
            listener(account);
        }
    }

    /// Awaits the deletion listeners for `account`, one after another.
    ///
    /// Whatever deletes an account calls this first, while the account's
    /// tokens can still be read: before [`Store::delete_account`], and
    /// before [`Store::destroy_data_keys`] for its tenant. Afterwards it
    /// calls [`Self::notify_account_changed`] whatever happened, also when
    /// the deletion failed or stopped early: a listener may have stopped the
    /// account's watcher, and the notification starts it again.
    pub async fn before_account_deleted(&self, account: &AccountId) {
        let listeners = self
            .inner
            .deletion_listeners
            .read()
            .map(|listeners| listeners.clone())
            .unwrap_or_default();
        for listener in listeners {
            listener(account).await;
        }
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.inner.store
    }

    /// The configuration.
    #[must_use]
    pub fn config(&self) -> &AuthConfig {
        &self.inner.config
    }

    pub(crate) fn verifier(&self) -> &dyn CredentialVerifier {
        self.inner.verifier.as_ref()
    }

    pub(crate) fn limits(&self) -> &Limits {
        &self.inner.limits
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use postkeep_mail::ImapServer;
    use postkeep_store::{AccountId, MasterKey, Store};
    use secrecy::SecretString;

    use super::*;
    use crate::config::AuthConfig;
    use crate::verifier::{CredentialVerifier, VerifyFuture};

    struct Allow;

    impl CredentialVerifier for Allow {
        fn verify<'a>(
            &'a self,
            _server: &'a ImapServer,
            _email: &'a str,
            _password: &'a SecretString,
        ) -> VerifyFuture<'a> {
            Box::pin(async { Ok(()) })
        }
    }

    async fn state() -> (AuthState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("auth.db").display());
        let key =
            MasterKey::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap();
        let store = Store::connect(&url, &key).await.unwrap();
        let config = AuthConfig::new("https://mail.example.com", "/mcp").unwrap();
        (AuthState::new(store, config, Allow), dir)
    }

    #[tokio::test]
    async fn dropped_webhook_test_releases_the_slot() {
        let (state, _dir) = state().await;
        let account = AccountId("acct-drop".to_owned());
        let guard = state
            .try_begin_webhook_test(&account, 1_000, 10)
            .expect("slot");
        assert!(state.try_begin_webhook_test(&account, 1_000, 10).is_none());
        drop(guard);
        assert!(
            state.try_begin_webhook_test(&account, 1_000, 10).is_some(),
            "dropping the guard without finish must allow another test"
        );

        // The same release happens when the handler future is aborted.
        let account = AccountId("acct-abort".to_owned());
        let started = std::sync::Arc::new(AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&started);
        let background = state.clone();
        let task = tokio::spawn(async move {
            let _guard = background
                .try_begin_webhook_test(&account, 2_000, 10)
                .expect("slot");
            flag.store(true, Ordering::SeqCst);
            std::future::pending::<()>().await;
        });
        for _ in 0..1000 {
            if started.load(Ordering::SeqCst) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(
            started.load(Ordering::SeqCst),
            "the reservation was not taken"
        );
        assert!(
            state
                .try_begin_webhook_test(&AccountId("acct-abort".to_owned()), 2_000, 10)
                .is_none()
        );
        task.abort();
        let _ = task.await;
        let again = state.try_begin_webhook_test(&AccountId("acct-abort".to_owned()), 2_000, 10);
        assert!(
            again.is_some(),
            "aborting the handler must release the in-flight slot"
        );
        again.expect("slot").finish(2_000);
        assert!(
            state
                .try_begin_webhook_test(&AccountId("acct-abort".to_owned()), 2_009, 10)
                .is_none(),
            "finish still starts the cooldown"
        );
    }
}
