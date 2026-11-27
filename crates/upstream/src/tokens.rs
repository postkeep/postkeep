//! Access tokens for OAuth accounts: cached, refreshed before they expire,
//! and given up on when the provider revokes the grant.
//!
//! * Refreshes for one account are serialized, so concurrent tool calls
//!   trigger one refresh, not several racing ones that would invalidate
//!   each other's rotated refresh tokens.
//! * A rotated refresh token is saved before the new access token is used,
//!   and only while that refresh token is still the one stored. A sign-in
//!   that landed during the refresh is left alone and used instead.
//! * `invalid_grant` (and the other "sign in again" answers) marks the
//!   account in the store only when the rejected refresh token is still
//!   stored. Later calls fail fast until the user signs in again, which
//!   clears the mark.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError, Weak};

use http::StatusCode;
use postkeep_store::{AccountId, Store, StoreError, UpstreamTokens};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::oauth::{OAuthClient, OAuthError, TokenResponse, UpstreamProvider};

/// Access tokens are refreshed this many seconds before they expire.
pub const EXPIRY_MARGIN: i64 = 120;

/// How often a refresh may find that a sign-in replaced the grant before
/// it stops and asks the caller to retry.
const SUPERSEDED_ATTEMPTS: u32 = 4;

/// Assumed lifetime when the provider does not say (both say 3600).
const DEFAULT_LIFETIME: i64 = 3600;

/// Microsoft Graph requests in flight at once for one mailbox, from this
/// process.
///
/// Outlook allows four per app and mailbox, so a second process, such as
/// one starting during a rolling deploy, stays inside that limit for single
/// requests. A JSON batch can run four requests at once: it holds every slot
/// here, but two processes running batches can reach eight during a deploy.
pub const GRAPH_REQUESTS_PER_MAILBOX: usize = 2;

/// Why no access token is available.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The account has no stored tokens.
    #[error("this account is not connected through {0}; sign in again")]
    NotConnected(UpstreamProvider),
    /// The provider rejected the refresh token; the user must sign in again.
    #[error(
        "{provider} no longer accepts this sign-in ({reason}); sign in again from your MCP client"
    )]
    NeedsReauth {
        /// Provider.
        provider: UpstreamProvider,
        /// The recorded reason.
        reason: String,
    },
    /// The refresh failed for another reason; retrying may help.
    #[error(transparent)]
    OAuth(#[from] OAuthError),
    /// The store failed.
    #[error("could not load the account's tokens: {0}")]
    Store(#[from] StoreError),
}

/// Hands out access tokens for OAuth accounts. Cheap to clone.
#[derive(Clone)]
pub struct TokenManager {
    store: Store,
    oauth: OAuthClient,
    locks: Arc<Mutex<HashMap<AccountId, Weak<tokio::sync::Mutex<()>>>>>,
    graph_slots: Arc<Mutex<HashMap<AccountId, Weak<Semaphore>>>>,
}

impl fmt::Debug for TokenManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenManager")
            .field("oauth", &self.oauth)
            .finish_non_exhaustive()
    }
}

impl TokenManager {
    /// Creates the manager.
    #[must_use]
    pub fn new(store: Store, oauth: OAuthClient) -> Self {
        Self {
            store,
            oauth,
            locks: Arc::default(),
            graph_slots: Arc::default(),
        }
    }

    pub(crate) const fn set_deadline(&mut self, deadline: std::time::Instant) {
        self.oauth.set_deadline(deadline);
    }

    /// The OAuth client.
    #[must_use]
    pub const fn oauth(&self) -> &OAuthClient {
        &self.oauth
    }

    /// The store.
    #[must_use]
    pub const fn store(&self) -> &Store {
        &self.store
    }

    fn lock_for(&self, account: &AccountId) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.locks.lock().unwrap_or_else(PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(account).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(account.clone(), Arc::downgrade(&lock));
        lock
    }

    /// Waits for `count` of the [`GRAPH_REQUESTS_PER_MAILBOX`] Graph request
    /// slots of `account`. Every [`ApiClient`](crate::ApiClient) for
    /// Microsoft made from this manager or a clone of it shares them, so
    /// tool calls and webhook watchers together stay inside the limit.
    pub(crate) async fn graph_slot(
        &self,
        account: &AccountId,
        count: usize,
    ) -> Option<OwnedSemaphorePermit> {
        let slots = {
            let mut all = self
                .graph_slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            all.retain(|_, slots| slots.strong_count() > 0);
            all.get(account).and_then(Weak::upgrade).unwrap_or_else(|| {
                let slots = Arc::new(Semaphore::new(GRAPH_REQUESTS_PER_MAILBOX));
                all.insert(account.clone(), Arc::downgrade(&slots));
                slots
            })
        };
        // Never closed, so this always gets a permit.
        slots
            .acquire_many_owned(u32::try_from(count).ok()?)
            .await
            .ok()
    }

    /// A valid access token, refreshed if the cached one is missing or
    /// about to expire.
    ///
    /// # Errors
    ///
    /// Returns a [`TokenError`]; [`TokenError::NeedsReauth`] means the
    /// user must sign in again.
    pub async fn access_token(
        &self,
        account: &AccountId,
        provider: UpstreamProvider,
    ) -> Result<SecretString, TokenError> {
        if let Some(token) = self.cached(account, provider, None).await? {
            return Ok(token);
        }
        self.refresh(account, provider, None).await
    }

    /// Refreshes after the provider rejected `rejected` (HTTP 401), unless
    /// another task already replaced it.
    ///
    /// # Errors
    ///
    /// As [`TokenManager::access_token`].
    pub async fn refresh_after_rejection(
        &self,
        account: &AccountId,
        provider: UpstreamProvider,
        rejected: &SecretString,
    ) -> Result<SecretString, TokenError> {
        self.refresh(account, provider, Some(rejected)).await
    }

    /// The cached token if it is valid and not `rejected`.
    async fn cached(
        &self,
        account: &AccountId,
        provider: UpstreamProvider,
        rejected: Option<&SecretString>,
    ) -> Result<Option<SecretString>, TokenError> {
        let stored = self
            .store
            .upstream_tokens(account)
            .await?
            .ok_or(TokenError::NotConnected(provider))?;
        if let Some(reason) = stored.invalid_reason {
            return Err(TokenError::NeedsReauth { provider, reason });
        }
        let now = chrono::Utc::now().timestamp();
        let fresh = stored
            .tokens
            .access_expires_at
            .is_some_and(|expires| expires - EXPIRY_MARGIN > now);
        Ok(stored.tokens.access_token.filter(|token| {
            fresh
                && rejected.is_none_or(|rejected| rejected.expose_secret() != token.expose_secret())
        }))
    }

    async fn refresh(
        &self,
        account: &AccountId,
        provider: UpstreamProvider,
        rejected: Option<&SecretString>,
    ) -> Result<SecretString, TokenError> {
        let lock = self.lock_for(account);
        let _guard = self
            .oauth
            .http()
            .wait(lock.lock())
            .await
            .map_err(OAuthError::from)?;
        // The per-account lock does not cover sign-in. Each attempt re-reads
        // the row and writes back only while the refresh token it used is
        // still stored, so a newer grant is neither overwritten nor marked
        // invalid by `invalid_grant` on the old one.
        for _ in 0..SUPERSEDED_ATTEMPTS {
            if let Some(token) = self.cached(account, provider, rejected).await? {
                return Ok(token);
            }
            let stored = self
                .store
                .upstream_tokens(account)
                .await?
                .ok_or(TokenError::NotConnected(provider))?;
            if let Some(reason) = stored.invalid_reason.clone() {
                return Err(TokenError::NeedsReauth { provider, reason });
            }
            let refresh_token = stored.tokens.refresh_token.clone();
            match self.oauth.refresh(provider, &refresh_token).await {
                Ok(response) => {
                    let tokens = tokens_after_refresh(&stored.tokens, &response);
                    if self
                        .store
                        .save_upstream_tokens_if_current(account, &refresh_token, &tokens)
                        .await?
                    {
                        tracing::debug!(%provider, "refreshed an upstream access token");
                        return Ok(response.access_token);
                    }
                    tracing::info!(%provider, "a newer sign-in replaced the tokens during refresh; using the current ones");
                }
                Err(OAuthError::NeedsReauth { code, .. }) => {
                    if self
                        .store
                        .mark_upstream_tokens_invalid_if_current(account, &refresh_token, &code)
                        .await?
                    {
                        tracing::info!(%provider, %code, "upstream grant rejected; the account needs a new sign-in");
                        return Err(TokenError::NeedsReauth {
                            provider,
                            reason: code,
                        });
                    }
                    tracing::info!(%provider, "the rejected refresh token was already replaced; keeping the current sign-in");
                }
                Err(err) => return Err(err.into()),
            }
        }
        self.current_after_supersede(account, provider, rejected)
            .await
    }

    /// The credentials stored after every refresh attempt lost the race
    /// with a newer write.
    async fn current_after_supersede(
        &self,
        account: &AccountId,
        provider: UpstreamProvider,
        rejected: Option<&SecretString>,
    ) -> Result<SecretString, TokenError> {
        if let Some(token) = self.cached(account, provider, rejected).await? {
            return Ok(token);
        }
        let stored = self
            .store
            .upstream_tokens(account)
            .await?
            .ok_or(TokenError::NotConnected(provider))?;
        if let Some(reason) = stored.invalid_reason {
            return Err(TokenError::NeedsReauth { provider, reason });
        }
        // The grant kept changing and its access token is missing or inside
        // the expiry margin. Retrying may help; signing in again does not.
        Err(TokenError::OAuth(OAuthError::Rejected {
            provider,
            status: StatusCode::SERVICE_UNAVAILABLE,
            retry_after: None,
            code: "503".to_owned(),
            description: Some("the sign-in changed while refreshing; try again".to_owned()),
        }))
    }
}

/// The tokens to store after a refresh: the new access token, and the new
/// refresh token if the provider rotated it.
#[must_use]
pub fn tokens_after_refresh(previous: &UpstreamTokens, response: &TokenResponse) -> UpstreamTokens {
    UpstreamTokens {
        refresh_token: response
            .refresh_token
            .clone()
            .unwrap_or_else(|| previous.refresh_token.clone()),
        access_token: Some(response.access_token.clone()),
        access_expires_at: Some(expires_at(response.expires_in)),
        scope: response
            .scope
            .clone()
            .unwrap_or_else(|| previous.scope.clone()),
    }
}

/// The tokens to store after the first sign-in.
#[must_use]
pub fn tokens_after_sign_in(
    provider: UpstreamProvider,
    response: &TokenResponse,
) -> Option<UpstreamTokens> {
    Some(UpstreamTokens {
        refresh_token: response.refresh_token.clone()?,
        access_token: Some(response.access_token.clone()),
        access_expires_at: Some(expires_at(response.expires_in)),
        scope: response
            .scope
            .clone()
            .unwrap_or_else(|| provider.scopes().join(" ")),
    })
}

/// Unix time at which a token issued now with `expires_in` expires.
fn expires_at(expires_in: Option<i64>) -> i64 {
    let lifetime = expires_in
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_LIFETIME)
        .min(24 * 3600);
    chrono::Utc::now().timestamp() + lifetime
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn slot_manager(
        server: &wiremock::MockServer,
    ) -> (TokenManager, AccountId, tempfile::TempDir) {
        let key = postkeep_store::MasterKey::parse(
            &postkeep_store::MasterKey::generate_encoded().unwrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("slots.db").display());
        let store = Store::connect(&url, &key).await.unwrap();
        let account = store
            .upsert_oauth_account(
                &postkeep_store::OAuthAccount {
                    provider: postkeep_store::Provider::Graph,
                    subject: "slot-test",
                    email: "test@example.com",
                },
                &UpstreamTokens {
                    refresh_token: SecretString::from("refresh".to_owned()),
                    access_token: Some(SecretString::from("cached".to_owned())),
                    access_expires_at: Some(postkeep_store::now() + 3600),
                    scope: "mail".to_owned(),
                },
            )
            .await
            .unwrap();
        let oauth = OAuthClient::new(
            crate::Http::for_tests(),
            crate::Endpoints::all_at(&url::Url::parse(&server.uri()).unwrap()),
            url::Url::parse("https://mail.example.com").unwrap(),
            None,
            None,
        );
        (TokenManager::new(store, oauth), account.id, dir)
    }

    #[tokio::test]
    async fn a_graph_batch_waits_for_and_holds_every_mailbox_slot() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/ordinary"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let (manager, account, _dir) = slot_manager(&server).await;
        let one = manager.graph_slot(&account, 1).await.unwrap();
        let two = manager.graph_slot(&account, 1).await.unwrap();
        let batch = manager.graph_slot(&account, GRAPH_REQUESTS_PER_MAILBOX);
        tokio::pin!(batch);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut batch)
                .await
                .is_err()
        );
        drop(one);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut batch)
                .await
                .is_err()
        );
        drop(two);
        let held = batch.await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                manager.graph_slot(&account, 1)
            )
            .await
            .is_err()
        );
        let api = crate::ApiClient::new(
            manager.clone(),
            account.clone(),
            UpstreamProvider::Microsoft,
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(10);
        let scoped = api.until(deadline);
        assert!(
            scoped
                .call_batch(
                    &url::Url::parse(&format!("{}/graph/v1.0/$batch", server.uri())).unwrap(),
                    &[],
                    bytes::Bytes::new(),
                    1024,
                    deadline,
                )
                .await
                .unwrap()
                .is_none()
        );
        // The scoped batch and this ordinary client contend for the same held permits.
        let url = url::Url::parse(&format!("{}/ordinary", server.uri())).unwrap();
        let ordinary = api.call(http::Method::GET, &url, &[], bytes::Bytes::new(), 1024);
        tokio::pin!(ordinary);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut ordinary)
                .await
                .is_err()
        );
        assert!(server.received_requests().await.unwrap().is_empty());
        drop(held);
        assert!(ordinary.await.unwrap().is_success());
        assert!(manager.graph_slot(&account, 1).await.is_some());
        let lock = manager.lock_for(&account);
        let _held_refresh = lock.lock().await;
        let mut limited = manager.clone();
        limited.set_deadline(std::time::Instant::now() + std::time::Duration::from_millis(10));
        let err = limited
            .refresh_after_rejection(
                &account,
                UpstreamProvider::Microsoft,
                &SecretString::from("rejected".to_owned()),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            TokenError::OAuth(OAuthError::Http(crate::http::HttpError::Deadline))
        ));
    }
}
