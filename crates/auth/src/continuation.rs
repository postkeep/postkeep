//! The [`ContinuationHook`]: Microsoft or Google sign-ins that an
//! embedding starts from its own pages to add a mailbox to one of its
//! tenants.

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use postkeep_store::{Account, StoreError, UpstreamPurpose};
use postkeep_upstream::UpstreamProvider;
use secrecy::{ExposeSecret, SecretString};

use crate::error::no_store;
use crate::pages;
use crate::sign_in::SignInFuture;
use crate::state::AuthState;
use crate::upstream;

/// A sign-in that an embedding started with
/// [`AuthState::start_upstream_sign_in`], finished.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ContinuedSignIn<'a> {
    /// The tenant the sign-in was started for.
    pub tenant: &'a str,
    /// The value the embedding passed when it started the sign-in.
    pub continuation: &'a str,
    /// The account in `tenant`, created or updated, with its new tokens
    /// stored.
    pub account: &'a Account,
    /// The headers of the browser's callback request.
    pub headers: &'a HeaderMap,
}

/// Leaves out the continuation and the browser's cookies.
impl std::fmt::Debug for ContinuedSignIn<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContinuedSignIn")
            .field("tenant", &self.tenant)
            .field("account", &self.account.id)
            .finish_non_exhaustive()
    }
}

/// Finishes the Microsoft or Google sign-ins that an embedding starts with
/// [`AuthState::start_upstream_sign_in`], for example on an operator page
/// that adds Outlook mailboxes to a tenant.
///
/// The callback checks such a sign-in as it does one from the sign-in
/// page: it works once, only in the browser that started it, and needs
/// every scope and an allowed address. It then creates or updates the
/// account in the sign-in's tenant, stores its tokens, and answers with
/// the response of [`finish`](Self::finish), typically a redirect back to
/// the embedding's page. A sign-in that fails shows the server's error
/// page, or the embedding's
/// [`InvalidRequestPage::callback_page`](crate::InvalidRequestPage::callback_page),
/// and does not reach the hook.
pub trait ContinuationHook: Send + Sync + 'static {
    /// The response to the provider's callback once `sign_in.account` is
    /// stored. The server adds `Cache-Control: no-store`.
    fn finish<'a>(&'a self, state: &'a AuthState, sign_in: ContinuedSignIn<'a>)
    -> SignInFuture<'a>;
}

impl AuthState {
    /// Starts a Microsoft or Google sign-in that adds a mailbox to
    /// `tenant`, from an embedding's own page, and returns the redirect to
    /// the provider. The redirect sets the browser-binding cookie, so the
    /// sign-in finishes only in this browser. At
    /// `/oauth/{provider}/callback` the account is stored in `tenant`, and
    /// the [`ContinuationHook`] gets it with `continuation`. `login_hint`
    /// fills in the address at the provider. `None` if the provider is not
    /// configured.
    ///
    /// Whoever can get this called adds a mailbox to `tenant`. Call it only
    /// for a same-origin `POST` from a person the embedding has signed in
    /// and allows to change `tenant`, and take `tenant` from that session,
    /// never from the request.
    ///
    /// # Errors
    ///
    /// Returns an error if no [`ContinuationHook`] is installed, `tenant`
    /// is empty, or the store fails.
    pub async fn start_upstream_sign_in(
        &self,
        provider: UpstreamProvider,
        tenant: &str,
        continuation: &str,
        login_hint: Option<&str>,
    ) -> Result<Option<Response>, StoreError> {
        if tenant.is_empty() {
            return Err(StoreError::InvalidInput("tenant must not be empty"));
        }
        if self.continuation_hook().is_none() {
            return Err(StoreError::InvalidInput(
                "no continuation hook is installed",
            ));
        }
        let Some(client) = self
            .upstream()
            .filter(|client| client.is_configured(provider))
        else {
            return Ok(None);
        };
        let purpose = UpstreamPurpose::Continue {
            tenant: tenant.to_owned(),
            continuation: SecretString::from(continuation.to_owned()),
        };
        upstream::begin(self, provider, client, purpose, login_hint).await
    }
}

/// Hands a finished sign-in for `tenant` to the continuation hook.
pub async fn finish(
    state: &AuthState,
    tenant: &str,
    continuation: &SecretString,
    account: &Account,
    headers: &HeaderMap,
) -> Response {
    let Some(hook) = state.continuation_hook() else {
        tracing::error!("no continuation hook is installed to finish an upstream sign-in");
        return pages::server_error();
    };
    let sign_in = ContinuedSignIn {
        tenant,
        continuation: continuation.expose_secret(),
        account,
        headers,
    };
    (no_store(), hook.finish(state, sign_in).await).into_response()
}
