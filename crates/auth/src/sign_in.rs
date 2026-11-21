//! The [`SignInHook`]: authorization requests that an embedding signs in
//! itself, instead of the mailbox sign-in page, and the
//! [`InvalidRequestPage`] for the requests `/authorize` refuses and for the
//! server's own pages at `/oauth/{provider}/callback`.

use std::future::Future;
use std::pin::Pin;

use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use postkeep_store::{AuthorizationRequest, Client, GrantSubject, StoreError};

use crate::authorize;
use crate::state::AuthState;

/// The future [`SignInHook::start`] and
/// [`ContinuationHook::finish`](crate::ContinuationHook::finish) return.
pub type SignInFuture<'a> = Pin<Box<dyn Future<Output = Response> + Send + 'a>>;

/// An authorization request handed to a [`SignInHook`].
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct SignInRequest<'a> {
    /// The pending request's ID. It is a secret: whoever holds it can
    /// approve or deny the request. Keep it out of logs and away from
    /// other sites.
    pub id: &'a str,
    /// The validated request, stored until
    /// [`AuthConfig::sign_in_ttl`](crate::AuthConfig::sign_in_ttl) passes.
    pub request: &'a AuthorizationRequest,
    /// The client asking for access.
    pub client: &'a Client,
    /// The headers of the browser's `GET /authorize`.
    pub headers: &'a HeaderMap,
}

/// Leaves out the request ID and the browser's cookies, which are secrets.
impl std::fmt::Debug for SignInRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignInRequest")
            .field("request", self.request)
            .field("client", self.client)
            .finish_non_exhaustive()
    }
}

/// Signs people in for resources that an embedding serves itself, instead
/// of the mailbox sign-in page.
///
/// `GET /authorize` checks a request as usual (client, redirect URI, PKCE,
/// resource) and stores it. If [`handles`](Self::handles) is true for its
/// resource, the browser gets the response of [`start`](Self::start),
/// typically a redirect to the embedding's own sign-in or consent page.
/// That page finishes with [`AuthState::approve_sign_in`], for a principal
/// it chooses, or with [`AuthState::deny_sign_in`]. It should accept those
/// actions only as same-origin form posts, as the sign-in page does. The
/// code exchange with PKCE, refresh rotation and replay detection then work
/// as they do for a mailbox.
///
/// The tokens act for the principal, not for a mailbox account, and
/// [`TokenResolver`](crate::TokenResolver) refuses them. The embedding also
/// installs a [`PrincipalResolver`](crate::PrincipalResolver) that reads
/// them with [`AuthState::access_grant`]. A request the hook handles cannot
/// be finished on the mailbox sign-in page or with Microsoft or Google.
pub trait SignInHook: Send + Sync + 'static {
    /// Whether this hook signs people in for `resource`, the request's
    /// RFC 8707 resource indicator. A request without one always gets the
    /// mailbox sign-in page.
    fn handles(&self, resource: &str) -> bool;

    /// The response to `GET /authorize` for a request this hook handles.
    /// The server adds `Cache-Control: no-store`.
    fn start<'a>(&'a self, state: &'a AuthState, request: SignInRequest<'a>) -> SignInFuture<'a>;
}

/// An embedding's error pages, in place of the server's own.
///
/// [`page`](Self::page) is the page `/authorize` shows a browser for a
/// request it refuses, in place of the server's "This link can't be used"
/// page. [`callback_page`](Self::callback_page) answers the server's pages
/// at `/oauth/{provider}/callback`.
///
/// The requests `/authorize` refuses have no or an unknown client, a
/// redirect URI that is not registered or not allowed, an incomplete
/// sign-in form, or an error that cannot go back to a web app. A request
/// that goes back to the app, and the server's `500`, `429` and `403` pages
/// at `/authorize`, stay the server's.
///
/// The response to a refused request is sent as it is: a page, never a
/// redirect to the request's redirect URI (RFC 9700 section 4.11.1).
/// Install it with [`AuthState::set_invalid_request_page`].
pub trait InvalidRequestPage: Send + Sync + 'static {
    /// The page for the refused request with `request`'s method, URI,
    /// version and headers (not its body or extensions). `reason` is the
    /// sentence the server's page shows, such as "The authorization request
    /// has no `client_id`." Both can hold text taken from the request: the
    /// reason for a Client ID Metadata Document names the `client_id`'s host
    /// and why its document was refused, and the URI and headers are the
    /// browser's. Escape them as HTML before putting them on the page.
    fn page(&self, request: &Parts, reason: &str) -> Response;

    /// The page for `request` in place of the server's own page at
    /// `/oauth/{provider}/callback`; `None`, the default, keeps the
    /// server's. `page` is what the server's page says, with its status.
    /// Those pages are a Microsoft or Google sign-in that the callback does
    /// not finish (it expired, was used or was started in another browser;
    /// it was cancelled or needs an administrator's approval; the provider
    /// failed or a permission is missing; the allow-list, the usage hook or
    /// an address connected another way refused it; a storage error), a
    /// provider this server does not offer, Microsoft's admin-consent
    /// answer, and the request limit's `429`. A sign-in that finishes gets
    /// what started it.
    ///
    /// The server adds `Cache-Control: no-store`, since the address holds
    /// the provider's code and `state`; the `Set-Cookie` of its own page,
    /// which clears the browser-binding cookie of a sign-in it ended; and
    /// the `429`'s `Retry-After`. `page.message` can name the address the
    /// provider gave, and the URI and headers are the browser's: escape
    /// them as HTML.
    fn callback_page(&self, request: &Parts, page: &CallbackPage<'_>) -> Option<Response> {
        let _ = (request, page);
        None
    }
}

/// What the server's own page at `/oauth/{provider}/callback` says.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct CallbackPage<'a> {
    /// The status the server's page has.
    pub status: StatusCode,
    /// Its title, such as "This sign-in has expired".
    pub title: &'a str,
    /// The sentences under the title.
    pub message: &'a str,
}

/// The method, URI, version and headers of `request`, without its body or
/// extensions.
pub fn head(request: &axum::extract::Request) -> Parts {
    let mut head = axum::extract::Request::new(());
    *head.method_mut() = request.method().clone();
    *head.uri_mut() = request.uri().clone();
    *head.version_mut() = request.version();
    *head.headers_mut() = request.headers().clone();
    head.into_parts().0
}

impl AuthState {
    /// The pending authorization request `id`, if it has not expired or
    /// been finished and the sign-in hook handles it.
    ///
    /// # Errors
    ///
    /// Returns an error if the store fails.
    pub async fn sign_in_request(
        &self,
        id: &str,
    ) -> Result<Option<AuthorizationRequest>, StoreError> {
        let request = self.store().authorization_request(id).await?;
        Ok(request.filter(|request| self.hook_handles(request)))
    }

    /// Approves the pending request `id` for `principal`: issues an
    /// authorization code for it and returns the redirect that takes the
    /// browser back to the client. `None` if [`sign_in_request`] finds no
    /// such request.
    ///
    /// [`sign_in_request`]: Self::sign_in_request
    ///
    /// # Errors
    ///
    /// Returns an error if `principal` is empty or the store fails. The
    /// request stays pending, so the page can try again.
    pub async fn approve_sign_in(
        &self,
        id: &str,
        principal: &str,
    ) -> Result<Option<Response>, StoreError> {
        if principal.is_empty() {
            return Err(StoreError::InvalidInput("principal must not be empty"));
        }
        let Some(request) = self.sign_in_request(id).await? else {
            return Ok(None);
        };
        let response = authorize::issue_code(
            self,
            &request,
            id,
            GrantSubject::Principal(principal.to_owned()),
        )
        .await?;
        tracing::info!(client_id = %request.client_id, "sign-in approved");
        Ok(Some(response))
    }

    /// Denies the pending request `id`: deletes it and returns the redirect
    /// that takes the browser back to the client with `access_denied`.
    /// `None` if [`sign_in_request`] finds no such request.
    ///
    /// [`sign_in_request`]: Self::sign_in_request
    ///
    /// # Errors
    ///
    /// Returns an error if the store fails.
    pub async fn deny_sign_in(&self, id: &str) -> Result<Option<Response>, StoreError> {
        let Some(request) = self.sign_in_request(id).await? else {
            return Ok(None);
        };
        self.store().delete_authorization_request(id).await?;
        Ok(Some(authorize::error_redirect(
            self,
            &request.redirect_uri,
            "access_denied",
            "the user denied the request",
            request.state.as_deref(),
        )))
    }
}
