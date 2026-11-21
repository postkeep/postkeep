//! OAuth 2.1 authorization server for postkeep.
//!
//! MCP clients discover this server through the protected resource metadata
//! (RFC 9728) and authorization server metadata (RFC 8414), identify
//! themselves with a Client ID Metadata Document at an `https` URL or
//! register dynamically (RFC 7591), and send the user to a sign-in page.
//! There the user signs in with Microsoft or Google, or enters a mailbox
//! address and an app password, which an IMAP login checks before an
//! authorization code is issued. The page walks the user through creating
//! the app password.
//!
//! * Authorization code flow only, with PKCE (`S256`) required.
//! * Opaque access and refresh tokens; refresh tokens rotate on every use,
//!   and a replayed code or refresh token revokes its grant, except for
//!   refresh rotations within the configured grace from first use.
//! * Token revocation (RFC 7009) revokes the whole grant.
//! * Resource indicators (RFC 8707) are checked against the MCP endpoint.
//!
//! An account page (`/account`) lets a user sign in the same way to
//! disconnect one app or every app, replace the stored app password or
//! delete their data.
//!
//! [`router`] serves the OAuth endpoints and the account page. [`require_bearer`] is middleware
//! that protects the MCP endpoint and inserts an [`Authenticated`] value into
//! the request extensions. Who a token belongs to is decided by a
//! [`PrincipalResolver`]: by default [`TokenResolver`], which accepts the
//! access tokens this server issued and puts every caller in the
//! [`DEFAULT_TENANT`]. An embedding can install its own with
//! [`AuthState::set_principal_resolver`], including one whose callers may
//! use several mailboxes ([`PrincipalResolver::selects_mailboxes`]).
//!
//! An embedding that signs people in for some resources itself installs a
//! [`SignInHook`] with [`AuthState::set_sign_in_hook`]. `/authorize` hands
//! those requests to it, and the embedding approves each one for a
//! principal of its own with [`AuthState::approve_sign_in`].
//!
//! An embedding with its own error pages installs an
//! [`InvalidRequestPage`] with [`AuthState::set_invalid_request_page`].
//! `/authorize` shows it, in place of the server's own page, for a request
//! it refuses. `/oauth/{provider}/callback` shows the embedding's pages in
//! place of its own too, when it implements
//! [`InvalidRequestPage::callback_page`].
//!
//! An embedding page can also add a Microsoft or Google mailbox to one of
//! its tenants with [`AuthState::start_upstream_sign_in`]. The callback
//! stores the account in that tenant and hands it to the embedding's
//! [`ContinuationHook`].
//!
//! An embedding's checks on the MCP endpoint see each tool call as a
//! [`ToolCall`] and turn it down with a [`Refusal`].
//!
//! An embedding that limits how its tenants use the server installs a
//! [`UsageHook`]. It decides whether a sign-in may add another mailbox to
//! a tenant and, in the `postkeep` server, whether a tool call or a
//! message about to be sent ([`Sending`]) may go ahead, and hears how each
//! call it allowed ended ([`CallEnd`]). It can also lower
//! the [`OutboxCeilings`] of a mailbox's [`Outbox`], and say how many of
//! its webhook filter rules count.

mod account;
mod account_view;
mod assets;
mod authorize;
mod bearer;
mod check;
mod client_ip;
mod client_metadata;
mod config;
mod continuation;
mod error;
mod filters;
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing;
mod hosts;
mod limits;
mod metadata;
mod pages;
mod random;
mod redirect;
mod register;
mod sign_in;
mod state;
mod token;
mod upstream;
mod usage;
mod verifier;
mod webhook;

pub use account::ACCOUNT_PATH;
pub use bearer::{
    Authenticated, BearerRequest, DEFAULT_TENANT, PrincipalResolver, Resolution, ResolveFuture,
    TokenResolver, require_bearer,
};
pub use check::{CheckFuture, Refusal, ToolCall};
pub use client_ip::ClientIp;
pub use config::{AuthConfig, ConfigError, ResourcePrefix};
pub use continuation::{ContinuationHook, ContinuedSignIn};
pub use filters::{
    PatternPart, UnreadableRules, parse_filter_rules, parts as pattern_parts,
    plain as pattern_is_plain, unreadable_rules,
};
pub use hosts::{AllowedHosts, RequestHost};
pub use sign_in::{CallbackPage, InvalidRequestPage, SignInFuture, SignInHook, SignInRequest};
pub use state::{AccountListener, AuthState, DeletionFuture, DeletionListener};
pub use usage::{
    CallEnd, CeilingsFuture, DEFAULT_MAX_FILTER_RULES, HoldFuture, NewMailbox, Outbox,
    OutboxCeilings, Outcome, Sending, UsageHook, filter_rule_limit,
};
pub use verifier::{CredentialVerifier, MailVerifier, VerifyError, VerifyFuture};

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

/// Scope granted to every token: full access to the account's mail.
pub const SCOPE: &str = "mail";

/// Largest accepted request body for OAuth endpoints.
const BODY_LIMIT: usize = 16 * 1024;

/// Which optional parts [`router_with`] serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RouterOptions {
    /// The account page under [`ACCOUNT_PATH`]: sign-in, disconnecting
    /// apps, the stored password, deletion, webhook settings and their
    /// filter rules. On by default; an embedder with its own account pages
    /// turns it off.
    pub account_pages: bool,
}

impl Default for RouterOptions {
    fn default() -> Self {
        Self {
            account_pages: true,
        }
    }
}

/// Builds the router with the OAuth endpoints, metadata documents, the
/// sign-in page and the account page. Merge it into the application router
/// at the root.
pub fn router(state: AuthState) -> Router {
    router_with(state, RouterOptions::default())
}

/// [`router`] with some optional parts left out. The OAuth endpoints, the
/// metadata documents and the sign-in page are always served.
pub fn router_with(state: AuthState, options: RouterOptions) -> Router {
    let resource_metadata = state.config().resource_metadata_path();
    let prefixed_metadata = state
        .config()
        .prefixed_resource_route()
        .map(|route| format!("{}{route}", config::METADATA_PATH));
    let mut limited = Router::new()
        .route("/register", post(register::register))
        .route(
            "/authorize",
            get(authorize::show)
                .post(authorize::submit)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    authorize::embedded_page,
                )),
        )
        .route("/token", post(token::token))
        .route("/revoke", post(token::revoke))
        .route("/oauth/{provider}/start", post(upstream::start));
    if options.account_pages {
        limited = limited
            .route(account::ACCOUNT_PATH, get(account::show))
            .route("/account/sign-in", post(account::sign_in))
            .route("/account/sign-out", post(account::sign_out))
            .route("/account/revoke", post(account::revoke))
            .route("/account/clients/revoke", post(account::revoke_client))
            .route("/account/password", post(account::update_password))
            .route("/account/delete", post(account::delete))
            .route("/account/webhook", post(webhook::save))
            .route("/account/webhook/test", post(webhook::test))
            .route(
                "/account/webhook/rotate-secret",
                post(webhook::rotate_secret),
            )
            .route("/account/webhook/filters/add", post(filters::add))
            .route("/account/webhook/filters/edit", post(filters::edit))
            .route("/account/webhook/filters/remove", post(filters::remove))
            .route(
                "/account/webhook/filters/enabled",
                post(filters::set_enabled),
            );
    }
    let limited = limited
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            limit_requests,
        ))
        // After `route_layer`, so that each request is counted once: the
        // callback's own limit sits inside the layer that hands its pages,
        // the limit's `429` among them, to the embedding.
        .route(
            "/oauth/{provider}/callback",
            get(upstream::callback)
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    limit_requests,
                ))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    upstream::embedded_page,
                )),
        );
    let mut public = Router::new();
    for &(path, content_type, body) in pages::BRAND_ASSETS {
        public = public.route(
            path,
            get(move || async move { pages::brand_asset(content_type, body) }),
        );
    }
    for &(path, content_type, body) in assets::FILES {
        public = public.route(
            &format!("{}{path}", assets::ASSETS_PREFIX),
            get(move || async move { pages::brand_asset(content_type, body) }),
        );
    }
    if let Some(route) = prefixed_metadata {
        public = public.route(&route, get(metadata::protected_resource));
    }
    public
        .route(
            "/.well-known/oauth-authorization-server",
            get(metadata::authorization_server),
        )
        .route(config::METADATA_PATH, get(metadata::protected_resource))
        .route(&resource_metadata, get(metadata::protected_resource))
        .route(pages::ICON_PATH, get(pages::icon))
        .route(pages::LOGO_PATH, get(pages::logo))
        .merge(limited)
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(state)
}

/// Rejects clients that exceed [`AuthConfig::requests_per_minute`] with
/// `429 Too Many Requests`.
async fn limit_requests(
    State(state): State<AuthState>,
    ip: ClientIp,
    request: Request,
    next: Next,
) -> Response {
    let Err(wait) = state.limits().requests.check(&ip.key()) else {
        return next.run(request).await;
    };
    tracing::warn!("rate limit exceeded");
    let path = request.uri().path();
    let mut response = if path == "/authorize"
        || path.starts_with(account::ACCOUNT_PATH)
        || path.starts_with("/oauth/")
    {
        pages::message(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            &format!("Wait {} and try again.", limits::describe_wait(wait)),
        )
    } else {
        error::OAuthError::too_many_requests().into_response()
    };
    if let Ok(value) = HeaderValue::from_str(&wait.as_secs().max(1).to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}
