//! Sign-in with Microsoft or Google ("Continue with ..." buttons).
//!
//! postkeep is the OAuth client here. The flow:
//!
//! 1. `POST /oauth/{provider}/start` from one of postkeep's own pages
//!    (same-origin check, so another site can't start a sign-in in the
//!    user's browser). It stores a single-use sign-in under the hash of a
//!    random `state`, with a PKCE verifier and the hash of a random
//!    browser-binding value. The binding value goes into a short-lived
//!    `HttpOnly`, `SameSite=Lax` cookie. Then it redirects to the provider.
//!    An embedding's own page starts one the same way with
//!    [`AuthState::start_upstream_sign_in`].
//! 2. `GET /oauth/{provider}/callback`: the sign-in is taken (deleted) by
//!    `state`, and the binding cookie must match, so a callback URL crafted
//!    by someone else can't sign the victim in to the attacker's mailbox
//!    (login CSRF). The code is exchanged with the PKCE verifier, the
//!    granted scopes are checked, the identity is read and checked against
//!    the allowlist, and the encrypted tokens are stored.
//!    The take comes before the provider's code is used. It opens the sign-in
//!    before it deletes it; of two callbacks with one `state`, the one whose
//!    delete removes it gets it, and the other sees the page for a sign-in
//!    that expired or was used. If it cannot be opened for now (a key service
//!    that does not answer), the callback answers a server error and the
//!    sign-in stays; the code has not been sent to the provider, so loading the
//!    same callback URL again works until the sign-in expires
//!    ([`AuthConfig::sign_in_ttl`](crate::AuthConfig::sign_in_ttl)) or the
//!    provider's own code does (tested through the store, not the callback).
//!    One that can never be opened is deleted and the person starts again; one
//!    this version does not know stays until it expires.
//! 3. The sign-in then finishes what started it: the MCP client's
//!    authorization request (a code is issued as for an app password), an
//!    account page session, or, with the account stored in the embedding's
//!    tenant, its [`ContinuationHook`](crate::ContinuationHook).

use axum::Form;
use axum::extract::rejection::FormRejection;
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep_store::{
    Account, OAuthAccount, RemovedRefreshToken, Store, StoreError, UpstreamPurpose, UpstreamRequest,
};
use postkeep_upstream::oauth::OAuthError;
use postkeep_upstream::tokens::tokens_after_sign_in;
use postkeep_upstream::{OAuthClient, UpstreamProvider, pkce};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::account;
use crate::authorize;
use crate::continuation;
use crate::error::no_store;
use crate::pages::{self, OAuthButtons};
use crate::sign_in::CallbackPage;
use crate::state::AuthState;
use crate::usage;

/// The browser-binding cookie over HTTPS.
const SECURE_BINDING_COOKIE: &str = "__Host-postkeep_upstream";
/// The browser-binding cookie on a plain-HTTP local server.
const PLAIN_BINDING_COOKIE: &str = "postkeep_upstream";

/// Longest accepted `code` or `state`.
const MAX_PARAM_LEN: usize = 4096;

/// How an administrator approves the Microsoft app for an organization.
const ADMIN_CONSENT_GUIDE: &str = "https://postkeep.dev/docs/providers/microsoft-admin-consent/";

/// The path that starts a sign-in with `provider`.
#[must_use]
pub fn start_path(provider: UpstreamProvider) -> String {
    format!("/oauth/{}/start", provider.slug())
}

/// The sign-in buttons for the configured providers. `request_id` ties
/// them to an MCP client's authorization request; without it they sign in
/// to the account page.
#[must_use]
pub fn buttons(state: &AuthState, request_id: Option<&str>) -> OAuthButtons {
    let Some(client) = state.upstream() else {
        return OAuthButtons::default();
    };
    let path = |provider| client.is_configured(provider).then(|| start_path(provider));
    OAuthButtons {
        microsoft: path(UpstreamProvider::Microsoft),
        google: path(UpstreamProvider::Google),
        request_id: request_id.map(str::to_owned),
    }
}

fn binding_cookie_name(state: &AuthState) -> &'static str {
    if state.config().is_https() {
        SECURE_BINDING_COOKIE
    } else {
        PLAIN_BINDING_COOKIE
    }
}

fn binding_cookie(state: &AuthState, value: &str, max_age: u64) -> HeaderValue {
    let secure = if state.config().is_https() {
        "; Secure"
    } else {
        ""
    };
    let cookie = format!(
        "{}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
        binding_cookie_name(state)
    );
    HeaderValue::from_str(&cookie).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn read_binding_cookie(state: &AuthState, headers: &HeaderMap) -> Option<String> {
    let name = binding_cookie_name(state);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| value.to_owned())
        .filter(|value| !value.is_empty() && value.len() <= 128)
}

/// The stored form of the binding value.
fn binding_hash(value: &str) -> String {
    let digest = Sha256::new()
        .chain_update(b"postkeep/upstream-binding/v1/")
        .chain_update(value.as_bytes())
        .finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

fn provider_from_path(state: &AuthState, slug: &str) -> Option<(UpstreamProvider, OAuthClient)> {
    let provider = UpstreamProvider::from_slug(slug)?;
    let client = state.upstream()?;
    client
        .is_configured(provider)
        .then(|| (provider, client.clone()))
}

fn not_available() -> Response {
    pages::message(
        StatusCode::NOT_FOUND,
        "This sign-in option isn't available",
        "The server isn't set up for it. Go back and use another way to sign in.",
    )
}

fn expired() -> Response {
    pages::message(
        StatusCode::BAD_REQUEST,
        "This sign-in has expired",
        "It took too long, was already used, or was started in another browser. Go back to your app (or the account page) and start again.",
    )
}

#[derive(Deserialize)]
pub struct StartForm {
    #[serde(default)]
    request_id: String,
}

/// `POST /oauth/{provider}/start`
pub async fn start(
    State(state): State<AuthState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    form: Result<Form<StartForm>, FormRejection>,
) -> Response {
    if !account::same_origin(&state, &headers) {
        return account::forbidden();
    }
    let Some((provider, client)) = provider_from_path(&state, &slug) else {
        return not_available();
    };
    let request_id = form.map(|Form(form)| form.request_id).unwrap_or_default();
    let purpose = if request_id.is_empty() {
        UpstreamPurpose::Account
    } else {
        match authorize::mailbox_request(&state, &request_id).await {
            Ok(Some(_)) => UpstreamPurpose::Authorize {
                request_id: SecretString::from(request_id),
            },
            Ok(None) => return expired(),
            Err(err) => {
                tracing::error!(error = %err, "storage error");
                return pages::server_error();
            }
        }
    };
    match begin(&state, provider, &client, purpose, None).await {
        Ok(Some(response)) => response,
        Ok(None) => not_available(),
        Err(err) => {
            tracing::error!(error = %err, "could not start an upstream sign-in");
            pages::server_error()
        }
    }
}

/// Stores a sign-in for `purpose` and returns the redirect to `provider`,
/// which sets the browser-binding cookie. `None` if `client` can't sign in
/// with `provider`.
pub async fn begin(
    state: &AuthState,
    provider: UpstreamProvider,
    client: &OAuthClient,
    purpose: UpstreamPurpose,
    login_hint: Option<&str>,
) -> Result<Option<Response>, StoreError> {
    let random = || pkce::random_token().map_err(|_| StoreError::Random);
    let (state_value, verifier, binding) = (random()?, random()?, random()?);
    let challenge = pkce::challenge(&verifier);
    let Ok(url) = client.authorize_url(provider, &state_value, &challenge, login_hint) else {
        return Ok(None);
    };
    let ttl = state.config().sign_in_ttl;
    let request = UpstreamRequest {
        provider: provider.mail_provider(),
        purpose,
        code_verifier: SecretString::from(verifier),
        binding_hash: binding_hash(&binding),
    };
    state
        .store()
        .save_upstream_request(&state_value, &request, ttl)
        .await?;
    tracing::info!(%provider, "upstream sign-in started");
    let mut response = (no_store(), Redirect::to(url.as_str())).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        binding_cookie(state, &binding, ttl.as_secs()),
    );
    Ok(Some(response))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    /// Searched for Microsoft's `AADSTS` codes only; never shown or logged.
    error_description: Option<String>,
    /// Set by Microsoft's admin consent endpoint, whose answer carries no
    /// `state` of this server's.
    admin_consent: Option<String>,
}

/// `GET /oauth/{provider}/callback`
pub async fn callback(
    State(state): State<AuthState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    query: Result<Query<CallbackQuery>, axum::extract::rejection::QueryRejection>,
) -> Response {
    let (response, clear_cookie) =
        finish(&state, &slug, &headers, query.ok().map(|Query(q)| q)).await;
    // Clear the binding cookie only when this callback belongs to this
    // browser's sign-in: the state matched a stored request and the binding
    // cookie matched it. A missing state, an unknown state, or a state bound
    // to another browser must leave the cookie alone. An unrelated cross-site
    // GET would otherwise abort a sign-in that is still in progress.
    if clear_cookie {
        clear_binding_cookie(&state, response)
    } else {
        response
    }
}

/// Middleware on `/oauth/{provider}/callback`, outside the route's
/// request limit: answers a page of the server's own, the limit's `429`
/// among them, with the embedding's
/// [`InvalidRequestPage::callback_page`](crate::InvalidRequestPage::callback_page),
/// if one is installed and gives one.
pub async fn embedded_page(
    State(state): State<AuthState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(hook) = state.invalid_request_page() else {
        return next.run(request).await;
    };
    let head = crate::sign_in::head(&request);
    let response = next.run(request).await;
    let Some(shown) = response.extensions().get::<pages::Shown>().cloned() else {
        return response;
    };
    let page = CallbackPage {
        status: response.status(),
        title: &shown.title,
        message: &shown.message,
    };
    let Some(own) = hook.callback_page(&head, &page) else {
        return response;
    };
    let mut own = (no_store(), own).into_response();
    for cookie in response.headers().get_all(header::SET_COOKIE) {
        own.headers_mut().append(header::SET_COOKIE, cookie.clone());
    }
    if let Some(wait) = response.headers().get(header::RETRY_AFTER) {
        own.headers_mut().insert(header::RETRY_AFTER, wait.clone());
    }
    own
}

/// Expires the browser-binding cookie.
fn clear_binding_cookie(state: &AuthState, mut response: Response) -> Response {
    response
        .headers_mut()
        .append(header::SET_COOKIE, binding_cookie(state, "", 0));
    response
}

async fn finish(
    state: &AuthState,
    slug: &str,
    headers: &HeaderMap,
    query: Option<CallbackQuery>,
) -> (Response, bool) {
    let Some((provider, client)) = provider_from_path(state, slug) else {
        return (not_available(), false);
    };
    let (request, code) = match accept_callback(state, provider, headers, query).await {
        Ok(accepted) => accepted,
        Err(halt) => return (halt.response, halt.clear_cookie),
    };
    (
        finish_accepted(state, provider, &client, request, code, headers).await,
        true,
    )
}

/// Exchanges the code after the binding check has already run.
async fn finish_accepted(
    state: &AuthState,
    provider: UpstreamProvider,
    client: &OAuthClient,
    request: UpstreamRequest,
    code: String,
    headers: &HeaderMap,
) -> Response {
    let Some(store) = account_store(state, &request.purpose) else {
        return pages::server_error();
    };
    let token = match client
        .exchange_code(provider, &code, request.code_verifier.expose_secret())
        .await
    {
        Ok(token) => token,
        Err(err) => return sign_in_failed(provider, &err),
    };
    let revoke_unused = || async {
        if let Some(refresh) = token.refresh_token.as_ref()
            && let Err(err) = client.revoke(provider, refresh).await
        {
            tracing::warn!(%provider, error = %err, "could not revoke an unused upstream grant");
        }
    };
    let identity = match client.identity(provider, &token).await {
        Ok(identity) => identity,
        Err(err) => {
            revoke_unused().await;
            return sign_in_failed(provider, &err);
        }
    };
    if !state.config().email_allowed(&identity.email) {
        revoke_unused().await;
        return pages::message(
            StatusCode::FORBIDDEN,
            "This address isn't allowed",
            "This server isn't set up for that address. Ask the person who runs it to allow it.",
        );
    }
    let Some(tokens) = tokens_after_sign_in(provider, &token) else {
        return sign_in_failed(
            provider,
            &OAuthError::Malformed {
                provider,
                what: "no refresh token was issued",
            },
        );
    };
    let mail_provider = provider.mail_provider();
    let subject = Some(identity.subject.as_str());
    match usage::refusal(state, &store, &identity.email, mail_provider, subject).await {
        Ok(None) => {}
        Ok(Some(refusal)) => {
            revoke_unused().await;
            return pages::message(
                StatusCode::FORBIDDEN,
                "This mailbox can't be added",
                refusal.message(),
            );
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return pages::server_error();
        }
    }
    let account = match store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: mail_provider,
                subject: &identity.subject,
                email: &identity.email,
            },
            &tokens,
        )
        .await
    {
        Ok(account) => account,
        Err(StoreError::AccountConflict) => {
            revoke_unused().await;
            return pages::message(
                StatusCode::CONFLICT,
                "This address is already connected another way",
                &format!(
                    "{} is connected with an app password or another provider. Sign in that way instead, or delete the existing connection on the account page first.",
                    identity.email
                ),
            );
        }
        Err(StoreError::AccountDeleted) => {
            revoke_unused().await;
            return pages::account_deleted();
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return pages::server_error();
        }
    };
    tracing::info!(%provider, account_id = %account.id, "upstream sign-in completed");
    state.notify_account_changed(&account.id);
    let Some(response) = finish_purpose(state, request.purpose, &account, headers).await else {
        // The account's deletion committed before its session or the app's
        // code was stored: nothing of the account is left.
        revoke_unused().await;
        return pages::account_deleted();
    };
    response
}

/// The store a sign-in's account goes in: the tenant's, for a sign-in an
/// embedding started. `None`, before anything is stored, if no
/// continuation hook is installed to finish such a sign-in.
fn account_store(state: &AuthState, purpose: &UpstreamPurpose) -> Option<Store> {
    match purpose {
        UpstreamPurpose::Continue { tenant, .. } => {
            if state.continuation_hook().is_none() {
                tracing::error!("no continuation hook is installed to finish an upstream sign-in");
                return None;
            }
            Some(state.store().for_tenant(tenant))
        }
        UpstreamPurpose::Authorize { .. } | UpstreamPurpose::Account => Some(state.store().clone()),
    }
}

/// Finishes what started the sign-in, with the account it stored. `None` if
/// the account was deleted before that was done.
async fn finish_purpose(
    state: &AuthState,
    purpose: UpstreamPurpose,
    account: &Account,
    headers: &HeaderMap,
) -> Option<Response> {
    match purpose {
        UpstreamPurpose::Account => account::start_session(state, &account.id).await,
        UpstreamPurpose::Authorize { request_id } => {
            authorize::complete_by_id(state, request_id.expose_secret(), &account.id).await
        }
        UpstreamPurpose::Continue {
            tenant,
            continuation,
        } => Some(continuation::finish(state, &tenant, &continuation, account, headers).await),
    }
}

/// A callback that stops before a code exchange.
struct Halt {
    response: Response,
    /// Whether the binding cookie should be cleared. True only when this
    /// callback's `state` matched a stored sign-in and the binding cookie
    /// matched that sign-in.
    clear_cookie: bool,
}

/// Takes the stored sign-in for the callback's `state` and checks the
/// browser binding and the provider's answer. Returns the sign-in and the
/// authorization code, or the page to show instead.
async fn accept_callback(
    state: &AuthState,
    provider: UpstreamProvider,
    headers: &HeaderMap,
    query: Option<CallbackQuery>,
) -> Result<(UpstreamRequest, String), Box<Halt>> {
    let Some(query) = query else {
        return halt(expired(), false);
    };
    if provider == UpstreamProvider::Microsoft && query.admin_consent.is_some() {
        let approved = query.error.is_none();
        tracing::info!(approved, "Microsoft admin consent answered");
        return halt(admin_consent_answered(approved), false);
    }
    let Some(state_value) = query
        .state
        .as_deref()
        .filter(|value| !value.is_empty() && value.len() <= MAX_PARAM_LEN)
    else {
        return halt(expired(), false);
    };
    let request = match state.store().take_upstream_request(state_value).await {
        Ok(Some(request)) => request,
        Ok(None) => return halt(expired(), false),
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return halt(pages::server_error(), false);
        }
    };
    // Clear the cookie only when it matches this stored sign-in. A state
    // from another browser (an attacker's own sign-in, sent to the victim)
    // must not expire the victim's cookie, or their real callback fails.
    // A provider mismatch after a matching binding still clears it: the
    // cookie belongs to this browser.
    let bound = read_binding_cookie(state, headers).is_some_and(|value| {
        postkeep_store::constant_time_eq(
            binding_hash(&value).as_bytes(),
            request.binding_hash.as_bytes(),
        )
    });
    if !bound {
        tracing::warn!(%provider, "upstream callback without a matching browser binding");
        return halt(expired(), false);
    }
    if request.provider != provider.mail_provider() {
        tracing::warn!(%provider, "upstream callback for a different provider");
        return halt(expired(), true);
    }
    if let Some(error) = query.error.as_deref() {
        // The code comes from the browser's query string; log only a
        // plausible OAuth error code, never arbitrary text.
        let logged = if !error.is_empty()
            && error.len() <= 64
            && error.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        {
            error
        } else {
            "unrecognized"
        };
        tracing::info!(%provider, error = logged, "upstream sign-in not completed");
        let (title, detail) = not_completed(provider, error, query.error_description.as_deref());
        return halt(
            pages::message(StatusCode::BAD_REQUEST, title, &detail),
            true,
        );
    }
    let Some(code) = query
        .code
        .filter(|code| !code.is_empty() && code.len() <= MAX_PARAM_LEN)
    else {
        return halt(expired(), true);
    };
    Ok((request, code))
}

/// The title and text of the page for a provider that sent the browser
/// back with `error`. Microsoft's `description` is searched for the codes
/// that mean an administrator has to approve the app (Entra error codes
/// `AADSTS90094`, `AADSTS90095` and `AADSTS65001`); it is never shown.
fn not_completed(
    provider: UpstreamProvider,
    error: &str,
    description: Option<&str>,
) -> (&'static str, String) {
    let name = provider.display_name();
    let microsoft = provider == UpstreamProvider::Microsoft;
    let names = |code: &str| microsoft && description.is_some_and(|text| text.contains(code));
    if names("AADSTS90095") {
        return (
            "Your organization has to approve postkeep",
            format!(
                "Your organization reviews apps like postkeep before people can connect them. If Microsoft offered to send a request, a reviewer will decide, and Microsoft tells you the outcome. Nothing was connected. The approval is explained in the admin-consent guide: {ADMIN_CONSENT_GUIDE}"
            ),
        );
    }
    if names("AADSTS90094") || names("AADSTS65001") || (microsoft && error == "consent_required") {
        return (
            "Your organization has to approve postkeep",
            format!(
                "An administrator of your organization has to approve postkeep before you can connect this account, often because the app's publisher isn't verified. Nothing was connected. Send your administrator the admin-consent guide: {ADMIN_CONSENT_GUIDE}"
            ),
        );
    }
    let detail = if error == "access_denied" && microsoft {
        format!(
            "You cancelled the sign-in or didn't allow access at {name}. Nothing was connected. Go back and try again, or use another way to sign in. If {name} said that an administrator has to approve the app, see the admin-consent guide: {ADMIN_CONSENT_GUIDE}"
        )
    } else if error == "access_denied" {
        format!(
            "You cancelled the sign-in or didn't allow access at {name}. Nothing was connected. Go back and try again, or use another way to sign in."
        )
    } else {
        format!("{name} didn't complete the sign-in. Nothing was connected. Go back and try again.")
    };
    ("Sign-in not completed", detail)
}

/// The page Microsoft's admin consent endpoint returns the administrator
/// to. Its answer has no `state` to check, so it shows only what Microsoft
/// reported and changes nothing.
fn admin_consent_answered(approved: bool) -> Response {
    if approved {
        pages::message(
            StatusCode::OK,
            "Approved at Microsoft",
            "Microsoft recorded the approval for your organization. People in it can now sign in with Microsoft; nothing else is needed here.",
        )
    } else {
        pages::message(
            StatusCode::BAD_REQUEST,
            "Not approved",
            &format!(
                "Microsoft didn't record an approval. To approve postkeep for your organization, follow the admin-consent guide: {ADMIN_CONSENT_GUIDE}"
            ),
        )
    }
}

/// Ends a check with the page to show.
///
/// Boxed so the [`Response`] stays within the `result_large_err` size limit.
fn halt<T>(response: Response, clear_cookie: bool) -> Result<T, Box<Halt>> {
    Err(Box::new(Halt {
        response,
        clear_cookie,
    }))
}

fn sign_in_failed(provider: UpstreamProvider, err: &OAuthError) -> Response {
    tracing::warn!(%provider, error = %err, "upstream sign-in failed");
    let detail = match err {
        OAuthError::NoMailbox(_) => format!(
            "This {} account has no mailbox postkeep can reach. Work and school accounts need an Exchange Online mailbox; sign in with the account you read your mail with.",
            provider.display_name()
        ),
        OAuthError::MissingScopes(_) => format!(
            "postkeep needs permission to read, organize and send your mail. Sign in with {} again and leave every permission ticked.",
            provider.display_name()
        ),
        _ => format!(
            "{} sign-in didn't work. Nothing was connected. Go back and try again in a moment.",
            provider.display_name()
        ),
    };
    pages::message(
        StatusCode::BAD_GATEWAY,
        "Couldn't finish signing in",
        &detail,
    )
}

/// What [`revoke_before_delete`] did.
#[derive(Default)]
pub struct Revoked {
    /// The refresh token that it revoked, or tried to.
    refresh_token: Option<SecretString>,
    /// Whether Google confirmed that postkeep's access is revoked.
    confirmed: bool,
}

/// Revokes the upstream grant of an OAuth account before it is deleted.
/// Best effort: a failure is logged and the account is deleted anyway.
///
/// Returns the refresh token, and whether Google confirmed that postkeep's
/// access is revoked. Microsoft has no revoke endpoint, so that call does
/// not count as confirmed, and a skipped or failed Google call is not
/// confirmed either.
pub async fn revoke_before_delete(state: &AuthState, account: &postkeep_store::Account) -> Revoked {
    let Some(provider) = UpstreamProvider::for_mail_provider(account.provider) else {
        return Revoked::default();
    };
    let Some(client) = state.upstream() else {
        return Revoked::default();
    };
    let tokens = match state.store().upstream_tokens(&account.id).await {
        Ok(Some(stored)) => stored.tokens,
        Ok(None) => return Revoked::default(),
        Err(err) => {
            tracing::warn!(error = %err, "could not load upstream tokens to revoke");
            return Revoked::default();
        }
    };
    Revoked {
        confirmed: revoke_token(client, provider, &tokens.refresh_token).await,
        refresh_token: Some(tokens.refresh_token),
    }
}

/// Revokes the refresh token that the account's deletion removed, when it is
/// not the one that [`revoke_before_delete`] revoked: a reconnect stored it
/// in between. Returns whether Google confirmed every revocation.
pub async fn revoke_after_delete(
    state: &AuthState,
    account: &postkeep_store::Account,
    before: &Revoked,
    removed: Option<RemovedRefreshToken>,
) -> bool {
    let provider = UpstreamProvider::for_mail_provider(account.provider);
    let (Some(removed), Some(client), Some(UpstreamProvider::Google)) =
        (removed, state.upstream(), provider)
    else {
        // Nothing removed, or Microsoft, which has no revocation.
        return before.confirmed;
    };
    let token = match state.store().open_removed_refresh_token(&removed).await {
        Ok(token) => token,
        Err(err) => {
            tracing::warn!(error = %err, "could not read the removed upstream token to revoke");
            return false;
        }
    };
    if let Some(old) = &before.refresh_token
        && old.expose_secret() == token.expose_secret()
    {
        return before.confirmed;
    }
    // Revoked also when the old grant's revocation failed.
    let confirmed = revoke_token(client, UpstreamProvider::Google, &token).await;
    confirmed && before.confirmed
}

/// Revokes `token` at `provider`. Returns whether Google confirmed it.
async fn revoke_token(
    client: &OAuthClient,
    provider: UpstreamProvider,
    token: &SecretString,
) -> bool {
    match client.revoke(provider, token).await {
        Ok(()) => provider == UpstreamProvider::Google,
        Err(err) => {
            tracing::warn!(%provider, error = %err, "could not revoke the upstream grant");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_hashes_are_domain_separated() {
        assert_ne!(binding_hash("a"), binding_hash("b"));
        assert_eq!(binding_hash("a"), binding_hash("a"));
        assert_eq!(binding_hash("a").len(), 43);
    }

    #[test]
    fn start_paths() {
        assert_eq!(
            start_path(UpstreamProvider::Microsoft),
            "/oauth/microsoft/start"
        );
        assert_eq!(start_path(UpstreamProvider::Google), "/oauth/google/start");
    }
}
