//! The account page: a signed-in user can see their connection, disconnect
//! every app, delete their data, or replace the stored app-specific password
//! by signing in with a new one. Replacing that password signs out every
//! other account-page session. Signing in with the same password does not.
//!
//! Sessions are random tokens in an `HttpOnly`, `SameSite=Lax` cookie
//! (`__Host-` prefixed and `Secure` when the public URL is HTTPS); only
//! their hash is stored. Every form carries a CSRF token derived from the
//! session, and every `POST` must come from the server's own origin.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, extract::rejection::FormRejection};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep_store::{Account, Provider};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::account_view::{ClientView, ProviderView};
use crate::authorize::{CONNECTED_ANOTHER_WAY, SignInError, check_credentials, store_imap_account};
use crate::client_ip::ClientIp;
use crate::error::no_store;
use crate::pages::{
    self, AccountPage, AccountSignInPage, MailChoices, MessageKind, MessagePage, Notice,
};
use crate::random;
use crate::state::AuthState;
use crate::webhook::{self, TestResult, WebhookView};

/// Where the account page is served.
pub const ACCOUNT_PATH: &str = "/account";

/// The session cookie over HTTPS. `__Host-` pins it to this origin and path.
const SECURE_COOKIE: &str = "__Host-postkeep_session";
/// The session cookie on a plain-HTTP local server.
const PLAIN_COOKIE: &str = "postkeep_session";

/// The longest accepted email or confirmation value.
const MAX_FIELD_LEN: usize = 320;

fn cookie_name(state: &AuthState) -> &'static str {
    if state.config().is_https() {
        SECURE_COOKIE
    } else {
        PLAIN_COOKIE
    }
}

/// The session token from the request's cookies, if any.
fn session_token(state: &AuthState, headers: &HeaderMap) -> Option<String> {
    let name = cookie_name(state);
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

fn set_cookie(state: &AuthState, token: &str) -> HeaderValue {
    let secure = if state.config().is_https() {
        "; Secure"
    } else {
        ""
    };
    let max_age = state.config().session_ttl.absolute.as_secs();
    let value = format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}",
        cookie_name(state)
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn clear_cookie(state: &AuthState) -> HeaderValue {
    let secure = if state.config().is_https() {
        "; Secure"
    } else {
        ""
    };
    let value = format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}",
        cookie_name(state)
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| HeaderValue::from_static(""))
}

/// The CSRF token for a session: a hash of the session token, so it needs
/// no storage and can't be computed without the (`HttpOnly`) cookie.
pub fn csrf_token(session_token: &str) -> String {
    let digest = Sha256::new()
        .chain_update(b"postkeep/csrf/v1/")
        .chain_update(session_token.as_bytes())
        .finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

/// Whether a state-changing request comes from this server's own pages:
/// its `Origin` (or, failing that, `Referer`) must be the issuer.
pub fn same_origin(state: &AuthState, headers: &HeaderMap) -> bool {
    let issuer = state.config().issuer();
    if let Some(origin) = headers.get(header::ORIGIN) {
        return origin.to_str().is_ok_and(|origin| origin == issuer);
    }
    headers
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|referer| {
            referer
                .strip_prefix(issuer)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
}

/// A signed-in request.
pub struct Session {
    pub token: String,
    pub account: Account,
}

/// Why a request can't go ahead.
#[derive(Debug, Clone, Copy)]
pub enum Rejection {
    /// Wrong origin or CSRF token.
    Forbidden,
    /// No live session: back to the sign-in form.
    SignedOut,
    /// The store failed.
    Storage,
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        match self {
            Self::Forbidden => forbidden(),
            Self::SignedOut => see_other(ACCOUNT_PATH),
            Self::Storage => pages::server_error(),
        }
    }
}

async fn current_session(
    state: &AuthState,
    headers: &HeaderMap,
) -> Result<Option<Session>, Rejection> {
    let Some(token) = session_token(state, headers) else {
        return Ok(None);
    };
    match state
        .store()
        .session(&token, state.config().session_ttl)
        .await
    {
        Ok(Some(account)) if state.config().email_allowed(&account.email) => {
            Ok(Some(Session { token, account }))
        }
        Ok(_) => Ok(None),
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            Err(Rejection::Storage)
        }
    }
}

/// Checks origin, session and CSRF token for a form post. On failure,
/// returns the response to send instead.
pub async fn authorize_post(
    state: &AuthState,
    headers: &HeaderMap,
    csrf: &str,
) -> Result<Session, Rejection> {
    if !same_origin(state, headers) {
        return Err(Rejection::Forbidden);
    }
    let Some(session) = current_session(state, headers).await? else {
        return Err(Rejection::SignedOut);
    };
    let expected = csrf_token(&session.token);
    if !postkeep_store::constant_time_eq(expected.as_bytes(), csrf.as_bytes()) {
        return Err(Rejection::Forbidden);
    }
    Ok(session)
}

pub fn forbidden() -> Response {
    pages::message(
        StatusCode::FORBIDDEN,
        "This form has expired",
        "Reload the account page and try again.",
    )
}

pub fn see_other(location: &str) -> Response {
    (no_store(), Redirect::to(location)).into_response()
}

#[derive(Deserialize)]
pub struct NoticeQuery {
    notice: Option<String>,
    /// Preset id when the address's domain replaced the picked provider.
    #[serde(default, rename = "override")]
    provider_override: Option<String>,
}

/// `GET /account`
pub async fn show(
    State(state): State<AuthState>,
    headers: HeaderMap,
    Query(query): Query<NoticeQuery>,
) -> Response {
    let session = match current_session(&state, &headers).await {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };
    let Some(session) = session else {
        return sign_in_page(&state, StatusCode::OK, "", "", None, None, None);
    };
    let key = query.notice.as_deref().unwrap_or_default();
    // Filter notices show inside the Filter rules block, the redirect's target.
    let (notice, filter_notice) = if key.starts_with("filter") {
        (None, Notice::from_key(key))
    } else {
        (Notice::from_key(key), None)
    };
    render_account(
        &state,
        &session,
        PageExtras {
            notice,
            filter_notice,
            show_test_result: matches!(key, "webhook-test-sent" | "webhook-test-failed"),
            provider_override: if key == "signed-in" {
                query.provider_override.as_deref()
            } else {
                None
            },
            ..PageExtras::default()
        },
    )
    .await
}

/// What a particular rendering of the account page adds to the stored
/// state.
#[derive(Default)]
pub struct PageExtras<'a> {
    /// The alert at the top.
    pub notice: Option<Notice>,
    /// The result line of the Filter rules block.
    pub filter_notice: Option<Notice>,
    /// The alerts section to show instead of the stored settings (a form
    /// with validation errors).
    pub webhook: Option<WebhookView>,
    /// Show the result of the last test event.
    pub show_test_result: bool,
    /// Reopen the password form with this error.
    pub password_error: Option<&'a str>,
    /// Preset id from `?override=` on a signed-in redirect.
    pub provider_override: Option<&'a str>,
}

/// Renders the account page for a session.
pub async fn render_account(
    state: &AuthState,
    session: &Session,
    extras: PageExtras<'_>,
) -> Response {
    match account_page(state, session, extras).await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            pages::server_error()
        }
    }
}

async fn account_page(
    state: &AuthState,
    session: &Session,
    extras: PageExtras<'_>,
) -> Result<Response, postkeep_store::StoreError> {
    let store = state.store();
    let id = &session.account.id;
    let Some(overview) = store.account_overview(id).await? else {
        return Ok(see_other(ACCOUNT_PATH));
    };
    let now = postkeep_store::now();
    let clients: Vec<ClientView> = store
        .account_clients(id)
        .await?
        .iter()
        .map(|client| ClientView::new(client, now))
        .collect();
    let mut webhook = match extras.webhook {
        Some(view) => Some(view),
        None => webhook::load_view(state, id).await?,
    };
    if let Some(view) = webhook.as_mut() {
        view.filter_notice = extras.filter_notice;
    }
    if extras.show_test_result
        && let Some(view) = webhook.as_mut()
    {
        view.test_result = TestResult::latest(&store.recent_deliveries(id).await?);
    }
    let provider = ProviderView::new(&overview.account, &state.config().imap_servers);
    // An OAuth account whose grant the provider rejected needs a new sign-in.
    let mut notice = extras.notice;
    if notice.is_none() && overview.account.provider.is_oauth() {
        let rejected = store
            .upstream_tokens(id)
            .await?
            .is_some_and(|stored| stored.invalid_reason.is_some());
        if rejected {
            notice = Notice::from_key(match overview.account.provider {
                Provider::Gmail => "reauth-google",
                _ => "reauth-microsoft",
            });
        }
    }
    let connected_at = pages::format_date(overview.created_at);
    let override_hint = override_hint_for(&overview.account, extras.provider_override);
    let password_rejected = store.password_rejected_at(id).await?.is_some();
    Ok(pages::render(
        StatusCode::OK,
        &AccountPage {
            email: &overview.account.email,
            connected_at: &connected_at,
            connected_at_iso: &pages::format_rfc3339(overview.created_at),
            csrf_token: &csrf_token(&session.token),
            notice,
            provider: &provider,
            clients: &clients,
            mcp_url: &state.config().resource(),
            webhook,
            password_error: extras.password_error,
            password_rejected,
            override_hint,
        },
    ))
}

/// The signed-in hint when `picked` is the preset this account actually
/// uses and the address is at that preset's domain. Anything else, including
/// a query value that is not a preset id, shows nothing.
fn override_hint_for(account: &Account, picked: Option<&str>) -> Option<&'static str> {
    let preset = postkeep_mail::ImapPreset::parse(picked?)?;
    if account.provider != Provider::Imap || account.imap_server.as_deref() != Some(preset.id()) {
        return None;
    }
    if !preset.owns_address(&account.email) {
        return None;
    }
    Some(pages::domain_override_hint(preset))
}

fn sign_in_page(
    state: &AuthState,
    status: StatusCode,
    email: &str,
    imap_server: &str,
    error: Option<&str>,
    email_error: Option<&str>,
    password_error: Option<&str>,
) -> Response {
    pages::render(
        status,
        &AccountSignInPage {
            oauth: &crate::upstream::buttons(state, None),
            email,
            error,
            email_error,
            password_error,
            mail: &MailChoices::new(&state.config().imap_servers, imap_server, email),
        },
    )
}

#[derive(Deserialize)]
pub struct SignInForm {
    #[serde(default)]
    email: String,
    password: Option<SecretString>,
    #[serde(default)]
    imap_server: String,
}

/// The server to check a sign-in against: the one chosen on the form, or
/// for "detect", the server of an existing account with that address.
async fn server_selection(
    state: &AuthState,
    email: &str,
    chosen: &str,
) -> Result<String, postkeep_store::StoreError> {
    let chosen = chosen.trim();
    if !chosen.is_empty() && chosen != "auto" {
        return Ok(chosen.to_owned());
    }
    let account = state
        .store()
        .account_by_email(email, postkeep_store::Provider::Imap)
        .await?;
    Ok(account
        .and_then(|account| {
            state
                .config()
                .imap_servers
                .resolve(account.imap_server.as_deref())
        })
        .map(|server| server.id.id().to_owned())
        .unwrap_or_default())
}

/// `POST /account/sign-in`: checks the credentials like the OAuth sign-in
/// (same backoff and allowlist), stores the password, and starts a session.
///
/// When that replaces a different stored password, every other account-page
/// session for the account is ended first. This browser keeps the new
/// session. The same password, and a brand-new account, leave sessions alone.
pub async fn sign_in(
    State(state): State<AuthState>,
    ip: ClientIp,
    headers: HeaderMap,
    form: Result<Form<SignInForm>, FormRejection>,
) -> Response {
    if !same_origin(&state, &headers) {
        return forbidden();
    }
    let Ok(Form(form)) = form else {
        return sign_in_page(
            &state,
            StatusCode::BAD_REQUEST,
            "",
            "",
            Some("The form was incomplete. Try again."),
            None,
            None,
        );
    };
    let email: String = form
        .email
        .trim()
        .to_lowercase()
        .chars()
        .take(MAX_FIELD_LEN)
        .collect();
    let selection = match server_selection(&state, &email, &form.imap_server).await {
        Ok(selection) => selection,
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return pages::server_error();
        }
    };
    let raw_password = form
        .password
        .as_ref()
        .map_or("", |password| password.expose_secret());
    let retry = |problem: &SignInError| match problem {
        SignInError::Fields {
            email: email_error,
            password: password_error,
        } => sign_in_page(
            &state,
            StatusCode::BAD_REQUEST,
            &email,
            &form.imap_server,
            None,
            *email_error,
            *password_error,
        ),
        SignInError::Form(message) => sign_in_page(
            &state,
            StatusCode::BAD_REQUEST,
            &email,
            &form.imap_server,
            Some(message),
            None,
            None,
        ),
    };
    let (server, password) =
        match check_credentials(&state, ip, &selection, &email, raw_password).await {
            Ok(checked) => checked,
            Err(problem) => return retry(&problem),
        };
    let stored = match store_imap_account(&state, &email, &password, &server, &retry).await {
        Ok(stored) => stored,
        Err(page) => return *page,
    };
    if stored.password_changed {
        tracing::info!(
            account_id = %stored.account.id,
            "replaced the stored password; ended other account-page sessions"
        );
    }
    let account = stored.account;
    state.notify_account_changed(&account.id);
    let override_id = state
        .config()
        .imap_servers
        .domain_override(&selection, &email)
        .map(postkeep_mail::ImapPreset::id);
    crate::authorize::log_sign_in_accepted(&state, &account.id, server.id.id(), &selection, &email);
    open_account_session(&state, &account.id, override_id)
        .await
        .unwrap_or_else(pages::account_deleted)
}

/// Starts an account page session for `account` and redirects to the page.
/// `None` if the account was deleted in the meantime.
pub async fn start_session(
    state: &AuthState,
    account: &postkeep_store::AccountId,
) -> Option<Response> {
    open_account_session(state, account, None).await
}

/// Starts the session. `provider_override` is a preset id when the address's
/// domain replaced the pick, and is only used as a notice key. `None` if the
/// account was deleted in the meantime: no session is stored.
async fn open_account_session(
    state: &AuthState,
    account: &postkeep_store::AccountId,
    provider_override: Option<&str>,
) -> Option<Response> {
    let Ok(token) = random::token() else {
        return Some(pages::server_error());
    };
    let ttl = state.config().session_ttl;
    match state.store().create_session(&token, account, ttl).await {
        Ok(()) => {}
        Err(postkeep_store::StoreError::AccountDeleted) => return None,
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return Some(pages::server_error());
        }
    }
    tracing::info!(account_id = %account, "account page sign-in");
    let location = provider_override.map_or_else(
        || format!("{ACCOUNT_PATH}?notice=signed-in"),
        |id| format!("{ACCOUNT_PATH}?notice=signed-in&override={id}"),
    );
    let mut response = see_other(&location);
    response
        .headers_mut()
        .insert(header::SET_COOKIE, set_cookie(state, &token));
    Some(response)
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf_token: String,
}

/// `POST /account/sign-out`
pub async fn sign_out(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<CsrfForm>, FormRejection>,
) -> Response {
    let csrf = form.map(|Form(form)| form.csrf_token).unwrap_or_default();
    let session = match authorize_post(&state, &headers, &csrf).await {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };
    if let Err(err) = state.store().delete_session(&session.token).await {
        tracing::error!(error = %err, "storage error");
        return pages::server_error();
    }
    let mut response = see_other(ACCOUNT_PATH);
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie(&state));
    response
}

#[derive(Deserialize)]
pub struct RevokeForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    confirm: String,
}

/// `POST /account/revoke`: disconnects every app.
pub async fn revoke(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<RevokeForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return forbidden();
    };
    let session = match authorize_post(&state, &headers, &form.csrf_token).await {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };
    if form.confirm != "yes" {
        return see_other(&format!("{ACCOUNT_PATH}?notice=confirm-revoke"));
    }
    match state
        .store()
        .revoke_account_grants(&session.account.id)
        .await
    {
        Ok(revoked) => {
            tracing::info!(account_id = %session.account.id, revoked, "revoked app access from the account page");
            see_other(&format!("{ACCOUNT_PATH}?notice=revoked"))
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            pages::server_error()
        }
    }
}

#[derive(Deserialize)]
pub struct RevokeClientForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    client_id: String,
}

/// `POST /account/clients/revoke`: disconnects one app from this account.
pub async fn revoke_client(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<RevokeClientForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return forbidden();
    };
    let session = match authorize_post(&state, &headers, &form.csrf_token).await {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };
    let client_id = form.client_id.trim();
    if client_id.is_empty() || client_id.len() > 128 {
        return see_other(&format!("{ACCOUNT_PATH}#apps"));
    }
    // Scoped to the session's account, so a forged client ID can at most
    // revoke this account's own grant to that app.
    match state
        .store()
        .revoke_client_grants(&session.account.id, client_id)
        .await
    {
        Ok(revoked) => {
            tracing::info!(account_id = %session.account.id, revoked, "revoked one app from the account page");
            see_other(&format!("{ACCOUNT_PATH}?notice=client-revoked#apps"))
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            pages::server_error()
        }
    }
}

#[derive(Deserialize)]
pub struct PasswordForm {
    #[serde(default)]
    csrf_token: String,
    password: Option<SecretString>,
}

/// `POST /account/password`: replaces the stored password of an IMAP
/// account after checking it with the account's server (same backoff and
/// allowlist as signing in). Every other account-page session for this
/// account is ended; this browser stays signed in. Connected apps keep
/// their tokens.
pub async fn update_password(
    State(state): State<AuthState>,
    ip: ClientIp,
    headers: HeaderMap,
    form: Result<Form<PasswordForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return forbidden();
    };
    let session = match authorize_post(&state, &headers, &form.csrf_token).await {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };
    let account = &session.account;
    if account.provider != Provider::Imap {
        return see_other(&format!("{ACCOUNT_PATH}#security"));
    }
    let failed = |message: &str| {
        let session = &session;
        let state = &state;
        let message = message.to_owned();
        async move {
            let mut response = render_account(
                state,
                session,
                PageExtras {
                    password_error: Some(&message),
                    ..PageExtras::default()
                },
            )
            .await;
            if response.status().is_success() {
                *response.status_mut() = StatusCode::BAD_REQUEST;
            }
            response
        }
    };
    let Some(server) = state
        .config()
        .imap_servers
        .resolve(account.imap_server.as_deref())
    else {
        return failed(
            "This account's mail server is no longer offered here. Sign out and connect again.",
        )
        .await;
    };
    let raw_password = form
        .password
        .as_ref()
        .map_or("", |password| password.expose_secret());
    let (server, password) =
        match check_credentials(&state, ip, server.id.id(), &account.email, raw_password).await {
            Ok(checked) => checked,
            Err(SignInError::Fields { password, email }) => {
                return failed(
                    password
                        .or(email)
                        .unwrap_or("Check the password and try again."),
                )
                .await;
            }
            Err(SignInError::Form(message)) => return failed(&message).await,
        };
    match state
        .store()
        .upsert_imap_account(&account.email, &password, Some(server.id.id()))
        .await
    {
        Ok(_) => {}
        Err(postkeep_store::StoreError::AccountConflict) => {
            return failed(CONNECTED_ANOTHER_WAY).await;
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return pages::server_error();
        }
    }
    // A stolen session cookie, or a browser still signed in with the old
    // password, must not keep the account page. This request's own session
    // stays so the person who changed the password is not signed out.
    if let Err(err) = state
        .store()
        .delete_other_sessions(&account.id, &session.token)
        .await
    {
        tracing::error!(error = %err, "storage error");
        return pages::server_error();
    }
    tracing::info!(account_id = %account.id, "password replaced from the account page");
    state.notify_account_changed(&account.id);
    see_other(&format!("{ACCOUNT_PATH}?notice=password-updated#security"))
}

/// Tells the account listeners about an account when dropped: after its
/// deletion worked or failed, and when the request is dropped while it
/// runs (the browser went away, or the request timed out). A deletion
/// listener may have stopped the account's watcher, and this starts it
/// again for an account that is still there.
struct NotifyOnDrop<'a>(&'a AuthState, &'a postkeep_store::AccountId);

impl Drop for NotifyOnDrop<'_> {
    fn drop(&mut self) {
        self.0.notify_account_changed(self.1);
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    confirm_email: String,
}

/// `POST /account/delete`: deletes the account and everything stored for
/// it.
pub async fn delete(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<DeleteForm>, FormRejection>,
) -> Response {
    let Ok(Form(form)) = form else {
        return forbidden();
    };
    let session = match authorize_post(&state, &headers, &form.csrf_token).await {
        Ok(session) => session,
        Err(rejection) => return rejection.into_response(),
    };
    if !form
        .confirm_email
        .trim()
        .eq_ignore_ascii_case(&session.account.email)
    {
        return see_other(&format!("{ACCOUNT_PATH}?notice=confirm-delete"));
    }
    let _changed = NotifyOnDrop(&state, &session.account.id);
    // First, while the tokens are stored: Gmail's users.stop needs the
    // grant that the revoke ends.
    state.before_account_deleted(&session.account.id).await;
    let revoked = crate::upstream::revoke_before_delete(&state, &session.account).await;
    let store = state.store();
    let removed = match store
        .delete_account_returning_refresh_token(&session.account.id)
        .await
    {
        Ok(removed) => removed,
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return pages::server_error();
        }
    };
    // A reconnect may have stored a new grant after the revocation read the
    // old one: the deletion removed it, and it is revoked too.
    let google_revoked =
        crate::upstream::revoke_after_delete(&state, &session.account, &revoked, removed).await;
    tracing::info!(account_id = %session.account.id, "account deleted from the account page");
    let mut response = pages::render(
        StatusCode::OK,
        &MessagePage {
            kind: MessageKind::Success,
            title: "Your data was deleted",
            message: match session.account.provider {
                Provider::Imap => {
                    "The stored app password, settings and every token for this account are gone. To cut off access completely, also delete the app password at your mail provider (for iCloud Mail, at account.apple.com)."
                }
                Provider::Graph => {
                    "The stored Microsoft sign-in, settings and every token for this account are gone. Microsoft doesn't let apps remove their own access, so to cut it off completely, remove postkeep at account.live.com/consent/Manage (personal accounts) or myapps.microsoft.com (work or school)."
                }
                Provider::Gmail if google_revoked => {
                    "The stored Google sign-in, settings and every token for this account are gone, and postkeep's access was revoked at Google."
                }
                Provider::Gmail => {
                    "The stored Google sign-in, settings and every token for this account are gone, but Google access could not be confirmed as revoked. To cut it off, remove postkeep at myaccount.google.com/permissions."
                }
            },
        },
    );
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_cookie(&state));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csrf_tokens_depend_on_the_session() {
        assert_eq!(csrf_token("a"), csrf_token("a"));
        assert_ne!(csrf_token("a"), csrf_token("b"));
        assert_eq!(csrf_token("a").len(), 43);
    }

    /// Locks the current derivation of one session token.
    #[test]
    fn csrf_token_for_a_fixed_session() {
        assert_eq!(
            csrf_token("session"),
            "QdILqfbZNf73M4p-Uh0PUKI-8iRwgHN5qQlLjWHRwL4"
        );
    }
}
