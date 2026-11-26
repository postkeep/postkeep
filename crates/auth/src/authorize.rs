//! The authorization endpoint and sign-in page.

use axum::extract::rejection::{FormRejection, QueryRejection};
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Extension, Form};
use postkeep_mail::ImapServer;
use postkeep_store::{
    AccountId, AuthorizationRequest, Client, CodeGrant, GrantSubject, Provider, StoreError,
    UpsertedImapAccount,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::RouterOptions;
use crate::account;
use crate::client_ip::ClientIp;
use crate::client_metadata::{self, MetadataError};
use crate::error::no_store;
use crate::limits::describe_wait;
use crate::pages::{self, MailChoices, OAuthButtons, SignInPage};
use crate::sign_in::SignInRequest;
use crate::state::AuthState;
use crate::verifier::VerifyError;
use crate::{SCOPE, random, redirect, usage};

const MAX_STATE_LEN: usize = 2048;
const MAX_EMAIL_LEN: usize = 254;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    resource: Option<String>,
}

/// `GET /authorize`: validates the request and shows the sign-in page, or
/// hands the request to the sign-in hook if it handles the resource.
pub async fn show(
    State(state): State<AuthState>,
    Extension(options): Extension<RouterOptions>,
    ip: ClientIp,
    headers: HeaderMap,
    query: Result<Query<AuthorizeQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(query)) = query else {
        return invalid_link("The authorization request is malformed.");
    };
    let Some(client_id) = query.client_id.as_deref() else {
        return invalid_link("The authorization request has no client_id.");
    };
    let from_document = client_metadata::is_document_url(client_id);
    let client = match find_client(&state, client_id, &ip.key()).await {
        Ok(client) => client,
        Err(page) => return *page,
    };
    // A metadata document client's redirect URI must match exactly
    // (draft-ietf-oauth-client-id-metadata-document section 4.2), without
    // the loopback port leeway that registered native clients get.
    let registered = |uri: &str| {
        if from_document {
            client
                .redirect_uris
                .iter()
                .any(|registered| registered == uri)
        } else {
            redirect::matches(&client.redirect_uris, uri)
        }
    };
    let redirect_uri = match query.redirect_uri.clone() {
        Some(uri) if registered(&uri) => uri,
        Some(_) => {
            return invalid_link("The redirect address does not match the app's registration.");
        }
        None => match client.redirect_uris.as_slice() {
            [only] => only.clone(),
            _ => return invalid_link("The authorization request has no redirect_uri."),
        },
    };
    // Checked again here, so registrations stored before a validation rule
    // existed cannot use a URI that rule now refuses.
    if redirect::validate(&redirect_uri).is_err() {
        return invalid_link("The app's redirect address is not allowed.");
    }

    // From here on, errors go back to the client (RFC 6749 section 4.1.2.1)
    // when that cannot be abused as an open redirect; see `request_error`.
    let client_state = query.state.as_deref();
    let back = |code: &str, description: &str| {
        request_error(&state, &redirect_uri, code, description, client_state)
    };
    if query.response_type.as_deref() != Some("code") {
        return back(
            "unsupported_response_type",
            "only response_type=code is supported",
        );
    }
    if client_state.is_some_and(|value| value.len() > MAX_STATE_LEN) {
        return back("invalid_request", "state is too long");
    }
    let Some(challenge) = query.code_challenge.as_deref() else {
        return back("invalid_request", "PKCE is required: send code_challenge");
    };
    if query.code_challenge_method.as_deref() != Some("S256") {
        return back("invalid_request", "code_challenge_method must be S256");
    }
    if !random::valid_challenge(challenge) {
        return back("invalid_request", "code_challenge is malformed");
    }
    match query.resource.as_deref() {
        None if state.config().per_request_resources => {
            return back("invalid_target", "the resource parameter is required");
        }
        Some(resource) if !state.config().accepts_resource(resource) => {
            return back(
                "invalid_target",
                "the resource parameter does not name this server",
            );
        }
        _ => {}
    }

    let Ok(request_id) = random::token() else {
        return pages::server_error();
    };
    let request = AuthorizationRequest {
        client_id: client.id.clone(),
        redirect_uri: redirect_uri.clone(),
        state: query.state.clone(),
        code_challenge: challenge.to_owned(),
        scope: SCOPE.to_owned(),
        resource: query.resource.clone(),
    };
    if let Err(err) = state
        .store()
        .save_authorization_request(&request_id, &request, state.config().sign_in_ttl)
        .await
    {
        tracing::error!(error = %err, "storage error");
        return pages::server_error();
    }
    begin_sign_in(&state, options, &headers, &client, &request, &request_id).await
}

/// Hands a stored request to the sign-in hook if it handles the resource;
/// otherwise shows the sign-in page.
async fn begin_sign_in(
    state: &AuthState,
    options: RouterOptions,
    headers: &HeaderMap,
    client: &Client,
    request: &AuthorizationRequest,
    request_id: &str,
) -> Response {
    if let Some(hook) = state.sign_in_hook_for(request) {
        let started = SignInRequest {
            id: request_id,
            request,
            client,
            headers,
        };
        return (no_store(), hook.start(state, started).await).into_response();
    }
    sign_in_page(
        state,
        options,
        client,
        request,
        request_id,
        &SignInValues::default(),
        None,
    )
}

/// The registered client, or the one a metadata document URL describes;
/// otherwise the error page to show.
async fn find_client(
    state: &AuthState,
    client_id: &str,
    client_key: &str,
) -> Result<Client, Box<Response>> {
    if client_metadata::is_document_url(client_id) {
        return match state.metadata_client(client_id, client_key).await {
            Ok(client) => Ok(client),
            Err(MetadataError::Store(err)) => {
                tracing::error!(error = %err, "storage error");
                Err(Box::new(pages::server_error()))
            }
            Err(err) => {
                tracing::info!(error = %err, "refused a client metadata document");
                let host = crate::account_view::display_host(client_id);
                Err(Box::new(invalid_link(&format!(
                    "The app asking for access ({host}) can't be used: {err}."
                ))))
            }
        };
    }
    match state.store().client(client_id).await {
        Ok(Some(client)) => Ok(client),
        Ok(None) => Err(Box::new(invalid_link(
            "The app asking for access is not registered with this server.",
        ))),
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            Err(Box::new(pages::server_error()))
        }
    }
}

#[derive(Deserialize)]
pub struct SignInForm {
    request_id: String,
    #[serde(default)]
    email: String,
    password: Option<SecretString>,
    #[serde(default)]
    imap_server: String,
    #[serde(default)]
    action: String,
}

/// `POST /authorize`: checks the credentials and redirects back with a code.
///
/// Every action needs a same-origin `Origin` or `Referer`. The sign-in page
/// sends `Referrer-Policy: same-origin`, so a real form post passes. A
/// cross-site post gets the forbidden page and is never redirected:
/// cancelling would otherwise send the browser to a registered client's web
/// redirect URI (RFC 9700 section 4.11.1), and a credential post would be
/// login CSRF into an attacker-chosen request.
pub async fn submit(
    State(state): State<AuthState>,
    Extension(options): Extension<RouterOptions>,
    ip: ClientIp,
    headers: HeaderMap,
    form: Result<Form<SignInForm>, FormRejection>,
) -> Response {
    if !account::same_origin(&state, &headers) {
        return account::forbidden();
    }
    let Ok(Form(form)) = form else {
        return invalid_link("The sign-in form was incomplete.");
    };
    let store = state.store();
    let request = match mailbox_request(&state, &form.request_id).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            return pages::message(
                StatusCode::BAD_REQUEST,
                "This sign-in page has expired",
                "Go back to your app and start connecting again.",
            );
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return pages::server_error();
        }
    };

    if form.action == "cancel" {
        if let Err(err) = store.delete_authorization_request(&form.request_id).await {
            tracing::error!(error = %err, "storage error");
        }
        return error_redirect(
            &state,
            &request.redirect_uri,
            "access_denied",
            "the user cancelled the sign-in",
            request.state.as_deref(),
        );
    }

    let client = match store.client(&request.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return invalid_link("The app asking for access is no longer registered."),
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return pages::server_error();
        }
    };
    let email = form.email.trim().to_lowercase();
    let values = SignInValues {
        email: email.clone(),
        imap_server: form.imap_server.clone(),
    };
    let retry = |problem: &SignInError| {
        sign_in_page(
            &state,
            options,
            &client,
            &request,
            &form.request_id,
            &values,
            Some(problem),
        )
    };

    let raw_password = form
        .password
        .as_ref()
        .map_or("", |password| password.expose_secret());
    let (server, password) =
        match check_credentials(&state, ip, &form.imap_server, &email, raw_password).await {
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
            "replaced the stored password; ended account-page sessions"
        );
    }
    let account = stored.account;
    // The stored password may have changed: let watchers reconnect.
    state.notify_account_changed(&account.id);
    log_sign_in_accepted(
        &state,
        &account.id,
        server.id.id(),
        &form.imap_server,
        &email,
    );
    complete(&state, &request, &form.request_id, &client, &account.id)
        .await
        .unwrap_or_else(pages::account_deleted)
}

/// Logs a successful IMAP sign-in: which server was used, and whether the
/// address's domain replaced `selection`. The address is not included.
pub fn log_sign_in_accepted(
    state: &AuthState,
    account: &AccountId,
    server_id: &str,
    selection: &str,
    email: &str,
) {
    tracing::info!(
        account_id = %account,
        server = server_id,
        overridden = state
            .config()
            .imap_servers
            .domain_override(selection, email)
            .is_some(),
        "sign-in accepted"
    );
}

/// Finishes the pending authorization request `request_id` for
/// `account_id`, after a sign-in with Microsoft or Google. `None` if the
/// account was deleted in the meantime.
pub async fn complete_by_id(
    state: &AuthState,
    request_id: &str,
    account_id: &AccountId,
) -> Option<Response> {
    let store = state.store();
    let request = match mailbox_request(state, request_id).await {
        Ok(Some(request)) => request,
        Ok(None) => {
            return Some(pages::message(
                StatusCode::BAD_REQUEST,
                "This sign-in page has expired",
                "Your mailbox is connected, but the app's request timed out. Go back to your app and connect again.",
            ));
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return Some(pages::server_error());
        }
    };
    let client = match store.client(&request.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => {
            return Some(invalid_link(
                "The app asking for access is no longer registered.",
            ));
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return Some(pages::server_error());
        }
    };
    complete(state, &request, request_id, &client, account_id).await
}

/// The pending request `id` for the mailbox sign-in: `None` if it expired,
/// was finished, or belongs to the sign-in hook.
pub async fn mailbox_request(
    state: &AuthState,
    id: &str,
) -> Result<Option<AuthorizationRequest>, StoreError> {
    let request = state.store().authorization_request(id).await?;
    Ok(request.filter(|request| !state.hook_handles(request)))
}

/// Finishes an authorization for `account_id`: issues a code and redirects
/// back to the client. `None` if the account was deleted in the meantime.
async fn complete(
    state: &AuthState,
    request: &AuthorizationRequest,
    request_id: &str,
    client: &Client,
    account_id: &AccountId,
) -> Option<Response> {
    let subject = GrantSubject::Account(account_id.clone());
    match issue_code(state, request, request_id, subject).await {
        Ok(response) => {
            tracing::info!(account_id = %account_id, client_id = %client.id, "account connected");
            Some(response)
        }
        Err(StoreError::AccountDeleted) => None,
        Err(err) => {
            tracing::error!(error = %err, "could not issue an authorization code");
            Some(pages::server_error())
        }
    }
}

/// Issues an authorization code for `subject`, ends the pending request
/// and returns the redirect back to the client.
pub async fn issue_code(
    state: &AuthState,
    request: &AuthorizationRequest,
    request_id: &str,
    subject: GrantSubject,
) -> Result<Response, StoreError> {
    let code = random::token().map_err(|_| StoreError::Random)?;
    let mut params = vec![("code", code.as_str())];
    if let Some(client_state) = request.state.as_deref() {
        params.push(("state", client_state));
    }
    params.push(("iss", state.config().issuer()));
    let url = redirect::with_params(&request.redirect_uri, &params)
        .ok_or(StoreError::InvalidInput("the redirect URI is not a URL"))?;
    let grant = CodeGrant {
        client_id: request.client_id.clone(),
        subject,
        redirect_uri: request.redirect_uri.clone(),
        code_challenge: request.code_challenge.clone(),
        scope: request.scope.clone(),
        resource: request.resource.clone(),
    };
    state
        .store()
        .save_code(&code, &grant, state.config().code_ttl)
        .await?;
    if let Err(err) = state.store().delete_authorization_request(request_id).await {
        tracing::warn!(error = %err, "could not delete the pending authorization request");
    }
    Ok((no_store(), Redirect::to(&url)).into_response())
}

/// Why a sign-in attempt was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInError {
    /// One or both fields are badly formed; shown next to the fields.
    Fields {
        email: Option<&'static str>,
        password: Option<&'static str>,
    },
    /// Shown as an alert above the form.
    Form(String),
}

impl SignInError {
    pub fn form(message: &str) -> Self {
        Self::Form(message.to_owned())
    }
}

/// Shown when an address already belongs to an account created another
/// way (for example with "Continue with Microsoft").
pub const CONNECTED_ANOTHER_WAY: &str = "This address is already connected another way, for example with Microsoft or Google. Sign in that way instead, or delete the existing connection on the account page first.";

/// Whether `email` looks like a full address: something before the `@` and
/// a dotted domain after it.
fn well_formed_email(email: &str) -> bool {
    email.len() <= MAX_EMAIL_LEN
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !domain.contains("..")
        })
}

/// Validates the input, picks the IMAP server (`selection` is a server
/// identifier, or empty or `auto` to detect it from the address) and checks
/// the credentials with the verifier. Returns the server and the password
/// as it should be stored, or what to show the user on failure.
///
/// Failed attempts back off exponentially per client IP (up to
/// [`AuthConfig::ip_backoff_max`](crate::AuthConfig::ip_backoff_max)) and per
/// address (up to the much shorter
/// [`AuthConfig::account_backoff_max`](crate::AuthConfig::account_backoff_max)),
/// so a guesser is slowed down hard while the real owner, signing in from
/// another address, waits at most a minute.
pub async fn check_credentials(
    state: &AuthState,
    ip: ClientIp,
    selection: &str,
    email: &str,
    raw_password: &str,
) -> Result<(ImapServer, SecretString), SignInError> {
    let email_error = (!well_formed_email(email))
        .then_some("Enter your full email address, for example alice@example.com.");
    // Dashes and spaces alone are an empty app password.
    let password_error = raw_password
        .chars()
        .all(|c| c.is_whitespace() || c == '-')
        .then_some("Paste your app password.");
    if email_error.is_some() || password_error.is_some() {
        return Err(SignInError::Fields {
            email: email_error,
            password: password_error,
        });
    }
    let Some(server) = state.config().imap_servers.choose(selection, email) else {
        return Err(SignInError::form(
            "Choose one of the listed mail providers and try again.",
        ));
    };
    let password = server.normalize_password(raw_password);
    if !state.config().email_allowed(email) {
        return Err(SignInError::form(
            "This server isn't set up for that address. Ask the person who runs it to allow it.",
        ));
    }
    let limits = state.limits();
    let ip_key = ip.key();
    let wait = [
        limits.sign_in_ip.retry_after(&ip_key),
        limits.sign_in_account.retry_after(email),
    ]
    .into_iter()
    .flatten()
    .max();
    if let Some(wait) = wait {
        return Err(SignInError::Form(format!(
            "Too many failed attempts. Wait {} and try again.",
            describe_wait(wait)
        )));
    }
    match state.verifier().verify(&server, email, &password).await {
        Ok(()) => {
            // The IP's record is kept: signing in to one's own account must
            // not reset the backoff for guessing at others.
            limits.sign_in_account.record_success(email);
            Ok((server, password))
        }
        Err(VerifyError::Rejected) => {
            limits.sign_in_ip.record_failure(&ip_key);
            limits.sign_in_account.record_failure(email);
            tracing::info!(
                client = %ip_key,
                server = server.id.id(),
                overridden = state
                    .config()
                    .imap_servers
                    .domain_override(selection, email)
                    .is_some(),
                "sign-in rejected"
            );
            Err(SignInError::Form(format!(
                "{} didn't accept that address and password. Check that you pasted an app password, not your regular password, and that the right provider is selected.",
                server.name
            )))
        }
        Err(VerifyError::InvalidInput(_)) => Err(SignInError::form(
            "Check the address and password and try again.",
        )),
        Err(err) => {
            tracing::warn!(error = %err, server = server.id.id(), "could not verify credentials");
            Err(SignInError::Form(format!(
                "Couldn't reach {} just now. Wait a moment and try again.",
                server.name
            )))
        }
    }
}

/// Stores the account for an app password sign-in that
/// [`check_credentials`] accepted. If the address would be a new mailbox,
/// the usage hook is asked first. `Err` is the page to show instead: the
/// form from `retry` with the hook's refusal or [`CONNECTED_ANOTHER_WAY`],
/// or a server error.
pub async fn store_imap_account(
    state: &AuthState,
    email: &str,
    password: &SecretString,
    server: &ImapServer,
    retry: impl Fn(&SignInError) -> Response,
) -> Result<UpsertedImapAccount, Box<Response>> {
    let store = state.store();
    let stored = match usage::refusal(state, store, email, Provider::Imap, None).await {
        Ok(None) => {
            let server = Some(server.id.id());
            store
                .upsert_imap_account_ending_sessions(email, password, server)
                .await
        }
        Ok(Some(refusal)) => {
            return Err(Box::new(retry(&SignInError::form(refusal.message()))));
        }
        Err(err) => Err(err),
    };
    match stored {
        Ok(stored) => Ok(stored),
        Err(StoreError::AccountConflict) => {
            Err(Box::new(retry(&SignInError::form(CONNECTED_ANOTHER_WAY))))
        }
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            Err(Box::new(pages::server_error()))
        }
    }
}

/// What the user typed, shown again after an error.
#[derive(Default)]
struct SignInValues {
    email: String,
    imap_server: String,
}

/// The messages a sign-in page shows.
#[derive(Clone, Copy, Default)]
struct SignInErrors<'a> {
    error: Option<&'a str>,
    email_error: Option<&'a str>,
    password_error: Option<&'a str>,
}

impl<'a> From<&'a SignInError> for SignInErrors<'a> {
    fn from(problem: &'a SignInError) -> Self {
        match problem {
            SignInError::Fields { email, password } => Self {
                error: None,
                email_error: *email,
                password_error: *password,
            },
            SignInError::Form(message) => Self {
                error: Some(message),
                ..Self::default()
            },
        }
    }
}

fn sign_in_page(
    state: &AuthState,
    options: RouterOptions,
    client: &Client,
    request: &AuthorizationRequest,
    request_id: &str,
    values: &SignInValues,
    problem: Option<&SignInError>,
) -> Response {
    let status = if problem.is_some() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::OK
    };
    let errors = problem.map(SignInErrors::from).unwrap_or_default();
    let redirect_host = crate::account_view::display_host(&request.redirect_uri);
    // Stored names predate the registration filter, so strip again here.
    let client_name =
        crate::register::client_name_for_display(client.name.as_deref(), "An unnamed app");
    // The name in a metadata document is self-asserted; its host is not.
    let client_host = client_metadata::is_document_url(&client.id)
        .then(|| crate::account_view::display_host(&client.id));
    pages::render(
        status,
        &SignInPage {
            client_name: &client_name,
            client_host: client_host.as_deref(),
            redirect_host: &redirect_host,
            request_id,
            email: &values.email,
            error: errors.error,
            email_error: errors.email_error,
            password_error: errors.password_error,
            mail: &MailChoices::new(
                &state.config().imap_servers,
                &values.imap_server,
                &values.email,
            ),
            oauth: &if options.account_pages {
                crate::upstream::buttons(state, Some(request_id))
            } else {
                OAuthButtons::default()
            },
        },
    )
}

/// Marks a response of [`invalid_link`], so that [`embedded_page`] can
/// swap it for the embedding's page.
#[derive(Clone)]
struct Invalid(String);

fn invalid_link(detail: &str) -> Response {
    let mut page = pages::message(
        StatusCode::BAD_REQUEST,
        "This link can't be used",
        &format!("{detail} Go back to your app and try connecting again."),
    );
    page.extensions_mut().insert(Invalid(detail.to_owned()));
    page
}

/// Middleware on `/authorize`: answers a request it refuses with the
/// embedding's [`InvalidRequestPage`](crate::InvalidRequestPage), if one is
/// installed.
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
    match response.extensions().get::<Invalid>() {
        Some(Invalid(reason)) => hook.page(&head, reason),
        None => response,
    }
}

/// Reports an invalid authorization request.
///
/// Anyone can register a client, so redirecting to its `https` redirect URI
/// straight away would turn this server into an open redirector: a link on
/// the server's own domain that lands on any site (RFC 9700 section
/// 4.11.1). Those errors are shown as a page instead. Loopback and
/// private-use scheme URIs (native apps, RFC 8252) cannot point at a web
/// site, so their errors still go back to the app as the spec describes.
/// Cancelling goes back only after `submit` has accepted a same-origin post,
/// since that is the user choosing to return.
fn request_error(
    state: &AuthState,
    redirect_uri: &str,
    code: &str,
    description: &str,
    client_state: Option<&str>,
) -> Response {
    if redirect::is_web(redirect_uri) {
        return invalid_link(&format!(
            "The app sent an invalid request ({code}: {description})."
        ));
    }
    error_redirect(state, redirect_uri, code, description, client_state)
}

pub fn error_redirect(
    state: &AuthState,
    redirect_uri: &str,
    code: &str,
    description: &str,
    client_state: Option<&str>,
) -> Response {
    let mut params = vec![("error", code), ("error_description", description)];
    if let Some(client_state) = client_state {
        params.push(("state", client_state));
    }
    params.push(("iss", state.config().issuer()));
    redirect::with_params(redirect_uri, &params).map_or_else(pages::server_error, |url| {
        (no_store(), Redirect::to(&url)).into_response()
    })
}
