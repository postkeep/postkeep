//! Sign-in with Microsoft and Google against mocked provider endpoints.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse as _, Redirect, Response};
use axum::routing::get;
use axum::{Router, middleware};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http_body_util::BodyExt;
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, CallbackPage, CheckFuture, ContinuationHook,
    ContinuedSignIn, CredentialVerifier, InvalidRequestPage, NewMailbox, Refusal, RouterOptions,
    SignInFuture, SignInHook, SignInRequest, UsageHook, VerifyFuture, require_bearer, router,
    router_with,
};
use postkeep_mail::ImapServer;
use postkeep_store::{MasterKey, OAuthAccount, Provider, Store, StoreError, UpstreamTokens};
use postkeep_upstream::{AppCredentials, Endpoints, Http, OAuthClient, UpstreamProvider};
use secrecy::SecretString;
use serde_json::json;
use tokio::runtime::Handle;
use tower::ServiceExt;
use wiremock::matchers::{body_string_contains, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ISSUER: &str = "https://mail.example.com";
const REDIRECT: &str = "http://127.0.0.1/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

struct AcceptAll;

impl CredentialVerifier for AcceptAll {
    fn verify<'a>(
        &'a self,
        _server: &'a ImapServer,
        _email: &'a str,
        _password: &'a SecretString,
    ) -> VerifyFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

struct TestApp {
    app: Router,
    state: AuthState,
    store: Store,
    _dir: tempfile::TempDir,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn location(&self) -> String {
        self.headers[header::LOCATION].to_str().unwrap().to_owned()
    }

    /// The `name=value` part of the `Set-Cookie` header for `name`.
    fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(&format!("{name}=")))
            .map(|value| value.split(';').next().unwrap_or_default().to_owned())
    }
}

fn param(url: &str, name: &str) -> Option<String> {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

fn id_token(sub: &str) -> String {
    let claims = json!({
        "iss": "https://accounts.google.com", "aud": "google-client", "sub": sub,
        "exp": chrono::Utc::now().timestamp() + 3600
    });
    format!(
        "e30.{}.c2ln",
        URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes())
    )
}

async fn app(
    server: Option<&MockServer>,
    microsoft: bool,
    google: bool,
    configure: impl FnOnce(&mut AuthConfig),
) -> TestApp {
    let dir = tempfile::tempdir().unwrap();
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    app_in(dir, &key, server, microsoft, google, configure).await
}

/// As [`app`], on the database in `dir` under `key`.
async fn app_in(
    dir: tempfile::TempDir,
    key: &MasterKey,
    server: Option<&MockServer>,
    microsoft: bool,
    google: bool,
    configure: impl FnOnce(&mut AuthConfig),
) -> TestApp {
    let url = format!("sqlite://{}", dir.path().join("auth.db").display());
    let store = Store::connect(&url, key).await.unwrap();
    let mut config = AuthConfig::new(ISSUER, "/mcp").unwrap();
    configure(&mut config);
    let state = AuthState::new(store.clone(), config, AcceptAll);
    if let Some(server) = server {
        let app = |id: &str| AppCredentials {
            client_id: id.to_owned(),
            client_secret: SecretString::from("shh".to_owned()),
        };
        state.enable_upstream(OAuthClient::new(
            Http::for_tests(),
            Endpoints::all_at(&url::Url::parse(&server.uri()).unwrap()),
            url::Url::parse(ISSUER).unwrap(),
            microsoft.then(|| app("ms-client")),
            google.then(|| app("google-client")),
        ));
    }
    let protected = Router::new()
        .route(
            "/mcp",
            get(|Extension(auth): Extension<Authenticated>| async move { auth.account_id.0 }),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));
    TestApp {
        app: protected.merge(router(state.clone())),
        state,
        store,
        _dir: dir,
    }
}

async fn reply(response: Response) -> Reply {
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

impl TestApp {
    async fn send(&self, request: Request<Body>) -> Reply {
        reply(self.app.clone().oneshot(request).await.unwrap()).await
    }

    async fn get(&self, uri: &str, cookie: Option<&str>) -> Reply {
        let mut request = Request::get(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    async fn post(&self, uri: &str, fields: &[(&str, &str)], origin: Option<&str>) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request =
            Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    async fn client(&self) -> String {
        let reply = self
            .send(
                Request::post("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "redirect_uris": [REDIRECT],
                            "client_name": "Test App",
                            "token_endpoint_auth_method": "none",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        let value: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
        value["client_id"].as_str().unwrap().to_owned()
    }

    /// Opens the MCP client's sign-in page; returns its HTML.
    async fn sign_in_page(&self, client_id: &str) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", REDIRECT),
                ("state", "client-state"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
            ])
            .finish();
        let reply = self.get(&format!("/authorize?{query}"), None).await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        reply.body
    }

    /// Starts a sign-in; returns the provider URL and the binding cookie.
    async fn start(&self, provider: &str, request_id: Option<&str>) -> (String, String) {
        let fields: Vec<(&str, &str)> = request_id
            .map(|id| vec![("request_id", id)])
            .unwrap_or_default();
        let reply = self
            .post(&format!("/oauth/{provider}/start"), &fields, Some(ISSUER))
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        let cookie = reply.cookie("__Host-postkeep_upstream").unwrap();
        let set_cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
        assert!(set_cookie.contains("HttpOnly") && set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Secure"));
        (reply.location(), cookie)
    }

    /// Deletes the account of `session` on the account page, as its owner
    /// does: with the page's CSRF token and the account's address.
    async fn delete_account(&self, session: &str, email: &str) -> Reply {
        let page = self.get("/account", Some(session)).await;
        let marker = "name=\"csrf_token\" value=\"";
        let start = page.body.find(marker).unwrap() + marker.len();
        let end = start + page.body[start..].find('"').unwrap();
        let fields = [
            ("csrf_token", &page.body[start..end]),
            ("confirm_email", email),
        ];
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send(
            Request::post("/account/delete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ISSUER)
                .header(header::COOKIE, session)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }
}

fn request_id(html: &str) -> String {
    let marker = "name=\"request_id\" value=\"";
    let start = html.find(marker).unwrap() + marker.len();
    let end = start + html[start..].find('"').unwrap();
    html[start..end].to_owned()
}

async fn mock_microsoft(server: &MockServer, email: &str) {
    Mock::given(method("POST"))
        .and(path("/microsoft/common/oauth2/v2.0/token"))
        .and(body_string_contains("code=ms-code"))
        .and(body_string_contains("code_verifier="))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "ms-access", "refresh_token": "ms-refresh", "expires_in": 3600,
            "scope": "Mail.ReadWrite Mail.Send User.Read"
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/graph/v1.0/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "ms-user-1", "mail": email, "userPrincipalName": email
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/graph/v1.0/me/mailFolders/inbox"))
        .and(query_param("$select", "id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "inbox-id" })))
        .with_priority(10)
        .mount(server)
        .await;
}

async fn mock_google(server: &MockServer, email: &str) {
    Mock::given(method("POST"))
        .and(path("/google-oauth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "g-access", "refresh_token": "g-refresh", "expires_in": 3600,
            "scope": "openid https://www.googleapis.com/auth/gmail.modify",
            "id_token": id_token("g-user-1")
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/gmail/v1/users/me/profile"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "emailAddress": email })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn buttons_show_only_for_configured_providers() {
    let plain = app(None, false, false, |_| {}).await;
    let client = plain.client().await;
    let html = plain.sign_in_page(&client).await;
    assert!(!html.contains("/oauth/microsoft/start") && !html.contains("/oauth/google/start"));
    assert_eq!(
        plain
            .post("/oauth/google/start", &[], Some(ISSUER))
            .await
            .status,
        StatusCode::NOT_FOUND
    );

    let server = MockServer::start().await;
    let ms_only = app(Some(&server), true, false, |_| {}).await;
    let client = ms_only.client().await;
    let html = ms_only.sign_in_page(&client).await;
    assert!(html.contains("action=\"/oauth/microsoft/start\""), "{html}");
    assert!(!html.contains("/oauth/google/start"));
    // The button carries the pending request so the sign-in finishes it.
    assert_eq!(html.matches("name=\"request_id\"").count(), 2);
    let account_page = ms_only.get("/account", None).await;
    assert!(
        account_page
            .body
            .contains("action=\"/oauth/microsoft/start\"")
    );
    assert_eq!(
        ms_only
            .post("/oauth/google/start", &[], Some(ISSUER))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn disabling_account_pages_removes_upstream_starts_but_not_callbacks() {
    let server = MockServer::start().await;
    let mut app = app(Some(&server), true, true, |_| {}).await;
    let mut options = RouterOptions::default();
    options.account_pages = false;
    app.app = router_with(app.state.clone(), options);
    for provider in ["microsoft", "google"] {
        let start = format!("/oauth/{provider}/start");
        assert_eq!(
            app.post(&start, &[], None).await.status,
            StatusCode::NOT_FOUND
        );
        let callback = format!("/oauth/{provider}/callback");
        assert_eq!(
            app.get(&callback, None).await.status,
            StatusCode::BAD_REQUEST
        );
    }
    let client = app.client().await;
    let page = app.sign_in_page(&client).await;
    let retry = app
        .post(
            "/authorize",
            &[("request_id", &request_id(&page))],
            Some(ISSUER),
        )
        .await;
    assert_eq!(retry.status, StatusCode::BAD_REQUEST);
    for html in [page, retry.body] {
        assert!(html.contains("name=\"password\""));
        assert!(!html.contains("/oauth/"));
    }
}

#[tokio::test]
async fn starting_requires_the_servers_own_origin() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, true, |_| {}).await;
    for origin in [None, Some("https://evil.example")] {
        let reply = app.post("/oauth/microsoft/start", &[], origin).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert!(reply.headers.get(header::SET_COOKIE).is_none());
    }
    // An unknown authorization request is refused before leaving the site.
    let reply = app
        .post(
            "/oauth/microsoft/start",
            &[("request_id", "nope")],
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

/// Signs people in for every resource itself; its page is the request ID.
struct EveryResource;

impl SignInHook for EveryResource {
    fn handles(&self, _resource: &str) -> bool {
        true
    }

    fn start<'a>(&'a self, _state: &'a AuthState, request: SignInRequest<'a>) -> SignInFuture<'a> {
        let id = request.id.to_owned();
        Box::pin(async move { id.into_response() })
    }
}

#[tokio::test]
async fn a_sign_in_hooks_request_cannot_use_microsoft_or_google() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, true, |_| {}).await;
    app.state.set_sign_in_hook(Arc::new(EveryResource));
    let client = app.client().await;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client.as_str()),
            ("redirect_uri", REDIRECT),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("resource", "https://mail.example.com/mcp"),
        ])
        .finish();
    let page = app.get(&format!("/authorize?{query}"), None).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    for provider in ["microsoft", "google"] {
        let reply = app
            .post(
                &format!("/oauth/{provider}/start"),
                &[("request_id", page.body.as_str())],
                Some(ISSUER),
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{provider}");
        assert!(
            reply.headers.get(header::SET_COOKIE).is_none(),
            "{provider}"
        );
    }
}

#[tokio::test]
async fn microsoft_sign_in_completes_the_mcp_authorization() {
    let server = MockServer::start().await;
    mock_microsoft(&server, "person@example.com").await;
    let app = app(Some(&server), true, false, |_| {}).await;
    let client = app.client().await;
    let request_id = request_id(&app.sign_in_page(&client).await);

    let (authorize, cookie) = app.start("microsoft", Some(&request_id)).await;
    assert!(authorize.starts_with(&format!(
        "{}/microsoft/common/oauth2/v2.0/authorize?",
        server.uri()
    )));
    assert_eq!(param(&authorize, "client_id").as_deref(), Some("ms-client"));
    assert_eq!(
        param(&authorize, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(
        param(&authorize, "redirect_uri").as_deref(),
        Some("https://mail.example.com/oauth/microsoft/callback")
    );
    let state = param(&authorize, "state").unwrap();

    let reply = app
        .get(
            &format!("/oauth/microsoft/callback?code=ms-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let back = reply.location();
    assert!(back.starts_with(REDIRECT), "{back}");
    assert_eq!(param(&back, "state").as_deref(), Some("client-state"));
    assert_eq!(param(&back, "iss").as_deref(), Some(ISSUER));
    // The binding cookie is cleared.
    let cleared = reply.cookie("__Host-postkeep_upstream").unwrap();
    assert_eq!(cleared, "__Host-postkeep_upstream=");

    // The MCP client redeems the code as usual.
    let code = param(&back, "code").unwrap();
    let token = app
        .post(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("client_id", &client),
                ("code_verifier", VERIFIER),
            ],
            None,
        )
        .await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);

    let account = app
        .store
        .account_by_subject(Provider::Graph, "ms-user-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(account.email, "person@example.com");
    let tokens = app
        .store
        .upstream_tokens(&account.id)
        .await
        .unwrap()
        .unwrap();
    assert!(tokens.invalid_reason.is_none());

    // The state is single-use.
    let second = app
        .get(
            &format!("/oauth/microsoft/callback?code=ms-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(second.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_unrelated_callback_leaves_the_sign_in_in_progress() {
    let server = MockServer::start().await;
    mock_microsoft(&server, "person@example.com").await;
    let app = app(Some(&server), true, false, |_| {}).await;
    let (authorize, cookie) = app.start("microsoft", None).await;
    let state = param(&authorize, "state").unwrap();

    // A cross-site GET with no state, or with a state we never issued, must
    // not expire the binding cookie or the stored sign-in.
    for uri in [
        "/oauth/microsoft/callback",
        "/oauth/microsoft/callback?code=ms-code&state=not-the-state",
    ] {
        let stray = app.get(uri, Some(&cookie)).await;
        assert_eq!(
            stray.status,
            StatusCode::BAD_REQUEST,
            "{uri}: {}",
            stray.body
        );
        assert!(
            stray.cookie("__Host-postkeep_upstream").is_none(),
            "{uri} cleared the binding cookie: {:?}",
            stray
                .headers
                .get_all(header::SET_COOKIE)
                .iter()
                .collect::<Vec<_>>()
        );
    }

    let reply = app
        .get(
            &format!("/oauth/microsoft/callback?code=ms-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.cookie("__Host-postkeep_upstream").as_deref(),
        Some("__Host-postkeep_upstream=")
    );
    assert!(
        app.store
            .account_by_subject(Provider::Graph, "ms-user-1")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_callback_for_another_sign_in_keeps_the_victims_cookie() {
    let server = MockServer::start().await;
    mock_microsoft(&server, "person@example.com").await;
    let app = app(Some(&server), true, true, |_| {}).await;

    let (victim_authorize, victim_cookie) = app.start("microsoft", None).await;
    let victim_state = param(&victim_authorize, "state").unwrap();

    // The attacker starts their own sign-in, then sends the victim that
    // state. It matches a stored request, but not this browser's binding.
    let (attacker_authorize, _attacker_cookie) = app.start("microsoft", None).await;
    let attacker_state = param(&attacker_authorize, "state").unwrap();
    let attack = app
        .get(
            &format!("/oauth/microsoft/callback?error=access_denied&state={attacker_state}"),
            Some(&victim_cookie),
        )
        .await;
    assert_eq!(attack.status, StatusCode::BAD_REQUEST, "{}", attack.body);
    assert!(
        attack.cookie("__Host-postkeep_upstream").is_none(),
        "a mismatched binding must not expire the victim's cookie: {:?}",
        attack
            .headers
            .get_all(header::SET_COOKIE)
            .iter()
            .collect::<Vec<_>>()
    );

    let reply = app
        .get(
            &format!("/oauth/microsoft/callback?code=ms-code&state={victim_state}"),
            Some(&victim_cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.location(), "/account?notice=signed-in");
    assert_eq!(
        reply.cookie("__Host-postkeep_upstream").as_deref(),
        Some("__Host-postkeep_upstream=")
    );
    assert!(
        app.store
            .account_by_subject(Provider::Graph, "ms-user-1")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn a_provider_mismatch_with_the_right_browser_clears_the_cookie() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, true, |_| {}).await;
    let (authorize, cookie) = app.start("microsoft", None).await;
    let state = param(&authorize, "state").unwrap();
    let reply = app
        .get(
            &format!("/oauth/google/callback?code=whatever&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_eq!(
        reply.cookie("__Host-postkeep_upstream").as_deref(),
        Some("__Host-postkeep_upstream=")
    );
}

#[tokio::test]
async fn callbacks_need_the_browser_that_started_them() {
    let server = MockServer::start().await;
    mock_microsoft(&server, "person@example.com").await;
    let app = app(Some(&server), true, false, |_| {}).await;
    let (authorize, _cookie) = app.start("microsoft", None).await;
    let state = param(&authorize, "state").unwrap();
    // Someone else's browser (no cookie, or another one) can't finish it.
    for cookie in [None, Some("__Host-postkeep_upstream=forged")] {
        let reply = app
            .get(
                &format!("/oauth/microsoft/callback?code=ms-code&state={state}"),
                cookie,
            )
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }
    assert!(
        app.store
            .account_by_subject(Provider::Graph, "ms-user-1")
            .await
            .unwrap()
            .is_none()
    );
    // A callback for the other provider's path is refused too.
    let (authorize, cookie) = app.start("microsoft", None).await;
    let state = param(&authorize, "state").unwrap();
    let reply = app
        .get(
            &format!("/oauth/google/callback?code=ms-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cancelled_sign_ins_connect_nothing() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, false, |_| {}).await;
    let (authorize, cookie) = app.start("microsoft", None).await;
    let state = param(&authorize, "state").unwrap();
    let reply = app
        .get(
            &format!("/oauth/microsoft/callback?error=access_denied&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("cancelled"), "{}", reply.body);
}

/// The admin-consent guide that Microsoft refusals point to.
const CONSENT_GUIDE: &str = "https://postkeep.dev/docs/providers/microsoft-admin-consent/";

/// The callback answering `provider`'s sign-in with `error` and
/// `description`, as the provider sends it.
async fn refused(app: &TestApp, provider: &str, error: &str, description: &str) -> Reply {
    let (authorize, cookie) = app.start(provider, None).await;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", &param(&authorize, "state").unwrap())
        .append_pair("error", error)
        .append_pair("error_description", description)
        .finish();
    let callback = format!("/oauth/{provider}/callback?{query}");
    app.get(&callback, Some(&cookie)).await
}

#[tokio::test]
async fn microsoft_refusals_say_when_an_administrator_has_to_approve() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, true, |_| {}).await;
    let approve = "An administrator of your organization has to approve postkeep";
    for (error, description, says) in [
        (
            "access_denied",
            "AADSTS90094: Admin consent is required.",
            approve,
        ),
        ("consent_required", "AADSTS65001: No consent yet.", approve),
        (
            "access_denied",
            "AADSTS90095: Approval required.",
            "a reviewer will decide",
        ),
        (
            "access_denied",
            "AADSTS65004: User declined to consent.",
            "You cancelled",
        ),
    ] {
        let reply = refused(&app, "microsoft", error, description).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{description}");
        assert!(reply.body.contains(says), "{description}: {}", reply.body);
        assert!(reply.body.contains(CONSENT_GUIDE), "{description}");
        assert!(!reply.body.contains("AADSTS"), "{description} is not shown");
    }
    let google = refused(&app, "google", "access_denied", "AADSTS90094: no").await;
    assert!(google.body.contains("You cancelled"), "{}", google.body);
    assert!(!google.body.contains(CONSENT_GUIDE));
}

#[tokio::test]
async fn microsofts_admin_consent_answer_has_a_page_of_its_own() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, true, |_| {}).await;
    let approved = app
        .get(
            "/oauth/microsoft/callback?admin_consent=True\
             &tenant=aaaabbbb-0000-cccc-1111-dddd2222eeee\
             &scope=https%3A%2F%2Fgraph.microsoft.com%2FMail.ReadWrite",
            None,
        )
        .await;
    assert_eq!(approved.status, StatusCode::OK, "{}", approved.body);
    assert!(approved.body.contains("Microsoft recorded the approval"));
    assert!(approved.headers.get(header::SET_COOKIE).is_none());

    let declined = app
        .get(
            "/oauth/microsoft/callback?admin_consent=True&error=consent_required\
             &error_description=AADSTS65004%3a+The+resource+owner+denied+the+request.",
            None,
        )
        .await;
    assert_eq!(declined.status, StatusCode::BAD_REQUEST);
    assert!(declined.body.contains(CONSENT_GUIDE), "{}", declined.body);

    // Google has no such endpoint, so its callback still wants a state.
    let google = app
        .get("/oauth/google/callback?admin_consent=True", None)
        .await;
    assert!(
        google.body.contains("This sign-in has expired"),
        "{}",
        google.body
    );
}

#[tokio::test]
async fn google_sign_in_opens_the_account_page_and_delete_revokes() {
    let server = Arc::new(MockServer::start().await);
    mock_google(&server, "someone@example.com").await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=g-refresh"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let app = app(Some(&server), false, true, |_| {}).await;
    // The deletion listeners run before the revoke: Gmail's users.stop needs
    // the grant.
    let revoked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (requests, record) = (Arc::clone(&server), Arc::clone(&revoked));
    app.state.add_deletion_listener(Arc::new(move |_| {
        let (requests, record) = (Arc::clone(&requests), Arc::clone(&record));
        Box::pin(async move {
            let received = requests.received_requests().await.unwrap_or_default();
            let path = "/google-oauth/revoke";
            let done = received.iter().any(|request| request.url.path() == path);
            record.lock().unwrap().push(done);
        })
    }));
    let (authorize, cookie) = app.start("google", None).await;
    assert_eq!(param(&authorize, "access_type").as_deref(), Some("offline"));
    assert_eq!(param(&authorize, "prompt").as_deref(), Some("consent"));
    let state = param(&authorize, "state").unwrap();
    let reply = app
        .get(
            &format!("/oauth/google/callback?code=g-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.location(), "/account?notice=signed-in");
    let session = reply.cookie("__Host-postkeep_session").unwrap();
    let page = app.get("/account", Some(&session)).await;
    assert!(page.body.contains("someone@example.com"), "{}", page.body);

    let csrf = {
        let marker = "name=\"csrf_token\" value=\"";
        let start = page.body.find(marker).unwrap() + marker.len();
        let end = start + page.body[start..].find('"').unwrap();
        page.body[start..end].to_owned()
    };
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf_token", csrf.as_str()),
            ("confirm_email", "someone@example.com"),
        ])
        .finish();
    let reply = app
        .send(
            Request::post("/account/delete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ISSUER)
                .header(header::COOKIE, &session)
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(reply.body.contains("revoked at Google"));
    assert_eq!(*revoked.lock().unwrap(), [false]);
    assert!(
        app.store
            .account_by_subject(Provider::Gmail, "g-user-1")
            .await
            .unwrap()
            .is_none()
    );
    server.verify().await;
}

/// A grant that a reconnect stores while the account page deletes the
/// account, once the old grant's revocation has read the old one, is revoked
/// too, and the page doesn't claim that the access was revoked when Google
/// refuses. The old grant's revocation waits for the reconnect.
#[tokio::test]
async fn a_grant_stored_while_its_account_is_deleted_is_revoked_too() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@example.com").await;
    let (called, on_called) = tokio::sync::oneshot::channel();
    let (done, on_done) = std::sync::mpsc::channel();
    let waiting = std::sync::Mutex::new(Some((called, on_done)));
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=g-refresh"))
        .respond_with(move |_: &wiremock::Request| {
            let first = waiting.lock().unwrap().take();
            if let Some((called, on_done)) = first {
                called.send(()).unwrap();
                on_done.recv().unwrap();
            }
            ResponseTemplate::new(200)
        })
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=g-renewed"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;
    let app = app(Some(&server), false, true, |_| {}).await;
    let store = app.store.clone();
    let reconnect = tokio::spawn(async move {
        on_called.await.unwrap();
        let gmail = OAuthAccount {
            provider: Provider::Gmail,
            subject: "g-user-1",
            email: "someone@example.com",
        };
        let renewed = UpstreamTokens {
            refresh_token: SecretString::from("g-renewed".to_owned()),
            access_token: None,
            access_expires_at: None,
            scope: "gmail".to_owned(),
        };
        store.upsert_oauth_account(&gmail, &renewed).await.unwrap();
        done.send(()).unwrap();
    });
    let (authorize, cookie) = app.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let callback = format!("/oauth/google/callback?code=g-code&state={state}");
    let reply = app.get(&callback, Some(&cookie)).await;
    let session = reply.cookie("__Host-postkeep_session").unwrap();
    let reply = app.delete_account(&session, "someone@example.com").await;
    reconnect.await.unwrap();
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let unconfirmed = reply.body.contains("could not be confirmed as revoked");
    assert!(unconfirmed, "{}", reply.body);
    server.verify().await;
}

/// A usage hook that holds the first new mailbox it is asked about until
/// `open` is notified, and lets any later one through. A callback asks it once
/// the sign-in is taken and the provider has answered, before anything is
/// stored.
#[derive(Default)]
struct Gate {
    asked: AtomicUsize,
    open: tokio::sync::Notify,
}

impl UsageHook for Gate {
    fn before_connect<'a>(&'a self, _mailbox: NewMailbox<'a>) -> CheckFuture<'a> {
        let first = self.asked.fetch_add(1, Ordering::SeqCst) == 0;
        Box::pin(async move {
            if first {
                self.open.notified().await;
            }
            Ok(())
        })
    }
}

/// Of two callbacks for one sign-in at once, one finishes it; the other sees
/// the ordinary page for a sign-in that expired or was already used, not an
/// error. The callback that took the sign-in waits in the usage hook until the
/// other has answered.
#[tokio::test]
async fn the_second_of_two_callbacks_at_once_sees_the_expired_page() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@example.com").await;
    let app = app(Some(&server), false, true, |_| {}).await;
    let gate = Arc::new(Gate::default());
    app.state.set_usage_hook(gate.clone());
    let (authorize, cookie) = app.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let uri = format!("/oauth/google/callback?code=g-code&state={state}");
    let mut one = Box::pin(app.get(&uri, Some(&cookie)));
    let mut two = Box::pin(app.get(&uri, Some(&cookie)));
    let (lost, won) = tokio::select! {
        lost = &mut one => (lost, two),
        lost = &mut two => (lost, one),
    };
    assert_eq!(lost.status, StatusCode::BAD_REQUEST, "{}", lost.body);
    assert!(
        lost.body.contains("This sign-in has expired"),
        "{}",
        lost.body
    );
    gate.open.notify_one();
    let won = won.await;
    assert_eq!(won.status, StatusCode::SEE_OTHER, "{}", won.body);
    assert_eq!(won.location(), "/account?notice=signed-in");
    assert_eq!(gate.asked.load(Ordering::SeqCst), 1);
}

/// The master key was lost and replaced while a sign-in was in progress. The
/// callback cannot open the sign-in: the person sees a server error and the
/// sign-in is removed, so the same link then says it expired; starting again
/// works and finishes under the new key.
#[tokio::test]
async fn a_sign_in_started_under_a_replaced_master_key_must_be_started_again() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@example.com").await;
    let before = app(Some(&server), false, true, |_| {}).await;
    let (authorize, cookie) = before.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let TestApp { _dir: dir, .. } = before;

    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let after = app_in(dir, &key, Some(&server), false, true, |_| {}).await;
    let uri = format!("/oauth/google/callback?code=g-code&state={state}");
    let first = after.get(&uri, Some(&cookie)).await;
    assert_eq!(
        first.status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        first.body
    );
    let again = after.get(&uri, Some(&cookie)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST, "{}", again.body);
    assert!(
        again.body.contains("This sign-in has expired"),
        "{}",
        again.body
    );

    let (authorize, cookie) = after.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let uri = format!("/oauth/google/callback?code=g-code&state={state}");
    let done = after.get(&uri, Some(&cookie)).await;
    assert_eq!(done.status, StatusCode::SEE_OTHER, "{}", done.body);
    assert_eq!(done.location(), "/account?notice=signed-in");
}

#[tokio::test]
async fn google_delete_says_so_when_revoke_fails() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@example.com").await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=g-refresh"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "error": "server_error",
            "error_description": "unavailable"
        })))
        .expect(1)
        .mount(&server)
        .await;
    let app = app(Some(&server), false, true, |_| {}).await;
    let (authorize, cookie) = app.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let reply = app
        .get(
            &format!("/oauth/google/callback?code=g-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let session = reply.cookie("__Host-postkeep_session").unwrap();
    let page = app.get("/account", Some(&session)).await;
    let csrf = {
        let marker = "name=\"csrf_token\" value=\"";
        let start = page.body.find(marker).unwrap() + marker.len();
        let end = start + page.body[start..].find('"').unwrap();
        page.body[start..end].to_owned()
    };
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("csrf_token", csrf.as_str()),
            ("confirm_email", "someone@example.com"),
        ])
        .finish();
    let reply = app
        .send(
            Request::post("/account/delete")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ISSUER)
                .header(header::COOKIE, &session)
                .body(Body::from(body))
                .unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(
        reply.body.contains("could not be confirmed as revoked"),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("myaccount.google.com/permissions"),
        "{}",
        reply.body
    );
    assert!(!reply.body.contains("revoked at Google"), "{}", reply.body);
    assert!(
        app.store
            .account_by_subject(Provider::Gmail, "g-user-1")
            .await
            .unwrap()
            .is_none(),
        "the account is still deleted when revocation fails"
    );
}

#[tokio::test]
async fn disallowed_or_conflicting_addresses_are_refused_and_revoked() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@example.com").await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;

    let restricted = app(Some(&server), false, true, |config| {
        config.allowed_emails = Some(vec!["other@example.com".to_owned()]);
    })
    .await;
    let (authorize, cookie) = restricted.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let reply = restricted
        .get(
            &format!("/oauth/google/callback?code=g-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    let app = app(Some(&server), false, true, |_| {}).await;
    app.store
        .upsert_account(
            "someone@example.com",
            &SecretString::from("app-password".to_owned()),
        )
        .await
        .unwrap();
    let (authorize, cookie) = app.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let reply = app
        .get(
            &format!("/oauth/google/callback?code=g-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
    assert!(
        app.store
            .account_by_subject(Provider::Gmail, "g-user-1")
            .await
            .unwrap()
            .is_none()
    );
}

/// A sign-in whose account is deleted while it is saved keeps nothing, says
/// so and revokes the new grant. A trigger stands in for the deletion: the
/// sign-in's update of the account's row then changes nothing, as on
/// PostgreSQL once a deletion that it waited for has committed. Google, as
/// Microsoft offers no revocation.
#[tokio::test]
async fn a_sign_in_whose_account_was_just_deleted_says_so_and_revokes() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@example.com").await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=g-refresh"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let app = app(Some(&server), false, true, |_| {}).await;
    let sign_in = async || {
        let (authorize, cookie) = app.start("google", None).await;
        let state = param(&authorize, "state").unwrap();
        app.get(
            &format!("/oauth/google/callback?code=g-code&state={state}"),
            Some(&cookie),
        )
        .await
    };
    let first = sign_in().await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{}", first.body);

    let gone = "CREATE TRIGGER gone BEFORE UPDATE ON accounts \
                BEGIN SELECT RAISE(IGNORE); END";
    sqlx::query(gone).execute(app.store.pool()).await.unwrap();
    let again = sign_in().await;
    assert_eq!(again.status, StatusCode::CONFLICT, "{}", again.body);
    assert!(
        again.body.contains("This account was just deleted"),
        "{}",
        again.body
    );
    server.verify().await;
}

/// A sign-in whose account is deleted once the sign-in has stored it, before
/// the account page's session or the app's code is stored, says so, and one
/// with Google revokes the new grant. A listener of account changes, which
/// runs between the two, deletes the account.
#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_whose_account_is_deleted_before_it_finishes_says_so() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@example.com").await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=g-refresh"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&server)
        .await;
    let app = app(Some(&server), false, true, |_| {}).await;
    let store = app.store.clone();
    app.state.add_account_listener(Arc::new(move |account| {
        let delete = store.delete_account(account);
        let deleted = tokio::task::block_in_place(|| Handle::current().block_on(delete));
        assert!(deleted.unwrap(), "the account was not there to delete");
    }));
    let client = app.client().await;
    let mut replies = Vec::new();
    // With Google, for the account page and then for the app.
    for request in [None, Some(request_id(&app.sign_in_page(&client).await))] {
        let (authorize, cookie) = app.start("google", request.as_deref()).await;
        let state = param(&authorize, "state").unwrap();
        let callback = format!("/oauth/google/callback?code=g-code&state={state}");
        replies.push(app.get(&callback, Some(&cookie)).await);
    }
    // With an app password, for the account page and then for the app.
    let email = ("email", "someone@icloud.com");
    let password = ("password", "abcdabcdabcdabcd");
    let fields = [email, password];
    replies.push(app.post("/account/sign-in", &fields, Some(ISSUER)).await);
    let request = request_id(&app.sign_in_page(&client).await);
    let request = ("request_id", request.as_str());
    let connect = [request, email, password, ("action", "connect")];
    replies.push(app.post("/authorize", &connect, Some(ISSUER)).await);
    for reply in replies {
        assert_eq!(reply.status, StatusCode::CONFLICT, "{}", reply.body);
        let deleted = reply.body.contains("This account was just deleted");
        assert!(deleted, "{}", reply.body);
    }
    server.verify().await;
}

/// With Sign in with Google and the Gmail app password choice both on the
/// page, an address connected with Google stays with Google: the app password
/// form refuses it and the Google account is not touched.
#[tokio::test]
async fn a_gmail_address_connected_with_google_is_refused_on_the_app_password_form() {
    let server = MockServer::start().await;
    mock_google(&server, "someone@gmail.com").await;
    let app = app(Some(&server), false, true, |_| {}).await;
    let client = app.client().await;
    let page = app.sign_in_page(&client).await;
    assert!(page.contains("action=\"/oauth/google/start\""), "{page}");
    assert!(
        page.contains("value=\"gmail\" id=\"provider-gmail\""),
        "{page}"
    );

    let (authorize, cookie) = app.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let callback = format!("/oauth/google/callback?code=g-code&state={state}");
    let reply = app.get(&callback, Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let google = Provider::Gmail;
    let before = app.store.account_by_subject(google, "g-user-1").await;
    let before = before.unwrap().unwrap();

    let id = request_id(&page);
    let form = [
        ("request_id", id.as_str()),
        ("email", "Someone@Gmail.com"),
        ("password", "abcd efgh ijkl mnop"),
        ("imap_server", "auto"),
        ("action", "connect"),
    ];
    let refused = app.post("/authorize", &form, Some(ISSUER)).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert!(
        refused.body.contains("already connected another way"),
        "{}",
        refused.body
    );
    let after = app.store.account_by_subject(google, "g-user-1").await;
    assert_eq!(after.unwrap().unwrap(), before);
    let by_password = app
        .store
        .account_by_email("someone@gmail.com", Provider::Imap)
        .await;
    assert!(by_password.unwrap().is_none());
}

/// What the continuation hook was handed for one sign-in.
#[derive(Debug, PartialEq, Eq)]
struct Finished {
    tenant: String,
    continuation: String,
    email: String,
    /// Whether the sign-in's `Debug` output shows the continuation or a
    /// cookie.
    secrets_in_debug: bool,
}

/// An embedding's page that adds mailboxes: it records every finished
/// sign-in and sends the browser back to `/connected`.
#[derive(Default)]
struct Connections {
    finished: std::sync::Mutex<Vec<Finished>>,
}

impl ContinuationHook for Connections {
    fn finish<'a>(
        &'a self,
        _state: &'a AuthState,
        sign_in: ContinuedSignIn<'a>,
    ) -> SignInFuture<'a> {
        let debug = format!("{sign_in:?}");
        self.finished.lock().unwrap().push(Finished {
            tenant: sign_in.tenant.to_owned(),
            continuation: sign_in.continuation.to_owned(),
            email: sign_in.account.email.clone(),
            secrets_in_debug: debug.contains(sign_in.continuation) || debug.contains("upstream="),
        });
        Box::pin(async { Redirect::to("/connected").into_response() })
    }
}

/// Starts a Microsoft sign-in for the tenant `acme`; returns its `state`
/// and the binding cookie.
async fn start_for_acme(state: &AuthState, continuation: &str) -> (String, String) {
    let started = state
        .start_upstream_sign_in(
            UpstreamProvider::Microsoft,
            "acme",
            continuation,
            Some("person@example.com"),
        )
        .await
        .unwrap()
        .unwrap();
    let started = reply(started).await;
    assert_eq!(started.status, StatusCode::SEE_OTHER);
    let authorize = started.location();
    assert_eq!(
        param(&authorize, "login_hint").as_deref(),
        Some("person@example.com")
    );
    let cookie = started.cookie("__Host-postkeep_upstream").unwrap();
    (param(&authorize, "state").unwrap(), cookie)
}

#[tokio::test]
async fn an_embedding_page_adds_a_microsoft_mailbox_to_a_tenant() {
    let server = MockServer::start().await;
    mock_microsoft(&server, "person@example.com").await;
    let app = app(Some(&server), true, false, |_| {}).await;
    let hook = Arc::new(Connections::default());
    app.state.set_continuation_hook(hook.clone());

    let (state, cookie) = start_for_acme(&app.state, "connect-1").await;
    let callback = format!("/oauth/microsoft/callback?code=ms-code&state={state}");
    let reply = app.get(&callback, Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.location(), "/connected");
    assert_eq!(reply.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        reply.cookie("__Host-postkeep_upstream").unwrap(),
        "__Host-postkeep_upstream="
    );
    assert_eq!(
        *hook.finished.lock().unwrap(),
        [Finished {
            tenant: "acme".to_owned(),
            continuation: "connect-1".to_owned(),
            email: "person@example.com".to_owned(),
            secrets_in_debug: false,
        }]
    );
    // The account and its tokens are in the tenant, not the default one.
    let account = app
        .store
        .for_tenant("acme")
        .account_by_subject(Provider::Graph, "ms-user-1")
        .await
        .unwrap()
        .unwrap();
    assert!(
        app.store
            .upstream_tokens(&account.id)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        app.store
            .account_by_subject(Provider::Graph, "ms-user-1")
            .await
            .unwrap()
            .is_none()
    );
    // The state is single use.
    let again = app.get(&callback, Some(&cookie)).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);

    // A cancelled sign-in shows the server's page and doesn't reach the hook.
    let (state, cookie) = start_for_acme(&app.state, "connect-2").await;
    let cancelled = app
        .get(
            &format!("/oauth/microsoft/callback?error=access_denied&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(cancelled.status, StatusCode::BAD_REQUEST);
    assert_eq!(hook.finished.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn sign_ins_for_a_tenant_need_a_hook_from_start_to_finish() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, false, |_| {}).await;
    let start = |provider, tenant: &'static str| {
        app.state
            .start_upstream_sign_in(provider, tenant, "connect-1", None)
    };
    assert!(matches!(
        start(UpstreamProvider::Microsoft, "acme").await,
        Err(StoreError::InvalidInput(
            "no continuation hook is installed"
        ))
    ));

    // Another server on the same database has the hook and starts one. This
    // server can't finish it: it stops before exchanging the code, which
    // would fail against the empty mock, and stores nothing.
    let other = AuthState::new(
        app.store.clone(),
        AuthConfig::new(ISSUER, "/mcp").unwrap(),
        AcceptAll,
    );
    other.enable_upstream(app.state.upstream().unwrap().clone());
    other.set_continuation_hook(Arc::new(Connections::default()));
    let (state, cookie) = start_for_acme(&other, "connect-1").await;
    let reply = app
        .get(
            &format!("/oauth/microsoft/callback?code=ms-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    let acme = app.store.for_tenant("acme");
    assert_eq!(acme.accounts_in_tenant().await.unwrap(), Vec::new());

    app.state
        .set_continuation_hook(Arc::new(Connections::default()));
    assert!(matches!(
        start(UpstreamProvider::Microsoft, "").await,
        Err(StoreError::InvalidInput("tenant must not be empty"))
    ));
    assert!(
        start(UpstreamProvider::Google, "acme")
            .await
            .unwrap()
            .is_none()
    );
}

const PLAN_FULL: &str = "This workspace has all the mailboxes its plan includes.";

/// A usage hook that refuses new mailboxes with one address and records
/// each mailbox it is asked about as `tenant email provider`.
struct Plan {
    refused: &'static str,
    asked: std::sync::Mutex<Vec<String>>,
}

impl Plan {
    fn refusing(refused: &'static str) -> Arc<Self> {
        Arc::new(Self {
            refused,
            asked: std::sync::Mutex::default(),
        })
    }

    /// What the hook was asked since the last call.
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut self.asked.lock().unwrap())
    }
}

impl UsageHook for Plan {
    fn before_connect<'a>(&'a self, mailbox: NewMailbox<'a>) -> CheckFuture<'a> {
        let provider = mailbox.provider.as_str();
        let asked = format!("{} {} {provider}", mailbox.tenant, mailbox.email);
        self.asked.lock().unwrap().push(asked);
        let answer = if mailbox.email == self.refused {
            Err(Refusal::new(PLAN_FULL))
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(answer))
    }
}

#[tokio::test]
async fn the_usage_hook_can_refuse_a_google_mailbox() {
    let server = MockServer::start().await;
    mock_google(&server, "Someone@Example.com").await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=g-refresh"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let app = app(Some(&server), false, true, |_| {}).await;
    let plan = Plan::refusing("someone@example.com");
    app.state.set_usage_hook(plan.clone());

    let (authorize, cookie) = app.start("google", None).await;
    let state = param(&authorize, "state").unwrap();
    let callback = format!("/oauth/google/callback?code=g-code&state={state}");
    let reply = app.get(&callback, Some(&cookie)).await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN, "{}", reply.body);
    assert!(reply.body.contains(PLAN_FULL), "{}", reply.body);
    assert_eq!(plan.take(), ["default someone@example.com gmail"]);
    let stored = app.store.account_by_subject(Provider::Gmail, "g-user-1");
    assert!(stored.await.unwrap().is_none());
}

#[tokio::test]
async fn the_usage_hook_sees_the_tenant_and_knows_a_renamed_mailbox() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, false, |_| {}).await;
    app.state
        .set_continuation_hook(Arc::new(Connections::default()));
    let plan = Plan::refusing("renamed@example.com");
    app.state.set_usage_hook(plan.clone());

    // The second sign-in is the same Microsoft account with a new address,
    // so it adds no mailbox and the hook isn't asked.
    for email in ["person@example.com", "renamed@example.com"] {
        server.reset().await;
        mock_microsoft(&server, email).await;
        let (state, cookie) = start_for_acme(&app.state, "connect-1").await;
        let callback = format!("/oauth/microsoft/callback?code=ms-code&state={state}");
        let reply = app.get(&callback, Some(&cookie)).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    }
    assert_eq!(plan.take(), ["acme person@example.com graph"]);
    let acme = app.store.for_tenant("acme");
    let account = acme.account_by_subject(Provider::Graph, "ms-user-1");
    assert_eq!(account.await.unwrap().unwrap().email, "renamed@example.com");
}

/// An embedding's error pages: `418` with what the server's callback page
/// said, except for a `404`, which stays the server's.
struct OwnPages;

impl InvalidRequestPage for OwnPages {
    fn page(&self, _request: &axum::http::request::Parts, _reason: &str) -> Response {
        StatusCode::IM_A_TEAPOT.into_response()
    }

    fn callback_page(
        &self,
        request: &axum::http::request::Parts,
        page: &CallbackPage<'_>,
    ) -> Option<Response> {
        (page.status != StatusCode::NOT_FOUND).then(|| {
            let body = format!(
                "{} {} | {} | {} | {}",
                request.method,
                request.uri.path(),
                page.status.as_u16(),
                page.title,
                page.message
            );
            (StatusCode::IM_A_TEAPOT, body).into_response()
        })
    }
}

#[tokio::test]
async fn an_embeddings_pages_replace_the_callbacks_own() {
    let server = MockServer::start().await;
    let app = app(Some(&server), true, false, |_| {}).await;
    app.state.set_invalid_request_page(Arc::new(OwnPages));
    app.state
        .set_continuation_hook(Arc::new(Connections::default()));

    let expired = app
        .get(
            "/oauth/microsoft/callback?code=ms-code&state=unknown",
            Some("__Host-postkeep_upstream=someone"),
        )
        .await;
    assert_eq!(expired.status, StatusCode::IM_A_TEAPOT);
    assert!(
        expired.body.starts_with(
            "GET /oauth/microsoft/callback | 400 | This sign-in has expired | It took too long"
        ),
        "{}",
        expired.body
    );
    assert_eq!(expired.headers[header::CACHE_CONTROL], "no-store");
    assert!(expired.headers.get(header::SET_COOKIE).is_none());

    // The server's page clears the binding cookie, and so does the hook's.
    let (state, cookie) = start_for_acme(&app.state, "connect-1").await;
    let cancelled = app
        .get(
            &format!("/oauth/microsoft/callback?error=access_denied&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(cancelled.status, StatusCode::IM_A_TEAPOT);
    assert!(
        cancelled
            .body
            .contains("| 400 | Sign-in not completed | You cancelled the sign-in"),
        "{}",
        cancelled.body
    );
    assert_eq!(
        cancelled.cookie("__Host-postkeep_upstream").unwrap(),
        "__Host-postkeep_upstream="
    );

    app.state
        .set_usage_hook(Plan::refusing("refused@example.com"));
    mock_microsoft(&server, "refused@example.com").await;
    let (state, cookie) = start_for_acme(&app.state, "connect-2").await;
    let refused = app
        .get(
            &format!("/oauth/microsoft/callback?code=ms-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(refused.status, StatusCode::IM_A_TEAPOT);
    assert!(
        refused.body.contains(&format!(
            "| 403 | This mailbox can't be added | {PLAN_FULL}"
        )),
        "{}",
        refused.body
    );

    // The hook keeps the server's page.
    let unavailable = app.get("/oauth/google/callback", None).await;
    assert_eq!(unavailable.status, StatusCode::NOT_FOUND);
    assert!(
        unavailable
            .body
            .contains("This sign-in option isn&#39;t available"),
        "{}",
        unavailable.body
    );

    // A sign-in that finishes gets what started it.
    server.reset().await;
    mock_microsoft(&server, "person@example.com").await;
    let (state, cookie) = start_for_acme(&app.state, "connect-3").await;
    let finished = app
        .get(
            &format!("/oauth/microsoft/callback?code=ms-code&state={state}"),
            Some(&cookie),
        )
        .await;
    assert_eq!(finished.status, StatusCode::SEE_OTHER, "{}", finished.body);
    assert_eq!(finished.location(), "/connected");
}

#[tokio::test]
async fn the_callbacks_429_is_the_embeddings_page_and_counts_as_before() {
    let server = MockServer::start().await;
    // Without a hook: a `POST` counts, each request counts once, and the
    // budget is the one the other limited routes share.
    let plain = app(Some(&server), true, false, |config| {
        config.requests_per_minute = 3;
    })
    .await;
    let post = plain.post("/oauth/microsoft/callback", &[], None).await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
    for _ in 0..2 {
        let reply = plain.get("/oauth/microsoft/callback", None).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    }
    let limited = plain.get("/oauth/microsoft/callback", None).await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        limited.body.contains("Too many requests"),
        "{}",
        limited.body
    );
    assert!(limited.headers.contains_key(header::RETRY_AFTER));
    let authorize = plain.get("/authorize?client_id=x", None).await;
    assert_eq!(authorize.status, StatusCode::TOO_MANY_REQUESTS);

    let own = app(Some(&server), true, false, |config| {
        config.requests_per_minute = 1;
    })
    .await;
    own.state.set_invalid_request_page(Arc::new(OwnPages));
    let first = own.get("/oauth/microsoft/callback", None).await;
    assert_eq!(first.status, StatusCode::IM_A_TEAPOT);
    assert!(
        first.body.contains("| 400 | This sign-in has expired |"),
        "{}",
        first.body
    );
    let second = own.get("/oauth/microsoft/callback", None).await;
    assert_eq!(second.status, StatusCode::IM_A_TEAPOT);
    assert!(
        second
            .body
            .starts_with("GET /oauth/microsoft/callback | 429 | Too many requests | Wait "),
        "{}",
        second.body
    );
    assert!(second.headers.contains_key(header::RETRY_AFTER));
    assert_eq!(second.headers[header::CACHE_CONTROL], "no-store");
}
