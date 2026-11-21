//! End-to-end tests of the OAuth flow against an in-memory router.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Router, middleware};
use base64::Engine;
use http_body_util::BodyExt;
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, CeilingsFuture, CheckFuture, CredentialVerifier,
    InvalidRequestPage, NewMailbox, Outbox, OutboxCeilings, Refusal, UsageHook, VerifyError,
    VerifyFuture, require_bearer, router,
};
use postkeep_mail::ImapServer;
use postkeep_store::{
    AccountId, AddedFilterRule, ChangedFilterRule, DeliveryRecord, MAX_CONSECUTIVE_FAILURES,
    MasterKey, NewClient, NewFilterRule, OutboxLimitChange, Provider, Store, WebhookSettings,
};
use postkeep_webhook::sign;
use postkeep_webhook::testing::{Receiver, receiver};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tower::ServiceExt;

const ISSUER: &str = "https://mail.example.com";
const EMAIL: &str = "me@icloud.com";
const PASSWORD: &str = "abcdabcdabcdabcd";
/// A second password the fake verifier accepts for [`EMAIL`].
const ALT_PASSWORD: &str = "zzzzzzzzzzzzzzzz";
const REDIRECT: &str = "http://127.0.0.1/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
/// The title of the account page's webhook section, which shows only when
/// webhooks are on.
const ALERTS_TITLE: &str = "Webhook";

/// Accepts exactly one address and password; `down@icloud.com` simulates
/// an unreachable server. `me@example.org` exists only at Yahoo,
/// `me@fastmail.com` only at Fastmail and `me@gmail.com` only at Gmail.
struct FakeVerifier;

impl CredentialVerifier for FakeVerifier {
    fn verify<'a>(
        &'a self,
        server: &'a ImapServer,
        email: &'a str,
        password: &'a SecretString,
    ) -> VerifyFuture<'a> {
        Box::pin(async move {
            match (email, password.expose_secret()) {
                ("down@icloud.com", _) => Err(VerifyError::Unavailable("timeout".to_owned())),
                ("me@example.org", PASSWORD) if server.id.id() == "yahoo" => Ok(()),
                ("me@fastmail.com", PASSWORD) if server.id.id() == "fastmail" => Ok(()),
                ("me@gmail.com", PASSWORD) if server.id.id() == "gmail" => Ok(()),
                ("me@example.org" | "me@fastmail.com", _) => Err(VerifyError::Rejected),
                (EMAIL, PASSWORD | ALT_PASSWORD) => Ok(()),
                _ => Err(VerifyError::Rejected),
            }
        })
    }
}

struct TestApp {
    app: Router,
    dir: std::sync::Arc<tempfile::TempDir>,
    key: String,
    state: AuthState,
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|err| panic!("{err}: {}", self.body))
    }

    fn location(&self) -> url::Url {
        url::Url::parse(self.headers[header::LOCATION].to_str().unwrap()).unwrap()
    }
}

fn query_param(url: &url::Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

async fn app_with(configure: impl FnOnce(&mut AuthConfig)) -> TestApp {
    let dir = std::sync::Arc::new(tempfile::tempdir().unwrap());
    let key = MasterKey::generate_encoded().unwrap();
    app_in(dir, key, configure, None).await
}

/// An app with webhooks enabled, delivering to a local receiver.
async fn webhook_app() -> (TestApp, Receiver) {
    let dir = std::sync::Arc::new(tempfile::tempdir().unwrap());
    let key = MasterKey::generate_encoded().unwrap();
    let receiver = receiver(&[]).await;
    let app = app_in(dir, key, |_| {}, Some(receiver.deliverer.clone())).await;
    (app, receiver)
}

/// A second app on the same database, for example with other settings.
async fn app_sharing(other: &TestApp, configure: impl FnOnce(&mut AuthConfig)) -> TestApp {
    app_in(other.dir.clone(), other.key.clone(), configure, None).await
}

async fn app_in(
    dir: std::sync::Arc<tempfile::TempDir>,
    key: String,
    configure: impl FnOnce(&mut AuthConfig),
    deliverer: Option<postkeep_webhook::Deliverer>,
) -> TestApp {
    let url = format!("sqlite://{}", dir.path().join("auth.db").display());
    let store = Store::connect(&url, &MasterKey::parse(&key).unwrap())
        .await
        .unwrap();
    let mut config = AuthConfig::new(ISSUER, "/mcp").unwrap();
    configure(&mut config);
    let state = AuthState::new(store, config, FakeVerifier);
    if let Some(deliverer) = deliverer {
        state.enable_webhooks(deliverer);
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
        dir,
        key,
        state,
    }
}

async fn app() -> TestApp {
    app_with(|_| {}).await
}

impl TestApp {
    async fn send(&self, request: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        Reply {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn get(&self, uri: &str) -> Reply {
        self.send(Request::get(uri).body(Body::empty()).unwrap())
            .await
    }

    async fn get_with_token(&self, uri: &str, token: &str) -> Reply {
        self.send(
            Request::get(uri)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn post_form(&self, uri: &str, fields: &[(&str, &str)]) -> Reply {
        self.post_form_with(uri, fields, None).await
    }

    async fn post_form_with(
        &self,
        uri: &str,
        fields: &[(&str, &str)],
        basic: Option<(&str, &str)>,
    ) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request =
            Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some((id, secret)) = basic {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{id}:{secret}"));
            request = request.header(header::AUTHORIZATION, format!("Basic {encoded}"));
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    async fn post_json(&self, uri: &str, body: &Value) -> Reply {
        self.send(
            Request::post(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }

    async fn register(&self, body: Value) -> Value {
        let reply = self.post_json("/register", &body).await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.json()
    }

    async fn public_client(&self) -> String {
        let client = self
            .register(json!({
                "redirect_uris": [REDIRECT],
                "client_name": "Test <App>",
                "token_endpoint_auth_method": "none",
            }))
            .await;
        client["client_id"].as_str().unwrap().to_owned()
    }

    fn authorize_uri(client_id: &str, redirect_uri: &str) -> String {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("state", "st@te"),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
                ("scope", "mail"),
                ("resource", "https://mail.example.com/mcp"),
            ])
            .finish();
        format!("/authorize?{query}")
    }

    /// Opens the sign-in page and returns the pending request ID.
    async fn start(&self, client_id: &str, redirect_uri: &str) -> String {
        let reply = self
            .get(&Self::authorize_uri(client_id, redirect_uri))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        request_id(&reply.body)
    }

    async fn sign_in(&self, request_id: &str, email: &str, password: &str) -> Reply {
        self.sign_in_from(request_id, email, password, "192.0.2.1")
            .await
    }

    /// Signs in with `X-Forwarded-For: ip` (tests configure that header).
    async fn sign_in_from(&self, request_id: &str, email: &str, password: &str, ip: &str) -> Reply {
        self.sign_in_with(request_id, email, password, ip, "auto")
            .await
    }

    /// Signs in choosing the mail server `imap_server`.
    async fn sign_in_with(
        &self,
        request_id: &str,
        email: &str,
        password: &str,
        ip: &str,
        imap_server: &str,
    ) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("request_id", request_id),
                ("email", email),
                ("password", password),
                ("imap_server", imap_server),
                ("action", "connect"),
            ])
            .finish();
        self.send(
            Request::post("/authorize")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ISSUER)
                .header("x-forwarded-for", ip)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    /// Posts the sign-in form. `origin` and `referer` are omitted when
    /// `None`, so a test can send one without the other.
    async fn post_authorize(
        &self,
        fields: &[(&str, &str)],
        origin: Option<&str>,
        referer: Option<&str>,
    ) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request = Request::post("/authorize")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(referer) = referer {
            request = request.header(header::REFERER, referer);
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    /// Runs the whole flow and returns the token response.
    async fn tokens(&self, client_id: &str) -> Value {
        let request_id = self.start(client_id, REDIRECT).await;
        let reply = self.sign_in(&request_id, EMAIL, PASSWORD).await;
        let code = query_param(&reply.location(), "code").unwrap();
        let reply = self
            .post_form(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("redirect_uri", REDIRECT),
                    ("client_id", client_id),
                    ("code_verifier", VERIFIER),
                ],
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        reply.json()
    }
}

impl TestApp {
    /// Posts a form to the account page with the given cookie and `Origin`.
    async fn post_account(
        &self,
        uri: &str,
        fields: &[(&str, &str)],
        cookie: Option<&str>,
        origin: Option<&str>,
    ) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        let mut request =
            Request::post(uri).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    async fn get_account(&self, cookie: &str) -> Reply {
        self.send(
            Request::get("/account")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// Signs in on the account page and returns the session cookie pair.
    async fn account_session(&self) -> String {
        self.account_sign_in(EMAIL, PASSWORD).await
    }

    /// Signs in on the account page as `email` and returns the session cookie.
    async fn account_sign_in(&self, email: &str, password: &str) -> String {
        let reply = self
            .post_account(
                "/account/sign-in",
                &[("email", email), ("password", password)],
                None,
                Some(ISSUER),
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        let cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
        cookie.split(';').next().unwrap().to_owned()
    }
}

fn csrf(html: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).unwrap() + marker.len();
    let end = start + html[start..].find('"').unwrap();
    html[start..end].to_owned()
}

fn request_id(html: &str) -> String {
    let marker = "name=\"request_id\" value=\"";
    let start = html.find(marker).unwrap() + marker.len();
    let end = start + html[start..].find('"').unwrap();
    html[start..end].to_owned()
}

/// Installs a trigger that makes `touch_client`'s update fail. Reads of the
/// client still succeed, so the token request gets as far as recording activity.
async fn fail_client_activity_updates(app: &TestApp) {
    use sqlx::Connection as _;
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(app.dir.path().join("auth.db"))
        .busy_timeout(std::time::Duration::from_secs(5));
    let mut conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_client_touch
         BEFORE UPDATE ON oauth_clients
         BEGIN
             SELECT RAISE(ABORT, 'touch failed');
         END",
    )
    .execute(&mut conn)
    .await
    .unwrap();
    conn.close().await.unwrap();
}

#[tokio::test]
async fn code_exchange_returns_tokens_when_client_activity_cannot_be_recorded() {
    let app = app().await;
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;
    let signed_in = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    let code = query_param(&signed_in.location(), "code").unwrap();
    fail_client_activity_updates(&app).await;

    let reply = app
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("client_id", &client_id),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let access = reply.json()["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        app.get_with_token("/mcp", &access).await.status,
        StatusCode::OK,
        "the committed access token is usable even though activity was not recorded"
    );
}

#[tokio::test]
async fn publishes_discovery_documents() {
    let app = app().await;
    let unauthorized = app.get("/mcp").await;
    assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
    let challenge = unauthorized.headers[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap();
    assert_eq!(
        challenge,
        "Bearer resource_metadata=\"https://mail.example.com/.well-known/oauth-protected-resource/mcp\""
    );

    let resource = app
        .get("/.well-known/oauth-protected-resource/mcp")
        .await
        .json();
    assert_eq!(resource["resource"], "https://mail.example.com/mcp");
    assert_eq!(resource["authorization_servers"], json!([ISSUER]));
    assert_eq!(
        app.get("/.well-known/oauth-protected-resource")
            .await
            .json(),
        resource
    );

    let server = app
        .get("/.well-known/oauth-authorization-server")
        .await
        .json();
    assert_eq!(server["issuer"], ISSUER);
    assert_eq!(
        server["authorization_endpoint"],
        "https://mail.example.com/authorize"
    );
    assert_eq!(server["token_endpoint"], "https://mail.example.com/token");
    assert_eq!(
        server["registration_endpoint"],
        "https://mail.example.com/register"
    );
    assert_eq!(server["code_challenge_methods_supported"], json!(["S256"]));

    for (path, content_type) in [
        ("/oauth/icon.svg", "image/svg+xml"),
        ("/oauth/logo.svg", "image/svg+xml"),
        ("/favicon.ico", "image/x-icon"),
        ("/favicon.svg", "image/svg+xml"),
        ("/apple-touch-icon.png", "image/png"),
        ("/icon-192.png", "image/png"),
        ("/icon-512.png", "image/png"),
        ("/site.webmanifest", "application/manifest+json"),
        ("/assets/css/tokens.css", "text/css"),
        ("/assets/css/app.css", "text/css"),
        ("/assets/css/postkeep.css", "text/css"),
        ("/assets/js/app.js", "text/javascript"),
        ("/assets/fonts/Geist-Variable.woff2", "font/woff2"),
        ("/assets/providers/icloud.svg", "image/svg+xml"),
        ("/assets/providers/fastmail.svg", "image/svg+xml"),
        ("/assets/providers/yahoo.svg", "image/svg+xml"),
        ("/assets/providers/gmail.svg", "image/svg+xml"),
        (
            "/assets/providers/microsoft/ms-symbollockup_signin_light.svg",
            "image/svg+xml",
        ),
        ("/assets/providers/google/signin-dark@2x.png", "image/png"),
    ] {
        let asset = app.get(path).await;
        assert_eq!(asset.status, StatusCode::OK, "{path}");
        assert!(
            asset.headers[header::CONTENT_TYPE]
                .to_str()
                .unwrap()
                .starts_with(content_type),
            "{path}"
        );
        assert_eq!(asset.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }
}

#[tokio::test]
async fn full_authorization_code_flow() {
    let app = app().await;
    let client_id = app.public_client().await;

    // The sign-in page: escaped client name, guide, security headers.
    let page = app
        .get(&TestApp::authorize_uri(
            &client_id,
            "http://127.0.0.1:51000/callback",
        ))
        .await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains("Test &#60;App&#62;") || page.body.contains("Test &lt;App&gt;"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Test <App>"));
    assert!(page.body.contains("https://account.apple.com"));
    assert!(page.body.contains("https://support.apple.com/en-us/102654"));
    assert!(page.body.contains("App-Specific Passwords"));
    assert!(page.body.contains("<code><bdi>127.0.0.1</bdi></code>"));
    assert!(
        page.body.contains("<bdi>Test &lt;App&gt;</bdi>")
            || page.body.contains("<bdi>Test &#60;App&#62;</bdi>"),
        "{}",
        page.body
    );
    let csp = page.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("script-src 'self'"));
    assert!(csp.contains("font-src 'self'"));
    assert!(!csp.contains("unsafe-inline"));
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    // The form comes before the guide (mobile shows it first), and the
    // guide is a native disclosure, open by default.
    let form_at = page.body.find("action=\"/authorize\"").unwrap();
    let guide_at = page.body.find("id=\"guide\"").unwrap();
    assert!(form_at < guide_at);
    assert!(
        page.body
            .contains("<details class=\"guide\" id=\"guide\" open")
    );
    assert!(page.body.contains("href=\"#guide\""));
    assert!(!page.body.contains("Skip to sign in"));
    assert!(!page.body.contains("<script>") && !page.body.contains(" style=\""));
    let request_id = request_id(&page.body);

    // A wrong password re-renders the page with an error and keeps the email.
    let wrong = app
        .sign_in(&request_id, "Me@iCloud.com", "wrong-pass-word-xx")
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert!(
        wrong.body.contains("didn&#39;t accept")
            || wrong.body.contains("accept that address")
            || wrong.body.contains("didn&#x27;t accept"),
        "{}",
        wrong.body
    );
    assert!(wrong.body.contains("value=\"me@icloud.com\""));

    // The right one (pasted with dashes) redirects back with a code.
    let ok = app
        .sign_in(&request_id, " ME@icloud.com ", "abcd-abcd-abcd-abcd")
        .await;
    assert_eq!(ok.status, StatusCode::SEE_OTHER, "{}", ok.body);
    let location = ok.location();
    assert_eq!(location.port(), Some(51000));
    assert_eq!(query_param(&location, "state").as_deref(), Some("st@te"));
    assert_eq!(query_param(&location, "iss").as_deref(), Some(ISSUER));
    let code = query_param(&location, "code").unwrap();

    // The pending request is gone once used.
    let again = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    assert!(again.body.contains("expired"));

    // A wrong verifier burns the code.
    let token_fields = |verifier: &'static str| {
        vec![
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "http://127.0.0.1:51000/callback"),
            ("client_id", client_id.as_str()),
            ("code_verifier", verifier),
        ]
    };
    let good = app.post_form("/token", &token_fields(VERIFIER)).await;
    assert_eq!(good.status, StatusCode::OK, "{}", good.body);
    assert_eq!(good.headers[header::CACHE_CONTROL], "no-store");
    let tokens = good.json();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 3600);
    assert_eq!(tokens["scope"], "mail");
    // The access token opens the MCP endpoint.
    let access = tokens["access_token"].as_str().unwrap();
    let mcp = app.get_with_token("/mcp", access).await;
    assert_eq!(mcp.status, StatusCode::OK);
    assert_ne!(mcp.body, "");
    let bad = app.get_with_token("/mcp", "not-a-token").await;
    assert_eq!(bad.status, StatusCode::UNAUTHORIZED);
    assert!(
        bad.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("invalid_token")
    );

    // Refresh tokens rotate.
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let refreshed = app
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.body);
    let refreshed = refreshed.json();
    assert_ne!(refreshed["refresh_token"], tokens["refresh_token"]);

    // Revoking the new refresh token revokes the grant, access tokens too.
    let new_access = refreshed["access_token"].as_str().unwrap();
    assert_eq!(
        app.get_with_token("/mcp", new_access).await.status,
        StatusCode::OK
    );
    let revoked = app
        .post_form(
            "/revoke",
            &[
                ("token", refreshed["refresh_token"].as_str().unwrap()),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(
        app.get_with_token("/mcp", new_access).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.get_with_token("/mcp", access).await.status,
        StatusCode::UNAUTHORIZED
    );
}

/// A client that presents another client's token gets the same 200 as for
/// an unknown token, and the token keeps working (RFC 7009 section 2.1).
#[tokio::test]
async fn revoke_leaves_another_clients_token_alone() {
    let app = app().await;
    let owner = app.public_client().await;
    let other = app.public_client().await;
    let request_id = app.start(&owner, REDIRECT).await;
    let signed_in = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    let code = query_param(&signed_in.location(), "code").unwrap();
    let issued = app
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("client_id", &owner),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(issued.status, StatusCode::OK, "{}", issued.body);
    let issued = issued.json();
    let access = issued["access_token"].as_str().unwrap();
    let refresh = issued["refresh_token"].as_str().unwrap();

    for token in [access, refresh] {
        let reply = app
            .post_form("/revoke", &[("token", token), ("client_id", &other)])
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    }
    assert_eq!(
        app.get_with_token("/mcp", access).await.status,
        StatusCode::OK,
        "the other client must not revoke the grant"
    );

    let unknown = app
        .post_form(
            "/revoke",
            &[("token", "not-a-token"), ("client_id", &owner)],
        )
        .await;
    assert_eq!(unknown.status, StatusCode::OK);

    let revoked = app
        .post_form("/revoke", &[("token", refresh), ("client_id", &owner)])
        .await;
    assert_eq!(revoked.status, StatusCode::OK);
    assert_eq!(
        app.get_with_token("/mcp", access).await.status,
        StatusCode::UNAUTHORIZED
    );
}

/// Replays revoke the grant (OAuth 2.1 section 4.1.3, RFC 9700 section
/// 4.14.2): a stolen code or refresh token is useless to whoever comes
/// second, and the first party's tokens stop working too.
#[tokio::test]
async fn reused_codes_and_refresh_tokens_revoke_the_grant() {
    let app = app_with(|config| config.refresh_reuse_grace = Duration::ZERO).await;
    let client_id = app.public_client().await;
    let refresh_with = async |token: &str| {
        app.post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", token),
                ("client_id", &client_id),
            ],
        )
        .await
    };

    let request_id = app.start(&client_id, REDIRECT).await;
    let signed_in = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    let code = query_param(&signed_in.location(), "code").unwrap();
    let fields = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("client_id", client_id.as_str()),
        ("code_verifier", VERIFIER),
    ];
    let first = app.post_form("/token", &fields).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let first = first.json();
    let access = first["access_token"].as_str().unwrap();
    assert_eq!(
        app.get_with_token("/mcp", access).await.status,
        StatusCode::OK
    );
    let replay = app.post_form("/token", &fields).await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.json()["error"], "invalid_grant");
    assert!(replay.body.contains("already used"), "{}", replay.body);
    assert_eq!(
        app.get_with_token("/mcp", access).await.status,
        StatusCode::UNAUTHORIZED
    );
    let refresh = first["refresh_token"].as_str().unwrap();
    assert_eq!(refresh_with(refresh).await.json()["error"], "invalid_grant");

    let tokens = app.tokens(&client_id).await;
    let old_refresh = tokens["refresh_token"].as_str().unwrap();
    let rotated = refresh_with(old_refresh).await;
    assert_eq!(rotated.status, StatusCode::OK, "{}", rotated.body);
    let rotated = rotated.json();
    let new_access = rotated["access_token"].as_str().unwrap();
    assert_eq!(
        app.get_with_token("/mcp", new_access).await.status,
        StatusCode::OK
    );
    let replay = refresh_with(old_refresh).await;
    assert_eq!(replay.json()["error"], "invalid_grant");
    assert!(replay.body.contains("already used"), "{}", replay.body);
    assert_eq!(
        app.get_with_token("/mcp", new_access).await.status,
        StatusCode::UNAUTHORIZED
    );
    let new_refresh = rotated["refresh_token"].as_str().unwrap();
    assert_eq!(
        refresh_with(new_refresh).await.json()["error"],
        "invalid_grant"
    );
}

#[tokio::test]
async fn refresh_reuse_grace_keeps_both_rotations() {
    let app = app_with(|_| {}).await;
    let strict = app_sharing(&app, |config| config.refresh_reuse_grace = Duration::ZERO).await;
    let client_id = app.public_client().await;
    let tokens = app.tokens(&client_id).await;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let fields = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh),
        ("client_id", &client_id),
    ];
    let one = app.post_form("/token", &fields).await;
    let two = app.post_form("/token", &fields).await;
    assert_eq!(one.status, StatusCode::OK, "{}", one.body);
    assert_eq!(two.status, StatusCode::OK, "{}", two.body);
    let one = one.json();
    let two = two.json();
    assert_ne!(one["access_token"], two["access_token"]);
    assert_ne!(one["refresh_token"], two["refresh_token"]);
    for pair in [&one, &two] {
        assert_eq!(
            app.get_with_token("/mcp", pair["access_token"].as_str().unwrap())
                .await
                .status,
            StatusCode::OK
        );
    }
    assert_eq!(
        strict.post_form("/token", &fields).await.json()["error"],
        "invalid_grant"
    );
    for pair in [&one, &two] {
        assert_eq!(
            app.get_with_token("/mcp", pair["access_token"].as_str().unwrap())
                .await
                .status,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn rejects_bad_authorization_requests() {
    let app = app().await;
    let client_id = app.public_client().await;

    // Unknown client or unregistered redirect: an error page, no redirect.
    let unknown = app.get(&TestApp::authorize_uri("nope", REDIRECT)).await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    assert!(unknown.headers.get(header::LOCATION).is_none());
    assert!(
        unknown.body.contains("This link can&#39;t be used"),
        "{}",
        unknown.body
    );
    let foreign = app
        .get(&TestApp::authorize_uri(
            &client_id,
            "https://evil.example/cb",
        ))
        .await;
    assert_eq!(foreign.status, StatusCode::BAD_REQUEST);
    assert!(foreign.headers.get(header::LOCATION).is_none());

    // Other errors go back to the client.
    for (query, error) in [
        ("response_type=token", "unsupported_response_type"),
        (
            "response_type=code&code_challenge_method=S256",
            "invalid_request",
        ),
        (
            &format!("response_type=code&code_challenge={CHALLENGE}&code_challenge_method=plain"),
            "invalid_request",
        ),
        (
            &format!(
                "response_type=code&code_challenge={CHALLENGE}&code_challenge_method=S256&resource=https://other.example/mcp"
            ),
            "invalid_target",
        ),
    ] {
        let uri =
            format!("/authorize?client_id={client_id}&redirect_uri={REDIRECT}&state=s&{query}");
        let reply = app.get(&uri).await;
        assert_eq!(
            reply.status,
            StatusCode::SEE_OTHER,
            "{query}: {}",
            reply.body
        );
        let location = reply.location();
        assert_eq!(
            query_param(&location, "error").as_deref(),
            Some(error),
            "{query}"
        );
        assert_eq!(query_param(&location, "state").as_deref(), Some("s"));
    }

    // For a web redirect URI the same errors are a page, so a registered
    // client cannot use this server as an open redirector.
    let web = app
        .register(json!({
            "redirect_uris": ["https://client.example/cb"],
            "token_endpoint_auth_method": "none",
        }))
        .await;
    let web_id = web["client_id"].as_str().unwrap();
    let uri = format!(
        "{}&response_type=token",
        TestApp::authorize_uri(web_id, "https://client.example/cb")
            .replace("response_type=code&", "")
    );
    let reply = app.get(&uri).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert!(reply.headers.get(header::LOCATION).is_none());
    assert!(
        reply.body.contains("unsupported_response_type"),
        "{}",
        reply.body
    );

    // Cancelling returns access_denied.
    let request_id = app.start(&client_id, REDIRECT).await;
    let cancel = app
        .post_authorize(
            &[("request_id", &request_id), ("action", "cancel")],
            Some(ISSUER),
            None,
        )
        .await;
    assert_eq!(cancel.status, StatusCode::SEE_OTHER);
    assert_eq!(
        query_param(&cancel.location(), "error").as_deref(),
        Some("access_denied")
    );
}

/// Answers every refused request with `418` and what it was given.
struct EchoPage;

impl InvalidRequestPage for EchoPage {
    fn page(&self, request: &axum::http::request::Parts, reason: &str) -> axum::response::Response {
        let cookie = request
            .headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("none");
        let body = format!(
            "{} {} | {reason} | cookie={cookie}",
            request.method, request.uri
        );
        (StatusCode::IM_A_TEAPOT, body).into_response()
    }
}

#[tokio::test]
async fn an_embeddings_page_replaces_the_page_of_a_refused_request() {
    let app = app().await;
    app.state.set_invalid_request_page(Arc::new(EchoPage));
    let client_id = app.public_client().await;
    let echoed = async |reply: Reply| {
        assert_eq!(reply.status, StatusCode::IM_A_TEAPOT, "{}", reply.body);
        reply.body
    };

    let no_client = app
        .send(
            Request::get("/authorize")
                .header(header::COOKIE, "theme=dark")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        echoed(no_client).await,
        "GET /authorize | The authorization request has no client_id. | cookie=theme=dark"
    );
    let unknown = echoed(app.get(&TestApp::authorize_uri("nope", REDIRECT)).await).await;
    assert!(
        unknown.contains("| The app asking for access is not registered with this server. |"),
        "{unknown}"
    );
    let foreign = echoed(
        app.get(&TestApp::authorize_uri(
            &client_id,
            "https://evil.example/cb",
        ))
        .await,
    )
    .await;
    assert!(
        foreign.contains("| The redirect address does not match the app's registration. |"),
        "{foreign}"
    );
    let web = app
        .register(json!({
            "redirect_uris": ["https://client.example/cb"],
            "token_endpoint_auth_method": "none",
        }))
        .await;
    let web_uri = format!(
        "{}&response_type=token",
        TestApp::authorize_uri(
            web["client_id"].as_str().unwrap(),
            "https://client.example/cb"
        )
        .replace("response_type=code&", "")
    );
    let web_error = echoed(app.get(&web_uri).await).await;
    assert!(
        web_error.contains("| The app sent an invalid request (unsupported_response_type: "),
        "{web_error}"
    );
    let form = echoed(app.post_authorize(&[], Some(ISSUER), None).await).await;
    assert_eq!(
        form,
        "POST /authorize | The sign-in form was incomplete. | cookie=none"
    );

    // A valid request, and an error that goes back to a loopback app, stay
    // the server's.
    app.start(&client_id, REDIRECT).await;
    let back = app
        .get(&format!(
            "/authorize?client_id={client_id}&redirect_uri={REDIRECT}&state=s&response_type=token"
        ))
        .await;
    assert_eq!(back.status, StatusCode::SEE_OTHER, "{}", back.body);
    assert_eq!(
        query_param(&back.location(), "error").as_deref(),
        Some("unsupported_response_type")
    );
}

#[tokio::test]
async fn authorize_post_requires_the_servers_own_origin() {
    let app = app().await;
    let client = app
        .register(json!({
            "redirect_uris": ["https://attacker.example/cb"],
            "token_endpoint_auth_method": "none",
        }))
        .await;
    let client_id = client["client_id"].as_str().unwrap();
    let redirect = "https://attacker.example/cb";

    // A cross-site cancel must not redirect, and must leave the request
    // in place so the user can still finish it.
    let request_id = app.start(client_id, redirect).await;
    let cross = app
        .post_authorize(
            &[("request_id", &request_id), ("action", "cancel")],
            Some("https://attacker.example"),
            None,
        )
        .await;
    assert_eq!(cross.status, StatusCode::FORBIDDEN, "{}", cross.body);
    assert!(cross.headers.get(header::LOCATION).is_none());
    assert!(
        cross.body.contains("This form has expired"),
        "{}",
        cross.body
    );
    assert!(!cross.body.contains("attacker.example"), "{}", cross.body);

    let same = app
        .post_authorize(
            &[("request_id", &request_id), ("action", "cancel")],
            Some(ISSUER),
            None,
        )
        .await;
    assert_eq!(same.status, StatusCode::SEE_OTHER, "{}", same.body);
    let location = same.location();
    assert_eq!(
        query_param(&location, "error").as_deref(),
        Some("access_denied")
    );
    assert!(location.as_str().starts_with(redirect), "{location}");

    // No `Origin`, and a `Referer` from another site, is still refused.
    // A same-origin `Referer` (what `Referrer-Policy: same-origin` sends)
    // is accepted, and the earlier refusal did not consume the request.
    let request_id = app.start(client_id, redirect).await;
    let foreign = app
        .post_authorize(
            &[("request_id", &request_id), ("action", "cancel")],
            None,
            Some("https://attacker.example/phish"),
        )
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN, "{}", foreign.body);
    assert!(foreign.headers.get(header::LOCATION).is_none());

    let page = format!("{ISSUER}/authorize");
    let referer = app
        .post_authorize(
            &[("request_id", &request_id), ("action", "cancel")],
            None,
            Some(&page),
        )
        .await;
    assert_eq!(referer.status, StatusCode::SEE_OTHER, "{}", referer.body);
    assert_eq!(
        query_param(&referer.location(), "error").as_deref(),
        Some("access_denied")
    );

    // The credential post is the same check: a cross-site form with the
    // victim's password must not complete an attacker-chosen request.
    let request_id = app.start(client_id, redirect).await;
    let login = app
        .post_authorize(
            &[
                ("request_id", &request_id),
                ("email", EMAIL),
                ("password", PASSWORD),
                ("action", "connect"),
            ],
            Some("https://attacker.example"),
            None,
        )
        .await;
    assert_eq!(login.status, StatusCode::FORBIDDEN, "{}", login.body);
    assert!(login.headers.get(header::LOCATION).is_none());
    let still_there = app
        .post_authorize(
            &[("request_id", &request_id), ("action", "cancel")],
            Some(ISSUER),
            None,
        )
        .await;
    assert_eq!(
        still_there.status,
        StatusCode::SEE_OTHER,
        "{}",
        still_there.body
    );
    assert_eq!(
        query_param(&still_there.location(), "error").as_deref(),
        Some("access_denied")
    );
}

/// The stored server of the account with `email`.
async fn stored_server(app: &TestApp, email: &str) -> Option<String> {
    let url = format!("sqlite://{}", app.dir.path().join("auth.db").display());
    let store = Store::connect(&url, &MasterKey::parse(&app.key).unwrap())
        .await
        .unwrap();
    store
        .account_by_email(email, postkeep_store::Provider::Imap)
        .await
        .unwrap()
        .and_then(|account| account.imap_server)
}

#[tokio::test]
async fn sign_in_offers_and_records_mail_providers() {
    let app = app().await;
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;

    // Every preset is offered as a radio card with its own logo file; the
    // default server is preselected.
    let page = app.get(&TestApp::authorize_uri(&client_id, REDIRECT)).await;
    let body = &page.body;
    assert!(body.contains("name=\"imap_server\""), "{body}");
    for (id, name) in [
        ("icloud", "iCloud Mail"),
        ("fastmail", "Fastmail"),
        ("yahoo", "Yahoo Mail"),
        ("gmail", "Gmail"),
    ] {
        let checked = if id == "icloud" { " checked" } else { "" };
        assert!(
            body.contains(&format!("value=\"{id}\" id=\"provider-{id}\"{checked}>")),
            "{body}"
        );
        assert!(
            body.contains(&format!("src=\"/assets/providers/{id}.svg\"")),
            "{body}"
        );
        assert!(
            body.contains(&format!("<span class=\"picker__label\">{name}</span>")),
            "{body}"
        );
    }
    assert!(
        body.contains("https://login.yahoo.com/account/security"),
        "{body}"
    );
    assert!(
        body.contains("https://myaccount.google.com/apppasswords"),
        "{body}"
    );
    assert!(
        body.contains(
            "Not affiliated with or endorsed by Apple, Microsoft, Google, Yahoo or Fastmail"
        ),
        "{body}"
    );
    // No OAuth provider is configured, so no sign-in buttons.
    assert!(!body.contains("class=\"oauth\""), "{body}");
    assert!(
        body.contains(
            "<h2 class=\"section-title\" id=\"pw-title\">Connect with an app password</h2>"
        ),
        "{body}"
    );

    // A custom domain falls back to iCloud Mail unless another provider
    // is chosen; the choice is kept after an error.
    let reply = app
        .sign_in_with(&request_id, "me@example.org", PASSWORD, "192.0.2.1", "auto")
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        reply.body.contains("iCloud Mail didn&#39;t accept")
            || reply.body.contains("iCloud Mail didn&#x27;t accept"),
        "{}",
        reply.body
    );
    let reply = app
        .sign_in_with(&request_id, "me@example.org", "wrong", "192.0.2.1", "yahoo")
        .await;
    assert!(
        reply
            .body
            .contains("value=\"yahoo\" id=\"provider-yahoo\" checked>"),
        "{}",
        reply.body
    );
    let reply = app
        .sign_in_with(
            &request_id,
            "me@example.org",
            PASSWORD,
            "192.0.2.2",
            "yahoo",
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        stored_server(&app, "me@example.org").await.as_deref(),
        Some("yahoo")
    );

    // Known domains are detected; unknown choices are refused.
    let request_id = app.start(&client_id, REDIRECT).await;
    let reply = app
        .sign_in_with(
            &request_id,
            "me@fastmail.com",
            PASSWORD,
            "192.0.2.3",
            "nope",
        )
        .await;
    assert!(
        reply
            .body
            .contains("Choose one of the listed mail providers"),
        "{}",
        reply.body
    );
    // A provider's own domain wins over the picker.
    let reply = app
        .sign_in_with(
            &request_id,
            "me@fastmail.com",
            PASSWORD,
            "192.0.2.4",
            "yahoo",
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        stored_server(&app, "me@fastmail.com").await.as_deref(),
        Some("fastmail")
    );

    // Gmail addresses go to Gmail whatever is picked, in any case, and the app
    // password may be pasted in the groups Google shows it in.
    let request_id = app.start(&client_id, REDIRECT).await;
    let pasted = "abcd abcd abcd abcd";
    let reply = app
        .sign_in_with(&request_id, "Me@GMail.com", pasted, "192.0.2.5", "yahoo")
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        stored_server(&app, "me@gmail.com").await.as_deref(),
        Some("gmail")
    );
}

#[tokio::test]
async fn a_single_provider_needs_no_picker() {
    let app = app_with(|config| {
        config.imap_servers =
            postkeep_mail::ImapServers::new(vec![postkeep_mail::ImapPreset::ICloud], None);
    })
    .await;
    let client_id = app.public_client().await;
    let page = app.get(&TestApp::authorize_uri(&client_id, REDIRECT)).await;
    assert!(!page.body.contains("name=\"imap_server\""), "{}", page.body);
    assert!(
        page.body.contains("Get an app-specific password"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Get an app password<"), "{}", page.body);
    // Fastmail isn't offered, so its addresses go to iCloud Mail.
    let request_id = app.start(&client_id, REDIRECT).await;
    let reply = app.sign_in(&request_id, "me@fastmail.com", PASSWORD).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reply = app
        .sign_in_with(
            &request_id,
            "me@fastmail.com",
            PASSWORD,
            "192.0.2.9",
            "fastmail",
        )
        .await;
    assert!(
        reply
            .body
            .contains("Choose one of the listed mail providers"),
        "{}",
        reply.body
    );
}

const ICLOUD_OVERRIDE: &str = "This is an iCloud address, so iCloud Mail will be used.";
const FASTMAIL_OVERRIDE: &str = "This is a Fastmail address, so Fastmail will be used.";
const GMAIL_OVERRIDE: &str = "This is a Gmail address, so Gmail will be used.";

fn preset_domains_rendered(body: &str) -> bool {
    postkeep_mail::ImapPreset::ALL.iter().all(|preset| {
        let domains = preset.domains().join(" ");
        body.contains(&format!("data-domains=\"{domains}\""))
    })
}

fn form_override_shown(body: &str, hint: &str) -> bool {
    body.contains(&format!(
        "id=\"provider-override\" aria-live=\"polite\">{hint}</p>"
    ))
}

fn form_override_hidden(body: &str) -> bool {
    body.contains("id=\"provider-override\" aria-live=\"polite\" hidden></p>")
}

#[tokio::test]
async fn domain_override_is_explained_on_both_sign_in_pages() {
    let app = app_with(|config| {
        config.free_sign_in_failures = 30;
    })
    .await;
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;

    let authorize = app.get(&TestApp::authorize_uri(&client_id, REDIRECT)).await;
    let account = app.get("/account").await;
    for body in [&authorize.body, &account.body] {
        assert!(preset_domains_rendered(body), "{body}");
        assert!(
            body.contains(&format!("data-override-hint=\"{ICLOUD_OVERRIDE}\"")),
            "{body}"
        );
        assert!(
            body.contains(&format!("data-override-hint=\"{FASTMAIL_OVERRIDE}\"")),
            "{body}"
        );
        assert!(
            body.contains(&format!("data-override-hint=\"{GMAIL_OVERRIDE}\"")),
            "{body}"
        );
        assert!(form_override_hidden(body), "{body}");
        assert!(
            body.contains("aria-describedby=\"email-hint provider-override\""),
            "{body}"
        );
    }

    // A conflicting pick is kept on the form and the hint names the preset
    // `choose` will use. A matching pick, and an unknown domain, stay quiet.
    let mismatch = app
        .sign_in_with(
            &request_id,
            EMAIL,
            "wrongwrongwrongw",
            "192.0.2.21",
            "yahoo",
        )
        .await;
    assert_eq!(mismatch.status, StatusCode::BAD_REQUEST);
    assert!(
        form_override_shown(&mismatch.body, ICLOUD_OVERRIDE),
        "{}",
        mismatch.body
    );
    assert!(
        mismatch.body.contains("iCloud Mail didn"),
        "{}",
        mismatch.body
    );
    assert!(
        mismatch
            .body
            .contains("value=\"yahoo\" id=\"provider-yahoo\" checked>"),
        "{}",
        mismatch.body
    );

    let matched = app
        .sign_in_with(
            &request_id,
            "me@fastmail.com",
            "wrongwrongwrongw",
            "192.0.2.22",
            "fastmail",
        )
        .await;
    assert!(form_override_hidden(&matched.body), "{}", matched.body);
    assert!(
        !form_override_shown(&matched.body, FASTMAIL_OVERRIDE),
        "{}",
        matched.body
    );

    let unknown = app
        .sign_in_with(
            &request_id,
            "me@example.com",
            "wrongwrongwrongw",
            "192.0.2.23",
            "yahoo",
        )
        .await;
    assert!(form_override_hidden(&unknown.body), "{}", unknown.body);
    assert!(
        unknown
            .body
            .contains("value=\"yahoo\" id=\"provider-yahoo\" checked>"),
        "{}",
        unknown.body
    );

    let account_mismatch = app
        .post_account(
            "/account/sign-in",
            &[
                ("email", EMAIL),
                ("password", "wrongwrongwrongw"),
                ("imap_server", "yahoo"),
            ],
            None,
            Some(ISSUER),
        )
        .await;
    assert_eq!(account_mismatch.status, StatusCode::BAD_REQUEST);
    assert!(
        form_override_shown(&account_mismatch.body, ICLOUD_OVERRIDE),
        "{}",
        account_mismatch.body
    );

    let account_matched = app
        .post_account(
            "/account/sign-in",
            &[
                ("email", "me@fastmail.com"),
                ("password", "wrongwrongwrongw"),
                ("imap_server", "fastmail"),
            ],
            None,
            Some(ISSUER),
        )
        .await;
    assert!(
        form_override_hidden(&account_matched.body),
        "{}",
        account_matched.body
    );

    let account_unknown = app
        .post_account(
            "/account/sign-in",
            &[
                ("email", "me@example.com"),
                ("password", "wrongwrongwrongw"),
                ("imap_server", "yahoo"),
            ],
            None,
            Some(ISSUER),
        )
        .await;
    assert!(
        form_override_hidden(&account_unknown.body),
        "{}",
        account_unknown.body
    );

    // Success on the account page carries the same hint. A later sign-in
    // whose pick matches does not, and a forged override value is ignored.
    let signed_in = app
        .post_account(
            "/account/sign-in",
            &[
                ("email", EMAIL),
                ("password", PASSWORD),
                ("imap_server", "yahoo"),
            ],
            None,
            Some(ISSUER),
        )
        .await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    let location = signed_in.headers[header::LOCATION].to_str().unwrap();
    assert!(location.contains("notice=signed-in"), "{location}");
    assert!(location.contains("override=icloud"), "{location}");
    assert_eq!(stored_server(&app, EMAIL).await.as_deref(), Some("icloud"));
    let cookie = signed_in.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let page = app
        .send(
            Request::get(location)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body
            .contains(&format!("id=\"provider-override\">{ICLOUD_OVERRIDE}</p>")),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("You&#39;re signed in") || page.body.contains("You're signed in"),
        "{}",
        page.body
    );

    let again = app
        .post_account(
            "/account/sign-in",
            &[
                ("email", EMAIL),
                ("password", PASSWORD),
                ("imap_server", "icloud"),
            ],
            None,
            Some(ISSUER),
        )
        .await;
    let again_location = again.headers[header::LOCATION].to_str().unwrap();
    assert!(
        again_location.contains("notice=signed-in"),
        "{again_location}"
    );
    assert!(!again_location.contains("override="), "{again_location}");
    let again_cookie = again.headers[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let quiet = app
        .send(
            Request::get(again_location)
                .header(header::COOKIE, again_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        !quiet.body.contains("id=\"provider-override\""),
        "{}",
        quiet.body
    );

    let forged = app
        .send(
            Request::get("/account?notice=signed-in&override=%3Cscript%3Eyahoo")
                .header(header::COOKIE, again_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(!forged.body.contains("<script>"));
    assert!(
        !forged.body.contains("id=\"provider-override\""),
        "{}",
        forged.body
    );
    let wrong_preset = app
        .send(
            Request::get("/account?notice=signed-in&override=yahoo")
                .header(header::COOKIE, again_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        !wrong_preset.body.contains("id=\"provider-override\""),
        "{}",
        wrong_preset.body
    );
    assert!(
        !wrong_preset.body.contains("This is a Yahoo address"),
        "{}",
        wrong_preset.body
    );
}

#[tokio::test]
async fn validates_sign_in_input() {
    let app = app_with(|config| {
        config.allowed_emails = Some(vec![EMAIL.to_owned(), "down@icloud.com".to_owned()]);
        config.free_sign_in_failures = 1;
        config.sign_in_backoff_base = std::time::Duration::from_mins(1);
    })
    .await;
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;

    let cases = [
        ("not-an-address", PASSWORD, "full email address"),
        (EMAIL, " - ", "Paste your app password"),
        ("stranger@icloud.com", PASSWORD, "set up for that address"),
        ("down@icloud.com", PASSWORD, "reach iCloud Mail"),
    ];
    for (email, password, expected) in cases {
        let reply = app.sign_in(&request_id, email, password).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(reply.body.contains(expected), "{email}: {}", reply.body);
    }

    // Badly formed fields are marked next to the inputs, both at once, and
    // the first invalid field gets focus. The email is kept.
    let reply = app.sign_in(&request_id, "someone@icloud", "").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let body = &reply.body;
    assert!(body.contains("id=\"email-error\""), "{body}");
    assert!(body.contains("id=\"password-error\""), "{body}");
    assert!(body.contains("Check the highlighted fields"), "{body}");
    assert!(body.contains("value=\"someone@icloud\" aria-invalid=\"true\" aria-describedby=\"email-error email-hint provider-override\" autofocus"), "{body}");
    assert_eq!(body.matches("autofocus").count(), 1, "{body}");

    let reply = app.sign_in(&request_id, EMAIL, "").await;
    assert!(!reply.body.contains("id=\"email-error\""), "{}", reply.body);
    assert!(
        reply
            .body
            .contains("aria-describedby=\"password-error password-hint\" autofocus"),
        "{}",
        reply.body
    );

    // Two rejections start the backoff, even with the right password.
    for _ in 0..2 {
        app.sign_in(&request_id, EMAIL, "wrongwrongwrongw").await;
    }
    let locked = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    assert!(
        locked.body.contains("Too many failed attempts"),
        "{}",
        locked.body
    );
}

#[tokio::test]
async fn confidential_clients_authenticate() {
    let app = app().await;
    let client = app
        .register(json!({ "redirect_uris": ["https://client.example/cb"], "client_name": "Web" }))
        .await;
    assert_eq!(client["token_endpoint_auth_method"], "client_secret_basic");
    let client_id = client["client_id"].as_str().unwrap();
    let secret = client["client_secret"].as_str().unwrap();

    let request_id = app.start(client_id, "https://client.example/cb").await;
    let reply = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    let code = query_param(&reply.location(), "code").unwrap();
    let fields = [
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("code_verifier", VERIFIER),
    ];

    let missing = app
        .post_form(
            "/token",
            &[fields.as_slice(), &[("client_id", client_id)]].concat(),
        )
        .await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(missing.json()["error"], "invalid_client");
    let wrong = app
        .post_form_with("/token", &fields, Some((client_id, "wrong")))
        .await;
    assert_eq!(wrong.status, StatusCode::UNAUTHORIZED);
    assert!(wrong.headers.contains_key(header::WWW_AUTHENTICATE));

    // Failed client authentication does not consume the code.
    let ok = app
        .post_form_with("/token", &fields, Some((client_id, secret)))
        .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);
}

#[tokio::test]
async fn authorize_rechecks_redirects_stored_before_the_scheme_rules() {
    let app = app().await;
    let url = format!("sqlite://{}", app.dir.path().join("auth.db").display());
    let store = Store::connect(&url, &MasterKey::parse(&app.key).unwrap())
        .await
        .unwrap();

    // Registrations from before browser-handler schemes were rejected,
    // including scheme-replacement forms (`googlechromes://`,
    // `x-safari-https://`) that the OS opens as https.
    for uri in [
        "microsoft-edge:https://evil.example/phish",
        "googlechromes://evil.example/cb",
        "x-safari-https://evil.example/cb",
        "x-safari-http://evil.example/cb",
        "opera-http://evil.example/cb",
    ] {
        let planted = store
            .create_client(&NewClient {
                name: Some("Browser".to_owned()),
                redirect_uris: vec![uri.to_owned()],
                secret: None,
            })
            .await
            .unwrap();
        let reply = app.get(&TestApp::authorize_uri(&planted.id, uri)).await;
        assert_eq!(
            reply.status,
            StatusCode::BAD_REQUEST,
            "{uri}: {}",
            reply.body
        );
        assert!(
            reply.headers.get(header::LOCATION).is_none(),
            "{uri}: refused redirect must not be a 303: {}",
            reply.body
        );
        assert!(
            reply.body.contains("not allowed"),
            "{uri}: the code must not be redirected: {}",
            reply.body
        );
        assert!(!reply.body.contains("evil.example"), "{uri}");
    }

    // A private-use URI with no host is still a native app, and the consent
    // page shows the whole URI rather than only the scheme.
    let native = store
        .create_client(&NewClient {
            name: Some("Native".to_owned()),
            redirect_uris: vec!["com.example.app:/cb".to_owned()],
            secret: None,
        })
        .await
        .unwrap();
    let page = app
        .get(&TestApp::authorize_uri(&native.id, "com.example.app:/cb"))
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("com.example.app:/cb"),
        "consent page hid the redirect: {}",
        page.body
    );
}

#[tokio::test]
async fn registration_validates_metadata() {
    let app = app().await;
    for (body, error) in [
        (json!({}), "invalid_redirect_uri"),
        (
            json!({ "redirect_uris": ["http://evil.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["javascript:alert(1)"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["microsoft-edge:https://evil.example/phish"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["googlechromes://evil.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["x-safari-https://evil.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["x-safari-http://evil.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["opera-http://evil.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["ftp://files.example/cb"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["ms-settings:network"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": ["com.example.app:https://evil.example/phish"] }),
            "invalid_redirect_uri",
        ),
        // Line breaks would smuggle a second, unchecked URI into storage.
        (
            json!({ "redirect_uris": ["https://client.example/cb\njavascript:alert(1)"] }),
            "invalid_redirect_uri",
        ),
        (
            json!({ "redirect_uris": [REDIRECT], "grant_types": ["client_credentials"] }),
            "invalid_client_metadata",
        ),
        (
            json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "private_key_jwt" }),
            "invalid_client_metadata",
        ),
    ] {
        let reply = app.post_json("/register", &body).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(reply.json()["error"], error, "{body}");
    }
    let malformed = app
        .send(
            Request::post("/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{"))
                .unwrap(),
        )
        .await;
    assert_eq!(malformed.status, StatusCode::BAD_REQUEST);
    assert_eq!(malformed.json()["error"], "invalid_client_metadata");
}

#[tokio::test]
async fn tokens_for_other_resources_are_refused() {
    let app = app().await;
    let client_id = app.public_client().await;
    let tokens = app.tokens(&client_id).await;
    let refresh = tokens["refresh_token"].as_str().unwrap();
    let reply = app
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
                ("resource", "https://other.example/mcp"),
            ],
        )
        .await;
    assert_eq!(reply.json()["error"], "invalid_target");
    let unsupported = app
        .post_form(
            "/token",
            &[("grant_type", "password"), ("client_id", &client_id)],
        )
        .await;
    assert_eq!(unsupported.json()["error"], "unsupported_grant_type");
}

#[tokio::test(start_paused = true)]
async fn backoff_resists_deliberate_lockout() {
    use std::time::Duration;
    // A blocking task held for the test's life keeps the paused clock from jumping
    // ahead while the test awaits the database, so only `advance` moves it.
    let (_hold, held) = std::sync::mpsc::channel::<()>();
    tokio::task::spawn_blocking(move || held.recv());
    let app = app_with(|config| {
        config.client_ip_header = Some(header::HeaderName::from_static("x-forwarded-for"));
        config.free_sign_in_failures = 0;
        config.sign_in_backoff_base = Duration::from_secs(1);
        config.account_backoff_max = Duration::from_secs(1);
        config.ip_backoff_max = Duration::from_mins(15);
    })
    .await;
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;
    let attack = || app.sign_in_from(&request_id, EMAIL, "wrongwrongwrongw", "203.0.113.66");

    // An attacker guesses at the victim's address from one IP, waiting out
    // each backoff: 1 s, then 2 s, then 4 s for that IP.
    assert!(attack().await.body.contains("accept that address"));
    tokio::time::advance(Duration::from_millis(1050)).await;
    assert!(attack().await.body.contains("accept that address"));
    tokio::time::advance(Duration::from_millis(2050)).await;
    assert!(attack().await.body.contains("accept that address"));
    assert!(attack().await.body.contains("Wait"));

    // The real owner, elsewhere, waits at most the short account backoff
    // (1 s), while the attacker's IP still has about 3 s to wait.
    tokio::time::advance(Duration::from_millis(1050)).await;
    let owner = app
        .sign_in_from(&request_id, EMAIL, PASSWORD, "198.51.100.5")
        .await;
    assert_eq!(owner.status, StatusCode::SEE_OTHER, "{}", owner.body);
    assert!(query_param(&owner.location(), "code").is_some());

    // The attacker's IP is still backing off.
    let request_id = app.start(&client_id, REDIRECT).await;
    let again = app
        .sign_in_from(&request_id, EMAIL, "wrongwrongwrongw", "203.0.113.66")
        .await;
    assert!(again.body.contains("Wait"), "{}", again.body);
}

#[tokio::test]
async fn limits_client_registrations() {
    let app = app_with(|config| {
        config.registrations_per_ip = 2;
        config.max_clients = 3;
    })
    .await;
    let body = json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none" });
    let send = |ip: &'static str| {
        let body = body.clone();
        let app = &app;
        async move {
            app.send(
                Request::post("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("x-forwarded-for", ip)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
        }
    };
    // Without a configured header, all requests share the peer address.
    assert_eq!(send("192.0.2.1").await.status, StatusCode::CREATED);
    assert_eq!(send("192.0.2.2").await.status, StatusCode::CREATED);
    let limited = send("192.0.2.3").await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(
        limited.headers.contains_key(header::RETRY_AFTER)
            || limited.json()["error"] == "invalid_request"
    );

    let app = app_sharing(&app, |config| {
        config.client_ip_header = Some(header::HeaderName::from_static("x-forwarded-for"));
        config.max_clients = 3;
    })
    .await;
    let reply = app
        .send(
            Request::post("/register")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "198.51.100.1")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
    let full = app
        .send(
            Request::post("/register")
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", "198.51.100.2")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
    assert_eq!(
        full.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        full.body
    );
}

#[tokio::test]
async fn rate_limits_oauth_endpoints() {
    let app = app_with(|config| config.requests_per_minute = 3).await;
    for _ in 0..3 {
        let reply = app
            .post_form("/token", &[("grant_type", "refresh_token")])
            .await;
        assert_ne!(reply.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let limited = app
        .post_form("/token", &[("grant_type", "refresh_token")])
        .await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.contains_key(header::RETRY_AFTER));
    let page = app.get("/authorize?client_id=x").await;
    assert_eq!(page.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(page.body.contains("Too many requests"));
    // Discovery stays available.
    assert_eq!(
        app.get("/.well-known/oauth-authorization-server")
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn allowlist_applies_to_existing_tokens() {
    let app = app().await;
    let client_id = app.public_client().await;
    let tokens = app.tokens(&client_id).await;
    let access = tokens["access_token"].as_str().unwrap();
    let refresh = tokens["refresh_token"].as_str().unwrap();
    assert_eq!(
        app.get_with_token("/mcp", access).await.status,
        StatusCode::OK
    );

    // The operator later restricts the server to someone else.
    let restricted = app_sharing(&app, |config| {
        config.allowed_emails = Some(vec!["someone-else@icloud.com".to_owned()]);
    })
    .await;
    let denied = restricted.get_with_token("/mcp", access).await;
    assert_eq!(denied.status, StatusCode::UNAUTHORIZED);
    let refreshed = restricted
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(refreshed.status, StatusCode::BAD_REQUEST);
    assert_eq!(refreshed.json()["error"], "invalid_grant");
}

#[tokio::test]
async fn account_page_sign_in_and_session() {
    let app = app().await;

    // Signed out: the sign-in form.
    let page = app.get("/account").await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(
        page.body.contains("action=\"/account/sign-in\""),
        "{}",
        page.body
    );
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    // `no-referrer` would make browsers send `Origin: null` on the form post.
    assert_eq!(page.headers[header::REFERRER_POLICY], "same-origin");

    // Cross-site, opaque or origin-less posts are refused, even with good input.
    for origin in [None, Some("https://evil.example"), Some("null")] {
        let reply = app
            .post_account(
                "/account/sign-in",
                &[("email", EMAIL), ("password", PASSWORD)],
                None,
                origin,
            )
            .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert!(!reply.headers.contains_key(header::SET_COOKIE));
    }

    // Bad input is reported like on the OAuth sign-in page.
    let reply = app
        .post_account(
            "/account/sign-in",
            &[("email", EMAIL), ("password", "wrongwrongwrongw")],
            None,
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("accept that address"), "{}", reply.body);

    // A good sign-in sets a hardened session cookie.
    let reply = app
        .post_account(
            "/account/sign-in",
            &[("email", EMAIL), ("password", PASSWORD)],
            None,
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let set_cookie = reply.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        set_cookie.starts_with("__Host-postkeep_session="),
        "{set_cookie}"
    );
    for attribute in ["HttpOnly", "Secure", "SameSite=Lax", "Path=/"] {
        assert!(set_cookie.contains(attribute), "{set_cookie}");
    }
    let cookie = set_cookie.split(';').next().unwrap().to_owned();

    let page = app.get_account(&cookie).await;
    assert_eq!(page.status, StatusCode::OK);
    assert!(page.body.contains(EMAIL));
    assert!(page.body.contains("No apps connected yet"), "{}", page.body);
    assert!(page.body.contains("https://mail.example.com/mcp"));
    assert!(page.body.contains("iCloud Mail"));
    assert!(page.body.contains("action=\"/account/password\""));
    let token = csrf(&page.body);
    assert_eq!(token.len(), 43);

    // Notices come from fixed keys only.
    let noticed = app
        .send(
            Request::get("/account?notice=signed-in")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        noticed.body.contains("You&#39;re signed in") || noticed.body.contains("You're signed in")
    );
    let injected = app
        .send(
            Request::get("/account?notice=%3Cscript%3E")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(!injected.body.contains("<script>"));

    // Sign-out needs the CSRF token, then ends the session.
    let reply = app
        .post_account(
            "/account/sign-out",
            &[("csrf_token", "nope")],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    let reply = app
        .post_account(
            "/account/sign-out",
            &[("csrf_token", &token)],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert!(
        reply.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let page = app.get_account(&cookie).await;
    assert!(page.body.contains("action=\"/account/sign-in\""));
}

#[tokio::test]
async fn account_page_revokes_apps_and_deletes_data() {
    let app = app().await;
    let client_id = app.public_client().await;
    let tokens = app.tokens(&client_id).await;
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    assert_eq!(
        app.get_with_token("/mcp", &access).await.status,
        StatusCode::OK
    );

    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    assert!(
        page.body.contains("1 MCP client can use this mailbox."),
        "{}",
        page.body
    );
    assert!(page.body.contains(&format!("value=\"{client_id}\"")));
    let token = csrf(&page.body);

    // Revoking needs the confirmation box.
    let reply = app
        .post_account(
            "/account/revoke",
            &[("csrf_token", &token)],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert!(
        reply.headers[header::LOCATION]
            .to_str()
            .unwrap()
            .contains("confirm-revoke")
    );
    assert_eq!(
        app.get_with_token("/mcp", &access).await.status,
        StatusCode::OK
    );

    // A CSRF token from another session doesn't work.
    let other = app.account_session().await;
    let other_token = csrf(&app.get_account(&other).await.body);
    let reply = app
        .post_account(
            "/account/revoke",
            &[("csrf_token", &other_token), ("confirm", "yes")],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);

    let reply = app
        .post_account(
            "/account/revoke",
            &[("csrf_token", &token), ("confirm", "yes")],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert!(
        reply.headers[header::LOCATION]
            .to_str()
            .unwrap()
            .ends_with("notice=revoked")
    );
    assert_eq!(
        app.get_with_token("/mcp", &access).await.status,
        StatusCode::UNAUTHORIZED
    );
    let refreshed = app
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
                ("client_id", &client_id),
            ],
        )
        .await;
    assert_eq!(refreshed.json()["error"], "invalid_grant");

    // Deleting needs the address typed exactly.
    let reply = app
        .post_account(
            "/account/delete",
            &[
                ("csrf_token", &token),
                ("confirm_email", "someone@icloud.com"),
            ],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert!(
        reply.headers[header::LOCATION]
            .to_str()
            .unwrap()
            .contains("confirm-delete")
    );
    let reply = app
        .post_account(
            "/account/delete",
            &[
                ("csrf_token", &token),
                ("confirm_email", "  ME@icloud.com "),
            ],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert!(reply.body.contains("Your data was deleted"));
    assert!(
        reply.headers[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    // Every session of the account is gone.
    for session in [&cookie, &other] {
        let page = app.get_account(session).await;
        assert!(page.body.contains("action=\"/account/sign-in\""));
    }
}

/// The deletion listeners run while the account is still there. The
/// account listeners are told once after them, also when the deletion fails
/// or its request is dropped, so that a watcher a deletion listener stopped
/// starts again.
#[tokio::test]
async fn account_deletion_runs_the_deletion_listeners_first() {
    let app = app().await;
    let cookie = app.account_session().await;
    let store = app.state.store().clone();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let hang = Arc::new(AtomicBool::new(false));
    let started = Arc::new(tokio::sync::Notify::new());
    let (lookup, record) = (store.clone(), Arc::clone(&events));
    let (stuck, running) = (Arc::clone(&hang), Arc::clone(&started));
    app.state.add_deletion_listener(Arc::new(move |account| {
        let (lookup, record) = (lookup.clone(), Arc::clone(&record));
        let (stuck, running) = (Arc::clone(&stuck), Arc::clone(&running));
        Box::pin(async move {
            let there = lookup.account(account).await.unwrap().is_some();
            let seen = if there { "there" } else { "gone" };
            record.lock().unwrap().push(seen);
            if stuck.load(Ordering::SeqCst) {
                running.notify_one();
                std::future::pending::<()>().await;
            }
        })
    }));
    let record = Arc::clone(&events);
    app.state.add_account_listener(Arc::new(move |_| {
        record.lock().unwrap().push("changed");
    }));
    let keep = "CREATE TRIGGER keep BEFORE DELETE ON accounts \
                BEGIN SELECT RAISE(ABORT, 'kept'); END";
    sqlx::query(keep).execute(store.pool()).await.unwrap();
    let token = csrf(&app.get_account(&cookie).await.body);
    let fields = [("csrf_token", token.as_str()), ("confirm_email", EMAIL)];
    let delete = async || {
        app.post_account("/account/delete", &fields, Some(&cookie), Some(ISSUER))
            .await
    };

    let reply = delete().await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(*events.lock().unwrap(), ["there", "changed"]);

    // Dropped while the listener runs, as when the browser goes away.
    hang.store(true, Ordering::SeqCst);
    tokio::select! {
        _ = delete() => {}
        () = started.notified() => {}
    }
    hang.store(false, Ordering::SeqCst);
    let told = ["there", "changed", "there", "changed"];
    assert_eq!(*events.lock().unwrap(), told);

    sqlx::query("DROP TRIGGER keep")
        .execute(store.pool())
        .await
        .unwrap();
    let reply = delete().await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(events.lock().unwrap()[4..], ["there", "changed"]);
}

#[tokio::test]
async fn account_page_respects_the_allowlist() {
    let app = app().await;
    let cookie = app.account_session().await;
    // The same database, now restricted to someone else.
    let restricted = app_sharing(&app, |config| {
        config.allowed_emails = Some(vec!["other@icloud.com".to_owned()]);
    })
    .await;
    let page = restricted.get_account(&cookie).await;
    assert!(page.body.contains("action=\"/account/sign-in\""));
    let reply = restricted
        .post_account(
            "/account/sign-in",
            &[("email", EMAIL), ("password", PASSWORD)],
            None,
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("set up for that address"));
}

/// The value of a readonly input by id.
fn input_value(html: &str, id: &str) -> String {
    let marker = format!("id=\"{id}\"");
    let start = html.find(&marker).unwrap();
    let tag_end = start + html[start..].find('>').unwrap();
    let tag = &html[start..tag_end];
    let value_at = tag.find("value=\"").unwrap() + "value=\"".len();
    let value_end = value_at + tag[value_at..].find('"').unwrap();
    tag[value_at..value_end].to_owned()
}

fn webhook_fields<'a>(csrf: &'a str, url: &'a str, value: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("csrf_token", csrf),
        ("enabled", "on"),
        ("webhook_url", url),
        ("auth_header_name", "Authorization"),
        ("auth_header_value", value),
        ("hmac_signing", "on"),
    ]
}

#[tokio::test]
async fn account_page_hides_webhooks_when_off() {
    let app = app().await;
    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    assert!(!page.body.contains(ALERTS_TITLE), "{}", page.body);
    let csrf = csrf(&page.body);
    let reply = app
        .post_account(
            "/account/webhook",
            &webhook_fields(&csrf, "https://hooks.example.com/", "x"),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let remove = [("csrf_token", csrf.as_str()), ("all", "yes")];
    let reply = app
        .post_account(
            "/account/webhook/filters/remove",
            &remove,
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let switch = [
        ("csrf_token", csrf.as_str()),
        ("id", "x"),
        ("enabled", "off"),
    ];
    let reply = app
        .post_account(
            "/account/webhook/filters/enabled",
            &switch,
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    for path in [
        "/account/webhook/filters/add",
        "/account/webhook/filters/edit",
    ] {
        let fields = rule_fields(&csrf, "block", "from", "equals", "x");
        let reply = app
            .post_account(path, &fields, Some(&cookie), Some(ISSUER))
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn account_page_revokes_one_app() {
    let app = app().await;
    let (first, second) = (app.public_client().await, app.public_client().await);
    let first_tokens = app.tokens(&first).await;
    let second_tokens = app.tokens(&second).await;
    let first_access = first_tokens["access_token"].as_str().unwrap().to_owned();
    let second_access = second_tokens["access_token"].as_str().unwrap().to_owned();

    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    assert!(
        page.body.contains("2 MCP clients can use this mailbox."),
        "{}",
        page.body
    );
    let token = csrf(&page.body);

    // The CSRF token is required.
    let reply = app
        .post_account(
            "/account/clients/revoke",
            &[("csrf_token", "nope"), ("client_id", &first)],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    // So is the same origin.
    let reply = app
        .post_account(
            "/account/clients/revoke",
            &[("csrf_token", &token), ("client_id", &first)],
            Some(&cookie),
            Some("https://evil.example"),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert_eq!(
        app.get_with_token("/mcp", &first_access).await.status,
        StatusCode::OK
    );

    let reply = app
        .post_account(
            "/account/clients/revoke",
            &[("csrf_token", &token), ("client_id", &first)],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    assert_eq!(
        reply.headers[header::LOCATION].to_str().unwrap(),
        "/account?notice=client-revoked#apps"
    );
    assert_eq!(
        app.get_with_token("/mcp", &first_access).await.status,
        StatusCode::UNAUTHORIZED
    );
    let refreshed = app
        .post_form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                (
                    "refresh_token",
                    first_tokens["refresh_token"].as_str().unwrap(),
                ),
                ("client_id", &first),
            ],
        )
        .await;
    assert_eq!(refreshed.json()["error"], "invalid_grant");
    assert_eq!(
        app.get_with_token("/mcp", &second_access).await.status,
        StatusCode::OK,
        "other apps keep working"
    );
    let page = app.get_account(&cookie).await;
    assert!(page.body.contains("1 MCP client can use this mailbox."));

    // An unknown or empty client ID changes nothing.
    for client_id in ["unknown", ""] {
        let reply = app
            .post_account(
                "/account/clients/revoke",
                &[("csrf_token", &token), ("client_id", client_id)],
                Some(&cookie),
                Some(ISSUER),
            )
            .await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER);
    }
    assert_eq!(
        app.get_with_token("/mcp", &second_access).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn account_page_replaces_the_password() {
    let app = app().await;
    let client_id = app.public_client().await;
    let tokens = app.tokens(&client_id).await;
    let access = tokens["access_token"].as_str().unwrap().to_owned();
    let cookie = app.account_session().await;
    let other = app.account_session().await;
    let token = csrf(&app.get_account(&cookie).await.body);

    // A rejected password reopens the form with the error; nothing changes.
    let reply = app
        .post_account(
            "/account/password",
            &[("csrf_token", &token), ("password", "wrongwrongwrongw")],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(
        reply.body.contains("id=\"new_password-error\""),
        "{}",
        reply.body
    );
    assert!(reply.body.contains("disclose--setting\" open"));
    // An empty one too.
    let reply = app
        .post_account(
            "/account/password",
            &[("csrf_token", &token), ("password", " - ")],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    // CSRF is checked first.
    let reply = app
        .post_account(
            "/account/password",
            &[("csrf_token", "nope"), ("password", PASSWORD)],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::FORBIDDEN);
    assert!(
        app.get_account(&other)
            .await
            .body
            .contains("id=\"new_password\""),
        "a rejected password keeps other account sessions"
    );

    let reply = app
        .post_account(
            "/account/password",
            &[("csrf_token", &token), ("password", "abcd-abcd-abcd-abcd")],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.headers[header::LOCATION].to_str().unwrap(),
        "/account?notice=password-updated#security"
    );
    assert_eq!(
        app.get_with_token("/mcp", &access).await.status,
        StatusCode::OK,
        "apps keep their tokens"
    );
    let signed_out = app.get_account(&other).await;
    assert!(
        signed_out.body.contains("Sign in with an app password"),
        "the other session was ended: {}",
        signed_out.body
    );
    assert!(
        !signed_out.body.contains("id=\"new_password\""),
        "a signed-out session must not see the account page"
    );
    assert!(
        app.get_account(&cookie)
            .await
            .body
            .contains("id=\"new_password\""),
        "the session that changed the password stays signed in"
    );
}

#[tokio::test]
async fn account_page_says_the_mail_server_rejected_the_password_until_a_new_one_is_stored() {
    let app = app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = store.find_account(EMAIL).await.unwrap().unwrap().id;
    let notice = |body: &str| body.contains("id=\"password-rejected\"");
    assert!(!notice(&app.get_account(&cookie).await.body));

    store.mark_password_rejected(&account).await.unwrap();
    let page = app.get_account(&cookie).await.body;
    assert!(notice(&page), "{page}");
    assert!(page.contains("rejected the stored app-specific password"));
    assert!(page.contains("You can create one at <a href=\"https://account.apple.com\""));

    let fields = [("csrf_token", &csrf(&page)[..]), ("password", ALT_PASSWORD)];
    let reply = app
        .post_account("/account/password", &fields, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert!(!notice(&app.get_account(&cookie).await.body));
    assert_eq!(store.password_rejected_at(&account).await.unwrap(), None);
}

fn signed_in(body: &str) -> bool {
    body.contains("id=\"new_password\"")
}

#[tokio::test]
async fn signing_in_again_ends_sessions_only_when_the_password_changes() {
    let app = app().await;
    // A different account is not affected by this address's password.
    let other_account = app.account_sign_in("me@fastmail.com", PASSWORD).await;
    let first = app.account_session().await;
    assert!(signed_in(&app.get_account(&other_account).await.body));
    assert!(
        signed_in(&app.get_account(&first).await.body),
        "creating another account does not end the first session"
    );

    // The same password, pasted with the dashes an app password is shown with.
    let second = app.account_sign_in(EMAIL, "abcd-abcd-abcd-abcd").await;
    assert!(
        signed_in(&app.get_account(&first).await.body),
        "signing in again with the same password keeps the other session"
    );
    assert!(signed_in(&app.get_account(&second).await.body));
    assert!(signed_in(&app.get_account(&other_account).await.body));

    let rotated = app.account_sign_in(EMAIL, ALT_PASSWORD).await;
    let ended = app.get_account(&first).await;
    assert!(
        ended.body.contains("action=\"/account/sign-in\""),
        "the old session was ended: {}",
        ended.body
    );
    assert!(!signed_in(&ended.body));
    assert!(
        !signed_in(&app.get_account(&second).await.body),
        "every previous session of this account was ended"
    );
    assert!(
        signed_in(&app.get_account(&rotated).await.body),
        "the browser that set the new password stays signed in"
    );
    assert!(
        signed_in(&app.get_account(&other_account).await.body),
        "another account's session stays"
    );
}

#[tokio::test]
async fn authorize_with_a_new_password_ends_account_sessions() {
    let app = app().await;
    let cookie = app.account_session().await;
    let client_id = app.public_client().await;

    let request_id = app.start(&client_id, REDIRECT).await;
    let same = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    assert_eq!(same.status, StatusCode::SEE_OTHER, "{}", same.body);
    assert!(query_param(&same.location(), "code").is_some());
    assert!(
        signed_in(&app.get_account(&cookie).await.body),
        "authorizing with the same password keeps the account-page session"
    );

    let request_id = app.start(&client_id, REDIRECT).await;
    let changed = app.sign_in(&request_id, EMAIL, ALT_PASSWORD).await;
    assert_eq!(changed.status, StatusCode::SEE_OTHER, "{}", changed.body);
    assert!(
        query_param(&changed.location(), "code").is_some(),
        "the app still receives a code: {}",
        changed.body
    );
    let ended = app.get_account(&cookie).await;
    assert!(
        ended.body.contains("action=\"/account/sign-in\""),
        "authorize with a new password ends account-page sessions: {}",
        ended.body
    );
    assert!(!signed_in(&ended.body));
}

const PLAN_FULL: &str = "This workspace has all the mailboxes its plan includes.";
const DAY: i64 = 24 * 60 * 60;

/// A usage hook that refuses new mailboxes with one address, gives every
/// outbox lower ceilings, and records what it is asked: each mailbox as
/// `tenant email provider`, each outbox as `outbox tenant mailbox`.
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

    fn outbox_ceilings<'a>(&'a self, outbox: Outbox<'a>) -> CeilingsFuture<'a> {
        let asked = format!("outbox {} {}", outbox.tenant, outbox.mailbox.0);
        self.asked.lock().unwrap().push(asked);
        let ceilings = OutboxCeilings::new(14 * DAY, 2_000).with_max_filter_rules(1);
        Box::pin(std::future::ready(Some(ceilings)))
    }
}

#[tokio::test]
async fn the_usage_hook_decides_whether_a_sign_in_adds_a_mailbox() {
    let app = app().await;
    let plan = Plan::refusing(EMAIL);
    app.state.set_usage_hook(plan.clone());
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;

    let wrong = app.sign_in(&request_id, EMAIL, "qqqqqqqqqqqqqqqq").await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    let nothing: Vec<String> = Vec::new();
    assert_eq!(plan.take(), nothing, "a rejected password isn't asked");

    let shouted = EMAIL.to_uppercase();
    let refused = app.sign_in(&request_id, &shouted, PASSWORD).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert!(refused.body.contains(PLAN_FULL), "{}", refused.body);
    let fields = [("email", EMAIL), ("password", PASSWORD)];
    let refused = app
        .post_account("/account/sign-in", &fields, None, Some(ISSUER))
        .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{}", refused.body);
    assert!(refused.body.contains(PLAN_FULL), "{}", refused.body);
    let store = app.state.store();
    assert!(store.find_account(EMAIL).await.unwrap().is_none());
    let asked = format!("default {EMAIL} imap");
    assert_eq!(plan.take(), [asked.as_str(); 2]);

    // Another address is asked about once: signing in again adds nothing.
    let allowed = app
        .sign_in_with(
            &request_id,
            "me@example.org",
            PASSWORD,
            "192.0.2.1",
            "yahoo",
        )
        .await;
    assert_eq!(allowed.status, StatusCode::SEE_OTHER, "{}", allowed.body);
    app.account_sign_in("me@example.org", PASSWORD).await;
    assert_eq!(plan.take(), ["default me@example.org imap"]);

    // A mailbox the tenant already has signs in without asking.
    let password = SecretString::from(PASSWORD.to_owned());
    store.upsert_account(EMAIL, &password).await.unwrap();
    app.account_sign_in(EMAIL, PASSWORD).await;
    assert_eq!(plan.take(), nothing);
}

#[tokio::test]
async fn the_usage_hook_can_lower_the_outbox_ceilings_on_the_account_page() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let defaults = "Events are kept for 7 days (server default), at most 1000 (server default).";
    let page = app.get_account(&cookie).await;
    let server = format!("{defaults} Up to 30 days and 10000 events.");
    assert!(page.body.contains(&server), "{}", page.body);

    let plan = Plan::refusing("nobody@example.com");
    app.state.set_usage_hook(plan.clone());
    let page = app.get_account(&cookie).await;
    let lower = format!("{defaults} Up to 14 days and 2000 events.");
    assert!(page.body.contains(&lower), "{}", page.body);
    let store = app.state.store();
    let account = store.find_account(EMAIL).await.unwrap().unwrap().id;
    assert_eq!(plan.take(), [format!("outbox default {}", account.0)]);

    // Set before the ceilings were lowered: shown as stored, which is what
    // pruning keeps.
    let settings = WebhookSettings {
        enabled: false,
        url: "https://hooks.example.com/me".to_owned(),
        auth_header: None,
        signing: true,
        signing_secret: SecretString::from("whsec_test".to_owned()),
        include_sender: false,
    };
    store.save_webhook(&account, &settings).await.unwrap();
    add_rule(
        store,
        &account,
        "block",
        "from",
        "equals",
        "one@example.com",
    )
    .await;
    add_rule(
        store,
        &account,
        "block",
        "from",
        "equals",
        "two@example.com",
    )
    .await;
    let month = OutboxLimitChange::Set(30 * DAY);
    store
        .set_webhook_outbox_limits(&account, month, OutboxLimitChange::Keep)
        .await
        .unwrap();
    let page = app.get_account(&cookie).await;
    let kept = "Events are kept for 30 days (this account), at most 1000 (server default). \
                Up to 14 days and 2000 events.";
    assert!(page.body.contains(kept), "{}", page.body);
    // The hook's filter number comes from the same single answer.
    assert_eq!(
        page.body.matches("Past the limit").count(),
        1,
        "{}",
        page.body
    );
    assert_eq!(plan.take(), [format!("outbox default {}", account.0)]);

    // A refused add asks once, also for the page it shows again.
    let token = csrf(&page.body);
    let fields = rule_fields(&token, "block", "from", "equals", "x");
    let reply = app
        .post_account(
            "/account/webhook/filters/add",
            &fields,
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("This mailbox may have at most 1 filter rules."),
        "{}",
        reply.body
    );
    assert_eq!(plan.take(), [format!("outbox default {}", account.0)]);
}

#[tokio::test]
async fn account_page_configures_and_tests_a_webhook() {
    let (app, mut receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    assert!(page.body.contains(ALERTS_TITLE), "{}", page.body);
    assert!(page.body.contains("7 days"), "{}", page.body);
    assert!(page.body.contains("1000"), "{}", page.body);
    assert!(page.body.contains("Created when you save"));
    let csrf = csrf(&page.body);
    let url = receiver.url("/hook");
    let token = "Bearer secret-token-value-123456";

    // Needs the session, the CSRF token and the origin.
    for (cookie, csrf, origin) in [
        (None, csrf.as_str(), Some(ISSUER)),
        (Some(cookie.as_str()), "wrong", Some(ISSUER)),
        (
            Some(cookie.as_str()),
            csrf.as_str(),
            Some("https://evil.example"),
        ),
    ] {
        let reply = app
            .post_account(
                "/account/webhook",
                &webhook_fields(csrf, &url, token),
                cookie,
                origin,
            )
            .await;
        assert!(
            matches!(reply.status, StatusCode::FORBIDDEN | StatusCode::SEE_OTHER),
            "{}",
            reply.status
        );
        assert_ne!(
            reply
                .headers
                .get(header::LOCATION)
                .map(|v| v.to_str().unwrap()),
            Some("/account?notice=webhook-saved#alerts")
        );
    }

    // Unsafe URLs and headers are refused with field errors.
    for (bad_url, name, message) in [
        (
            "http://hooks.example.com/",
            "Authorization",
            "The URL must use https.",
        ),
        (
            "https://10.0.0.1/",
            "Authorization",
            "addresses are blocked",
        ),
        (
            "https://169.254.169.254/latest/",
            "Authorization",
            "addresses are blocked",
        ),
        (
            "https://localhost/",
            "Authorization",
            "addresses are blocked",
        ),
        (
            "https://hooks.example.com/",
            "Host",
            "This header name can&#39;t be used.",
        ),
    ] {
        let mut fields = webhook_fields(&csrf, bad_url, token);
        fields[3] = ("auth_header_name", name);
        let reply = app
            .post_account("/account/webhook", &fields, Some(&cookie), Some(ISSUER))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad_url}");
        assert!(reply.body.contains(message), "{bad_url}: {}", reply.body);
        assert!(reply.body.contains("aria-invalid=\"true\""));
        assert!(
            !reply.body.contains(token),
            "the header value is never echoed"
        );
    }

    // A valid save.
    let reply = app
        .post_account(
            "/account/webhook",
            &webhook_fields(&csrf, &url, token),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=webhook-saved#alerts"
    );
    let page = app.get_account(&cookie).await;
    assert!(page.body.contains(&url));
    assert!(page.body.contains("Ends in <code>…3456</code>"));
    assert!(!page.body.contains(token));
    assert!(page.body.contains("No deliveries yet."));
    let secret = input_value(&page.body, "signing_secret");
    assert!(secret.starts_with("whsec_"), "{secret}");

    // A blank value keeps the stored one; rotating replaces the secret.
    let reply = app
        .post_account(
            "/account/webhook/rotate-secret",
            &webhook_fields(&csrf, &url, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=secret-rotated#alerts"
    );
    let page = app.get_account(&cookie).await;
    let rotated = input_value(&page.body, "signing_secret");
    assert_ne!(rotated, secret);

    // A test event goes out signed, with the auth header, and is logged.
    let reply = app
        .post_account(
            "/account/webhook/test",
            &webhook_fields(&csrf, &url, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=webhook-test-sent#alerts",
        "{}",
        reply.body
    );
    let got = receiver.requests.recv().await.unwrap();
    assert!(got.head.starts_with("POST /hook HTTP/1.1"));
    assert_eq!(got.header("authorization"), Some(token));
    let json = got.json();
    assert_eq!(json["test"], true);
    assert_eq!(json["account"], EMAIL);
    let stamp: i64 = got.header("x-webhook-timestamp").unwrap().parse().unwrap();
    let signature = got.header("x-signature-256").unwrap();
    assert!(sign::verify(
        &rotated, stamp, &got.body, signature, stamp, 300
    ));
    assert!(!sign::verify(
        &secret, stamp, &got.body, signature, stamp, 300
    ));
    let page = app
        .send(
            Request::get("/account?notice=webhook-test-sent")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        page.body
            .contains("Test delivered. Your endpoint answered <code>200 OK</code> in "),
        "{}",
        page.body
    );
    assert!(page.body.contains("<code>test</code>"));
    assert!(page.body.contains("Last delivered "));

    // Test events are rate limited.
    let reply = app
        .post_account(
            "/account/webhook/test",
            &webhook_fields(&csrf, &url, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=webhook-wait#alerts"
    );

    // Turning it off and clearing the header name removes the header.
    let reply = app
        .post_account(
            "/account/webhook",
            &[
                ("csrf_token", csrf.as_str()),
                ("webhook_url", url.as_str()),
                ("auth_header_name", ""),
            ],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER);
    let page = app.get_account(&cookie).await;
    assert!(!page.body.contains("Ends in <code>"));
    assert!(
        page.body.contains("form=\"alerts-form\">"),
        "the switch is off: {}",
        page.body
    );
}

#[tokio::test]
async fn unreadable_webhook_settings_can_be_replaced() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    // A connected app puts the revoke-all control on the page, so a 500
    // from the webhook card would hide it. The grant exists once the code
    // is exchanged.
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;
    let authorized = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    assert_eq!(
        authorized.status,
        StatusCode::SEE_OTHER,
        "{}",
        authorized.body
    );
    let code = query_param(&authorized.location(), "code").unwrap();
    let tokens = app
        .post_form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", &code),
                ("redirect_uri", REDIRECT),
                ("client_id", &client_id),
                ("code_verifier", VERIFIER),
            ],
        )
        .await;
    assert_eq!(tokens.status, StatusCode::OK, "{}", tokens.body);
    let store = open_store(&app).await;
    let account = account_id(&store).await;
    let old_url = "https://old.example/hook";
    let old_header = "Bearer old-secret-value-zzzz";
    store
        .save_webhook(
            &account,
            &WebhookSettings {
                enabled: true,
                url: old_url.to_owned(),
                auth_header: Some(("authorization".to_owned(), SecretString::from(old_header))),
                signing: true,
                signing_secret: SecretString::from("whsec_old_secret".to_owned()),
                include_sender: true,
            },
        )
        .await
        .unwrap();
    add_rule(
        &store,
        &account,
        "block",
        "from",
        "equals",
        "news@example.com",
    )
    .await;
    // The secrets become text that no key opens, as if they were sealed under
    // a key the app no longer has.
    let unreadable = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a_u8; 40]);
    let replaced = sqlx::query(
        "UPDATE webhooks SET auth_header_value_ciphertext = $1, signing_secret_ciphertext = $1 \
         WHERE account_id = $2",
    )
    .bind(format!("v1.{unreadable}"))
    .bind(&account.0)
    .execute(store.pool())
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(replaced, 1);
    store.close().await;

    let page = app.get_account(&cookie).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(
        page.body.contains("encryption key changed"),
        "the webhook section explains the unreadable settings: {}",
        page.body
    );
    assert!(
        page.body.contains("<bdi>news@example.com</bdi>"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Revoke all apps"));
    assert!(page.body.contains("Delete account and data"));
    assert!(!page.body.contains("whsec_old_secret"));
    assert!(!page.body.contains(old_url));
    assert!(!page.body.contains(old_header));
    let csrf = csrf(&page.body);

    let reply = app
        .post_account(
            "/account/revoke",
            &[("csrf_token", &csrf), ("confirm", "yes")],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.headers[header::LOCATION].to_str().unwrap(),
        "/account?notice=revoked"
    );
    let reply = app
        .post_account(
            "/account/delete",
            &[
                ("csrf_token", &csrf),
                ("confirm_email", "wrong@example.com"),
            ],
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.headers[header::LOCATION].to_str().unwrap(),
        "/account?notice=confirm-delete"
    );

    let reply = app
        .post_account(
            "/account/webhook/rotate-secret",
            &webhook_fields(&csrf, old_url, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.headers[header::LOCATION].to_str().unwrap(),
        "/account?notice=webhook-unreadable#alerts"
    );
    let noticed = app
        .send(
            Request::get("/account?notice=webhook-unreadable")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(noticed.status, StatusCode::OK, "{}", noticed.body);
    assert!(
        noticed
            .body
            .contains("Enter them again and save to replace the stored settings"),
        "{}",
        noticed.body
    );

    let new_url = "https://hooks.example/new";
    let new_header = "Bearer fresh-token-value-9876";
    let reply = app
        .post_account(
            "/account/webhook",
            &webhook_fields(&csrf, new_url, new_header),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.headers[header::LOCATION].to_str().unwrap(),
        "/account?notice=webhook-saved#alerts"
    );
    let page = app.get_account(&cookie).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains(new_url), "{}", page.body);
    assert!(
        !page.body.contains("encryption key changed"),
        "saving replaced the unreadable settings: {}",
        page.body
    );
    assert!(
        page.body.contains("Ends in <code>…9876</code>"),
        "{}",
        page.body
    );
    let secret = input_value(&page.body, "signing_secret");
    assert!(secret.starts_with("whsec_"), "{secret}");
    assert_ne!(secret, "whsec_old_secret");
}

/// Adds a filter rule to `account`'s webhook and gives its ID.
async fn add_rule(
    store: &Store,
    account: &AccountId,
    action: &str,
    field: &str,
    kind: &str,
    pattern: &str,
) -> String {
    let [action, field, kind] = [action, field, kind].map(str::to_owned);
    let pattern = SecretString::from(pattern.to_owned());
    let rule = NewFilterRule {
        action,
        field,
        kind,
        pattern,
    };
    match store
        .add_webhook_filter_rule(account, &rule, 9, |_| Ok(()))
        .await
    {
        Ok(AddedFilterRule::Added(id)) => id,
        other => panic!("{other:?}"),
    }
}

/// Saves a webhook for `account`, so the account page has a Filter rules block.
async fn save_test_webhook(store: &Store, account: &AccountId) {
    let settings = WebhookSettings {
        enabled: true,
        url: "https://hooks.example.com/me".to_owned(),
        auth_header: None,
        signing: true,
        signing_secret: SecretString::from("whsec_test".to_owned()),
        include_sender: false,
    };
    store.save_webhook(account, &settings).await.unwrap();
}

/// Turns the pattern of the rule `id` into text that no key opens.
async fn garble_pattern(store: &Store, id: &str) {
    let unreadable = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a_u8; 40]);
    let garbled =
        sqlx::query("UPDATE webhook_filter_rules SET pattern_ciphertext = $1 WHERE id = $2")
            .bind(format!("v1.{unreadable}"))
            .bind(id)
            .execute(store.pool())
            .await
            .unwrap()
            .rows_affected();
    assert_eq!(garbled, 1);
}

/// The Filter rules block of an account page, from its `id` to Delivery
/// history; its add form and confirms are details too.
fn filters_block(body: &str) -> &str {
    let start = body
        .find("id=\"filters\"")
        .unwrap_or_else(|| panic!("no filter rules block: {body}"));
    let end = start
        + body[start..]
            .find("<details class=\"disclose disclose--history\">")
            .unwrap();
    &body[start..end]
}

/// An escaped character as a row draws it.
fn esc(escape: &str) -> String {
    format!(
        "<span class=\"esc\"><span class=\"visually-hidden\">hidden character </span>{escape}</span>"
    )
}

/// Checks that every ID an `aria-describedby` in `block` names is an element
/// of `block`.
fn assert_descriptions_exist(block: &str) {
    let marker = "aria-describedby=\"";
    for (at, _) in block.match_indices(marker) {
        let start = at + marker.len();
        let ids = &block[start..start + block[start..].find('"').unwrap()];
        for id in ids.split(' ') {
            assert!(block.contains(&format!("id=\"{id}\"")), "{id}: {block}");
        }
    }
}

/// The add form's fields.
const fn rule_fields<'a>(
    csrf: &'a str,
    action: &'a str,
    field: &'a str,
    kind: &'a str,
    pattern: &'a str,
) -> [(&'static str, &'a str); 5] {
    [
        ("csrf_token", csrf),
        ("action", action),
        ("field", field),
        ("kind", kind),
        ("pattern", pattern),
    ]
}

/// Checks that the block lists these patterns, as escaped in the page, with
/// their state, in this order.
fn assert_rows(body: &str, expected: &[(&str, &str)]) {
    let block = filters_block(body);
    let rows: Vec<&str> = block.split("<li class=\"row\">").skip(1).collect();
    assert_eq!(rows.len(), expected.len(), "{block}");
    for (index, (row, (pattern, state))) in rows.iter().zip(expected).enumerate() {
        let number = index + 1;
        assert!(row.contains(&format!("<bdi>{pattern}</bdi>")), "{row}");
        assert!(row.contains(&format!("Rule {number} ·")), "{row}");
        assert!(row.contains(&format!("</span>{state}</span>")), "{row}");
    }
}

#[tokio::test]
async fn account_page_lists_the_filter_rules() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    assert!(page.body.contains(ALERTS_TITLE), "{}", page.body);
    assert!(
        !page.body.contains("id=\"filters\""),
        "no webhook, no block"
    );

    let store = app.state.store();
    let account = account_id(store).await;
    save_test_webhook(store, &account).await;
    let page = app.get_account(&cookie).await;
    assert!(
        page.body.contains("id=\"filters\">"),
        "closed: {}",
        page.body
    );
    let block = filters_block(&page.body);
    assert!(block.contains("disclose__meta\">None</span>"), "{block}");
    assert!(block.contains("No filter rules, so every new message calls the webhook."));

    add_rule(
        store,
        &account,
        "block",
        "from",
        "equals",
        "news@example.com",
    )
    .await;
    let page = app.get_account(&cookie).await;
    assert!(filters_block(&page.body).contains("disclose__meta\">1 rule</span>"));

    let spoof = add_rule(
        store,
        &account,
        "allow",
        "subject",
        "contains",
        "<b>\u{202E}x",
    )
    .await;
    add_rule(
        store,
        &account,
        "allow",
        "from_domain",
        "domain",
        "example.com",
    )
    .await;
    let off = store.set_webhook_filter_rule_enabled(&account, &spoof, false, 0, |_| Ok(()));
    assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);
    let page = app.get_account(&cookie).await;
    assert!(filters_block(&page.body).contains("disclose__meta\">3 rules</span>"));
    let spoofed = format!("&#60;b&#62;{}x", esc("\\u{202e}"));
    let shown = [
        ("news@example.com", "On"),
        (spoofed.as_str(), "Off"),
        ("example.com", "On"),
    ];
    assert_rows(&page.body, &shown);
    assert!(!page.body.contains('\u{202E}'), "{}", page.body);
    assert!(!page.body.contains("Past the limit"));
    assert!(!page.body.contains("limit of"));

    // Off wins over past the limit.
    app.state.set_max_filter_rules(1);
    let page = app.get_account(&cookie).await;
    let shown = [shown[0], shown[1], ("example.com", "Past the limit")];
    assert_rows(&page.body, &shown);
    assert_eq!(page.body.matches("Past the limit").count(), 1);
    assert!(filters_block(&page.body).contains("this mailbox's limit of 1 judge nothing"));

    let csrf = csrf(&page.body);
    let invalid = webhook_fields(&csrf, "http://hooks.example.com/", "x");
    let reply = app
        .post_account("/account/webhook", &invalid, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert!(filters_block(&reply.body).contains("disclose__meta\">3 rules</span>"));

    // Exactly at the limit, no rule is past it.
    app.state.set_max_filter_rules(3);
    let page = app.get_account(&cookie).await;
    assert!(!page.body.contains("limit of"), "{}", page.body);

    let first = store.webhook_filter_rules(&account, 9).await.unwrap()[0]
        .id
        .clone();
    garble_pattern(store, &first).await;
    let page = app.get_account(&cookie).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("id=\"filters\" open"), "{}", page.body);
    let block = filters_block(&page.body);
    assert!(
        block.contains("disclose__meta\">Can't be read</span>"),
        "{block}"
    );
    assert!(block.contains("These filter rules can't be read because the encryption key changed"));
    assert!(!block.contains("Rule 1"), "{block}");
    assert!(block.contains(
        "href=\"https://postkeep.dev/docs/webhooks/#unreadable-rules\" target=\"_blank\" \
         rel=\"noopener noreferrer\""
    ));
    assert!(
        block.contains("What to do<span class=\"visually-hidden\"> (opens in a new tab)</span>")
    );
}

/// The patterns of `account`'s rules, oldest first.
async fn rule_patterns(store: &Store, account: &AccountId) -> Vec<String> {
    let rules = store.webhook_filter_rules(account, 9).await.unwrap();
    let patterns = rules.iter().map(|rule| rule.pattern.expose_secret());
    patterns.map(str::to_owned).collect()
}

#[tokio::test]
async fn account_page_removes_filter_rules() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = account_id(store).await;
    save_test_webhook(store, &account).await;
    let one = add_rule(store, &account, "block", "from", "equals", "one").await;
    add_rule(store, &account, "block", "from", "equals", "two").await;
    let password = SecretString::from("other-password".to_owned());
    let other = store.upsert_account("other@icloud.com", &password).await;
    let other = other.unwrap().id;
    save_test_webhook(store, &other).await;
    let theirs = add_rule(store, &other, "block", "from", "equals", "theirs").await;
    let woke = Arc::new(AtomicUsize::new(0));
    let flag = Arc::clone(&woke);
    app.state.add_account_listener(Arc::new(move |_| {
        flag.fetch_add(1, Ordering::SeqCst);
    }));
    let token = csrf(&app.get_account(&cookie).await.body);
    let path = "/account/webhook/filters/remove";
    let remove = async |fields: &[(&str, &str)]| {
        app.post_account(path, fields, Some(&cookie), Some(ISSUER))
            .await
    };

    let all = [("csrf_token", token.as_str()), ("all", "yes")];
    let wrong = remove(&[("csrf_token", "nope"), ("all", "yes")]).await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{}", wrong.body);
    let foreign = app
        .post_account(path, &all, Some(&cookie), Some("https://evil.example"))
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN, "{}", foreign.body);
    let signed_out = app.post_account(path, &all, None, Some(ISSUER)).await;
    assert_eq!(signed_out.status, StatusCode::SEE_OTHER);
    assert_eq!(signed_out.headers[header::LOCATION], "/account");
    assert_eq!(rule_patterns(store, &account).await, ["one", "two"]);
    assert_eq!(rule_patterns(store, &other).await, ["theirs"]);
    assert_eq!(woke.load(Ordering::SeqCst), 0);

    let notice = |key: &str| format!("/account?notice={key}#filters");
    let reply = remove(&[("csrf_token", &token), ("id", &theirs)]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.headers[header::LOCATION], notice("filter-gone"));
    assert_eq!(rule_patterns(store, &other).await, ["theirs"]);
    assert_eq!(woke.load(Ordering::SeqCst), 0);

    let reply = remove(&[("csrf_token", &token), ("id", &one)]).await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-removed"));
    assert_eq!(rule_patterns(store, &account).await, ["two"]);
    assert_eq!(woke.load(Ordering::SeqCst), 1);

    let reply = remove(&all).await;
    assert_eq!(reply.headers[header::LOCATION], notice("filters-removed"));
    assert_eq!(rule_patterns(store, &account).await, [""; 0]);
    assert_eq!(woke.load(Ordering::SeqCst), 2);
    let reply = remove(&all).await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-gone"));
    assert_eq!(woke.load(Ordering::SeqCst), 2);
    assert_eq!(rule_patterns(store, &other).await, ["theirs"]);

    let notices = [
        ("filter-removed", "Filter rule removed.", true),
        (
            "filters-removed",
            "Every filter rule was removed, so every new message calls the webhook.",
            true,
        ),
        (
            "filter-gone",
            "That rule is no longer there, so nothing changed.",
            false,
        ),
    ];
    assert_filter_notices(&app, &cookie, &notices).await;
}

/// Each `(key, text, success)` notice opens the Filter rules block and shows
/// at its top, once, as a status (success) or an alert.
async fn assert_filter_notices(app: &TestApp, cookie: &str, notices: &[(&str, &str, bool)]) {
    for &(key, text, success) in notices {
        let request = Request::get(format!("/account?notice={key}"))
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        let page = app.send(request).await;
        let found = (page.body.find("id=\"filters\" open"), page.body.find(text));
        let (Some(block), Some(at)) = found else {
            panic!("{key}: {}", page.body)
        };
        assert!(at > block, "{key}: {}", page.body);
        assert_eq!(page.body.matches(text).count(), 1, "{key}");
        let line = &page.body[page.body[..at].rfind("<p ").unwrap()..at];
        let role = if success { "status" } else { "alert" };
        assert!(line.contains(&format!("role=\"{role}\"")), "{key}: {line}");
    }
}

const TYPED_NOTE: &str = "The pattern you typed has characters that don&#39;t show, so it isn&#39;t filled in again. Type or paste it again.";

#[tokio::test]
async fn account_page_adds_filter_rules() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = account_id(store).await;
    let path = "/account/webhook/filters/add";
    let token = csrf(&app.get_account(&cookie).await.body);
    let add = async |fields: &[(&str, &str)]| {
        app.post_account(path, fields, Some(&cookie), Some(ISSUER))
            .await
    };
    let valid = rule_fields(&token, "block", "from", "equals", "news@example.com");
    let to_block = "/account#filters";

    let reply = add(&valid).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.headers[header::LOCATION], to_block);
    let version = store.webhook_filter_rules_version(&account).await.unwrap();
    assert_eq!(version, None);

    save_test_webhook(store, &account).await;
    let password = SecretString::from("other-password".to_owned());
    let other = store.upsert_account("other@icloud.com", &password).await;
    let other = other.unwrap().id;
    save_test_webhook(store, &other).await;
    add_rule(store, &other, "block", "from", "equals", "theirs").await;
    let woke = Arc::new(AtomicUsize::new(0));
    let flag = Arc::clone(&woke);
    app.state.add_account_listener(Arc::new(move |_| {
        flag.fetch_add(1, Ordering::SeqCst);
    }));

    let page = app.get_account(&cookie).await;
    assert!(page.body.contains("id=\"filters\">"), "{}", page.body);
    let block = filters_block(&page.body);
    assert!(block.contains(
        "No filter rules, so every new message calls the webhook. Add one below, or let an agent add them with its filter tools."
    ));
    assert!(block.contains("id=\"filter-new-form\">"), "{block}");
    for selected in ["block", "from", "equals"] {
        assert!(
            block.contains(&format!("value=\"{selected}\" selected")),
            "{block}"
        );
    }
    assert!(!block.contains("aria-invalid"), "{block}");
    for described in ["pattern-hint", "action-hint", "kind-hint"] {
        let attribute = format!("aria-describedby=\"filter-new-{described}\"");
        assert!(block.contains(&attribute), "{block}");
    }
    assert_descriptions_exist(block);

    let wrong = add(&rule_fields("nope", "block", "from", "equals", "x")).await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{}", wrong.body);
    let foreign = app
        .post_account(path, &valid, Some(&cookie), Some("https://evil.example"))
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN, "{}", foreign.body);
    let signed_out = app.post_account(path, &valid, None, Some(ISSUER)).await;
    assert_eq!(signed_out.status, StatusCode::SEE_OTHER);
    assert_eq!(signed_out.headers[header::LOCATION], "/account");
    let unknown = add(&rule_fields(&token, "maybe", "from", "equals", "x")).await;
    assert_eq!(unknown.status, StatusCode::FORBIDDEN, "{}", unknown.body);
    assert_eq!(rule_patterns(store, &account).await, [""; 0]);
    assert_eq!(woke.load(Ordering::SeqCst), 0);

    let reply = add(&valid).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let added = "/account?notice=filter-added#filters";
    assert_eq!(reply.headers[header::LOCATION], added);
    let rules = store.webhook_filter_rules(&account, 9).await.unwrap();
    assert_eq!(rules.len(), 1);
    let names = [&rules[0].action, &rules[0].field, &rules[0].kind];
    assert_eq!(names, ["block", "from", "equals"]);
    assert_eq!(rules[0].pattern.expose_secret(), "news@example.com");
    assert!(rules[0].enabled);
    assert_eq!(woke.load(Ordering::SeqCst), 1);
    assert_eq!(rule_patterns(store, &other).await, ["theirs"]);
    let page = app.get_account(&cookie).await;
    let block = filters_block(&page.body);
    assert!(block.contains("Rules you or an agent added, oldest first."));
    assert!(
        block.contains("It stops judging new mail right away. You or an agent can add it again.")
    );
    assert_descriptions_exist(block);

    // Each refusal shows the page again with the form open and stores nothing.
    let refused = |reply: &Reply, reason: &str| {
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
        assert!(reply.body.contains("id=\"filters\" open"), "{}", reply.body);
        let block = filters_block(&reply.body);
        let form = &block[block.find("id=\"filter-new-form\" open").expect(block)..];
        assert_eq!(block.matches(reason).count(), 1, "{reason}: {block}");
        assert!(form.contains(reason), "{reason}: {form}");
        assert!(
            form.contains("id=\"filter-new-pattern\" name=\"pattern\""),
            "{form}"
        );
        let input = &form[form.find("id=\"filter-new-pattern\"").unwrap()..];
        let input = &input[..input.find('>').unwrap()];
        assert!(input.contains("aria-invalid=\"true\" autofocus"), "{input}");
        assert_descriptions_exist(block);
        input.to_owned()
    };
    let with_error = "aria-describedby=\"filter-new-pattern-error filter-new-pattern-hint\"";
    let cases = [
        (
            ["allow", "subject", "regex", ""],
            "The pattern must be 1 to 512 bytes.",
        ),
        (
            ["block", "subject", "domain", "example.com"],
            "A domain rule cannot look at the subject.",
        ),
        (
            ["block", "subject", "regex", "(?=<b>)"],
            "Look-around, including look-ahead and look-behind, is not supported.",
        ),
    ];
    for ([action, field, kind, pattern], reason) in cases {
        let reply = add(&rule_fields(&token, action, field, kind, pattern)).await;
        let input = refused(&reply, reason);
        assert!(input.contains(with_error), "{input}");
        assert!(!reply.body.contains("filter-new-pattern-note"));
    }
    let reply = add(&rule_fields(&token, "allow", "subject", "regex", "")).await;
    let form = filters_block(&reply.body);
    let form = &form[form.find("id=\"filter-new-form\"").unwrap()..];
    for selected in ["allow", "subject", "regex"] {
        assert!(
            form.contains(&format!("value=\"{selected}\" selected")),
            "{form}"
        );
    }
    assert!(!form.contains("value=\"block\" selected"), "{form}");
    let reply = add(&rule_fields(&token, "block", "subject", "regex", "(?=<b>)")).await;
    assert!(
        reply.body.contains("value=\"(?=&#60;b&#62;)\""),
        "{}",
        reply.body
    );

    let unknown = add_rule(store, &account, "block", "body", "equals", "x").await;
    let reply = add(&valid).await;
    let input = refused(
        &reply,
        "A rule that&#39;s on has an action, field or kind this server doesn&#39;t know. \
         Turn that rule off or remove it, then try again.",
    );
    assert!(input.contains(with_error), "{input}");
    assert!(
        store
            .remove_webhook_filter_rule(&account, &unknown)
            .await
            .unwrap()
    );

    app.state.set_max_filter_rules(1);
    let at_limit = "This mailbox may have at most 1 filter rules.";
    let input = refused(&add(&valid).await, at_limit);
    assert!(input.contains(with_error), "{input}");
    let spoof = rule_fields(&token, "block", "from", "equals", "a\u{202E}b");
    let reply = add(&spoof).await;
    let input = refused(&reply, at_limit);
    assert!(!reply.body.contains('\u{202E}'), "{}", reply.body);
    assert!(input.contains("value=\"\""), "{input}");
    assert!(
        input.contains(
            "aria-describedby=\"filter-new-pattern-error filter-new-pattern-note filter-new-pattern-hint\""
        ),
        "{input}"
    );
    let block = filters_block(&reply.body);
    let note = format!("<p class=\"field__hint\" id=\"filter-new-pattern-note\">{TYPED_NOTE}</p>");
    let (error_at, note_at) = (block.find(at_limit).unwrap(), block.find(&note));
    assert!(note_at.is_some_and(|at| at > error_at), "{block}");
    assert_eq!(rule_patterns(store, &account).await, ["news@example.com"]);
    assert_eq!(woke.load(Ordering::SeqCst), 1);

    app.state.set_max_filter_rules(9);
    garble_pattern(store, &rules[0].id).await;
    for fields in [valid, rule_fields(&token, "block", "from", "equals", "")] {
        let reply = add(&fields).await;
        assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
        assert_eq!(reply.headers[header::LOCATION], to_block);
    }
    let version = store.webhook_filter_rules_version(&account).await.unwrap();
    assert_eq!(
        store.remove_webhook_filter_rules(&account).await.unwrap(),
        1
    );
    assert_eq!(woke.load(Ordering::SeqCst), 1);
    assert!(version.is_some());

    let notices = [("filter-added", "Filter rule added.", true)];
    assert_filter_notices(&app, &cookie, &notices).await;
}

#[tokio::test]
async fn account_page_marks_hidden_characters_in_patterns() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = account_id(store).await;
    save_test_webhook(store, &account).await;
    add_rule(
        store,
        &account,
        "block",
        "subject",
        "contains",
        "\\u{202e}x",
    )
    .await;
    add_rule(store, &account, "block", "subject", "contains", "\u{202E}x").await;
    let page = app.get_account(&cookie).await;
    let marked = format!("{}x", esc("\\u{202e}"));
    assert_rows(&page.body, &[("\\u{202e}x", "On"), (marked.as_str(), "On")]);
    assert!(!page.body.contains('\u{202E}'), "{}", page.body);
}

const STORED_NOTE: &str = "This pattern has characters that don&#39;t show, written as \\u{…} in the rule, so it isn&#39;t filled in. Type it again to change this rule.";

/// The Edit panel of the rule `id`, from its `id` attribute to its end.
fn edit_form<'a>(body: &'a str, id: &str) -> &'a str {
    let block = filters_block(body);
    let start = block
        .find(&format!("id=\"filter-{id}-form\""))
        .unwrap_or_else(|| panic!("{id}: {block}"));
    let end = start + block[start..].find("</details>").unwrap();
    &block[start..end]
}

/// An Edit form's fields for the rule `id`.
const fn edit_fields<'a>(
    csrf: &'a str,
    id: &'a str,
    [action, field, kind, pattern]: [&'a str; 4],
) -> [(&'static str, &'a str); 6] {
    [
        ("csrf_token", csrf),
        ("id", id),
        ("action", action),
        ("field", field),
        ("kind", kind),
        ("pattern", pattern),
    ]
}

/// The pattern input of the rule form `form` for the rule `id`.
fn pattern_input<'a>(form: &'a str, id: &str) -> &'a str {
    let start = form.find(&format!("id=\"filter-{id}-pattern\""));
    let input = &form[start.unwrap_or_else(|| panic!("{id}: {form}"))..];
    &input[..input.find('>').unwrap()]
}

#[tokio::test]
async fn account_page_edits_filter_rules() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = account_id(store).await;
    save_test_webhook(store, &account).await;
    let a = add_rule(
        store,
        &account,
        "block",
        "from",
        "equals",
        "news@example.com",
    )
    .await;
    let b = add_rule(store, &account, "allow", "subject", "contains", "\u{202E}x").await;
    let c = add_rule(
        store,
        &account,
        "block",
        "from",
        "equals",
        "old@example.com",
    )
    .await;
    let off = store.set_webhook_filter_rule_enabled(&account, &c, false, 0, |_| Ok(()));
    assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);
    let password = SecretString::from("other-password".to_owned());
    let other = store.upsert_account("other@icloud.com", &password).await;
    let other = other.unwrap().id;
    save_test_webhook(store, &other).await;
    let theirs = add_rule(store, &other, "block", "from", "equals", "theirs").await;
    let woke = Arc::new(AtomicUsize::new(0));
    let flag = Arc::clone(&woke);
    app.state.add_account_listener(Arc::new(move |_| {
        flag.fetch_add(1, Ordering::SeqCst);
    }));

    let page = app.get_account(&cookie).await;
    assert!(!page.body.contains('\u{202E}'), "{}", page.body);
    assert_descriptions_exist(filters_block(&page.body));
    let form = edit_form(&page.body, &a);
    assert!(
        form.starts_with(&format!("id=\"filter-{a}-form\">")),
        "{form}"
    );
    assert!(form.contains("Edit<span class=\"visually-hidden\"> rule 1</span></summary>"));
    assert!(
        form.contains("<p class=\"confirm__title\">Edit rule 1</p>"),
        "{form}"
    );
    for selected in ["block", "from", "equals"] {
        let selected = format!("value=\"{selected}\" selected");
        assert!(form.contains(&selected), "{form}");
    }
    let input = pattern_input(form, &a);
    assert!(input.contains("value=\"news@example.com\""), "{input}");
    let hint_only = format!("aria-describedby=\"filter-{a}-pattern-hint\"");
    assert!(input.contains(&hint_only), "{input}");
    assert!(!input.contains("aria-invalid"), "{input}");
    let form = edit_form(&page.body, &b);
    let input = pattern_input(form, &b);
    assert!(input.contains("value=\"\""), "{input}");
    let with_note = format!("aria-describedby=\"filter-{b}-pattern-note filter-{b}-pattern-hint\"");
    assert!(input.contains(&with_note), "{input}");
    let note = format!("<p class=\"field__hint\" id=\"filter-{b}-pattern-note\">{STORED_NOTE}</p>");
    assert!(form.contains(&note), "{form}");

    let token = csrf(&page.body);
    let path = "/account/webhook/filters/edit";
    let edit = async |id: &str, rule: [&str; 4]| {
        let fields = edit_fields(&token, id, rule);
        app.post_account(path, &fields, Some(&cookie), Some(ISSUER))
            .await
    };
    let invoice = ["allow", "subject", "contains", "Invoice"];
    let notice = |key: &str| format!("/account?notice={key}#filters");
    let unchanged = async |patterns: &[&str], switches: &[bool]| {
        assert_eq!(rule_patterns(store, &account).await, patterns);
        assert_eq!(rule_switches(store, &account).await, switches);
    };

    let wrong = edit_fields("nope", &a, invoice);
    let wrong = app
        .post_account(path, &wrong, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{}", wrong.body);
    let valid = edit_fields(&token, &a, invoice);
    let foreign = app
        .post_account(path, &valid, Some(&cookie), Some("https://evil.example"))
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN, "{}", foreign.body);
    let unknown = edit(&a, ["allow", "subject", "maybe", "Invoice"]).await;
    assert_eq!(unknown.status, StatusCode::FORBIDDEN, "{}", unknown.body);
    let signed_out = app.post_account(path, &valid, None, Some(ISSUER)).await;
    assert_eq!(signed_out.status, StatusCode::SEE_OTHER);
    assert_eq!(signed_out.headers[header::LOCATION], "/account");
    let patterns = ["news@example.com", "\u{202E}x", "old@example.com"];
    unchanged(&patterns, &[true, true, false]).await;
    assert_eq!(woke.load(Ordering::SeqCst), 0);

    let reply = edit(&a, invoice).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.headers[header::LOCATION], notice("filter-saved"));
    let rules = store.webhook_filter_rules(&account, 9).await.unwrap();
    assert_eq!(rules[0].id, a);
    let names = [&rules[0].action, &rules[0].field, &rules[0].kind];
    assert_eq!(names, ["allow", "subject", "contains"]);
    assert_eq!(woke.load(Ordering::SeqCst), 1);
    let reply = edit(&c, ["block", "from", "contains", "old"]).await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-saved"));
    let patterns = ["Invoice", "\u{202E}x", "old"];
    unchanged(&patterns, &[true, true, false]).await;
    assert_eq!(woke.load(Ordering::SeqCst), 2);

    // A refused edit opens only its own row's form, with the typed values.
    let lookahead = "Look-around, including look-ahead and look-behind, is not supported.";
    let reply = edit(&b, ["allow", "subject", "regex", "(?=x)"]).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert!(reply.body.contains("id=\"filters\" open"), "{}", reply.body);
    let block = filters_block(&reply.body);
    assert_descriptions_exist(block);
    assert_eq!(block.matches(lookahead).count(), 1, "{block}");
    let form = edit_form(&reply.body, &b);
    assert!(
        form.starts_with(&format!("id=\"filter-{b}-form\" open>")),
        "{form}"
    );
    assert!(form.contains(lookahead), "{form}");
    assert!(form.contains("value=\"regex\" selected"), "{form}");
    let input = pattern_input(form, &b);
    assert!(input.contains("value=\"(?=x)\""), "{input}");
    assert!(input.contains("aria-invalid=\"true\" autofocus"), "{input}");
    let with_error =
        format!("aria-describedby=\"filter-{b}-pattern-error filter-{b}-pattern-hint\"");
    assert!(input.contains(&with_error), "{input}");
    assert!(!reply.body.contains(&format!("filter-{b}-pattern-note")));
    for id in [&a, &c] {
        let form = edit_form(&reply.body, id);
        assert!(
            form.starts_with(&format!("id=\"filter-{id}-form\">")),
            "{form}"
        );
    }
    assert!(block.contains("id=\"filter-new-form\">"), "{block}");
    unchanged(&patterns, &[true, true, false]).await;
    assert_eq!(woke.load(Ordering::SeqCst), 2);

    // The docs' fix for unknown names: turn the rule off, then change it.
    let u = add_rule(store, &account, "block", "body", "equals", "x").await;
    let reply = edit(&a, invoice).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{}", reply.body);
    assert_descriptions_exist(filters_block(&reply.body));
    let form = edit_form(&reply.body, &a);
    assert!(
        form.starts_with(&format!("id=\"filter-{a}-form\" open>")),
        "{form}"
    );
    assert!(form.contains(
        "A rule that&#39;s on has an action, field or kind this server doesn&#39;t know. \
         Turn that rule off or remove it, then try again."
    ));
    let off = store.set_webhook_filter_rule_enabled(&account, &u, false, 0, |_| Ok(()));
    assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);
    let reply = edit(&u, ["block", "subject", "equals", "x"]).await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-saved"));
    let rules = store.webhook_filter_rules(&account, 9).await.unwrap();
    assert_eq!(rules[3].field, "subject");
    assert!(!rules[3].enabled);
    assert_eq!(woke.load(Ordering::SeqCst), 3);

    let reply = edit(&theirs, invoice).await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-gone"));
    assert_eq!(rule_patterns(store, &other).await, ["theirs"]);
    let removed = store.remove_webhook_filter_rule(&account, &u).await;
    assert!(removed.unwrap());
    let reply = edit(&u, ["block", "subject", "equals", ""]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.headers[header::LOCATION], notice("filter-gone"));
    unchanged(&patterns, &[true, true, false]).await;
    assert_eq!(woke.load(Ordering::SeqCst), 3);

    garble_pattern(store, &a).await;
    let reply = edit(&c, ["block", "from", "contains", "new"]).await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.headers[header::LOCATION], "/account#filters");
    assert_eq!(woke.load(Ordering::SeqCst), 3);

    store.remove_webhook_filter_rules(&account).await.unwrap();
    let notices = [("filter-saved", "Filter rule saved.", true)];
    assert_filter_notices(&app, &cookie, &notices).await;
}

/// Whether each of `account`'s rules is on, oldest first.
async fn rule_switches(store: &Store, account: &AccountId) -> Vec<bool> {
    let rules = store.webhook_filter_rules(account, 9).await.unwrap();
    rules.iter().map(|rule| rule.enabled).collect()
}

#[tokio::test]
async fn account_page_turns_filter_rules_on_and_off() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = account_id(store).await;
    save_test_webhook(store, &account).await;
    let a = add_rule(
        store,
        &account,
        "block",
        "from",
        "equals",
        "news@example.com",
    )
    .await;
    // Stored without a check: it doesn't compile.
    let b = add_rule(store, &account, "allow", "subject", "regex", "(?=x)").await;
    let off = store.set_webhook_filter_rule_enabled(&account, &b, false, 0, |_| Ok(()));
    assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);
    let password = SecretString::from("other-password".to_owned());
    let other = store.upsert_account("other@icloud.com", &password).await;
    let other = other.unwrap().id;
    save_test_webhook(store, &other).await;
    let theirs = add_rule(store, &other, "block", "from", "equals", "theirs").await;
    let woke = Arc::new(AtomicUsize::new(0));
    let flag = Arc::clone(&woke);
    app.state.add_account_listener(Arc::new(move |_| {
        flag.fetch_add(1, Ordering::SeqCst);
    }));
    let page = app.get_account(&cookie).await;
    let rows: Vec<&str> = filters_block(&page.body)
        .split("<li class=\"row\">")
        .collect();
    assert!(
        rows[1].contains("name=\"enabled\" value=\"off\""),
        "{}",
        rows[1]
    );
    assert!(rows[1].contains("Turn off<span class=\"visually-hidden\"> rule 1</span>"));
    assert!(
        rows[2].contains("name=\"enabled\" value=\"on\""),
        "{}",
        rows[2]
    );
    assert!(rows[2].contains("Turn on<span class=\"visually-hidden\"> rule 2</span>"));
    let token = csrf(&page.body);
    let path = "/account/webhook/filters/enabled";
    let switch = async |id: &str, enabled: &str| {
        let fields = [
            ("csrf_token", token.as_str()),
            ("id", id),
            ("enabled", enabled),
        ];
        app.post_account(path, &fields, Some(&cookie), Some(ISSUER))
            .await
    };

    let fields = [
        ("csrf_token", token.as_str()),
        ("id", &a),
        ("enabled", "off"),
    ];
    let wrong = [("csrf_token", "nope"), ("id", &a), ("enabled", "off")];
    let wrong = app
        .post_account(path, &wrong, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(wrong.status, StatusCode::FORBIDDEN, "{}", wrong.body);
    let foreign = app
        .post_account(path, &fields, Some(&cookie), Some("https://evil.example"))
        .await;
    assert_eq!(foreign.status, StatusCode::FORBIDDEN, "{}", foreign.body);
    let signed_out = app.post_account(path, &fields, None, Some(ISSUER)).await;
    assert_eq!(signed_out.status, StatusCode::SEE_OTHER);
    assert_eq!(signed_out.headers[header::LOCATION], "/account");
    let reply = switch(&a, "maybe").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.headers[header::LOCATION], "/account#filters");
    assert_eq!(rule_switches(store, &account).await, [true, false]);
    assert_eq!(woke.load(Ordering::SeqCst), 0);

    let notice = |key: &str| format!("/account?notice={key}#filters");
    let reply = switch(&theirs, "off").await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-gone"));
    assert_eq!(rule_switches(store, &other).await, [true]);

    let reply = switch(&a, "off").await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-off"));
    assert_eq!(rule_switches(store, &account).await, [false, false]);
    assert_eq!(woke.load(Ordering::SeqCst), 1);
    let reply = switch(&a, "on").await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-on"));
    assert_eq!(rule_switches(store, &account).await, [true, false]);
    assert_eq!(woke.load(Ordering::SeqCst), 2);

    let reply = switch(&b, "on").await;
    assert_eq!(
        reply.headers[header::LOCATION],
        notice("filter-wont-compile")
    );
    assert_eq!(rule_switches(store, &account).await, [true, false]);
    assert_eq!(woke.load(Ordering::SeqCst), 2);

    // Past the limit, `b` judges nothing, so it isn't compiled.
    app.state.set_max_filter_rules(1);
    let reply = switch(&b, "on").await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-on"));
    assert_eq!(woke.load(Ordering::SeqCst), 3);
    let page = app.get_account(&cookie).await;
    assert_rows(
        &page.body,
        &[("news@example.com", "On"), ("(?=x)", "Past the limit")],
    );
    let off = store.set_webhook_filter_rule_enabled(&account, &b, false, 0, |_| Ok(()));
    assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);

    garble_pattern(store, &a).await;
    // Turning off reads no rule.
    let reply = switch(&b, "off").await;
    assert_eq!(reply.headers[header::LOCATION], notice("filter-off"));
    assert_eq!(woke.load(Ordering::SeqCst), 4);
    let reply = switch(&b, "on").await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(reply.headers[header::LOCATION], "/account#filters");
    assert_eq!(woke.load(Ordering::SeqCst), 4);

    let notices = [
        ("filter-on", "Filter rule turned on.", true),
        (
            "filter-off",
            "Filter rule turned off. It judges nothing until you turn it on again.",
            true,
        ),
        (
            "filter-unknown",
            "Not turned on: this rule, or another rule that&#39;s on, has an action, field or kind this server doesn&#39;t know.",
            false,
        ),
        (
            "filter-wont-compile",
            "Not turned on: the rules that are on wouldn&#39;t compile together with this one. Remove it, or turn off or remove other rules first.",
            false,
        ),
    ];
    // The unreadable block is always open; a readable one opens for the notice.
    store.remove_webhook_filter_rules(&account).await.unwrap();
    assert_filter_notices(&app, &cookie, &notices).await;
}

/// A rule that's on and holds the mail shows why, and the block opens with
/// what to do. Rules that judge nothing, or compile, show as before.
#[tokio::test]
async fn account_page_marks_the_rules_that_hold_the_mail() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = account_id(store).await;
    save_test_webhook(store, &account).await;
    let news = "news@example.com";
    add_rule(store, &account, "block", "from", "equals", news).await;
    let unknown = add_rule(store, &account, "block", "body", "equals", "x").await;
    let alert = "<p class=\"result result--bad\" role=\"alert\">";
    let page = app.get_account(&cookie).await;
    assert_rows(&page.body, &[(news, "On"), ("x", "Can&#39;t be read")]);
    let block = filters_block(&page.body);
    assert!(page.body.contains("id=\"filters\" open"), "{block}");
    let row = block.split("<li class=\"row\">").nth(2).unwrap();
    assert!(row.contains("badge badge--danger"), "{row}");
    assert!(block.contains(
        "A rule that&#39;s on has an action, field or kind this server doesn&#39;t know, \
         so new mail waits and doesn&#39;t call the webhook. Turn off or remove each rule marked Can&#39;t be read. \
         <a href=\""
    ));
    assert!(block.contains("/docs/webhooks/#unreadable-rules\" target=\"_blank\""));

    // Past the limit or off, it judges nothing and holds nothing.
    app.state.set_max_filter_rules(1);
    let page = app.get_account(&cookie).await;
    assert_rows(&page.body, &[(news, "On"), ("x", "Past the limit")]);
    assert!(!filters_block(&page.body).contains(alert), "{}", page.body);
    app.state.set_max_filter_rules(9);
    let off = store.set_webhook_filter_rule_enabled(&account, &unknown, false, 0, |_| Ok(()));
    assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);
    let page = app.get_account(&cookie).await;
    assert_rows(&page.body, &[(news, "On"), ("x", "Off")]);
    assert!(!filters_block(&page.body).contains(alert));

    assert!(
        store
            .remove_webhook_filter_rule(&account, &unknown)
            .await
            .unwrap()
    );
    let alone = add_rule(store, &account, "allow", "subject", "regex", "(?=x)").await;
    let page = app.get_account(&cookie).await;
    assert_rows(
        &page.body,
        &[(news, "On"), ("(?=x)", "Doesn&#39;t compile")],
    );
    assert!(filters_block(&page.body).contains(
        "A rule that&#39;s on doesn&#39;t compile on this server, so new mail waits and doesn&#39;t call the webhook. \
         Turn off or remove the rule marked Doesn&#39;t compile."
    ));

    assert!(
        store
            .remove_webhook_filter_rule(&account, &alone)
            .await
            .unwrap()
    );
    let mut heavy = Vec::new();
    for i in 0..4 {
        let pattern = format!(r"\w{{24}}-{i}");
        heavy.push(add_rule(store, &account, "allow", "subject", "regex", &pattern).await);
    }
    let page = app.get_account(&cookie).await;
    let shown = [
        (news, "On"),
        (r"\w{24}-0", "On"),
        (r"\w{24}-1", "On"),
        (r"\w{24}-2", "On"),
        (r"\w{24}-3", "Doesn&#39;t compile"),
    ];
    assert_rows(&page.body, &shown);
    assert!(filters_block(&page.body).contains(
        "A rule that&#39;s on doesn&#39;t fit with the older rules that are on: together they&#39;re \
         too large to compile, so new mail waits and doesn&#39;t call the webhook."
    ));

    // Rules that compile show as before.
    assert!(
        store
            .remove_webhook_filter_rule(&account, &heavy[3])
            .await
            .unwrap()
    );
    let page = app.get_account(&cookie).await;
    assert_rows(&page.body, &shown[..4]);
    assert!(!filters_block(&page.body).contains(alert));
    assert!(!page.body.contains("id=\"filters\" open"), "{}", page.body);
}

#[tokio::test]
async fn unreadable_filter_rules_can_be_removed_on_the_account_page() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let store = app.state.store();
    let account = account_id(store).await;
    save_test_webhook(store, &account).await;
    let id = add_rule(store, &account, "block", "from", "equals", "one").await;
    garble_pattern(store, &id).await;
    let page = app.get_account(&cookie).await;
    assert!(
        filters_block(&page.body).contains("Remove all rules"),
        "{}",
        page.body
    );
    let fields = [("csrf_token", csrf(&page.body)), ("all", "yes".to_owned())];
    let path = "/account/webhook/filters/remove";
    let fields = fields
        .each_ref()
        .map(|(name, value)| (*name, value.as_str()));
    let reply = app
        .post_account(path, &fields, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=filters-removed#filters"
    );
    let page = app.get_account(&cookie).await;
    assert!(
        filters_block(&page.body).contains("No filter rules"),
        "{}",
        page.body
    );
}

/// Settings that a newer version wrote are not replaced like unreadable ones:
/// the page, the form and the secret rotation fail, and nothing is overwritten.
#[tokio::test]
async fn webhook_settings_in_a_newer_format_are_not_replaced() {
    let (app, _receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let token = csrf(&app.get_account(&cookie).await.body);
    let old = webhook_fields(&token, "https://old.example/hook", "Bearer old-token-value");
    let saved = app
        .post_account("/account/webhook", &old, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);
    let store = open_store(&app).await;
    let write = "UPDATE webhooks SET signing_secret_ciphertext = 'v3.AAAA'";
    sqlx::query(write).execute(store.pool()).await.unwrap();

    let error = StatusCode::INTERNAL_SERVER_ERROR;
    let page = app.get_account(&cookie).await;
    assert_eq!(page.status, error, "{}", page.body);
    let new = webhook_fields(&token, "https://new.example/hook", "Bearer new-token-value");
    let rotate = "/account/webhook/rotate-secret";
    for (path, fields) in [("/account/webhook", &new), (rotate, &old)] {
        let reply = app
            .post_account(path, fields, Some(&cookie), Some(ISSUER))
            .await;
        assert_eq!(reply.status, error, "{path}: {}", reply.body);
    }
    let read = sqlx::query_scalar("SELECT signing_secret_ciphertext FROM webhooks");
    let kept: String = read.fetch_one(store.pool()).await.unwrap();
    assert_eq!(kept, "v3.AAAA");
}

/// The master key was replaced and no previous key is configured, so the
/// stored password and webhook settings cannot be read. The user signs in
/// again for an app and gets the redirect, and saving webhook settings
/// replaces the unreadable ones.
#[tokio::test]
async fn signing_in_again_after_the_master_key_changed_replaces_what_could_not_be_read() {
    let (before, receiver) = webhook_app().await;
    let cookie = before.account_session().await;
    let page = before.get_account(&cookie).await;
    let token = csrf(&page.body);
    let fields = webhook_fields(&token, "https://old.example/hook", "Bearer old-token-value");
    let saved = before
        .post_account("/account/webhook", &fields, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);

    // The same database under another master key, with no previous key.
    let key = MasterKey::generate_encoded().unwrap();
    let deliverer = Some(receiver.deliverer.clone());
    let app = app_in(before.dir.clone(), key, |_| {}, deliverer).await;
    let client_id = app.public_client().await;
    let request_id = app.start(&client_id, REDIRECT).await;
    let authorized = app.sign_in(&request_id, EMAIL, PASSWORD).await;
    assert_eq!(
        authorized.status,
        StatusCode::SEE_OTHER,
        "{}",
        authorized.body
    );
    assert!(query_param(&authorized.location(), "code").is_some());

    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    assert!(
        page.body.contains("encryption key changed"),
        "{}",
        page.body
    );
    let (token, new_url) = (csrf(&page.body), "https://hooks.example/new");
    let fields = webhook_fields(&token, new_url, "Bearer new-token-value");
    let reply = app
        .post_account("/account/webhook", &fields, Some(&cookie), Some(ISSUER))
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    let page = app.get_account(&cookie).await;
    assert!(page.body.contains(new_url), "{}", page.body);
    assert!(
        !page.body.contains("encryption key changed"),
        "{}",
        page.body
    );
}

/// The master key was replaced and no previous key is configured, so the
/// stored password cannot be read. Signing in for an app answers with the
/// redirect, not a server error, and stores the new password under a data key
/// that the new master key wraps, which a process with that key alone reads.
#[tokio::test]
async fn a_sign_in_after_the_master_key_was_replaced_connects_again() {
    let before = app().await;
    let client_id = before.public_client().await;
    let request_id = before.start(&client_id, REDIRECT).await;
    let first = before.sign_in(&request_id, EMAIL, PASSWORD).await;
    assert_eq!(first.status, StatusCode::SEE_OTHER, "{}", first.body);

    let key = MasterKey::generate_encoded().unwrap();
    let app = app_in(before.dir.clone(), key, |_| {}, None).await;
    let request_id = app.start(&client_id, REDIRECT).await;
    let again = app.sign_in(&request_id, EMAIL, ALT_PASSWORD).await;
    assert_eq!(again.status, StatusCode::SEE_OTHER, "{}", again.body);
    assert!(query_param(&again.location(), "code").is_some());

    let store = open_store(&app).await;
    let account = account_id(&store).await;
    let found = store.credentials(&account).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), ALT_PASSWORD);
}

#[tokio::test]
async fn concurrent_webhook_tests_send_only_once() {
    let (app, mut receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    let csrf = csrf(&page.body);
    let url = receiver.url("/hook");
    let fields = webhook_fields(&csrf, &url, "Bearer secret-token-value-123456");

    let first = app.post_account(
        "/account/webhook/test",
        &fields,
        Some(&cookie),
        Some(ISSUER),
    );
    let second = app.post_account(
        "/account/webhook/test",
        &fields,
        Some(&cookie),
        Some(ISSUER),
    );
    let (left, right) = tokio::join!(first, second);
    let locations = [
        left.headers[header::LOCATION].to_str().unwrap(),
        right.headers[header::LOCATION].to_str().unwrap(),
    ];
    let sent = locations
        .iter()
        .filter(|location| location.contains("webhook-test-sent"))
        .count();
    let waiting = locations
        .iter()
        .filter(|location| location.contains("webhook-wait"))
        .count();
    assert_eq!(sent, 1, "{locations:?}");
    assert_eq!(waiting, 1, "{locations:?}");
    assert_eq!(left.status, StatusCode::SEE_OTHER, "{}", left.body);
    assert_eq!(right.status, StatusCode::SEE_OTHER, "{}", right.body);

    let got = receiver.requests.recv().await.unwrap();
    assert!(got.head.starts_with("POST /hook HTTP/1.1"), "{}", got.head);
    assert!(
        receiver.requests.try_recv().is_err(),
        "a second test request was sent"
    );
}

fn failure_record() -> DeliveryRecord {
    DeliveryRecord {
        created_at: postkeep_store::now(),
        test: false,
        succeeded: false,
        summary: "HTTP 500".to_owned(),
        elapsed_ms: None,
    }
}

async fn open_store(app: &TestApp) -> Store {
    let url = format!("sqlite://{}", app.dir.path().join("auth.db").display());
    Store::connect(&url, &MasterKey::parse(&app.key).unwrap())
        .await
        .unwrap()
}

async fn account_id(store: &Store) -> AccountId {
    store
        .account_by_email(EMAIL, Provider::Imap)
        .await
        .unwrap()
        .unwrap()
        .id
}

async fn pause_saved_webhook(store: &Store, account: &AccountId) {
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        store
            .record_delivery(account, &failure_record())
            .await
            .unwrap();
    }
    let hook = store.webhook(account).await.unwrap().unwrap();
    assert!(hook.is_paused());
    assert!(hook.settings.enabled);
}

/// "Send test event" with the form unchanged must not clear a pause or
/// reset the failure count, even when the test fails. Saving the same
/// settings still does.
#[tokio::test]
async fn unchanged_failed_test_keeps_a_pause_until_save() {
    let (app, mut receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    let csrf = csrf(&page.body);
    let url = receiver.url("/hook");
    let token = "Bearer secret-token-value-123456";
    let saved = app
        .post_account(
            "/account/webhook",
            &webhook_fields(&csrf, &url, token),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);

    let store = open_store(&app).await;
    let account = account_id(&store).await;
    pause_saved_webhook(&store, &account).await;
    let before = store.webhook(&account).await.unwrap().unwrap();
    let paused_at = before.paused_at;
    let failures = before.consecutive_failures;
    let delivered = before.delivered_sequence;
    store
        .append_mail_event(&account, r#"{"event":"new_mail","id":"kept"}"#, None)
        .await
        .unwrap();

    let woke = Arc::new(AtomicUsize::new(0));
    let flag = Arc::clone(&woke);
    app.state.add_account_listener(Arc::new(move |_| {
        flag.fetch_add(1, Ordering::SeqCst);
    }));
    receiver.respond_with(&[500]);
    // The account form posts a blank auth value; the stored header is kept.
    let reply = app
        .post_account(
            "/account/webhook/test",
            &webhook_fields(&csrf, &url, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(reply.status, StatusCode::SEE_OTHER, "{}", reply.body);
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=webhook-test-failed#alerts"
    );
    let _got = receiver.requests.recv().await.unwrap();
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert_eq!(hook.paused_at, paused_at, "a failed test cleared the pause");
    assert_eq!(hook.consecutive_failures, failures);
    assert_eq!(hook.delivered_sequence, delivered);
    assert!(hook.settings.enabled);
    assert!(hook.is_paused());
    assert_eq!(
        woke.load(Ordering::SeqCst),
        0,
        "a failed test woke the pump"
    );

    let save = app
        .post_account(
            "/account/webhook",
            &webhook_fields(&csrf, &url, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(save.status, StatusCode::SEE_OTHER, "{}", save.body);
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert!(hook.paused_at.is_none(), "Save did not clear the pause");
    assert_eq!(hook.consecutive_failures, 0);
    assert_eq!(
        hook.delivered_sequence, delivered,
        "the paused queue is kept"
    );
    assert!(hook.settings.enabled);
}

/// A successful test of unchanged settings keeps the pause and wakes the
/// pump so a real delivery can recover it.
#[tokio::test]
async fn unchanged_successful_test_keeps_a_pause_and_wakes_the_pump() {
    let (app, mut receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    let csrf = csrf(&page.body);
    let url = receiver.url("/hook");
    let saved = app
        .post_account(
            "/account/webhook",
            &webhook_fields(&csrf, &url, "Bearer secret-token-value-123456"),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);

    let store = open_store(&app).await;
    let account = account_id(&store).await;
    pause_saved_webhook(&store, &account).await;
    let before = store.webhook(&account).await.unwrap().unwrap();
    let woke = Arc::new(AtomicUsize::new(0));
    let flag = Arc::clone(&woke);
    app.state.add_account_listener(Arc::new(move |_| {
        flag.fetch_add(1, Ordering::SeqCst);
    }));
    let reply = app
        .post_account(
            "/account/webhook/test",
            &webhook_fields(&csrf, &url, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=webhook-test-sent#alerts",
        "{}",
        reply.body
    );
    let got = receiver.requests.recv().await.unwrap();
    assert_eq!(got.json()["test"], true);
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert_eq!(hook.paused_at, before.paused_at);
    assert_eq!(hook.consecutive_failures, before.consecutive_failures);
    assert!(hook.is_paused());
    assert_eq!(
        woke.load(Ordering::SeqCst),
        1,
        "a successful test did not wake the pump"
    );
}

/// Changing the URL on the test form still saves, which clears a pause and
/// skips events queued for the previous URL.
#[tokio::test]
async fn changing_the_url_on_the_test_form_still_clears_a_pause() {
    let (app, mut receiver) = webhook_app().await;
    let cookie = app.account_session().await;
    let page = app.get_account(&cookie).await;
    let csrf = csrf(&page.body);
    let url = receiver.url("/hook");
    let saved = app
        .post_account(
            "/account/webhook",
            &webhook_fields(&csrf, &url, "Bearer secret-token-value-123456"),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(saved.status, StatusCode::SEE_OTHER, "{}", saved.body);

    let store = open_store(&app).await;
    let account = account_id(&store).await;
    pause_saved_webhook(&store, &account).await;
    store
        .append_mail_event(&account, r#"{"event":"new_mail","id":"old"}"#, None)
        .await
        .unwrap();
    let before = store.webhook(&account).await.unwrap().unwrap();
    assert!(before.last_sequence >= 1);

    receiver.respond_with(&[500]);
    let changed = receiver.url("/other");
    let reply = app
        .post_account(
            "/account/webhook/test",
            &webhook_fields(&csrf, &changed, ""),
            Some(&cookie),
            Some(ISSUER),
        )
        .await;
    assert_eq!(
        reply.headers[header::LOCATION],
        "/account?notice=webhook-test-failed#alerts",
        "{}",
        reply.body
    );
    let _got = receiver.requests.recv().await.unwrap();
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert_eq!(hook.settings.url, changed);
    assert!(hook.paused_at.is_none());
    assert_eq!(hook.consecutive_failures, 0);
    assert_eq!(hook.delivered_sequence, hook.last_sequence);
    assert!(hook.settings.enabled);
}
