//! An embedding's sign-in hook. `/authorize` hands it the requests for the
//! resources it handles, the embedding approves or denies each one for a
//! principal of its own, and the tokens follow the usual code exchange,
//! rotation and replay rules without ever acting for a mailbox account.

#![allow(
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::Form;
use axum::http::{Request, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Router};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions};
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, BearerRequest, CredentialVerifier, PrincipalResolver,
    Resolution, ResolveFuture, ResourcePrefix, SignInFuture, SignInHook, SignInRequest,
    VerifyFuture,
};
use postkeep_mail::ImapServer;
use postkeep_store::{AccountId, GrantSubject, MasterKey, Store};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const ISSUER: &str = "https://app.example.com";
const HOST: &str = "app.example.com";
const WORKSPACES: &str = "https://app.example.com/w/";
const ACME: &str = "https://app.example.com/w/acme/mcp";
const MAILBOX: &str = "https://app.example.com/mcp";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "http://127.0.0.1/callback";

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

/// What the hook was handed for one request.
#[derive(Debug, PartialEq, Eq)]
struct Started {
    resource: Option<String>,
    client: Option<String>,
    cookie: Option<String>,
    /// Whether the request's `Debug` output shows its ID or the cookie.
    secrets_in_debug: bool,
}

/// Signs people in for the resources under `prefix` with a page that posts
/// to `/consent`, and records every request it is handed.
struct Consent {
    prefix: &'static str,
    started: Mutex<Vec<Started>>,
}

impl Consent {
    fn new(prefix: &'static str) -> Arc<Self> {
        Arc::new(Self {
            prefix,
            started: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.started.lock().unwrap().len()
    }
}

impl SignInHook for Consent {
    fn handles(&self, resource: &str) -> bool {
        resource.starts_with(self.prefix)
    }

    fn start<'a>(&'a self, _state: &'a AuthState, request: SignInRequest<'a>) -> SignInFuture<'a> {
        let debug = format!("{request:?}");
        self.started.lock().unwrap().push(Started {
            resource: request.request.resource.clone(),
            client: request.client.name.clone(),
            cookie: request
                .headers
                .get(header::COOKIE)
                .map(|value| value.to_str().unwrap().to_owned()),
            secrets_in_debug: debug.contains(request.id) || debug.contains("session="),
        });
        let page = format!(
            "<form method=\"post\" action=\"/consent\">\
             <input type=\"hidden\" name=\"request_id\" value=\"{}\"></form>",
            request.id
        );
        // The server replaces this with `no-store`.
        Box::pin(
            async move { ([(header::CACHE_CONTROL, "max-age=600")], Html(page)).into_response() },
        )
    }
}

#[derive(Deserialize)]
struct ConsentForm {
    request_id: String,
    #[serde(default)]
    principal: String,
    action: String,
}

/// The embedding's consent page. A real one takes the principal from its
/// own session and accepts only same-origin posts.
async fn consent(Extension(auth): Extension<AuthState>, Form(form): Form<ConsentForm>) -> Response {
    let finished = if form.action == "approve" {
        auth.approve_sign_in(&form.request_id, &form.principal)
            .await
    } else {
        auth.deny_sign_in(&form.request_id).await
    };
    match finished {
        Ok(Some(response)) => response,
        Ok(None) => (StatusCode::NOT_FOUND, "no such sign-in").into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

/// Takes this server's access tokens for principals: the embedding's
/// members, in the tenant `acme`, each with a mailbox named after it.
struct Members;

impl PrincipalResolver for Members {
    fn resolve<'a>(
        &'a self,
        state: &'a AuthState,
        token: &'a str,
        request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let grant = match state.access_grant(token, request).await? {
                Ok(grant) => grant,
                Err(refusal) => return Ok(Resolution::Refused(refusal)),
            };
            let GrantSubject::Principal(principal) = grant.subject else {
                return Ok(Resolution::Refused("the access token is not for a member"));
            };
            Ok(Resolution::Authenticated(
                Authenticated::for_account(
                    AccountId(format!("mailbox-of-{principal}")),
                    grant.client_id,
                    grant.scope,
                )
                .with_tenant("acme")
                .with_principal(principal),
            ))
        })
    }
}

struct Setup {
    app: Router,
    _dir: tempfile::TempDir,
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|err| unreachable!("{err}: {}", self.body))
    }

    /// The hidden `request_id` of a sign-in or consent page.
    fn request_id(&self) -> String {
        let marker = "name=\"request_id\" value=\"";
        let start = self.body.find(marker).unwrap() + marker.len();
        self.body[start..start + self.body[start..].find('"').unwrap()].to_owned()
    }

    /// The query of a redirect back to the client.
    fn back(&self) -> HashMap<String, String> {
        let location = url::Url::parse(self.headers[header::LOCATION].to_str().unwrap()).unwrap();
        assert_eq!(&location[..url::Position::AfterPath], REDIRECT);
        location.query_pairs().into_owned().collect()
    }

    fn challenge(&self) -> &str {
        self.headers[header::WWW_AUTHENTICATE].to_str().unwrap()
    }

    /// The access and refresh token of a successful token response.
    fn tokens(&self) -> (String, String) {
        assert_eq!(self.status, StatusCode::OK, "{}", self.body);
        let json = self.json();
        let token = |name: &str| json[name].as_str().unwrap().to_owned();
        (token("access_token"), token("refresh_token"))
    }
}

/// Every name under `/w` is its own resource, and `hook` signs people in
/// for them.
fn workspaces(hook: &Arc<Consent>) -> Extensions {
    Extensions::new()
        .resource_prefix(ResourcePrefix::new("/w").unwrap())
        .sign_in_hook(hook.clone())
}

async fn setup(extensions: Extensions) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let mut auth = AuthConfig::new(ISSUER, app::MCP_PATH).unwrap();
    auth.refresh_reuse_grace = std::time::Duration::ZERO;
    auth.requests_per_minute = 10_000;
    let config = AppConfig {
        bucket: None,
        auth,
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits::default(),
        pool: postkeep::pool::PoolConfig::default(),
        watchers: None,
        upstream: None,
        google_push: None,
    };
    let consent_page = Router::new().route("/consent", post(consent));
    let app = app::router_with(
        config,
        store,
        AcceptAll,
        CancellationToken::new(),
        extensions.route(consent_page),
    );
    Setup { app, _dir: dir }
}

impl Setup {
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

    async fn form(&self, uri: &str, fields: &[(&str, &str)]) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send(
            Request::post(uri)
                .header(header::HOST, HOST)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ISSUER)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    async fn register(&self) -> String {
        let reply = self
            .send(
                Request::post("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "client_name": "Agent",
                            "redirect_uris": [REDIRECT],
                            "token_endpoint_auth_method": "none",
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.json()["client_id"].as_str().unwrap().to_owned()
    }

    /// `GET /authorize` from a browser with a session cookie.
    async fn authorize(&self, client_id: &str, resource: Option<&str>) -> Reply {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
            ("state", "xyz"),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
        ];
        if let Some(resource) = resource {
            pairs.push(("resource", resource));
        }
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(pairs)
            .finish();
        self.send(
            Request::get(format!("/authorize?{query}"))
                .header(header::HOST, HOST)
                .header(header::COOKIE, "session=member-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn sign_in_with_password(&self, request_id: &str, action: &str) -> Reply {
        self.form(
            "/authorize",
            &[
                ("request_id", request_id),
                ("email", "user@example.com"),
                ("password", "abcd-efgh-ijkl-mnop"),
                ("action", action),
            ],
        )
        .await
    }

    async fn consent(&self, request_id: &str, principal: &str, action: &str) -> Reply {
        self.form(
            "/consent",
            &[
                ("request_id", request_id),
                ("principal", principal),
                ("action", action),
            ],
        )
        .await
    }

    /// A code for `ACME` that the embedding approved for `principal`.
    async fn approved_code(&self, client_id: &str, principal: &str) -> String {
        let page = self.authorize(client_id, Some(ACME)).await;
        let approved = self.consent(&page.request_id(), principal, "approve").await;
        assert_eq!(approved.status, StatusCode::SEE_OTHER, "{}", approved.body);
        approved.back()["code"].clone()
    }

    async fn exchange(&self, client_id: &str, code: &str, verifier: &str) -> Reply {
        self.form(
            "/token",
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
                ("code_verifier", verifier),
                ("resource", ACME),
            ],
        )
        .await
    }

    async fn refresh(&self, client_id: &str, refresh_token: &str) -> Reply {
        self.form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", client_id),
                ("resource", ACME),
            ],
        )
        .await
    }

    /// `tools/list` at `path` with `token`.
    async fn mcp(&self, path: &str, token: &str) -> Reply {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
        self.send(
            Request::post(path)
                .header(header::HOST, HOST)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header("mcp-protocol-version", "2025-06-18")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
    }
}

#[tokio::test]
async fn the_hook_signs_principals_in_and_the_code_flow_is_unchanged() {
    let hook = Consent::new(WORKSPACES);
    let server = setup(workspaces(&hook).principal_resolver(Arc::new(Members))).await;
    let client = server.register().await;

    let page = server.authorize(&client, Some(ACME)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(page.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        *hook.started.lock().unwrap(),
        [Started {
            resource: Some(ACME.to_owned()),
            client: Some("Agent".to_owned()),
            cookie: Some("session=member-1".to_owned()),
            secrets_in_debug: false,
        }]
    );
    let request_id = page.request_id();
    // The mailbox sign-in can neither finish nor cancel it.
    for action in ["connect", "cancel"] {
        let reply = server.sign_in_with_password(&request_id, action).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{action}");
        assert!(
            reply.body.contains("This sign-in page has expired"),
            "{action}"
        );
    }
    let empty = server.consent(&request_id, "", "approve").await;
    assert_eq!(
        (empty.status, empty.body.as_str()),
        (
            StatusCode::BAD_REQUEST,
            "invalid input: principal must not be empty"
        )
    );

    let approved = server.consent(&request_id, "member-1", "approve").await;
    assert_eq!(approved.status, StatusCode::SEE_OTHER, "{}", approved.body);
    assert_eq!(approved.headers[header::CACHE_CONTROL], "no-store");
    let back = approved.back();
    assert_eq!(
        (back["state"].as_str(), back["iss"].as_str()),
        ("xyz", ISSUER)
    );
    assert_eq!(
        server
            .consent(&request_id, "member-1", "approve")
            .await
            .status,
        StatusCode::NOT_FOUND,
        "approving finished the request"
    );

    let (access, refresh) = server
        .exchange(&client, &back["code"], VERIFIER)
        .await
        .tokens();
    let listed = server.mcp("/w/acme/mcp", &access).await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    let elsewhere = server.mcp("/w/beta/mcp", &access).await;
    assert_eq!(elsewhere.status, StatusCode::UNAUTHORIZED);
    assert!(
        elsewhere
            .challenge()
            .ends_with("error_description=\"the access token is for another resource\""),
        "{}",
        elsewhere.challenge()
    );

    // Refreshing rotates the pair; using the old refresh token again
    // revokes the grant.
    let (rotated, _) = server.refresh(&client, &refresh).await.tokens();
    assert_eq!(
        server.mcp("/w/acme/mcp", &rotated).await.status,
        StatusCode::OK
    );
    let replayed = server.refresh(&client, &refresh).await;
    assert_eq!(replayed.status, StatusCode::BAD_REQUEST);
    assert_eq!(replayed.json()["error"], "invalid_grant");
    assert_eq!(
        server.mcp("/w/acme/mcp", &rotated).await.status,
        StatusCode::UNAUTHORIZED
    );

    // PKCE is checked, and a second use of a code revokes its grant.
    let code = server.approved_code(&client, "member-1").await;
    let wrong = server.exchange(&client, &code, &"x".repeat(43)).await;
    assert_eq!(wrong.json()["error"], "invalid_grant");
    let code = server.approved_code(&client, "member-2").await;
    let (access, _) = server.exchange(&client, &code, VERIFIER).await.tokens();
    assert_eq!(
        server.mcp("/w/acme/mcp", &access).await.status,
        StatusCode::OK
    );
    let again = server.exchange(&client, &code, VERIFIER).await;
    assert_eq!(again.json()["error"], "invalid_grant");
    assert_eq!(
        server.mcp("/w/acme/mcp", &access).await.status,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_default_resolver_refuses_tokens_for_principals() {
    let hook = Consent::new(WORKSPACES);
    let server = setup(workspaces(&hook)).await;
    let client = server.register().await;
    let code = server.approved_code(&client, "member-1").await;
    let (access, _) = server.exchange(&client, &code, VERIFIER).await.tokens();
    let reply = server.mcp("/w/acme/mcp", &access).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(
        reply.challenge().ends_with(
            "error=\"invalid_token\", \
             error_description=\"the access token is not for a mailbox account\""
        ),
        "{}",
        reply.challenge()
    );
}

#[tokio::test]
async fn denying_sends_access_denied_back_to_the_client() {
    let hook = Consent::new(WORKSPACES);
    let server = setup(workspaces(&hook)).await;
    let client = server.register().await;
    let request_id = server.authorize(&client, Some(ACME)).await.request_id();

    let denied = server.consent(&request_id, "", "deny").await;
    assert_eq!(denied.status, StatusCode::SEE_OTHER, "{}", denied.body);
    assert_eq!(denied.headers[header::CACHE_CONTROL], "no-store");
    let back = denied.back();
    assert_eq!(back["error"], "access_denied");
    assert_eq!(
        (back["state"].as_str(), back["iss"].as_str()),
        ("xyz", ISSUER)
    );
    assert!(!back.contains_key("code"));
    assert_eq!(
        server
            .consent(&request_id, "member-1", "approve")
            .await
            .status,
        StatusCode::NOT_FOUND,
        "denying finished the request"
    );
}

#[tokio::test]
async fn other_requests_keep_the_mailbox_sign_in() {
    let hook = Consent::new(WORKSPACES);
    let server = setup(workspaces(&hook)).await;
    let client = server.register().await;
    let page = server.authorize(&client, Some(MAILBOX)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("name=\"password\""), "{}", page.body);
    assert_eq!(hook.calls(), 0);
    // The embedding can neither approve nor deny it, and the mailbox
    // sign-in still finishes it.
    let request_id = page.request_id();
    for action in ["approve", "deny"] {
        assert_eq!(
            server.consent(&request_id, "member-1", action).await.status,
            StatusCode::NOT_FOUND,
            "{action}"
        );
    }
    let signed_in = server.sign_in_with_password(&request_id, "connect").await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    assert!(signed_in.back().contains_key("code"));

    // A request without a resource gets the sign-in page even from a hook
    // that handles every resource.
    let everything = Consent::new("");
    let server = setup(Extensions::new().sign_in_hook(everything.clone())).await;
    let client = server.register().await;
    let page = server.authorize(&client, None).await;
    assert!(page.body.contains("name=\"password\""), "{}", page.body);
    assert_eq!(everything.calls(), 0);
    let page = server.authorize(&client, Some(MAILBOX)).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(everything.calls(), 1);
}
