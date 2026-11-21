//! Allowed host patterns, per-request resources, resources under a path
//! prefix and strict audience binding. The default configuration is
//! covered by `pins.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use clap::Parser as _;
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions};
use postkeep::cli::{Cli, Command};
use postkeep_auth::{
    AuthConfig, AuthState, BearerRequest, CredentialVerifier, PrincipalResolver, Resolution,
    ResolveFuture, ResourcePrefix, VerifyFuture,
};
use postkeep_mail::ImapServer;
use postkeep_store::{CodeGrant, GrantSubject, MasterKey, Store};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const ISSUER: &str = "https://app.example.com";
const HOST_A: &str = "a.mcp.example.com";
const HOST_B: &str = "b.mcp.example.com";
const RESOURCE_A: &str = "https://a.mcp.example.com/mcp";
const RESOURCE_B: &str = "https://b.mcp.example.com/mcp";
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

struct Setup {
    app: Router,
    store: Store,
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

    fn challenge(&self) -> String {
        self.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .to_owned()
    }
}

async fn setup(per_request: bool) -> Setup {
    setup_with(Extensions::new().per_request_resources(per_request)).await
}

async fn setup_with(extensions: Extensions) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let mut auth = AuthConfig::new(ISSUER, app::MCP_PATH).unwrap();
    auth.requests_per_minute = 10_000;
    let config = AppConfig {
        bucket: None,
        auth,
        extra_allowed_hosts: vec!["*.mcp.example.com".to_owned()],
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits::default(),
        pool: postkeep::pool::PoolConfig::default(),
        watchers: None,
        upstream: None,
        google_push: None,
    };
    let app = app::router_with(
        config,
        store.clone(),
        AcceptAll,
        CancellationToken::new(),
        extensions,
    );
    Setup {
        app,
        store,
        _dir: dir,
    }
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
                .header(header::HOST, "app.example.com")
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
                        json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(reply.status, StatusCode::CREATED, "{}", reply.body);
        reply.json()["client_id"].as_str().unwrap().to_owned()
    }

    /// `GET /authorize` with `resource` (or none).
    async fn authorize(&self, client_id: &str, resource: Option<&str>) -> Reply {
        let mut pairs = vec![
            ("response_type", "code"),
            ("client_id", client_id),
            ("redirect_uri", REDIRECT),
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
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    /// Signs in for `resource` and returns the authorization code.
    async fn code(&self, client_id: &str, resource: &str) -> String {
        let page = self.authorize(client_id, Some(resource)).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let marker = "name=\"request_id\" value=\"";
        let start = page.body.find(marker).unwrap() + marker.len();
        let request_id = &page.body[start..start + page.body[start..].find('"').unwrap()];
        let signed_in = self
            .form(
                "/authorize",
                &[
                    ("request_id", request_id),
                    ("email", "user@example.com"),
                    ("password", "abcd-efgh-ijkl-mnop"),
                    ("action", "connect"),
                ],
            )
            .await;
        assert_eq!(
            signed_in.status,
            StatusCode::SEE_OTHER,
            "{}",
            signed_in.body
        );
        let location =
            url::Url::parse(signed_in.headers[header::LOCATION].to_str().unwrap()).unwrap();
        location
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned()
    }

    async fn exchange(&self, client_id: &str, code: &str, resource: Option<&str>) -> Reply {
        let mut fields = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("code_verifier", VERIFIER),
        ];
        if let Some(resource) = resource {
            fields.push(("resource", resource));
        }
        self.form("/token", &fields).await
    }

    async fn mcp(&self, host: &str, token: Option<&str>) -> Reply {
        self.mcp_at(host, app::MCP_PATH, token).await
    }

    async fn mcp_at(&self, host: &str, path: &str, token: Option<&str>) -> Reply {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} });
        let mut request = Request::post(path)
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", "2025-06-18");
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        self.send(request.body(Body::from(body.to_string())).unwrap())
            .await
    }

    /// An access token for a grant stored directly with `resource`.
    async fn token_with_resource(&self, resource: Option<&str>, token: &str) -> String {
        let account = self
            .store
            .upsert_account("direct@example.com", &SecretString::from("pw".to_owned()))
            .await
            .unwrap();
        let client = self.register().await;
        let grant = self
            .store
            .create_grant(&CodeGrant {
                client_id: client,
                subject: GrantSubject::Account(account.id),
                redirect_uri: REDIRECT.to_owned(),
                code_challenge: CHALLENGE.to_owned(),
                scope: "mail".to_owned(),
                resource: resource.map(str::to_owned),
            })
            .await
            .unwrap();
        self.store
            .save_tokens(
                &grant,
                token,
                Duration::from_hours(1),
                &format!("{token}-refresh"),
                Duration::from_hours(1),
            )
            .await
            .unwrap();
        token.to_owned()
    }
}

fn redirect_error(reply: &Reply) -> Option<String> {
    let location = url::Url::parse(reply.headers.get(header::LOCATION)?.to_str().ok()?).ok()?;
    location
        .query_pairs()
        .find(|(key, _)| key == "error")
        .map(|(_, value)| value.into_owned())
}

#[tokio::test]
async fn a_host_pattern_matches_one_label_and_unknown_hosts_are_refused_first() {
    let setup = setup(false).await;
    // An allowed host reaches the bearer check.
    assert_eq!(
        setup.mcp(HOST_A, None).await.status,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        setup.mcp("app.example.com", None).await.status,
        StatusCode::UNAUTHORIZED
    );
    // Others are refused before any token is looked at.
    for host in ["x.y.mcp.example.com", "mcp.example.com", "evil.test"] {
        let reply = setup.mcp(host, Some("whatever")).await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN, "{host}");
        assert_eq!(reply.body, "Forbidden: Host header is not allowed");
        assert!(!reply.headers.contains_key(header::WWW_AUTHENTICATE));
    }
}

#[tokio::test]
async fn each_host_is_its_own_resource() {
    let setup = setup(true).await;
    let metadata = setup
        .send(
            Request::get("/.well-known/oauth-protected-resource/mcp")
                .header(header::HOST, HOST_A)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(metadata.json()["resource"], RESOURCE_A);
    assert_eq!(metadata.json()["authorization_servers"], json!([ISSUER]));
    assert_eq!(
        setup.mcp(HOST_B, None).await.challenge(),
        "Bearer resource_metadata=\"https://b.mcp.example.com/.well-known/oauth-protected-resource/mcp\""
    );

    let client = setup.register().await;
    let code = setup.code(&client, RESOURCE_A).await;
    let token = setup.exchange(&client, &code, Some(RESOURCE_A)).await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    let access = token.json()["access_token"].as_str().unwrap().to_owned();
    let refresh = token.json()["refresh_token"].as_str().unwrap().to_owned();

    let at_a = setup.mcp(HOST_A, Some(&access)).await;
    assert_eq!(at_a.status, StatusCode::OK, "{}", at_a.body);
    // Host A's token presented at host B.
    let at_b = setup.mcp(HOST_B, Some(&access)).await;
    assert_eq!(at_b.status, StatusCode::UNAUTHORIZED);
    assert!(
        at_b.challenge()
            .ends_with("error_description=\"the access token is for another resource\""),
        "{}",
        at_b.challenge()
    );
    // The issuer's own host is not the resource either.
    assert_eq!(
        setup.mcp("app.example.com", Some(&access)).await.status,
        StatusCode::UNAUTHORIZED
    );

    // Refreshing must name the same resource.
    let wrong = setup
        .form(
            "/token",
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &refresh),
                ("client_id", &client),
                ("resource", RESOURCE_B),
            ],
        )
        .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.json()["error"], "invalid_target");
}

#[tokio::test]
async fn resource_is_required_and_exact_at_authorize_and_token() {
    let setup = setup(true).await;
    let client = setup.register().await;
    for resource in [
        None,
        Some(ISSUER),
        Some("https://a.mcp.example.com/mcp/"),
        Some("https://x.y.mcp.example.com/mcp"),
        Some("https://a.mcp.example.com/other"),
    ] {
        let reply = setup.authorize(&client, resource).await;
        assert_eq!(
            redirect_error(&reply).as_deref(),
            Some("invalid_target"),
            "{resource:?}: {} {}",
            reply.status,
            reply.body
        );
    }

    let code = setup.code(&client, RESOURCE_A).await;
    let missing = setup.exchange(&client, &code, None).await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert_eq!(missing.json()["error"], "invalid_request");
    let other = setup.exchange(&client, &code, Some(RESOURCE_B)).await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST);
    assert_eq!(other.json()["error"], "invalid_target");
}

#[tokio::test]
async fn grants_without_the_exact_resource_are_refused() {
    let setup = setup(true).await;
    for (resource, token, description) in [
        (None, "no-resource", "the access token names no resource"),
        (
            Some(ISSUER),
            "issuer-resource",
            "the access token is for another resource",
        ),
        (
            Some(RESOURCE_B),
            "other-host",
            "the access token is for another resource",
        ),
    ] {
        let token = setup.token_with_resource(resource, token).await;
        let reply = setup.mcp(HOST_A, Some(&token)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{resource:?}");
        assert!(
            reply.challenge().ends_with(&format!(
                "error=\"invalid_token\", error_description=\"{description}\""
            )),
            "{resource:?}: {}",
            reply.challenge()
        );
    }
}

#[tokio::test]
async fn the_default_mode_keeps_the_lenient_resource_rules() {
    let setup = setup(false).await;
    // Without per-request resources a grant without a resource still works,
    // as in every earlier version.
    let token = setup.token_with_resource(None, "legacy").await;
    let reply = setup.mcp("app.example.com", Some(&token)).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(
        setup.mcp(HOST_A, None).await.challenge(),
        "Bearer resource_metadata=\"https://app.example.com/.well-known/oauth-protected-resource/mcp\""
    );
}

const APP_HOST: &str = "app.example.com";
const ACME: &str = "https://app.example.com/w/acme/mcp";

fn with_prefix() -> Extensions {
    Extensions::new().resource_prefix(ResourcePrefix::new("/w").unwrap())
}

#[tokio::test]
async fn each_name_under_the_prefix_is_its_own_resource() {
    let setup = setup_with(with_prefix()).await;
    let metadata = setup
        .send(
            Request::get("/.well-known/oauth-protected-resource/w/acme/mcp")
                .header(header::HOST, APP_HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(metadata.status, StatusCode::OK);
    assert_eq!(metadata.json()["resource"], ACME);
    assert_eq!(metadata.json()["authorization_servers"], json!([ISSUER]));
    assert_eq!(
        setup
            .mcp_at(APP_HOST, "/w/beta/mcp", None)
            .await
            .challenge(),
        "Bearer resource_metadata=\"https://app.example.com/.well-known/oauth-protected-resource/w/beta/mcp\""
    );

    let client = setup.register().await;
    for resource in [
        "https://app.example.com/w/acme/mcp/",
        "https://app.example.com/w/a.b/mcp",
        "https://app.example.com/w/a/b/mcp",
        "https://app.example.com/x/acme/mcp",
    ] {
        let reply = setup.authorize(&client, Some(resource)).await;
        assert_eq!(
            redirect_error(&reply).as_deref(),
            Some("invalid_target"),
            "{resource}"
        );
    }
    let code = setup.code(&client, ACME).await;
    let token = setup.exchange(&client, &code, Some(ACME)).await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    let access = token.json()["access_token"].as_str().unwrap().to_owned();

    let at_acme = setup.mcp_at(APP_HOST, "/w/acme/mcp", Some(&access)).await;
    assert_eq!(at_acme.status, StatusCode::OK, "{}", at_acme.body);
    // The same path on another host, another name, the bare endpoint, and a
    // name that cannot be a resource.
    for (host, path, description) in [
        (
            HOST_A,
            "/w/acme/mcp",
            "the access token is for another resource",
        ),
        (
            APP_HOST,
            "/w/beta/mcp",
            "the access token is for another resource",
        ),
        (
            APP_HOST,
            "/w/ACME/mcp",
            "the access token is for another resource",
        ),
        (APP_HOST, "/mcp", "the access token is for another resource"),
        (APP_HOST, "/w/a.b/mcp", "this URL is not served here"),
    ] {
        let reply = setup.mcp_at(host, path, Some(&access)).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{host}{path}");
        assert!(
            reply
                .challenge()
                .ends_with(&format!("error_description=\"{description}\"")),
            "{host}{path}: {}",
            reply.challenge()
        );
    }
    // Deeper paths are not served at all.
    assert_eq!(
        setup
            .mcp_at(APP_HOST, "/w/acme/x/mcp", Some(&access))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

/// Refuses every token and records the resource of each request.
#[derive(Default)]
struct RecordResources(Arc<Mutex<Vec<Option<String>>>>);

impl PrincipalResolver for RecordResources {
    fn resolve<'a>(
        &'a self,
        _state: &'a AuthState,
        _token: &'a str,
        request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        self.0
            .lock()
            .unwrap()
            .push(request.resource.map(str::to_owned));
        Box::pin(async { Ok(Resolution::Refused("recorded")) })
    }
}

#[tokio::test]
async fn a_resolver_sees_the_resource_of_each_request() {
    let recorder = RecordResources::default();
    let seen = recorder.0.clone();
    let setup = setup_with(with_prefix().principal_resolver(Arc::new(recorder))).await;
    for (host, path) in [
        (APP_HOST, "/w/acme/mcp"),
        (HOST_B, "/w/acme/mcp"),
        (HOST_A, "/mcp"),
        (APP_HOST, "/w/a.b/mcp"),
    ] {
        let reply = setup.mcp_at(host, path, Some("any")).await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{host}{path}");
    }
    assert_eq!(
        *seen.lock().unwrap(),
        [
            Some(ACME.to_owned()),
            Some("https://b.mcp.example.com/w/acme/mcp".to_owned()),
            Some(RESOURCE_A.to_owned()),
            None,
        ]
    );
}

/// The other cases build the router with `Extensions`; this one checks that
/// `ServerBuilder::per_request_resources` reaches the server it runs.
/// `ServerBuilder::serve` sets the process's logger and fails once one is
/// set, so this is the only test here that runs it.
#[tokio::test]
async fn the_builder_hands_per_request_resources_to_the_server() {
    let dir = tempfile::tempdir().unwrap();
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let database = format!("sqlite://{}", dir.path().join("server.db").display());
    let master_key = "00".repeat(32);
    let bind = addr.to_string();
    let command_line = [
        "postkeep",
        "serve",
        "--public-url",
        ISSUER,
        "--allowed-hosts",
        "*.mcp.example.com",
        "--master-key",
        &master_key,
        "--database-url",
        &database,
        "--bind",
        &bind,
        "--webhooks",
        "false",
    ];
    let Command::Serve(args) = Cli::try_parse_from(command_line).unwrap().command else {
        unreachable!("parsed serve");
    };
    let server = postkeep::ServerBuilder::new(*args)
        .listener(listener)
        .per_request_resources(true)
        .serve();
    let check = async {
        let deadline = Instant::now() + Duration::from_secs(30);
        let metadata = loop {
            if let Some(body) = get(addr, HOST_A, "/.well-known/oauth-protected-resource/mcp").await
            {
                break serde_json::from_str::<Value>(&body)
                    .unwrap_or_else(|err| panic!("{err}: {body}"));
            }
            assert!(Instant::now() < deadline, "the server never answered");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        // Without per-request resources, every host shares the issuer's.
        assert_eq!(metadata["resource"], RESOURCE_A);
    };
    tokio::select! {
        result = server => panic!("the server stopped: {result:?}"),
        () = check => {}
    }
}

/// The body of `GET path` with `Host: host` from the server at `addr`, or
/// `None` while it does not answer.
async fn get(addr: SocketAddr, host: &str, path: &str) -> Option<String> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await.ok()?;
    let (_, body) = response.split_once("\r\n\r\n")?;
    Some(body.to_owned())
}
