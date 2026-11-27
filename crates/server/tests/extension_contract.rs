//! Every extension point fires when an embedding registers it, through
//! `Extensions` and through `ServerBuilder`. One fake embedding implements
//! every hook and records what each one is asked. A new hook adds its case
//! here; the default build is covered by `pins.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::{IntoResponse as _, Redirect, Response};
use axum::{Extension, Router};
use clap::Parser as _;
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions};
use postkeep::cli::{Cli, Command, ServeArgs};
use postkeep::readiness::{ReadinessCheck, ReadinessFuture};
use postkeep::tools::{
    ExtensionCall, RejectedPassword, SkillDocument, ToolExtension, ToolFuture, WebhookProblem,
    WebhookProblemKind,
};
use postkeep::watch::{SharedJob, WatchConfig, WatchOwnership, WatchSignal, Watchers};
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, BearerRequest, CallEnd, CallbackPage, CeilingsFuture,
    CheckFuture, ContinuationHook, ContinuedSignIn, CredentialVerifier, InvalidRequestPage,
    NewMailbox, Outbox, OutboxCeilings, PrincipalResolver, Refusal, Resolution, ResolveFuture,
    ResourcePrefix, Sending, SignInFuture, SignInHook, SignInRequest, ToolCall, UnreadableRules,
    UsageHook, VerifyFuture,
};
use postkeep_mail::{ImapServer, ImapServers};
use postkeep_store::{
    AccountId, DataKey, Kek, KeyWrapper, MasterKey, NewClient, NewFilterRule, Provider, Store,
    WebhookSettings, WrapFuture, Wrapped,
};
use postkeep_upstream::{AppCredentials, Endpoints, Http, OAuthClient, UpstreamProvider};
use postkeep_webhook::Deliverer;
use rmcp::model::{CallToolResult, Icon, Implementation, Tool};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

const HOST: &str = "mail.example.com";
/// A resource the embedding signs people in for.
const WORKSPACE: &str = "https://mail.example.com/w/acme/mcp";
/// The mailbox resource, which the server signs people in for.
const MAILBOX: &str = "https://mail.example.com/mcp";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const SIGN_IN_PAGE: &str = "the embedding's sign-in page";
const INVALID_PAGE: &str = "the embedding's page for a refused request";
const CALLBACK_PAGE: &str = "the embedding's page at the callback";
const PARAGRAPH: &str = "Plan tools: get_plan reports the workspace's plan.";
const NO_SENDS_LEFT: &str = "this workspace sent all the messages its plan allows today";
const REJECTED: &str = "The mail server rejected the stored password. Reconnect it in the app.";
const DAY: i64 = 24 * 60 * 60;

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

/// Accepts one fixed key and counts every call.
struct CountingResolver {
    account: AccountId,
    calls: AtomicUsize,
}

/// Gives its one key a second mailbox, and turns on the selector.
struct SelectingResolver {
    account: AccountId,
    other: AccountId,
}

impl PrincipalResolver for SelectingResolver {
    fn resolve<'a>(
        &'a self,
        _state: &'a AuthState,
        _token: &'a str,
        _request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            Ok(Resolution::Authenticated(
                Authenticated::for_account(
                    self.account.clone(),
                    "embedding".to_owned(),
                    "mail".to_owned(),
                )
                .with_mailboxes([self.other.clone()]),
            ))
        })
    }

    fn selects_mailboxes(&self) -> bool {
        true
    }
}

impl PrincipalResolver for CountingResolver {
    fn resolve<'a>(
        &'a self,
        _state: &'a AuthState,
        token: &'a str,
        _request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            Ok(if token == "embedding-key" {
                Resolution::Authenticated(
                    Authenticated::for_account(
                        self.account.clone(),
                        "embedding".to_owned(),
                        "mail".to_owned(),
                    )
                    .with_tenant("tenant-a"),
                )
            } else {
                Resolution::Refused("unknown embedding key")
            })
        })
    }
}

/// Not ready until `warm` is set.
struct WarmUp {
    warm: AtomicBool,
}

impl ReadinessCheck for WarmUp {
    fn check(&self) -> ReadinessFuture<'_> {
        Box::pin(async move {
            if self.warm.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err("warming up".to_owned())
            }
        })
    }
}

/// An embedding with every hook, which records what each one is asked. It
/// signs people in for the names under `/w`, adds one tool, lets nothing
/// send, lowers the outbox ceilings, leaves every mailbox and shared job to
/// another process, and wraps data keys with a KEK of its own.
#[derive(Default)]
struct Embedding {
    log: Mutex<Vec<String>>,
}

impl Embedding {
    fn push(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }
}

impl SignInHook for Embedding {
    fn handles(&self, resource: &str) -> bool {
        resource.starts_with("https://mail.example.com/w/")
    }

    fn start<'a>(&'a self, _state: &'a AuthState, request: SignInRequest<'a>) -> SignInFuture<'a> {
        let resource = request.request.resource.as_deref().unwrap_or("-");
        self.push(format!("start {resource}"));
        Box::pin(async { SIGN_IN_PAGE.into_response() })
    }
}

impl ContinuationHook for Embedding {
    fn finish<'a>(
        &'a self,
        _state: &'a AuthState,
        sign_in: ContinuedSignIn<'a>,
    ) -> SignInFuture<'a> {
        let (tenant, continuation) = (sign_in.tenant, sign_in.continuation);
        self.push(format!(
            "finish {tenant} {continuation} {}",
            sign_in.account.email
        ));
        Box::pin(async { Redirect::to("/connected").into_response() })
    }
}

impl InvalidRequestPage for Embedding {
    fn page(&self, request: &axum::http::request::Parts, reason: &str) -> Response {
        self.push(format!(
            "invalid {} {} {reason}",
            request.method, request.uri
        ));
        (StatusCode::BAD_REQUEST, INVALID_PAGE).into_response()
    }

    fn callback_page(
        &self,
        request: &axum::http::request::Parts,
        page: &CallbackPage<'_>,
    ) -> Option<Response> {
        self.push(format!(
            "callback {} {} {} {}",
            request.method,
            request.uri,
            page.status.as_u16(),
            page.title
        ));
        Some((page.status, CALLBACK_PAGE).into_response())
    }
}

impl ToolExtension for Embedding {
    fn server_info(&self, info: Implementation) -> Implementation {
        info.with_website_url("https://example.com")
            .with_icons(vec![Icon::new("https://example.com/icon.png")])
    }

    fn tools(&self, caller: &Authenticated) -> Vec<Tool> {
        self.push(format!("tools {}", caller.tenant));
        let Value::Object(schema) = json!({ "type": "object" }) else {
            unreachable!("a schema is an object");
        };
        vec![Tool::new(
            "get_plan",
            "The workspace's plan.",
            Arc::new(schema),
        )]
    }

    fn skills(&self, caller: &Authenticated) -> Vec<SkillDocument> {
        self.push(format!("skills {}", caller.tenant));
        vec![
            SkillDocument::from_markdown(
                "---\nname: \"daily-review\"\ndescription: \"Review recent activity.\"\n---\n",
            )
            .unwrap(),
        ]
    }

    fn call<'a>(&'a self, call: ExtensionCall<'a>) -> ToolFuture<'a> {
        self.push(format!("call {}", call.name));
        let result = CallToolResult::structured(json!({ "plan": "team" }));
        Box::pin(async move { Ok(result) })
    }

    fn instructions(&self) -> Option<String> {
        Some(PARAGRAPH.to_owned())
    }

    fn check<'a>(&'a self, call: ToolCall<'a>) -> CheckFuture<'a> {
        self.push(format!("check {}", call.name));
        Box::pin(std::future::ready(Ok(())))
    }

    fn password_rejected(&self, rejected: RejectedPassword<'_>) -> Option<String> {
        let (tenant, mailbox) = (&rejected.caller.tenant, &rejected.mailbox.0);
        self.push(format!("rejected {tenant} {mailbox}"));
        Some(REJECTED.to_owned())
    }

    fn webhook_problem(&self, problem: WebhookProblem<'_>) -> Option<String> {
        let (tenant, mailbox) = (&problem.caller.tenant, &problem.mailbox.0);
        self.push(format!("problem {tenant} {mailbox}"));
        Some(worded(problem.kind))
    }
}

/// What the embedding says about `kind`.
fn worded(kind: &WebhookProblemKind) -> String {
    format!("the embedding's words for {kind:?}")
}

impl UsageHook for Embedding {
    fn before_connect<'a>(&'a self, mailbox: NewMailbox<'a>) -> CheckFuture<'a> {
        let (tenant, email) = (mailbox.tenant, mailbox.email);
        self.push(format!(
            "connect {tenant} {email} {}",
            mailbox.provider.as_str()
        ));
        Box::pin(std::future::ready(Ok(())))
    }

    fn before_call<'a>(&'a self, call: ToolCall<'a>) -> CheckFuture<'a> {
        self.push(format!("usage {}", call.name));
        Box::pin(std::future::ready(Ok(())))
    }

    fn before_send<'a>(&'a self, sending: Sending<'a>) -> CheckFuture<'a> {
        self.push(format!("send {}", sending.mailbox.0));
        Box::pin(std::future::ready(Err(Refusal::new(NO_SENDS_LEFT))))
    }

    fn after_call(&self, call: ToolCall<'_>, end: CallEnd) {
        self.push(format!("after {} {:?}", call.name, end.outcome));
    }

    fn outbox_ceilings<'a>(&'a self, outbox: Outbox<'a>) -> CeilingsFuture<'a> {
        self.push(format!("ceilings {} {}", outbox.tenant, outbox.mailbox.0));
        let ceilings = OutboxCeilings::new(14 * DAY, 2_000).with_max_filter_rules(2);
        Box::pin(std::future::ready(Some(ceilings)))
    }
}

impl WatchOwnership for Embedding {
    fn attach(&self, _watchers: &Watchers) {
        self.push("attach".to_owned());
    }

    fn owns(&self, account: &AccountId) -> bool {
        self.push(format!("owns {}", account.0));
        false
    }

    fn forward(&self, signal: WatchSignal) {
        self.push(format!("forward {signal:?}"));
    }

    fn runs(&self, job: SharedJob) -> bool {
        self.push(format!("runs {job:?}"));
        false
    }
}

impl KeyWrapper for Embedding {
    fn current(&self) -> Kek {
        Kek {
            provider: "embedding".to_owned(),
            id: "kek-1".to_owned(),
            version: 1,
        }
    }

    fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
        self.push(format!("wrap {tenant}"));
        let bytes = key.expose().iter().map(|byte| !byte).collect();
        let kek = self.current();
        Box::pin(std::future::ready(Ok(Wrapped { kek, bytes })))
    }

    fn unwrap<'a>(
        &'a self,
        tenant: &'a str,
        kek: &'a Kek,
        wrapped: &'a [u8],
    ) -> WrapFuture<'a, DataKey> {
        self.push(format!("unwrap {tenant} {}", kek.id));
        let key = DataKey::from_bytes(&wrapped.iter().map(|byte| !byte).collect::<Vec<_>>());
        Box::pin(std::future::ready(key))
    }
}

/// A response's status, headers (names in lower case) and body.
struct Reply {
    status: StatusCode,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> &str {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map_or("", |(_, value)| value.as_str())
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_owned()))
        .collect();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn get(app: &Router, path: &str) -> (StatusCode, String) {
    let request = Request::get(path).header(header::HOST, HOST);
    let reply = send(app, request.body(Body::empty()).unwrap()).await;
    (reply.status, reply.body)
}

async fn mcp(app: &Router, token: &str, method: &str) -> (StatusCode, String) {
    mcp_with(app, token, method, json!({})).await
}

async fn mcp_with(app: &Router, token: &str, method: &str, params: Value) -> (StatusCode, String) {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let response = app
        .clone()
        .oneshot(
            Request::post(app::MCP_PATH)
                .header(header::HOST, HOST)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header("mcp-protocol-version", "2025-06-18")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Calls `tool` with the embedding's key: `Ok` with the structured output,
/// or `Err` with the error text.
async fn call(app: &Router, tool: &str, arguments: Value) -> Result<Value, String> {
    let params = json!({ "name": tool, "arguments": arguments });
    let (status, body) = mcp_with(app, "embedding-key", "tools/call", params).await;
    assert_eq!(status, StatusCode::OK, "{tool}: {body}");
    let reply: Value = serde_json::from_str(&body).unwrap();
    let result = &reply["result"];
    if result["isError"] == true {
        Err(result["content"][0]["text"].as_str().unwrap().to_owned())
    } else {
        Ok(result["structuredContent"].clone())
    }
}

fn config() -> AppConfig {
    AppConfig {
        bucket: None,
        auth: AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap(),
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits::default(),
        pool: postkeep::pool::PoolConfig::default(),
        watchers: None,
        upstream: None,
        google_push: None,
    }
}

async fn store(dir: &tempfile::TempDir) -> Store {
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    Store::connect(&url, &key).await.unwrap()
}

/// The caller's mailbox in `tenant-a`, on an IMAP preset this server no
/// longer offers so that no server tool reaches the network, and an MCP
/// client.
async fn caller_and_client(store: &Store) -> (AccountId, String) {
    let password = SecretString::from("pw".to_owned());
    let account = store
        .for_tenant("tenant-a")
        .upsert_imap_account("user@example.com", &password, Some("retired"))
        .await
        .unwrap();
    let client = store
        .create_client(&NewClient {
            name: Some("Agent".to_owned()),
            redirect_uris: vec!["http://127.0.0.1/cb".to_owned()],
            secret: None,
        })
        .await
        .unwrap();
    (account.id, client.id)
}

/// The embedding's page that adds a Microsoft mailbox to `tenant-a`. A real
/// one takes the tenant from its own session and accepts only same-origin
/// posts.
async fn connect(Extension(auth): Extension<AuthState>) -> Response {
    let started = auth
        .start_upstream_sign_in(UpstreamProvider::Microsoft, "tenant-a", "connect-1", None)
        .await;
    match started {
        Ok(Some(redirect)) => redirect,
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    }
}

/// A server with every hook of one [`Embedding`], its key resolved by a
/// [`CountingResolver`], webhooks on, and Microsoft sign-in against a mock.
struct Harness {
    app: Router,
    embedding: Arc<Embedding>,
    watchers: Watchers,
    store: Store,
    account: AccountId,
    client: String,
    microsoft: MockServer,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir).await;
    let (account, client) = caller_and_client(&store).await;
    let microsoft = MockServer::start().await;
    let credentials = AppCredentials {
        client_id: "ms-client".to_owned(),
        client_secret: SecretString::from("shh".to_owned()),
    };
    let upstream = OAuthClient::new(
        Http::for_tests(),
        Endpoints::all_at(&url::Url::parse(&microsoft.uri()).unwrap()),
        url::Url::parse(&format!("https://{HOST}")).unwrap(),
        Some(credentials),
        None,
    );
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::default(),
        Deliverer::new("postkeep-contract"),
        WatchConfig::default(),
        CancellationToken::new(),
    );
    let embedding = Arc::new(Embedding::default());
    let resolver = Arc::new(CountingResolver {
        account: account.clone(),
        calls: AtomicUsize::new(0),
    });
    let app = app::router_with(
        AppConfig {
            watchers: Some(watchers.clone()),
            upstream: Some(upstream),
            ..config()
        },
        store.clone(),
        AcceptAll,
        CancellationToken::new(),
        Extensions::new()
            .route(Router::new().route("/connect", axum::routing::post(connect)))
            .principal_resolver(resolver)
            .resource_prefix(ResourcePrefix::new("/w").unwrap())
            .sign_in_hook(embedding.clone())
            .continuation_hook(embedding.clone())
            .invalid_request_page(embedding.clone())
            .tool_extension(embedding.clone())
            .usage_hook(embedding.clone())
            .watch_ownership(embedding.clone()),
    );
    assert_eq!(
        embedding.take(),
        ["attach"],
        "the watchers are handed over once"
    );
    Harness {
        app,
        embedding,
        watchers,
        store,
        account,
        client,
        microsoft,
        _dir: dir,
    }
}

/// `GET /authorize` for `client` and `resource`.
fn authorize_path(client: &str, resource: &str) -> String {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("response_type", "code"),
            ("client_id", client),
            ("code_challenge", CHALLENGE),
            ("code_challenge_method", "S256"),
            ("resource", resource),
        ])
        .finish();
    format!("/authorize?{query}")
}

/// Microsoft's token endpoint and Graph, signing `email` in.
async fn mock_microsoft(server: &MockServer, email: &str) {
    Mock::given(matchers::method("POST"))
        .and(matchers::path("/microsoft/common/oauth2/v2.0/token"))
        .and(matchers::body_string_contains("code=ms-code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "ms-access", "refresh_token": "ms-refresh", "expires_in": 3600,
            "scope": "Mail.ReadWrite Mail.Send User.Read"
        })))
        .mount(server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/graph/v1.0/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "ms-user-1", "mail": email, "userPrincipalName": email
        })))
        .mount(server)
        .await;
    Mock::given(matchers::method("GET"))
        .and(matchers::path("/graph/v1.0/me/mailFolders/inbox"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "inbox-id" })))
        .mount(server)
        .await;
}

/// `postkeep serve` settings for a server on `addr` with the database at
/// `database_url` and Microsoft sign-in.
fn serve_args(addr: SocketAddr, database_url: &str) -> ServeArgs {
    let master_key = "00".repeat(32);
    let bind = addr.to_string();
    let command_line = [
        "postkeep",
        "serve",
        "--public-url",
        "https://mail.example.com",
        "--master-key",
        &master_key,
        "--database-url",
        database_url,
        "--bind",
        &bind,
        "--microsoft-client-id",
        "ms-client",
        "--microsoft-client-secret",
        "shh",
    ];
    let Command::Serve(args) = Cli::try_parse_from(command_line).unwrap().command else {
        unreachable!("parsed serve");
    };
    *args
}

/// Sends one request to the server at `addr`; `None` while it does not
/// answer.
async fn send_to(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Option<Reply> {
    let mut stream = tokio::net::TcpStream::connect(addr).await.ok()?;
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        let _ = write!(request, "{name}: {value}\r\n");
    }
    let _ = write!(request, "\r\n{body}");
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await.ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_owned()))
        .collect();
    Some(Reply {
        status: StatusCode::from_u16(status).ok()?,
        headers,
        body: body.to_owned(),
    })
}

/// Status and body of `GET path` from the server at `addr`, or `None` while
/// it does not answer.
async fn fetch(addr: SocketAddr, path: &str) -> Option<(u16, String)> {
    let reply = send_to(addr, "GET", path, &[], "").await?;
    Some((reply.status.as_u16(), reply.body))
}

/// Waits until `GET path` from the server at `addr` answers `expected`.
async fn wait_for(addr: SocketAddr, path: &str, expected: (u16, &str)) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let reply = fetch(addr, path).await;
        if reply
            .as_ref()
            .is_some_and(|(status, body)| (*status, body.as_str()) == expected)
        {
            return;
        }
        assert!(Instant::now() < deadline, "{path} answered {reply:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One MCP request with the embedding's key to the server at `addr`.
async fn mcp_at(addr: SocketAddr, method: &str, params: Value) -> Value {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let headers = [
        ("content-type", "application/json"),
        ("accept", "application/json, text/event-stream"),
        ("mcp-protocol-version", "2025-06-18"),
        ("authorization", "Bearer embedding-key"),
    ];
    let reply = send_to(addr, "POST", app::MCP_PATH, &headers, &body.to_string())
        .await
        .unwrap();
    assert_eq!(reply.status, StatusCode::OK, "{method}: {}", reply.body);
    serde_json::from_str(&reply.body).unwrap()
}

/// `ServerBuilder::serve` sets the process's logger and fails once one is
/// set, so this is the only test here that runs it.
#[tokio::test]
async fn every_builder_addition_reaches_the_server_it_runs() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    // `--bind` names a port held here, so a server that binds it fails.
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let held = taken.local_addr().unwrap();
    let database = |name: &str| format!("sqlite://{}", dir.path().join(name).display());

    let store = postkeep::open_store(&serve_args(addr, &database("shared.db")))
        .await
        .unwrap();
    sqlx::query("CREATE TABLE embedding_notes (body TEXT NOT NULL)")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO embedding_notes (body) VALUES ($1)")
        .bind("kept by the embedding")
        .execute(store.pool())
        .await
        .unwrap();
    let (account, client) = caller_and_client(&store).await;
    let pool = store.pool().clone();
    let routes = Router::new()
        .route(
            "/ext/note",
            axum::routing::get(move || async move {
                sqlx::query_scalar::<_, String>("SELECT body FROM embedding_notes")
                    .fetch_one(&pool)
                    .await
                    .unwrap()
            }),
        )
        .route("/connect", axum::routing::post(connect));
    let embedding = Arc::new(Embedding::default());
    let resolver = Arc::new(CountingResolver {
        account,
        calls: AtomicUsize::new(0),
    });
    let warm_up = Arc::new(WarmUp {
        warm: AtomicBool::new(false),
    });

    // A server that opened a database of its own would create this file.
    let server = postkeep::ServerBuilder::new(serve_args(held, &database("unused.db")))
        .store(store)
        .listener(listener)
        .route(routes)
        .principal_resolver(resolver.clone())
        .resource_prefix(ResourcePrefix::new("/w").unwrap())
        .sign_in_hook(embedding.clone())
        .continuation_hook(embedding.clone())
        .invalid_request_page(embedding.clone())
        .tool_extension(embedding.clone())
        .usage_hook(embedding.clone())
        .watch_ownership(embedding.clone())
        .readiness_check(warm_up.clone())
        .default_pages(false)
        .serve();
    let checks = async {
        wait_for(addr, "/readyz", (503, "warming up")).await;
        warm_up.warm.store(true, Ordering::SeqCst);
        wait_for(addr, "/readyz", (200, "ready")).await;
        // The purge and the background pass start beside the server and ask
        // first thing, in either order.
        let deadline = Instant::now() + Duration::from_secs(30);
        while embedding.log.lock().unwrap().len() < 3 {
            assert!(Instant::now() < deadline, "{:?}", embedding.take());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut asked = embedding.take();
        assert_eq!(asked.remove(0), "attach");
        asked.sort();
        assert_eq!(asked, ["runs Purge", "runs Reencrypt"]);
        assert_eq!(
            fetch(addr, "/ext/note").await,
            Some((200, "kept by the embedding".to_owned()))
        );
        for page in ["/", "/account"] {
            let reply = fetch(addr, page).await.unwrap();
            assert_eq!(reply.0, 404, "{page} is a default page");
        }
        let started = send_to(addr, "POST", "/connect", &[], "").await.unwrap();
        assert_eq!(started.status, StatusCode::SEE_OTHER, "{}", started.body);
        let microsoft = started.header("location");
        assert!(
            microsoft.starts_with("https://login.microsoftonline.com/"),
            "{microsoft}"
        );
        assert_eq!(
            fetch(addr, &authorize_path(&client, WORKSPACE)).await,
            Some((200, SIGN_IN_PAGE.to_owned()))
        );
        assert_eq!(
            fetch(addr, "/authorize").await,
            Some((400, INVALID_PAGE.to_owned()))
        );
        assert_eq!(
            fetch(addr, "/oauth/microsoft/callback").await,
            Some((400, CALLBACK_PAGE.to_owned()))
        );
        let listed = mcp_at(addr, "tools/list", json!({})).await;
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 19);
        let listed = mcp_at(addr, "skills/list", json!({})).await;
        let skills = listed["result"]["skills"].as_array().unwrap();
        assert_eq!(
            skills.last().unwrap()["frontmatter"]["name"],
            "daily-review"
        );
        let get_plan = json!({ "name": "get_plan", "arguments": {} });
        let called = mcp_at(addr, "tools/call", get_plan).await;
        assert_eq!(
            called["result"]["structuredContent"],
            json!({ "plan": "team" })
        );
        assert_eq!(
            embedding.take(),
            [
                format!("start {WORKSPACE}"),
                "invalid GET /authorize The authorization request has no client_id.".to_owned(),
                "callback GET /oauth/microsoft/callback 400 This sign-in has expired".to_owned(),
                "tools tenant-a".to_owned(),
                "skills tenant-a".to_owned(),
                "tools tenant-a".to_owned(),
                "check get_plan".to_owned(),
                "usage get_plan".to_owned(),
                "call get_plan".to_owned(),
                "after get_plan Done".to_owned(),
            ]
        );
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 3);
    };
    tokio::select! {
        result = server => panic!("the server stopped: {result:?}"),
        () = checks => {}
    }
    assert!(!dir.path().join("unused.db").exists());
}

#[tokio::test]
async fn the_principal_resolver_decides_mcp_access() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir).await;
    let account = store
        .upsert_account("user@example.com", &SecretString::from("pw".to_owned()))
        .await
        .unwrap();
    let resolver = Arc::new(CountingResolver {
        account: account.id.clone(),
        calls: AtomicUsize::new(0),
    });
    let app = app::router_with(
        config(),
        store,
        AcceptAll,
        CancellationToken::new(),
        Extensions::new().principal_resolver(resolver.clone()),
    );

    let (status, body) = mcp(&app, "embedding-key", "tools/list").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 18);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

    let (status, _) = mcp(&app, "some-token", "tools/list").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_readiness_check_holds_readyz_until_it_passes() {
    let dir = tempfile::tempdir().unwrap();
    let check = Arc::new(WarmUp {
        warm: AtomicBool::new(false),
    });
    let app = app::router_with(
        config(),
        store(&dir).await,
        AcceptAll,
        CancellationToken::new(),
        Extensions::new().readiness_check(check.clone()),
    );
    assert_eq!(
        get(&app, "/readyz").await,
        (StatusCode::SERVICE_UNAVAILABLE, "warming up".to_owned())
    );
    assert_eq!(
        get(&app, "/healthz").await,
        (StatusCode::OK, "ok".to_owned())
    );

    check.warm.store(true, Ordering::SeqCst);
    // `/readyz` reuses an answer for up to a second.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let reply = get(&app, "/readyz").await;
        if reply == (StatusCode::OK, "ready".to_owned()) {
            break;
        }
        assert!(Instant::now() < deadline, "still {reply:?}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn a_selecting_resolver_turns_on_the_mailbox_selector() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir).await;
    let password = SecretString::from("pw".to_owned());
    let account = store
        .upsert_imap_account("user@example.com", &password, Some("retired"))
        .await
        .unwrap();
    let other = store
        .upsert_imap_account("other@example.com", &password, Some("retired"))
        .await
        .unwrap();
    let app = app::router_with(
        config(),
        store.clone(),
        AcceptAll,
        CancellationToken::new(),
        Extensions::new().principal_resolver(Arc::new(SelectingResolver {
            account: account.id,
            other: other.id.clone(),
        })),
    );

    let (status, body) = mcp(&app, "key", "tools/list").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Value = serde_json::from_str(&body).unwrap();
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert!(
        tools
            .iter()
            .all(|tool| tool["inputSchema"]["properties"]["mailbox"]["type"] == "string")
    );

    store
        .save_webhook(
            &other.id,
            &postkeep_store::WebhookSettings {
                enabled: true,
                url: "https://hooks.example.com/other".to_owned(),
                auth_header: None,
                signing: true,
                signing_secret: SecretString::from("whsec_test-secret-0123456789".to_owned()),
                include_sender: false,
            },
        )
        .await
        .unwrap();
    let (status, body) = mcp_with(
        &app,
        "key",
        "tools/call",
        json!({ "name": "get_webhook_status", "arguments": { "mailbox": "other@example.com" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let called: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        called["result"]["structuredContent"]["configured"], true,
        "{body}"
    );
}

#[tokio::test]
async fn the_sign_in_hook_answers_authorize_for_its_resources() {
    let h = harness().await;
    assert_eq!(
        get(&h.app, &authorize_path(&h.client, WORKSPACE)).await,
        (StatusCode::OK, SIGN_IN_PAGE.to_owned())
    );
    assert_eq!(h.embedding.take(), [format!("start {WORKSPACE}")]);

    let (status, page) = get(&h.app, &authorize_path(&h.client, MAILBOX)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("name=\"request_id\""), "{page}");
    assert_eq!(h.embedding.take(), Vec::<String>::new());
}

#[tokio::test]
async fn the_invalid_request_page_answers_the_requests_authorize_refuses() {
    let h = harness().await;
    assert_eq!(
        get(&h.app, "/authorize").await,
        (StatusCode::BAD_REQUEST, INVALID_PAGE.to_owned())
    );
    assert_eq!(
        get(&h.app, &authorize_path("nope", WORKSPACE)).await,
        (StatusCode::BAD_REQUEST, INVALID_PAGE.to_owned())
    );
    let unknown = format!(
        "invalid GET {} The app asking for access is not registered with this server.",
        authorize_path("nope", WORKSPACE)
    );
    assert_eq!(
        h.embedding.take(),
        [
            "invalid GET /authorize The authorization request has no client_id.".to_owned(),
            unknown,
        ]
    );

    // A request it accepts is not the page's.
    assert_eq!(
        get(&h.app, &authorize_path(&h.client, WORKSPACE)).await,
        (StatusCode::OK, SIGN_IN_PAGE.to_owned())
    );
    assert_eq!(h.embedding.take(), [format!("start {WORKSPACE}")]);
}

#[tokio::test]
async fn the_invalid_request_page_answers_the_callbacks_own_pages() {
    let h = harness().await;
    assert_eq!(
        get(&h.app, "/oauth/microsoft/callback").await,
        (StatusCode::BAD_REQUEST, CALLBACK_PAGE.to_owned())
    );
    assert_eq!(
        h.embedding.take(),
        ["callback GET /oauth/microsoft/callback 400 This sign-in has expired"]
    );
}

#[tokio::test]
async fn the_continuation_hook_finishes_the_sign_ins_the_embedding_starts() {
    let h = harness().await;
    mock_microsoft(&h.microsoft, "person@example.com").await;
    let start = Request::post("/connect").header(header::HOST, HOST);
    let started = send(&h.app, start.body(Body::empty()).unwrap()).await;
    assert_eq!(started.status, StatusCode::SEE_OTHER, "{}", started.body);
    let location = url::Url::parse(started.header("location")).unwrap();
    let (_, state) = location
        .query_pairs()
        .find(|(key, _)| key == "state")
        .unwrap();
    let cookie = started.header("set-cookie").split(';').next().unwrap();

    let callback = Request::get(format!(
        "/oauth/microsoft/callback?code=ms-code&state={state}"
    ))
    .header(header::HOST, HOST)
    .header(header::COOKIE, cookie);
    let finished = send(&h.app, callback.body(Body::empty()).unwrap()).await;
    assert_eq!(finished.status, StatusCode::SEE_OTHER, "{}", finished.body);
    assert_eq!(finished.header("location"), "/connected");
    let account = h
        .store
        .for_tenant("tenant-a")
        .account_by_subject(Provider::Graph, "ms-user-1")
        .await
        .unwrap()
        .unwrap();
    // The usage hook allows the new mailbox, and the process that watches
    // it hears about it, before the embedding gets the browser back.
    assert_eq!(
        h.embedding.take(),
        [
            "connect tenant-a person@example.com graph".to_owned(),
            format!("owns {}", account.id.0),
            format!("forward {:?}", WatchSignal::Changed(account.id)),
            "finish tenant-a connect-1 person@example.com".to_owned(),
        ]
    );
}

#[tokio::test]
async fn the_tool_extension_lists_checks_and_runs_its_tools() {
    let h = harness().await;
    let (status, body) = mcp(&h.app, "embedding-key", "tools/list").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Value = serde_json::from_str(&body).unwrap();
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!((tools.len(), &tools[18]["name"]), (19, &json!("get_plan")));
    assert_eq!(h.embedding.take(), ["tools tenant-a"]);

    let (status, body) = mcp(&h.app, "embedding-key", "skills/list").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: Value = serde_json::from_str(&body).unwrap();
    let skills = listed["result"]["skills"].as_array().unwrap();
    assert_eq!(skills.len(), 4);
    assert_eq!(skills[3]["uri"], "skill://daily-review/SKILL.md");
    assert_eq!(h.embedding.take(), ["skills tenant-a"]);

    let initialize = json!({
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": { "name": "contract", "version": "1" }
    });
    let (_, body) = mcp_with(&h.app, "embedding-key", "initialize", initialize).await;
    let info: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        info["result"]["serverInfo"],
        json!({
            "name": "postkeep",
            "title": "postkeep",
            "version": env!("CARGO_PKG_VERSION"),
            "websiteUrl": "https://example.com",
            "icons": [{ "src": "https://example.com/icon.png" }]
        })
    );
    let instructions = info["result"]["instructions"].as_str().unwrap();
    assert!(instructions.ends_with(PARAGRAPH), "{instructions}");

    assert_eq!(
        call(&h.app, "get_plan", json!({})).await,
        Ok(json!({ "plan": "team" }))
    );
    assert_eq!(
        h.embedding.take(),
        [
            "tools tenant-a",
            "check get_plan",
            "usage get_plan",
            "call get_plan",
            "after get_plan Done"
        ]
    );
}

#[tokio::test]
async fn the_tool_extension_words_the_status_of_a_mailbox_with_a_rejected_password() {
    let h = harness().await;
    let status = call(&h.app, "get_webhook_status", json!({})).await.unwrap();
    assert_eq!(status["state"], "not_configured", "{status}");
    let asked = h.embedding.take();
    assert!(asked.iter().all(|entry| !entry.starts_with("rejected")));

    h.store.mark_password_rejected(&h.account).await.unwrap();
    let status = call(&h.app, "get_webhook_status", json!({})).await.unwrap();
    assert_eq!(status["state"], "needs_password", "{status}");
    assert_eq!(status["message"], REJECTED, "{status}");
    let asked = format!("rejected tenant-a {}", h.account.0);
    assert!(h.embedding.take().contains(&asked));
}

#[tokio::test]
async fn the_tool_extension_words_each_webhook_problem_a_tool_tells() {
    let h = harness().await;
    let said = |kind: WebhookProblemKind| Err(worded(&kind));
    let message = |status: Value| Err(status["message"].as_str().unwrap().to_owned());
    let rule = json!({ "action": "allow", "field": "from", "kind": "equals", "pattern": "a@b.c" });
    for (tool, arguments) in [
        ("set_webhook_enabled", json!({ "enabled": false })),
        ("set_webhook_outbox_limits", json!({ "reset": true })),
        ("list_webhook_filters", json!({})),
        ("add_webhook_filter", rule.clone()),
        ("remove_webhook_filter", json!({ "all": true })),
    ] {
        let answer = call(&h.app, tool, arguments).await;
        assert_eq!(answer, said(WebhookProblemKind::NoWebhook), "{tool}");
    }
    let asked = format!("problem tenant-a {}", h.account.0);
    let log = h.embedding.take();
    let times = log.iter().filter(|entry| **entry == asked).count();
    assert_eq!(times, 5, "{log:?}");

    let mut hook = WebhookSettings {
        enabled: false,
        url: String::new(),
        auth_header: None,
        signing: true,
        signing_secret: SecretString::from("whsec_contract".to_owned()),
        include_sender: false,
    };
    h.store.save_webhook(&h.account, &hook).await.unwrap();
    let enable = json!({ "enabled": true });
    let answer = call(&h.app, "set_webhook_enabled", enable.clone()).await;
    assert_eq!(answer, said(WebhookProblemKind::NoEndpoint));
    // The hook is asked only for words a tool says: not by an add whose rules parse.
    h.embedding.take();
    let added = call(&h.app, "add_webhook_filter", rule.clone()).await;
    assert!(added.is_ok(), "{added:?}");
    let all = json!({ "all": true });
    call(&h.app, "remove_webhook_filter", all).await.unwrap();
    let log = h.embedding.take();
    assert!(!log.contains(&asked), "{log:?}");

    hook.enabled = true;
    hook.url = "https://hooks.example.com/new-mail".to_owned();
    h.store.save_webhook(&h.account, &hook).await.unwrap();
    // A rule on a field this version doesn't know.
    let unknown = NewFilterRule {
        action: "allow".to_owned(),
        field: "body".to_owned(),
        kind: "contains".to_owned(),
        pattern: SecretString::from("x".to_owned()),
    };
    let added = h
        .store
        .add_webhook_filter_rule(&h.account, &unknown, 2, |_| Ok(()));
    added.await.unwrap();
    let unknown = WebhookProblemKind::Rules(UnreadableRules::UnknownName);
    let status = call(&h.app, "get_webhook_status", json!({})).await.unwrap();
    assert_eq!(status["state"], "rules_unreadable", "{status}");
    assert_eq!(message(status), said(unknown.clone()));
    let answer = call(&h.app, "add_webhook_filter", rule).await;
    assert_eq!(answer, said(unknown));
    // Nor by the status of a webhook that is off, which shows no message.
    let off = json!({ "enabled": false });
    call(&h.app, "set_webhook_enabled", off).await.unwrap();
    h.embedding.take();
    let status = call(&h.app, "get_webhook_status", json!({})).await.unwrap();
    assert_eq!(status["state"], "disabled", "{status}");
    assert_eq!(status["filter_rules_unreadable"], true, "{status}");
    let log = h.embedding.take();
    assert!(!log.contains(&asked), "{log:?}");
    call(&h.app, "set_webhook_enabled", enable.clone())
        .await
        .unwrap();

    let garble = "UPDATE webhook_filter_rules SET pattern_ciphertext = 'bad'";
    sqlx::query(garble).execute(h.store.pool()).await.unwrap();
    let status = call(&h.app, "get_webhook_status", json!({})).await.unwrap();
    assert_eq!(
        message(status),
        said(WebhookProblemKind::RulesUndecryptable)
    );
    let answer = call(&h.app, "list_webhook_filters", json!({})).await;
    assert_eq!(answer, said(WebhookProblemKind::RulesUndecryptable));

    let garble = "UPDATE webhooks SET signing_secret_ciphertext = 'bad'";
    sqlx::query(garble).execute(h.store.pool()).await.unwrap();
    let status = call(&h.app, "get_webhook_status", json!({})).await.unwrap();
    assert_eq!(status["state"], "unreadable", "{status}");
    let kind = WebhookProblemKind::Unreadable { turning_on: false };
    assert_eq!(message(status), said(kind));
    let answer = call(&h.app, "set_webhook_enabled", enable).await;
    assert_eq!(
        answer,
        said(WebhookProblemKind::Unreadable { turning_on: true })
    );
}

#[tokio::test]
async fn the_usage_hook_is_asked_before_calls_sends_and_outbox_ceilings_and_hears_the_end() {
    let h = harness().await;
    let mailbox = &h.account.0;
    let message = json!({ "to": ["x@example.com"], "subject": "s", "body": "b" });
    assert_eq!(
        call(&h.app, "send_message", message).await,
        Err(NO_SENDS_LEFT.to_owned())
    );
    assert_eq!(
        h.embedding.take(),
        [
            "check send_message".to_owned(),
            "usage send_message".to_owned(),
            format!("send {mailbox}"),
            "after send_message Refused".to_owned(),
        ]
    );

    let status = call(&h.app, "get_webhook_status", json!({})).await.unwrap();
    let ceilings = (
        &status["outbox_max_retention_seconds"],
        &status["outbox_max_events_limit"],
    );
    assert_eq!(ceilings, (&json!(14 * DAY), &json!(2_000)), "{status}");
    assert_eq!(status["filter_rules_limit"], 2, "{status}");
    assert_eq!(
        h.embedding.take(),
        [
            "check get_webhook_status".to_owned(),
            "usage get_webhook_status".to_owned(),
            format!("ceilings tenant-a {mailbox}"),
            "after get_webhook_status Done".to_owned(),
        ]
    );
}

#[tokio::test]
async fn the_usage_hook_says_how_many_filter_rules_a_mailbox_may_have() {
    let h = harness().await;
    let settings = postkeep_store::WebhookSettings {
        enabled: true,
        url: "https://hooks.example.com/mail".to_owned(),
        auth_header: None,
        signing: false,
        signing_secret: SecretString::from("whsec_test".to_owned()),
        include_sender: true,
    };
    h.store.save_webhook(&h.account, &settings).await.unwrap();
    let rule = json!({ "action": "block", "field": "from", "kind": "contains", "pattern": "x" });
    let asked_once = || {
        let asked = h.embedding.take();
        let ceilings = asked.iter().filter(|entry| entry.starts_with("ceilings"));
        assert_eq!(ceilings.count(), 1, "{asked:?}");
    };
    for _ in 0..2 {
        call(&h.app, "add_webhook_filter", rule.clone())
            .await
            .unwrap();
        asked_once();
    }
    let third = call(&h.app, "add_webhook_filter", rule).await;
    assert_eq!(
        third,
        Err("This mailbox may have at most 2 filter rules.".to_owned())
    );
    asked_once();
}

#[tokio::test]
async fn the_ownership_hook_hears_of_changes_to_mailboxes_it_leaves_to_others() {
    let h = harness().await;
    h.watchers.refresh(&h.account);
    assert_eq!(
        h.embedding.take(),
        [
            format!("owns {}", h.account.0),
            format!("forward {:?}", WatchSignal::Changed(h.account.clone())),
        ]
    );
}

/// The key wrapper is set on the store that an embedding hands to the
/// server, not on the builder. A store wraps its tenants' data keys with it,
/// and a new store, under another master key, unwraps them through it.
#[tokio::test]
async fn the_key_wrapper_wraps_and_unwraps_the_data_keys_of_a_store() {
    let dir = tempfile::tempdir().unwrap();
    let embedding = Arc::new(Embedding::default());
    let first = store(&dir).await.with_key_wrapper(embedding.clone());
    let (version, key) = first.for_tenant("tenant-a").data_key().await.unwrap();
    assert_eq!(version, 1);
    // A new key is read back through the wrapper.
    assert_eq!(embedding.take(), ["wrap tenant-a", "unwrap tenant-a kek-1"]);
    let row = sqlx::query_as::<_, (String, String)>("SELECT provider, kek_id FROM data_keys")
        .fetch_one(first.pool())
        .await
        .unwrap();
    assert_eq!(row, ("embedding".to_owned(), "kek-1".to_owned()));

    let second = store(&dir).await.with_key_wrapper(embedding.clone());
    let (_, found) = second.for_tenant("tenant-a").data_key().await.unwrap();
    assert_eq!(found.expose(), key.expose());
    assert_eq!(embedding.take(), ["unwrap tenant-a kek-1"]);
}
