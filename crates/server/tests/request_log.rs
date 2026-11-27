//! The request log: one JSON line per answered request outside the probes,
//! with its route as written, its status and its time, and the caller, the
//! tool and its outcome for MCP requests, while no line holds a query, a
//! path value, a header, a body, a tool's arguments or result, a token, a
//! client IP or an email address. Every other line of a request carries its
//! `request_id`. Runs in process on SQLite, without network access.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderName, Request, StatusCode, header};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions, RequestLimits};
use postkeep::tools::{ExtensionCall, GET_MAILBOX_CAPABILITIES, ToolExtension, ToolFuture};
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, BearerRequest, CheckFuture, CredentialVerifier,
    PrincipalResolver, Refusal, Resolution, ResolveFuture, ToolCall, VerifyFuture,
};
use postkeep_mail::{ImapSecurity, ImapServer, ImapServers, MailConfig};
use postkeep_store::{AccountId, MasterKey, Store};
use rmcp::ErrorData;
use rmcp::model::{CallToolResult, Tool};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use tracing::subscriber::DefaultGuard;

const HOST: &str = "mail.example.com";
const LOG_TARGET: &str = "postkeep::request_log";
/// Markers that ride on requests and must reach no line.
const HEADER_MARKERS: [&str; 4] = [
    "agent-marker",
    "cookie-marker",
    "origin-marker",
    "203.0.113.77",
];

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

/// `workspace-key` is `key:1` in `tenant-a`, and with selection on, also
/// `key:2` in `tenant-b`.
struct Keys(AccountId, Option<AccountId>);

impl PrincipalResolver for Keys {
    fn resolve<'a>(
        &'a self,
        _state: &'a AuthState,
        token: &'a str,
        _request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let caller = |account: &AccountId, tenant, principal| {
                Authenticated::for_account(account.clone(), "agent".to_owned(), "mail".to_owned())
                    .with_tenant(tenant)
                    .with_principal(principal)
            };
            Ok(match token {
                "workspace-key" => {
                    let a = caller(&self.0, "tenant-a", "key:1");
                    let Some(other) = &self.1 else {
                        return Ok(Resolution::Authenticated(a));
                    };
                    let b = caller(other, "tenant-b", "key:2");
                    Resolution::Authenticated(a.clone().with_tenancies(vec![a, b]))
                }
                _ => Resolution::Refused("unknown key"),
            })
        })
    }

    fn selects_mailboxes(&self) -> bool {
        self.1.is_some()
    }

    fn tenant_argument(&self) -> Option<&'static str> {
        Some("tenant")
    }
}

/// Lists `get_account`, which takes 20 ms, and `broken_account`, which
/// answers a JSON-RPC error; refuses `delete_message`.
struct AccountTools;

fn tool(name: &'static str) -> Tool {
    let Value::Object(schema) = json!({ "type": "object" }) else {
        panic!("a schema is an object");
    };
    Tool::new(name, "An account tool.", Arc::new(schema))
}

impl ToolExtension for AccountTools {
    fn tools(&self, _caller: &Authenticated) -> Vec<Tool> {
        vec![tool("get_account"), tool("broken_account")]
    }

    fn hides_tool(&self, caller: &Authenticated, name: &str) -> bool {
        caller.principal == "key:1" && name == GET_MAILBOX_CAPABILITIES
    }

    fn call<'a>(&'a self, call: ExtensionCall<'a>) -> ToolFuture<'a> {
        let broken = call.name == "broken_account";
        Box::pin(async move {
            if broken {
                return Err(ErrorData::invalid_params("bad arguments", None));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(CallToolResult::structured(
                json!({ "marker": "result-marker" }),
            ))
        })
    }

    fn check<'a>(&'a self, call: ToolCall<'a>) -> CheckFuture<'a> {
        let verdict = if call.name == "delete_message" {
            Err(Refusal::new("deleting mail is turned off"))
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(verdict))
    }
}

struct Harness {
    app: Router,
    _dir: tempfile::TempDir,
}

async fn harness(limits: RequestLimits) -> Harness {
    harness_with(limits, true, None, false).await
}

/// With `extension` false, no tool extension: a tool call skips its check.
/// With `mail`, the account uses that IMAP server instead of a retired preset.
/// With `selects`, the caller can also act in a second tenant.
async fn harness_with(
    limits: RequestLimits,
    extension: bool,
    mail: Option<MailConfig>,
    selects: bool,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let password = SecretString::from("app-password".to_owned());
    // A preset this server no longer offers: a server tool that opens it fails.
    let account = store
        .for_tenant("tenant-a")
        .upsert_imap_account(
            "a@example.com",
            &password,
            mail.is_none().then_some("retired"),
        )
        .await
        .unwrap();
    let mut auth = AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap();
    auth.client_ip_header = Some(HeaderName::from_static("fly-client-ip"));
    auth.requests_per_minute = 3;
    auth.registrations_per_ip = 0;
    if let Some(mail) = mail {
        auth.imap_servers = ImapServers::custom_only("Silent", mail);
    }
    let config = AppConfig {
        bucket: None,
        auth,
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: vec!["https://origin-marker.example".to_owned()],
        limits,
        pool: postkeep::pool::PoolConfig::default(),
        watchers: None,
        upstream: None,
        google_push: None,
    };
    let other = if selects {
        Some(
            store
                .for_tenant("tenant-b")
                .upsert_imap_account("b@example.com", &password, Some("retired"))
                .await
                .unwrap()
                .id,
        )
    } else {
        None
    };
    let mut extensions = Extensions::new().principal_resolver(Arc::new(Keys(account.id, other)));
    if extension {
        extensions = extensions.tool_extension(Arc::new(AccountTools));
    }
    let app = app::router_with(
        config,
        store,
        AcceptAll,
        CancellationToken::new(),
        extensions,
    );
    Harness { app, _dir: dir }
}

struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The JSON lines `POSTKEEP_LOG_FORMAT=json` writes at `info`, for the whole
/// test on its thread; rmcp's tasks run there too on the current-thread
/// runtime.
struct Capture {
    buf: Arc<Mutex<Vec<u8>>>,
    _guard: DefaultGuard,
}

fn capture() -> Capture {
    // With one dispatcher alive, a callsite's interest comes from the thread
    // that reaches it first; two idle ones alive for the whole process make
    // tracing ask every dispatcher, so no test's capture loses lines.
    static OTHERS: OnceLock<[tracing::Dispatch; 2]> = OnceLock::new();
    OTHERS.get_or_init(|| {
        [(); 2].map(|()| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()))
    });
    let buf = Arc::new(Mutex::new(Vec::new()));
    let writer = Arc::clone(&buf);
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || Shared(Arc::clone(&writer)))
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    Capture { buf, _guard: guard }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8(self.buf.lock().unwrap().clone()).unwrap()
    }

    fn lines(&self) -> Vec<Value> {
        self.text()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn requests(&self) -> Vec<Value> {
        self.lines()
            .into_iter()
            .filter(|line| line["target"] == LOG_TARGET)
            .collect()
    }

    /// The first line with `message`, which must exist.
    fn find(&self, message: &str) -> Value {
        self.lines()
            .into_iter()
            .find(|line| line["message"] == message)
            .unwrap_or_else(|| panic!("no line {message:?}: {}", self.text()))
    }

    /// Asserts that no captured line holds any of `markers`.
    fn assert_absent(&self, markers: &[&str]) {
        let text = self.text();
        for marker in markers {
            assert!(!text.contains(marker), "{marker} was logged: {text}");
        }
    }
}

/// The keys of a line, sorted.
fn keys(line: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = line
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

/// Asserts a request line's exact keys besides `timestamp`, `level`,
/// `message`, `target`, `request_id` and `ms`, and their values.
fn assert_line(line: &Value, expected: &Value) {
    let id = line["request_id"].as_str().unwrap();
    assert!(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{line}"
    );
    assert!(line["ms"].is_u64(), "{line}");
    assert_eq!(line["level"], "INFO", "{line}");
    assert_eq!(line["message"], "answered a request", "{line}");
    let mut want: Vec<&str> = expected
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    want.extend([
        "timestamp",
        "level",
        "message",
        "target",
        "request_id",
        "ms",
    ]);
    want.sort_unstable();
    assert_eq!(keys(line), want, "{line}");
    for (key, value) in expected.as_object().unwrap() {
        assert_eq!(&line[key], value, "{key}: {line}");
    }
}

/// Adds the header markers to a request.
fn marked(builder: axum::http::request::Builder) -> axum::http::request::Builder {
    builder
        .header(header::USER_AGENT, "agent-marker/1.0")
        .header(header::COOKIE, "theme=cookie-marker")
        .header(header::ORIGIN, "https://origin-marker.example")
        .header("fly-client-ip", "203.0.113.77")
}

/// A JSON-RPC request to `/mcp` at `host`, with the header markers.
fn mcp_at(host: &str, token: &str, method: &str, params: &Value) -> Request<Body> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    marked(Request::post(app::MCP_PATH))
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", "2025-06-18")
        .header("mcp-method", method)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A `tools/call` of `name`, with the header markers.
fn call(token: &str, name: &str, arguments: &Value) -> Request<Body> {
    let params = json!({ "name": name, "arguments": arguments });
    mcp_at(HOST, token, "tools/call", &params)
}

/// A `GET` of `uri`, with the header markers.
fn get(uri: &str) -> Request<Body> {
    marked(Request::get(uri))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap()
}

/// Sends `request` and reads the whole answer; returns its status.
async fn send(app: &Router, request: Request<Body>) -> StatusCode {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    response.into_body().collect().await.unwrap();
    status
}

#[tokio::test]
async fn pages_log_their_route_and_no_query_header_path_value_or_client_ip() {
    let h = harness(RequestLimits::default()).await;
    let log = capture();
    send(
        &h.app,
        get("/oauth/microsoft/callback?code=code-marker&state=state-marker"),
    )
    .await;
    let registration = json!({
        "redirect_uris": ["https://client.example/cb"],
        "client_name": "name-marker"
    });
    let register = marked(Request::post("/register"))
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(registration.to_string()))
        .unwrap();
    assert_eq!(send(&h.app, register).await, StatusCode::TOO_MANY_REQUESTS);
    let authorize = "/authorize?client_id=client-marker&login_hint=hint-marker%40mail-marker.test";
    send(&h.app, get(authorize)).await;
    assert_eq!(
        send(&h.app, get(authorize)).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        send(&h.app, get("/no/such/path-marker")).await,
        StatusCode::NOT_FOUND
    );

    let requests = log.requests();
    assert_eq!(requests.len(), 5, "{}", log.text());
    for (message, request) in [
        ("client registration limit reached", &requests[1]),
        ("rate limit exceeded", &requests[3]),
    ] {
        let line = log.find(message);
        assert!(line.get("client").is_none(), "{line}");
        assert!(line.get("path").is_none(), "{line}");
        assert_eq!(line["span"]["request_id"], request["request_id"], "{line}");
    }
    let callback = &requests[0];
    assert_line(
        callback,
        &json!({
            "method": "GET",
            "route": "/oauth/{provider}/callback",
            "status": callback["status"],
        }),
    );
    assert_line(
        &requests[1],
        &json!({ "method": "POST", "route": "/register", "status": 429 }),
    );
    let first = &requests[2];
    assert_line(
        first,
        &json!({ "method": "GET", "route": "/authorize", "status": first["status"] }),
    );
    assert_ne!(first["status"], 429, "{first}");
    assert_line(
        &requests[3],
        &json!({ "method": "GET", "route": "/authorize", "status": 429 }),
    );
    assert_line(&requests[4], &json!({ "method": "GET", "status": 404 }));

    log.assert_absent(&[
        "code-marker",
        "state-marker",
        "name-marker",
        "client-marker",
        "hint-marker",
        "mail-marker",
        "path-marker",
    ]);
    log.assert_absent(&HEADER_MARKERS);
}

#[tokio::test]
async fn the_probes_log_no_line() {
    let h = harness(RequestLimits::default()).await;
    let log = capture();
    send(&h.app, get("/no/such/path")).await;
    send(&h.app, get("/healthz")).await;
    send(&h.app, get("/readyz")).await;

    let requests = log.requests();
    assert!(!requests.is_empty(), "the 404 is logged: {}", log.text());
    assert_eq!(requests.len(), 1, "{}", log.text());
    assert_eq!(requests[0]["status"], 404);
    for line in &requests {
        assert_ne!(line["route"], "/healthz");
        assert_ne!(line["route"], "/readyz");
    }
}

#[tokio::test]
async fn every_line_of_a_request_carries_its_request_id() {
    let h = harness(RequestLimits::default()).await;
    let log = capture();
    let refused = "refused an MCP request for a host this server does not serve";
    for _ in 0..2 {
        let request = mcp_at("evil.example", "workspace-key", "tools/list", &json!({}));
        assert_eq!(send(&h.app, request).await, StatusCode::FORBIDDEN);
    }
    let warns: Vec<Value> = log
        .lines()
        .into_iter()
        .filter(|line| line["message"] == refused)
        .collect();
    assert_eq!(warns.len(), 2, "{}", log.text());
    let requests = log.requests();
    assert_eq!(requests.len(), 2, "{}", log.text());
    for (warn, request) in warns.iter().zip(&requests) {
        assert_eq!(warn["span"]["request_id"], request["request_id"], "{warn}");
        assert_line(
            request,
            &json!({ "method": "POST", "route": "/mcp", "status": 403 }),
        );
    }
    assert_ne!(requests[0]["request_id"], requests[1]["request_id"]);

    // Both are written in rmcp's task for the call.
    for name in ["delete_message", "no-such-tool"] {
        let request = call("workspace-key", name, &json!({ "id": "m1" }));
        assert_eq!(send(&h.app, request).await, StatusCode::OK);
    }
    let requests = log.requests();
    assert_eq!(requests.len(), 4, "{}", log.text());
    let refusal = log.find("the embedding refused a tool call");
    assert_eq!(
        refusal["span"]["request_id"], requests[2]["request_id"],
        "{refusal}"
    );
    let error = log.find("response error");
    let id = &requests[3]["request_id"];
    assert!(
        error["spans"]
            .as_array()
            .unwrap()
            .iter()
            .any(|span| &span["request_id"] == id),
        "{error}"
    );
    assert!(error["span"].get("request_id").is_none(), "{error}");
}

#[tokio::test]
async fn a_tool_call_logs_its_caller_tool_outcome_and_time_and_no_secret() {
    let h = harness(RequestLimits::default()).await;
    let log = capture();
    let mail = json!({
        "to": ["x@mail-marker.test"],
        "subject": "subject-marker",
        "body": "body-marker"
    });
    for (token, name, arguments, status) in [
        (
            "workspace-key",
            "get_account",
            json!({ "note": "argument-marker" }),
            StatusCode::OK,
        ),
        ("workspace-key", "send_message", mail, StatusCode::OK),
        (
            "workspace-key",
            "delete_message",
            json!({ "id": "m1" }),
            StatusCode::OK,
        ),
        (
            "wrong-key",
            "get_account",
            json!({}),
            StatusCode::UNAUTHORIZED,
        ),
    ] {
        assert_eq!(
            send(&h.app, call(token, name, &arguments)).await,
            status,
            "{name}"
        );
    }

    log.find("the embedding refused a tool call");
    let requests = log.requests();
    assert_eq!(requests.len(), 4, "{}", log.text());
    let caller = |tool: &str, outcome: &str| {
        json!({
            "method": "POST",
            "route": "/mcp",
            "status": 200,
            "principal": "key:1",
            "tenant": "tenant-a",
            "tool": tool,
            "outcome": outcome,
        })
    };
    assert_line(&requests[0], &caller("get_account", "ok"));
    assert!(requests[0]["ms"].as_u64().unwrap() >= 20, "{}", requests[0]);
    assert_line(&requests[1], &caller("send_message", "tool_error"));
    assert_line(&requests[2], &caller("delete_message", "tool_error"));
    assert_line(
        &requests[3],
        &json!({ "method": "POST", "route": "/mcp", "status": 401 }),
    );

    log.assert_absent(&[
        "workspace-key",
        "wrong-key",
        "argument-marker",
        "result-marker",
        "mail-marker",
        "subject-marker",
        "body-marker",
    ]);
    log.assert_absent(&HEADER_MARKERS);
}

#[tokio::test]
async fn json_rpc_errors_log_rpc_error_and_name_only_real_tools() {
    let h = harness(RequestLimits::default()).await;
    let log = capture();
    for name in [
        "no-such-tool\nforged",
        GET_MAILBOX_CAPABILITIES,
        "broken_account",
    ] {
        let request = call("workspace-key", name, &json!({}));
        assert_eq!(send(&h.app, request).await, StatusCode::OK, "{name}");
    }

    let errors = log
        .lines()
        .into_iter()
        .filter(|line| line["message"] == "response error")
        .count();
    assert_eq!(errors, 3, "{}", log.text());
    let requests = log.requests();
    assert_eq!(requests.len(), 3, "{}", log.text());
    let caller = json!({
        "method": "POST",
        "route": "/mcp",
        "status": 200,
        "principal": "key:1",
        "tenant": "tenant-a",
        "outcome": "rpc_error",
    });
    assert_line(&requests[0], &caller);
    assert_line(&requests[1], &caller);
    let mut broken = caller;
    broken["tool"] = json!("broken_account");
    assert_line(&requests[2], &broken);

    log.assert_absent(&["no-such-tool", GET_MAILBOX_CAPABILITIES]);
}

#[tokio::test]
async fn the_caller_is_logged_once_the_token_check_passed() {
    let h = harness(RequestLimits::default()).await;
    let log = capture();
    let request = mcp_at(HOST, "workspace-key", "tools/list", &json!({}));
    assert_eq!(send(&h.app, request).await, StatusCode::OK);

    let requests = log.requests();
    assert_eq!(requests.len(), 1, "{}", log.text());
    assert_line(
        &requests[0],
        &json!({
            "method": "POST",
            "route": "/mcp",
            "status": 200,
            "principal": "key:1",
            "tenant": "tenant-a",
        }),
    );
}

#[tokio::test]
async fn an_answer_of_the_limits_is_logged() {
    let limits = RequestLimits {
        max_body_bytes: 64,
        ..RequestLimits::default()
    };
    let h = harness(limits).await;
    let log = capture();
    let request = Request::post(app::MCP_PATH)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, 1024)
        .body(Body::from(vec![b' '; 1024]))
        .unwrap();
    assert_eq!(send(&h.app, request).await, StatusCode::PAYLOAD_TOO_LARGE);

    let requests = log.requests();
    assert_eq!(requests.len(), 1, "{}", log.text());
    assert_line(
        &requests[0],
        &json!({ "method": "POST", "route": "/mcp", "status": 413 }),
    );
}

#[tokio::test]
async fn the_request_line_keeps_the_principal_and_tenant_together() {
    let h = harness_with(RequestLimits::default(), false, None, true).await;
    let log = capture();
    let request = call(
        "workspace-key",
        "get_webhook_status",
        &json!({ "tenant": "tenant-b" }),
    );
    assert_eq!(send(&h.app, request).await, StatusCode::OK);
    let mut broken = call("workspace-key", "get_webhook_status", &json!({}));
    *broken.body_mut() = Body::from_stream(futures::stream::once(async {
        Err::<axum::body::Bytes, _>(io::Error::other("interrupted body"))
    }));
    assert_eq!(send(&h.app, broken).await, StatusCode::BAD_REQUEST);

    // With no hooks or bucket, the selector's refusal still comes before
    // the tool can answer that uploads are off.
    let refused = call(
        "workspace-key",
        "upload_attachment",
        &json!({ "tenant": "unknown" }),
    );
    let response = h.app.clone().oneshot(refused).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let reply: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        reply["result"]["content"][0]["text"],
        "unknown tenant: pass the id of one this connection can use"
    );

    let requests = log.requests();
    assert_eq!(requests.len(), 3, "{}", log.text());
    assert_line(
        &requests[0],
        &json!({
            "method": "POST", "route": "/mcp", "status": 200,
            "principal": "key:2", "tenant": "tenant-b", "tool": "get_webhook_status", "outcome": "ok",
        }),
    );
    assert_line(
        &requests[1],
        &json!({
            "method": "POST", "route": "/mcp", "status": 400,
            "principal": "key:1", "tenant": "tenant-a",
        }),
    );
    assert_line(
        &requests[2],
        &json!({
            "method": "POST", "route": "/mcp", "status": 200,
            "principal": "key:1", "tenant": "tenant-a", "tool": "upload_attachment", "outcome": "tool_error",
        }),
    );
}

#[tokio::test]
async fn without_an_extension_server_tools_are_named_and_unknown_names_are_not() {
    let h = harness_with(RequestLimits::default(), false, None, false).await;
    let log = capture();
    let mail = json!({ "to": ["x@example.test"], "subject": "s", "body": "b" });
    for (name, arguments) in [("send_message", mail), ("no-such-tool", json!({}))] {
        let request = call("workspace-key", name, &arguments);
        assert_eq!(send(&h.app, request).await, StatusCode::OK, "{name}");
    }

    log.find("response error");
    let requests = log.requests();
    assert_eq!(requests.len(), 2, "{}", log.text());
    let mut caller = json!({
        "method": "POST",
        "route": "/mcp",
        "status": 200,
        "principal": "key:1",
        "tenant": "tenant-a",
        "outcome": "rpc_error",
    });
    assert_line(&requests[1], &caller);
    caller["tool"] = json!("send_message");
    caller["outcome"] = json!("tool_error");
    assert_line(&requests[0], &caller);
}

#[tokio::test]
async fn a_server_tool_cut_off_by_the_timeout_is_still_named() {
    // An IMAP server on this machine that accepts and never greets, so the
    // call outlasts the request timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _open = socket;
                std::future::pending::<()>().await;
            });
        }
    });
    let mut mail = MailConfig::default();
    mail.imap.host = "127.0.0.1".to_owned();
    mail.imap.port = port;
    mail.imap.security = ImapSecurity::Plaintext;
    mail.timeout = Duration::from_secs(30);
    let limits = RequestLimits {
        request_timeout: Duration::from_millis(300),
        ..RequestLimits::default()
    };
    let h = harness_with(limits, false, Some(mail), false).await;
    let log = capture();
    let request = call("workspace-key", "list_folders", &json!({}));
    assert_eq!(send(&h.app, request).await, StatusCode::SERVICE_UNAVAILABLE);

    let requests = log.requests();
    assert_eq!(requests.len(), 1, "{}", log.text());
    assert_line(
        &requests[0],
        &json!({
            "method": "POST",
            "route": "/mcp",
            "status": 503,
            "principal": "key:1",
            "tenant": "tenant-a",
            "tool": "list_folders",
        }),
    );
}
