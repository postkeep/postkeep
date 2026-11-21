//! End-to-end tests: OAuth sign-in, then MCP over Streamable HTTP.
//!
//! `mcp_endpoint_*` tests run without a mail server. The `greenmail_*` tests
//! are ignored by default and need GreenMail (see CONTRIBUTING.md).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

mod common;
mod imap;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering::SeqCst};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig};
use postkeep::mailbox::id::{imap_id, parse_imap_id};
use postkeep::mailbox::{
    Change, Criteria, Cutoff, Mailbox, NOTHING_LEFT, Selected,
    selection::{REFUSAL, SearchSelection},
};
use postkeep::watch::{WatchConfig, Watchers};
use postkeep_auth::{AuthConfig, CredentialVerifier, MailVerifier, VerifyFuture};
use postkeep_mail::{ImapSecurity, ImapServer, ImapServers, MailConfig, Paging, SmtpSecurity};
use postkeep_store::{
    AccountId, DeliveryRecord, MasterKey, NewFilterRule, Provider, Store, StoreError, WatchCursor,
    WebhookSettings,
};
use postkeep_webhook::testing::{Receiver, receiver};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use imap::{ACCEPT, BUSY, REJECT, scripted_mail, unreachable_mail};

const HOST: &str = "mail.example.com";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "http://127.0.0.1/callback";
const PROTOCOL: &str = "2025-06-18";
/// The origin of a browser-based client that `harness` also accepts.
const BROWSER_CLIENT: &str = "http://localhost:6274";

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

struct Harness {
    app: Router,
    store: Store,
    watchers: Option<Watchers>,
    receiver: Option<Receiver>,
    _dir: tempfile::TempDir,
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|err| panic!("{err}: {}", self.body))
    }
}

async fn harness(mail: MailConfig, verifier: impl CredentialVerifier) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let mut auth = AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap();
    auth.imap_servers = ImapServers::custom_only("Test mail", mail);
    let config = AppConfig {
        auth,
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: vec![BROWSER_CLIENT.to_owned()],
        limits: app::RequestLimits {
            max_body_bytes: 64 * 1024,
            ..app::RequestLimits::default()
        },
        pool: postkeep::pool::PoolConfig::default(),
        watchers: None,
        upstream: None,
        google_push: None,
    };
    Harness {
        app: app::router(config, store.clone(), verifier, CancellationToken::new()),
        store,
        watchers: None,
        receiver: None,
        _dir: dir,
    }
}

/// Watchers on, with a local receiver. The store is the same one the app uses.
async fn webhook_harness() -> Harness {
    webhook_harness_for(unreachable_mail(), |_, _| {}).await
}

/// [`webhook_harness`] with the mail server of `mail`; `tune` changes the
/// watcher and pool settings.
async fn webhook_harness_for(
    mail: MailConfig,
    tune: impl FnOnce(&mut WatchConfig, &mut postkeep::pool::PoolConfig),
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let hook_receiver = receiver(&[]).await;
    let mut auth = AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap();
    auth.imap_servers = ImapServers::custom_only("Test mail", mail.clone());
    let mut watch = WatchConfig {
        retry_delays: Vec::new(),
        outbox_min_backoff: Duration::from_millis(20),
        outbox_max_backoff: Duration::from_millis(50),
        webhook_retry_interval: Duration::from_millis(400),
        ..WatchConfig::default()
    };
    let mut pool = postkeep::pool::PoolConfig::default();
    tune(&mut watch, &mut pool);
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::custom_only("Test mail", mail),
        hook_receiver.deliverer.clone(),
        watch,
        CancellationToken::new(),
    );
    let config = AppConfig {
        auth,
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits {
            max_body_bytes: 64 * 1024,
            ..app::RequestLimits::default()
        },
        pool,
        watchers: Some(watchers.clone()),
        upstream: None,
        google_push: None,
    };
    Harness {
        app: app::router(config, store.clone(), AcceptAll, CancellationToken::new()),
        store,
        watchers: Some(watchers),
        receiver: Some(hook_receiver),
        _dir: dir,
    }
}

impl Harness {
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
                // `POST /authorize` requires this. `/token` ignores it.
                .header(header::ORIGIN, format!("https://{HOST}"))
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    /// Registers a client, signs in and returns an access token.
    async fn sign_in(&self, email: &str, password: &str) -> String {
        let register = self
            .send(
                Request::post("/register")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "client_name": "Test" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(register.status, StatusCode::CREATED, "{}", register.body);
        let client_id = register.json()["client_id"].as_str().unwrap().to_owned();

        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", REDIRECT),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
                ("resource", &format!("https://{HOST}/mcp")),
            ])
            .finish();
        let page = self
            .send(
                Request::get(format!("/authorize?{query}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let marker = "name=\"request_id\" value=\"";
        let start = page.body.find(marker).unwrap() + marker.len();
        let request_id = &page.body[start..start + page.body[start..].find('"').unwrap()];

        let signed_in = self
            .form(
                "/authorize",
                &[
                    ("request_id", request_id),
                    ("email", email),
                    ("password", password),
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
        let code = location
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();

        let token = self
            .form(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", &code),
                    ("client_id", &client_id),
                    ("code_verifier", VERIFIER),
                ],
            )
            .await;
        assert_eq!(token.status, StatusCode::OK, "{}", token.body);
        token.json()["access_token"].as_str().unwrap().to_owned()
    }

    /// Waits for the watchers and the outbox pumps that sign-ins started to
    /// stop, as each does at once while no webhook is saved. One still
    /// starting could read a webhook saved next and run a session of its own
    /// (another login, an early catch-up) or deliver an event early. Call it
    /// before anything else starts a watcher or a pump, as `running` and
    /// `pumps` count every account's.
    async fn until_watchers_stop(&self) {
        let watchers = self
            .watchers
            .as_ref()
            .expect("until_watchers_stop needs a webhook harness");
        for _ in 0..1000 {
            if watchers.running() == 0 && watchers.pumps() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(watchers.running(), 0, "the sign-ins' watchers did not stop");
        assert_eq!(
            watchers.pumps(),
            0,
            "the sign-ins' outbox pumps did not stop"
        );
    }

    async fn rpc_raw(&self, token: Option<&str>, host: &str, body: &Value) -> Reply {
        self.rpc_from(token, host, None, body).await
    }

    /// [`Self::rpc_raw`] with the `Origin` a browser page would send.
    async fn rpc_from(
        &self,
        token: Option<&str>,
        host: &str,
        origin: Option<&str>,
        body: &Value,
    ) -> Reply {
        let mut request = Request::post("/mcp")
            .header(header::HOST, host)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL);
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        self.send(request.body(Body::from(body.to_string())).unwrap())
            .await
    }

    async fn rpc(&self, token: &str, method: &str, params: Value) -> Value {
        let reply = self
            .rpc_raw(
                Some(token),
                HOST,
                &json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
            )
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{method}: {}", reply.body);
        let body = reply.json();
        assert!(body.get("error").is_none(), "{method}: {body}");
        body["result"].clone()
    }

    async fn call(&self, token: &str, tool: &str, arguments: Value) -> Value {
        self.rpc(
            token,
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }

    /// Calls `tool`, which must succeed, and returns its `structuredContent`
    /// once that matches the output schema that `tools/list` advertises.
    async fn call_ok(&self, token: &str, tool: &str, arguments: Value) -> Value {
        let result = self.call(token, tool, arguments).await;
        assert_ne!(result["isError"], json!(true), "{tool}: {result}");
        let listed = self.rpc(token, "tools/list", json!({})).await;
        common::assert_matches_output_schema(&listed["tools"], tool, &result["structuredContent"]);
        result["structuredContent"].clone()
    }
}

fn initialize() -> Value {
    json!({
        "protocolVersion": PROTOCOL,
        "capabilities": {},
        "clientInfo": { "name": "test", "version": "1.0" },
    })
}

#[tokio::test]
async fn mcp_endpoint_records_a_rejected_password_until_a_login_works() {
    let login = Arc::new(AtomicU8::new(BUSY));
    let mail = scripted_mail(Arc::clone(&login), Arc::default(), None).await;
    let harness = harness(mail, AcceptAll).await;
    let token = harness
        .sign_in("me@icloud.com", "abcd-efgh-ijkl-mnop")
        .await;
    let account = harness.store.find_account("me@icloud.com").await;
    let account = account.unwrap().unwrap().id;
    let rejected_at = async || harness.store.password_rejected_at(&account).await.unwrap();
    let list = || harness.call(&token, "list_folders", json!({}));

    // A refusal that may pass is not a rejection.
    assert_eq!(list().await["isError"], true);
    assert_eq!(rejected_at().await, None);

    // The mail server rejects the password: the tool says so, the store
    // records it, and the webhook status asks for a new one.
    login.store(REJECT, SeqCst);
    let result = list().await;
    assert!(result.to_string().contains("rejected the stored password"));
    assert!(rejected_at().await.is_some());
    let status = || harness.call_ok(&token, "get_webhook_status", json!({}));
    let rejected = status().await;
    assert_eq!(rejected["state"], "needs_password", "{rejected}");
    assert_eq!(
        rejected["message"],
        "The mail server rejected the stored password. Enter a new app password on the account page (/account)."
    );

    // A login the server accepts clears it. Webhooks are off in this harness.
    login.store(ACCEPT, SeqCst);
    assert_ne!(list().await["isError"], true);
    assert_eq!(rejected_at().await, None);
    let accepted = status().await;
    assert_eq!(accepted["state"], "unavailable", "{accepted}");
    assert_eq!(accepted["message"], Value::Null);
}

/// Polls until `done` says so, for ten seconds at most.
async fn until(mut done: impl AsyncFnMut() -> bool) {
    for _ in 0..1000 {
        if done().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("it did not happen");
}

#[tokio::test]
async fn a_tool_login_that_clears_the_record_starts_a_stopped_watcher_again() {
    let (login, accepted) = (
        Arc::new(AtomicU8::new(REJECT)),
        Arc::<AtomicUsize>::default(),
    );
    let mail = scripted_mail(Arc::clone(&login), Arc::clone(&accepted), None).await;
    let harness = webhook_harness_for(mail, |watch, pool| {
        // Three rejections within milliseconds; a session that fails waits an hour.
        watch.auth_backoff = Duration::from_millis(10);
        (watch.min_backoff, watch.max_backoff) = (Duration::from_hours(1), Duration::from_hours(1));
        // Every tool call logs in.
        pool.idle_timeout = Duration::ZERO;
    })
    .await;
    let token = harness
        .sign_in("me@icloud.com", "abcd-efgh-ijkl-mnop")
        .await;
    harness.until_watchers_stop().await;
    let account = harness.store.find_account("me@icloud.com").await;
    let account = account.unwrap().unwrap().id;
    let hook = settings("https://hooks.example.com/mail", USER_SECRET, USER_AUTH);
    harness.store.save_webhook(&account, &hook).await.unwrap();
    let watchers = harness.watchers.as_ref().unwrap();
    watchers.refresh(&account);
    let rejected_at = async || harness.store.password_rejected_at(&account).await.unwrap();

    // Three rejections stop the watcher and leave the record.
    until(async || watchers.running() == 0 && rejected_at().await.is_some()).await;

    // A tool's login that works clears the record, and the watcher logs in again.
    login.store(ACCEPT, SeqCst);
    harness.call_ok(&token, "list_folders", json!({})).await;
    until(async || accepted.load(SeqCst) == 2).await;
    assert_eq!((watchers.running(), rejected_at().await), (1, None));

    // With no record to clear, a tool's login leaves the watcher alone.
    harness.call_ok(&token, "list_folders", json!({})).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(accepted.load(SeqCst), 3);
}

#[tokio::test]
async fn mcp_endpoint_requires_a_token() {
    let harness = harness(unreachable_mail(), AcceptAll).await;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": initialize() });
    let reply = harness.rpc_raw(None, HOST, &body).await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert!(
        reply.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("https://mail.example.com/.well-known/oauth-protected-resource/mcp")
    );

    let health = harness
        .send(Request::get("/healthz").body(Body::empty()).unwrap())
        .await;
    assert_eq!(
        (health.status, health.body.as_str()),
        (StatusCode::OK, "ok")
    );
    let landing = harness
        .send(Request::get("/").body(Body::empty()).unwrap())
        .await;
    assert!(landing.body.contains("https://mail.example.com/mcp"));
}

#[tokio::test]
async fn mcp_endpoint_lists_tools_and_reports_mail_errors() {
    let harness = harness(unreachable_mail(), AcceptAll).await;
    let token = harness
        .sign_in("me@icloud.com", "abcd-efgh-ijkl-mnop")
        .await;

    let info = harness.rpc(&token, "initialize", initialize()).await;
    assert_eq!(
        info["serverInfo"],
        json!({
            "name": "postkeep",
            "title": "postkeep",
            "version": env!("CARGO_PKG_VERSION"),
            "websiteUrl": "https://postkeep.dev",
            "icons": [{
                "src": "https://postkeep.dev/apple-touch-icon.png",
                "mimeType": "image/png",
                "sizes": ["180x180"]
            }]
        })
    );
    assert!(info["capabilities"]["tools"].is_object());
    assert!(
        info["instructions"]
            .as_str()
            .unwrap()
            .contains("search_messages")
    );
    assert!(
        info["instructions"]
            .as_str()
            .unwrap()
            .contains("set_webhook_outbox_limits")
    );

    let tools = harness.rpc(&token, "tools/list", json!({})).await;
    let mut names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "add_webhook_filter",
            "create_draft",
            "create_folder",
            "delete_message",
            "download_attachment",
            "get_message",
            "get_webhook_status",
            "list_folders",
            "list_webhook_filters",
            "move_message",
            "remove_webhook_filter",
            "reply_to_message",
            "search_messages",
            "send_message",
            "set_webhook_enabled",
            "set_webhook_outbox_limits",
            "update_flags",
        ]
    );
    let listed = tools["tools"].as_array().unwrap();
    let find = |name: &str| listed.iter().find(|tool| tool["name"] == name).unwrap();
    let status_tool = find("get_webhook_status");
    assert_eq!(status_tool["annotations"]["readOnlyHint"], true);
    assert_ne!(status_tool["annotations"]["openWorldHint"], true);
    let toggle = find("set_webhook_enabled");
    assert_ne!(toggle["annotations"]["readOnlyHint"], true);
    assert_eq!(toggle["annotations"]["destructiveHint"], true);
    assert_eq!(toggle["annotations"]["idempotentHint"], true);
    assert_eq!(toggle["annotations"]["openWorldHint"], true);
    let toggle_description = toggle["description"].as_str().unwrap();
    assert!(
        toggle_description.contains("skips events queued while it was off"),
        "{toggle_description}"
    );
    let limits_tool = find("set_webhook_outbox_limits");
    assert_eq!(limits_tool["annotations"]["destructiveHint"], true);
    assert_eq!(limits_tool["annotations"]["idempotentHint"], true);
    assert_ne!(limits_tool["annotations"]["readOnlyHint"], true);
    assert_ne!(limits_tool["annotations"]["openWorldHint"], true);
    let hints = |name: &str| {
        let annotations = &find(name)["annotations"];
        [
            "readOnlyHint",
            "destructiveHint",
            "idempotentHint",
            "openWorldHint",
        ]
        .map(|hint| annotations[hint].as_bool())
    };
    assert_eq!(
        hints("list_webhook_filters"),
        [Some(true), Some(false), None, Some(false)]
    );
    let (yes, no) = (Some(true), Some(false));
    assert_eq!(hints("add_webhook_filter"), [no, no, no, no]);
    assert_eq!(hints("remove_webhook_filter"), [no, yes, yes, no]);
    assert_eq!(hints("download_attachment"), [yes, no, None, no]);
    let limits_description = limits_tool["description"].as_str().unwrap();
    assert!(
        limits_description.contains("oldest") && limits_description.contains("not delivered"),
        "{limits_description}"
    );
    for tool in tools["tools"].as_array().unwrap() {
        assert!(tool["inputSchema"].is_object(), "{tool}");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{tool}");
        // A declared output schema would oblige structuredContent, which
        // download_attachment leaves out so that clients keep the image.
        if tool["name"] == "download_attachment" {
            assert!(tool.get("outputSchema").is_none(), "{tool}");
        } else {
            assert!(tool["outputSchema"].is_object(), "{tool}");
        }
        assert_ne!(tool["description"].as_str().unwrap(), "");
    }
    let delete = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "delete_message")
        .unwrap();
    assert_eq!(delete["annotations"]["destructiveHint"], true);

    // Mail errors come back as tool errors the model can read.
    let result = harness.call(&token, "list_folders", json!({})).await;
    assert_eq!(result["isError"], true, "{result}");
    // Invalid arguments are rejected before connecting.
    let result = harness
        .call(&token, "search_messages", json!({ "since": "yesterday" }))
        .await;
    assert_eq!(result["isError"], true);
    assert!(
        result.to_string().contains("since must be a date"),
        "{result}"
    );
    let result = harness
        .call(
            &token,
            "send_message",
            json!({ "to": ["not an address"], "subject": "s", "body": "b" }),
        )
        .await;
    assert_eq!(result["isError"], true);
    // create_draft's refusals; a blank id is a new draft, which needs a recipient.
    for (arguments, error) in [
        (
            json!({ "id": "imap.1", "cc": ["a@example.com"], "body": "b" }),
            "cc, bcc and subject",
        ),
        (
            json!({ "subject": "s", "body": "b" }),
            "at least one recipient",
        ),
        (
            json!({ "reply_all": true, "to": ["a@example.com"], "body": "b" }),
            "reply_all can only be set when drafting a reply",
        ),
        (
            json!({ "id": "", "subject": "s", "body": "b" }),
            "at least one recipient",
        ),
    ] {
        let result = harness.call(&token, "create_draft", arguments).await;
        assert_eq!(result["isError"], true, "{result}");
        assert!(result.to_string().contains(error), "{result}");
    }
}

/// Every tool refuses an argument it does not take, before it runs, with a
/// tool error that names it, such as `importance` on `send_message`.
#[tokio::test]
async fn tools_refuse_arguments_they_do_not_take() {
    let harness = harness(unreachable_mail(), AcceptAll).await;
    let token = harness
        .sign_in("me@icloud.com", "abcd-efgh-ijkl-mnop")
        .await;
    // Arguments each tool takes, for all seventeen.
    let calls = json!({
        "list_folders": {},
        "search_messages": { "text": "budget" },
        "get_message": { "id": "imap.1" },
        "download_attachment": { "id": "imap.1", "attachment_id": "1" },
        "send_message": { "to": ["someone@example.com"], "subject": "s", "body": "b" },
        "reply_to_message": { "id": "imap.1", "body": "b" },
        "create_draft": { "to": ["someone@example.com"], "subject": "s", "body": "b" },
        "update_flags": { "id": "imap.1", "read": true },
        "move_message": { "id": "imap.1", "destination": "Archive" },
        "delete_message": { "id": "imap.1" },
        "create_folder": { "name": "Receipts" },
        "get_webhook_status": {},
        "set_webhook_enabled": { "enabled": true },
        "set_webhook_outbox_limits": { "reset": true },
        "list_webhook_filters": { "limit": 5 },
        "add_webhook_filter": { "action": "block", "field": "from", "kind": "equals", "pattern": "x" },
        "remove_webhook_filter": { "all": true },
    });
    let calls = calls.as_object().unwrap();
    assert_eq!(calls.len(), 17);
    for (tool, arguments) in calls {
        let mut arguments = arguments.clone();
        arguments["importance"] = json!("high");
        let result = harness.call(&token, tool, arguments).await;
        assert_eq!(result["isError"], true, "{tool}: {result}");
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("unknown field `importance`"),
            "{tool}: {text}"
        );
    }
}

#[tokio::test]
async fn mcp_endpoint_rejects_oversized_bodies() {
    let harness = harness(unreachable_mail(), AcceptAll).await;
    let token = harness
        .sign_in("me@icloud.com", "abcd-efgh-ijkl-mnop")
        .await;
    let huge = "x".repeat(100 * 1024);
    let body = json!({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": { "name": "send_message", "arguments": { "to": ["a@example.com"], "subject": "s", "body": huge } }
    });
    let body = body.to_string();
    let request = Request::post("/mcp")
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len())
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", PROTOCOL)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body))
        .unwrap();
    let reply = harness.send(request).await;
    assert_eq!(
        reply.status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "{}",
        reply.body
    );
}

#[tokio::test]
async fn mcp_endpoint_rejects_unknown_hosts() {
    let harness = harness(unreachable_mail(), AcceptAll).await;
    let token = harness.sign_in("me@icloud.com", "abcdefghijklmnop").await;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": initialize() });
    let reply = harness.rpc_raw(Some(&token), "evil.example", &body).await;
    assert!(
        reply.status.is_client_error(),
        "{}: {}",
        reply.status,
        reply.body
    );
}

#[tokio::test]
async fn mcp_endpoint_checks_the_origin_before_the_token() {
    let harness = harness(unreachable_mail(), AcceptAll).await;
    let token = harness
        .sign_in("user@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": initialize() });

    let reply = harness.rpc_from(Some(&token), HOST, None, &body).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    for origin in [
        "https://mail.example.com",
        "https://Mail.Example.com:443",
        BROWSER_CLIENT,
    ] {
        let reply = harness
            .rpc_from(Some(&token), HOST, Some(origin), &body)
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{origin}: {}", reply.body);
    }

    for origin in [
        "https://evil.example",
        "http://mail.example.com",
        "https://mail.example.com:8443",
        "http://localhost:6275",
        "https://mail.example.com/mcp",
        "null",
        "not an origin",
    ] {
        for token in [Some(token.as_str()), None] {
            let reply = harness.rpc_from(token, HOST, Some(origin), &body).await;
            assert_eq!(
                (reply.status, reply.body.as_str()),
                (
                    StatusCode::FORBIDDEN,
                    "Forbidden: Origin header is not allowed"
                ),
                "{origin}, token: {}",
                token.is_some()
            );
        }
    }
}

fn greenmail_config() -> MailConfig {
    let host = std::env::var("GREENMAIL_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = |name: &str, default: u16| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let mut mail = MailConfig::default();
    mail.imap.host.clone_from(&host);
    mail.imap.port = port("GREENMAIL_IMAP_PORT", 3143);
    mail.imap.security = ImapSecurity::Plaintext;
    mail.smtp.host = host;
    mail.smtp.port = port("GREENMAIL_SMTP_PORT", 3025);
    mail.smtp.security = SmtpSecurity::Plaintext;
    mail.timeout = Duration::from_secs(10);
    mail
}

/// A mailbox of its own, which the first mail (from alice, with the subject
/// `first`) makes: GreenMail creates the user, with its address as password.
/// No other test works in it, which matters because GreenMail 2.1.14 cannot
/// serve two sessions that work in one mailbox at once: while one session
/// changes flags or expunges, the others get `NO ... No such message with
/// uid` or lose their connection.
async fn new_mailbox(first: &str) -> String {
    let harness = harness(greenmail_config(), MailVerifier).await;
    let alice = harness.sign_in("alice@example.com", "alicepass").await;
    let user = format!("u{}@example.com", uuid::Uuid::new_v4().simple());
    let args = json!({ "to": [user], "subject": first, "body": "Hi", "save_to_sent": false });
    harness.call_ok(&alice, "send_message", args).await;
    user
}

#[tokio::test]
async fn imap_deadline_is_checked_after_pooled_session_validation() {
    use postkeep::mailbox::{IdsFrom, Mode, Selector, Status};
    use postkeep::pool::{Fingerprint, ImapPool, PoolConfig};
    use postkeep_mail::{Credentials, MailClient};
    let login = Arc::new(AtomicU8::new(ACCEPT));
    let accepted = Arc::new(AtomicUsize::new(0));
    let config = scripted_mail(
        login.clone(),
        accepted.clone(),
        Some(Arc::new(AtomicU32::new(1002))),
    )
    .await;
    let client = MailClient::new(
        config,
        Credentials::new(
            "deadline@example.com",
            &SecretString::from("password".to_owned()),
        )
        .unwrap(),
    )
    .unwrap();
    let pool = ImapPool::new(PoolConfig::default());
    let mailbox = Mailbox::imap(
        AccountId("deadline-test".to_owned()),
        client,
        Fingerprint::new("custom", "deadline@example.com", "password"),
        pool.clone(),
    );
    mailbox.list_folders().await.unwrap();
    assert_eq!(accepted.load(SeqCst), 1);
    login.store(imap::SLOW_NOOP, SeqCst);
    let mark_read = Change::Flags {
        read: Some(true),
        flagged: None,
    };
    let outcomes = mailbox
        .apply(
            &[Selector {
                id: None,
                folder: Some("INBOX".to_owned()),
                uid: Some(1),
            }],
            IdsFrom::Caller,
            &mark_read,
            Mode::Act,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert_eq!(outcomes[0].status, Status::NotReached);
    assert_eq!(
        accepted.load(SeqCst),
        1,
        "no reconnect or mutation after the slow NOOP"
    );
    assert_eq!(pool.idle_count(), 1, "the usable session is still returned");
    // The same real listing path must refuse a move out of a retained All folder.
    login.store(imap::ALL_FOLDER, SeqCst);
    let most = postkeep::tools::MOST_IDS;
    let mut selection = SearchSelection {
        folder: "All".to_owned(),
        criteria: Criteria {
            until: Some(Cutoff::Imap {
                uid: u32::try_from(most + 1).unwrap(),
                uid_validity: 1,
            }),
            ..Criteria::default()
        },
    };
    let refused = mailbox
        .selected(
            &selection,
            &Change::Move("Archive".to_owned()),
            most,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(
        refused.to_string(),
        format!(
            "this move keeps the messages in All too, so a selection moves at most {most} of them; narrow the search"
        )
    );
    login.store(imap::SLOW_FETCH, SeqCst);
    selection.criteria.subject = Some("message".to_owned());
    let outcome = mailbox
        .selected(
            &selection,
            &mark_read,
            2,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
    assert!(
        matches!(&outcome, Selected::Done(reason) if reason == "searching took all the time: narrow the search"),
        "{outcome:?}"
    );
    assert_eq!(
        accepted.load(SeqCst),
        1,
        "no reconnect after the slow fetch"
    );
    assert_eq!(
        pool.idle_count(),
        1,
        "the completed fetch leaves the session usable"
    );
}

async fn widening_imap(mode: u8) -> (Mailbox, Arc<AtomicUsize>) {
    use postkeep::pool::{Fingerprint, ImapPool, PoolConfig};
    use postkeep_mail::{Credentials, MailClient};
    let logins = Arc::default();
    let config = scripted_mail(
        Arc::new(AtomicU8::new(mode)),
        Arc::clone(&logins),
        Some(Arc::new(AtomicU32::new(1002))),
    )
    .await;
    let password = SecretString::from("password".to_owned());
    let credentials = Credentials::new("otters@example.net", &password).unwrap();
    let client = MailClient::new(config, credentials).unwrap();
    let mailbox = Mailbox::imap(
        AccountId("imap-header-test".to_owned()),
        client,
        Fingerprint::new("custom", "otters@example.net", "password"),
        ImapPool::new(PoolConfig::default()),
    );
    (mailbox, logins)
}

async fn selected_uids(mailbox: &Mailbox, criteria: Criteria) -> Vec<u32> {
    let selected = mailbox
        .selected(
            &SearchSelection {
                folder: "All".to_owned(),
                criteria,
            },
            &Change::Move("Archive".to_owned()),
            postkeep::tools::MOST_IDS,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap();
    let Selected::Matches { ids, more: false } = selected else {
        panic!("{selected:?}");
    };
    ids.iter()
        .map(|id| parse_imap_id(id.id.as_deref().unwrap()).unwrap().1)
        .collect()
}

#[tokio::test]
async fn imap_checks_widened_pages_selections_and_cutoffs() {
    let (mailbox, _) = widening_imap(imap::ALL_FOLDER).await;
    let mut criteria = Criteria {
        subject: Some("Message 100".to_owned()),
        ..Criteria::default()
    };
    for (limit, expected, estimated) in [
        (3, &[1001, 1000, 100][..], false),
        (2, &[1001, 1000][..], true),
    ] {
        let page = mailbox
            .search("All", &criteria, Paging::new(0, limit))
            .await
            .unwrap();
        let uids: Vec<_> = page.messages.iter().map(|m| m.uid.unwrap()).collect();
        assert_eq!(
            (uids.as_slice(), page.estimated, page.has_more),
            (expected, estimated, estimated)
        );
        if !estimated {
            assert_eq!(page.total, 3);
        }
    }
    for (uid, expected) in [(1001, vec![1001, 1000, 100]), (1000, vec![1000, 100])] {
        criteria.until = Some(Cutoff::Imap {
            uid,
            uid_validity: 1,
        });
        assert_eq!(selected_uids(&mailbox, criteria.clone()).await, expected);
    }
}

#[tokio::test]
async fn imap_gmail_checks_headers_and_refuses_text_before_searching() {
    let (mailbox, logins) = widening_imap(imap::GMAIL).await;
    let selection = SearchSelection {
        folder: "All".to_owned(),
        criteria: Criteria {
            text: Some("otter".to_owned()),
            until: Some(Cutoff::Imap {
                uid: 1001,
                uid_validity: 1,
            }),
            ..Criteria::default()
        },
    };
    let refused = mailbox
        .selected(
            &selection,
            &Change::Flags {
                read: Some(true),
                flagged: None,
            },
            3,
            Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap_err();
    assert_eq!(
        logins.load(SeqCst),
        0,
        "text is refused before acquiring a session"
    );
    assert_eq!(
        refused.to_string(),
        "IMAP can't match the text filter exactly as given, so a selection can't use it; narrow with other filters instead"
    );
    for (to, expected) in [
        ("to1001@example.net", vec![1001]),
        ("cc1001@example.net", vec![]),
    ] {
        let mut criteria = Criteria {
            to: Some(to.to_owned()),
            ..Criteria::default()
        };
        let page = mailbox
            .search("All", &criteria, Paging::default())
            .await
            .unwrap();
        let uids: Vec<_> = page.messages.iter().map(|m| m.uid.unwrap()).collect();
        assert_eq!(uids, expected, "{to}");
        criteria.until = page.cutoff;
        assert_eq!(selected_uids(&mailbox, criteria).await, expected);
    }
    let reversed = Criteria {
        subject: Some("1001 message".to_owned()),
        ..Criteria::default()
    };
    let page = mailbox
        .search("All", &reversed, Paging::default())
        .await
        .unwrap();
    assert_eq!(page.messages, []);
}

#[tokio::test]
async fn imap_moves_check_the_source_and_gmail_user_labels() {
    for (mode, destination, previews) in [
        (
            imap::GMAIL,
            "Receipts",
            &[
                (
                    true,
                    "dry run, nothing changed: would move 1 message to Receipts (1 already there)",
                ),
                (false, "2 messages: 1 moved to Receipts, 1 already there"),
                (false, "2 messages: 2 already there"),
            ][..],
        ),
        (
            imap::GMAIL,
            "INBOX",
            &[
                (
                    true,
                    concat!(
                        "dry run, nothing changed: would move 2 messages to INBOX (2 of them: ",
                        "the source folder doesn't show what the destination already held)"
                    ),
                ),
                (
                    false,
                    "2 messages: 2 moved to INBOX; the source folder doesn't show what the destination already held",
                ),
            ][..],
        ),
        (
            imap::ALL_FOLDER,
            "Receipts",
            &[(
                true,
                "dry run, nothing changed: would move 2 messages to Receipts (2 of them: the source folder doesn't show what the destination already held)",
            )][..],
        ),
    ] {
        let mail = scripted_mail(Arc::new(AtomicU8::new(mode)), Arc::default(), None).await;
        let harness = harness(mail, AcceptAll).await;
        let token = harness.sign_in("otters@example.net", "password").await;
        if mode == imap::ALL_FOLDER {
            let id = imap_id("INBOX", u32::MAX, Some(1));
            for destination in ["INBOX", "inbox"] {
                let result = harness
                    .call_ok(
                        &token,
                        "move_message",
                        json!({ "ids": [id], "destination": destination }),
                    )
                    .await;
                assert!(
                    result["result"]
                        .as_str()
                        .unwrap()
                        .starts_with("1 message: 1 not found"),
                    "{destination}: {result}"
                );
            }
        }
        let ids = [1, 2].map(|uid| postkeep::mailbox::id::imap_id("All", uid, Some(1)));
        for (dry, expected) in previews {
            let result = harness
                .call_ok(
                    &token,
                    "move_message",
                    json!({ "ids": ids, "destination": destination, "dry_run": dry }),
                )
                .await;
            assert_eq!(
                result["result"], *expected,
                "{mode}: {destination}, dry={dry}"
            );
        }
    }
}

/// A lost set may reconnect, but a refused reconnect stops the call after one
/// attempt, whether it is a LOGIN rejection or another setup failure. An old
/// opaque id checks the folder first, so alternating folders also covers that
/// session acquisition path.
#[tokio::test]
async fn imap_bulk_stops_after_one_failed_reconnect_but_continues_after_set_errors() {
    use postkeep::mailbox::{Change, IdsFrom, Mailbox, Mode, Selector, Status};
    use postkeep::pool::{Fingerprint, ImapPool, PoolConfig};
    use postkeep_mail::{Credentials, MailClient};

    for (opaque, alternating, after_drop) in [
        (false, false, imap::DROP_AND_REJECT),
        (false, true, imap::DROP_AND_REJECT),
        (true, true, imap::DROP_AND_REJECT),
        (false, false, imap::DROP_AND_BUSY),
        (false, false, imap::DROP_AND_ACCEPT),
    ] {
        let login = Arc::new(AtomicU8::new(ACCEPT));
        let accepted = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        let config =
            imap::scripted_mail_counted(login.clone(), accepted.clone(), None, attempts.clone())
                .await;
        let client = MailClient::new(
            config,
            Credentials::new(
                "bulk@example.com",
                &SecretString::from("password".to_owned()),
            )
            .unwrap(),
        )
        .unwrap();
        let mailbox = Mailbox::imap(
            AccountId("bulk-test".to_owned()),
            client,
            Fingerprint::new("custom", "bulk@example.com", "password"),
            ImapPool::new(PoolConfig::default()),
        );
        mailbox.list_folders().await.unwrap();
        assert_eq!(attempts.load(SeqCst), 1);
        login.store(after_drop, SeqCst);
        let ids: Vec<_> = (1..=1000)
            .map(|uid| {
                let folder = if alternating && uid % 2 == 0 {
                    "other"
                } else {
                    "INBOX"
                };
                if opaque {
                    Selector {
                        id: Some(imap_id(folder, uid, None)),
                        ..Selector::default()
                    }
                } else {
                    Selector {
                        folder: Some(folder.to_owned()),
                        uid: Some(uid),
                        ..Selector::default()
                    }
                }
            })
            .collect();
        let outcomes = mailbox
            .apply(
                &ids,
                IdsFrom::Caller,
                &Change::Flags {
                    read: Some(true),
                    flagged: None,
                },
                Mode::Act,
                std::time::Instant::now() + Duration::from_secs(20),
            )
            .await
            .unwrap();
        assert_eq!(outcomes.len(), 1000);
        assert_eq!(attempts.load(SeqCst), 2, "one reconnect after the lost set");
        let set_size = if alternating {
            1
        } else {
            postkeep_mail::UID_SET_MAX
        };
        let reconnected = after_drop == imap::DROP_AND_ACCEPT;
        assert_eq!(accepted.load(SeqCst), if reconnected { 2 } else { 1 });
        let failed = if reconnected { set_size } else { 2 * set_size };
        assert!(
            outcomes[..failed]
                .iter()
                .all(|out| out.status == Status::Failed)
        );
        let remaining = if reconnected {
            Status::NotFound
        } else {
            Status::NotReached
        };
        assert!(outcomes[failed..].iter().all(|out| out.status == remaining));
        if !reconnected {
            assert_ne!(outcomes[set_size].reason, "");
            assert!(
                outcomes[set_size..]
                    .iter()
                    .all(|out| out.reason == outcomes[set_size].reason)
            );
        }
    }
}

#[tokio::test]
async fn imap_refuses_to_forward_more_bytes_than_it_reserved() {
    let login = Arc::new(AtomicU8::new(imap::UNDER_REPORTED_SIZE));
    let mail = scripted_mail(login, Arc::default(), None).await;
    let harness = harness(mail, AcceptAll).await;
    let token = harness
        .sign_in("me@icloud.com", "abcd-efgh-ijkl-mnop")
        .await;
    let result = harness.call(&token, "send_message", json!({
        "forward": imap_id("INBOX", 1, None), "to": ["someone@example.org"], "subject": "Forward", "body": "Note"
    })).await;
    assert_eq!(result["isError"], true, "{result}");
    let error = result["content"][0]["text"].as_str().unwrap();
    assert!(
        error.contains("larger than the provider reported"),
        "{error}"
    );
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn greenmail_end_to_end() {
    let mail = greenmail_config();
    let harness = harness(mail, MailVerifier).await;
    let user = new_mailbox("welcome").await;
    let token = harness.sign_in(&user, &user).await;

    let folders = harness.call_ok(&token, "list_folders", json!({})).await;
    assert!(
        folders["folders"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["name"] == "INBOX" && f["role"] == "inbox")
    );

    let subject = format!("e2e {}", std::process::id());
    let sent = harness
        .call_ok(
            &token,
            "send_message",
            json!({ "to": [format!("Bob <{user}>")], "subject": subject, "body": "Hello from the MCP test", "attachments": [{"filename": "forward.txt", "text": "attachment text"}] }),
        )
        .await;
    assert!(sent["message_id"].as_str().unwrap().contains('@'));

    // Delivery is asynchronous; poll briefly.
    let mut found = Value::Null;
    for _ in 0..20 {
        found = harness
            .call_ok(
                &token,
                "search_messages",
                json!({ "subject": subject, "unread_only": true }),
            )
            .await;
        if found["total"] == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(found["total"], 1, "{found}");
    assert!(
        found.get("selection").is_none(),
        "the one-match page is complete"
    );
    let uid = found["messages"][0]["uid"].as_u64().unwrap();
    let id = found["messages"][0]["id"].as_str().unwrap().to_owned();

    let message = harness
        .call_ok(&token, "get_message", json!({ "id": id }))
        .await;
    assert_eq!(message["id"], id.as_str());
    assert_eq!(message["uid"], uid);
    assert_eq!(message["folder"], "INBOX");
    assert!(
        message["body"]
            .as_str()
            .unwrap()
            .contains("Hello from the MCP test")
    );
    assert_eq!(message["unread"], true, "reading must not mark as read");
    // Use a distinct subject so searches for the original still match one message.
    let forwarded_subject = format!("Forwarded copy {}", std::process::id());
    harness
        .call_ok(
            &token,
            "send_message",
            json!({
                "forward": id, "to": [user], "subject": forwarded_subject, "body": "Forwarding note"
            }),
        )
        .await;
    let matches = wait_for_messages(&harness, &token, "INBOX", &forwarded_subject, 1).await;
    let forwarded_id = &matches["messages"][0]["id"];
    let forward = harness
        .call_ok(&token, "get_message", json!({"id": forwarded_id}))
        .await;
    let body = forward["body"].as_str().unwrap();
    assert!(body.contains("Forwarding note"));
    assert!(body.contains("Forwarded message"));
    assert!(body.contains("Hello from the MCP test"));
    assert_eq!(forward["attachments"][0]["filename"], "forward.txt");
    // The bulk path shares validation, previews, set commands and COPYUID results.
    for name in ["Bulk Archive", "Deleted Messages"] {
        harness
            .call_ok(&token, "create_folder", json!({ "name": name }))
            .await;
    }
    let bulk_subject = format!("{subject} bulk");
    for _ in 0..3 {
        harness
            .call_ok(
                &token,
                "send_message",
                json!({ "to": [user], "subject": bulk_subject, "body": "Bulk action fixture" }),
            )
            .await;
    }
    let found = wait_for_messages(&harness, &token, "INBOX", &bulk_subject, 3).await;
    let ids: Vec<_> = found["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|message| message["id"].as_str().unwrap().to_owned())
        .collect();
    let (_, first_uid, validity) = parse_imap_id(&ids[0]).unwrap();
    let stale = imap_id(
        "INBOX",
        first_uid,
        Some(validity.unwrap().checked_add(1).unwrap_or(1)),
    );
    let old = imap_id("INBOX", first_uid, None);
    let missing_id = imap_id("INBOX", 999_999, validity);
    for (tool, mut args) in [
        ("update_flags", json!({ "read": true })),
        ("move_message", json!({ "destination": "Bulk Archive" })),
        ("delete_message", json!({})),
    ] {
        args["ids"] = json!([ids[0], ids[1], ids[2], stale, old, "bad-id", missing_id]);
        args["dry_run"] = json!(true);
        args["list_all"] = json!(true);
        let preview = harness.call_ok(&token, tool, args).await;
        assert!(
            preview["result"].as_str().unwrap().contains("3 messages"),
            "{preview}"
        );
        let groups = preview["messages"].as_array().unwrap();
        let failed: Vec<_> = groups
            .iter()
            .filter(|group| group["status"] == "failed")
            .collect();
        let mut failed_ids: Vec<_> = failed
            .iter()
            .flat_map(|group| group["ids"].as_array().unwrap())
            .map(|id| id.as_str().unwrap())
            .collect();
        failed_ids.sort_unstable();
        let mut expected = vec![stale.as_str(), old.as_str(), "bad-id"];
        expected.sort_unstable();
        assert_eq!(failed_ids, expected);
        let reasons: std::collections::HashSet<_> = failed
            .iter()
            .map(|group| group["reason"].as_str().unwrap())
            .collect();
        assert_eq!(reasons.len(), 3, "each refusal has its own reason");
        for (id, words) in [
            (stale.as_str(), "out of date"),
            (old.as_str(), "call search_messages again"),
            ("bad-id", "not a message id"),
        ] {
            let group = failed
                .iter()
                .find(|group| {
                    group["ids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|value| value == id)
                })
                .unwrap();
            assert!(group["reason"].as_str().unwrap().contains(words), "{group}");
        }
        assert_eq!(
            groups
                .iter()
                .find(|group| group["status"] == "not_found")
                .unwrap()["ids"],
            json!([missing_id])
        );
    }
    let unchanged = wait_for_messages(&harness, &token, "INBOX", &bulk_subject, 3).await;
    assert!(
        unchanged["messages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|message| message["unread"] == true)
    );
    harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "id": ids[0], "read": true }),
        )
        .await;
    let flags = harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "ids": [ids[1], ids[0]], "read": true }),
        )
        .await;
    assert_eq!(
        flags["result"],
        "2 messages: 1 marked as read, 1 already marked as asked"
    );
    for destination in ["INBOX", "inbox"] {
        let own = harness
            .call_ok(
                &token,
                "move_message",
                json!({ "id": ids[0], "destination": destination }),
            )
            .await;
        assert_eq!(
            own["result"],
            format!("message {} is already in {destination}", ids[0])
        );
    }
    let flagged = harness
        .call_ok(
            &token,
            "update_flags",
            json!({
                "ids": [ids[0], ids[1], ids[2], stale, old, "bad-id", missing_id],
                "read": true, "flagged": true, "list_all": true,
            }),
        )
        .await;
    assert!(
        flagged["result"]
            .as_str()
            .unwrap()
            .contains("3 marked as read and flagged"),
        "{flagged}"
    );
    let flags = wait_for_messages(&harness, &token, "INBOX", &bulk_subject, 3).await;
    assert!(
        flags["messages"]
            .as_array()
            .unwrap()
            .iter()
            .all(|message| message["unread"] == false && message["flagged"] == true)
    );
    let mut move_ids = ids.clone();
    move_ids.push(stale);
    let moved = harness
        .call_ok(
            &token,
            "move_message",
            json!({ "ids": move_ids, "destination": "Bulk Archive", "list_all": true }),
        )
        .await;
    assert_eq!(moved["new_ids"].as_object().unwrap().len(), 3, "{moved}");
    let new_ids: Vec<_> = ids
        .iter()
        .map(|id| moved["new_ids"][id].as_str().unwrap().to_owned())
        .collect();
    let rerun = harness
        .call_ok(
            &token,
            "move_message",
            json!({ "ids": ids, "destination": "Bulk Archive" }),
        )
        .await;
    assert!(
        rerun["result"].as_str().unwrap().contains("3 not found"),
        "{rerun}"
    );
    assert!(rerun.get("messages").is_none());
    let already = harness
        .call_ok(
            &token,
            "move_message",
            json!({ "ids": new_ids, "destination": "Bulk Archive" }),
        )
        .await;
    assert_eq!(already["result"], "3 messages: 3 already there");
    let back = harness
        .call_ok(
            &token,
            "move_message",
            json!({ "ids": [new_ids[0]], "destination": "inbox", "list_all": true }),
        )
        .await;
    let back_id = back["new_ids"][new_ids[0].as_str()].as_str().unwrap();
    assert_eq!(parse_imap_id(back_id).unwrap().0, "INBOX");
    let restored = harness
        .call_ok(
            &token,
            "move_message",
            json!({ "ids": [back_id], "destination": "Bulk Archive", "list_all": true }),
        )
        .await;
    let mut new_ids = new_ids;
    new_ids[0] = restored["new_ids"][back_id].as_str().unwrap().to_owned();
    let trashed = harness
        .call_ok(
            &token,
            "delete_message",
            json!({ "ids": new_ids, "list_all": true }),
        )
        .await;
    assert_eq!(trashed["result"], "3 messages: 3 moved to the trash");
    let trash_ids: Vec<_> = trashed["new_ids"]
        .as_object()
        .unwrap()
        .values()
        .map(|id| id.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(trash_ids.len(), 3);
    let already = harness
        .call_ok(&token, "delete_message", json!({ "ids": trash_ids }))
        .await;
    assert!(
        already["result"]
            .as_str()
            .unwrap()
            .contains("already in Trash; use permanent deletion"),
        "{already}"
    );

    // A search selection never takes a message appended after its UID cutoff.
    let selection_subject = format!("{subject} selection");
    for _ in 0..3 {
        harness
            .call_ok(
                &token,
                "send_message",
                json!({ "to": [user], "subject": selection_subject, "body": "Selection fixture" }),
            )
            .await;
    }
    let originals = wait_for_messages(&harness, &token, "INBOX", &selection_subject, 3).await;
    let selected_page = harness
        .call_ok(
            &token,
            "search_messages",
            json!({ "subject": selection_subject, "limit": 1 }),
        )
        .await;
    let selection = selected_page["selection"].as_str().unwrap();
    harness
        .call_ok(
            &token,
            "send_message",
            json!({ "to": [user], "subject": selection_subject, "body": "Later fixture" }),
        )
        .await;
    wait_for_messages(&harness, &token, "INBOX", &selection_subject, 4).await;
    harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "id": originals["messages"][0]["id"], "read": true }),
        )
        .await;
    let preview = harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "selection": selection, "read": true, "dry_run": true, "list_all": true }),
        )
        .await;
    assert_eq!(
        preview["result"],
        "dry run, nothing changed: would mark 2 messages as read"
    );
    assert_eq!(preview["messages"][0]["ids"].as_array().unwrap().len(), 2);
    let read = harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "selection": selection, "read": true }),
        )
        .await;
    assert_eq!(
        read["result"],
        format!("2 messages: 2 marked as read; {NOTHING_LEFT}")
    );
    let repeated = harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "selection": selection, "read": true }),
        )
        .await;
    assert_eq!(repeated["result"], NOTHING_LEFT);
    for (tool, arguments, expected) in [
        (
            "update_flags",
            json!({ "selection": "garbled", "read": true }),
            REFUSAL,
        ),
        (
            "update_flags",
            json!({ "selection": selection, "read": true, "flagged": true }),
            "with a selection, change read or flagged, one per call",
        ),
        (
            "move_message",
            json!({ "id": originals["messages"][0]["id"], "selection": selection, "destination": "Bulk Archive" }),
            "give one of id, ids or selection",
        ),
        (
            "delete_message",
            json!({ "selection": selection, "permanent": true }),
            "a permanent delete takes one id a call, after the person has confirmed it",
        ),
    ] {
        let refused = harness.call(&token, tool, arguments).await;
        assert_eq!(refused["isError"], true);
        assert_eq!(refused["content"][0]["text"], expected);
    }
    let moved = harness
        .call_ok(
            &token,
            "move_message",
            json!({ "selection": selection, "destination": "Bulk Archive", "list_all": true }),
        )
        .await;
    assert_eq!(
        moved["result"],
        format!("3 messages: 3 moved to Bulk Archive; {NOTHING_LEFT}")
    );
    assert_eq!(moved["messages"][0]["ids"].as_array().unwrap().len(), 3);
    let repeated = harness
        .call_ok(
            &token,
            "move_message",
            json!({ "selection": selection, "destination": "Bulk Archive" }),
        )
        .await;
    assert_eq!(repeated["result"], NOTHING_LEFT);
    let left = wait_for_messages(&harness, &token, "INBOX", &selection_subject, 1).await;
    assert_eq!(left["messages"][0]["unread"], true);

    let missing = harness
        .call(
            &token,
            "download_attachment",
            json!({ "id": id, "attachment_id": "2" }),
        )
        .await;
    assert_eq!(missing["isError"], true, "{missing}");
    assert!(
        missing["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no attachment 2"),
        "{missing}"
    );
    // Clients written for earlier versions still address messages by folder and UID.
    let legacy = harness
        .call_ok(
            &token,
            "get_message",
            json!({ "folder": "INBOX", "uid": uid }),
        )
        .await;
    assert_eq!(legacy["id"], id.as_str());

    harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "folder": "INBOX", "uid": uid, "read": true, "flagged": true }),
        )
        .await;
    let flagged = harness
        .call_ok(
            &token,
            "search_messages",
            json!({ "subject": subject, "flagged_only": true }),
        )
        .await;
    assert_eq!(flagged["messages"][0]["unread"], false);

    let reply = harness
        .call_ok(
            &token,
            "reply_to_message",
            json!({ "id": id, "body": "Thanks!" }),
        )
        .await;
    assert!(reply["message_id"].as_str().is_some());

    harness
        .call_ok(&token, "create_folder", json!({ "name": "Drafts" }))
        .await;
    let draft = harness
        .call_ok(
            &token,
            "create_draft",
            json!({ "id": id, "body": "A second thought." }),
        )
        .await;
    assert_eq!(draft["folder"], "Drafts", "{draft}");
    let drafts = harness
        .call_ok(
            &token,
            "search_messages",
            json!({ "folder": "Drafts", "subject": format!("Re: {subject}") }),
        )
        .await;
    assert_eq!(drafts["total"], 1, "{drafts}");

    let folder = format!("Archive {}", std::process::id());
    harness
        .call_ok(&token, "create_folder", json!({ "name": folder }))
        .await;
    harness
        .call_ok(
            &token,
            "move_message",
            json!({ "id": id, "destination": folder }),
        )
        .await;
    let moved = harness
        .call_ok(&token, "search_messages", json!({ "folder": folder }))
        .await;
    assert_eq!(moved["total"], 1);
    let moved_id = moved["messages"][0]["id"].as_str().unwrap().to_owned();
    assert_ne!(moved_id, id);
    harness
        .call_ok(
            &token,
            "delete_message",
            json!({ "id": moved_id, "permanent": true }),
        )
        .await;
    let empty = harness
        .call_ok(&token, "search_messages", json!({ "folder": folder }))
        .await;
    assert_eq!(empty["total"], 0);

    let missing = harness
        .call(
            &token,
            "get_message",
            json!({ "folder": "INBOX", "uid": 999_999 }),
        )
        .await;
    assert_eq!(missing["isError"], true);
    for args in [
        json!({ "id": "not-an-id" }),
        json!({ "uid": uid }),
        json!({}),
    ] {
        let rejected = harness.call(&token, "get_message", args).await;
        assert_eq!(rejected["isError"], true, "{rejected}");
    }
}

/// Polls until `folder` holds `count` messages with `subject` in it.
async fn wait_for_messages(
    harness: &Harness,
    token: &str,
    folder: &str,
    subject: &str,
    count: usize,
) -> Value {
    let mut found = Value::Null;
    for _ in 0..20 {
        let arguments = json!({ "folder": folder, "subject": subject });
        found = harness.call_ok(token, "search_messages", arguments).await;
        if found["total"] == count {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert_eq!(found["total"], count, "{folder}: {found}");
    found
}

/// A server that files sent mail itself gets no appended copy, whatever the
/// caller says, and `sent_copy` says it saved one. Elsewhere `save_to_sent`
/// decides: left out or `true` appends, `false` does not.
#[tokio::test]
#[ignore = "requires GreenMail"]
async fn greenmail_sent_copy_follows_the_server_and_the_caller() {
    // (server files sent mail, save_to_sent as the caller gave it, what the
    // tools report, copies appended to Sent)
    let cases = [
        (false, None, "saved to Sent Messages", 1),
        (false, Some(true), "saved to Sent Messages", 1),
        (false, Some(false), "not saved (not requested)", 0),
        (true, None, "saved by the mail server", 0),
        (true, Some(true), "saved by the mail server", 0),
        (true, Some(false), "saved by the mail server", 0),
    ];
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let user = new_mailbox(&format!("{tag} welcome")).await;
    for by_server in [false, true] {
        let mut mail = greenmail_config();
        mail.server_files_sent = by_server;
        let harness = harness(mail, MailVerifier).await;
        let token = harness.sign_in(&user, &user).await;
        // The Sent folder exists (it may already), so a copy appended by
        // mistake would be found.
        let folder = json!({ "name": "Sent Messages" });
        harness.call(&token, "create_folder", folder).await;
        for (index, &(_, save_to_sent, reported, copies)) in cases
            .iter()
            .enumerate()
            .filter(|(_, case)| case.0 == by_server)
        {
            let subject = format!("{tag} case {index}");
            let mut send_args = json!({
                "to": [user], "subject": subject, "body": "Hi",
            });
            let mut reply_args = json!({ "body": "Thanks!" });
            if let Some(save_to_sent) = save_to_sent {
                send_args["save_to_sent"] = json!(save_to_sent);
                reply_args["save_to_sent"] = json!(save_to_sent);
            }
            let sent = harness.call_ok(&token, "send_message", send_args).await;
            assert_eq!(sent["sent_copy"], reported, "send: {subject}");
            let delivered = wait_for_messages(&harness, &token, "INBOX", &subject, 1).await;
            wait_for_messages(&harness, &token, "Sent Messages", &subject, copies).await;

            reply_args["id"] = delivered["messages"][0]["id"].clone();
            let replied = harness
                .call_ok(&token, "reply_to_message", reply_args)
                .await;
            assert_eq!(replied["sent_copy"], reported, "reply: {subject}");
            let re_subject = format!("Re: {subject}");
            wait_for_messages(&harness, &token, "Sent Messages", &re_subject, copies).await;
        }
    }
}

/// Where a permanent delete would only remove a label, the tool refuses it
/// and says why, the message stays, and a delete to the trash still works.
#[tokio::test]
#[ignore = "requires GreenMail"]
async fn greenmail_permanent_delete_is_refused_where_it_only_removes_a_label() {
    let mut mail = greenmail_config();
    mail.permanent_delete = false;
    let harness = harness(mail, MailVerifier).await;
    let subject = format!("label {}", uuid::Uuid::new_v4().simple());
    let user = new_mailbox(&subject).await;
    let token = harness.sign_in(&user, &user).await;
    let trash = "Deleted Messages";
    let folder = json!({ "name": trash });
    harness.call_ok(&token, "create_folder", folder).await;
    let found = wait_for_messages(&harness, &token, "INBOX", &subject, 1).await;
    let id = found["messages"][0]["id"].clone();

    let args = json!({ "id": id, "permanent": true });
    let refused = harness.call(&token, "delete_message", args).await;
    assert_eq!(refused["isError"], true, "{refused}");
    let text = refused.to_string();
    assert!(text.contains("keep the message in All Mail"), "{text}");
    assert!(text.contains("Delete without `permanent`"), "{text}");
    wait_for_messages(&harness, &token, "INBOX", &subject, 1).await;
    // Targets without UIDVALIDITY get the same answer here: being sent to
    // search again would not help.
    let uid = u32::try_from(found["messages"][0]["uid"].as_u64().unwrap()).unwrap();
    for target in [
        json!({ "folder": "INBOX", "uid": uid, "permanent": true }),
        json!({ "id": imap_id("INBOX", uid, None), "permanent": true }),
    ] {
        let refused = harness.call(&token, "delete_message", target).await;
        assert_eq!(refused["isError"], true, "{refused}");
        let text = refused.to_string();
        assert!(text.contains("keep the message in All Mail"), "{text}");
        assert!(!text.contains("call search_messages again"), "{text}");
        wait_for_messages(&harness, &token, "INBOX", &subject, 1).await;
    }

    let args = json!({ "id": id });
    harness.call_ok(&token, "delete_message", args).await;
    wait_for_messages(&harness, &token, "INBOX", &subject, 0).await;
    wait_for_messages(&harness, &token, trash, &subject, 1).await;
}

/// After the server renumbers a folder, every tool that acts on a message
/// refuses an id made before, and changes nothing. Ids without UIDVALIDITY
/// still work unchecked, except for a permanent delete.
#[tokio::test]
#[ignore = "requires GreenMail"]
async fn greenmail_stale_ids_are_refused() {
    let harness = harness(greenmail_config(), MailVerifier).await;
    let subject = format!("stale {}", uuid::Uuid::new_v4().simple());
    let user = new_mailbox(&subject).await;
    let token = harness.sign_in(&user, &user).await;
    for name in ["Deleted Messages", "Elsewhere"] {
        harness
            .call_ok(&token, "create_folder", json!({ "name": name }))
            .await;
    }
    let found = wait_for_messages(&harness, &token, "INBOX", &subject, 1).await;
    let (folder, uid, uid_validity) =
        parse_imap_id(found["messages"][0]["id"].as_str().unwrap()).unwrap();
    assert_eq!(folder, "INBOX");
    let current = uid_validity.unwrap();
    // A server that recreated the folder would give it another value.
    let stale = imap_id("INBOX", uid, Some(current.checked_add(1).unwrap_or(1)));

    let account = harness
        .store
        .account_by_email(&user, Provider::Imap)
        .await
        .unwrap()
        .unwrap();
    let selection = SearchSelection {
        folder: "INBOX".to_owned(),
        criteria: Criteria {
            subject: Some(subject.clone()),
            until: Some(Cutoff::Imap {
                uid,
                uid_validity: current.checked_add(1).unwrap_or(1),
            }),
            ..Criteria::default()
        },
    }
    .encode(&account.id)
    .unwrap();
    let refused = harness
        .call(
            &token,
            "update_flags",
            json!({ "selection": selection, "read": true }),
        )
        .await;
    assert_eq!(refused["isError"], true);
    assert_eq!(
        refused["content"][0]["text"],
        "this folder was renumbered since the search; search again"
    );

    for (tool, args) in [
        ("get_message", json!({ "id": stale })),
        (
            "download_attachment",
            json!({ "id": stale, "attachment_id": "1" }),
        ),
        ("update_flags", json!({ "id": stale, "flagged": true })),
        (
            "move_message",
            json!({ "id": stale, "destination": "Elsewhere" }),
        ),
        ("delete_message", json!({ "id": stale })),
        ("delete_message", json!({ "id": stale, "permanent": true })),
        (
            "reply_to_message",
            json!({ "id": stale, "body": "This must not be sent." }),
        ),
    ] {
        let refused = harness.call(&token, tool, args).await;
        assert_eq!(refused["isError"], true, "{tool}: {refused}");
        let text = refused.to_string();
        assert!(text.contains("out of date"), "{tool}: {text}");
    }
    let kept = wait_for_messages(&harness, &token, "INBOX", &subject, 1).await;
    assert_eq!(kept["messages"][0]["flagged"], false, "{kept}");
    assert_eq!(kept["messages"][0]["answered"], false, "{kept}");

    let old = imap_id("INBOX", uid, None);
    let message = harness
        .call_ok(&token, "get_message", json!({ "id": old }))
        .await;
    assert_eq!(
        message["id"],
        imap_id("INBOX", uid, Some(current)).as_str(),
        "the answer carries a current id"
    );
    for target in [
        json!({ "id": old, "permanent": true }),
        json!({ "folder": "INBOX", "uid": uid, "permanent": true }),
    ] {
        let refused = harness.call(&token, "delete_message", target).await;
        assert_eq!(refused["isError"], true, "{refused}");
        let text = refused.to_string();
        assert!(text.contains("call search_messages again"), "{text}");
    }
    wait_for_messages(&harness, &token, "INBOX", &subject, 1).await;

    // Changing an unchecked opaque id is refused, but legacy selectors still work.
    for (tool, mut args) in [
        ("update_flags", json!({ "read": true })),
        ("move_message", json!({ "destination": "Elsewhere" })),
        ("delete_message", json!({})),
    ] {
        args["id"] = json!(old);
        let refused = harness.call(&token, tool, args).await;
        assert_eq!(refused["isError"], true);
        assert!(refused.to_string().contains("call search_messages again"));
    }
    let current_id = imap_id("INBOX", uid, Some(current));
    let flagged = harness
        .call_ok(
            &token,
            "update_flags",
            json!({ "folder": "INBOX", "uid": uid, "read": true }),
        )
        .await;
    assert_eq!(
        flagged["result"],
        format!("message {current_id} marked as read"),
        "{flagged}"
    );
    let trashed = harness
        .call_ok(
            &token,
            "delete_message",
            json!({ "folder": "INBOX", "uid": uid }),
        )
        .await;
    let in_trash = wait_for_messages(&harness, &token, "Deleted Messages", &subject, 1).await;
    let trash_id = in_trash["messages"][0]["id"].as_str().unwrap();
    assert_eq!(
        trashed["result"],
        format!("moved message {current_id} to the trash; its new id is {trash_id}"),
        "{trashed}"
    );
}

fn settings(url: &str, secret: &str, auth: &str) -> WebhookSettings {
    WebhookSettings {
        enabled: true,
        url: url.to_owned(),
        auth_header: Some((
            "x-sentinel-name".to_owned(),
            SecretString::from(auth.to_owned()),
        )),
        signing: true,
        signing_secret: SecretString::from(secret.to_owned()),
        include_sender: true,
    }
}

fn failure(summary: &str) -> DeliveryRecord {
    DeliveryRecord {
        created_at: postkeep_store::now(),
        test: false,
        succeeded: false,
        summary: summary.to_owned(),
        elapsed_ms: Some(5),
    }
}

const USER_SECRET: &str = "whsec_SENTINEL-SECRET-USER";
const ALICE_SECRET: &str = "whsec_SENTINEL-SECRET-ALICE";
const USER_AUTH: &str = "Bearer SENTINEL-AUTH-USER";
const ALICE_AUTH: &str = "Bearer SENTINEL-AUTH-ALICE";
const USER_PATH: &str = "USER-PATH-SENTINEL";
const ALICE_PATH: &str = "ALICE-PATH-SENTINEL";
const QUERY_SENTINEL: &str = "QUERY-SENTINEL";

fn assert_no_secrets(body: &str) {
    for secret in [
        USER_SECRET,
        ALICE_SECRET,
        USER_AUTH,
        ALICE_AUTH,
        USER_PATH,
        ALICE_PATH,
        QUERY_SENTINEL,
        "x-sentinel-name",
    ] {
        assert!(!body.contains(secret), "{secret} leaked: {body}");
    }
}

/// Webhooks are off, so the status says so and enabling is refused.
#[tokio::test]
async fn webhook_tools_when_webhooks_are_off() {
    let harness = harness(unreachable_mail(), AcceptAll).await;
    let token = harness
        .sign_in("user@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    let unauthenticated = harness
        .rpc_raw(
            None,
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "get_webhook_status", "arguments": {} }
            }),
        )
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let status = harness
        .call_ok(&token, "get_webhook_status", json!({}))
        .await;
    assert_eq!(status["state"], "unavailable");
    assert_eq!(status["configured"], false);
    assert_eq!(status["outbox_retention_seconds"], 604_800);
    assert_eq!(status["outbox_retention_source"], "default");
    assert_eq!(status["outbox_max_events"], 1000);
    assert_eq!(status["outbox_max_events_source"], "default");
    assert_eq!(status["outbox_max_retention_seconds"], 2_592_000);
    assert_eq!(status["outbox_max_events_limit"], 10_000);
    assert_eq!(status["filter_rules_limit"], 1000);
    assert_eq!(status["filter_rules_active"], 0);
    assert!(status.get("events_pruned").is_none(), "{status}");

    let missing_limits = harness
        .call(
            &token,
            "set_webhook_outbox_limits",
            json!({ "max_events": 2 }),
        )
        .await;
    assert_eq!(missing_limits["isError"], true, "{missing_limits}");
    assert!(
        missing_limits.to_string().contains("/account"),
        "{missing_limits}"
    );

    // No saved row yet: enabling is refused because the server flag is off,
    // and disabling points at the account page.
    let enable = harness
        .call(&token, "set_webhook_enabled", json!({ "enabled": true }))
        .await;
    assert_eq!(enable["isError"], true, "{enable}");
    let text = enable.to_string();
    assert!(text.contains("POSTKEEP_WEBHOOKS"), "{enable}");

    let disable = harness
        .call(&token, "set_webhook_enabled", json!({ "enabled": false }))
        .await;
    assert_eq!(disable["isError"], true, "{disable}");
    assert!(disable.to_string().contains("/account"), "{disable}");

    let user = harness
        .store
        .account_by_email("user@example.com", Provider::Imap)
        .await
        .unwrap()
        .unwrap();
    harness
        .store
        .save_webhook(
            &user.id,
            &settings("https://hooks.example/off", USER_SECRET, USER_AUTH),
        )
        .await
        .unwrap();
    let updated = harness
        .call_ok(
            &token,
            "set_webhook_outbox_limits",
            json!({ "retention": "36h", "max_events": 2 }),
        )
        .await;
    assert_eq!(updated["state"], "unavailable");
    assert_eq!(updated["outbox_retention_seconds"], 129_600);
    assert_eq!(updated["outbox_retention_source"], "account");
    assert_eq!(updated["outbox_max_events"], 2);
    assert_eq!(updated["outbox_max_events_source"], "account");
    assert_eq!(updated["events_pruned"], 0);
    assert_no_secrets(&updated.to_string());
    let again = harness
        .call_ok(&token, "get_webhook_status", json!({}))
        .await;
    assert!(again.get("events_pruned").is_none(), "{again}");
    assert_eq!(again["outbox_max_events"], 2);

    // A saved row can still change its limits while the server flag is off.
    // Enabling stays refused; the flag is checked before the row.
    let enable_saved = harness
        .call(&token, "set_webhook_enabled", json!({ "enabled": true }))
        .await;
    assert_eq!(enable_saved["isError"], true, "{enable_saved}");
    assert!(
        enable_saved.to_string().contains("POSTKEEP_WEBHOOKS"),
        "{enable_saved}"
    );
}

/// Each token sees only its own webhook. Enabling the caller's paused
/// webhook clears the pause and delivers events that were kept.
#[tokio::test]
async fn webhook_tools_are_scoped_to_the_signed_in_account() {
    let mut harness = webhook_harness().await;
    let user_token = harness
        .sign_in("user@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    let alice_token = harness
        .sign_in("alice@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    harness.until_watchers_stop().await;
    let user = harness
        .store
        .account_by_email("user@example.com", Provider::Imap)
        .await
        .unwrap()
        .unwrap();
    let alice = harness
        .store
        .account_by_email("alice@example.com", Provider::Imap)
        .await
        .unwrap()
        .unwrap();
    let receiver = harness.receiver.as_ref().unwrap();
    let user_url = receiver.url(&format!("/{USER_PATH}?{QUERY_SENTINEL}=user"));
    let alice_url = receiver.url(&format!("/{ALICE_PATH}?{QUERY_SENTINEL}=alice"));
    harness
        .store
        .save_webhook(&user.id, &settings(&user_url, USER_SECRET, USER_AUTH))
        .await
        .unwrap();
    harness
        .store
        .save_webhook(&alice.id, &settings(&alice_url, ALICE_SECRET, ALICE_AUTH))
        .await
        .unwrap();
    harness
        .store
        .append_mail_event(&user.id, r#"{"event":"new_mail","id":"m1"}"#, None)
        .await
        .unwrap();
    let poisonous = format!("{user_url} {USER_SECRET} {USER_AUTH} x-sentinel-name");
    for _ in 0..10 {
        harness
            .store
            .record_delivery(&user.id, &failure(&poisonous))
            .await
            .unwrap();
    }

    let user_reply = harness
        .rpc_raw(
            Some(&user_token),
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "get_webhook_status", "arguments": {} }
            }),
        )
        .await;
    assert_eq!(user_reply.status, StatusCode::OK, "{}", user_reply.body);
    assert_no_secrets(&user_reply.body);
    let user_status = user_reply.json()["result"]["structuredContent"].clone();
    assert_eq!(user_status["state"], "paused");
    assert_eq!(user_status["configured"], true);
    assert_eq!(user_status["enabled"], true);
    assert_eq!(user_status["paused"], true);
    assert!(user_status["paused_since"].is_string());
    assert_eq!(user_status["consecutive_failures"], 10);
    assert_eq!(user_status["failure_threshold"], 10);
    assert_eq!(user_status["url_host"], "hooks.test");
    assert!(user_status["pending_events"].as_i64().unwrap() >= 1);
    assert!(user_status["retry_interval_seconds"].is_number());

    let alice_reply = harness
        .rpc_raw(
            Some(&alice_token),
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "get_webhook_status", "arguments": {} }
            }),
        )
        .await;
    assert_no_secrets(&alice_reply.body);
    let alice_status = alice_reply.json()["result"]["structuredContent"].clone();
    assert_eq!(alice_status["state"], "active");
    assert_eq!(alice_status["paused"], false);
    assert_eq!(alice_status["url_host"], "hooks.test");

    // Alice turning her webhook off does not touch the other account.
    let alice_off = harness
        .rpc_raw(
            Some(&alice_token),
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "set_webhook_enabled",
                    "arguments": { "enabled": false }
                }
            }),
        )
        .await;
    assert_no_secrets(&alice_off.body);
    assert_eq!(
        alice_off.json()["result"]["structuredContent"]["state"],
        "disabled"
    );
    let still = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert!(still.is_paused());

    let enabled = harness
        .rpc_raw(
            Some(&user_token),
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "set_webhook_enabled",
                    "arguments": { "enabled": true }
                }
            }),
        )
        .await;
    assert_no_secrets(&enabled.body);
    let enabled_status = enabled.json()["result"]["structuredContent"].clone();
    assert_eq!(enabled_status["state"], "active");
    assert_eq!(enabled_status["paused"], false);
    assert_eq!(enabled_status["consecutive_failures"], 0);
    assert_ne!(enabled.json()["result"]["isError"], true);

    let delivered = tokio::time::timeout(
        Duration::from_secs(5),
        harness.receiver.as_mut().unwrap().requests.recv(),
    )
    .await
    .expect("enabling a paused webhook did not retry")
    .unwrap();
    assert_eq!(delivered.header("x-webhook-sequence"), Some("1"));
    assert_eq!(delivered.json()["id"], "m1");

    let mut recovered = false;
    for _ in 0..50 {
        let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
        if hook.delivered_sequence >= 1 && hook.paused_at.is_none() {
            assert_eq!(hook.consecutive_failures, 0);
            assert!(hook.settings.enabled);
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(recovered, "the kept event was not delivered");

    let alice_hook = harness.store.webhook(&alice.id).await.unwrap().unwrap();
    assert!(!alice_hook.settings.enabled);

    // Turning it off, then on, drops events kept while it was off.
    let off = harness
        .call_ok(
            &user_token,
            "set_webhook_enabled",
            json!({ "enabled": false }),
        )
        .await;
    assert_eq!(off["state"], "disabled");
    harness
        .store
        .append_mail_event(&user.id, r#"{"event":"new_mail","id":"m2"}"#, None)
        .await
        .unwrap();
    harness
        .call_ok(
            &user_token,
            "set_webhook_enabled",
            json!({ "enabled": true }),
        )
        .await;
    let extra = tokio::time::timeout(
        Duration::from_millis(400),
        harness.receiver.as_mut().unwrap().requests.recv(),
    )
    .await;
    assert!(
        extra.is_err(),
        "a re-enabled webhook delivered a skipped event: {extra:?}"
    );
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert_eq!(hook.delivered_sequence, hook.last_sequence);

    let missing = harness
        .sign_in("bob@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    let refused = harness
        .call(&missing, "set_webhook_enabled", json!({ "enabled": true }))
        .await;
    assert_eq!(refused["isError"], true, "{refused}");
    let text = refused.to_string();
    assert!(text.contains("/account"), "{refused}");
    assert_no_secrets(&text);

    if let Some(watchers) = &harness.watchers {
        watchers.shutdown(Duration::from_secs(2)).await;
    }
}

/// Each token changes only its own outbox. Lowering the cap deletes the
/// oldest events, including ones not yet delivered, and the ones that
/// remain are delivered in sequence order.
#[tokio::test]
async fn outbox_limits_are_scoped_and_prune_the_oldest_events() {
    let mut harness = webhook_harness().await;
    let user_token = harness
        .sign_in("user@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    let alice_token = harness
        .sign_in("alice@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    harness.until_watchers_stop().await;
    let unauthenticated = harness
        .rpc_raw(
            None,
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "set_webhook_outbox_limits",
                    "arguments": { "max_events": 2 }
                }
            }),
        )
        .await;
    assert_eq!(unauthenticated.status, StatusCode::UNAUTHORIZED);

    let missing = harness
        .call(
            &user_token,
            "set_webhook_outbox_limits",
            json!({ "retention": "36h" }),
        )
        .await;
    assert_eq!(missing["isError"], true, "{missing}");
    assert!(missing.to_string().contains("/account"), "{missing}");
    assert_no_secrets(&missing.to_string());

    let user = harness
        .store
        .account_by_email("user@example.com", Provider::Imap)
        .await
        .unwrap()
        .unwrap();
    let alice = harness
        .store
        .account_by_email("alice@example.com", Provider::Imap)
        .await
        .unwrap()
        .unwrap();
    let receiver = harness.receiver.as_ref().unwrap();
    harness
        .store
        .save_webhook(
            &user.id,
            &settings(
                &receiver.url(&format!("/{USER_PATH}?{QUERY_SENTINEL}=user")),
                USER_SECRET,
                USER_AUTH,
            ),
        )
        .await
        .unwrap();
    harness
        .store
        .save_webhook(
            &alice.id,
            &settings(
                &receiver.url(&format!("/{ALICE_PATH}?{QUERY_SENTINEL}=alice")),
                ALICE_SECRET,
                ALICE_AUTH,
            ),
        )
        .await
        .unwrap();
    for n in 1..=4 {
        harness
            .store
            .append_mail_event(
                &user.id,
                &format!(r#"{{"event":"new_mail","id":"m{n}"}}"#),
                None,
            )
            .await
            .unwrap();
    }

    let status = harness
        .call_ok(&user_token, "get_webhook_status", json!({}))
        .await;
    assert_eq!(status["outbox_retention_source"], "default");
    assert_eq!(status["outbox_max_events"], 1000);
    assert!(status.get("events_pruned").is_none(), "{status}");
    assert_no_secrets(&status.to_string());

    let updated = harness
        .call_ok(
            &user_token,
            "set_webhook_outbox_limits",
            json!({ "retention": "36h", "max_events": 2 }),
        )
        .await;
    assert_eq!(updated["events_pruned"], 2);
    assert_eq!(updated["outbox_retention_seconds"], 129_600);
    assert_eq!(updated["outbox_retention_source"], "account");
    assert_eq!(updated["outbox_max_events"], 2);
    assert_eq!(updated["outbox_max_events_source"], "account");
    assert_eq!(updated["outbox_max_retention_seconds"], 2_592_000);
    assert_eq!(updated["outbox_max_events_limit"], 10_000);
    assert_eq!(updated["pending_events"], 2);
    assert_no_secrets(&updated.to_string());
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert_eq!((hook.delivered_sequence, hook.last_sequence), (0, 4));
    assert_eq!(hook.outbox_retention_secs, Some(129_600));
    assert_eq!(hook.outbox_max_events, Some(2));

    let alice_status = harness
        .call_ok(&alice_token, "get_webhook_status", json!({}))
        .await;
    assert_eq!(alice_status["outbox_retention_source"], "default");
    assert_eq!(alice_status["outbox_max_events_source"], "default");
    assert_eq!(alice_status["outbox_max_events"], 1000);
    assert_no_secrets(&alice_status.to_string());
    harness
        .call_ok(
            &alice_token,
            "set_webhook_outbox_limits",
            json!({ "max_events": 4 }),
        )
        .await;
    let user_still = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert_eq!(user_still.outbox_max_events, Some(2));
    let alice_hook = harness.store.webhook(&alice.id).await.unwrap().unwrap();
    assert_eq!(alice_hook.outbox_max_events, Some(4));
    assert!(alice_hook.outbox_retention_secs.is_none());

    // Already enabled: this wakes delivery without skipping the queue.
    let enabled = harness
        .call_ok(
            &user_token,
            "set_webhook_enabled",
            json!({ "enabled": true }),
        )
        .await;
    assert_eq!(enabled["state"], "active");
    assert_no_secrets(&enabled.to_string());
    let mut sequences = Vec::new();
    for _ in 0..2 {
        let delivered = tokio::time::timeout(
            Duration::from_secs(5),
            harness.receiver.as_mut().unwrap().requests.recv(),
        )
        .await
        .expect("kept event was not delivered")
        .unwrap();
        sequences.push(delivered.header("x-webhook-sequence").unwrap().to_owned());
    }
    assert_eq!(sequences, ["3", "4"]);
    // The receiver has both requests, but the pump records each delivery a
    // moment later, and a success recorded after the failures below would
    // clear them.
    until(async || {
        let deliveries = harness.store.recent_deliveries(&user.id).await.unwrap();
        deliveries.iter().filter(|record| record.succeeded).count() >= 2
    })
    .await;

    for (arguments, needle) in [
        (json!({ "retention": "31d" }), "30 days"),
        (json!({ "retention": "30m" }), "30 minutes"),
        (json!({ "retention": 0 }), "0 seconds"),
        (json!({ "max_events": 10001 }), "not 10001"),
    ] {
        let rejected = harness
            .call(&user_token, "set_webhook_outbox_limits", arguments)
            .await;
        assert_eq!(rejected["isError"], true, "{rejected}");
        let text = rejected.to_string();
        assert!(text.contains(needle), "{text}");
        assert!(
            text.contains("3600") || text.contains("10000"),
            "the allowed range is missing: {text}"
        );
        assert_no_secrets(&text);
    }
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert_eq!(hook.outbox_retention_secs, Some(129_600));
    assert_eq!(hook.outbox_max_events, Some(2));

    let reset = harness
        .call_ok(
            &user_token,
            "set_webhook_outbox_limits",
            json!({ "reset": true, "retention": "not a duration", "max_events": { "bad": true } }),
        )
        .await;
    assert_eq!(reset["outbox_retention_source"], "default");
    assert_eq!(reset["outbox_max_events_source"], "default");
    assert_eq!(reset["outbox_retention_seconds"], 604_800);
    assert_eq!(reset["outbox_max_events"], 1000);
    assert_no_secrets(&reset.to_string());
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert!(hook.outbox_retention_secs.is_none() && hook.outbox_max_events.is_none());

    harness
        .store
        .set_webhook_enabled(&alice.id, false)
        .await
        .unwrap();
    let disabled = harness
        .call_ok(
            &alice_token,
            "set_webhook_outbox_limits",
            json!({ "retention": "2d" }),
        )
        .await;
    assert_eq!(disabled["state"], "disabled");
    assert_eq!(disabled["outbox_retention_seconds"], 2 * 24 * 60 * 60);
    assert_no_secrets(&disabled.to_string());

    for _ in 0..10 {
        harness
            .store
            .record_delivery(&user.id, &failure("HTTP 500"))
            .await
            .unwrap();
    }
    assert!(
        harness
            .store
            .webhook(&user.id)
            .await
            .unwrap()
            .unwrap()
            .is_paused()
    );
    let paused = harness
        .call_ok(
            &user_token,
            "set_webhook_outbox_limits",
            json!({ "max_events": 3 }),
        )
        .await;
    assert_eq!(paused["state"], "paused");
    assert_eq!(paused["outbox_max_events"], 3);
    assert_eq!(paused["outbox_retention_source"], "default");
    assert_no_secrets(&paused.to_string());

    if let Some(watchers) = &harness.watchers {
        watchers.shutdown(Duration::from_secs(2)).await;
    }
}

/// Enabling a saved webhook whose URL is empty or invalid is refused. The
/// row stays off, and the error tells the user to finish setup on /account
/// without repeating the URL.
#[tokio::test]
async fn enabling_a_webhook_without_a_usable_endpoint_is_refused() {
    let harness = webhook_harness().await;
    let token = harness
        .sign_in("user@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    harness.until_watchers_stop().await;
    let user = harness
        .store
        .account_by_email("user@example.com", Provider::Imap)
        .await
        .unwrap()
        .unwrap();
    let mut empty = settings("https://hooks.example/unused", USER_SECRET, USER_AUTH);
    empty.enabled = false;
    empty.url.clear();
    harness.store.save_webhook(&user.id, &empty).await.unwrap();

    let enable = harness
        .call(&token, "set_webhook_enabled", json!({ "enabled": true }))
        .await;
    assert_eq!(enable["isError"], true, "{enable}");
    let text = enable.to_string();
    assert!(text.contains("/account"), "{enable}");
    assert!(text.contains("no usable endpoint"), "{enable}");
    assert_no_secrets(&text);
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert!(!hook.settings.enabled, "enabling an empty URL turned it on");
    assert_eq!(hook.settings.url, "");

    let sentinel = "INVALID-PATH-SENTINEL";
    let mut invalid = empty;
    invalid.url = format!("http://hooks.example/{sentinel}");
    harness
        .store
        .save_webhook(&user.id, &invalid)
        .await
        .unwrap();
    let again = harness
        .call(&token, "set_webhook_enabled", json!({ "enabled": true }))
        .await;
    assert_eq!(again["isError"], true, "{again}");
    let again_text = again.to_string();
    assert!(again_text.contains("/account"), "{again}");
    assert!(
        !again_text.contains(sentinel),
        "the invalid URL leaked: {again}"
    );
    assert_no_secrets(&again_text);
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);
    assert!(hook.settings.url.contains(sentinel));

    let disable = harness
        .call(&token, "set_webhook_enabled", json!({ "enabled": false }))
        .await;
    assert_ne!(disable["isError"], true, "{disable}");
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);

    let receiver = harness.receiver.as_ref().unwrap();
    let mut usable = settings(&receiver.url("/hook"), USER_SECRET, USER_AUTH);
    usable.enabled = false;
    harness.store.save_webhook(&user.id, &usable).await.unwrap();
    let enabled = harness
        .call_ok(&token, "set_webhook_enabled", json!({ "enabled": true }))
        .await;
    assert_eq!(enabled["state"], "active");
    assert_eq!(enabled["enabled"], true);
    let hook = harness.store.webhook(&user.id).await.unwrap().unwrap();
    assert!(hook.settings.enabled);

    if let Some(watchers) = &harness.watchers {
        watchers.shutdown(Duration::from_secs(2)).await;
    }
}

/// Settings sealed under a key this process does not have are reported as
/// unreadable. Enabling is refused; disabling still turns the row off.
/// Nothing in the tool result is the URL path, a secret, or ciphertext.
#[tokio::test]
async fn unreadable_webhook_status_refuses_enable_and_allows_disable() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("server.db");
    let url = format!("sqlite://{}", db_path.display());
    // The key the webhook's secrets are sealed under, which the server does
    // not have. The test keeps its bytes, to seal under it.
    let lost_bytes = [0x6c_u8; 32];
    let lost = MasterKey::parse(&STANDARD.encode(lost_bytes)).unwrap();
    let current = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let email = "unreadable@example.com";
    let password = "abcd-efgh-ijkl-mnop";
    let secret = "whsec_SENTINEL-SECRET-UNREADABLE";
    let auth = "Bearer SENTINEL-AUTH-UNREADABLE";
    let path = "UNREADABLE-PATH-SENTINEL";
    let query = "UNREADABLE-QUERY-SENTINEL";
    let event_marker = "UNREADABLE-EVENT-SENTINEL";
    let hook_url = format!("https://hooks.test/{path}?token={query}");

    let store = Store::connect(&url, &current).await.unwrap();
    let account = store
        .upsert_account(email, &SecretString::from(password.to_owned()))
        .await
        .unwrap();
    let account_id = account.id.clone();
    store
        .save_webhook(&account_id, &settings(&hook_url, secret, auth))
        .await
        .unwrap();
    let poisonous = format!("{hook_url} {secret} {auth} x-sentinel-name");
    for _ in 0..10 {
        store
            .record_delivery(&account_id, &failure(&poisonous))
            .await
            .unwrap();
    }
    store
        .append_mail_event(
            &account_id,
            &format!(r#"{{"event":"new_mail","id":"{event_marker}"}}"#),
            None,
        )
        .await
        .unwrap();
    assert!(
        store
            .webhook(&account_id)
            .await
            .unwrap()
            .unwrap()
            .is_paused()
    );
    store_rule(&store, &account_id, "allow", "body", "contains", "x").await;
    seal_webhook_secrets(&store, &lost_bytes, &account_id.0, secret, auth).await;
    store.close().await;

    let ciphertext = sqlite_text(
        &db_path,
        "SELECT signing_secret_ciphertext FROM webhooks WHERE account_id = ?1",
        &account_id.0,
    )
    .await;
    let auth_ciphertext = sqlite_text(
        &db_path,
        "SELECT auth_header_value_ciphertext FROM webhooks WHERE account_id = ?1",
        &account_id.0,
    )
    .await;
    let signing_body = ciphertext.trim_start_matches("v1.");
    let auth_body = auth_ciphertext.trim_start_matches("v1.");
    assert!(signing_body.len() > 16 && auth_body.len() > 16);

    let store = Store::connect(&url, &current).await.unwrap();
    let err = store.webhook(&account_id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");

    let hook_receiver = receiver(&[]).await;
    let mut auth_config = AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap();
    auth_config.imap_servers = ImapServers::custom_only("Test mail", unreachable_mail());
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::custom_only("Test mail", unreachable_mail()),
        hook_receiver.deliverer.clone(),
        WatchConfig {
            min_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(30),
            outbox_min_backoff: Duration::from_secs(30),
            outbox_max_backoff: Duration::from_secs(30),
            webhook_retry_interval: Duration::from_secs(30),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    );
    let config = AppConfig {
        auth: auth_config,
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits {
            max_body_bytes: 64 * 1024,
            ..app::RequestLimits::default()
        },
        pool: postkeep::pool::PoolConfig::default(),
        watchers: Some(watchers.clone()),
        upstream: None,
        google_push: None,
    };
    let mut harness = Harness {
        app: app::router(config, store.clone(), AcceptAll, CancellationToken::new()),
        store,
        watchers: Some(watchers),
        receiver: Some(hook_receiver),
        _dir: dir,
    };

    let token = harness.sign_in(email, password).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let watchers = harness.watchers.as_ref().unwrap();
    assert_eq!(
        watchers.running(),
        0,
        "signing in must not leave an unreadable webhook retrying"
    );
    assert_eq!(
        watchers.pumps(),
        0,
        "the pump must not retry an unreadable webhook"
    );
    assert!(
        harness
            .receiver
            .as_mut()
            .unwrap()
            .requests
            .try_recv()
            .is_err()
    );

    let reply = harness
        .rpc_raw(
            Some(&token),
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "get_webhook_status", "arguments": {} }
            }),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_no_webhook_leak(
        &reply.body,
        &[
            secret,
            auth,
            path,
            query,
            event_marker,
            signing_body,
            auth_body,
        ],
    );
    let status = reply.json()["result"]["structuredContent"].clone();
    assert_eq!(status["state"], "unreadable");
    assert_eq!(status["configured"], true);
    assert_eq!(status["enabled"], true);
    assert_eq!(status["paused"], false);
    assert!(status["paused_since"].is_null());
    assert!(status["last_error"].is_null());
    assert!(status["url_host"].is_null());
    assert!(status["next_retry_at"].is_null());
    assert!(status["pending_events"].as_i64().unwrap() >= 1);
    assert_eq!(status["message"], UNREADABLE_WEBHOOK);
    assert_eq!(
        status["filter_rules_unreadable"], true,
        "the settings' state stays"
    );

    let enable = harness
        .call(&token, "set_webhook_enabled", json!({ "enabled": true }))
        .await;
    assert_eq!(enable["isError"], true, "{enable}");
    assert_eq!(error_text(&enable), UNREADABLE_ENABLE_REFUSED);
    let enable_text = enable.to_string();
    assert_no_webhook_leak(
        &enable_text,
        &[
            secret,
            auth,
            path,
            query,
            event_marker,
            signing_body,
            auth_body,
        ],
    );
    let still = harness
        .call_ok(&token, "get_webhook_status", json!({}))
        .await;
    assert_eq!(still["state"], "unreadable");
    assert_eq!(
        still["enabled"], true,
        "enabling an unreadable row must not stick"
    );

    let disabled = harness
        .rpc_raw(
            Some(&token),
            HOST,
            &json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "set_webhook_enabled",
                    "arguments": { "enabled": false }
                }
            }),
        )
        .await;
    assert_eq!(disabled.status, StatusCode::OK, "{}", disabled.body);
    assert_ne!(
        disabled.json()["result"]["isError"],
        json!(true),
        "{}",
        disabled.body
    );
    assert_no_webhook_leak(
        &disabled.body,
        &[
            secret,
            auth,
            path,
            query,
            event_marker,
            signing_body,
            auth_body,
        ],
    );
    let disabled_status = disabled.json()["result"]["structuredContent"].clone();
    assert_eq!(disabled_status["state"], "unreadable");
    assert_eq!(disabled_status["enabled"], false);
    assert_eq!(disabled_status["paused"], false);

    if let Some(watchers) = &harness.watchers {
        watchers.shutdown(Duration::from_secs(2)).await;
    }
    harness.store.close().await;
    let store = Store::connect(&url, &lost).await.unwrap();
    let hook = store.webhook(&account_id).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);
    assert!(hook.paused_at.is_none());
    assert_eq!(hook.settings.url, hook_url);
    assert_eq!(hook.settings.signing_secret.expose_secret(), secret);
    let (_, stored_auth) = hook.settings.auth_header.unwrap();
    assert_eq!(stored_auth.expose_secret(), auth);
    assert!(store.pending_mail_event_count(&account_id).await.unwrap() >= 1);
    store.close().await;
}

/// Stores a rule through the store, at a limit of 9, with no check.
async fn store_rule(
    store: &Store,
    account: &AccountId,
    action: &str,
    field: &str,
    kind: &str,
    pattern: &str,
) {
    let [action, field, kind] = [action, field, kind].map(str::to_owned);
    let pattern = SecretString::from(pattern.to_owned());
    let rule = NewFilterRule {
        action,
        field,
        kind,
        pattern,
    };
    let added = store.add_webhook_filter_rule(account, &rule, 9, |_| Ok(()));
    assert!(matches!(
        added.await.unwrap(),
        postkeep_store::AddedFilterRule::Added(_)
    ));
}

/// The webhook harness with `max_filter_rules` rules counting, one signed-in
/// mailbox with a webhook saved, its token and its ID.
async fn filter_harness(max_filter_rules: usize) -> (Harness, String, AccountId) {
    let harness = webhook_harness_for(unreachable_mail(), |watch, _| {
        watch.max_filter_rules = max_filter_rules;
    })
    .await;
    let token = harness
        .sign_in("user@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    harness.until_watchers_stop().await;
    let user = harness
        .store
        .account_by_email("user@example.com", Provider::Imap);
    let user = user.await.unwrap().unwrap().id;
    let hook = settings("https://hooks.example.com/mail", USER_SECRET, USER_AUTH);
    harness.store.save_webhook(&user, &hook).await.unwrap();
    (harness, token, user)
}

const UNREADABLE_WEBHOOK: &str = "These webhook settings can't be read because the encryption key changed. Enter the URL and auth header again on the account page (/account) and save to replace them.";

const UNREADABLE_ENABLE_REFUSED: &str = "These webhook settings can't be read, so they can't be turned on. Enter the URL and auth header again on the account page (/account) and save to replace them. Turning the webhook off still works.";

const UNDECRYPTABLE_RULES: &str = "This mailbox's filter rules can't be read because the encryption key changed, so its new mail waits. Ask the server's operator to put the previous master key back in POSTKEEP_PREVIOUS_MASTER_KEYS and restart the server. Only if that key is gone, remove them all with remove_webhook_filter (all: true) and add the rules again from scratch.";

const UNKNOWN_RULES: &str = "A filter rule that's on has an action, field or kind this server doesn't know, so this mailbox's new mail waits. Remove it with remove_webhook_filter (list_webhook_filters shows it as written), or turn it off on the account page (/account).";

/// The newest rule past the server's setting is disabled.
#[tokio::test]
async fn the_status_counts_the_filter_rules_at_the_mailbox_s_limit() {
    let (harness, token, user) = filter_harness(2).await;
    for pattern in ["a", "b", "c"] {
        store_rule(
            &harness.store,
            &user,
            "allow",
            "subject",
            "contains",
            pattern,
        )
        .await;
    }
    let status = harness
        .call_ok(&token, "get_webhook_status", json!({}))
        .await;
    assert_eq!(status["state"], "active", "{status}");
    let counts = [
        &status["filter_rules_active"],
        &status["filter_rules_disabled"],
        &status["filter_rules_limit"],
        &status["filter_rules_unreadable"],
        &status["message"],
    ];
    assert_eq!(
        counts,
        [&json!(2), &json!(1), &json!(2), &json!(false), &Value::Null]
    );
}

#[tokio::test]
async fn the_account_page_counts_the_rules_at_the_server_s_setting() {
    let (harness, _token, user) = filter_harness(1).await;
    for pattern in ["a", "b"] {
        store_rule(
            &harness.store,
            &user,
            "allow",
            "subject",
            "contains",
            pattern,
        )
        .await;
    }
    let fields = [
        ("email", "user@example.com"),
        ("password", "abcd-efgh-ijkl-mnop"),
    ];
    let signed_in = harness.form("/account/sign-in", &fields).await;
    assert_eq!(
        signed_in.status,
        StatusCode::SEE_OTHER,
        "{}",
        signed_in.body
    );
    let cookie = signed_in.headers[header::SET_COOKIE].to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap();
    let page = harness
        .send(
            Request::get("/account")
                .header(header::HOST, HOST)
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(
        page.body.matches("Past the limit").count(),
        1,
        "{}",
        page.body
    );
}

/// Rules this server can't read make an active or paused state `rules_unreadable`, but
/// leave `disabled` and `needs_password` as they are.
#[tokio::test]
async fn filter_rules_that_cannot_be_read_show_in_the_status() {
    let (harness, token, user) = filter_harness(9).await;
    store_rule(&harness.store, &user, "allow", "body", "contains", "x").await;
    let status = async || {
        harness
            .call_ok(&token, "get_webhook_status", json!({}))
            .await
    };
    let unknown = status().await;
    assert_eq!(unknown["state"], "rules_unreadable", "{unknown}");
    assert_eq!(unknown["filter_rules_unreadable"], true);
    assert_eq!(unknown["filter_rules_active"], 1);
    assert_eq!(unknown["message"], UNKNOWN_RULES);
    for _ in 0..10 {
        let failed = failure("timed out");
        harness.store.record_delivery(&user, &failed).await.unwrap();
    }
    let paused = status().await;
    assert_eq!(
        (&paused["paused"], &paused["state"]),
        (&json!(true), &json!("rules_unreadable"))
    );

    let garble = "UPDATE webhook_filter_rules SET pattern_ciphertext = 'bad'";
    sqlx::query(garble)
        .execute(harness.store.pool())
        .await
        .unwrap();
    let garbled = status().await;
    assert_eq!(garbled["state"], "rules_unreadable", "{garbled}");
    assert_eq!(garbled["filter_rules_unreadable"], true);
    assert_eq!(garbled["message"], UNDECRYPTABLE_RULES);
    let counts = (
        &garbled["filter_rules_active"],
        &garbled["filter_rules_disabled"],
    );
    assert_eq!(counts, (&json!(0), &json!(0)));

    let off = json!({ "enabled": false });
    let off = harness.call_ok(&token, "set_webhook_enabled", off).await;
    assert_eq!(off["state"], "disabled", "{off}");
    assert_eq!(off["message"], Value::Null);
    assert_eq!(off["filter_rules_unreadable"], true);

    harness.store.mark_password_rejected(&user).await.unwrap();
    let rejected = status().await;
    assert_eq!(rejected["state"], "needs_password", "{rejected}");
    assert_eq!(
        rejected["message"],
        "The mail server rejected the stored password. Enter a new app password on the account page (/account)."
    );
    assert_eq!(rejected["filter_rules_unreadable"], true);
}

/// An allow rule on the subject.
fn subject_rule(pattern: &str) -> Value {
    json!({ "action": "allow", "field": "subject", "kind": "contains", "pattern": pattern })
}

/// The text of a tool error.
fn error_text(result: &Value) -> &str {
    assert_eq!(result["isError"], true, "{result}");
    result["content"][0]["text"].as_str().unwrap()
}

/// The `field` of each listed rule.
fn listed<'a>(list: &'a Value, field: &str) -> Vec<&'a Value> {
    let filters = list["filters"].as_array().unwrap();
    filters.iter().map(|filter| &filter[field]).collect()
}

#[tokio::test]
async fn agents_add_list_and_remove_filter_rules() {
    let (harness, token, _) = filter_harness(9).await;
    let add = |pattern: &str| harness.call_ok(&token, "add_webhook_filter", subject_rule(pattern));
    let first = add("invoice").await;
    let counts = |added: &Value| {
        let names = ["active", "disabled", "limit", "unreadable"];
        names.map(|name| added[format!("filter_rules_{name}")].clone())
    };
    assert_eq!(counts(&first), [json!(1), json!(0), json!(9), json!(false)]);
    let second = add("receipt").await;
    assert_eq!(
        counts(&second),
        [json!(2), json!(0), json!(9), json!(false)]
    );

    let list = harness
        .call_ok(&token, "list_webhook_filters", json!({}))
        .await;
    assert_eq!(listed(&list, "id"), [&first["id"], &second["id"]]);
    assert_eq!(listed(&list, "pattern"), ["invoice", "receipt"]);
    assert_eq!(listed(&list, "active"), [true, true]);
    let rule = &list["filters"][0];
    let names = (&rule["action"], &rule["field"], &rule["kind"]);
    assert_eq!(
        names,
        (&json!("allow"), &json!("subject"), &json!("contains"))
    );
    let added_at = rule["added_at"].as_str().unwrap();
    assert!(
        chrono::DateTime::parse_from_rfc3339(added_at).is_ok(),
        "{added_at}"
    );
    assert_eq!(
        (&list["offset"], list.get("next_offset")),
        (&json!(0), None)
    );
    assert_eq!(counts(&list), counts(&second));

    let remove = |arguments: Value| harness.call_ok(&token, "remove_webhook_filter", arguments);
    let by_id = json!({ "id": first["id"] });
    assert_eq!(remove(by_id.clone()).await["removed"], 1);
    assert_eq!(remove(by_id).await["removed"], 0);
    assert_eq!(remove(json!({ "all": true })).await["removed"], 1);
    let list = harness
        .call_ok(&token, "list_webhook_filters", json!({}))
        .await;
    assert_eq!(list["filters"], json!([]));
}

#[tokio::test]
async fn the_mailbox_s_limit_refuses_an_add_and_disables_newer_rules() {
    let (harness, token, user) = filter_harness(2).await;
    let add = || harness.call(&token, "add_webhook_filter", subject_rule("x"));
    for _ in 0..2 {
        assert_ne!(add().await["isError"], true);
    }
    let at_limit = "This mailbox may have at most 2 filter rules.";
    assert_eq!(error_text(&add().await), at_limit);

    harness
        .store
        .remove_webhook_filter_rules(&user)
        .await
        .unwrap();
    for pattern in ["a", "b", "c"] {
        store_rule(
            &harness.store,
            &user,
            "allow",
            "subject",
            "contains",
            pattern,
        )
        .await;
    }
    let list = async || {
        harness
            .call_ok(&token, "list_webhook_filters", json!({}))
            .await
    };
    let three = list().await;
    assert_eq!(listed(&three, "active"), [true, true, false]);
    assert_eq!(error_text(&add().await), at_limit);
    let oldest = json!({ "id": three["filters"][0]["id"] });
    let removed = harness
        .call_ok(&token, "remove_webhook_filter", oldest)
        .await;
    assert_eq!(removed["removed"], 1);
    let two = list().await;
    assert_eq!(listed(&two, "pattern"), ["b", "c"]);
    assert_eq!(listed(&two, "active"), [true, true]);
}

/// A turned-off rule with a field this version doesn't know is neither read nor
/// counted as active, but it keeps its place toward the limit.
#[tokio::test]
async fn a_rule_turned_off_judges_nothing_and_still_counts_toward_the_limit() {
    let (harness, token, user) = filter_harness(3).await;
    store_rule(&harness.store, &user, "allow", "subject", "contains", "a").await;
    store_rule(&harness.store, &user, "allow", "body", "contains", "x").await;
    let status = async || {
        harness
            .call_ok(&token, "get_webhook_status", json!({}))
            .await
    };
    assert_eq!(status().await["state"], "rules_unreadable");
    let rules = harness.store.webhook_filter_rules(&user, 9).await.unwrap();
    let body = &rules.iter().find(|rule| rule.field == "body").unwrap().id;
    let off = harness
        .store
        .set_webhook_filter_rule_enabled(&user, body, false, 3, |_| Ok(()));
    assert_eq!(
        off.await.unwrap(),
        postkeep_store::ChangedFilterRule::Changed
    );

    let counts = |reply: &Value| {
        let names = ["active", "disabled", "limit", "unreadable"];
        names.map(|name| reply[format!("filter_rules_{name}")].clone())
    };
    let now = status().await;
    assert_eq!(now["state"], "active", "{now}");
    assert_eq!(counts(&now), [json!(1), json!(1), json!(3), json!(false)]);
    let list = harness
        .call_ok(&token, "list_webhook_filters", json!({}))
        .await;
    assert_eq!(listed(&list, "enabled"), [true, false]);
    assert_eq!(listed(&list, "active"), [true, false]);
    let added = harness.call_ok(&token, "add_webhook_filter", subject_rule("c"));
    let added = added.await;
    assert_eq!(counts(&added), [json!(2), json!(1), json!(3), json!(false)]);
    let fourth = harness.call(&token, "add_webhook_filter", subject_rule("d"));
    let at_limit = "This mailbox may have at most 3 filter rules.";
    assert_eq!(error_text(&fourth.await), at_limit);
}

#[tokio::test]
async fn invalid_rules_are_refused_and_store_nothing() {
    let (harness, token, user) = filter_harness(9).await;
    let refused = async |action: &str, field: &str, kind: &str, pattern: &str| {
        let rule = json!({ "action": action, "field": field, "kind": kind, "pattern": pattern });
        let result = harness.call(&token, "add_webhook_filter", rule).await;
        error_text(&result).to_owned()
    };
    let length = "the pattern must be 1 to 512 bytes";
    assert_eq!(refused("allow", "subject", "contains", "").await, length);
    let long = "x".repeat(513);
    assert_eq!(refused("allow", "subject", "contains", &long).await, length);
    let look_around = refused("block", "subject", "regex", "(?=x)").await;
    assert!(look_around.contains("look-around"), "{look_around}");
    assert!(!look_around.contains("(?=x)"), "{look_around}");
    let subject = refused("allow", "subject", "domain", "example.com").await;
    assert_eq!(subject, "a domain rule cannot look at the subject");
    let at = refused("allow", "from", "domain", "@example.com").await;
    assert!(at.starts_with("a domain rule needs a plain domain"), "{at}");
    let deny = json!({ "action": "deny", "field": "subject", "kind": "contains", "pattern": "x" });
    let request = json!({ "name": "add_webhook_filter", "arguments": deny });
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": request });
    let reply = harness.rpc_raw(Some(&token), HOST, &body).await.json();
    let refused_call = reply.get("error").is_some() || reply["result"]["isError"] == true;
    assert!(refused_call, "{reply}");
    for arguments in [json!({}), json!({ "id": "x", "all": true })] {
        let result = harness
            .call(&token, "remove_webhook_filter", arguments)
            .await;
        assert_eq!(error_text(&result), "Give either id or all: true.");
    }
    let stored = harness.store.webhook_filter_rules(&user, 9).await.unwrap();
    assert!(stored.is_empty());
}

#[tokio::test]
async fn the_rules_are_listed_a_page_at_a_time() {
    let (harness, token, user) = filter_harness(9).await;
    for pattern in ["a", "b", "c"] {
        store_rule(
            &harness.store,
            &user,
            "allow",
            "subject",
            "contains",
            pattern,
        )
        .await;
    }
    let page = |arguments: Value| harness.call_ok(&token, "list_webhook_filters", arguments);
    let first = page(json!({ "limit": 2 })).await;
    assert_eq!(listed(&first, "pattern"), ["a", "b"]);
    assert_eq!(first["next_offset"], 2);
    let last = page(json!({ "offset": 2 })).await;
    assert_eq!(listed(&last, "pattern"), ["c"]);
    assert_eq!(
        (&last["offset"], last.get("next_offset")),
        (&json!(2), None)
    );
    let one = page(json!({ "limit": 0 })).await;
    assert_eq!(listed(&one, "pattern"), ["a"]);
    assert_eq!(one["filter_rules_active"], 3);
}

/// A rule with a name this server does not know is listed as written; one it
/// can't decrypt is not. Either way an add is refused and a removal works.
#[tokio::test]
async fn filter_rules_that_cannot_be_read_can_still_be_removed() {
    let (harness, token, user) = filter_harness(9).await;
    store_rule(&harness.store, &user, "allow", "body", "contains", "x").await;
    let list = harness
        .call_ok(&token, "list_webhook_filters", json!({}))
        .await;
    assert_eq!(listed(&list, "field"), ["body"]);
    assert_eq!(list["filter_rules_unreadable"], true);
    let add = || harness.call(&token, "add_webhook_filter", subject_rule("y"));
    assert_eq!(error_text(&add().await), UNKNOWN_RULES);

    let garble = "UPDATE webhook_filter_rules SET pattern_ciphertext = 'bad'";
    sqlx::query(garble)
        .execute(harness.store.pool())
        .await
        .unwrap();
    let list = harness
        .call(&token, "list_webhook_filters", json!({}))
        .await;
    assert_eq!(error_text(&list), UNDECRYPTABLE_RULES);
    assert_eq!(error_text(&add().await), UNDECRYPTABLE_RULES);
    let all = json!({ "all": true });
    let removed = harness.call_ok(&token, "remove_webhook_filter", all).await;
    assert_eq!(removed["removed"], 1);
    let status = harness
        .call_ok(&token, "get_webhook_status", json!({}))
        .await;
    let readable = (&status["state"], &status["filter_rules_unreadable"]);
    assert_eq!(readable, (&json!("active"), &json!(false)));
}

/// Each token reaches only its own mailbox's rules, and a mailbox without a
/// webhook has none.
#[tokio::test]
async fn filter_tools_are_scoped_to_the_signed_in_account() {
    let (harness, user_token, user) = filter_harness(9).await;
    let alice_token = harness
        .sign_in("alice@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    harness.until_watchers_stop().await;
    let alice = harness
        .store
        .account_by_email("alice@example.com", Provider::Imap);
    let alice = alice.await.unwrap().unwrap().id;
    let hook = settings("https://hooks.example.com/alice", ALICE_SECRET, ALICE_AUTH);
    harness.store.save_webhook(&alice, &hook).await.unwrap();
    let added = harness
        .call_ok(&user_token, "add_webhook_filter", subject_rule("mine"))
        .await;
    let list = harness
        .call_ok(&alice_token, "list_webhook_filters", json!({}))
        .await;
    assert_eq!(list["filters"], json!([]));
    let theirs = json!({ "id": added["id"] });
    let removed = harness
        .call_ok(&alice_token, "remove_webhook_filter", theirs)
        .await;
    assert_eq!(removed["removed"], 0);
    assert_eq!(
        harness
            .store
            .webhook_filter_rules(&user, 9)
            .await
            .unwrap()
            .len(),
        1
    );

    let bob = harness
        .sign_in("bob@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    let missing = "No webhook is saved for this account. Set it up on the account page (/account).";
    for (tool, arguments) in [
        ("list_webhook_filters", json!({})),
        ("add_webhook_filter", subject_rule("x")),
        ("remove_webhook_filter", json!({ "all": true })),
    ] {
        let result = harness.call(&bob, tool, arguments).await;
        assert_eq!(error_text(&result), missing, "{tool}");
    }
}

/// On a multi-thread runtime the rules are checked off the async workers.
#[tokio::test(flavor = "multi_thread")]
async fn an_add_works_on_a_multi_thread_runtime() {
    let (harness, token, _) = filter_harness(9).await;
    let added = harness
        .call_ok(&token, "add_webhook_filter", subject_rule("x"))
        .await;
    assert_eq!(added["filter_rules_active"], 1);
    let status = harness
        .call_ok(&token, "get_webhook_status", json!({}))
        .await;
    assert_eq!(status["state"], "active", "{status}");
}

/// Rules that decrypt and parse but don't compile make the status
/// `rules_unreadable`, and its message names the oldest rule that doesn't
/// compile with the ones before it. Rules that compile show as before.
#[tokio::test]
async fn filter_rules_that_do_not_compile_show_in_the_status() {
    let (harness, token, user) = filter_harness(9).await;
    let store = &harness.store;
    store_rule(store, &user, "block", "from", "equals", "news@example.com").await;
    store_rule(store, &user, "allow", "subject", "regex", "(?=x)").await;
    let ids = async || {
        let rules = store.webhook_filter_rules(&user, 9).await.unwrap();
        rules.into_iter().map(|rule| rule.id).collect::<Vec<_>>()
    };
    let status = async || {
        harness
            .call_ok(&token, "get_webhook_status", json!({}))
            .await
    };
    let alone = ids().await[1].clone();
    let held = status().await;
    assert_eq!(held["state"], "rules_unreadable", "{held}");
    assert_eq!(held["filter_rules_unreadable"], true);
    assert_eq!(held["filter_rules_active"], 2);
    assert_eq!(
        held["message"],
        format!(
            "Filter rule {alone} doesn't compile on this server, so this mailbox's new mail waits. Remove it with remove_webhook_filter, or turn it off on the account page (/account)."
        )
    );
    let list = harness
        .call_ok(&token, "list_webhook_filters", json!({}))
        .await;
    assert_eq!(list["filter_rules_unreadable"], true);
    assert_eq!(listed(&list, "active"), [true, true]);

    let remove = |id: &str| harness.call_ok(&token, "remove_webhook_filter", json!({ "id": id }));
    assert_eq!(remove(&alone).await["removed"], 1);
    for i in 0..4 {
        let pattern = format!(r"\w{{24}}-{i}");
        store_rule(store, &user, "allow", "subject", "regex", &pattern).await;
    }
    let tips = ids().await[4].clone();
    let held = status().await;
    assert_eq!(held["state"], "rules_unreadable", "{held}");
    assert_eq!(
        held["message"],
        format!(
            "Filter rule {tips} doesn't fit with the older rules that are on: together they're too large to compile, so this mailbox's new mail waits. Remove it with remove_webhook_filter, or turn it off on the account page (/account)."
        )
    );
    assert_eq!(remove(&tips).await["removed"], 1);
    let readable = status().await;
    let shown = (
        &readable["state"],
        &readable["filter_rules_unreadable"],
        &readable["message"],
    );
    assert_eq!(shown, (&json!("active"), &json!(false), &Value::Null));
}

/// A watcher that rules it can't read stopped starts again once a tool removes
/// them, or adds a rule after they were removed elsewhere, and records the mail
/// it held. A change that changes nothing restarts nothing.
#[tokio::test]
async fn a_filter_change_starts_a_watcher_stopped_by_its_rules_again() {
    let (accepted, inbox) = (Arc::<AtomicUsize>::default(), Arc::new(AtomicU32::new(3)));
    let login = Arc::new(AtomicU8::new(ACCEPT));
    let mail = scripted_mail(login, Arc::clone(&accepted), Some(Arc::clone(&inbox))).await;
    let harness = webhook_harness_for(mail, |watch, _| {
        (watch.poll_interval, watch.debounce) =
            (Duration::from_millis(20), Duration::from_millis(20));
        // A session that fails waits an hour, so the test fails instead.
        (watch.min_backoff, watch.max_backoff) = (Duration::from_hours(1), Duration::from_hours(1));
    })
    .await;
    let token = harness
        .sign_in("user@example.com", "abcd-efgh-ijkl-mnop")
        .await;
    harness.until_watchers_stop().await;
    let watchers = harness.watchers.as_ref().unwrap();
    let user = harness
        .store
        .account_by_email("user@example.com", Provider::Imap);
    let user = user.await.unwrap().unwrap().id;
    let url = harness.receiver.as_ref().unwrap().url("/mail");
    let store = &harness.store;
    store
        .save_webhook(&user, &settings(&url, USER_SECRET, USER_AUTH))
        .await
        .unwrap();
    let cursor = WatchCursor {
        uid_validity: 1,
        last_uid: 1,
    };
    store.set_watch_cursor(&user, cursor).await.unwrap();
    store_rule(store, &user, "allow", "body", "contains", "x").await;
    watchers.refresh(&user);
    // The last event's sequence and the last UID the cursor passed.
    let recorded = async || {
        let hook = store.webhook(&user).await.unwrap().unwrap();
        (hook.last_sequence, hook.cursor.unwrap().last_uid)
    };
    let state = async || {
        let status = harness
            .call_ok(&token, "get_webhook_status", json!({}))
            .await;
        status["state"].as_str().unwrap().to_owned()
    };
    let logins = || accepted.load(SeqCst);

    // The rule stops the drain: nothing is recorded or skipped.
    until(async || logins() == 1 && watchers.running() == 0).await;
    assert_eq!(recorded().await, (0, 1));
    assert_eq!(state().await, "rules_unreadable");

    // Removing it starts the watcher again, which records UID 2.
    let all = json!({ "all": true });
    let removed = harness.call_ok(&token, "remove_webhook_filter", all).await;
    assert_eq!(removed["removed"], 1);
    until(async || logins() == 2 && recorded().await == (1, 2)).await;
    assert_eq!(watchers.running(), 1);
    assert_eq!(state().await, "active");

    // A rule stored elsewhere stops the polling watcher at UID 3; removing it
    // there restarts nothing.
    store_rule(store, &user, "allow", "body", "contains", "x").await;
    inbox.store(4, SeqCst);
    until(async || watchers.running() == 0).await;
    assert_eq!(recorded().await, (1, 2));
    store.remove_webhook_filter_rules(&user).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((logins(), watchers.running()), (2, 0));

    // An add starts it again, and UID 3 is recorded.
    let block = json!({ "action": "block", "field": "subject", "kind": "equals", "pattern": "nothing has this subject" });
    harness.call_ok(&token, "add_webhook_filter", block).await;
    until(async || logins() == 3 && recorded().await == (2, 3)).await;
    assert_eq!(watchers.running(), 1);

    // A removal of nothing and a refused add restart nothing.
    let unknown = json!({ "id": "no-such-rule" });
    let removed = harness
        .call_ok(&token, "remove_webhook_filter", unknown)
        .await;
    assert_eq!(removed["removed"], 0);
    let domain = json!({ "action": "allow", "field": "subject", "kind": "domain", "pattern": "example.com" });
    assert_eq!(
        harness.call(&token, "add_webhook_filter", domain).await["isError"],
        true
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!((logins(), watchers.running()), (3, 1));
    // Consecutive arrivals are fetched as one UID range and recorded in one event.
    inbox.store(6, SeqCst);
    until(async || recorded().await == (3, 5)).await;
    watchers.shutdown(Duration::from_secs(2)).await;
}

/// The text in the first column of `query`'s first row, or `""`.
async fn sqlite_text(db: &std::path::Path, query: &'static str, account_id: &str) -> String {
    use sqlx::Connection as _;
    let options = sqlx::sqlite::SqliteConnectOptions::new().filename(db);
    let mut conn = sqlx::SqliteConnection::connect_with(&options)
        .await
        .unwrap();
    let value: Option<Option<String>> = sqlx::query_scalar(query)
        .bind(account_id)
        .fetch_optional(&mut conn)
        .await
        .unwrap();
    conn.close().await.unwrap();
    value.flatten().unwrap_or_default()
}

/// Replaces the signing secret and the header value of an account's webhook
/// with v1 values sealed under `key`, whatever format the writers use.
async fn seal_webhook_secrets(
    store: &Store,
    key: &[u8; 32],
    account: &str,
    signing_secret: &str,
    header_value: &str,
) {
    let signing = seal_v1(key, &format!("webhook/secret/{account}"), signing_secret);
    let header = seal_v1(key, &format!("webhook/auth/{account}"), header_value);
    let replaced = sqlx::query(
        "UPDATE webhooks SET signing_secret_ciphertext = $1, auth_header_value_ciphertext = $2 \
         WHERE account_id = $3",
    )
    .bind(signing)
    .bind(header)
    .bind(account)
    .execute(store.pool())
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(replaced, 1);
}

/// A v1 value: `v1.` and the base64url, without padding, of a nonce and the
/// AES-256-GCM ciphertext under the master key `key`, with `context` as
/// associated data.
fn seal_v1(key: &[u8; 32], context: &str, plaintext: &str) -> String {
    use ring::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
    use ring::rand::{SecureRandom, SystemRandom};
    let mut nonce = [0_u8; NONCE_LEN];
    SystemRandom::new().fill(&mut nonce).unwrap();
    let sealing = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let mut blob = plaintext.as_bytes().to_vec();
    let aad = Aad::from(context.as_bytes());
    let nonce_to_use = Nonce::assume_unique_for_key(nonce);
    sealing
        .seal_in_place_append_tag(nonce_to_use, aad, &mut blob)
        .unwrap();
    format!(
        "v1.{}",
        URL_SAFE_NO_PAD.encode([nonce.as_slice(), blob.as_slice()].concat())
    )
}

fn assert_no_webhook_leak(body: &str, parts: &[&str]) {
    for part in parts {
        assert!(!part.is_empty(), "refusing to check an empty secret");
        assert!(!body.contains(part), "{part} leaked: {body}");
    }
    assert!(!body.contains("x-sentinel-name"), "{body}");
}
