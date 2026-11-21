//! An embedding's tool extension and usage hook: the extension's tools are
//! listed after the server's to the callers it picks and get the mailbox a
//! call names, its paragraph ends the instructions, and its check runs
//! before every tool call, ahead of the usage hook, which also decides
//! whether a message is sent, can lower a mailbox's outbox ceilings and hears
//! how each call it allowed ended.
//! Runs in process on SQLite, without network access: the mailboxes use an
//! IMAP preset this server no longer offers, so a server tool that ran
//! fails with a recognisable error.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

mod bucket;
mod imap;

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions};
use postkeep::tools::{ExtensionCall, ToolExtension, ToolFuture};
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, BearerRequest, CallEnd, CeilingsFuture, CheckFuture,
    CredentialVerifier, HoldFuture, Outbox, OutboxCeilings, PrincipalResolver, Refusal, Resolution,
    ResolveFuture, Sending, ToolCall, UsageHook, VerifyFuture,
};
use postkeep_mail::{ImapServer, ImapServers};
use postkeep_store::{AccountId, MasterKey, OutboxLimitChange, Store, WebhookSettings};
use rmcp::ErrorData;
use rmcp::model::{CallToolResult, JsonObject, Tool, ToolAnnotations};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use imap::{ACCEPT, scripted_mail};

const HOST: &str = "mail.example.com";
const UNKNOWN: &str = "unknown mailbox: pass the id or address of a mailbox this connection can \
use, or leave mailbox out to use the default one";
/// What a server tool that opened a mailbox fails with.
const OPENED: &str = "this account's mail provider is no longer offered by this server";
const PARAGRAPH: &str = "Account tools: get_account reports the plan.";
const OVER_LIMIT: &str = "this workspace made too many calls this minute; reading still works";
const NO_SENDS_LEFT: &str = "a@example.com sent all the messages its plan allows today";
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

/// `workspace-key` may use A (the default) and B; `other-key` only A;
/// `search-key` only D, on a scripted mail server.
struct Keys {
    a: AccountId,
    b: AccountId,
    d: AccountId,
}

impl PrincipalResolver for Keys {
    fn resolve<'a>(
        &'a self,
        _state: &'a AuthState,
        token: &'a str,
        _request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let caller = |principal: &str| {
                Authenticated::for_account(self.a.clone(), "agent".to_owned(), "mail".to_owned())
                    .with_tenant("tenant-a")
                    .with_principal(principal)
            };
            Ok(match token {
                "workspace-key" => {
                    Resolution::Authenticated(caller("key:1").with_mailboxes([self.b.clone()]))
                }
                "other-key" => Resolution::Authenticated(caller("other")),
                "other-app" => {
                    let mut caller = caller("key:1");
                    "another-app".clone_into(&mut caller.client_id);
                    Resolution::Authenticated(caller)
                }
                "search-key" => Resolution::Authenticated(
                    Authenticated::for_account(
                        self.d.clone(),
                        "agent".to_owned(),
                        "mail".to_owned(),
                    )
                    .with_tenant("tenant-a"),
                ),
                _ => Resolution::Refused("unknown key"),
            })
        })
    }

    fn selects_mailboxes(&self) -> bool {
        true
    }
}

/// Lists two account tools to `key:1`, plus one named like a server tool,
/// and records every check and call.
#[derive(Default)]
struct AccountTools {
    log: Mutex<Vec<String>>,
}

impl AccountTools {
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.lock().unwrap())
    }

    fn record(
        &self,
        kind: &str,
        name: &str,
        mailbox: Option<&AccountId>,
        arguments: Option<&JsonObject>,
    ) {
        let mut keys: Vec<&str> = arguments
            .map(|arguments| arguments.keys().map(String::as_str).collect())
            .unwrap_or_default();
        keys.sort_unstable();
        let mailbox = mailbox.map_or("-", |mailbox| mailbox.0.as_str());
        self.push(format!("{kind} {name} {mailbox} [{}]", keys.join(",")));
    }

    fn push(&self, entry: String) {
        self.log.lock().unwrap().push(entry);
    }
}

fn tool(name: &'static str, schema: Value, read_only: bool) -> Tool {
    let Value::Object(schema) = schema else {
        panic!("a schema is an object");
    };
    Tool::new(name, "An account tool.", Arc::new(schema))
        .annotate(ToolAnnotations::new().read_only(read_only))
}

impl ToolExtension for AccountTools {
    fn tools(&self, caller: &Authenticated) -> Vec<Tool> {
        if caller.principal != "key:1" {
            return Vec::new();
        }
        vec![
            tool("get_account", json!({ "type": "object" }), true),
            tool(
                "disconnect_mailbox",
                json!({
                    "type": "object",
                    "properties": {
                        "mailbox": { "type": "string", "description": "The mailbox to disconnect." }
                    },
                    "required": ["mailbox"]
                }),
                false,
            ),
            tool("list_folders", json!({ "type": "object" }), false),
        ]
    }

    /// Answers after `wait` milliseconds, panics with `panic` and fails
    /// with `fail`.
    fn call<'a>(&'a self, call: ExtensionCall<'a>) -> ToolFuture<'a> {
        self.record("call", call.name, call.mailbox, call.arguments.as_ref());
        let result = CallToolResult::structured(json!({
            "tool": call.name,
            "mailbox": call.mailbox.map(|mailbox| mailbox.0.clone()),
        }));
        let argument = |name| call.arguments.as_ref()?.get(name).cloned();
        let (wait, panics, fails) = (argument("wait"), argument("panic"), argument("fail"));
        Box::pin(async move {
            let wait = wait.and_then(|wait| wait.as_u64()).unwrap_or(0);
            tokio::time::sleep(Duration::from_millis(wait)).await;
            assert!(panics.is_none(), "a tool that panics");
            match fails {
                Some(_) => Err(ErrorData::internal_error("the tool failed", None)),
                None => Ok(result),
            }
        })
    }

    fn instructions(&self) -> Option<String> {
        Some(PARAGRAPH.to_owned())
    }

    fn check<'a>(&'a self, call: ToolCall<'a>) -> CheckFuture<'a> {
        let kind = if call.read_only { "read" } else { "write" };
        self.record(kind, call.name, call.mailbox, call.arguments);
        let verdict = match call.name {
            "delete_message" => Err(Refusal::new(
                "deleting mail is turned off for this workspace",
            )),
            "disconnect_mailbox" if call.mailbox.is_none() => {
                Err(Refusal::new("name the mailbox to disconnect"))
            }
            _ => Ok(()),
        };
        Box::pin(std::future::ready(verdict))
    }
}

/// Writes the calls and messages it is asked about to the extension's log,
/// and the ends of calls to its own. Over the limit, it lets only reads go
/// ahead; it never lets A send, and gives A's outbox lower ceilings.
struct Usage {
    log: Arc<AccountTools>,
    ends: Mutex<Vec<String>>,
    a: AccountId,
    over_limit: AtomicBool,
    holds: AtomicBool,
    held_files: Mutex<Option<Value>>,
}

impl Usage {
    fn ends(&self) -> Vec<String> {
        std::mem::take(&mut *self.ends.lock().unwrap())
    }
}

impl UsageHook for Usage {
    fn before_call<'a>(&'a self, call: ToolCall<'a>) -> CheckFuture<'a> {
        self.log
            .record("usage", call.name, call.mailbox, call.arguments);
        let verdict = if self.over_limit.load(Ordering::SeqCst) && !call.read_only {
            Err(Refusal::new(OVER_LIMIT))
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(verdict))
    }

    fn holds<'a>(&'a self, call: ToolCall<'a>) -> HoldFuture<'a> {
        let holds = self.holds.load(Ordering::SeqCst);
        if holds {
            *self.held_files.lock().unwrap() = call
                .arguments
                .and_then(|args| args.get("attachments"))
                .cloned();
            assert!(
                call.arguments
                    .is_some_and(|args| !args.contains_key("hold_id"))
            );
            self.log.push(format!(
                "holds {} {} {}",
                call.name,
                call.caller.principal,
                call.mailbox.unwrap_or(&call.caller.account_id).0
            ));
        }
        Box::pin(std::future::ready(holds))
    }

    fn before_send<'a>(&'a self, sending: Sending<'a>) -> CheckFuture<'a> {
        let kind = sending.tool;
        let (caller, mailbox) = (&sending.caller.principal, &sending.mailbox.0);
        self.log.push(format!("{kind} {caller} {mailbox}"));
        let verdict = if *sending.mailbox == self.a {
            Err(Refusal::new(NO_SENDS_LEFT))
        } else {
            Ok(())
        };
        Box::pin(std::future::ready(verdict))
    }

    fn after_call(&self, call: ToolCall<'_>, end: CallEnd) {
        let found = end
            .found
            .map_or_else(String::new, |found| format!(" {found}"));
        let held = if end.held { " held" } else { "" };
        let entry = format!("{} {:?}{found}{held}", call.name, end.outcome);
        self.ends.lock().unwrap().push(entry);
    }

    fn outbox_ceilings<'a>(&'a self, outbox: Outbox<'a>) -> CeilingsFuture<'a> {
        let smaller = outbox.tenant == "tenant-a" && *outbox.mailbox == self.a;
        let ceilings = smaller.then(|| OutboxCeilings::new(14 * DAY, 2_000));
        Box::pin(std::future::ready(ceilings))
    }
}

struct Harness {
    extended: Router,
    plain: Router,
    /// With the usage hook and no extension.
    limited: Router,
    /// With the extension and the usage hook.
    both: Router,
    tools: Arc<AccountTools>,
    usage: Arc<Usage>,
    store: Store,
    a: AccountId,
    b: AccountId,
    /// The stand-in bucket the routers put uploads in, and its server.
    uploads: bucket::StandIn,
    _bucket: wiremock::MockServer,
    _dir: tempfile::TempDir,
}

async fn harness() -> Harness {
    harness_with_smtp(None).await
}

async fn harness_with_smtp(smtp: Option<u16>) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let tenant = store.for_tenant("tenant-a");
    let password = SecretString::from("app-password".to_owned());
    let mut ids = Vec::new();
    for email in ["a@example.com", "b@example.com", "c@example.com"] {
        let account = tenant
            .upsert_imap_account(email, &password, Some("retired"))
            .await
            .unwrap();
        ids.push(account.id);
    }
    let d = tenant.upsert_imap_account("d@example.com", &password, None);
    let d = d.await.unwrap().id;
    let (a, b) = (ids[0].clone(), ids[1].clone());
    let mut mail = scripted_mail(Arc::new(AtomicU8::new(ACCEPT)), Arc::default(), None).await;
    if let Some(port) = smtp {
        mail.smtp.port = port;
    }
    let bucket_server = wiremock::MockServer::start().await;
    let (uploads, bucket) = bucket::stand_in(&bucket_server).await;
    let bucket: Arc<dyn postkeep::bucket::Bucket> = Arc::new(bucket);
    let tools = Arc::new(AccountTools::default());
    let usage = Arc::new(Usage {
        log: tools.clone(),
        ends: Mutex::default(),
        a: a.clone(),
        over_limit: AtomicBool::new(false),
        holds: AtomicBool::new(false),
        held_files: Mutex::default(),
    });
    let build = |extension: Option<Arc<AccountTools>>, usage: Option<Arc<Usage>>| {
        let mut auth = AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap();
        auth.imap_servers = ImapServers::custom_only("Scripted", mail.clone());
        let config = AppConfig {
            bucket: Some(bucket.clone()),
            auth,
            extra_allowed_hosts: Vec::new(),
            extra_allowed_origins: Vec::new(),
            limits: app::RequestLimits::default(),
            pool: postkeep::pool::PoolConfig::default(),
            watchers: None,
            upstream: None,
            google_push: None,
        };
        let resolver = Arc::new(Keys {
            a: a.clone(),
            b: b.clone(),
            d: d.clone(),
        });
        let mut extensions = Extensions::new().principal_resolver(resolver);
        if let Some(extension) = extension {
            extensions = extensions.tool_extension(extension);
        }
        if let Some(usage) = usage {
            extensions = extensions.usage_hook(usage);
        }
        app::router_with(
            config,
            store.clone(),
            AcceptAll,
            CancellationToken::new(),
            extensions,
        )
    };
    Harness {
        extended: build(Some(tools.clone()), None),
        plain: build(None, None),
        limited: build(None, Some(usage.clone())),
        both: build(Some(tools.clone()), Some(usage.clone())),
        tools,
        usage,
        store,
        a,
        b,
        uploads,
        _bucket: bucket_server,
        _dir: dir,
    }
}

/// A new upload of `token`'s caller holding `file`: its id.
async fn upload(app: &Router, token: &str, file: &[u8]) -> String {
    let made = call(app, token, "upload_attachment", json!({}))
        .await
        .unwrap();
    let request = Request::put("/upload")
        .header(header::HOST, HOST)
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", made["token"].as_str().unwrap()),
        )
        .body(Body::from(file.to_vec()))
        .unwrap();
    let put = app.clone().oneshot(request).await.unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);
    made["upload_id"].as_str().unwrap().to_owned()
}

fn rpc_request(token: &str, method: &str, params: &Value, protocol: &str) -> Request<Body> {
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    Request::post(app::MCP_PATH)
        .header(header::HOST, HOST)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", protocol)
        .header("mcp-method", method)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn rpc_at(app: &Router, token: &str, method: &str, params: Value, protocol: &str) -> Value {
    let request = rpc_request(token, method, &params, protocol);
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert_eq!(status, StatusCode::OK, "{method}: {text}");
    serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("{method}: not JSON: {text}"))
}

async fn rpc(app: &Router, token: &str, method: &str, params: Value) -> Value {
    rpc_at(app, token, method, params, "2025-06-18").await
}

/// Calls `tool` and returns `Ok` with the structured output, or `Err` with
/// the error text.
async fn call(app: &Router, token: &str, tool: &str, arguments: Value) -> Result<Value, String> {
    let reply = rpc(
        app,
        token,
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
    )
    .await;
    let result = &reply["result"];
    assert!(result.is_object(), "{tool}: {reply}");
    if result["isError"] == true {
        Err(result["content"][0]["text"].as_str().unwrap().to_owned())
    } else {
        Ok(result["structuredContent"].clone())
    }
}

async fn listed(app: &Router, token: &str) -> Vec<Value> {
    let reply = rpc(app, token, "tools/list", json!({})).await;
    reply["result"]["tools"].as_array().unwrap().clone()
}

/// The `cacheScope` of a `tools/list` answer under the 2026-07-28 protocol.
async fn cache_scope(app: &Router) -> Value {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let params = json!({ "_meta": meta });
    let reply = rpc_at(app, "workspace-key", "tools/list", params, "2026-07-28").await;
    reply["result"]["cacheScope"].clone()
}

async fn instructions(app: &Router) -> String {
    let params = json!({
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": { "name": "test", "version": "1" }
    });
    let reply = rpc(app, "workspace-key", "initialize", params).await;
    reply["result"]["instructions"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn the_extension_lists_its_tools_to_the_callers_it_picks() {
    let h = harness().await;
    let plain = listed(&h.plain, "workspace-key").await;
    assert_eq!(plain.len(), 18);
    let extended = listed(&h.extended, "workspace-key").await;
    assert_eq!(extended.len(), 20, "list_folders stays the server's");
    assert_eq!(&extended[..18], &plain[..]);
    assert_eq!(extended[18]["name"], "get_account");
    assert_eq!(
        extended[18]["inputSchema"]["properties"]["mailbox"],
        json!({
            "description": "Mailbox to use: its id or email address. Omit it to use the default mailbox.",
            "type": "string"
        })
    );
    assert_eq!(extended[18]["annotations"]["readOnlyHint"], true);
    assert_eq!(extended[19]["name"], "disconnect_mailbox");
    assert_eq!(
        extended[19]["inputSchema"]["properties"]["mailbox"],
        json!({ "type": "string", "description": "The mailbox to disconnect." })
    );
    assert_eq!(extended[19]["inputSchema"]["required"], json!(["mailbox"]));
    assert_eq!(listed(&h.extended, "other-key").await, plain);

    assert_eq!(cache_scope(&h.plain).await, "public");
    assert_eq!(cache_scope(&h.extended).await, "private");

    let plain = instructions(&h.plain).await;
    assert_eq!(
        instructions(&h.extended).await,
        format!("{plain}\n\n{PARAGRAPH}")
    );
    assert_eq!(h.tools.take(), Vec::<String>::new());
}

#[tokio::test]
async fn extension_tools_get_the_mailbox_the_call_names() {
    let h = harness().await;
    let key = "workspace-key";
    let b = &h.b.0;
    assert_eq!(
        call(&h.extended, key, "get_account", json!({})).await,
        Ok(json!({ "tool": "get_account", "mailbox": null }))
    );
    assert_eq!(
        h.tools.take(),
        ["read get_account - []", "call get_account - []"]
    );

    let arguments = json!({ "mailbox": "B@example.com", "confirm": true });
    assert_eq!(
        call(&h.extended, key, "disconnect_mailbox", arguments).await,
        Ok(json!({ "tool": "disconnect_mailbox", "mailbox": b }))
    );
    assert_eq!(
        h.tools.take(),
        [
            format!("write disconnect_mailbox {b} [confirm]"),
            format!("call disconnect_mailbox {b} [confirm]"),
        ]
    );

    assert_eq!(
        call(&h.extended, key, "disconnect_mailbox", json!({})).await,
        Err("name the mailbox to disconnect".to_owned())
    );
    assert_eq!(h.tools.take(), ["write disconnect_mailbox - []"]);

    let arguments = json!({ "mailbox": "c@example.com" });
    assert_eq!(
        call(&h.extended, key, "get_account", arguments).await,
        Err(UNKNOWN.to_owned())
    );
    assert_eq!(h.tools.take(), Vec::<String>::new());

    let params = json!({ "name": "get_account", "arguments": {} });
    let reply = rpc(&h.extended, "other-key", "tools/call", params).await;
    assert_eq!(reply["error"]["message"], "tool not found", "{reply}");
    assert_eq!(h.tools.take(), Vec::<String>::new());

    let error = call(&h.extended, key, "list_folders", json!({}))
        .await
        .unwrap_err();
    assert!(error.starts_with(OPENED), "the server's tool ran: {error}");
    assert_eq!(h.tools.take(), ["read list_folders - []"]);
}

/// Every server tool but `delete_message`, with arguments, and whether it
/// only reads.
fn server_tools() -> Vec<(&'static str, Value, bool)> {
    vec![
        ("list_folders", json!({}), true),
        ("search_messages", json!({}), true),
        ("get_message", json!({ "id": "m1" }), true),
        (
            "download_attachment",
            json!({ "id": "m1", "attachment_id": "1" }),
            true,
        ),
        (
            "send_message",
            json!({ "to": ["x@example.com"], "subject": "s", "body": "b" }),
            false,
        ),
        (
            "reply_to_message",
            json!({ "id": "m1", "body": "b" }),
            false,
        ),
        (
            "create_draft",
            json!({ "to": ["x@example.com"], "subject": "s", "body": "b" }),
            false,
        ),
        ("update_flags", json!({ "id": "m1", "read": true }), false),
        (
            "move_message",
            json!({ "id": "m1", "destination": "Archive" }),
            false,
        ),
        ("create_folder", json!({ "name": "Projects" }), false),
        ("get_webhook_status", json!({}), true),
        ("set_webhook_enabled", json!({ "enabled": false }), false),
        (
            "set_webhook_outbox_limits",
            json!({ "max_events": 50 }),
            false,
        ),
        ("list_webhook_filters", json!({}), true),
        (
            "add_webhook_filter",
            json!({ "action": "allow", "field": "subject", "kind": "contains", "pattern": "x" }),
            false,
        ),
        ("remove_webhook_filter", json!({ "all": true }), false),
    ]
}

#[tokio::test]
async fn the_check_runs_before_every_server_tool() {
    let h = harness().await;
    let key = "workspace-key";
    for (tool, arguments, read_only) in server_tools() {
        let mut keys: Vec<String> = arguments.as_object().unwrap().keys().cloned().collect();
        keys.sort_unstable();
        let mut named = arguments;
        named["mailbox"] = json!("b@example.com");
        let result = call(&h.extended, key, tool, named.clone()).await;
        assert_eq!(
            result,
            call(&h.plain, key, tool, named).await,
            "{tool} ran as it does without the extension"
        );
        let kind = if read_only { "read" } else { "write" };
        assert_eq!(
            h.tools.take(),
            [format!("{kind} {tool} {} [{}]", h.b.0, keys.join(","))],
            "{tool}"
        );
    }

    assert_eq!(
        call(&h.extended, key, "delete_message", json!({ "id": "m1" })).await,
        Err("deleting mail is turned off for this workspace".to_owned())
    );
    assert_eq!(h.tools.take(), ["write delete_message - [id]"]);
    let error = call(&h.plain, key, "delete_message", json!({ "id": "m1" }))
        .await
        .unwrap_err();
    assert!(error.starts_with(OPENED), "{error}");

    let arguments = json!({ "mailbox": "c@example.com" });
    assert_eq!(
        call(&h.extended, key, "list_folders", arguments).await,
        Err(UNKNOWN.to_owned())
    );
    assert_eq!(h.tools.take(), Vec::<String>::new());
}

#[tokio::test]
async fn an_extension_that_does_not_word_a_rejected_password_keeps_the_servers_message() {
    let h = harness().await;
    h.store.mark_password_rejected(&h.b).await.unwrap();
    let (key, named) = ("workspace-key", json!({ "mailbox": "b@example.com" }));
    let status = |app, named| call(app, key, "get_webhook_status", named);
    let plain = status(&h.plain, named.clone()).await.unwrap();
    assert_eq!(plain["state"], "needs_password");
    assert_eq!(status(&h.extended, named).await.unwrap(), plain);
}

#[tokio::test]
async fn the_usage_hook_runs_before_every_tool_call() {
    let h = harness().await;
    let key = "workspace-key";
    let b = &h.b.0;
    assert_eq!(listed(&h.limited, key).await, listed(&h.plain, key).await);
    assert_eq!(cache_scope(&h.limited).await, "public");
    let delete = ("delete_message", json!({ "id": "m1" }), false);
    for (tool, arguments, _) in server_tools().into_iter().chain([delete]) {
        let mut keys: Vec<String> = arguments.as_object().unwrap().keys().cloned().collect();
        keys.sort_unstable();
        let mut named = arguments;
        named["mailbox"] = json!("b@example.com");
        let result = call(&h.limited, key, tool, named.clone()).await;
        let end = if result.is_ok() { "Done" } else { "Failed" };
        assert_eq!(h.usage.ends(), [format!("{tool} {end}")]);
        assert_eq!(
            result,
            call(&h.plain, key, tool, named).await,
            "{tool} ran as it does without the hook"
        );
        let mut asked = vec![format!("usage {tool} {b} [{}]", keys.join(","))];
        match tool {
            "send_message" => asked.push(format!("send_message key:1 {b}")),
            "reply_to_message" => asked.push(format!("reply_to_message key:1 {b}")),
            _ => {}
        }
        assert_eq!(h.tools.take(), asked, "{tool}");
    }

    let arguments = json!({ "mailbox": "c@example.com" });
    assert_eq!(
        call(&h.limited, key, "list_folders", arguments).await,
        Err(UNKNOWN.to_owned())
    );
    assert_eq!(h.tools.take(), Vec::<String>::new());
    assert_eq!(h.usage.ends(), Vec::<String>::new());
}

#[tokio::test]
async fn the_usage_hook_can_refuse_calls_and_messages() {
    let h = harness().await;
    let key = "workspace-key";
    let a = &h.a.0;
    let message = json!({ "to": ["x@example.com"], "subject": "s", "body": "b" });
    assert_eq!(
        call(&h.limited, key, "send_message", message.clone()).await,
        Err(NO_SENDS_LEFT.to_owned())
    );
    assert_eq!(
        h.tools.take(),
        [
            "usage send_message - [body,subject,to]".to_owned(),
            format!("send_message key:1 {a}"),
        ]
    );
    assert_eq!(h.usage.ends(), ["send_message Refused"]);
    let reply = json!({ "id": "m1", "body": "b" });
    assert_eq!(
        call(&h.limited, key, "reply_to_message", reply).await,
        Err(NO_SENDS_LEFT.to_owned())
    );
    assert_eq!(
        h.tools.take(),
        [
            "usage reply_to_message - [body,id]".to_owned(),
            format!("reply_to_message key:1 {a}"),
        ]
    );
    assert_eq!(h.usage.ends(), ["reply_to_message Refused"]);
    let invalid = json!({ "to": ["nobody"], "subject": "s", "body": "b" });
    assert_eq!(
        call(&h.limited, key, "send_message", invalid).await,
        Err("to: \"nobody\" is not a valid email address".to_owned())
    );
    assert_eq!(h.tools.take(), ["usage send_message - [body,subject,to]"]);
    assert_eq!(h.usage.ends(), ["send_message Failed"]);

    h.usage.over_limit.store(true, Ordering::SeqCst);
    assert_eq!(
        call(&h.limited, key, "send_message", message).await,
        Err(OVER_LIMIT.to_owned())
    );
    assert_eq!(h.tools.take(), ["usage send_message - [body,subject,to]"]);
    assert_eq!(h.usage.ends(), Vec::<String>::new(), "a refused call");
    let error = call(&h.limited, key, "list_folders", json!({}))
        .await
        .unwrap_err();
    assert!(error.starts_with(OPENED), "reading still works: {error}");
    assert_eq!(h.tools.take(), ["usage list_folders - []"]);
    assert_eq!(h.usage.ends(), ["list_folders Failed"]);
}

/// One loopback SMTP submission, returning the exact bytes it accepted.
async fn receive_smtp(listener: TcpListener) -> String {
    let (stream, _) = listener.accept().await.unwrap();
    let (read, mut write) = stream.into_split();
    write.write_all(b"220 test ready\r\n").await.unwrap();
    let mut lines = BufReader::new(read).lines();
    let mut raw = String::new();
    while let Some(line) = lines.next_line().await.unwrap() {
        let answer: &[u8] = match line.split(' ').next().unwrap() {
            "EHLO" => b"250-test\r\n250 AUTH PLAIN\r\n",
            "AUTH" => b"235 logged in\r\n",
            "MAIL" | "RCPT" => b"250 ok\r\n",
            "DATA" => {
                write.write_all(b"354 mail data\r\n").await.unwrap();
                loop {
                    let line = lines.next_line().await.unwrap().unwrap();
                    if line == "." {
                        break;
                    }
                    raw.push_str(&line);
                    raw.push_str("\r\n");
                }
                b"250 accepted\r\n"
            }
            "QUIT" => {
                write.write_all(b"221 bye\r\n").await.unwrap();
                break;
            }
            _ => b"500 unexpected command\r\n",
        };
        write.write_all(answer).await.unwrap();
    }
    raw
}

#[tokio::test]
async fn a_held_send_pins_the_bytes_of_its_uploads() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let h = harness_with_smtp(Some(listener.local_addr().unwrap().port())).await;
    let smtp = tokio::spawn(receive_smtp(listener));
    h.usage.holds.store(true, Ordering::SeqCst);
    let key = "search-key";
    let message = |id: &str| {
        json!({"to": ["x@example.com"], "subject": "s", "body": "b", "save_to_sent": false,
            "attachments": [{"upload_id": id, "filename": "data.csv", "content_type": "text/csv"}]})
    };
    let id = upload(&h.limited, key, b"abc").await;
    let held = call(&h.limited, key, "send_message", message(&id))
        .await
        .unwrap();
    assert_eq!(held["status"], "held");
    assert!(
        held["next"]
            .as_str()
            .unwrap()
            .contains("data.csv (3 bytes)"),
        "{held}"
    );
    // The same digest a typed file of these bytes pins.
    let digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(
        h.usage.held_files.lock().unwrap().as_ref().unwrap()[0]["sha256"],
        digest
    );
    let other = upload(&h.limited, key, b"abd").await;
    let mut swapped = message(&other);
    swapped["hold_id"] = held["hold_id"].clone();
    let error = call(&h.limited, key, "send_message", swapped)
        .await
        .unwrap_err();
    assert!(error.contains("these arguments differ"), "{error}");
    let mut confirm = message(&id);
    confirm["hold_id"] = held["hold_id"].clone();
    let sent = call(&h.limited, key, "send_message", confirm)
        .await
        .unwrap();
    assert_eq!(sent["status"], "sent");
    let raw = tokio::time::timeout(Duration::from_secs(5), smtp)
        .await
        .unwrap()
        .unwrap();
    assert!(raw.contains("filename=\"data.csv\"") && raw.contains("\r\n\r\nYWJj\r\n"));
    // A piece changed in the bucket after the hold refuses the whole send.
    let before = h.uploads.names();
    let changed = upload(&h.limited, key, b"abc").await;
    let held = call(&h.limited, key, "send_message", message(&changed))
        .await
        .unwrap();
    let piece = h
        .uploads
        .names()
        .into_iter()
        .find(|name| !before.contains(name))
        .unwrap();
    h.uploads.objects.lock().unwrap().get_mut(&piece).unwrap()[0] ^= 1;
    let mut confirm = message(&changed);
    confirm["hold_id"] = held["hold_id"].clone();
    let error = call(&h.limited, key, "send_message", confirm)
        .await
        .unwrap_err();
    assert!(
        error.starts_with(
            "attachment \"data.csv\": the uploaded file could not be read; nothing was sent."
        ),
        "{error}"
    );
}

#[tokio::test]
async fn a_held_send_checks_its_handle_before_asking_to_send() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let h = harness_with_smtp(Some(listener.local_addr().unwrap().port())).await;
    let smtp = tokio::spawn(receive_smtp(listener));
    h.usage.holds.store(true, Ordering::SeqCst);
    let key = "workspace-key";
    let message = json!({"to": ["x@example.com"], "subject": "s", "body": "placeholder body"});
    let held = call(&h.limited, key, "send_message", message.clone())
        .await
        .unwrap();
    assert_eq!(held["status"], "held");
    assert!(held.get("message_id").is_none() && held.get("sent_copy").is_none());
    chrono::DateTime::parse_from_rfc3339(held["expires_at"].as_str().unwrap()).unwrap();
    assert!(
        held["next"]
            .as_str()
            .unwrap()
            .contains(held["hold_id"].as_str().unwrap())
    );
    assert_eq!(ended(&h.usage).await, ["send_message Done held"]);
    assert_eq!(
        h.tools.take(),
        [
            "usage send_message - [body,subject,to]".to_owned(),
            format!("holds send_message key:1 {}", h.a.0)
        ]
    );
    let mut confirm = message.clone();
    confirm["hold_id"] = held["hold_id"].clone();
    for token in ["other-key", "other-app"] {
        let error = call(&h.limited, token, "send_message", confirm.clone())
            .await
            .unwrap_err();
        assert!(error.starts_with("Not sent: no held message"), "{error}");
        assert_eq!(
            h.tools.take(),
            ["usage send_message - [body,hold_id,subject,to]"]
        );
        assert_eq!(ended(&h.usage).await, ["send_message Failed"]);
    }
    let mut wrong = confirm.clone();
    wrong["mailbox"] = json!("b@example.com");
    assert!(
        call(&h.limited, key, "send_message", wrong)
            .await
            .unwrap_err()
            .starts_with("Not sent: no held message")
    );
    h.tools.take();
    h.usage.ends();
    let mut changed = confirm.clone();
    changed["body"] = json!("changed body");
    assert!(
        call(&h.limited, key, "send_message", changed)
            .await
            .unwrap_err()
            .starts_with("Not sent: these arguments differ")
    );
    assert_eq!(
        h.tools.take(),
        ["usage send_message - [body,hold_id,subject,to]"]
    );
    assert_eq!(ended(&h.usage).await, ["send_message Failed"]);
    let error = call(&h.limited, key, "send_message", confirm.clone())
        .await
        .unwrap_err();
    assert!(
        error.starts_with(NO_SENDS_LEFT) && error.contains("This hold is used up"),
        "{error}"
    );
    assert_eq!(
        h.tools.take(),
        [
            "usage send_message - [body,hold_id,subject,to]".to_owned(),
            format!("send_message key:1 {}", h.a.0)
        ]
    );
    assert_eq!(ended(&h.usage).await, ["send_message Refused"]);
    assert!(
        call(&h.limited, key, "send_message", confirm)
            .await
            .unwrap_err()
            .starts_with("Not sent: no held message")
    );
    assert_eq!(
        h.tools.take(),
        ["usage send_message - [body,hold_id,subject,to]"]
    );
    assert_eq!(ended(&h.usage).await, ["send_message Failed"]);

    // On the scripted mailbox, only the exact confirming file can reach SMTP.
    let mut exact = json!({"to": ["x@example.com"], "subject": "s", "body": "b", "save_to_sent": false,
        "attachments": [{"filename": "data.csv", "content_type": "text/csv", "content": "YWJj"}]
    });
    let held = call(&h.limited, "search-key", "send_message", exact.clone())
        .await
        .unwrap();
    assert_eq!(held["status"], "held");
    assert!(
        held["next"]
            .as_str()
            .unwrap()
            .contains("data.csv (3 bytes)")
    );
    assert_eq!(
        *h.usage.held_files.lock().unwrap(),
        Some(json!([{
            "filename": "data.csv", "content_type": "text/csv", "size": 3,
            "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        }]))
    );
    exact["hold_id"] = held["hold_id"].clone();
    let mut other_file = exact.clone();
    other_file["attachments"][0]["content"] = json!("YWJk");
    let error = call(&h.limited, "search-key", "send_message", other_file)
        .await
        .unwrap_err();
    assert!(error.contains("these arguments differ"), "{error}");
    let sent = call(&h.limited, "search-key", "send_message", exact)
        .await
        .unwrap();
    assert_eq!(sent["status"], "sent");
    let raw = tokio::time::timeout(Duration::from_secs(5), smtp)
        .await
        .unwrap()
        .unwrap();
    assert!(raw.contains("filename=\"data.csv\""));
    assert!(raw.contains("\r\n\r\nYWJj\r\n"));
    h.tools.take();
    assert_eq!(
        ended(&h.usage).await,
        [
            "send_message Done held",
            "send_message Failed",
            "send_message Done"
        ]
    );

    // Both tools treat a blank handle as absent, then take it before asking to send.
    for (tool, mut arguments) in [
        ("send_message", message.clone()),
        (
            "reply_to_message",
            json!({"id": "m1", "body": "placeholder reply"}),
        ),
    ] {
        arguments["mailbox"] = json!("b@example.com");
        arguments["hold_id"] = json!("  ");
        let held = call(&h.limited, key, tool, arguments.clone())
            .await
            .unwrap();
        assert_eq!(held["status"], "held");
        assert_eq!(ended(&h.usage).await, [format!("{tool} Done held")]);
        let asked = h.tools.take();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[1], format!("holds {tool} key:1 {}", h.b.0));
        arguments["hold_id"] = held["hold_id"].clone();
        let error = call(&h.limited, key, tool, arguments).await.unwrap_err();
        assert!(
            error.starts_with(OPENED) && error.contains("This hold is used up"),
            "{error}"
        );
        let asked = h.tools.take();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[1], format!("{tool} key:1 {}", h.b.0));
        assert_eq!(ended(&h.usage).await, [format!("{tool} Failed")]);
    }
    // An invalid message never asks the hold question.
    let invalid = json!({"to": ["nobody"], "subject": "s", "body": "placeholder"});
    assert!(
        call(&h.limited, key, "send_message", invalid)
            .await
            .unwrap_err()
            .contains("not a valid email")
    );
    assert_eq!(h.tools.take(), ["usage send_message - [body,subject,to]"]);
    h.usage.ends();
    for _ in 0..20 {
        assert_eq!(
            call(&h.limited, key, "send_message", message.clone())
                .await
                .unwrap()["status"],
            "held"
        );
    }
    let error = call(&h.limited, key, "send_message", message)
        .await
        .unwrap_err();
    assert!(error.starts_with("Not sent: too many messages"), "{error}");
    h.tools.take();
    h.usage.ends();
    call(&h.limited, key, "get_webhook_status", json!({}))
        .await
        .unwrap();
    assert_eq!(
        h.tools.take(),
        ["usage get_webhook_status - []"],
        "another tool never asks holds"
    );
    assert_eq!(ended(&h.usage).await, ["get_webhook_status Done"]);
}

#[tokio::test]
async fn the_extension_checks_a_call_before_the_usage_hook() {
    let h = harness().await;
    let key = "workspace-key";
    let b = &h.b.0;
    assert_eq!(
        call(&h.both, key, "get_account", json!({})).await,
        Ok(json!({ "tool": "get_account", "mailbox": null }))
    );
    assert_eq!(
        h.tools.take(),
        [
            "read get_account - []",
            "usage get_account - []",
            "call get_account - []"
        ]
    );
    assert_eq!(h.usage.ends(), ["get_account Done"]);
    assert_eq!(
        call(&h.both, key, "delete_message", json!({ "id": "m1" })).await,
        Err("deleting mail is turned off for this workspace".to_owned())
    );
    assert_eq!(h.tools.take(), ["write delete_message - [id]"]);
    assert_eq!(h.usage.ends(), Vec::<String>::new(), "the check refused it");

    let message = json!({
        "mailbox": "b@example.com",
        "to": ["x@example.com"],
        "subject": "s",
        "body": "b"
    });
    let error = call(&h.both, key, "send_message", message)
        .await
        .unwrap_err();
    assert!(error.starts_with(OPENED), "the hook let B send: {error}");
    assert_eq!(
        h.tools.take(),
        [
            format!("write send_message {b} [body,subject,to]"),
            format!("usage send_message {b} [body,subject,to]"),
            format!("send_message key:1 {b}"),
        ]
    );

    h.usage.over_limit.store(true, Ordering::SeqCst);
    let arguments = json!({ "mailbox": "b@example.com" });
    assert_eq!(
        call(&h.both, key, "disconnect_mailbox", arguments).await,
        Err(OVER_LIMIT.to_owned())
    );
    assert_eq!(
        h.tools.take(),
        [
            format!("write disconnect_mailbox {b} []"),
            format!("usage disconnect_mailbox {b} []"),
        ]
    );
    assert_eq!(h.usage.ends(), ["send_message Failed"]);
}

/// The ends the usage hook hears within five seconds; none follows.
async fn ended(usage: &Usage) -> Vec<String> {
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if !usage.ends.lock().unwrap().is_empty() {
            break;
        }
    }
    let ends = usage.ends();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(usage.ends(), Vec::<String>::new(), "after {ends:?}");
    ends
}

#[tokio::test]
async fn the_usage_hook_hears_once_how_each_call_it_allowed_ended() {
    let h = harness().await;
    let key = "workspace-key";
    let search = json!({ "offset": 10 });
    let found = call(&h.limited, "search-key", "search_messages", search).await;
    assert_eq!(found.unwrap()["total"], 3);
    assert_eq!(h.usage.ends(), ["search_messages Done 3"]);

    let failing = json!({ "name": "get_account", "arguments": { "fail": true } });
    let reply = rpc(&h.both, key, "tools/call", failing).await;
    assert_eq!(reply["error"]["message"], "the tool failed", "{reply}");
    assert_eq!(h.usage.ends(), ["get_account Failed"]);
    let unlisted = json!({ "name": "get_account", "arguments": {} });
    let reply = rpc(&h.both, "other-key", "tools/call", unlisted).await;
    assert_eq!(reply["error"]["message"], "tool not found", "{reply}");
    assert_eq!(h.usage.ends(), Vec::<String>::new());

    // A client that leaves: the call runs on, and the hook hears its end.
    let slow = json!({ "name": "get_account", "arguments": { "wait": 500 } });
    let request = rpc_request(key, "tools/call", &slow, "2025-06-18");
    let started = async {
        let entry = "call get_account - [wait]".to_owned();
        let wait = async {
            while !h.tools.log.lock().unwrap().contains(&entry) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        };
        let waited = tokio::time::timeout(Duration::from_secs(5), wait).await;
        assert!(waited.is_ok(), "the tool didn't start within 5 s");
    };
    tokio::select! {
        _ = h.both.clone().oneshot(request) => panic!("it answered before the tool ended"),
        () = started => {}
    }
    assert_eq!(h.usage.ends(), Vec::<String>::new(), "the tool still runs");
    assert_eq!(ended(&h.usage).await, ["get_account Done"]);

    // A call dropped before it answered.
    let panics = json!({ "name": "get_account", "arguments": { "panic": true } });
    let request = rpc_request(key, "tools/call", &panics, "2025-06-18");
    let call = tokio::time::timeout(Duration::from_secs(1), h.both.clone().oneshot(request));
    let _ = call.await;
    assert_eq!(ended(&h.usage).await, ["get_account Failed"]);
}

/// Retention and event cap, then the ceilings for both, from a webhook
/// status.
fn outbox(status: &Value) -> [i64; 4] {
    [
        "outbox_retention_seconds",
        "outbox_max_events",
        "outbox_max_retention_seconds",
        "outbox_max_events_limit",
    ]
    .map(|field| status[field].as_i64().unwrap())
}

#[tokio::test]
async fn the_usage_hook_can_lower_a_mailbox_s_outbox_ceilings() {
    let h = harness().await;
    let key = "workspace-key";
    let status = call(&h.limited, key, "get_webhook_status", json!({})).await;
    assert_eq!(outbox(&status.unwrap()), [7 * DAY, 1_000, 14 * DAY, 2_000]);
    let named = json!({ "mailbox": "b@example.com" });
    let status = call(&h.limited, key, "get_webhook_status", named).await;
    assert_eq!(outbox(&status.unwrap()), [7 * DAY, 1_000, 30 * DAY, 10_000]);

    let limits = "set_webhook_outbox_limits";
    let longer = json!({ "retention": "20d" });
    let range = "outbox retention must be from 3600 seconds (1 hour) to 1209600 seconds \
                 (14 days), not 1728000 seconds (20 days)";
    assert_eq!(
        call(&h.limited, key, limits, longer.clone()).await,
        Err(range.to_owned())
    );
    assert_eq!(
        call(&h.limited, key, limits, json!({ "max_events": 2_001 })).await,
        Err("outbox max events must be from 1 to 2000, not 2001".to_owned())
    );
    let error = call(&h.plain, key, limits, longer).await.unwrap_err();
    assert!(error.starts_with("No webhook is saved"), "{error}");

    let settings = WebhookSettings {
        enabled: false,
        url: "https://hooks.example.com/a".to_owned(),
        auth_header: None,
        signing: true,
        signing_secret: SecretString::from("whsec_test".to_owned()),
        include_sender: false,
    };
    h.store.save_webhook(&h.a, &settings).await.unwrap();
    let most = json!({ "retention": "14d", "max_events": 2_000 });
    let update = call(&h.limited, key, limits, most).await.unwrap();
    assert_eq!(outbox(&update), [14 * DAY, 2_000, 14 * DAY, 2_000]);
    assert_eq!(update["outbox_retention_source"], "account");

    // Set before the ceilings were lowered: reported as stored, which is
    // what pruning keeps.
    let month = OutboxLimitChange::Set(30 * DAY);
    h.store
        .set_webhook_outbox_limits(&h.a, month, OutboxLimitChange::Keep)
        .await
        .unwrap();
    let off = json!({ "enabled": false });
    let status = call(&h.limited, key, "set_webhook_enabled", off).await;
    assert_eq!(outbox(&status.unwrap()), [30 * DAY, 2_000, 14 * DAY, 2_000]);
    let update = call(&h.limited, key, limits, json!({ "reset": true })).await;
    let update = update.unwrap();
    assert_eq!(outbox(&update), [7 * DAY, 1_000, 14 * DAY, 2_000]);
    assert_eq!(update["outbox_retention_source"], "default");
}
