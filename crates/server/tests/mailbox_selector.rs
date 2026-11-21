//! The mailbox selector: with a principal resolver whose callers hold
//! several mailboxes, each of the 18 tools takes a `mailbox` argument,
//! acts on the mailbox it names, and refuses any other mailbox with the
//! same unknown-mailbox error. Runs in process on SQLite, without network
//! access: the two mailboxes fail in different, recognisable ways before
//! any connection is made, which shows which one a tool opened.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions};
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, BearerRequest, CredentialVerifier, PrincipalResolver,
    Resolution, ResolveFuture, VerifyFuture,
};
use postkeep_mail::ImapServer;
use postkeep_store::{
    AccountId, MasterKey, OAuthAccount, Provider, Store, UpstreamTokens, WebhookSettings,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

mod bucket;

const HOST: &str = "mail.example.com";
const TENANT: &str = "tenant-a";
const UNKNOWN: &str = "unknown mailbox: pass the id or address of a mailbox this connection can \
use, or leave mailbox out to use the default one";
/// What opening mailbox A (IMAP, on a preset this server no longer offers)
/// fails with.
const OPENED_A: &str = "this account's mail provider is no longer offered by this server";
/// What opening mailbox B (Outlook, without Microsoft sign-in configured)
/// fails with.
const OPENED_B: &str = "this server no longer offers Microsoft accounts";

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

/// `two-mailboxes` may use A (the default) and B, and is also handed D,
/// which lives in another tenant. `one-mailbox` may use A only.
struct FakeResolver {
    a: AccountId,
    b: AccountId,
    d: AccountId,
    selects: bool,
}

impl PrincipalResolver for FakeResolver {
    fn resolve<'a>(
        &'a self,
        _state: &'a AuthState,
        token: &'a str,
        _request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let caller = || {
                Authenticated::for_account(self.a.clone(), "agent".to_owned(), "mail".to_owned())
                    .with_tenant(TENANT)
                    .with_principal("workspace-key")
            };
            Ok(match token {
                "two-mailboxes" => Resolution::Authenticated(
                    caller().with_mailboxes([self.b.clone(), self.d.clone()]),
                ),
                "one-mailbox" => Resolution::Authenticated(caller()),
                _ => Resolution::Refused("unknown key"),
            })
        })
    }

    fn selects_mailboxes(&self) -> bool {
        self.selects
    }
}

struct Harness {
    selecting: Router,
    plain: Router,
    store: Store,
    a: AccountId,
    b: AccountId,
    c: AccountId,
    d: AccountId,
    _dir: tempfile::TempDir,
    _bucket: wiremock::MockServer,
}

fn password() -> SecretString {
    SecretString::from("app-password".to_owned())
}

fn webhook(url: &str) -> WebhookSettings {
    WebhookSettings {
        enabled: true,
        url: url.to_owned(),
        auth_header: None,
        signing: true,
        signing_secret: SecretString::from("whsec_test-secret-0123456789".to_owned()),
        include_sender: false,
    }
}

async fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let tenant = store.for_tenant(TENANT);
    let a = tenant
        .upsert_imap_account("a@example.com", &password(), Some("retired"))
        .await
        .unwrap()
        .id;
    let b = tenant
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: "subject-b",
                email: "b@example.com",
            },
            &UpstreamTokens {
                refresh_token: SecretString::from("refresh-b".to_owned()),
                access_token: None,
                access_expires_at: None,
                scope: "Mail.ReadWrite".to_owned(),
            },
        )
        .await
        .unwrap()
        .id;
    let c = tenant
        .upsert_imap_account("c@example.com", &password(), Some("retired"))
        .await
        .unwrap()
        .id;
    let d = store
        .for_tenant("tenant-b")
        .upsert_imap_account("d@example.com", &password(), Some("retired"))
        .await
        .unwrap()
        .id;
    store
        .save_webhook(&b, &webhook("https://hooks.example.com/b"))
        .await
        .unwrap();
    store
        .save_webhook(&c, &webhook("https://hooks.example.com/c"))
        .await
        .unwrap();

    let bucket_server = wiremock::MockServer::start().await;
    let bucket: Arc<dyn postkeep::bucket::Bucket> =
        Arc::new(bucket::stand_in(&bucket_server).await.1);
    let build = |selects: bool| {
        let config = AppConfig {
            bucket: Some(bucket.clone()),
            auth: AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap(),
            extra_allowed_hosts: Vec::new(),
            extra_allowed_origins: Vec::new(),
            limits: app::RequestLimits::default(),
            pool: postkeep::pool::PoolConfig::default(),
            watchers: None,
            upstream: None,
            google_push: None,
        };
        let resolver = Arc::new(FakeResolver {
            a: a.clone(),
            b: b.clone(),
            d: d.clone(),
            selects,
        });
        app::router_with(
            config,
            store.clone(),
            AcceptAll,
            CancellationToken::new(),
            Extensions::new().principal_resolver(resolver),
        )
    };
    Harness {
        selecting: build(true),
        plain: build(false),
        store,
        a,
        b,
        c,
        d,
        _dir: dir,
        _bucket: bucket_server,
    }
}

async fn rpc(app: &Router, token: &str, method: &str, params: Value) -> Value {
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
    let text = String::from_utf8_lossy(&bytes);
    assert_eq!(status, StatusCode::OK, "{method}: {text}");
    serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("{method}: not JSON: {text}"))
}

/// Calls `tool` and returns its result: `Ok` with the structured output, or
/// `Err` with the error text.
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

/// Valid arguments for every tool, so each one gets as far as opening the
/// mailbox.
fn tools() -> Vec<(&'static str, Value)> {
    vec![
        ("list_folders", json!({})),
        ("search_messages", json!({})),
        ("get_message", json!({ "id": "m1" })),
        (
            "download_attachment",
            json!({ "id": "m1", "attachment_id": "1" }),
        ),
        (
            "send_message",
            json!({ "to": ["x@example.com"], "subject": "s", "body": "b" }),
        ),
        ("reply_to_message", json!({ "id": "m1", "body": "b" })),
        (
            "create_draft",
            json!({ "to": ["x@example.com"], "subject": "s", "body": "b" }),
        ),
        ("update_flags", json!({ "id": "m1", "read": true })),
        (
            "move_message",
            json!({ "id": "m1", "destination": "Archive" }),
        ),
        ("delete_message", json!({ "id": "m1" })),
        ("create_folder", json!({ "name": "Projects" })),
        ("get_webhook_status", json!({})),
        ("set_webhook_enabled", json!({ "enabled": false })),
        ("set_webhook_outbox_limits", json!({ "max_events": 50 })),
        ("list_webhook_filters", json!({})),
        (
            "add_webhook_filter",
            json!({ "action": "allow", "field": "subject", "kind": "contains", "pattern": "x" }),
        ),
        ("remove_webhook_filter", json!({ "all": true })),
        ("upload_attachment", json!({})),
    ]
}

const MAIL_TOOLS: usize = 11;

fn with_mailbox(arguments: &Value, mailbox: Value) -> Value {
    let mut arguments = arguments.clone();
    arguments
        .as_object_mut()
        .unwrap()
        .insert("mailbox".to_owned(), mailbox);
    arguments
}

async fn listed_tools(app: &Router) -> Vec<Value> {
    let reply = rpc(app, "two-mailboxes", "tools/list", json!({})).await;
    reply["result"]["tools"].as_array().unwrap().clone()
}

async fn instructions(app: &Router) -> String {
    let reply = rpc(
        app,
        "two-mailboxes",
        "initialize",
        json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "1" }
        }),
    )
    .await;
    reply["result"]["instructions"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn every_schema_takes_mailbox_only_when_the_resolver_selects() {
    let h = harness().await;
    let selecting = listed_tools(&h.selecting).await;
    let plain = listed_tools(&h.plain).await;
    assert_eq!(selecting.len(), 18);
    assert_eq!(plain.len(), 18);
    for (selecting, plain) in selecting.iter().zip(&plain) {
        let name = selecting["name"].as_str().unwrap();
        assert_eq!(name, plain["name"]);
        let schema = &selecting["inputSchema"];
        assert_eq!(
            schema["properties"]["mailbox"],
            json!({
                "description": "Mailbox to use: its id or email address. Omit it to use the default mailbox.",
                "type": "string"
            }),
            "{name}"
        );
        let required = schema["required"].as_array().cloned().unwrap_or_default();
        assert!(!required.contains(&json!("mailbox")), "{name}");
        assert!(
            plain["inputSchema"]["properties"].get("mailbox").is_none(),
            "{name}"
        );
        let mut without = selecting.clone();
        without["inputSchema"]["properties"]
            .as_object_mut()
            .unwrap()
            .remove("mailbox");
        assert_eq!(&without, plain, "{name}: only the argument is added");
    }

    let selecting = instructions(&h.selecting).await;
    let plain = instructions(&h.plain).await;
    assert_eq!(
        selecting.strip_prefix(plain.as_str()),
        Some(
            " This connection can use several mailboxes: every tool takes an optional mailbox \
argument, the id or address of one of them, and uses the default mailbox without it."
        )
    );
}

#[tokio::test]
async fn every_tool_refuses_a_mailbox_the_caller_cannot_use() {
    let h = harness().await;
    let refused = [
        // In the tenant, not the caller's.
        json!(h.c.0),
        json!("c@example.com"),
        json!(" C@Example.com "),
        // Nowhere.
        json!("nobody@example.com"),
        json!("00000000-0000-0000-0000-000000000000"),
        // Handed out by the resolver, but in another tenant.
        json!(h.d.0),
        json!("d@example.com"),
        // Not a name.
        json!(7),
        json!(["b@example.com"]),
        json!({ "id": h.b.0 }),
    ];
    for (tool, arguments) in tools() {
        for mailbox in &refused {
            let result = call(
                &h.selecting,
                "two-mailboxes",
                tool,
                with_mailbox(&arguments, mailbox.clone()),
            )
            .await;
            assert_eq!(result, Err(UNKNOWN.to_owned()), "{tool} with {mailbox}");
        }
        // A caller with one mailbox cannot reach another one either.
        for mailbox in [json!(h.b.0), json!("b@example.com")] {
            let result = call(
                &h.selecting,
                "one-mailbox",
                tool,
                with_mailbox(&arguments, mailbox.clone()),
            )
            .await;
            assert_eq!(result, Err(UNKNOWN.to_owned()), "{tool} with {mailbox}");
        }
    }
    // The refused calls changed nothing in the other mailboxes.
    for account in [&h.b, &h.c] {
        let hook = h.store.webhook(account).await.unwrap().unwrap();
        assert!(hook.settings.enabled, "{account}");
        assert_eq!(
            h.store.webhook_outbox_overrides(account).await.unwrap(),
            Some((None, None)),
            "{account}"
        );
    }
}

#[tokio::test]
async fn every_tool_acts_on_the_selected_mailbox() {
    let h = harness().await;
    let all = tools();
    for (tool, arguments) in &all[..MAIL_TOOLS] {
        for (mailbox, opened) in [
            (None, OPENED_A),
            (Some(Value::Null), OPENED_A),
            (Some(json!("  ")), OPENED_A),
            (Some(json!(h.a.0)), OPENED_A),
            (Some(json!("a@example.com")), OPENED_A),
            (Some(json!(h.b.0)), OPENED_B),
            (Some(json!("b@example.com")), OPENED_B),
            (Some(json!(" B@Example.COM ")), OPENED_B),
        ] {
            let arguments = mailbox
                .clone()
                .map_or_else(|| arguments.clone(), |m| with_mailbox(arguments, m));
            let error = call(&h.selecting, "two-mailboxes", tool, arguments)
                .await
                .unwrap_err();
            assert!(
                error.starts_with(opened),
                "{tool} with {mailbox:?}: {error}"
            );
        }
    }

    // The webhook tools: B has a webhook, the default mailbox A has none.
    let token = "two-mailboxes";
    let status = call(&h.selecting, token, "get_webhook_status", json!({}))
        .await
        .unwrap();
    assert_eq!(status["configured"], false);
    let status = call(
        &h.selecting,
        token,
        "get_webhook_status",
        json!({ "mailbox": "b@example.com" }),
    )
    .await
    .unwrap();
    assert_eq!(status["configured"], true);
    assert_eq!(status["enabled"], true);

    let missing = "No webhook is saved for this account. Set it up on the account page (/account).";
    // The webhook tools after the status; the upload, last, opens no mailbox.
    for (tool, arguments) in &all[MAIL_TOOLS + 1..all.len() - 1] {
        let error = call(&h.selecting, token, tool, arguments.clone())
            .await
            .unwrap_err();
        assert_eq!(error, missing, "{tool} on the default mailbox");
    }
    let disabled = call(
        &h.selecting,
        token,
        "set_webhook_enabled",
        json!({ "enabled": false, "mailbox": h.b.0 }),
    )
    .await
    .unwrap();
    assert_eq!(disabled["enabled"], false);
    let limited = call(
        &h.selecting,
        token,
        "set_webhook_outbox_limits",
        json!({ "max_events": 50, "mailbox": "B@example.com" }),
    )
    .await
    .unwrap();
    assert_eq!(limited["configured"], true);
    assert_eq!(limited["outbox_max_events"], 50, "{limited}");

    let b = h.store.webhook(&h.b).await.unwrap().unwrap();
    assert!(!b.settings.enabled);
    assert_eq!(
        h.store.webhook_outbox_overrides(&h.b).await.unwrap(),
        Some((None, Some(50)))
    );
    let c = h.store.webhook(&h.c).await.unwrap().unwrap();
    assert!(c.settings.enabled, "the other mailbox is untouched");
    assert!(h.store.webhook(&h.a).await.unwrap().is_none());
    assert!(h.store.webhook(&h.d).await.unwrap().is_none());

    // A filter rule added with B selected is B's alone.
    let (_, rule) = &all[MAIL_TOOLS + 4];
    let added = call(
        &h.selecting,
        token,
        "add_webhook_filter",
        with_mailbox(rule, json!(h.b.0)),
    );
    assert_eq!(added.await.unwrap()["filter_rules_active"], 1);
    for (account, rules) in [(&h.b, 1), (&h.c, 0), (&h.a, 0)] {
        let stored = h.store.webhook_filter_rules(account, 9).await.unwrap();
        assert_eq!(stored.len(), rules, "{account}");
    }
}

/// Without selection no tool takes `mailbox`, so each refuses it, as any
/// argument it does not take, rather than act on the token's mailbox.
#[tokio::test]
async fn without_selection_the_tools_refuse_a_mailbox_argument() {
    let h = harness().await;
    for (tool, arguments) in &tools() {
        let error = call(
            &h.plain,
            "two-mailboxes",
            tool,
            with_mailbox(arguments, json!(h.b.0)),
        )
        .await
        .unwrap_err();
        assert!(error.contains("unknown field `mailbox`"), "{tool}: {error}");
    }
}
