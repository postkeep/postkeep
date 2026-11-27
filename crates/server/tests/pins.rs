//! Byte-for-byte pins of the server's public surface, so refactors of
//! `serve()` and the extension points cannot change it unnoticed.
//!
//! Pinned in `tests/pins/`: the `tools/list` response (names, input and
//! output schemas, annotations), the `skills/list` response (`skills-list.json`),
//! the instructions from `initialize`, the route table, the authorization-server
//! and protected-resource metadata, and the `WWW-Authenticate` header of a
//! `401`. The tests build the router in process; the last one starts
//! `postkeep serve` itself with only the
//! required settings and checks it against the same files, so the binary
//! keeps the pinned surface too. Everything runs on SQLite, without network
//! access.
//!
//! JSON pins store the exact response bytes, indented for review without
//! reordering anything; the test checks that removing that indentation gives
//! back the response byte for byte. Any change fails with a line diff. After
//! an intended change, rerun with `UPDATE_PINS=1` to rewrite the files and
//! explain the change in the pull request.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig};
use postkeep::watch::{WatchConfig, Watchers};
use postkeep_auth::{AuthConfig, CredentialVerifier, VerifyFuture};
use postkeep_mail::{ImapServer, ImapServers};
use postkeep_store::{CodeGrant, GrantSubject, MasterKey, NewClient, Store};
use postkeep_upstream::{AppCredentials, Endpoints, Http, OAuthClient, PushExpectations};
use postkeep_webhook::Deliverer;
use rmcp::model::{SKILLS_EXTENSION_ID, Skill};
use secrecy::SecretString;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

mod serve;

const HOST: &str = "mail.example.com";
const ORIGIN: &str = "https://mail.example.com";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const REDIRECT: &str = "http://127.0.0.1/callback";
const PROTOCOL: &str = "2025-06-18";
const CODE: &str = "pins-authorization-code";
const DEFAULT_ROUTES: &str = "# Default: webhooks on, no Microsoft or Google sign-in\n";

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

/// Which optional parts of the server are configured.
#[derive(Clone, Copy)]
enum Setup {
    /// `postkeep serve` with only the required settings: webhooks on, no
    /// Microsoft or Google sign-in.
    Default,
    /// Microsoft and Google sign-in, webhooks and Gmail push.
    Providers,
}

struct Harness {
    target: Target,
    _dir: tempfile::TempDir,
}

/// Where the harness sends its requests.
enum Target {
    /// The router, in process.
    Router(Router),
    /// `postkeep serve` itself, over TCP.
    Binary(Binary),
}

/// `postkeep serve` on a free local port. Killed when dropped.
struct Binary {
    child: Child,
    addr: SocketAddr,
    log: PathBuf,
    /// The client that [`CODE`] was issued to.
    client_id: String,
}

struct Reply {
    status: StatusCode,
    headers: axum::http::HeaderMap,
    body: String,
}

async fn harness(setup: Setup) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let mut auth = AuthConfig::new(ORIGIN, app::MCP_PATH).unwrap();
    // The route probes send many requests from one client.
    auth.requests_per_minute = 100_000;
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::default(),
        Deliverer::new("postkeep-pins"),
        WatchConfig::default(),
        CancellationToken::new(),
    );
    let (upstream, google_push) = match setup {
        Setup::Default => (None, None),
        Setup::Providers => {
            let credentials = |id: &str| AppCredentials {
                client_id: id.to_owned(),
                client_secret: SecretString::from("shh".to_owned()),
            };
            // A closed local port: nothing here may reach a provider.
            let endpoints = Endpoints::all_at(&url::Url::parse("http://127.0.0.1:9/").unwrap());
            let upstream = OAuthClient::new(
                Http::for_tests(),
                endpoints,
                url::Url::parse(ORIGIN).unwrap(),
                Some(credentials("ms-client")),
                Some(credentials("google-client")),
            );
            let push = (
                "projects/demo/topics/gmail".to_owned(),
                PushExpectations {
                    audience: format!("{ORIGIN}/push/google"),
                    service_account: "push@demo.iam.gserviceaccount.com".to_owned(),
                },
            );
            (Some(upstream), Some(push))
        }
    };
    let config = AppConfig {
        bucket: None,
        auth,
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits::default(),
        pool: postkeep::pool::PoolConfig::default(),
        watchers: Some(watchers),
        upstream,
        google_push,
    };
    let app = app::router(config, store, AcceptAll, CancellationToken::new());
    Harness {
        target: Target::Router(app),
        _dir: dir,
    }
}

/// `postkeep serve` with only the required settings, on a new SQLite
/// database: [`Setup::Default`] the way a self-hoster starts it.
///
/// The binary checks passwords with the real mail server, so the database
/// gets an account, a client and the authorization code [`CODE`] before the
/// server starts, and [`Harness::sign_in`] redeems the code.
async fn binary() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::generate_encoded().unwrap();
    let store = Store::connect(&url, &MasterKey::parse(&key).unwrap())
        .await
        .unwrap();
    let password = SecretString::from("abcd-efgh-ijkl-mnop".to_owned());
    let account = store
        .upsert_account("user@example.com", &password)
        .await
        .unwrap();
    let client = store
        .create_client(&NewClient {
            name: Some("Pins".to_owned()),
            redirect_uris: vec![REDIRECT.to_owned()],
            secret: None,
        })
        .await
        .unwrap();
    let grant = CodeGrant {
        client_id: client.id.clone(),
        subject: GrantSubject::Account(account.id),
        redirect_uri: REDIRECT.to_owned(),
        code_challenge: CHALLENGE.to_owned(),
        scope: postkeep_auth::SCOPE.to_owned(),
        resource: Some(format!("{ORIGIN}{}", app::MCP_PATH)),
    };
    store
        .save_code(CODE, &grant, Duration::from_mins(10))
        .await
        .unwrap();
    store.close().await;

    let log = dir.path().join("server.log");
    let mut command = Command::new(env!("CARGO_BIN_EXE_postkeep"));
    command
        .arg("serve")
        .env_clear()
        .env("POSTKEEP_PUBLIC_URL", ORIGIN)
        .env("POSTKEEP_MASTER_KEY", &key)
        .env("POSTKEEP_DATABASE_URL", &url)
        // The route probes send many requests from one client.
        .env("POSTKEEP_RATE_LIMIT", "100000")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap());
    let mut child = serve::on_any_port(&mut command).spawn().unwrap();
    let addr = serve::bound(&mut child, &log, "postkeep is ready");
    let mut binary = Binary {
        child,
        addr,
        log,
        client_id: client.id,
    };
    binary.wait_until_ready().await;
    Harness {
        target: Target::Binary(binary),
        _dir: dir,
    }
}

impl Harness {
    async fn send(&self, request: Request<Body>) -> Reply {
        let app = match &self.target {
            Target::Router(app) => app.clone(),
            Target::Binary(binary) => return binary.send(request).await,
        };
        let response = app.oneshot(request).await.unwrap();
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
        self.send(
            Request::get(uri)
                .header(header::HOST, HOST)
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn form(&self, uri: &str, fields: &[(&str, &str)]) -> Reply {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send(
            Request::post(uri)
                .header(header::HOST, HOST)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ORIGIN)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    /// Registers a client, signs in and returns an access token. The
    /// binary's client and code are already in its database.
    async fn sign_in(&self) -> String {
        if let Target::Binary(binary) = &self.target {
            return self.redeem(CODE, &binary.client_id).await;
        }
        let register = self
            .send(
                Request::post("/register")
                    .header(header::HOST, HOST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({ "redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none", "client_name": "Pins" })
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(register.status, StatusCode::CREATED, "{}", register.body);
        let client_id = serde_json::from_str::<Value>(&register.body).unwrap()["client_id"]
            .as_str()
            .unwrap()
            .to_owned();
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", &client_id),
                ("redirect_uri", REDIRECT),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
                ("resource", &format!("{ORIGIN}/mcp")),
            ])
            .finish();
        let page = self.get(&format!("/authorize?{query}")).await;
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
        let code = location
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned();
        self.redeem(&code, &client_id).await
    }

    /// Exchanges an authorization code for an access token.
    async fn redeem(&self, code: &str, client_id: &str) -> String {
        let token = self
            .form(
                "/token",
                &[
                    ("grant_type", "authorization_code"),
                    ("code", code),
                    ("client_id", client_id),
                    ("code_verifier", VERIFIER),
                ],
            )
            .await;
        assert_eq!(token.status, StatusCode::OK, "{}", token.body);
        serde_json::from_str::<Value>(&token.body).unwrap()["access_token"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn rpc(&self, token: Option<&str>, method: &str, params: &Value) -> Reply {
        let mut request = Request::post(app::MCP_PATH)
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("mcp-protocol-version", PROTOCOL);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        self.send(request.body(Body::from(body.to_string())).unwrap())
            .await
    }
}

impl Binary {
    /// Sends `request` on a new connection and reads the reply to its end.
    async fn send(&self, request: Request<Body>) -> Reply {
        let (parts, body) = request.into_parts();
        let body = body.collect().await.unwrap().to_bytes();
        let mut head = format!("{} {} HTTP/1.1\r\n", parts.method, parts.uri);
        for (name, value) in &parts.headers {
            let _ = write!(head, "{name}: {}\r\n", value.to_str().unwrap());
        }
        if !body.is_empty() {
            let _ = write!(head, "content-length: {}\r\n", body.len());
        }
        head.push_str("connection: close\r\n\r\n");
        let mut raw = head.into_bytes();
        raw.extend_from_slice(&body);
        let reply = exchange(self.addr, &raw)
            .await
            .unwrap_or_else(|err| panic!("{} {}: {err}\n{}", parts.method, parts.uri, self.log()));
        parse_reply(&reply)
    }

    /// Waits until `/readyz` answers `200`.
    async fn wait_until_ready(&mut self) {
        let probe = format!("GET /readyz HTTP/1.1\r\nhost: {HOST}\r\nconnection: close\r\n\r\n");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let reply = exchange(self.addr, probe.as_bytes()).await;
            if reply.is_ok_and(|reply| reply.starts_with(b"HTTP/1.1 200 ")) {
                return;
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("postkeep serve exited with {status}\n{}", self.log());
            }
            assert!(
                Instant::now() < deadline,
                "postkeep serve was not ready after 30 s\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Binary {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Writes `request` on a new connection and reads until the server closes
/// it.
async fn exchange(addr: SocketAddr, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    stream.write_all(request).await?;
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut reply)).await??;
    Ok(reply)
}

/// Splits an HTTP/1.1 reply into its status, headers and body.
fn parse_reply(raw: &[u8]) -> Reply {
    let end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = std::str::from_utf8(&raw[..end]).unwrap();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap().split(' ').nth(1).unwrap();
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value.trim()).unwrap(),
        );
    }
    assert!(
        !headers.contains_key(header::TRANSFER_ENCODING),
        "{status}: chunked replies are not decoded here"
    );
    Reply {
        status: StatusCode::from_bytes(status.as_bytes()).unwrap(),
        headers,
        body: String::from_utf8_lossy(&raw[end + 4..]).into_owned(),
    }
}

fn pin_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/pins")
        .join(name)
}

/// Compares `actual` with the pinned file, or rewrites it with `UPDATE_PINS=1`.
fn check_pin(name: &str, actual: &str) {
    let path = pin_path(name);
    if std::env::var_os("UPDATE_PINS").is_some() {
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "{}: {err}; run with UPDATE_PINS=1 to create it",
            path.display()
        )
    });
    assert_pin(name, &expected, actual);
}

fn assert_pin(name: &str, expected: &str, actual: &str) {
    assert!(
        expected == actual,
        "tests/pins/{name} no longer matches (- pinned, + now). If the change is intended, \
         rerun with UPDATE_PINS=1 and explain it in the pull request.\n{}",
        line_diff(expected, actual)
    );
}

/// Pins a JSON response body byte for byte, indented for review.
fn check_json_pin(name: &str, raw: &str) {
    let indented = indent_json(raw);
    assert_eq!(
        compact_json(&indented),
        raw,
        "{name}: the response has whitespace outside strings, so the pin would not be exact"
    );
    check_pin(name, &indented);
}

/// Puts each JSON value on its own line, indented by two spaces, without
/// reordering keys or touching strings.
fn indent_json(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() * 2);
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    let mut chars = raw.chars().peekable();
    let newline = |out: &mut String, depth: usize| {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', depth * 2));
    };
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '{' | '[' => {
                out.push(c);
                let close = if c == '{' { '}' } else { ']' };
                if chars.peek() == Some(&close) {
                    out.push(close);
                    chars.next();
                } else {
                    depth += 1;
                    newline(&mut out, depth);
                }
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                newline(&mut out, depth);
                out.push(c);
            }
            ',' => {
                out.push(c);
                newline(&mut out, depth);
            }
            ':' => out.push_str(": "),
            c if c.is_ascii_whitespace() => {}
            c => out.push(c),
        }
    }
    out.push('\n');
    out
}

/// Removes every whitespace character outside JSON strings.
fn compact_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c.is_ascii_whitespace() {
            continue;
        }
        out.push(c);
    }
    out
}

/// A line diff with two lines of context around each change.
fn line_diff(expected: &str, actual: &str) -> String {
    let old: Vec<&str> = expected.lines().collect();
    let new: Vec<&str> = actual.lines().collect();
    // Longest common subsequence lengths of the suffixes.
    let mut common = vec![vec![0usize; new.len() + 1]; old.len() + 1];
    for i in (0..old.len()).rev() {
        for j in (0..new.len()).rev() {
            common[i][j] = if old[i] == new[j] {
                common[i + 1][j + 1] + 1
            } else {
                common[i + 1][j].max(common[i][j + 1])
            };
        }
    }
    let mut lines: Vec<(char, usize, &str)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while i < old.len() || j < new.len() {
        if i < old.len() && j < new.len() && old[i] == new[j] {
            lines.push((' ', i + 1, old[i]));
            i += 1;
            j += 1;
        } else if i < old.len() && (j == new.len() || common[i + 1][j] >= common[i][j + 1]) {
            lines.push(('-', i + 1, old[i]));
            i += 1;
        } else {
            lines.push(('+', j + 1, new[j]));
            j += 1;
        }
    }
    let changed: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, (tag, _, _))| *tag != ' ')
        .map(|(index, _)| index)
        .collect();
    let mut out = String::new();
    let mut last_shown = None;
    for (index, (tag, number, text)) in lines.iter().enumerate() {
        let near = changed
            .iter()
            .any(|&change| index + 2 >= change && index <= change + 2);
        if !near {
            continue;
        }
        if last_shown.is_some_and(|last| last + 1 != index) {
            out.push_str("...\n");
        }
        let _ = writeln!(out, "{tag} {number:>5} | {text}");
        last_shown = Some(index);
    }
    if out.is_empty() {
        out.push_str("(only the trailing newline differs)\n");
    }
    out
}

/// Every path served today, plus a few that must stay unknown.
fn probe_paths() -> Vec<String> {
    let mut paths: Vec<String> = [
        "/",
        "/healthz",
        "/readyz",
        "/mcp",
        "/register",
        "/authorize",
        "/token",
        "/revoke",
        "/account",
        "/account/sign-in",
        "/account/sign-out",
        "/account/revoke",
        "/account/clients/revoke",
        "/account/password",
        "/account/delete",
        "/account/webhook",
        "/account/webhook/test",
        "/account/webhook/rotate-secret",
        "/account/webhook/filters/add",
        "/account/webhook/filters/edit",
        "/account/webhook/filters/remove",
        "/account/webhook/filters/enabled",
        "/oauth/microsoft/start",
        "/oauth/google/start",
        "/oauth/other/start",
        "/oauth/microsoft/callback",
        "/oauth/google/callback",
        "/oauth/other/callback",
        "/oauth/icon.svg",
        "/oauth/logo.svg",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/openid-configuration",
        "/push/microsoft",
        "/push/microsoft/lifecycle",
        "/push/google",
        "/upload",
        "/favicon.ico",
        "/favicon.svg",
        "/apple-touch-icon.png",
        "/icon-192.png",
        "/icon-512.png",
        "/site.webmanifest",
        "/assets/missing.css",
        "/robots.txt",
        "/mcp/extra",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    // The pages' static files, listed the way `postkeep_auth` serves them:
    // every file under `crates/auth/static` except the font licences.
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../auth/static");
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext != "txt") {
                let relative = path.strip_prefix(&root).unwrap().to_string_lossy();
                paths.push(format!("/assets/{}", relative.replace('\\', "/")));
            }
        }
    }
    paths.sort();
    paths
}

async fn route_table(harness: &Harness) -> String {
    let mut table = String::new();
    for path in probe_paths() {
        for method in [Method::GET, Method::POST] {
            let reply = harness
                .send(
                    Request::builder()
                        .method(method.clone())
                        .uri(&path)
                        .header(header::HOST, HOST)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await;
            let content_type = reply
                .headers
                .get(header::CONTENT_TYPE)
                .map_or("-", |value| value.to_str().unwrap());
            let allow = reply
                .headers
                .get(header::ALLOW)
                .map(|value| format!(" allow={}", value.to_str().unwrap()))
                .unwrap_or_default();
            let _ = writeln!(
                table,
                "{method:<4} {path} -> {} {content_type}{allow}",
                reply.status.as_u16()
            );
        }
    }
    table
}

#[tokio::test]
async fn tools_list_is_pinned() {
    check_tools(&harness(Setup::Default).await).await;
}

async fn check_tools(harness: &Harness) {
    let token = harness.sign_in().await;
    let initialize = json!({
        "protocolVersion": PROTOCOL,
        "capabilities": {},
        "clientInfo": { "name": "pins", "version": "1.0" },
    });
    let reply = harness.rpc(Some(&token), "initialize", &initialize).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let info: Value = serde_json::from_str(&reply.body).unwrap();
    let instructions = info["result"]["instructions"].as_str().unwrap();
    check_pin("instructions.txt", &format!("{instructions}\n"));

    let reply = harness.rpc(Some(&token), "tools/list", &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let listed: Value = serde_json::from_str(&reply.body).unwrap();
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 18);
    for tool in tools {
        assert!(
            tool["title"]
                .as_str()
                .is_some_and(|title| !title.trim().is_empty()),
            "{} has no title",
            tool["name"]
        );
        assert!(
            tool["annotations"]["destructiveHint"].is_boolean(),
            "{} has no explicit destructiveHint",
            tool["name"]
        );
    }
    check_json_pin("tools-list.json", &reply.body);

    let capabilities = &info["result"]["capabilities"];
    assert_eq!(capabilities["resources"], json!({}));
    assert_eq!(capabilities["extensions"][SKILLS_EXTENSION_ID], json!({}));
    let reply = harness.rpc(Some(&token), "skills/list", &json!({})).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    check_json_pin("skills-list.json", &reply.body);
    let listed: Value = serde_json::from_str(&reply.body).unwrap();
    let skills: Vec<Skill> = serde_json::from_value(listed["result"]["skills"].clone()).unwrap();
    for skill in skills {
        let rmcp::model::SkillResources::Files(files) = skill.resources else {
            panic!("{} has no file manifest", skill.uri);
        };
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].uri, skill.uri);
        let reply = harness
            .rpc(Some(&token), "resources/read", &json!({ "uri": skill.uri }))
            .await;
        assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
        let read: Value = serde_json::from_str(&reply.body).unwrap();
        let contents = read["result"]["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], skill.uri);
        assert_eq!(contents[0]["mimeType"], "text/markdown");
        files[0]
            .verify(contents[0]["text"].as_str().unwrap().as_bytes())
            .unwrap();
    }
}

#[tokio::test]
async fn metadata_documents_are_pinned() {
    check_metadata(&harness(Setup::Default).await).await;
}

async fn check_metadata(harness: &Harness) {
    for (path, pin) in [
        (
            "/.well-known/oauth-authorization-server",
            "oauth-authorization-server.json",
        ),
        (
            "/.well-known/oauth-protected-resource",
            "oauth-protected-resource.json",
        ),
        (
            "/.well-known/oauth-protected-resource/mcp",
            "oauth-protected-resource-mcp.json",
        ),
    ] {
        let reply = harness.get(path).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}: {}", reply.body);
        assert_eq!(
            reply.headers[header::CONTENT_TYPE],
            "application/json",
            "{path}"
        );
        check_json_pin(pin, &reply.body);
    }
}

#[tokio::test]
async fn www_authenticate_is_pinned() {
    check_www_authenticate(&harness(Setup::Default).await).await;
}

async fn check_www_authenticate(harness: &Harness) {
    let initialize = json!({
        "protocolVersion": PROTOCOL,
        "capabilities": {},
        "clientInfo": { "name": "pins", "version": "1.0" },
    });
    let mut pinned = String::new();
    for (case, token) in [("no token", None), ("unknown token", Some("not-a-token"))] {
        let reply = harness.rpc(token, "initialize", &initialize).await;
        let challenges: Vec<&str> = reply
            .headers
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        let _ = writeln!(
            pinned,
            "{case}: {} WWW-Authenticate: {}",
            reply.status.as_u16(),
            challenges.join(" | ")
        );
    }
    check_pin("www-authenticate.txt", &pinned);
}

#[tokio::test]
async fn route_table_is_pinned() {
    let mut table = String::from(DEFAULT_ROUTES);
    table.push_str(&route_table(&harness(Setup::Default).await).await);
    table.push_str("\n# Microsoft and Google sign-in, webhooks and Gmail push\n");
    table.push_str(&route_table(&harness(Setup::Providers).await).await);
    check_pin("routes.txt", &table);
}

/// The default-build parity test: `postkeep serve`, started with only the
/// required settings, serves every pin of [`Setup::Default`]. The binary
/// always uses the real Microsoft and Google endpoints, so the second half
/// of the route table is only checked in process.
#[tokio::test]
async fn the_binary_serves_the_pinned_surface() {
    if std::env::var_os("UPDATE_PINS").is_some() {
        // The tests above rewrite the pins; the binary is checked against
        // them on the next run.
        return;
    }
    let binary = binary().await;
    check_tools(&binary).await;
    check_metadata(&binary).await;
    check_www_authenticate(&binary).await;
    let pinned = std::fs::read_to_string(pin_path("routes.txt")).unwrap();
    let (default, _) = pinned.split_once("\n# Microsoft").unwrap();
    let table = format!("{DEFAULT_ROUTES}{}", route_table(&binary).await);
    assert_pin("routes.txt", default, &table);
}

#[test]
fn pin_formatting_round_trips() {
    let raw = r#"{"a":[],"b":{},"c":[1,{"d":"x, y: {z}","e":"q\"uote\\"}],"f":true}"#;
    let indented = indent_json(raw);
    assert_eq!(compact_json(&indented), raw);
    assert_eq!(
        indented,
        "{\n  \"a\": [],\n  \"b\": {},\n  \"c\": [\n    1,\n    {\n      \"d\": \"x, y: {z}\",\n      \"e\": \"q\\\"uote\\\\\"\n    }\n  ],\n  \"f\": true\n}\n"
    );
    let diff = line_diff("a\nb\nc\n", "a\nB\nc\n");
    assert!(
        diff.contains("-     2 | b") && diff.contains("+     2 | B"),
        "{diff}"
    );
}
