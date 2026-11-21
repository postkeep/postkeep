//! `GET /readyz`: ready once the database answers and has every migration,
//! not ready while it does not, and draining from the first SIGINT or
//! SIGTERM on (through the binary).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions};
use postkeep_auth::{AuthConfig, CredentialVerifier, VerifyFuture};
use postkeep_mail::ImapServer;
use postkeep_store::{MasterKey, Store};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

#[cfg(unix)]
mod serve;

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

fn database_url(dir: &tempfile::TempDir) -> String {
    format!("sqlite://{}", dir.path().join("server.db").display())
}

async fn store(dir: &tempfile::TempDir) -> Store {
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    Store::connect(&database_url(dir), &key).await.unwrap()
}

fn router(store: Store) -> Router {
    let config = AppConfig {
        bucket: None,
        auth: AuthConfig::new("https://mail.example.com", app::MCP_PATH).unwrap(),
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits::default(),
        pool: postkeep::pool::PoolConfig::default(),
        watchers: None,
        upstream: None,
        google_push: None,
    };
    app::router_with(
        config,
        store,
        AcceptAll,
        CancellationToken::new(),
        Extensions::new(),
    )
}

async fn request(app: &Router, method: Method, path: &str) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn ready_once_the_database_answers_and_is_current() {
    let dir = tempfile::tempdir().unwrap();
    let app = router(store(&dir).await);
    assert_eq!(
        request(&app, Method::GET, "/readyz").await,
        (StatusCode::OK, "ready".to_owned())
    );
    assert_eq!(
        request(&app, Method::HEAD, "/readyz").await,
        (StatusCode::OK, String::new())
    );
}

#[tokio::test]
async fn not_ready_while_a_migration_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir).await;
    let pool = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(&database_url(&dir))
        .await
        .unwrap();
    sqlx::query(
        "DELETE FROM _sqlx_migrations WHERE version = (SELECT MAX(version) FROM _sqlx_migrations)",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;

    let app = router(store);
    assert_eq!(
        request(&app, Method::GET, "/readyz").await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "migrations pending".to_owned()
        )
    );
    assert_eq!(
        request(&app, Method::GET, "/healthz").await,
        (StatusCode::OK, "ok".to_owned()),
        "the process is still alive"
    );
}

#[tokio::test]
async fn not_ready_while_the_database_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir).await;
    let app = router(store.clone());
    store.close().await;
    assert_eq!(
        request(&app, Method::GET, "/readyz").await,
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "database unavailable".to_owned()
        )
    );
}

/// `postkeep serve` itself, stopped with real signals.
#[cfg(unix)]
mod drain {
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpStream};
    use std::path::PathBuf;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    /// The binary on a local port it picks with a new SQLite database. Killed
    /// when dropped.
    struct Server {
        child: Child,
        addr: SocketAddr,
        log: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl Server {
        fn start(drain_seconds: u64) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let log = dir.path().join("server.log");
            let mut command = Command::new(env!("CARGO_BIN_EXE_postkeep"));
            command
                .arg("serve")
                .env_clear()
                .env("POSTKEEP_PUBLIC_URL", "https://mail.example.com")
                .env("POSTKEEP_MASTER_KEY", "00".repeat(32))
                .env(
                    "POSTKEEP_DATABASE_URL",
                    format!("sqlite://{}", dir.path().join("server.db").display()),
                )
                .env("POSTKEEP_SHUTDOWN_DRAIN", drain_seconds.to_string())
                .env("POSTKEEP_WEBHOOKS", "false")
                .stdout(Stdio::null())
                .stderr(std::fs::File::create(&log).unwrap());
            let mut child = super::serve::on_any_port(&mut command).spawn().unwrap();
            let addr = super::serve::bound(&mut child, &log, "postkeep is ready");
            let server = Self {
                child,
                addr,
                log,
                _dir: dir,
            };
            server.wait_for((200, "ready"), Duration::from_secs(30));
            server
        }

        /// Status and body of `GET path`, or `None` if the server does not
        /// answer.
        fn get(&self, path: &str) -> Option<(u16, String)> {
            let mut stream = TcpStream::connect_timeout(&self.addr, Duration::from_secs(2)).ok()?;
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .ok()?;
            write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .ok()?;
            let mut response = String::new();
            stream.read_to_string(&mut response).ok()?;
            let status = response.split_whitespace().nth(1)?.parse().ok()?;
            let body = response.split_once("\r\n\r\n").map_or("", |(_, body)| body);
            Some((status, body.to_owned()))
        }

        /// Polls `/readyz` until it answers `expected`.
        fn wait_for(&self, expected: (u16, &str), limit: Duration) {
            let deadline = Instant::now() + limit;
            let mut last = None;
            while Instant::now() < deadline {
                last = self.get("/readyz");
                if last
                    .as_ref()
                    .is_some_and(|(status, body)| (*status, body.as_str()) == expected)
                {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            panic!(
                "/readyz never answered {expected:?}; last answer {last:?}\n{}",
                self.log()
            );
        }

        fn terminate(&self) {
            let status = Command::new("sh")
                .arg("-c")
                .arg(format!("kill -TERM {}", self.child.id()))
                .status()
                .unwrap();
            assert!(status.success(), "kill failed: {status}");
        }

        fn exit(&mut self, limit: Duration) -> ExitStatus {
            let deadline = Instant::now() + limit;
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                assert!(
                    Instant::now() < deadline,
                    "still running after {limit:?}\n{}",
                    self.log()
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        fn log(&self) -> String {
            std::fs::read_to_string(&self.log).unwrap_or_default()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    #[test]
    fn sigterm_drains_until_a_second_signal() {
        let mut server = Server::start(120);
        server.terminate();
        server.wait_for((503, "draining"), Duration::from_secs(10));
        assert_eq!(
            server.get("/healthz"),
            Some((200, "ok".to_owned())),
            "the server keeps serving while it drains"
        );
        server.terminate();
        let status = server.exit(Duration::from_secs(30));
        assert!(status.success(), "{status}\n{}", server.log());
        let log = server.log();
        assert!(log.contains("draining"), "{log}");
        assert!(log.contains("shutting down"), "{log}");
    }

    #[test]
    fn the_drain_ends_on_its_own() {
        let mut server = Server::start(2);
        let signalled = Instant::now();
        server.terminate();
        let status = server.exit(Duration::from_secs(30));
        assert!(status.success(), "{status}\n{}", server.log());
        assert!(
            signalled.elapsed() >= Duration::from_secs(2),
            "stopped after {:?}, before the drain was over",
            signalled.elapsed()
        );
    }
}
