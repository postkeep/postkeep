//! `POSTKEEP_METRICS_BIND`, through the binary: the metrics address counts
//! the main address's requests by route as written and the watchers' logins,
//! errors and refusals, and a metrics address that cannot be bound stops the
//! start.

#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

mod serve;

/// The binary with a SQLite database in its temp dir. Killed when dropped.
struct Process {
    child: Child,
    log: PathBuf,
}

/// The binary on local ports it picks, ready.
struct Server {
    process: Process,
    addr: SocketAddr,
    metrics: SocketAddr,
}

/// An answer's status, head and body.
struct Answer {
    status: u16,
    head: String,
    body: String,
}

/// `method path` on `addr`, or `None` if nothing answers.
fn request(addr: SocketAddr, method: &str, path: &str) -> Option<Answer> {
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok()?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let status = response.split_whitespace().nth(1)?.parse().ok()?;
    let (head, body) = response.split_once("\r\n\r\n")?;
    Some(Answer {
        status,
        head: head.to_owned(),
        body: body.to_owned(),
    })
}

impl Process {
    /// Starts the process; `extra` env pairs go last, so they override.
    fn spawn(dir: &Path, extra: &[(&str, String)]) -> Self {
        let log = dir.join("server.log");
        let mut command = Command::new(env!("CARGO_BIN_EXE_postkeep"));
        command
            .arg("serve")
            .env_clear()
            .env("POSTKEEP_PUBLIC_URL", "https://mail.example.com")
            .env("POSTKEEP_MASTER_KEY", "00".repeat(32))
            .env(
                "POSTKEEP_DATABASE_URL",
                format!("sqlite://{}", dir.join("server.db").display()),
            )
            .env("POSTKEEP_WEBHOOKS", "false")
            .env("POSTKEEP_METRICS_BIND", "127.0.0.1:0");
        serve::on_any_port(&mut command);
        for (name, value) in extra {
            command.env(name, value);
        }
        let child = command
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        Self { child, log }
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

impl Server {
    /// Starts the process and waits until `/readyz` answers `200`.
    fn start(dir: &Path, extra: &[(&str, String)]) -> Self {
        let mut process = Process::spawn(dir, extra);
        let addr = serve::bound(&mut process.child, &process.log, "postkeep is ready");
        let metrics = serve::bound(&mut process.child, &process.log, "serving metrics");
        let server = Self {
            process,
            addr,
            metrics,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if request(server.addr, "GET", "/readyz").is_some_and(|answer| answer.status == 200) {
                return server;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("/readyz never answered 200\n{}", server.process.log());
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn status(addr: SocketAddr, method: &str, path: &str) -> u16 {
    request(addr, method, path).unwrap().status
}

#[test]
fn the_metrics_address_counts_requests_by_route_as_written() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = Server::start(dir.path(), &[]);
    assert_eq!(status(server.addr, "GET", "/"), 200);
    assert_eq!(status(server.addr, "GET", "/healthz"), 200);
    let callback = status(
        server.addr,
        "GET",
        "/oauth/zzsecretzz/callback?code=qqsecretqq&state=x",
    );
    assert_eq!(status(server.addr, "GET", "/no-such-zzpathzz"), 404);
    assert_eq!(status(server.addr, "GET", "/metrics"), 404);

    let answer = request(server.metrics, "GET", "/metrics").unwrap();
    assert_eq!(answer.status, 200, "{}", answer.body);
    assert!(
        answer
            .head
            .to_ascii_lowercase()
            .contains("\r\ncontent-type: text/plain; version=0.0.4; charset=utf-8"),
        "{}",
        answer.head
    );
    let body = answer.body;
    for line in [
        "postkeep_http_requests_total{route=\"/\",status=\"200\"} 1\n".to_owned(),
        format!(
            "postkeep_http_requests_total{{route=\"/oauth/{{provider}}/callback\",status=\"{callback}\"}} 1\n"
        ),
        "postkeep_http_requests_total{route=\"unmatched\",status=\"404\"} 2\n".to_owned(),
        "postkeep_http_request_duration_seconds_count{route=\"/\"} 1\n".to_owned(),
        "# TYPE postkeep_tool_calls_total counter\n".to_owned(),
    ] {
        assert!(body.contains(&line), "{line} missing from\n{body}");
    }
    for absent in [
        "zzsecretzz",
        "qqsecretqq",
        "zzpathzz",
        "route=\"/healthz\"",
        "route=\"/readyz\"",
    ] {
        assert!(!body.contains(absent), "{absent} in\n{body}");
    }
    assert_eq!(status(server.metrics, "GET", "/"), 404);
    assert_eq!(status(server.metrics, "POST", "/metrics"), 405);

    // Through `sh`: slim CI images have `kill` only as a shell builtin.
    let kill = Command::new("sh")
        .arg("-c")
        .arg(format!("kill -TERM {}", server.process.child.id()))
        .status()
        .unwrap();
    assert!(kill.success(), "kill failed: {kill}");
    let exit = server.process.exit(Duration::from_secs(15));
    assert!(exit.success(), "{exit}\n{}", server.process.log());
}

#[test]
fn a_metrics_address_in_use_stops_the_start() {
    let dir = tempfile::tempdir().unwrap();
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = taken.local_addr().unwrap();
    let mut server = Process::spawn(dir.path(), &[("POSTKEEP_METRICS_BIND", addr.to_string())]);
    let exit = server.exit(Duration::from_secs(15));
    assert!(!exit.success(), "{}", server.log());
    let log = server.log();
    assert!(
        log.contains(&format!("could not listen on {addr} for metrics")),
        "{log}"
    );
}

/// A scripted IMAP server on 127.0.0.1, on a thread of its own: the first
/// connection takes the login and `CAPABILITY` and says `BYE` at the next
/// command; every later one rejects the login. Returns its port.
fn imap_server() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for (n, stream) in listener.incoming().enumerate() {
            let Ok(mut stream) = stream else { return };
            std::thread::spawn(move || {
                let _ = stream.write_all(b"* OK ready\r\n");
                let lines = BufReader::new(stream.try_clone().unwrap()).lines();
                for line in lines.map_while(Result::ok) {
                    let mut words = line.split(' ');
                    let tag = words.next().unwrap_or("*");
                    let reply = match (words.next().unwrap_or(""), n) {
                        ("LOGIN", 0) => format!("{tag} OK LOGIN completed\r\n"),
                        ("LOGIN", _) => format!("{tag} NO [AUTHENTICATIONFAILED] Invalid\r\n"),
                        ("CAPABILITY", _) => format!("* CAPABILITY IMAP4rev1\r\n{tag} OK done\r\n"),
                        _ => {
                            let _ = stream.write_all(b"* BYE Session expired\r\n");
                            return;
                        }
                    };
                    let _ = stream.write_all(reply.as_bytes());
                }
            });
        }
    });
    port
}

/// Two accounts with an enabled webhook each in `dir`'s `server.db`, under a
/// new master key. Returns the key and the accounts' ids.
fn seed(dir: &Path) -> (String, Vec<String>) {
    use postkeep_store::{MasterKey, Store, WebhookSettings};
    use secrecy::SecretString;
    let encoded = MasterKey::generate_encoded().unwrap();
    let key = MasterKey::parse(&encoded).unwrap();
    let url = format!("sqlite://{}", dir.join("server.db").display());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let ids = runtime.block_on(async {
        let store = Store::connect(&url, &key).await.unwrap();
        let mut ids = Vec::new();
        for email in ["first@example.com", "second@example.com"] {
            let password = SecretString::from("secret".to_owned());
            let account = store.upsert_account(email, &password).await.unwrap();
            let settings = WebhookSettings {
                enabled: true,
                url: "https://hooks.example.com/mail".to_owned(),
                auth_header: None,
                signing: false,
                signing_secret: SecretString::from("whsec_test".to_owned()),
                include_sender: true,
            };
            store.save_webhook(&account.id, &settings).await.unwrap();
            ids.push(account.id.0);
        }
        store.close().await;
        ids
    });
    (encoded, ids)
}

#[test]
fn watchers_count_their_logins_errors_and_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let (key, ids) = seed(dir.path());
    let imap = imap_server();
    let server = Server::start(
        dir.path(),
        &[
            ("POSTKEEP_WEBHOOKS", "true".to_owned()),
            ("POSTKEEP_MASTER_KEY", key),
            ("POSTKEEP_IMAP_HOST", "127.0.0.1".to_owned()),
            ("POSTKEEP_IMAP_PORT", imap.to_string()),
            ("POSTKEEP_IMAP_SECURITY", "plaintext".to_owned()),
            ("POSTKEEP_WEBHOOK_MAX_WATCHERS", "1".to_owned()),
        ],
    );
    // One watcher runs: its first session breaks after the login, and its
    // retry 5 s later is rejected; the other is refused.
    let expected = [
        "postkeep_imap_logins_total{server=\"custom\",outcome=\"ok\"} 1\n",
        "postkeep_imap_logins_total{server=\"custom\",outcome=\"rejected\"} 1\n",
        "postkeep_watcher_errors_total{provider=\"imap\"} 1\n",
        "postkeep_watchers_refused_total 1\n",
        "\npostkeep_watchers 1\n",
        "\npostkeep_db_connections{state=\"idle\"} ",
        "\npostkeep_db_connections{state=\"in_use\"} ",
    ];
    let deadline = Instant::now() + Duration::from_secs(20);
    let body = loop {
        let body = request(server.metrics, "GET", "/metrics").unwrap().body;
        if expected.iter().all(|line| body.contains(line)) {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "{body}\n{}",
            server.process.log()
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let samples = |family: &str| body.lines().filter(|line| line.starts_with(family)).count();
    assert_eq!(samples("postkeep_imap_logins_total{"), 2, "{body}");
    assert_eq!(samples("postkeep_watcher_errors_total{"), 1, "{body}");
    for absent in ["example.com", "127.0.0.1", &ids[0], &ids[1]] {
        assert!(!body.contains(absent), "{absent} in\n{body}");
    }
}
