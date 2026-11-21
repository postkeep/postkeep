//! Prometheus metrics, served in text format 0.0.4 at `GET /metrics` on
//! their own address (`POSTKEEP_METRICS_BIND`), outside the request log and
//! the limits.
//!
//! - The request log counts every answer it writes a line for: its route as
//!   written, its status and the time until its head, and a tool call's
//!   tool and outcome.
//! - Tool calls and watchers count their IMAP logins and SMTP sends by mail
//!   server and outcome; watchers also count their errors and refusals. The
//!   running watchers and the database connections are read at each scrape.
//! - Every label value comes from the code or from a fixed list: a route as
//!   the code writes it (or `unmatched`), a status, a bucket bound, a real
//!   tool's name (or `unknown`), an outcome, a mail server's id, a provider
//!   and a connection state. No label ever holds an
//!   address, a tenant, a principal, an account id, a token, a client IP, or
//!   a request's path, query or path value.
//! - Each server counts into its own registry, which `run_server` hands the
//!   router; nothing is kept for the whole process.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use postkeep_store::{Provider, Store};

use crate::watch::Watchers;

/// The content type of Prometheus text format 0.0.4.
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// The route label of a request no route served.
const UNMATCHED: &str = "unmatched";

/// The tool label of a tool call without a real tool's name.
const UNKNOWN_TOOL: &str = "unknown";

/// The duration buckets' upper bounds, with their `le` text. 1.5 s is the
/// MCP p95 the alerts check.
const BUCKETS: [(Duration, &str); 12] = [
    (Duration::from_millis(5), "0.005"),
    (Duration::from_millis(10), "0.01"),
    (Duration::from_millis(25), "0.025"),
    (Duration::from_millis(50), "0.05"),
    (Duration::from_millis(100), "0.1"),
    (Duration::from_millis(250), "0.25"),
    (Duration::from_millis(500), "0.5"),
    (Duration::from_secs(1), "1"),
    (Duration::from_millis(1500), "1.5"),
    (Duration::from_millis(2500), "2.5"),
    (Duration::from_secs(5), "5"),
    (Duration::from_secs(10), "10"),
];

/// One server's counters.
#[derive(Clone, Default)]
pub struct Metrics(Arc<Counters>);

#[derive(Default)]
struct Counters {
    requests: Mutex<BTreeMap<String, RouteCounts>>,
    tools: Mutex<BTreeMap<(String, &'static str), u64>>,
    /// Keyed by mail server id, then outcome; so are `smtp_sends`.
    imap_logins: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    smtp_sends: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    watcher_errors: Mutex<BTreeMap<&'static str, u64>>,
    watchers_refused: AtomicU64,
}

#[derive(Default)]
struct RouteCounts {
    statuses: BTreeMap<u16, u64>,
    /// Answers per bucket, not cumulative; the last slot is above 10 s.
    buckets: [u64; BUCKETS.len() + 1],
    micros: u64,
}

impl RouteCounts {
    fn add(&mut self, status: u16, slot: usize, micros: u64) {
        *self.statuses.entry(status).or_default() += 1;
        self.buckets[slot] += 1;
        self.micros = self.micros.saturating_add(micros);
    }
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics").finish_non_exhaustive()
    }
}

impl Metrics {
    /// Counts an answer: `route` is the route as written, `None` when no
    /// route served the request.
    pub fn answered(&self, route: Option<&str>, status: u16, elapsed: Duration) {
        let route = route.unwrap_or(UNMATCHED);
        let slot = BUCKETS
            .iter()
            .position(|(bound, _)| elapsed <= *bound)
            .unwrap_or(BUCKETS.len());
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let mut requests = self
            .0
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(counts) = requests.get_mut(route) {
            counts.add(status, slot, micros);
        } else {
            let mut counts = RouteCounts::default();
            counts.add(status, slot, micros);
            requests.insert(route.to_owned(), counts);
        }
    }

    /// Counts a tool call: `tool` is a real tool's name, `None` otherwise.
    pub fn tool_call(&self, tool: Option<&str>, outcome: &'static str) {
        let tool = tool.unwrap_or(UNKNOWN_TOOL).to_owned();
        *self
            .0
            .tools
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((tool, outcome))
            .or_default() += 1;
    }

    /// Counts a login to the mail server `server` (its id), when its result
    /// says something about the server.
    pub fn imap_login<T>(&self, server: &'static str, result: &postkeep_mail::Result<T>) {
        count_mail(&self.0.imap_logins, server, result);
    }

    /// Counts a send through the mail server `server` (its id), when its
    /// result says something about the server.
    pub fn smtp_send<T>(&self, server: &'static str, result: &postkeep_mail::Result<T>) {
        count_mail(&self.0.smtp_sends, server, result);
    }

    /// Counts a watcher run of `provider` that ended in an error.
    pub fn watcher_error(&self, provider: Provider) {
        *self
            .0
            .watcher_errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(provider.as_str())
            .or_default() += 1;
    }

    /// Counts a watcher not started because the most allowed run.
    pub fn watcher_refused(&self) {
        self.0.watchers_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Every family in text format 0.0.4, its series sorted.
    pub fn render(&self) -> String {
        let mut out = String::new();
        {
            let requests = self
                .0
                .requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            describe(
                &mut out,
                "postkeep_http_requests_total",
                "counter",
                "Answered HTTP requests by route as written and status; /healthz and /readyz are not counted.",
            );
            for (route, counts) in requests.iter() {
                let route = escape(route);
                for (status, count) in &counts.statuses {
                    let _ = writeln!(
                        out,
                        "postkeep_http_requests_total{{route=\"{route}\",status=\"{status}\"}} {count}"
                    );
                }
            }
            describe(
                &mut out,
                "postkeep_http_request_duration_seconds",
                "histogram",
                "Seconds until the answer's head of the counted HTTP requests, by route as written.",
            );
            for (route, counts) in requests.iter() {
                let route = escape(route);
                let name = "postkeep_http_request_duration_seconds";
                let mut cumulative = 0;
                for ((_, le), count) in BUCKETS.iter().zip(&counts.buckets) {
                    cumulative += count;
                    let _ = writeln!(
                        out,
                        "{name}_bucket{{route=\"{route}\",le=\"{le}\"}} {cumulative}"
                    );
                }
                let total: u64 = counts.buckets.iter().sum();
                let _ = writeln!(
                    out,
                    "{name}_bucket{{route=\"{route}\",le=\"+Inf\"}} {total}"
                );
                let _ = writeln!(
                    out,
                    "{name}_sum{{route=\"{route}\"}} {}.{:06}",
                    counts.micros / 1_000_000,
                    counts.micros % 1_000_000
                );
                let _ = writeln!(out, "{name}_count{{route=\"{route}\"}} {total}");
            }
        }
        describe(
            &mut out,
            "postkeep_tool_calls_total",
            "counter",
            "MCP tool calls by tool and outcome (ok, tool_error or rpc_error).",
        );
        for ((tool, outcome), count) in self
            .0
            .tools
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = writeln!(
                out,
                "postkeep_tool_calls_total{{tool=\"{}\",outcome=\"{outcome}\"}} {count}",
                escape(tool)
            );
        }
        render_mail(
            &mut out,
            "postkeep_imap_logins_total",
            "IMAP logins with a stored password by mail server and outcome (ok, rejected, unavailable or failed); sign-in checks are not counted.",
            &self.0.imap_logins,
        );
        render_mail(
            &mut out,
            "postkeep_smtp_sends_total",
            "Messages sent over SMTP by mail server and outcome (ok, rejected, unavailable or failed); a send refused with a permanent reply other than 535 is not counted.",
            &self.0.smtp_sends,
        );
        self.render_watchers(&mut out);
        out
    }

    /// The watchers' counter families.
    fn render_watchers(&self, out: &mut String) {
        describe(
            out,
            "postkeep_watcher_errors_total",
            "counter",
            "New-mail watcher runs that ended in an error, by provider; a rejected password is not one.",
        );
        for (provider, count) in self
            .0
            .watcher_errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            let _ = writeln!(
                out,
                "postkeep_watcher_errors_total{{provider=\"{provider}\"}} {count}"
            );
        }
        describe(
            out,
            "postkeep_watchers_refused_total",
            "counter",
            "New-mail watchers not started because POSTKEEP_WEBHOOK_MAX_WATCHERS run.",
        );
        let _ = writeln!(
            out,
            "postkeep_watchers_refused_total {}",
            self.0.watchers_refused.load(Ordering::Relaxed)
        );
    }
}

/// What a mail result says about the server: `None` when the request, not
/// the server, caused it.
fn mail_outcome<T>(result: &postkeep_mail::Result<T>) -> Option<&'static str> {
    use postkeep_mail::Error;
    match result {
        Ok(_) => Some("ok"),
        Err(Error::Authentication) => Some("rejected"),
        Err(Error::Unavailable { .. }) => Some("unavailable"),
        Err(
            Error::Timeout
            | Error::SubmissionUnconfirmed
            | Error::Io(_)
            | Error::Tls(_)
            | Error::Imap(_),
        ) => Some("failed"),
        // A 4xx reply, or none at all; a 5xx such as 550 is the recipient's.
        Err(Error::Smtp(err)) if err.is_transient() || err.status().is_none() => Some("failed"),
        Err(_) => None,
    }
}

/// Counts a mail result into `family`, when it says something.
fn count_mail<T>(
    family: &Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    server: &'static str,
    result: &postkeep_mail::Result<T>,
) {
    if let Some(outcome) = mail_outcome(result) {
        *family
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry((server, outcome))
            .or_default() += 1;
    }
}

/// A mail family: its description and its samples by server and outcome.
fn render_mail(
    out: &mut String,
    name: &str,
    help: &str,
    family: &Mutex<BTreeMap<(&'static str, &'static str), u64>>,
) {
    describe(out, name, "counter", help);
    for ((server, outcome), count) in family.lock().unwrap_or_else(PoisonError::into_inner).iter() {
        let _ = writeln!(
            out,
            "{name}{{server=\"{server}\",outcome=\"{outcome}\"}} {count}"
        );
    }
}

/// The gauges, read now: the running watchers (none without watchers) and
/// the database connections by state.
fn gauges(store: &Store, watchers: Option<&Watchers>) -> String {
    let mut out = String::new();
    describe(
        &mut out,
        "postkeep_watchers",
        "gauge",
        "New-mail watchers running in this process.",
    );
    let running = watchers.map_or(0, Watchers::running);
    let _ = writeln!(out, "postkeep_watchers {running}");
    describe(
        &mut out,
        "postkeep_db_connections",
        "gauge",
        "This process's open database connections by state (idle or in_use).",
    );
    let pool = store.pool();
    let idle = pool.num_idle();
    let in_use = usize::try_from(pool.size()).map_or(0, |size| size.saturating_sub(idle));
    let _ = writeln!(out, "postkeep_db_connections{{state=\"idle\"}} {idle}");
    let _ = writeln!(out, "postkeep_db_connections{{state=\"in_use\"}} {in_use}");
    out
}

/// A family's `# HELP` and `# TYPE` lines.
fn describe(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
}

/// A label value with `\`, `"` and newlines escaped.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// What a scrape reads: the counters, and the sources of the gauges.
#[derive(Clone)]
struct Scrape {
    metrics: Metrics,
    store: Store,
    watchers: Option<Watchers>,
}

/// Serves `GET /metrics` and nothing else: `metrics`, plus the gauges of
/// `store`'s pool and of `watchers` (`None` when webhooks are off).
pub fn router(metrics: Metrics, store: Store, watchers: Option<Watchers>) -> Router {
    Router::new()
        .route("/metrics", get(serve))
        .with_state(Scrape {
            metrics,
            store,
            watchers,
        })
}

async fn serve(State(scrape): State<Scrape>) -> impl IntoResponse {
    let mut body = scrape.metrics.render();
    body.push_str(&gauges(&scrape.store, scrape.watchers.as_ref()));
    (
        [
            (header::CONTENT_TYPE, CONTENT_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode, header};
    use http_body_util::BodyExt as _;
    use tower::ServiceExt as _;

    use postkeep_mail::Error;
    use postkeep_store::{MasterKey, Provider, Store};

    use super::{Metrics, gauges, mail_outcome, router};

    /// A store on a new SQLite database in `dir`.
    async fn store(dir: &tempfile::TempDir) -> Store {
        let url = format!("sqlite://{}", dir.path().join("metrics.db").display());
        let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
        Store::connect(&url, &key).await.unwrap()
    }

    /// The lines of `render()` that are samples, not comments.
    fn samples(metrics: &Metrics) -> Vec<String> {
        metrics
            .render()
            .lines()
            .filter(|line| !line.starts_with('#'))
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn an_empty_registry_describes_its_families() {
        let text = Metrics::default().render();
        let types: Vec<&str> = text
            .lines()
            .filter(|line| line.starts_with("# TYPE "))
            .collect();
        assert_eq!(
            types,
            [
                "# TYPE postkeep_http_requests_total counter",
                "# TYPE postkeep_http_request_duration_seconds histogram",
                "# TYPE postkeep_tool_calls_total counter",
                "# TYPE postkeep_imap_logins_total counter",
                "# TYPE postkeep_smtp_sends_total counter",
                "# TYPE postkeep_watcher_errors_total counter",
                "# TYPE postkeep_watchers_refused_total counter",
            ]
        );
        assert_eq!(
            samples(&Metrics::default()),
            ["postkeep_watchers_refused_total 0"],
            "{text}"
        );
    }

    #[test]
    fn requests_are_counted_by_route_and_status() {
        let metrics = Metrics::default();
        metrics.answered(Some("/a/{id}"), 200, Duration::from_millis(3));
        metrics.answered(Some("/a/{id}"), 404, Duration::from_millis(70));
        metrics.answered(Some("/a/{id}"), 200, Duration::from_secs(20));
        let r = "route=\"/a/{id}\"";
        let h = "postkeep_http_request_duration_seconds";
        let mut expected = vec![
            format!("postkeep_http_requests_total{{{r},status=\"200\"}} 2"),
            format!("postkeep_http_requests_total{{{r},status=\"404\"}} 1"),
        ];
        for le in ["0.005", "0.01", "0.025", "0.05"] {
            expected.push(format!("{h}_bucket{{{r},le=\"{le}\"}} 1"));
        }
        for le in ["0.1", "0.25", "0.5", "1", "1.5", "2.5", "5", "10"] {
            expected.push(format!("{h}_bucket{{{r},le=\"{le}\"}} 2"));
        }
        expected.push(format!("{h}_bucket{{{r},le=\"+Inf\"}} 3"));
        expected.push(format!("{h}_sum{{{r}}} 20.073000"));
        expected.push(format!("{h}_count{{{r}}} 3"));
        expected.push("postkeep_watchers_refused_total 0".to_owned());
        assert_eq!(samples(&metrics), expected);
    }

    #[test]
    fn a_time_on_a_bound_counts_in_that_bucket() {
        let on = Metrics::default();
        on.answered(Some("/"), 200, Duration::from_millis(5));
        assert!(on.render().contains(
            "postkeep_http_request_duration_seconds_bucket{route=\"/\",le=\"0.005\"} 1\n"
        ));
        let above = Metrics::default();
        above.answered(Some("/"), 200, Duration::from_micros(5001));
        assert!(above.render().contains(
            "postkeep_http_request_duration_seconds_bucket{route=\"/\",le=\"0.005\"} 0\n"
        ));
    }

    #[test]
    fn a_request_no_route_served_is_unmatched() {
        let metrics = Metrics::default();
        metrics.answered(None, 404, Duration::from_millis(1));
        assert!(
            metrics
                .render()
                .contains("postkeep_http_requests_total{route=\"unmatched\",status=\"404\"} 1\n")
        );
    }

    #[test]
    fn label_values_are_escaped() {
        let metrics = Metrics::default();
        metrics.answered(Some("/a\"b\\c\nd"), 200, Duration::from_millis(1));
        assert!(metrics.render().contains(
            "postkeep_http_requests_total{route=\"/a\\\"b\\\\c\\nd\",status=\"200\"} 1\n"
        ));
    }

    #[test]
    fn tool_calls_are_counted_by_tool_and_outcome() {
        let metrics = Metrics::default();
        metrics.tool_call(Some("list_folders"), "ok");
        metrics.tool_call(Some("list_folders"), "ok");
        metrics.tool_call(None, "rpc_error");
        assert_eq!(
            samples(&metrics),
            [
                "postkeep_tool_calls_total{tool=\"list_folders\",outcome=\"ok\"} 2",
                "postkeep_tool_calls_total{tool=\"unknown\",outcome=\"rpc_error\"} 1",
                "postkeep_watchers_refused_total 0",
            ]
        );
    }

    #[test]
    fn mail_results_are_told_apart() {
        let message = || Error::MessageNotFound {
            folder: "INBOX".to_owned(),
            uid: 1,
        };
        let cases: [(postkeep_mail::Result<()>, Option<&str>); _] = [
            (Ok(()), Some("ok")),
            (Err(Error::Authentication), Some("rejected")),
            (Err(Error::Unavailable { code: "454" }), Some("unavailable")),
            (Err(Error::Timeout), Some("failed")),
            (Err(Error::SubmissionUnconfirmed), Some("failed")),
            (
                Err(Error::Io(std::io::Error::other("reset"))),
                Some("failed"),
            ),
            (Err(Error::InvalidInput("to".to_owned())), None),
            (Err(Error::FolderNotFound("x".to_owned())), None),
            (Err(message()), None),
            (Err(Error::Unsupported("MOVE")), None),
            (Err(Error::Parse(1)), None),
        ];
        for (result, expected) in &cases {
            assert_eq!(mail_outcome(result), *expected, "{result:?}");
        }
    }

    #[test]
    fn mail_and_watcher_counters_are_rendered() {
        let metrics = Metrics::default();
        metrics.imap_login("custom", &Err::<(), _>(Error::Authentication));
        metrics.imap_login("custom", &Ok(()));
        metrics.smtp_send(
            "custom",
            &Err::<(), _>(Error::InvalidInput("to".to_owned())),
        );
        metrics.watcher_error(Provider::Graph);
        metrics.watcher_refused();
        metrics.watcher_refused();
        assert_eq!(
            samples(&metrics),
            [
                "postkeep_imap_logins_total{server=\"custom\",outcome=\"ok\"} 1",
                "postkeep_imap_logins_total{server=\"custom\",outcome=\"rejected\"} 1",
                "postkeep_watcher_errors_total{provider=\"graph\"} 1",
                "postkeep_watchers_refused_total 2",
            ]
        );
    }

    #[tokio::test]
    async fn the_gauges_read_the_watchers_and_the_pool() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        assert!(gauges(&store, None).contains("\npostkeep_watchers 0\n"));
        // sqlx hands a dropped connection back in a task, so the store's own
        // connections may still be on their way back.
        let settled = async || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            loop {
                let text = gauges(&store, None);
                if text.contains("{state=\"in_use\"} 0\n") {
                    return text;
                }
                assert!(std::time::Instant::now() < deadline, "{text}");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        settled().await;
        let held = store.pool().acquire().await.unwrap();
        let text = gauges(&store, None);
        assert!(
            text.contains("\npostkeep_db_connections{state=\"in_use\"} 1\n"),
            "{text}"
        );
        drop(held);
        let text = settled().await;
        let idle = store.pool().num_idle();
        assert!(
            text.contains(&format!(
                "\npostkeep_db_connections{{state=\"idle\"}} {idle}\n"
            )),
            "{text}"
        );
    }

    #[tokio::test]
    async fn only_get_metrics_is_served() {
        let metrics = Metrics::default();
        metrics.answered(Some("/"), 200, Duration::from_millis(1));
        let dir = tempfile::tempdir().unwrap();
        let app = router(metrics.clone(), store(&dir).await, None);
        let send = |method: Method, path: &str| {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(request)
        };
        let response = send(Method::GET, "/metrics").await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; version=0.0.4; charset=utf-8"
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(body.to_vec()).unwrap();
        let gauges = body.strip_prefix(&metrics.render()).unwrap();
        assert!(gauges.contains("\npostkeep_watchers 0\n"), "{body}");
        for state in ["idle", "in_use"] {
            let line = format!("\npostkeep_db_connections{{state=\"{state}\"}} ");
            assert!(gauges.contains(&line), "{body}");
        }
        assert_eq!(
            send(Method::POST, "/metrics").await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            send(Method::GET, "/").await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
    }
}
