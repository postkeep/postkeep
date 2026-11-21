//! The request log: one `info` line per answered request, with the target
//! `postkeep::request_log` and the message "answered a request".
//!
//! - The middleware is the outermost layer of everything but `/healthz` and
//!   `/readyz`, so the line also sees the answers of the limits, the timeout
//!   and the body limit, while the probes, which load balancers call every
//!   few seconds, get no line.
//! - The line holds `request_id`, `method`, `route` (the route as the code
//!   writes it; left out when no route matched), `status` and `ms`
//!   (milliseconds until the answer's head). An MCP request that passed the
//!   bearer check adds `principal` and `tenant`; a tool call adds `outcome`,
//!   and `tool` when the name is a real tool's.
//! - Only the method, the matched route and the answer's status are read:
//!   never the query, a path value, a header or a body. The id is made here
//!   and never taken from a request header, which anyone can send.
//! - The same answer is counted for the metrics (`crate::metrics`): its
//!   route, status and time, and a tool call's tool and outcome.
//! - The request runs inside the span `request` with the target
//!   `postkeep::request` and the level `ERROR`, so every line written while
//!   it runs carries its `request_id`, also with `postkeep::request_log=off`
//!   or a `warn` filter.

use std::sync::{Arc, OnceLock};
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::Method;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::Response;
use postkeep_auth::Authenticated;
use rmcp::ErrorData;
use rmcp::model::CallToolResponse;
use tracing::{Instrument as _, Span};

use crate::metrics::Metrics;

/// What the layers inside learn about a request: the first write wins.
#[derive(Clone)]
pub struct Note(Arc<Noted>);

struct Noted {
    span: Span,
    principal: OnceLock<String>,
    tenant: OnceLock<String>,
    tool: OnceLock<String>,
    outcome: OnceLock<&'static str>,
    /// The usage hook refused the message the tool call was to send.
    send_refused: OnceLock<()>,
    held: OnceLock<()>,
    /// How many messages a search matched.
    found: OnceLock<usize>,
}

/// Runs the request inside its span, and writes its line and counts it once
/// it is answered.
pub async fn log(State(metrics): State<Metrics>, mut request: Request, next: Next) -> Response {
    let start = Instant::now();
    let id = uuid::Uuid::new_v4().simple().to_string();
    let method = method_name(request.method());
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|path| path.as_str().to_owned());
    let span =
        tracing::error_span!(target: "postkeep::request", "request", request_id = id.as_str());
    let note = Note(Arc::new(Noted {
        span: span.clone(),
        principal: OnceLock::new(),
        tenant: OnceLock::new(),
        tool: OnceLock::new(),
        outcome: OnceLock::new(),
        send_refused: OnceLock::new(),
        held: OnceLock::new(),
        found: OnceLock::new(),
    }));
    request.extensions_mut().insert(note.clone());
    let response = next.run(request).instrument(span).await;
    let elapsed = start.elapsed();
    let ms = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let noted = &note.0;
    let status = response.status().as_u16();
    metrics.answered(route.as_deref(), status, elapsed);
    if let Some(outcome) = noted.outcome.get().copied() {
        metrics.tool_call(noted.tool.get().map(String::as_str), outcome);
    }
    tracing::info!(
        target: "postkeep::request_log",
        request_id = id.as_str(),
        method,
        route = route.as_deref(),
        status,
        ms,
        principal = noted.principal.get().map(String::as_str),
        tenant = noted.tenant.get().map(String::as_str),
        tool = noted.tool.get().map(String::as_str),
        outcome = noted.outcome.get().copied(),
        "answered a request"
    );
    response
}

/// Notes the caller once the bearer check let the request through. It
/// refuses nothing.
pub async fn note_caller(request: Request, next: Next) -> Response {
    let extensions = request.extensions();
    if let (Some(note), Some(caller)) =
        (extensions.get::<Note>(), extensions.get::<Authenticated>())
    {
        let _ = note.0.principal.set(caller.principal.clone());
        let _ = note.0.tenant.set(caller.tenant.clone());
    }
    next.run(request).await
}

impl Note {
    /// The note of the request whose parts rmcp hands a tool call.
    pub fn of(parts: Option<&Parts>) -> Option<Self> {
        parts?.extensions.get::<Self>().cloned()
    }

    /// The request's span.
    pub fn span(&self) -> Span {
        self.0.span.clone()
    }

    /// Notes the called tool, which must be a real one.
    pub fn tool(&self, name: &str) {
        let _ = self.0.tool.set(name.to_owned());
    }

    /// Notes that the usage hook refused the call's message.
    pub fn send_refused(&self) {
        let _ = self.0.send_refused.set(());
    }

    /// Whether the usage hook refused the call's message.
    pub fn was_send_refused(&self) -> bool {
        self.0.send_refused.get().is_some()
    }

    /// Notes that the call held a message without sending it.
    pub fn held(&self) {
        let _ = self.0.held.set(());
    }

    /// Whether the call held a message without sending it.
    pub fn was_held(&self) -> bool {
        self.0.held.get().is_some()
    }

    /// Notes how many messages a search matched.
    pub fn found(&self, total: usize) {
        let _ = self.0.found.set(total);
    }

    /// How many messages a search matched, once it answered.
    pub fn found_total(&self) -> Option<usize> {
        self.0.found.get().copied()
    }

    /// Notes how the tool call was answered.
    pub fn outcome(&self, answer: &Result<CallToolResponse, ErrorData>) {
        let _ = self.0.outcome.set(outcome_of(answer));
    }
}

/// `tool_error` for a result with `isError`, `rpc_error` for a JSON-RPC
/// error, else `ok`.
pub fn outcome_of(answer: &Result<CallToolResponse, ErrorData>) -> &'static str {
    match answer {
        Ok(CallToolResponse::Complete(result)) if result.is_error == Some(true) => "tool_error",
        Ok(_) => "ok",
        Err(_) => "rpc_error",
    }
}

const METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

/// The method's name when it is a standard one, else `other`, so a client
/// cannot put text of its choosing into the line.
fn method_name(method: &Method) -> &'static str {
    METHODS
        .into_iter()
        .find(|name| *name == method.as_str())
        .unwrap_or("other")
}

#[cfg(test)]
mod tests {
    use axum::http::Method;
    use rmcp::ErrorData;
    use rmcp::model::CallToolResult;

    use super::{METHODS, Note, log, method_name, outcome_of};
    use crate::metrics::Metrics;

    #[test]
    fn outcomes_tell_results_tool_errors_and_rpc_errors_apart() {
        assert_eq!(
            outcome_of(&Ok(CallToolResult::success(vec![]).into())),
            "ok"
        );
        assert_eq!(
            outcome_of(&Ok(CallToolResult::error(vec![]).into())),
            "tool_error"
        );
        assert_eq!(
            outcome_of(&Err(ErrorData::invalid_params("x", None))),
            "rpc_error"
        );
    }

    #[test]
    fn standard_methods_keep_their_name_and_others_are_other() {
        for name in METHODS {
            let method = Method::from_bytes(name.as_bytes()).unwrap();
            assert_eq!(method_name(&method), name);
        }
        let purge = Method::from_bytes(b"PURGE").unwrap();
        assert_eq!(method_name(&purge), "other");
    }

    #[tokio::test]
    async fn the_metrics_count_what_the_request_line_writes() {
        use axum::body::Body;
        use axum::http::Request;
        use axum::routing::{get, post};
        use axum::{Extension, Router, middleware};
        use tower::ServiceExt as _;

        let metrics = Metrics::default();
        let app = Router::new()
            .route("/items/{id}", get(|| async {}))
            .route(
                "/call",
                post(|Extension(note): Extension<Note>| async move {
                    note.tool("list_folders");
                    note.outcome(&Ok(CallToolResult::error(vec![]).into()));
                }),
            )
            .route(
                "/rpc",
                post(|Extension(note): Extension<Note>| async move {
                    note.outcome(&Err(ErrorData::invalid_params("x", None)));
                }),
            )
            .layer(middleware::from_fn_with_state(metrics.clone(), log));
        for (method, path) in [
            (Method::GET, "/items/zzidzz?q=qqtokqq"),
            (Method::GET, "/nothing-zzpathzz"),
            (Method::POST, "/call"),
            (Method::POST, "/rpc"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(request).await.unwrap();
        }
        let text = metrics.render();
        for line in [
            "postkeep_http_requests_total{route=\"/items/{id}\",status=\"200\"} 1\n",
            "postkeep_http_requests_total{route=\"unmatched\",status=\"404\"} 1\n",
            "postkeep_tool_calls_total{tool=\"list_folders\",outcome=\"tool_error\"} 1\n",
            "postkeep_tool_calls_total{tool=\"unknown\",outcome=\"rpc_error\"} 1\n",
        ] {
            assert!(text.contains(line), "{line} missing from\n{text}");
        }
        let tool_samples = text
            .lines()
            .filter(|line| line.starts_with("postkeep_tool_calls_total{"))
            .count();
        assert_eq!(tool_samples, 2, "{text}");
        for secret in ["zzidzz", "qqtokqq", "zzpathzz"] {
            assert!(!text.contains(secret), "{secret} in\n{text}");
        }
    }
}
