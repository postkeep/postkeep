//! A small HTTPS client for the provider APIs.
//!
//! Requests go to the fixed provider endpoints in [`Endpoints`], never to
//! URLs taken from user input. An Outlook attachment session returns its own
//! upload URL, which must match [`Endpoints::outlook_uploads`] by origin.
//! The webhook crate's private-address filtering is not needed here.
//! Responses are size-limited, every request
//! has a timeout, redirects are not followed and TLS is verified against the
//! Mozilla roots. Plain HTTP is refused unless the client was built with
//! [`Http::for_tests`].

use std::future::Future;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use url::Url;

/// Default time allowed for one request, from connect to the last body byte.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default response size limit: JSON responses are small.
pub const JSON_LIMIT: usize = 2 * 1024 * 1024;

/// Response size limit for raw messages (Graph `$value`, Gmail `raw`).
pub const MESSAGE_LIMIT: usize = 48 * 1024 * 1024;

/// An HTTP failure before a complete response arrived.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// No request was started because the call's time budget was used up.
    #[error("{DEADLINE_REASON}")]
    Deadline,

    /// The request could not be built.
    #[error("invalid request: {0}")]
    Request(String),
    /// No request reached the provider because connecting failed.
    #[error("could not reach {0}: connection failed")]
    Connect(String),
    /// The exchange failed after a connection was established.
    #[error("could not reach {host}: {reason}")]
    Transport {
        /// The host.
        host: String,
        /// What went wrong, without request data.
        reason: String,
    },
    /// The response body was larger than allowed.
    #[error("the response from {0} was too large")]
    TooLarge(String),
    /// The request did not complete in time.
    #[error("{0} did not answer in time")]
    Timeout(String),
}

/// Why a request was left unsent after a call's deadline.
pub const DEADLINE_REASON: &str = "the call's time budget was used up";

/// Checks the shared request-start boundary, without canceling work in flight.
///
/// # Errors
///
/// Returns [`HttpError::Deadline`] when the deadline has passed.
pub fn check_deadline(deadline: Option<Instant>) -> Result<(), HttpError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(HttpError::Deadline);
    }
    Ok(())
}

/// A complete response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// Status code.
    pub status: StatusCode,
    /// Headers.
    pub headers: HeaderMap,
    /// Body.
    pub body: Bytes,
}

impl HttpResponse {
    /// Whether the status is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status.is_success()
    }

    /// Parses the body as JSON.
    ///
    /// # Errors
    ///
    /// Returns the parse error.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

/// The provider endpoints. The defaults are the public services; tests
/// point them at a local mock server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    /// Microsoft identity platform, `https://login.microsoftonline.com`.
    pub microsoft_login: Url,
    /// Microsoft Graph v1.0, `https://graph.microsoft.com/v1.0`.
    pub graph: Url,
    /// Outlook's attachment upload origin, `https://outlook.office.com`.
    pub outlook_uploads: Url,
    /// Google's authorization endpoint host, `https://accounts.google.com`.
    pub google_accounts: Url,
    /// Google's token and revocation host, `https://oauth2.googleapis.com`.
    pub google_oauth: Url,
    /// Gmail API, `https://gmail.googleapis.com`.
    pub gmail: Url,
    /// Google's OAuth signing keys (JWKS),
    /// `https://www.googleapis.com/oauth2/v3/certs`.
    pub google_certs: Url,
}

impl Default for Endpoints {
    fn default() -> Self {
        let parse = |url: &str| {
            Url::parse(url).unwrap_or_else(|_| unreachable!("static endpoint URLs are valid"))
        };
        Self {
            microsoft_login: parse("https://login.microsoftonline.com"),
            graph: parse("https://graph.microsoft.com/v1.0"),
            outlook_uploads: parse("https://outlook.office.com"),
            google_accounts: parse("https://accounts.google.com"),
            google_oauth: parse("https://oauth2.googleapis.com"),
            gmail: parse("https://gmail.googleapis.com"),
            google_certs: parse("https://www.googleapis.com/oauth2/v3/certs"),
        }
    }
}

impl Endpoints {
    /// Every endpoint under one base URL, for tests against a mock server.
    #[must_use]
    pub fn all_at(base: &Url) -> Self {
        let join = |path: &str| {
            let mut url = base.clone();
            url.set_path(path);
            url
        };
        Self {
            microsoft_login: join("/microsoft"),
            graph: join("/graph/v1.0"),
            outlook_uploads: join("/outlook-uploads"),
            google_accounts: join("/google-accounts"),
            google_oauth: join("/google-oauth"),
            gmail: join("/gmail"),
            google_certs: join("/google-certs"),
        }
    }
}

/// Appends path segments to `base`, percent-encoding each one.
#[must_use]
pub fn join_segments(base: &Url, segments: &[&str]) -> Url {
    let mut url = base.clone();
    if let Ok(mut path) = url.path_segments_mut() {
        path.pop_if_empty();
        path.extend(segments);
    }
    url
}

/// The client. Cheap to clone; connections are pooled.
#[derive(Clone)]
pub struct Http {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    user_agent: http::HeaderValue,
    timeout: Duration,
    deadline: Option<Instant>,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Http {
    /// An HTTPS-only client trusting the Mozilla roots.
    #[must_use]
    pub fn new(user_agent: &str) -> Self {
        Self::build(user_agent, false)
    }

    /// **Tests only.** Also allows plain HTTP, for a local mock server.
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests() -> Self {
        Self::build("postkeep-test", true)
    }

    fn build(user_agent: &str, allow_http: bool) -> Self {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots_compat());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| unreachable!("ring supports the default protocol versions"))
            .with_root_certificates(roots)
            .with_no_client_auth();
        let builder = HttpsConnectorBuilder::new().with_tls_config(config);
        let connector = if allow_http {
            builder.https_or_http().enable_http1().build()
        } else {
            builder.https_only().enable_http1().build()
        };
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(8)
            .build(connector);
        Self {
            client,
            user_agent: http::HeaderValue::from_str(user_agent)
                .unwrap_or_else(|_| http::HeaderValue::from_static("postkeep")),
            timeout: REQUEST_TIMEOUT,
            deadline: None,
        }
    }

    pub(crate) const fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
    }

    /// Only local admission waits, never an HTTP exchange or a token rotation.
    pub(crate) async fn wait<T>(&self, wait: impl Future<Output = T>) -> Result<T, HttpError> {
        check_deadline(self.deadline)?;
        let value = match self.deadline {
            Some(deadline) => tokio::time::timeout_at(deadline.into(), wait)
                .await
                .map_err(|_| HttpError::Deadline)?,
            None => wait.await,
        };
        check_deadline(self.deadline)?;
        Ok(value)
    }

    /// Sends `request` and reads at most `limit` body bytes.
    ///
    /// # Errors
    ///
    /// Returns an [`HttpError`] on transport failure, timeout or an oversized body.
    /// For an oversized 4xx or 5xx response, returns its status and headers with
    /// an empty body instead.
    pub async fn send(
        &self,
        request: Request<Full<Bytes>>,
        limit: usize,
    ) -> Result<HttpResponse, HttpError> {
        self.send_response(request, Some(limit)).await
    }

    /// If the successful body is not needed, keep only status and headers; still read errors.
    pub(super) async fn send_response(
        &self,
        mut request: Request<Full<Bytes>>,
        limit: Option<usize>,
    ) -> Result<HttpResponse, HttpError> {
        let host = request.uri().host().unwrap_or_default().to_owned();
        request
            .headers_mut()
            .entry(http::header::USER_AGENT)
            .or_insert_with(|| self.user_agent.clone());
        check_deadline(self.deadline)?;
        let deadline = tokio::time::Instant::now() + self.timeout;
        let response = tokio::time::timeout_at(deadline, self.client.request(request))
            .await
            .map_err(|_| HttpError::Timeout(host.clone()))?
            .map_err(|err| {
                if err.is_connect() {
                    HttpError::Connect(host.clone())
                } else {
                    HttpError::Transport {
                        host: host.clone(),
                        reason: "the request failed".to_owned(),
                    }
                }
            })?;
        let (parts, body) = response.into_parts();
        let body = if parts.status.is_success() && limit.is_none() {
            Bytes::new()
        } else {
            let body = tokio::time::timeout_at(
                deadline,
                Limited::new(body, limit.unwrap_or(JSON_LIMIT)).collect(),
            )
            .await;
            match body {
                Ok(Ok(body)) => body.to_bytes(),
                Ok(Err(err)) if err.is::<http_body_util::LengthLimitError>() => {
                    if parts.status.is_client_error() || parts.status.is_server_error() {
                        Bytes::new()
                    } else {
                        return Err(HttpError::TooLarge(host));
                    }
                }
                Ok(Err(_)) => {
                    return Err(HttpError::Transport {
                        host,
                        reason: "the connection closed while reading the response".to_owned(),
                    });
                }
                Err(_) => return Err(HttpError::Timeout(host)),
            }
        };
        Ok(HttpResponse {
            status: parts.status,
            headers: parts.headers,
            body,
        })
    }
}

fn webpki_roots_compat() -> impl Iterator<Item = rustls::pki_types::TrustAnchor<'static>> {
    webpki_roots::TLS_SERVER_ROOTS.iter().cloned()
}

/// Builds a request, explicitly framing POST, PUT and PATCH bodies, including empty ones.
///
/// # Errors
///
/// Returns [`HttpError::Request`] if the URL or a header is invalid.
pub fn request(
    method: http::Method,
    url: &Url,
    headers: &[(http::HeaderName, String)],
    body: Bytes,
) -> Result<Request<Full<Bytes>>, HttpError> {
    let mut builder = Request::builder().method(method).uri(url.as_str());
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let len = body.len();
    let mut request = builder
        .body(Full::new(body))
        .map_err(|err| HttpError::Request(err.to_string()))?;
    // Hyper omits the length on empty POSTs; providers can refuse those with HTTP 411.
    if matches!(
        *request.method(),
        http::Method::POST | http::Method::PUT | http::Method::PATCH
    ) {
        request
            .headers_mut()
            .insert(http::header::CONTENT_LENGTH, len.into());
    }
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_and_encodes_segments() {
        let base =
            Url::parse("https://graph.microsoft.com/v1.0").unwrap_or_else(|_| unreachable!());
        let url = join_segments(&base, &["me", "messages", "AAMk/a+b=="]);
        assert_eq!(
            url.as_str(),
            "https://graph.microsoft.com/v1.0/me/messages/AAMk%2Fa+b=="
        );
        let trailing = Url::parse("https://example.com/base/").unwrap_or_else(|_| unreachable!());
        assert_eq!(
            join_segments(&trailing, &["x"]).as_str(),
            "https://example.com/base/x"
        );
    }

    #[test]
    fn endpoints_for_tests_share_one_base() {
        let base = Url::parse("http://127.0.0.1:9999").unwrap_or_else(|_| unreachable!());
        let endpoints = Endpoints::all_at(&base);
        assert_eq!(endpoints.graph.as_str(), "http://127.0.0.1:9999/graph/v1.0");
        assert_ne!(endpoints, Endpoints::default());
    }

    #[tokio::test]
    async fn https_only_client_refuses_plain_http() {
        let http = Http::new("postkeep-test");
        let url = Url::parse("http://127.0.0.1:9/").unwrap_or_else(|_| unreachable!());
        let request =
            request(http::Method::GET, &url, &[], Bytes::new()).unwrap_or_else(|_| unreachable!());
        assert!(http.send(request, JSON_LIMIT).await.is_err());
    }

    #[tokio::test]
    async fn sends_content_length_on_the_wire_for_body_methods() {
        use http::Method;
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let http = Http::for_tests();
        for (method, body, expected) in [
            (Method::POST, "", Some("0")),
            (Method::PUT, "", Some("0")),
            (Method::PATCH, "", Some("0")),
            (Method::POST, "é", Some("2")),
            (Method::GET, "", None),
            (Method::HEAD, "", None),
            (Method::DELETE, "", None),
        ] {
            let request = request(
                method.clone(),
                &url,
                &[],
                Bytes::from_static(body.as_bytes()),
            )
            .unwrap();
            let peer = async {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut lengths = Vec::new();
                loop {
                    let mut line = String::new();
                    assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        lengths.push(value.trim().to_owned());
                    }
                }
                stream
                    .get_mut()
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                lengths
            };
            let (answer, lengths) = tokio::join!(http.send(request, JSON_LIMIT), peer);
            assert_eq!(answer.unwrap().status, StatusCode::NO_CONTENT);
            assert_eq!(
                lengths,
                expected.into_iter().collect::<Vec<_>>(),
                "{method}"
            );
        }
    }

    #[tokio::test]
    async fn preserves_oversized_refusals_but_reports_exchange_failures() {
        use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
        use tokio::net::TcpListener;

        const PARTIAL_REFUSAL: &str = "HTTP/1.1 403 Forbidden\r\nContent-Length: 100\r\n\r\n{";

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let url = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let http = Http::for_tests();
        let post = || request(http::Method::POST, &url, &[], Bytes::new()).unwrap();
        let (release, hold) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            for (answer, stall) in [
                (
                    "HTTP/1.1 413 Content Too Large\r\nContent-Length: 2\r\n\r\n{}",
                    false,
                ),
                ("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", false),
                (PARTIAL_REFUSAL, false),
                ("", false),
                (PARTIAL_REFUSAL, true),
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                while stream.read_line(&mut line).await.unwrap() != 0 && line != "\r\n" {
                    line.clear();
                }
                assert_eq!(line, "\r\n", "the POST reached the server");
                stream.get_mut().write_all(answer.as_bytes()).await.unwrap();
                if stall {
                    let _ = hold.await;
                    return;
                }
                stream.get_mut().shutdown().await.unwrap();
            }
        });
        let refused = http.send(post(), 1).await.unwrap();
        assert_eq!(refused.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert!(refused.body.is_empty());
        assert!(matches!(
            http.send(post(), 1).await,
            Err(HttpError::TooLarge(_))
        ));
        let broken = http.send(post(), JSON_LIMIT).await;
        let lost = http.send(post(), JSON_LIMIT).await;
        let http = Http {
            timeout: Duration::from_secs(1),
            ..http
        };
        let stalled = http.send(post(), JSON_LIMIT).await;
        release.send(()).unwrap();
        peer.await.unwrap();
        assert!(matches!(stalled, Err(HttpError::Timeout(_))), "{stalled:?}");
        assert!(
            matches!(broken, Err(HttpError::Transport { .. })),
            "{broken:?}"
        );
        assert!(matches!(lost, Err(HttpError::Transport { .. })), "{lost:?}");
        assert!(matches!(
            http.send(post(), JSON_LIMIT).await,
            Err(HttpError::Connect(_))
        ));
    }
}
