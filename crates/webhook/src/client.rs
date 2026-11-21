//! A minimal HTTPS client that only talks to public addresses.
//!
//! Each delivery resolves the host, refuses it if *any* resolved address is
//! not public (see [`crate::ip`]), and then connects to one of the vetted
//! addresses directly, so a second DNS answer can't redirect the request
//! (DNS rebinding). TLS is verified against the Mozilla roots with the
//! URL's host name. Redirects are never followed and every step has a short
//! timeout. A delivery reads nothing from the response but its status line;
//! [`Deliverer::fetch`] reads a body up to a size limit.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_TYPE, HOST, USER_AGENT};
use http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::WebhookUrl;
use crate::ip;

/// Time allowed for a DNS lookup.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(3);
/// Time allowed for one TCP connection attempt.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Time allowed for a whole delivery attempt, from lookup to status line.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Resolved addresses tried per attempt.
const MAX_ADDRESSES: usize = 3;

/// Why an attempt failed before a response arrived.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeliveryError {
    /// The host is, or resolves to, a non-public address.
    #[error("{0} resolves to a private, loopback, link-local or metadata address")]
    Blocked(String),
    /// The host name did not resolve.
    #[error("could not resolve {0}")]
    Resolve(String),
    /// No TCP connection could be made.
    #[error("could not connect to {0}")]
    Connect(String),
    /// The TLS handshake failed, for example on an invalid certificate.
    #[error("TLS handshake with {host} failed: {reason}")]
    Tls {
        /// The host.
        host: String,
        /// What went wrong.
        reason: String,
    },
    /// The HTTP exchange failed.
    #[error("HTTP error from {host}: {reason}")]
    Http {
        /// The host.
        host: String,
        /// What went wrong.
        reason: String,
    },
    /// The attempt took longer than [`ATTEMPT_TIMEOUT`].
    #[error("{0} did not answer within 10 seconds")]
    Timeout(String),
}

impl DeliveryError {
    /// Whether trying again later could succeed.
    #[must_use]
    pub const fn is_transient(&self) -> bool {
        !matches!(self, Self::Blocked(_))
    }
}

/// A response's status and how long it took to arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status.
    pub status: StatusCode,
    /// Time from the start of the attempt to the status line.
    pub elapsed: Duration,
}

/// One request to deliver.
#[derive(Debug, Clone)]
pub struct Outgoing {
    /// Where to send it.
    pub url: WebhookUrl,
    /// Extra headers (signature, id, auth header).
    pub headers: HeaderMap,
    /// The JSON body.
    pub body: Bytes,
}

/// Sends webhook requests. Cheap to clone.
#[derive(Clone)]
pub struct Deliverer {
    tls: TlsConnector,
    user_agent: HeaderValue,
    allow_loopback: bool,
    overrides: Arc<HashMap<String, Vec<IpAddr>>>,
}

impl std::fmt::Debug for Deliverer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deliverer").finish_non_exhaustive()
    }
}

impl Deliverer {
    /// A deliverer trusting the Mozilla root certificates.
    #[must_use]
    pub fn new(user_agent: &str) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(user_agent, roots)
    }

    fn with_roots(user_agent: &str, roots: rustls::RootCertStore) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap_or_else(|_| unreachable!("ring supports the default protocol versions"))
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            tls: TlsConnector::from(Arc::new(config)),
            user_agent: HeaderValue::from_str(user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static("postkeep")),
            allow_loopback: false,
            overrides: Arc::default(),
        }
    }

    /// **Tests only.** Trusts `certificate` instead of the public roots,
    /// allows loopback addresses and resolves `host` to `ip`. Never use this
    /// in a server: it disables the loopback part of the SSRF protection.
    #[doc(hidden)]
    #[must_use]
    pub fn for_tests(certificate: CertificateDer<'static>, host: &str, ip: IpAddr) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(certificate)
            .unwrap_or_else(|_| unreachable!("test certificate must parse"));
        let mut deliverer = Self::with_roots("postkeep-test", roots);
        deliverer.allow_loopback = true;
        deliverer.overrides = Arc::new(HashMap::from([(host.to_owned(), vec![ip])]));
        deliverer
    }

    fn allowed(&self, ip: IpAddr) -> bool {
        ip::is_public(ip) || (self.allow_loopback && ip.is_loopback())
    }

    /// Makes one attempt. Any HTTP status counts as a response; only
    /// failures before the status line are errors.
    ///
    /// # Errors
    ///
    /// Returns a [`DeliveryError`] if the host is blocked or unreachable,
    /// TLS fails, or the attempt times out.
    pub async fn send(&self, request: &Outgoing) -> Result<Response, DeliveryError> {
        let started = Instant::now();
        let host = request.url.host();
        let status = timeout(ATTEMPT_TIMEOUT, self.exchange(request, &host))
            .await
            .map_err(|_| DeliveryError::Timeout(host.clone()))??;
        Ok(Response {
            status,
            elapsed: started.elapsed(),
        })
    }

    async fn resolve(
        &self,
        url: &WebhookUrl,
        host: &str,
    ) -> Result<Vec<SocketAddr>, DeliveryError> {
        let port = url.port();
        let addrs: Vec<SocketAddr> = if let Some(ip) = url.ip() {
            vec![SocketAddr::new(ip, port)]
        } else if let Some(ips) = self.overrides.get(host) {
            ips.iter().map(|&ip| SocketAddr::new(ip, port)).collect()
        } else {
            timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host((host, port)))
                .await
                .map_err(|_| DeliveryError::Resolve(host.to_owned()))?
                .map_err(|_| DeliveryError::Resolve(host.to_owned()))?
                .collect()
        };
        if addrs.is_empty() {
            return Err(DeliveryError::Resolve(host.to_owned()));
        }
        // One bad answer taints the name: refuse rather than pick the
        // public ones, so a split answer can't be used to probe.
        if addrs.iter().any(|addr| !self.allowed(addr.ip())) {
            return Err(DeliveryError::Blocked(host.to_owned()));
        }
        Ok(addrs)
    }

    async fn connect(addrs: &[SocketAddr], host: &str) -> Result<TcpStream, DeliveryError> {
        for addr in addrs.iter().take(MAX_ADDRESSES) {
            if let Ok(Ok(stream)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
        }
        Err(DeliveryError::Connect(host.to_owned()))
    }

    /// Resolves, connects and completes the TLS and HTTP/1.1 handshakes.
    /// The returned task drives the connection; abort it when done.
    async fn open(
        &self,
        url: &WebhookUrl,
        host: &str,
    ) -> Result<
        (
            hyper::client::conn::http1::SendRequest<Full<Bytes>>,
            tokio::task::JoinHandle<()>,
        ),
        DeliveryError,
    > {
        let addrs = self.resolve(url, host).await?;
        let stream = Self::connect(&addrs, host).await?;

        let server_name = match url.ip() {
            Some(ip) => ServerName::IpAddress(ip.into()),
            None => ServerName::try_from(host.to_owned()).map_err(|err| DeliveryError::Tls {
                host: host.to_owned(),
                reason: err.to_string(),
            })?,
        };
        let tls =
            self.tls
                .connect(server_name, stream)
                .await
                .map_err(|err| DeliveryError::Tls {
                    host: host.to_owned(),
                    reason: err.to_string(),
                })?;

        let http_error = |err: &dyn std::fmt::Display| DeliveryError::Http {
            host: host.to_owned(),
            reason: err.to_string(),
        };
        let (sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(16 * 1024)
            .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
            .await
            .map_err(|err| http_error(&err))?;
        let connection = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok((sender, connection))
    }

    async fn exchange(&self, request: &Outgoing, host: &str) -> Result<StatusCode, DeliveryError> {
        let (mut sender, connection) = self.open(&request.url, host).await?;
        let http_error = |err: &dyn std::fmt::Display| DeliveryError::Http {
            host: host.to_owned(),
            reason: err.to_string(),
        };
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(request.url.path_and_query())
            .header(HOST, request.url.authority())
            .header(CONTENT_TYPE, "application/json")
            .header(USER_AGENT, self.user_agent.clone());
        if let Some(headers) = builder.headers_mut() {
            for (name, value) in &request.headers {
                headers.insert(name, value.clone());
            }
        }
        let outgoing = builder
            .body(Full::new(request.body.clone()))
            .map_err(|err| http_error(&err))?;
        let result = sender.send_request(outgoing).await;
        connection.abort();
        Ok(result.map_err(|err| http_error(&err))?.status())
    }

    /// Fetches `url` with `GET`, under the same address rules as
    /// [`send`](Self::send). Redirects are returned, never followed. The
    /// body is read up to `max_body` bytes and the whole fetch must finish
    /// within `limit`.
    ///
    /// # Errors
    ///
    /// Returns a [`FetchError`] if the request fails before a response, the
    /// body is larger than `max_body`, or the fetch takes longer than `limit`.
    pub async fn fetch(
        &self,
        url: &WebhookUrl,
        max_body: usize,
        limit: Duration,
    ) -> Result<Fetched, FetchError> {
        let host = url.host();
        timeout(limit, self.get(url, &host, max_body))
            .await
            .map_err(|_| FetchError::Timeout(host.clone()))?
    }

    async fn get(
        &self,
        url: &WebhookUrl,
        host: &str,
        max_body: usize,
    ) -> Result<Fetched, FetchError> {
        let (mut sender, connection) = self.open(url, host).await?;
        let http_error = |err: &dyn std::fmt::Display| {
            FetchError::Request(DeliveryError::Http {
                host: host.to_owned(),
                reason: err.to_string(),
            })
        };
        let request = Request::builder()
            .method(Method::GET)
            .uri(url.path_and_query())
            .header(HOST, url.authority())
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, self.user_agent.clone())
            .body(Full::new(Bytes::new()))
            .map_err(|err| http_error(&err))?;
        let result = async {
            let response = sender
                .send_request(request)
                .await
                .map_err(|err| http_error(&err))?;
            let (parts, body) = response.into_parts();
            let body = Limited::new(body, max_body)
                .collect()
                .await
                .map_err(|err| {
                    if err.is::<LengthLimitError>() {
                        FetchError::TooLarge {
                            host: host.to_owned(),
                            limit: max_body,
                        }
                    } else {
                        http_error(&err)
                    }
                })?
                .to_bytes();
            Ok(Fetched {
                status: parts.status,
                headers: parts.headers,
                body,
            })
        }
        .await;
        connection.abort();
        result
    }
}

/// A response read by [`Deliverer::fetch`].
#[derive(Debug, Clone)]
pub struct Fetched {
    /// The HTTP status. A redirect is returned as is.
    pub status: StatusCode,
    /// The response headers.
    pub headers: HeaderMap,
    /// The body, at most the requested size.
    pub body: Bytes,
}

/// Why [`Deliverer::fetch`] failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FetchError {
    /// The request failed before a response arrived.
    #[error(transparent)]
    Request(#[from] DeliveryError),
    /// The body was larger than allowed.
    #[error("the response from {host} is larger than {limit} bytes")]
    TooLarge {
        /// The host.
        host: String,
        /// The largest body accepted, in bytes.
        limit: usize,
    },
    /// The fetch took longer than allowed.
    #[error("{0} did not answer in time")]
    Timeout(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolving(host: &str, ips: &[&str], allow_loopback: bool) -> Deliverer {
        let mut deliverer = Deliverer::new("test");
        deliverer.allow_loopback = allow_loopback;
        let ips = ips
            .iter()
            .map(|ip| {
                ip.parse()
                    .unwrap_or_else(|_| unreachable!("bad test address"))
            })
            .collect();
        deliverer.overrides = Arc::new(HashMap::from([(host.to_owned(), ips)]));
        deliverer
    }

    fn url(text: &str) -> WebhookUrl {
        WebhookUrl::parse(text).unwrap_or_else(|err| unreachable!("{err}"))
    }

    #[tokio::test]
    async fn names_resolving_to_internal_addresses_are_blocked() {
        for ips in [
            &["127.0.0.1"][..],
            &["169.254.169.254"],
            &["10.0.0.1"],
            &["fdaa::3"],
            &["::ffff:192.168.0.1"],
            // A single internal answer taints the whole name.
            &["1.1.1.1", "127.0.0.1"],
            &["2606:4700::1", "fd00:ec2::254"],
        ] {
            let deliverer = resolving("hooks.example.com", ips, false);
            let request = Outgoing {
                url: url("https://hooks.example.com/hook"),
                headers: HeaderMap::new(),
                body: Bytes::new(),
            };
            assert_eq!(
                deliverer.send(&request).await,
                Err(DeliveryError::Blocked("hooks.example.com".into())),
                "{ips:?}"
            );
        }
        // A fetch is held to the same rule.
        let deliverer = resolving("clients.example.com", &["10.0.0.1"], false);
        assert_eq!(
            deliverer
                .fetch(
                    &url("https://clients.example.com/client.json"),
                    1024,
                    Duration::from_secs(5)
                )
                .await
                .unwrap_err(),
            FetchError::Request(DeliveryError::Blocked("clients.example.com".into()))
        );
        // The test-only loopback allowance still refuses everything else.
        let deliverer = resolving("hooks.example.com", &["192.168.1.1"], true);
        let request = Outgoing {
            url: url("https://hooks.example.com/hook"),
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        assert!(matches!(
            deliverer.send(&request).await,
            Err(DeliveryError::Blocked(_))
        ));
    }
}
