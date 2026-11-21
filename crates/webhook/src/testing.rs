//! **Tests only.** A local HTTPS receiver with a throwaway certificate, and
//! a [`Deliverer`] that trusts it. Enabled by the `testing` feature, which
//! only dev-dependencies turn on.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, PoisonError};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

use crate::Deliverer;

/// The host name the receiver's certificate is issued for.
pub const HOST: &str = "hooks.test";

/// A request the receiver got.
#[derive(Debug, Clone)]
pub struct Received {
    /// Request line and headers.
    pub head: String,
    /// The body.
    pub body: Vec<u8>,
}

impl Received {
    /// A header value, case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    /// The body as JSON (`Null` if it isn't JSON).
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or_default()
    }
}

/// A response the receiver sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The HTTP status.
    pub status: u16,
    /// Extra headers.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

impl Reply {
    /// `status` with the body `ok`. A redirect also gets a `Location`.
    #[must_use]
    pub fn status(status: u16) -> Self {
        let headers = if (300..400).contains(&status) {
            vec![("Location".to_owned(), format!("https://{HOST}/elsewhere"))]
        } else {
            Vec::new()
        };
        Self {
            status,
            headers,
            body: b"ok".to_vec(),
        }
    }
}

/// A running receiver.
#[derive(Debug)]
pub struct Receiver {
    /// Its port on 127.0.0.1.
    pub port: u16,
    /// Requests in arrival order.
    pub requests: mpsc::UnboundedReceiver<Received>,
    /// A deliverer that trusts the receiver and resolves [`HOST`] to it.
    pub deliverer: Deliverer,
    certificate: CertificateDer<'static>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
}

impl Receiver {
    /// The receiver's URL for `path`.
    #[must_use]
    pub fn url(&self, path: &str) -> String {
        format!("https://{HOST}:{}{path}", self.port)
    }

    /// Queues statuses for the next responses (after which it answers 200).
    pub fn respond_with(&self, statuses: &[u16]) {
        self.reply_with(statuses.iter().map(|&status| Reply::status(status)));
    }

    /// Queues whole responses for the next requests (after which it answers 200).
    pub fn reply_with(&self, replies: impl IntoIterator<Item = Reply>) {
        self.replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(replies);
    }

    /// The receiver's certificate.
    #[must_use]
    pub fn certificate(&self) -> CertificateDer<'static> {
        self.certificate.clone()
    }
}

/// Starts a receiver on 127.0.0.1 answering `statuses` in turn, then 200.
///
/// # Panics
///
/// Panics if the certificate can't be generated or the port can't be bound.
#[expect(clippy::unwrap_used, reason = "test helper")]
pub async fn receiver(statuses: &[u16]) -> Receiver {
    let certified = rcgen::generate_simple_self_signed(vec![HOST.to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let listener = TcpListener::bind((loopback, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let replies = Arc::new(Mutex::new(
        statuses
            .iter()
            .map(|&status| Reply::status(status))
            .collect::<VecDeque<_>>(),
    ));
    let (tx, requests) = mpsc::unbounded_channel();
    let queue = replies.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let queue = queue.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Some(received) = read_request(&mut stream).await else {
                    return;
                };
                let reply = queue
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pop_front()
                    .unwrap_or_else(|| Reply::status(200));
                let _ = tx.send(received);
                let mut head = format!("HTTP/1.1 {} X\r\n", reply.status);
                for (name, value) in &reply.headers {
                    let _ = write!(head, "{name}: {value}\r\n");
                }
                let _ = write!(
                    head,
                    "Content-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&reply.body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Receiver {
        port,
        requests,
        deliverer: Deliverer::for_tests(certificate.clone(), HOST, loopback),
        certificate,
        replies,
    }
}

async fn read_request<S: AsyncReadExt + Unpin>(stream: &mut S) -> Option<Received> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(at) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
    let length = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    while buffer.len() < head_end + length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Some(Received {
        head,
        body: buffer[head_end..].to_vec(),
    })
}
