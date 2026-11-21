//! The HTTP server loop: hyper with a header read timeout, a connection
//! limit and graceful shutdown.
//!
//! `axum::serve` sets no header read timeout, so a client could hold a
//! connection open forever by sending a request's headers one byte at a
//! time (slowloris). This loop sets one and caps open connections.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt;

/// Connection-level limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// Open connections; further connections are closed right away.
    pub max_connections: usize,
    /// Time allowed to receive a request's headers.
    pub header_read_timeout: Duration,
    /// Time in-flight requests get to finish after shutdown starts.
    pub shutdown_grace: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            header_read_timeout: Duration::from_secs(15),
            shutdown_grace: Duration::from_secs(10),
        }
    }
}

/// Serves `router` on `listener` until `shutdown` completes, then waits up
/// to [`ConnectionLimits::shutdown_grace`] for open connections.
///
/// Each request carries [`ConnectInfo<SocketAddr>`] with the peer address.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    limits: ConnectionLimits,
    shutdown: impl Future<Output = ()>,
) {
    let connections = Arc::new(Semaphore::new(limits.max_connections.max(1)));
    let graceful = GracefulShutdown::new();
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .keep_alive(true);
    let mut shutdown = std::pin::pin!(shutdown);
    let mut refused: u64 = 0;

    loop {
        let (stream, peer) = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // Usually EMFILE or a reset during the handshake; back
                    // off briefly instead of spinning.
                    tracing::warn!(error = %err, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            refused += 1;
            if refused.is_power_of_two() {
                tracing::warn!(refused, "connection limit reached; closing new connections");
            }
            drop(stream);
            continue;
        };
        if let Err(err) = stream.set_nodelay(true) {
            tracing::debug!(error = %err, "could not set TCP_NODELAY");
        }
        let service = router.clone().map_request(
            move |mut request: axum::extract::Request<hyper::body::Incoming>| {
                request.extensions_mut().insert(ConnectInfo(peer));
                request.map(axum::body::Body::new)
            },
        );
        let service = TowerToHyperService::new(service.map_err(|err: Infallible| match err {}));
        let connection = builder.serve_connection(TokioIo::new(stream), service);
        let connection = graceful.watch(connection);
        tokio::spawn(async move {
            if let Err(err) = connection.await {
                tracing::trace!(error = %err, "connection ended with an error");
            }
            drop(permit);
        });
    }

    drop(listener);
    tokio::select! {
        () = graceful.shutdown() => {}
        () = tokio::time::sleep(limits.shutdown_grace) => {
            tracing::warn!("open connections did not finish in time");
        }
    }
}

/// The peer address type inserted into requests.
pub type Peer = ConnectInfo<SocketAddr>;
