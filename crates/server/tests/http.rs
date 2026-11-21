//! Tests of the HTTP server loop over real TCP connections.

#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use axum::routing::get;
use postkeep::http::{ConnectionLimits, serve};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

async fn start(limits: ConnectionLimits) -> (SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(
        "/peer",
        get(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.ip().to_string() }),
    );
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    tokio::spawn(serve(listener, router, limits, async move {
        stop.cancelled().await;
    }));
    (addr, cancel)
}

async fn read_all(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn serves_requests_with_peer_address() {
    let (addr, cancel) = start(ConnectionLimits::default()).await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_all(&mut stream).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("127.0.0.1"), "{response}");
    cancel.cancel();
}

#[tokio::test]
async fn closes_slow_header_senders() {
    let (addr, cancel) = start(ConnectionLimits {
        header_read_timeout: Duration::from_millis(200),
        ..ConnectionLimits::default()
    })
    .await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET /peer HTTP/1.1\r\nHo").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = stream.write_all(b"st: x\r\n\r\n").await;
    let response = read_all(&mut stream).await;
    assert!(
        !response.contains("200 OK"),
        "the slow request must not be served: {response}"
    );
    cancel.cancel();
}

#[tokio::test]
async fn refuses_connections_over_the_limit() {
    let (addr, cancel) = start(ConnectionLimits {
        max_connections: 1,
        ..ConnectionLimits::default()
    })
    .await;
    let _held = TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = TcpStream::connect(addr).await.unwrap();
    let _ = second
        .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await;
    let response = read_all(&mut second).await;
    assert!(response.is_empty(), "{response}");
    cancel.cancel();
}
