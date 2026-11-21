//! End-to-end delivery against a local TLS server.

use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use postkeep_webhook::testing::{HOST, receiver};
use postkeep_webhook::{
    Deliverer, DeliveryError, NewMailEvent, Outgoing, WebhookUrl, deliver, sign,
};

const SHORT: [Duration; 3] = [Duration::from_millis(10); 3];

fn request(url: &str) -> Outgoing {
    Outgoing {
        url: WebhookUrl::parse(url).unwrap_or_else(|err| unreachable!("{err}")),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"{}"),
    }
}

#[tokio::test]
async fn delivers_a_signed_event() {
    let mut server = receiver(&[]).await;
    let secret = sign::generate_secret().unwrap_or_else(|err| unreachable!("{err}"));
    let auth = postkeep_webhook::AuthHeader::new("Authorization", "Bearer xyz")
        .unwrap_or_else(|err| unreachable!("{err}"));
    let event = NewMailEvent::sample("me@icloud.com");
    let url =
        WebhookUrl::parse(&server.url("/hook?key=1")).unwrap_or_else(|err| unreachable!("{err}"));
    let request = event.request(url, "event-1", 1_700_000_000, Some(&auth), Some(&secret));

    let delivery = deliver(&server.deliverer, &request, &SHORT).await;
    assert!(delivery.succeeded(), "{}", delivery.summary());
    assert_eq!(delivery.attempts, 1);

    let got = server
        .requests
        .recv()
        .await
        .unwrap_or_else(|| unreachable!());
    assert!(
        got.head.starts_with("POST /hook?key=1 HTTP/1.1\r\n"),
        "{}",
        got.head
    );
    assert_eq!(
        got.header("host"),
        Some(format!("{HOST}:{}", server.port).as_str())
    );
    assert_eq!(got.header("content-type"), Some("application/json"));
    assert_eq!(got.header("authorization"), Some("Bearer xyz"));
    assert_eq!(got.header("x-webhook-id"), Some("event-1"));
    assert_eq!(got.header("x-webhook-event"), Some("new_mail"));
    assert_eq!(got.json()["test"], true);
    let signature = got.header("x-signature-256").unwrap_or_default();
    let stamp: i64 = got
        .header("x-webhook-timestamp")
        .and_then(|v| v.parse().ok())
        .unwrap_or_default();
    assert!(sign::verify(
        &secret,
        stamp,
        &got.body,
        signature,
        1_700_000_010,
        300
    ));
}

#[tokio::test]
async fn retries_transient_failures_with_backoff() {
    let mut server = receiver(&[503, 429, 408]).await;
    let delivery = deliver(&server.deliverer, &request(&server.url("/")), &SHORT).await;
    assert!(delivery.succeeded(), "{}", delivery.summary());
    assert_eq!(delivery.attempts, 4);
    for _ in 0..4 {
        assert!(server.requests.recv().await.is_some());
    }

    // Gives up after the last delay.
    server.respond_with(&[500, 500, 500, 500, 500]);
    let delivery = deliver(&server.deliverer, &request(&server.url("/")), &SHORT).await;
    assert!(!delivery.succeeded());
    assert_eq!(delivery.attempts, 4);
    assert_eq!(
        delivery.summary(),
        "HTTP 500 Internal Server Error (after 4 attempts)"
    );
}

#[tokio::test]
async fn client_errors_and_redirects_are_final() {
    for status in [401, 404, 302] {
        let mut server = receiver(&[status]).await;
        let delivery = deliver(&server.deliverer, &request(&server.url("/")), &SHORT).await;
        assert!(!delivery.succeeded());
        assert_eq!(delivery.attempts, 1, "{status}");
        assert!(server.requests.recv().await.is_some());
        // The redirect was not followed: no second request.
        assert!(server.requests.try_recv().is_err());
    }
}

#[tokio::test]
async fn certificates_are_verified() {
    let server = receiver(&[]).await;
    // The certificate does not cover this name.
    let deliverer = Deliverer::for_tests(
        server.certificate(),
        "wrong.test",
        std::net::Ipv4Addr::LOCALHOST.into(),
    );
    let url = format!("https://wrong.test:{}/", server.port);
    let delivery = deliver(&deliverer, &request(&url), &[]).await;
    assert!(
        matches!(delivery.result, Err(DeliveryError::Tls { .. })),
        "{delivery:?}"
    );

    // Untrusted certificate: the public roots don't include it.
    let delivery = deliver(&Deliverer::new("test"), &request(&server.url("/")), &[]).await;
    assert!(!delivery.succeeded());
}

#[tokio::test]
async fn unreachable_hosts_fail_quickly() {
    let server = receiver(&[]).await;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap_or_else(|err| unreachable!("{err}"));
    let port = listener.local_addr().map_or(0, |addr| addr.port());
    drop(listener);
    let url = format!("https://{HOST}:{port}/");
    let delivery = deliver(&server.deliverer, &request(&url), &SHORT).await;
    assert_eq!(delivery.result, Err(DeliveryError::Connect(HOST.into())));
    assert_eq!(delivery.attempts, 4);
}
