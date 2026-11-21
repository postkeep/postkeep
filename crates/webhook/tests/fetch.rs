//! `Deliverer::fetch` against a local TLS server.

use std::time::Duration;

use http::StatusCode;
use postkeep_webhook::testing::{Reply, receiver};
use postkeep_webhook::{FetchError, WebhookUrl};

fn url(text: &str) -> WebhookUrl {
    WebhookUrl::parse(text).unwrap_or_else(|err| unreachable!("{err}"))
}

const LIMIT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn fetch_returns_the_status_headers_and_body() {
    let mut server = receiver(&[]).await;
    server.reply_with([Reply {
        status: 200,
        headers: vec![("Cache-Control".to_owned(), "max-age=600".to_owned())],
        body: br#"{"client_id":"x"}"#.to_vec(),
    }]);
    let fetched = server
        .deliverer
        .fetch(&url(&server.url("/client.json")), 1024, LIMIT)
        .await
        .unwrap_or_else(|err| unreachable!("{err}"));
    assert_eq!(fetched.status, StatusCode::OK);
    assert_eq!(fetched.headers["cache-control"], "max-age=600");
    assert_eq!(&fetched.body[..], br#"{"client_id":"x"}"#);
    let got = server
        .requests
        .recv()
        .await
        .unwrap_or_else(|| unreachable!("no request"));
    assert!(
        got.head.starts_with("GET /client.json HTTP/1.1"),
        "{}",
        got.head
    );
    assert_eq!(got.header("accept"), Some("application/json"));
}

#[tokio::test]
async fn fetch_returns_a_redirect_without_following_it() {
    let mut server = receiver(&[302]).await;
    let fetched = server
        .deliverer
        .fetch(&url(&server.url("/moved")), 1024, LIMIT)
        .await
        .unwrap_or_else(|err| unreachable!("{err}"));
    assert_eq!(fetched.status, StatusCode::FOUND);
    assert!(fetched.headers.contains_key("location"));
    assert!(server.requests.recv().await.is_some());
    assert!(
        server.requests.try_recv().is_err(),
        "the redirect target was requested"
    );
}

#[tokio::test]
async fn fetch_refuses_a_body_over_the_limit() {
    let server = receiver(&[]).await;
    server.reply_with([Reply {
        status: 200,
        headers: Vec::new(),
        body: vec![b'a'; 2048],
    }]);
    let err = server
        .deliverer
        .fetch(&url(&server.url("/big")), 1024, LIMIT)
        .await
        .unwrap_err();
    assert!(
        matches!(err, FetchError::TooLarge { limit: 1024, .. }),
        "{err:?}"
    );
}
