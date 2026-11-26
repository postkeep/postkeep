//! What an embedding can add to the application or leave out of it
//! (`app::Extensions`). With no extensions the application is the one the
//! WP9 pins in `pins.rs` describe.

#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::{get, post};
use http_body_util::BodyExt;
use postkeep::app::{self, AppConfig, Extensions};
use postkeep_auth::{AuthConfig, CredentialVerifier, VerifyFuture};
use postkeep_mail::ImapServer;
use postkeep_store::{MasterKey, Store};
use secrecy::SecretString;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const HOST: &str = "mail.example.com";

struct AcceptAll;

impl CredentialVerifier for AcceptAll {
    fn verify<'a>(
        &'a self,
        _server: &'a ImapServer,
        _email: &'a str,
        _password: &'a SecretString,
    ) -> VerifyFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

async fn app(extensions: Extensions) -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("server.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let config = AppConfig {
        bucket: None,
        auth: AuthConfig::new(&format!("https://{HOST}"), app::MCP_PATH).unwrap(),
        extra_allowed_hosts: Vec::new(),
        extra_allowed_origins: Vec::new(),
        limits: app::RequestLimits {
            max_body_bytes: 64 * 1024,
            ..app::RequestLimits::default()
        },
        pool: postkeep::pool::PoolConfig::default(),
        watchers: None,
        upstream: None,
        google_push: None,
    };
    let router = app::router_with(
        config,
        store,
        AcceptAll,
        CancellationToken::new(),
        extensions,
    );
    (router, dir)
}

async fn status(app: &Router, method: Method, path: &str, body: Vec<u8>) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, HOST)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn an_extension_route_is_served_behind_the_request_limits() {
    let routes = Router::new()
        .route("/ext/status", get(|| async { "extension ok" }))
        .route("/ext/echo", post(|body: String| async move { body }));
    let (app, _dir) = app(Extensions::new().route(routes)).await;

    assert_eq!(
        status(&app, Method::GET, "/ext/status", Vec::new()).await,
        (StatusCode::OK, "extension ok".to_owned())
    );
    assert_eq!(
        status(&app, Method::POST, "/ext/echo", b"hi".to_vec()).await,
        (StatusCode::OK, "hi".to_owned())
    );
    // The application's body limit (64 KiB here) applies to extension routes.
    let (code, _) = status(&app, Method::POST, "/ext/echo", vec![b'a'; 65 * 1024]).await;
    assert_eq!(code, StatusCode::PAYLOAD_TOO_LARGE);
    // The built-in routes are still there.
    assert_eq!(
        status(&app, Method::GET, "/", Vec::new()).await.0,
        StatusCode::OK
    );
    assert_eq!(
        status(&app, Method::GET, "/account", Vec::new()).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_default_pages_can_be_turned_off() {
    let (app, _dir) = app(Extensions::new().default_pages(false)).await;
    for (method, path) in [
        (Method::GET, "/"),
        (Method::GET, "/account"),
        (Method::POST, "/account/sign-in"),
        (Method::POST, "/account/delete"),
        (Method::POST, "/account/webhook"),
        (Method::POST, "/account/webhook/filters/add"),
        (Method::POST, "/account/webhook/filters/edit"),
        (Method::POST, "/account/webhook/filters/remove"),
        (Method::POST, "/account/webhook/filters/enabled"),
        (Method::POST, "/oauth/microsoft/start"),
        (Method::POST, "/oauth/google/start"),
    ] {
        assert_eq!(
            status(&app, method.clone(), path, Vec::new()).await.0,
            StatusCode::NOT_FOUND,
            "{method} {path}"
        );
    }
    // Everything an MCP client needs stays.
    for (method, path, expected) in [
        (Method::GET, "/healthz", StatusCode::OK),
        (Method::GET, "/readyz", StatusCode::OK),
        (
            Method::GET,
            "/.well-known/oauth-authorization-server",
            StatusCode::OK,
        ),
        (
            Method::GET,
            "/.well-known/oauth-protected-resource/mcp",
            StatusCode::OK,
        ),
        (Method::GET, "/authorize", StatusCode::BAD_REQUEST),
        (Method::POST, "/register", StatusCode::BAD_REQUEST),
        (Method::POST, "/token", StatusCode::BAD_REQUEST),
        (Method::POST, "/mcp", StatusCode::UNAUTHORIZED),
    ] {
        assert_eq!(
            status(&app, method.clone(), path, Vec::new()).await.0,
            expected,
            "{method} {path}"
        );
    }
}

#[tokio::test]
async fn an_embedding_can_replace_the_landing_page() {
    let routes = Router::new().route("/", get(|| async { "my landing page" }));
    let (app, _dir) = app(Extensions::new().default_pages(false).route(routes)).await;
    assert_eq!(
        status(&app, Method::GET, "/", Vec::new()).await,
        (StatusCode::OK, "my landing page".to_owned())
    );
}
