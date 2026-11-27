//! Clients identified by an OAuth Client ID Metadata Document, served by a
//! local HTTPS receiver.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use http_body_util::BodyExt;
use postkeep_auth::{AuthConfig, AuthState, CredentialVerifier, VerifyFuture, router};
use postkeep_mail::ImapServer;
use postkeep_store::{MasterKey, Store};
use postkeep_webhook::testing::{Receiver, Reply, receiver};
use secrecy::SecretString;
use serde_json::{Value, json};
use tower::ServiceExt;

const ISSUER: &str = "https://mail.example.com";
const REDIRECT: &str = "http://127.0.0.1/callback";
const EPHEMERAL_REDIRECT: &str = "http://127.0.0.1:38159/callback";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

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

struct Setup {
    app: Router,
    store: Store,
    documents: Receiver,
    client_id: String,
    _dir: tempfile::TempDir,
}

struct Page {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn setup(configure: impl FnOnce(&mut AuthConfig)) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("auth.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let mut config = AuthConfig::new(ISSUER, "/mcp").unwrap();
    configure(&mut config);
    let state = AuthState::new(store.clone(), config, AcceptAll);
    let documents = receiver(&[]).await;
    state.set_client_metadata_fetcher(documents.deliverer.clone());
    let client_id = documents.url("/oauth/client.json");
    Setup {
        app: router(state),
        store,
        documents,
        client_id,
        _dir: dir,
    }
}

fn document(client_id: &str) -> Value {
    json!({
        "client_id": client_id,
        "client_name": "Metadata App",
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    })
}

fn serve(body: &Value, cache_control: &str) -> Reply {
    Reply {
        status: 200,
        headers: vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Cache-Control".to_owned(), cache_control.to_owned()),
        ],
        body: body.to_string().into_bytes(),
    }
}

impl Setup {
    async fn send(&self, request: Request<Body>) -> Page {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        Page {
            status,
            headers,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        }
    }

    async fn authorize(&self, client_id: &str, redirect_uri: &str) -> Page {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs([
                ("response_type", "code"),
                ("client_id", client_id),
                ("redirect_uri", redirect_uri),
                ("code_challenge", CHALLENGE),
                ("code_challenge_method", "S256"),
                ("scope", "mail offline_access"),
                ("resource", &format!("{ISSUER}/mcp")),
            ])
            .finish();
        self.send(
            Request::get(format!("/authorize?{query}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
    }

    async fn form(&self, uri: &str, fields: &[(&str, &str)]) -> Page {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields)
            .finish();
        self.send(
            Request::post(uri)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::ORIGIN, ISSUER)
                .body(Body::from(body))
                .unwrap(),
        )
        .await
    }

    async fn sign_in_for_code(&self, page: &Page, redirect_uri: &str) -> String {
        let marker = "name=\"request_id\" value=\"";
        let start = page.body.find(marker).unwrap() + marker.len();
        let request_id = &page.body[start..start + page.body[start..].find('"').unwrap()];
        let signed_in = self
            .form(
                "/authorize",
                &[
                    ("request_id", request_id),
                    ("email", "user@example.com"),
                    ("password", "abcd-efgh-ijkl-mnop"),
                    ("action", "connect"),
                ],
            )
            .await;
        assert_eq!(
            signed_in.status,
            StatusCode::SEE_OTHER,
            "{}",
            signed_in.body
        );
        let location = signed_in.headers[header::LOCATION].to_str().unwrap();
        assert_eq!(location.split_once('?').unwrap().0, redirect_uri);
        url::Url::parse(location)
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap()
            .1
            .into_owned()
    }

    const fn code_fields<'a>(&'a self, code: &'a str) -> [(&'static str, &'a str); 4] {
        [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", self.client_id.as_str()),
            ("code_verifier", VERIFIER),
        ]
    }

    /// Documents requested from the receiver so far.
    fn fetches(&mut self) -> usize {
        let mut count = 0;
        while self.documents.requests.try_recv().is_ok() {
            count += 1;
        }
        count
    }

    async fn refused(&self, client_id: &str, reply: Option<Reply>, reason: &str) {
        if let Some(reply) = reply {
            self.documents.reply_with([reply]);
        }
        let page = self.authorize(client_id, REDIRECT).await;
        assert_eq!(page.status, StatusCode::BAD_REQUEST, "{}", page.body);
        assert!(page.body.contains(reason), "{reason}: {}", page.body);
        assert!(self.store.client(client_id).await.unwrap().is_none());
    }
}

/// Signs in through the client that `body` describes and exchanges the code
/// with only the PKCE verifier, as a public client.
async fn signs_in_and_gets_tokens(body: impl FnOnce(&str) -> Value) {
    let mut setup = setup(|_| {}).await;
    let client_id = setup.client_id.clone();
    setup
        .documents
        .reply_with([serve(&body(&client_id), "public, max-age=600")]);

    let page = setup.authorize(&client_id, REDIRECT).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert!(page.body.contains("Metadata App"));
    assert!(
        page.body
            .contains("published by <code><bdi>hooks.test</bdi></code>")
    );
    let stored = setup.store.client(&client_id).await.unwrap().unwrap();
    assert!(!stored.confidential);
    assert_eq!(stored.redirect_uris, vec![REDIRECT.to_owned()]);
    assert_eq!(setup.fetches(), 1);

    let code = setup.sign_in_for_code(&page, REDIRECT).await;
    let exchange = setup.code_fields(&code);
    // A client using none must not authenticate (draft-03 section 5): a
    // secret, an assertion or Basic credentials are refused before the code
    // is used.
    let id: String = url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(exchange)
        .finish();
    let basic = Request::post("/token")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::AUTHORIZATION,
            format!("Basic {}", STANDARD.encode(format!("{id}:placeholder"))),
        )
        .body(Body::from(form))
        .unwrap();
    let mut refused = vec![setup.send(basic).await];
    for credential in [
        ("client_secret", "placeholder"),
        ("client_assertion", "placeholder"),
    ] {
        refused.push(
            setup
                .form("/token", &[&exchange[..], &[credential]].concat())
                .await,
        );
    }
    for page in refused {
        assert_eq!(page.status, StatusCode::UNAUTHORIZED, "{}", page.body);
        assert!(page.body.contains("invalid_client"), "{}", page.body);
    }
    let token = setup.form("/token", &exchange).await;
    assert_eq!(token.status, StatusCode::OK, "{}", token.body);
    let token: Value = serde_json::from_str(&token.body).unwrap();
    assert!(token["access_token"].is_string());
    assert!(token["refresh_token"].is_string());

    // Fresh for ten minutes: the next authorization uses the stored client.
    let again = setup.authorize(&client_id, REDIRECT).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
    assert_eq!(setup.fetches(), 0);
}

#[tokio::test]
async fn a_metadata_document_client_signs_in_and_gets_tokens() {
    signs_in_and_gets_tokens(document).await;
}

#[tokio::test]
async fn a_client_that_lists_none_among_its_methods_signs_in_as_a_public_client() {
    // ChatGPT's shape: private_key_jwt is only its preference, and this
    // server does not offer it, so the client uses none.
    signs_in_and_gets_tokens(|client_id| {
        let mut body = document(client_id);
        body["token_endpoint_auth_methods_supported"] = json!(["none", "private_key_jwt"]);
        body["token_endpoint_auth_method"] = json!("private_key_jwt");
        body
    })
    .await;
}

#[tokio::test]
async fn loopback_port_is_flexible_at_authorization_and_bound_at_redemption() {
    let mut setup = setup(|_| {}).await;
    setup
        .documents
        .reply_with([serve(&document(&setup.client_id), "max-age=600")]);
    for (redirect_uri, expected_status) in [
        (
            Some("http://127.0.0.1:9999/callback"),
            StatusCode::BAD_REQUEST,
        ),
        (Some(REDIRECT), StatusCode::BAD_REQUEST),
        (Some(EPHEMERAL_REDIRECT), StatusCode::OK),
        (None, StatusCode::OK),
    ] {
        // A failed redemption consumes the code, so each case signs in again.
        let page = setup.authorize(&setup.client_id, EPHEMERAL_REDIRECT).await;
        assert_eq!(page.status, StatusCode::OK, "{}", page.body);
        let code = setup.sign_in_for_code(&page, EPHEMERAL_REDIRECT).await;
        let mut fields = Vec::from(setup.code_fields(&code));
        fields.extend(redirect_uri.map(|uri| ("redirect_uri", uri)));
        let token = setup.form("/token", &fields).await;
        assert_eq!(
            token.status, expected_status,
            "{redirect_uri:?}: {}",
            token.body
        );
        let response: Value = serde_json::from_str(&token.body).unwrap();
        if expected_status == StatusCode::OK {
            assert!(response["access_token"].is_string());
        } else {
            assert_eq!(response["error"], "invalid_grant");
            assert_eq!(response["error_description"], "redirect_uri does not match");
        }
    }
    assert_eq!(setup.fetches(), 1);
}

#[tokio::test]
async fn localhost_ipv6_and_explicitly_registered_ports_accept_an_ephemeral_port() {
    let setup = setup(|_| {}).await;
    let mut body = document(&setup.client_id);
    body["redirect_uris"] = json!([
        "http://localhost/callback",
        "http://[::1]/callback",
        "http://127.0.0.1:9999/callback"
    ]);
    setup.documents.reply_with([serve(&body, "max-age=600")]);
    for redirect_uri in [
        "http://localhost:38159/callback",
        "http://[::1]:38159/callback",
        EPHEMERAL_REDIRECT,
    ] {
        let page = setup.authorize(&setup.client_id, redirect_uri).await;
        assert_eq!(page.status, StatusCode::OK, "{redirect_uri}: {}", page.body);
    }
}

#[tokio::test]
async fn authorization_rejects_redirect_changes_other_than_a_loopback_port() {
    let setup = setup(|_| {}).await;
    let mut body = document(&setup.client_id);
    body["redirect_uris"] = json!([
        REDIRECT,
        "https://client.example/cb",
        "com.example.app:/callback"
    ]);
    setup.documents.reply_with([serve(&body, "max-age=600")]);
    for redirect_uri in [
        "https://client.example:8443/cb",
        "https://client.example/cb/other",
        "http://127.0.0.1:38159/other",
        "http://127.0.0.1:38159/callback?extra=1",
        "http://localhost:38159/callback",
        "http://127.0.0.2:38159/callback",
        "http://[::1]:38159/callback",
        "http://user@127.0.0.1:38159/callback",
        "http://127.0.0.1:38159/callback#frag",
        "com.example.app:/other",
    ] {
        let page = setup.authorize(&setup.client_id, redirect_uri).await;
        assert_eq!(
            page.status,
            StatusCode::BAD_REQUEST,
            "{redirect_uri}: {}",
            page.body
        );
        assert!(
            page.body.contains("redirect address does not match"),
            "{redirect_uri}: {}",
            page.body
        );
        assert!(
            !page.headers.contains_key(header::LOCATION),
            "{redirect_uri}"
        );
    }
}

#[tokio::test]
async fn private_and_local_addresses_are_never_fetched() {
    let mut setup = setup(|_| {}).await;
    for client_id in [
        "https://10.0.0.1/client.json",
        "https://169.254.169.254/latest/meta-data",
        "https://[fdaa::3]/client.json",
        "https://localhost/client.json",
        "https://mail.internal/client.json",
    ] {
        setup
            .refused(
                client_id,
                None,
                "private and local addresses are not fetched",
            )
            .await;
    }
    setup
        .refused("http://hooks.test/client.json", None, "not registered")
        .await;
    assert_eq!(setup.fetches(), 0);
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let mut setup = setup(|_| {}).await;
    let client_id = setup.client_id.clone();
    let redirect = Reply {
        status: 302,
        headers: vec![(
            "Location".to_owned(),
            "https://10.0.0.1/client.json".to_owned(),
        )],
        body: Vec::new(),
    };
    setup
        .refused(&client_id, Some(redirect), "redirects are not followed")
        .await;
    assert_eq!(setup.fetches(), 1, "only the client_id URL is requested");
}

#[tokio::test]
async fn a_mismatched_client_id_is_refused_and_not_cached() {
    let mut setup = setup(|_| {}).await;
    let client_id = setup.client_id.clone();
    let other = document("https://hooks.test/someone-else.json");
    setup
        .refused(
            &client_id,
            Some(serve(&other, "max-age=86400")),
            "not the address it was fetched from",
        )
        .await;
    // The refusal is not cached: a corrected document is fetched at once.
    setup
        .documents
        .reply_with([serve(&document(&client_id), "max-age=600")]);
    let page = setup.authorize(&client_id, REDIRECT).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);
    assert_eq!(setup.fetches(), 2);
}

#[tokio::test]
async fn an_oversized_document_is_refused() {
    let setup = setup(|_| {}).await;
    let client_id = setup.client_id.clone();
    let mut big = document(&client_id);
    big["padding"] = json!("x".repeat(70 * 1024));
    setup
        .refused(
            &client_id,
            Some(serve(&big, "max-age=600")),
            "larger than 64 KiB",
        )
        .await;
}

#[tokio::test]
async fn errors_and_broken_documents_are_refused() {
    let mut setup = setup(|_| {}).await;
    let client_id = setup.client_id.clone();
    setup
        .refused(
            &client_id,
            Some(Reply::status(404)),
            "answered with HTTP 404",
        )
        .await;
    let broken = Reply {
        status: 200,
        headers: Vec::new(),
        body: b"<html>not json</html>".to_vec(),
    };
    setup
        .refused(&client_id, Some(broken), "not a JSON object")
        .await;
    let mut secret = document(&client_id);
    secret["client_secret"] = json!("published-secret");
    setup
        .refused(
            &client_id,
            Some(serve(&secret, "max-age=600")),
            "must not contain a client_secret",
        )
        .await;
    assert_eq!(setup.fetches(), 3);
}

#[tokio::test]
async fn the_client_limit_applies_to_metadata_documents() {
    let setup = setup(|config| config.max_clients = 0).await;
    let client_id = setup.client_id.clone();
    setup
        .refused(
            &client_id,
            Some(serve(&document(&client_id), "max-age=600")),
            "not accepting new apps",
        )
        .await;
}

#[tokio::test]
async fn new_metadata_clients_count_against_the_registration_limit() {
    let mut setup = setup(|config| config.registrations_per_ip = 1).await;
    let first = setup.client_id.clone();
    setup
        .documents
        .reply_with([serve(&document(&first), "max-age=600")]);
    let page = setup.authorize(&first, REDIRECT).await;
    assert_eq!(page.status, StatusCode::OK, "{}", page.body);

    let second = setup.documents.url("/oauth/second.json");
    setup
        .refused(
            &second,
            Some(serve(&document(&second), "max-age=600")),
            "too many new apps were added from your network",
        )
        .await;
    // A client that is already stored is not new, so it still works.
    let again = setup.authorize(&first, REDIRECT).await;
    assert_eq!(again.status, StatusCode::OK, "{}", again.body);
    assert_eq!(setup.fetches(), 2);
}

#[tokio::test]
async fn only_the_authorization_server_advertises_metadata_documents() {
    let setup = setup(|_| {}).await;
    let get = |path: &'static str| {
        let setup = &setup;
        async move {
            let page = setup
                .send(Request::get(path).body(Body::empty()).unwrap())
                .await;
            serde_json::from_str::<Value>(&page.body).unwrap()
        }
    };
    let server = get("/.well-known/oauth-authorization-server").await;
    assert_eq!(server["client_id_metadata_document_supported"], true);
    assert_eq!(
        server["scopes_supported"],
        json!(["mail", "offline_access"])
    );
    assert!(server["registration_endpoint"].is_string(), "DCR stays");
    let resource = get("/.well-known/oauth-protected-resource").await;
    assert_eq!(resource["scopes_supported"], json!(["mail"]));
    assert!(
        resource
            .get("client_id_metadata_document_supported")
            .is_none()
    );
}
