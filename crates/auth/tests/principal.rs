//! `PrincipalResolver`: the default token lookup and a replacement.

#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode, header};
use axum::routing::get;
use axum::{Router, middleware};
use http_body_util::BodyExt;
use postkeep_auth::{
    AuthConfig, AuthState, Authenticated, BearerRequest, CredentialVerifier, PrincipalResolver,
    Resolution, ResolveFuture, VerifyFuture, require_bearer,
};
use postkeep_mail::ImapServer;
use postkeep_store::{AccountId, CodeGrant, GrantSubject, MasterKey, NewClient, Store, StoreError};
use secrecy::SecretString;
use tower::ServiceExt;

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

/// Accepts `member-key` as a member of the `acme` tenant acting for one
/// mailbox, fails on `broken-key`, and refuses everything else.
struct MemberKeys {
    account: AccountId,
}

impl PrincipalResolver for MemberKeys {
    fn resolve<'a>(
        &'a self,
        _state: &'a AuthState,
        token: &'a str,
        request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            match token {
                "member-key" => {
                    let host = request
                        .headers
                        .get(header::HOST)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    Ok(Resolution::Authenticated(
                        Authenticated::for_account(
                            self.account.clone(),
                            "key-client".to_owned(),
                            "mail".to_owned(),
                        )
                        .with_tenant("acme")
                        .with_principal(format!("member:7@{host}")),
                    ))
                }
                "broken-key" => Err(StoreError::InvalidInput("broken")),
                _ => Ok(Resolution::Refused("unknown workspace key")),
            }
        })
    }
}

/// Takes this server's access tokens for principals, the embedding's
/// members, each in the `acme` tenant with a mailbox named after it.
struct Members;

impl PrincipalResolver for Members {
    fn resolve<'a>(
        &'a self,
        state: &'a AuthState,
        token: &'a str,
        request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let grant = match state.access_grant(token, request).await? {
                Ok(grant) => grant,
                Err(refusal) => return Ok(Resolution::Refused(refusal)),
            };
            let GrantSubject::Principal(principal) = grant.subject else {
                return Ok(Resolution::Refused("the access token is not for a member"));
            };
            Ok(Resolution::Authenticated(
                Authenticated::for_account(
                    AccountId(format!("mailbox-of-{principal}")),
                    grant.client_id,
                    grant.scope,
                )
                .with_tenant("acme")
                .with_principal(principal),
            ))
        })
    }
}

async fn setup() -> (Router, AuthState, Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("auth.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let state = AuthState::new(
        store.clone(),
        AuthConfig::new("https://mail.example.com", "/mcp").unwrap(),
        AcceptAll,
    );
    let app = Router::new()
        .route(
            "/mcp",
            get(|Extension(caller): Extension<Authenticated>| async move {
                format!(
                    "{} {} {} {}",
                    caller.tenant, caller.principal, caller.account_id.0, caller.client_id
                )
            }),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_bearer,
        ));
    (app, state, store, dir)
}

async fn call(app: &Router, token: Option<&str>) -> (StatusCode, String, Option<String>) {
    let mut request = Request::get("/mcp").header(header::HOST, "acme.example.com");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let challenge = response
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .map(|value| value.to_str().unwrap().to_owned());
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        String::from_utf8_lossy(&body).into_owned(),
        challenge,
    )
}

/// Stores a grant for `subject` and `resource` with the access token
/// `token`, as a code exchange would; returns the new client's ID.
async fn issue(store: &Store, subject: GrantSubject, resource: &str, token: &str) -> String {
    let client = store
        .create_client(&NewClient {
            name: None,
            redirect_uris: vec!["http://127.0.0.1/cb".to_owned()],
            secret: None,
        })
        .await
        .unwrap();
    let grant = store
        .create_grant(&CodeGrant {
            client_id: client.id.clone(),
            subject,
            redirect_uri: "http://127.0.0.1/cb".to_owned(),
            code_challenge: "c".repeat(43),
            scope: "mail".to_owned(),
            resource: Some(resource.to_owned()),
        })
        .await
        .unwrap();
    store
        .save_tokens(
            &grant,
            token,
            Duration::from_hours(1),
            &format!("{token}-refresh"),
            Duration::from_hours(1),
        )
        .await
        .unwrap();
    client.id
}

#[tokio::test]
async fn the_default_resolver_puts_token_holders_in_the_default_tenant() {
    let (app, _state, store, _dir) = setup().await;
    let account = store
        .upsert_account("user@example.com", &SecretString::from("pw".to_owned()))
        .await
        .unwrap();
    let client = store
        .create_client(&NewClient {
            name: None,
            redirect_uris: vec!["http://127.0.0.1/cb".to_owned()],
            secret: None,
        })
        .await
        .unwrap();
    let grant = store
        .create_grant(&CodeGrant {
            client_id: client.id.clone(),
            subject: GrantSubject::Account(account.id.clone()),
            redirect_uri: "http://127.0.0.1/cb".to_owned(),
            code_challenge: "c".repeat(43),
            scope: "mail".to_owned(),
            resource: Some("https://mail.example.com/mcp".to_owned()),
        })
        .await
        .unwrap();
    store
        .save_tokens(
            &grant,
            "issued-token",
            Duration::from_hours(1),
            "issued-refresh",
            Duration::from_hours(1),
        )
        .await
        .unwrap();
    let (status, body, _) = call(&app, Some("issued-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        format!("default {} {} {}", account.id.0, account.id.0, client.id)
    );
    let (status, _, challenge) = call(&app, Some("not-issued")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        challenge
            .unwrap()
            .ends_with("error_description=\"the access token is invalid or expired\"")
    );
}

#[tokio::test]
async fn the_default_resolver_refuses_tokens_for_principals() {
    let (app, _state, store, _dir) = setup().await;
    let client = store
        .create_client(&NewClient {
            name: None,
            redirect_uris: vec!["http://127.0.0.1/cb".to_owned()],
            secret: None,
        })
        .await
        .unwrap();
    let grant = store
        .create_grant(&CodeGrant {
            client_id: client.id,
            subject: GrantSubject::Principal("member:7".to_owned()),
            redirect_uri: "http://127.0.0.1/cb".to_owned(),
            code_challenge: "c".repeat(43),
            scope: "mail".to_owned(),
            resource: Some("https://mail.example.com/mcp".to_owned()),
        })
        .await
        .unwrap();
    store
        .save_tokens(
            &grant,
            "principal-token",
            Duration::from_hours(1),
            "principal-refresh",
            Duration::from_hours(1),
        )
        .await
        .unwrap();
    let (status, _, challenge) = call(&app, Some("principal-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        challenge
            .unwrap()
            .ends_with("error_description=\"the access token is not for a mailbox account\"")
    );
}

#[tokio::test]
async fn a_resolver_can_take_this_servers_tokens_for_principals() {
    let (app, state, store, _dir) = setup().await;
    state.set_principal_resolver(Arc::new(Members));
    let member = GrantSubject::Principal("member:7".to_owned());
    let resource = "https://mail.example.com/mcp";
    let client = issue(&store, member.clone(), resource, "member-token").await;
    issue(
        &store,
        member,
        "https://other.example.com/mcp",
        "elsewhere-token",
    )
    .await;
    let account = store
        .upsert_account("user@example.com", &SecretString::from("pw".to_owned()))
        .await
        .unwrap();
    issue(
        &store,
        GrantSubject::Account(account.id),
        resource,
        "mailbox-token",
    )
    .await;

    let (status, body, _) = call(&app, Some("member-token")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, format!("acme member:7 mailbox-of-member:7 {client}"));
    for (token, refusal) in [
        ("mailbox-token", "the access token is not for a member"),
        (
            "elsewhere-token",
            "the access token is for another resource",
        ),
        ("not-issued", "the access token is invalid or expired"),
    ] {
        let (status, _, challenge) = call(&app, Some(token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{token}");
        let challenge = challenge.unwrap();
        assert!(
            challenge.ends_with(&format!("error_description=\"{refusal}\"")),
            "{token}: {challenge}"
        );
    }
}

#[tokio::test]
async fn a_replacement_resolver_decides_who_the_caller_is() {
    let (app, state, store, _dir) = setup().await;
    let account = store
        .upsert_account("shared@example.com", &SecretString::from("pw".to_owned()))
        .await
        .unwrap();
    state.set_principal_resolver(Arc::new(MemberKeys {
        account: account.id.clone(),
    }));

    let (status, body, _) = call(&app, Some("member-key")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        format!("acme member:7@acme.example.com {} key-client", account.id.0)
    );

    let (status, _, challenge) = call(&app, Some("someone-else")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        challenge.unwrap(),
        "Bearer resource_metadata=\"https://mail.example.com/.well-known/oauth-protected-resource/mcp\", \
         error=\"invalid_token\", error_description=\"unknown workspace key\""
    );

    let (status, _, challenge) = call(&app, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!challenge.unwrap().contains("invalid_token"));

    let (status, _, _) = call(&app, Some("broken-key")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn a_caller_uses_its_account_and_the_mailboxes_it_is_given() {
    let id = |name: &str| AccountId(name.to_owned());
    let single = Authenticated::for_account(id("a"), "client".to_owned(), "mail".to_owned());
    assert_eq!(single.mailboxes, vec![id("a")]);
    assert!(single.may_use(&id("a")));
    assert!(!single.may_use(&id("b")));
    assert!(!MemberKeys { account: id("a") }.selects_mailboxes());
    assert!(!postkeep_auth::TokenResolver.selects_mailboxes());

    let several = single.with_mailboxes([id("b"), id("a"), id("c"), id("b")]);
    assert_eq!(several.account_id, id("a"));
    assert_eq!(several.mailboxes, vec![id("a"), id("b"), id("c")]);
    assert!(several.may_use(&id("c")));
    assert!(!several.may_use(&id("d")));

    let replaced = several.with_mailboxes([id("d")]);
    assert_eq!(replaced.mailboxes, vec![id("a"), id("d")]);
    assert!(!replaced.may_use(&id("b")));
}
