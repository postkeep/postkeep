//! The OAuth client and token manager against mocked provider endpoints.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep_store::{
    DataKey, Kek, KeyWrapper, LocalKeyWrapper, MasterKey, OAuthAccount, Provider, Store,
    StoreError, UpstreamTokens, WrapFuture, Wrapped,
};
use postkeep_upstream::{
    ApiClient, AppCredentials, Endpoints, Http, OAuthClient, OAuthError, TokenError, TokenManager,
    UpstreamProvider,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use url::Url;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const MS_TOKEN: &str = "/microsoft/common/oauth2/v2.0/token";
const GOOGLE_TOKEN: &str = "/google-oauth/token";

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

fn client(server: &MockServer) -> OAuthClient {
    let base = Url::parse(&server.uri()).unwrap();
    let app = |id: &str| AppCredentials {
        client_id: id.to_owned(),
        client_secret: secret("client-secret"),
    };
    OAuthClient::new(
        Http::for_tests(),
        Endpoints::all_at(&base),
        Url::parse("https://mail.example.com").unwrap(),
        Some(app("ms-client")),
        Some(app("google-client")),
    )
}

fn id_token(sub: &str, aud: &str) -> String {
    let claims = json!({
        "iss": "https://accounts.google.com",
        "aud": aud,
        "sub": sub,
        "exp": chrono::Utc::now().timestamp() + 3600,
    });
    format!(
        "{}.{}.c2ln",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"k"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

#[tokio::test]
async fn microsoft_sign_in_exchanges_the_code_and_reads_the_profile() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MS_TOKEN))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code=the-code"))
        .and(body_string_contains("code_verifier=the-verifier"))
        .and(body_string_contains("client_secret=client-secret"))
        .and(body_string_contains(
            "redirect_uri=https%3A%2F%2Fmail.example.com%2Foauth%2Fmicrosoft%2Fcallback",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "token_type": "Bearer",
            "scope": "https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/User.Read",
            "expires_in": 3599,
            "access_token": "ms-access",
            "refresh_token": "ms-refresh"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/graph/v1.0/me"))
        .and(header("authorization", "Bearer ms-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "00000000-0000-0000-0001-000000000001",
            "mail": null,
            "userPrincipalName": "Person@Outlook.example.com"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/graph/v1.0/me/mailFolders/inbox"))
        .and(query_param("$select", "id"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "id": "inbox-id" })))
        .with_priority(10)
        .mount(&server)
        .await;

    let client = client(&server);
    let token = client
        .exchange_code(UpstreamProvider::Microsoft, "the-code", "the-verifier")
        .await
        .unwrap();
    assert_eq!(token.access_token.expose_secret(), "ms-access");
    let identity = client
        .identity(UpstreamProvider::Microsoft, &token)
        .await
        .unwrap();
    assert_eq!(identity.subject, "00000000-0000-0000-0001-000000000001");
    assert_eq!(identity.email, "person@outlook.example.com");
}

#[tokio::test]
async fn microsoft_accounts_without_a_mailbox_are_refused() {
    // A directory user without Exchange Online can carry any `mail` value;
    // without a mailbox the address is not trusted.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MS_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "scope": "Mail.ReadWrite Mail.Send User.Read",
            "expires_in": 3599, "access_token": "ms-access", "refresh_token": "ms-refresh"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/graph/v1.0/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "00000000-0000-0000-0002-000000000002",
            "mail": "owner@example.com",
            "userPrincipalName": "intruder@tenant.example.net"
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/graph/v1.0/me/mailFolders/inbox"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": { "code": "MailboxNotEnabledForRESTAPI", "message": "The mailbox is either inactive, soft-deleted, or is hosted on-premise." }
        })))
        .mount(&server)
        .await;
    let client = client(&server);
    let token = client
        .exchange_code(UpstreamProvider::Microsoft, "the-code", "the-verifier")
        .await
        .unwrap();
    let err = client
        .identity(UpstreamProvider::Microsoft, &token)
        .await
        .unwrap_err();
    assert!(
        matches!(err, OAuthError::NoMailbox(UpstreamProvider::Microsoft)),
        "{err:?}"
    );
}

#[tokio::test]
async fn sign_in_fails_without_required_scopes_or_refresh_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN))
        .and(body_string_contains("code=narrow"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "a", "refresh_token": "r", "expires_in": 3599,
            "scope": "openid https://www.googleapis.com/auth/gmail.send",
            "id_token": id_token("1", "google-client")
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN))
        .and(body_string_contains("code=no-refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "a", "expires_in": 3599,
            "scope": "openid https://www.googleapis.com/auth/gmail.modify"
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN))
        .and(body_string_contains("code=used"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant", "error_description": "Bad Request"
        })))
        .mount(&server)
        .await;
    // The grant missing a scope is revoked rather than left behind.
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=r"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let client = client(&server);
    let google = UpstreamProvider::Google;
    assert!(matches!(
        client.exchange_code(google, "narrow", "v").await,
        Err(OAuthError::MissingScopes(missing)) if missing == ["https://www.googleapis.com/auth/gmail.modify"]
    ));
    assert!(matches!(
        client.exchange_code(google, "no-refresh", "v").await,
        Err(OAuthError::Malformed { .. })
    ));
    assert!(matches!(
        client.exchange_code(google, "used", "v").await,
        Err(OAuthError::NeedsReauth { .. })
    ));
}

#[tokio::test]
async fn google_sign_in_uses_the_id_token_and_gmail_profile() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(GOOGLE_TOKEN))
        .and(body_string_contains("code_verifier=v"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "g-access", "refresh_token": "g-refresh", "expires_in": 3599,
            "scope": "https://www.googleapis.com/auth/gmail.modify openid https://www.googleapis.com/auth/gmail.send",
            "token_type": "Bearer",
            "id_token": id_token("1180000000000000001", "google-client")
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/gmail/gmail/v1/users/me/profile"))
        .and(header("authorization", "Bearer g-access"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "emailAddress": "someone@example.com", "messagesTotal": 3, "historyId": "100"
        })))
        .mount(&server)
        .await;
    let client = client(&server);
    let token = client
        .exchange_code(UpstreamProvider::Google, "c", "v")
        .await
        .unwrap();
    let identity = client
        .identity(UpstreamProvider::Google, &token)
        .await
        .unwrap();
    assert_eq!(identity.subject, "1180000000000000001");
    assert_eq!(identity.email, "someone@example.com");

    // An ID token for another client is refused.
    let mut forged = token.clone();
    forged.id_token = Some(secret(&id_token("2", "someone-else")));
    assert!(
        client
            .identity(UpstreamProvider::Google, &forged)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn revokes_google_tokens_and_ignores_unknown_ones() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=live"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/google-oauth/revoke"))
        .and(body_string_contains("token=gone"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_token", "error_description": "Token expired or revoked"
        })))
        .mount(&server)
        .await;
    let client = client(&server);
    client
        .revoke(UpstreamProvider::Google, &secret("live"))
        .await
        .unwrap();
    client
        .revoke(UpstreamProvider::Google, &secret("gone"))
        .await
        .unwrap();
    // Microsoft has no revocation endpoint: nothing is sent.
    client
        .revoke(UpstreamProvider::Microsoft, &secret("live"))
        .await
        .unwrap();
}

async fn store_with_account(
    expires_at: i64,
) -> (Store, postkeep_store::AccountId, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let account = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: "subject-1",
                email: "person@example.com",
            },
            &UpstreamTokens {
                refresh_token: secret("refresh-1"),
                access_token: Some(secret("access-0")),
                access_expires_at: Some(expires_at),
                scope: "Mail.ReadWrite Mail.Send".to_owned(),
            },
        )
        .await
        .unwrap();
    (store, account.id, dir)
}

#[tokio::test]
async fn refreshes_expired_tokens_once_and_saves_the_rotated_refresh_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MS_TOKEN))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "access_token": "access-1", "refresh_token": "refresh-2", "expires_in": 3600,
                    "scope": "Mail.ReadWrite Mail.Send User.Read"
                }))
                .set_delay(std::time::Duration::from_millis(100)),
        )
        .expect(1)
        .mount(&server)
        .await;
    let (store, account, _dir) = store_with_account(chrono::Utc::now().timestamp() + 30).await;
    let manager = Arc::new(TokenManager::new(store.clone(), client(&server)));

    // Concurrent callers share one refresh.
    let mut tasks = Vec::new();
    for _ in 0..5 {
        let manager = Arc::clone(&manager);
        let account = account.clone();
        tasks.push(tokio::spawn(async move {
            manager
                .access_token(&account, UpstreamProvider::Microsoft)
                .await
                .map(|token| token.expose_secret().to_owned())
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().unwrap(), "access-1");
    }
    let stored = store.upstream_tokens(&account).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-2");
    assert_eq!(stored.tokens.scope, "Mail.ReadWrite Mail.Send User.Read");
    // The cached token is used until it nears expiry.
    let again = manager
        .access_token(&account, UpstreamProvider::Microsoft)
        .await
        .unwrap();
    assert_eq!(again.expose_secret(), "access-1");
}

#[tokio::test]
async fn a_rejected_access_token_is_refreshed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MS_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-1", "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (store, account, _dir) = store_with_account(chrono::Utc::now().timestamp() + 3000).await;
    let manager = TokenManager::new(store.clone(), client(&server));
    let cached = manager
        .access_token(&account, UpstreamProvider::Microsoft)
        .await
        .unwrap();
    assert_eq!(cached.expose_secret(), "access-0");
    let fresh = manager
        .refresh_after_rejection(&account, UpstreamProvider::Microsoft, &cached)
        .await
        .unwrap();
    assert_eq!(fresh.expose_secret(), "access-1");
    // Without rotation the old refresh token is kept.
    let stored = store.upstream_tokens(&account).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-1");
}

#[tokio::test]
async fn invalid_grant_marks_the_account_and_fails_fast() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MS_TOKEN))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "invalid_grant",
            "error_description": "AADSTS700082: The refresh token has expired due to inactivity."
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (store, account, _dir) = store_with_account(0).await;
    let manager = TokenManager::new(store.clone(), client(&server));
    for _ in 0..3 {
        let err = manager
            .access_token(&account, UpstreamProvider::Microsoft)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TokenError::NeedsReauth { ref reason, .. } if reason == "invalid_grant"),
            "{err}"
        );
    }
    let stored = store.upstream_tokens(&account).await.unwrap().unwrap();
    assert_eq!(stored.invalid_reason.as_deref(), Some("invalid_grant"));
    assert!(stored.tokens.access_token.is_none());
}

/// While a refresh of `refresh-1` is in flight, a sign-in stores a new grant.
/// The refresh's later write or `invalid_grant` must not clobber it.
async fn sign_in_during_refresh_keeps_the_new_grant(response: ResponseTemplate) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MS_TOKEN))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(response.set_delay(std::time::Duration::from_millis(800)))
        .expect(1)
        .mount(&server)
        .await;
    let (store, account, _dir) = store_with_account(0).await;
    let manager = TokenManager::new(store.clone(), client(&server));
    let account_for_refresh = account.clone();
    let task = tokio::spawn(async move {
        manager
            .access_token(&account_for_refresh, UpstreamProvider::Microsoft)
            .await
            .map(|token| token.expose_secret().to_owned())
    });
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let arrived = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .any(|request| request.url.path() == MS_TOKEN);
        if arrived {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the refresh request was not sent"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    store
        .save_upstream_tokens(
            &account,
            &UpstreamTokens {
                refresh_token: secret("refresh-new"),
                access_token: Some(secret("access-new")),
                access_expires_at: Some(chrono::Utc::now().timestamp() + 3600),
                scope: "Mail.ReadWrite Mail.Send".to_owned(),
            },
        )
        .await
        .unwrap();
    let token = task.await.unwrap().unwrap();
    assert_eq!(token, "access-new");
    let stored = store.upstream_tokens(&account).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-new");
    assert_eq!(
        stored
            .tokens
            .access_token
            .as_ref()
            .map(ExposeSecret::expose_secret),
        Some("access-new")
    );
    assert!(stored.invalid_reason.is_none());
}

#[tokio::test]
async fn a_sign_in_during_refresh_is_not_marked_invalid() {
    sign_in_during_refresh_keeps_the_new_grant(ResponseTemplate::new(400).set_body_json(json!({
        "error": "invalid_grant",
        "error_description": "The refresh token has expired."
    })))
    .await;
}

#[tokio::test]
async fn a_sign_in_during_refresh_is_not_overwritten() {
    sign_in_during_refresh_keeps_the_new_grant(ResponseTemplate::new(200).set_body_json(json!({
        "access_token": "access-stale",
        "refresh_token": "refresh-rotated",
        "expires_in": 3600,
        "scope": "Mail.ReadWrite Mail.Send"
    })))
    .await;
}

#[tokio::test]
async fn transient_failures_do_not_mark_the_account() {
    let server = MockServer::start().await;
    let (store, account, _dir) = store_with_account(0).await;
    let manager = TokenManager::new(store.clone(), client(&server));
    for (status, code) in [(503, "temporarily_unavailable"), (429, "slow_down")] {
        let _mock = Mock::given(method("POST"))
            .and(path(MS_TOKEN))
            .respond_with(
                ResponseTemplate::new(status)
                    .insert_header("Retry-After", "7")
                    .set_body_json(json!({"error":code})),
            )
            .expect(1)
            .up_to_n_times(1)
            .mount_as_scoped(&server)
            .await;
        let err = manager
            .access_token(&account, UpstreamProvider::Microsoft)
            .await
            .unwrap_err();
        assert!(
            matches!(err, TokenError::OAuth(ref inner) if inner.is_transient() && inner.is_rate_limited() == (status == 429) && inner.retry_after() == Some(7)),
            "{err}"
        );
        let stored = store.upstream_tokens(&account).await.unwrap().unwrap();
        assert!(stored.invalid_reason.is_none());
    }
}

/// The local key wrapper, except that `unwrap` fails like a key service that
/// does not answer while `down` is set.
struct Switch {
    local: LocalKeyWrapper,
    down: AtomicBool,
}

impl KeyWrapper for Switch {
    fn current(&self) -> Kek {
        self.local.current()
    }

    fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
        self.local.wrap(tenant, key)
    }

    fn unwrap<'a>(
        &'a self,
        tenant: &'a str,
        kek: &'a Kek,
        wrapped: &'a [u8],
    ) -> WrapFuture<'a, DataKey> {
        if self.down.load(Ordering::SeqCst) {
            let down = StoreError::KeyWrap("the key service is down".to_owned());
            return Box::pin(std::future::ready(Err(down)));
        }
        self.local.unwrap(tenant, kek, wrapped)
    }
}

/// A refresh that succeeded at the provider but whose new tokens cannot be
/// stored for now, because the key service does not answer, is a store error:
/// the account is not marked as rejected and its stored tokens stay, so the
/// next call refreshes again and stores.
#[tokio::test]
async fn a_failing_key_service_does_not_end_the_sign_in() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(MS_TOKEN))
        .and(body_string_contains("refresh_token=refresh-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-1", "refresh_token": "refresh-2", "expires_in": 3600,
            "scope": "Mail.ReadWrite Mail.Send"
        })))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let switch = Arc::new(Switch {
        local: LocalKeyWrapper::new(&key, &[]),
        down: AtomicBool::new(false),
    });
    let store = Store::connect(&url, &key)
        .await
        .unwrap()
        .with_key_wrapper(switch.clone());
    let tokens = UpstreamTokens {
        refresh_token: secret("refresh-1"),
        access_token: Some(secret("access-0")),
        access_expires_at: Some(0),
        scope: "Mail.ReadWrite Mail.Send".to_owned(),
    };
    let oauth = OAuthAccount {
        provider: Provider::Graph,
        subject: "subject-1",
        email: "person@example.com",
    };
    let account = store.upsert_oauth_account(&oauth, &tokens).await;
    let account = account.unwrap().id;
    // Another process adds a newer data key version, which this one must ask
    // the key service about before it writes.
    let stranger = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let other = Store::connect(&url, &stranger).await.unwrap();
    assert_eq!(other.data_key().await.unwrap().0, 2);
    other.close().await;

    switch.down.store(true, Ordering::SeqCst);
    let manager = TokenManager::new(store.clone(), client(&server));
    let err = manager
        .access_token(&account, UpstreamProvider::Microsoft)
        .await
        .unwrap_err();
    let msg = "a failed store write must surface as a store error, not a sign-in error";
    assert!(
        matches!(err, TokenError::Store(StoreError::KeyWrap(_))),
        "{msg}: {err:?}"
    );
    let stored = store.upstream_tokens(&account).await.unwrap().unwrap();
    assert!(
        stored.invalid_reason.is_none(),
        "the account was marked as rejected"
    );
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-1");

    switch.down.store(false, Ordering::SeqCst);
    let token = manager
        .access_token(&account, UpstreamProvider::Microsoft)
        .await
        .unwrap();
    assert_eq!(token.expose_secret(), "access-1");
    let stored = store.upstream_tokens(&account).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-2");
}

/// Notes when each request arrives, and answers it `hold` later.
struct Arrivals {
    seen: Arc<std::sync::Mutex<Vec<std::time::Instant>>>,
    hold: std::time::Duration,
}

impl wiremock::Respond for Arrivals {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        self.seen.lock().unwrap().push(std::time::Instant::now());
        ResponseTemplate::new(200)
            .set_body_json(json!({ "value": [] }))
            .set_delay(self.hold)
    }
}

#[tokio::test]
async fn graph_calls_for_one_mailbox_go_two_at_a_time() {
    let server = MockServer::start().await;
    let hold = std::time::Duration::from_millis(300);
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    Mock::given(method("GET"))
        .and(path("/graph/v1.0/me/messages"))
        .respond_with(Arrivals {
            seen: Arc::clone(&seen),
            hold,
        })
        .expect(5)
        .mount(&server)
        .await;
    let (store, account, _dir) = store_with_account(chrono::Utc::now().timestamp() + 3000).await;
    let tokens = TokenManager::new(store, client(&server));
    let api = ApiClient::new(tokens, account, UpstreamProvider::Microsoft);
    let url = Url::parse(&format!("{}/graph/v1.0/me/messages", server.uri())).unwrap();

    let calls: Vec<_> = (0..5)
        .map(|_| {
            let (api, url) = (api.clone(), url.clone());
            tokio::spawn(async move { api.get_json::<serde_json::Value>(&url, &[]).await })
        })
        .collect();
    for call in calls {
        call.await.unwrap().unwrap();
    }
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 5);
    // A third request goes out only after one of the two before it is answered.
    for three in seen.windows(3) {
        let apart = three[2] - three[0];
        assert!(
            apart >= hold,
            "{apart:?} between a request and the one two later"
        );
    }
}
