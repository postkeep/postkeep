//! Store tests. SQLite tests always run; the PostgreSQL variant is ignored
//! unless run explicitly with `TEST_POSTGRES_URL` set, for example:
//!
//! ```sh
//! TEST_POSTGRES_URL=postgres://postgres:postgres@localhost/postgres \
//!   cargo nextest run -p postkeep-store --all-features --run-ignored all
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{AUTH, KnownKey, PASSWORD, PAYLOAD, SECRET};
#[cfg(feature = "postgres")]
use postkeep_store::PushSubscription;
use postkeep_store::{
    AccountId, AddedFilterRule, AppendOutcome, AuthorizationRequest, ChangedFilterRule,
    ClaimRefused, Claimed, CodeGrant, DataKey, DeliveryEffect, DeliveryRecord, FilterRule,
    GrantSubject, HeldSend, HeldSendMatch, KEPT_DELIVERIES, LoadedWebhook,
    MAX_CONSECUTIVE_FAILURES, MasterKey, NewClient, NewFilterRule, OAuthAccount, OutboxLimitChange,
    PIECE_TAG, Provider, PurgePolicy, Redemption, RefreshRotation, SessionTtl, Store, StoreError,
    UploadBounds, UploadLookup, UploadOwner, UpstreamTokens, WatchCursor, WebhookSettings,
    open_piece, seal_piece,
};
use secrecy::{ExposeSecret, SecretString};

const MINUTE: Duration = Duration::from_secs(60);

fn key() -> MasterKey {
    MasterKey::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap()
}

fn random_key() -> MasterKey {
    MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap()
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

/// A unique value so tests can share one PostgreSQL database.
fn unique(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4().simple())
}

async fn sqlite() -> (Store, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    (Store::connect(&url, &key()).await.unwrap(), dir)
}

async fn client(store: &Store) -> String {
    store
        .create_client(&NewClient {
            name: Some("Test client".to_owned()),
            redirect_uris: vec!["http://127.0.0.1:9999/callback".to_owned()],
            secret: None,
        })
        .await
        .unwrap()
        .id
}

async fn exercise_accounts(store: &Store) {
    let email = format!("{}@ICLOUD.com", unique("user"));
    let account = store
        .upsert_account(&email, &secret("abcdabcdabcdabcd"))
        .await
        .unwrap();
    assert_eq!(account.email, email.to_lowercase());
    let again = store
        .upsert_account(&email.to_lowercase(), &secret("newpassword"))
        .await
        .unwrap();
    assert_eq!(again.id, account.id, "upsert keeps the account ID");
    let creds = store.credentials(&account.id).await.unwrap().unwrap();
    assert_eq!(creds.password.expose_secret(), "newpassword");

    assert!(store.delete_account(&account.id).await.unwrap());
    assert!(store.credentials(&account.id).await.unwrap().is_none());
    assert!(!store.delete_account(&account.id).await.unwrap());
}

/// A rejection of the stored password is recorded, and a login that works or a
/// password that is stored clears it.
async fn exercise_password_rejection(store: &Store) {
    let email = format!("{}@icloud.com", unique("rejected"));
    let password = secret("abcdabcdabcdabcd");
    let id = store.upsert_account(&email, &password).await.unwrap().id;
    let rejected = async || store.password_rejected_at(&id).await.unwrap();
    assert_eq!(rejected().await, None);

    store.mark_password_rejected(&id).await.unwrap();
    let at = rejected().await;
    assert!(at.is_some_and(|at| at > 1_700_000_000), "{at:?}");
    assert!(store.clear_password_rejected(&id).await.unwrap());
    assert_eq!(rejected().await, None);
    assert!(!store.clear_password_rejected(&id).await.unwrap());

    // A password that is stored clears it: the same one, and a new one.
    store.mark_password_rejected(&id).await.unwrap();
    store.upsert_account(&email, &password).await.unwrap();
    assert_eq!(rejected().await, None, "upsert_account");
    store.mark_password_rejected(&id).await.unwrap();
    let new = secret("zzzzzzzzzzzzzzzz");
    let ending = store.upsert_imap_account_ending_sessions(&email, &new, None);
    ending.await.unwrap();
    assert_eq!(rejected().await, None, "ending sessions");
}

async fn exercise_clients(store: &Store) {
    let public = client(store).await;
    let fetched = store.client(&public).await.unwrap().unwrap();
    assert!(!fetched.confidential);
    assert_eq!(fetched.redirect_uris, ["http://127.0.0.1:9999/callback"]);
    assert!(
        !store
            .verify_client_secret(&public, "anything")
            .await
            .unwrap()
    );

    let confidential = store
        .create_client(&NewClient {
            name: None,
            redirect_uris: vec![
                "https://a.example/cb".to_owned(),
                "https://b.example/cb".to_owned(),
            ],
            secret: Some(secret("s3cret")),
        })
        .await
        .unwrap();
    assert!(confidential.confidential);
    assert!(
        store
            .verify_client_secret(&confidential.id, "s3cret")
            .await
            .unwrap()
    );
    assert!(
        !store
            .verify_client_secret(&confidential.id, "wrong")
            .await
            .unwrap()
    );
    assert!(store.client("missing").await.unwrap().is_none());

    let err = store
        .create_client(&NewClient::default())
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InvalidInput(_)));
}

async fn exercise_oauth_flow(store: &Store) {
    let client_id = client(store).await;
    let account = store
        .upsert_account(&format!("{}@icloud.com", unique("flow")), &secret("pw"))
        .await
        .unwrap();

    let request_id = unique("request");
    let request = AuthorizationRequest {
        client_id: client_id.clone(),
        redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
        state: Some("xyz".to_owned()),
        code_challenge: "challenge".to_owned(),
        scope: "mail".to_owned(),
        resource: Some("https://mcp.example/mcp".to_owned()),
    };
    store
        .save_authorization_request(&request_id, &request, MINUTE)
        .await
        .unwrap();
    assert_eq!(
        store.authorization_request(&request_id).await.unwrap(),
        Some(request.clone())
    );
    store
        .delete_authorization_request(&request_id)
        .await
        .unwrap();
    assert_eq!(
        store.authorization_request(&request_id).await.unwrap(),
        None
    );

    let code = unique("code");
    let grant = CodeGrant {
        client_id: client_id.clone(),
        subject: GrantSubject::Account(account.id.clone()),
        redirect_uri: request.redirect_uri.clone(),
        code_challenge: request.code_challenge.clone(),
        scope: request.scope.clone(),
        resource: request.resource.clone(),
    };
    store.save_code(&code, &grant, MINUTE).await.unwrap();
    assert_eq!(
        store.take_code(&code).await.unwrap(),
        Redemption::Valid(grant.clone())
    );
    let (code_access, code_refresh) = (unique("access"), unique("refresh"));
    store
        .create_grant_for_code(&code, &grant, &code_access, MINUTE, &code_refresh, MINUTE)
        .await
        .unwrap()
        .unwrap();
    assert!(store.access_token(&code_access).await.unwrap().is_some());
    // A replayed code revokes the grant it created.
    assert_eq!(
        store.take_code(&code).await.unwrap(),
        Redemption::Replayed,
        "codes are single use"
    );
    assert!(store.access_token(&code_access).await.unwrap().is_none());
    assert_eq!(
        store
            .take_refresh_token(&code_refresh, &client_id)
            .await
            .unwrap(),
        Redemption::Invalid
    );
    assert_eq!(
        store.take_code(&unique("unknown")).await.unwrap(),
        Redemption::Invalid
    );

    // A replay racing the first redemption stops its grant from being made.
    let raced = unique("raced");
    store.save_code(&raced, &grant, MINUTE).await.unwrap();
    assert!(store.take_code(&raced).await.unwrap().valid().is_some());
    assert_eq!(store.take_code(&raced).await.unwrap(), Redemption::Replayed);
    assert_eq!(
        store
            .create_grant_for_code(
                &raced,
                &grant,
                &unique("access"),
                MINUTE,
                &unique("refresh"),
                MINUTE,
            )
            .await
            .unwrap(),
        None
    );

    let expired = unique("expired");
    store
        .save_code(&expired, &grant, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(
        store.take_code(&expired).await.unwrap(),
        Redemption::Invalid
    );

    let grant_id = store.create_grant(&grant).await.unwrap();
    let (access, refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&grant_id, &access, MINUTE, &refresh, MINUTE)
        .await
        .unwrap();
    let info = store.access_token(&access).await.unwrap().unwrap();
    assert_eq!(info.subject, GrantSubject::Account(account.id.clone()));
    assert_eq!(info.email.as_deref(), Some(account.email.as_str()));
    assert_eq!(info.resource, request.resource);
    assert!(store.access_token(&refresh).await.unwrap().is_none());

    assert_eq!(
        store
            .take_refresh_token(&refresh, "other-client")
            .await
            .unwrap(),
        Redemption::Invalid
    );
    let rotated = store
        .take_refresh_token(&refresh, &client_id)
        .await
        .unwrap()
        .valid()
        .unwrap();
    assert_eq!(rotated.grant_id, grant_id);
    let (access2, refresh2) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&grant_id, &access2, MINUTE, &refresh2, MINUTE)
        .await
        .unwrap();
    assert!(store.revoke_token(&refresh2, &client_id).await.unwrap());
    assert!(store.access_token(&access).await.unwrap().is_none());
    assert!(store.access_token(&access2).await.unwrap().is_none());
    assert!(!store.revoke_token(&refresh2, &client_id).await.unwrap());

    // RFC 7009 §2.1: a client cannot revoke another client's token, and
    // the attempt does not reveal that the token exists.
    let other = client(store).await;
    let foreign = store.create_grant(&grant).await.unwrap();
    let (foreign_access, foreign_refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&foreign, &foreign_access, MINUTE, &foreign_refresh, MINUTE)
        .await
        .unwrap();
    assert!(!store.revoke_token(&foreign_refresh, &other).await.unwrap());
    assert!(!store.revoke_token(&foreign_access, &other).await.unwrap());
    assert!(store.access_token(&foreign_access).await.unwrap().is_some());
    assert!(
        store
            .revoke_token(&foreign_refresh, &client_id)
            .await
            .unwrap()
    );
    assert!(store.access_token(&foreign_access).await.unwrap().is_none());

    // Reusing a rotated refresh token revokes the grant, including the
    // tokens issued by the rotation.
    let reused = store.create_grant(&grant).await.unwrap();
    let (access3, refresh3) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&reused, &access3, MINUTE, &refresh3, MINUTE)
        .await
        .unwrap();
    assert!(
        store
            .take_refresh_token(&refresh3, &client_id)
            .await
            .unwrap()
            .valid()
            .is_some()
    );
    let (access4, refresh4) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&reused, &access4, MINUTE, &refresh4, MINUTE)
        .await
        .unwrap();
    assert_eq!(
        store
            .take_refresh_token(&refresh3, &client_id)
            .await
            .unwrap(),
        Redemption::Replayed
    );
    assert!(store.access_token(&access4).await.unwrap().is_none());
    assert_eq!(
        store
            .take_refresh_token(&refresh4, &client_id)
            .await
            .unwrap(),
        Redemption::Invalid
    );

    let short = store.create_grant(&grant).await.unwrap();
    let (a, r) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&short, &a, Duration::ZERO, &r, Duration::ZERO)
        .await
        .unwrap();
    assert!(
        store.access_token(&a).await.unwrap().is_none(),
        "expired tokens are rejected"
    );
    assert!(store.purge_expired(PurgePolicy::default()).await.unwrap() >= 2);
    store.ping().await.unwrap();
}

async fn exercise_client_expiry(store: &Store) {
    let unused = client(store).await;
    let used = client(store).await;
    let account = store
        .upsert_account(&format!("{}@icloud.com", unique("expiry")), &secret("pw"))
        .await
        .unwrap();
    let grant_id = store
        .create_grant(&CodeGrant {
            client_id: used.clone(),
            subject: GrantSubject::Account(account.id.clone()),
            redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
            code_challenge: "challenge".to_owned(),
            scope: "mail".to_owned(),
            resource: None,
        })
        .await
        .unwrap();
    let refresh = unique("refresh");
    store
        .save_tokens(&grant_id, &unique("access"), MINUTE, &refresh, MINUTE)
        .await
        .unwrap();
    store.touch_client(&used).await.unwrap();
    assert!(store.client_count().await.unwrap() >= 2);

    let lenient = PurgePolicy {
        unused_client_ttl: Duration::from_hours(1),
        idle_client_ttl: Duration::from_hours(1),
    };
    let strict = PurgePolicy {
        unused_client_ttl: Duration::ZERO,
        idle_client_ttl: Duration::ZERO,
    };
    store.purge_expired(lenient).await.unwrap();
    assert!(store.client(&unused).await.unwrap().is_some());
    store.purge_expired(strict).await.unwrap();
    assert!(
        store.client(&unused).await.unwrap().is_none(),
        "unused client expires"
    );
    assert!(
        store.client(&used).await.unwrap().is_some(),
        "a client with a live grant is kept"
    );
    assert!(store.revoke_token(&refresh, &used).await.unwrap());
    store.purge_expired(strict).await.unwrap();
    assert!(
        store.client(&used).await.unwrap().is_none(),
        "idle client expires"
    );
}

#[tokio::test]
async fn sqlite_client_expiry() {
    let (store, _dir) = sqlite().await;
    exercise_client_expiry(&store).await;
    exercise_sessions(&store).await;
    exercise_account_clients(&store).await;
    exercise_webhooks(&store).await;
}

async fn exercise_sessions(store: &Store) {
    let email = format!("{}@icloud.com", unique("session"));
    let account = store
        .upsert_account(&email, &secret("abcdabcdabcdabcd"))
        .await
        .unwrap();
    let ttl = SessionTtl {
        idle: Duration::from_hours(1),
        absolute: Duration::from_hours(12),
    };
    let token = unique("token");
    store
        .create_session(&token, &account.id, ttl)
        .await
        .unwrap();
    assert_eq!(
        store.session(&token, ttl).await.unwrap(),
        Some(account.clone())
    );
    assert_eq!(store.session("other", ttl).await.unwrap(), None);
    store.delete_session(&token).await.unwrap();
    assert_eq!(store.session(&token, ttl).await.unwrap(), None);

    // An idle or absolute lifetime of zero ends the session at once.
    for ttl in [
        SessionTtl {
            idle: Duration::ZERO,
            absolute: Duration::from_hours(1),
        },
        SessionTtl {
            idle: Duration::from_hours(1),
            absolute: Duration::ZERO,
        },
    ] {
        let token = unique("short");
        store
            .create_session(&token, &account.id, ttl)
            .await
            .unwrap();
        assert_eq!(store.session(&token, ttl).await.unwrap(), None);
    }

    // Replacing a password ends every other account-page session and
    // leaves the caller's session, and other accounts, alone.
    let replaced = store
        .upsert_account(
            &format!("{}@icloud.com", unique("replaced")),
            &secret("abcdabcdabcdabcd"),
        )
        .await
        .unwrap();
    let current = unique("current");
    let other = unique("other");
    store
        .create_session(&current, &replaced.id, ttl)
        .await
        .unwrap();
    store
        .create_session(&other, &replaced.id, ttl)
        .await
        .unwrap();
    let foreign = store
        .upsert_account(
            &format!("{}@icloud.com", unique("foreign")),
            &secret("abcdabcdabcdabcd"),
        )
        .await
        .unwrap();
    let foreign_token = unique("foreign-token");
    store
        .create_session(&foreign_token, &foreign.id, ttl)
        .await
        .unwrap();
    assert_eq!(
        store
            .delete_other_sessions(&replaced.id, &current)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        store.session(&current, ttl).await.unwrap(),
        Some(replaced.clone())
    );
    assert_eq!(store.session(&other, ttl).await.unwrap(), None);
    assert_eq!(
        store.session(&foreign_token, ttl).await.unwrap(),
        Some(foreign)
    );
    assert_eq!(
        store
            .delete_other_sessions(&replaced.id, &current)
            .await
            .unwrap(),
        0
    );

    let overview = store.account_overview(&account.id).await.unwrap().unwrap();
    assert_eq!(overview.account, account);
    assert_eq!(overview.apps, 0);
    assert!(overview.created_at > 0);
    assert_eq!(store.revoke_account_grants(&account.id).await.unwrap(), 0);

    // Deleting the account ends its sessions.
    let token = unique("token");
    store
        .create_session(&token, &account.id, ttl)
        .await
        .unwrap();
    assert!(store.delete_account(&account.id).await.unwrap());
    assert_eq!(store.session(&token, ttl).await.unwrap(), None);
    assert!(store.account_overview(&account.id).await.unwrap().is_none());
}

fn settings(url: &str) -> WebhookSettings {
    WebhookSettings {
        enabled: true,
        url: url.to_owned(),
        auth_header: Some(("authorization".to_owned(), secret("Bearer t"))),
        signing: true,
        signing_secret: secret("whsec_one"),
        include_sender: false,
    }
}

fn record(succeeded: bool, test: bool) -> DeliveryRecord {
    DeliveryRecord {
        created_at: postkeep_store::now(),
        test,
        succeeded,
        summary: if succeeded {
            "HTTP 200 OK (after 1 attempt)"
        } else {
            "HTTP 500 (after 4 attempts)"
        }
        .to_owned(),
        elapsed_ms: Some(12),
    }
}

async fn exercise_webhooks(store: &Store) {
    let email = format!("{}@icloud.com", unique("hook"));
    let account = store.upsert_account(&email, &secret("pw")).await.unwrap();
    assert!(store.webhook(&account.id).await.unwrap().is_none());

    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert!(hook.settings.enabled && hook.settings.signing && !hook.settings.include_sender);
    assert_eq!(hook.settings.url, "https://a.example/h");
    let (name, value) = hook.settings.auth_header.clone().unwrap();
    assert_eq!(
        (name.as_str(), value.expose_secret()),
        ("authorization", "Bearer t")
    );
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_one");
    assert!(hook.cursor.is_none());
    assert!(
        store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account.id)
    );

    // The position moves only from where it was read, and no event is counted.
    // A webhook without one moves from none, and from no other.
    let at = |uid_validity, last_uid| WatchCursor {
        uid_validity,
        last_uid,
    };
    let (id, ghost) = (&account.id, AccountId("ghost".to_owned()));
    let advance = async |id: &AccountId, from: Option<WatchCursor>, to| {
        store.advance_watch_cursor(id, from, to).await.unwrap()
    };
    let cursor_of = async || store.webhook(id).await.unwrap().unwrap().cursor;
    assert!(!advance(id, Some(at(6, 0)), at(6, 5)).await);
    assert!(!advance(&ghost, None, at(6, 5)).await);
    assert_eq!(cursor_of().await, None);
    assert!(advance(id, None, at(6, 5)).await);
    assert!(!advance(id, None, at(6, 9)).await);
    assert_eq!(cursor_of().await, Some(at(6, 5)), "left as it was");

    let cursor = at(7, 41);
    store.set_watch_cursor(id, cursor).await.unwrap();
    assert_eq!(cursor_of().await, Some(cursor));
    let to = at(7, 90);
    assert!(!advance(id, Some(at(7, 40)), to).await && !advance(id, Some(at(8, 41)), to).await);
    assert!(!advance(&ghost, Some(cursor), to).await);
    assert!(advance(id, Some(cursor), to).await);
    let hook = store.webhook(id).await.unwrap().unwrap();
    assert_eq!((hook.cursor, hook.last_sequence), (Some(to), 0));
    assert!(advance(id, Some(to), cursor).await);

    // A Graph or Gmail position moves the same way: from none for a webhook
    // that has none, and only from the one that was read.
    let (first, second) = ("graph:one", "graph:two");
    let step = async |id: &AccountId, from: Option<&str>, next: &str| {
        store.advance_watch_position(id, from, next).await.unwrap()
    };
    let position = async || store.webhook(id).await.unwrap().unwrap().position;
    assert!(!step(id, Some(first), second).await && !step(&ghost, None, first).await);
    assert_eq!(position().await, None);
    assert!(step(id, None, first).await);
    assert!(!step(id, None, second).await && !step(id, Some(second), first).await);
    assert_eq!(position().await.as_deref(), Some(first), "left as it was");
    assert!(step(id, Some(first), first).await, "to the same position");
    assert!(step(id, Some(first), second).await);
    let hook = store.webhook(id).await.unwrap().unwrap();
    assert_eq!(
        (hook.position.as_deref(), hook.last_sequence),
        (Some(second), 0)
    );

    // Test failures are logged but don't count; real failures do, and the
    // limit pauses the webhook without turning it off.
    store
        .record_delivery(&account.id, &record(false, true))
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.consecutive_failures, 0);
    assert!(hook.last_error.is_some());
    assert!(hook.paused_at.is_none());
    for _ in 1..MAX_CONSECUTIVE_FAILURES {
        assert_eq!(
            store
                .record_delivery(&account.id, &record(false, false))
                .await
                .unwrap(),
            DeliveryEffect::None
        );
    }
    store
        .record_delivery(&account.id, &record(true, false))
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.consecutive_failures, 0, "a success resets the count");
    assert!(hook.last_error.is_none() && hook.last_success_at.is_some());
    assert_eq!(hook.delivery_state(), "active");

    // Saving an already-active webhook with the same URL keeps a count
    // that has not reached the limit.
    store
        .record_delivery(&account.id, &record(false, false))
        .await
        .unwrap();
    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    assert_eq!(
        store
            .webhook(&account.id)
            .await
            .unwrap()
            .unwrap()
            .consecutive_failures,
        1
    );

    for _ in 1..MAX_CONSECUTIVE_FAILURES {
        store
            .record_delivery(&account.id, &record(false, false))
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .record_delivery(&account.id, &record(false, false))
            .await
            .unwrap(),
        DeliveryEffect::Paused
    );
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert!(hook.settings.enabled);
    assert!(hook.paused_at.is_some());
    assert!(hook.disabled_reason.is_none());
    assert!(hook.is_paused());
    assert_eq!(hook.delivery_state(), "paused");
    assert_eq!(
        hook.next_retry_at(3600),
        Some(hook.last_attempt_at.unwrap() + 3600)
    );
    assert!(
        store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account.id)
    );
    let paused_at = hook.paused_at;
    let failures = hook.consecutive_failures;

    // Further failures keep the same pause. Test events neither count nor
    // recover it.
    assert_eq!(
        store
            .record_delivery(&account.id, &record(false, false))
            .await
            .unwrap(),
        DeliveryEffect::Paused
    );
    store
        .record_delivery(&account.id, &record(true, true))
        .await
        .unwrap();
    store
        .record_delivery(&account.id, &record(false, true))
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.paused_at, paused_at);
    assert_eq!(hook.consecutive_failures, failures + 1);
    assert!(hook.settings.enabled);
    assert!(hook.last_error.is_some());

    // The first real success clears the pause and the counter.
    assert_eq!(
        store
            .record_delivery(&account.id, &record(true, false))
            .await
            .unwrap(),
        DeliveryEffect::None
    );
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.consecutive_failures, 0);
    assert!(hook.paused_at.is_none());
    assert!(hook.last_error.is_none());
    assert!(hook.settings.enabled);
    assert!(hook.next_retry_at(3600).is_none());

    // Only the latest deliveries are kept.
    let recent = store.recent_deliveries(&account.id).await.unwrap();
    assert_eq!(recent.len(), usize::try_from(KEPT_DELIVERIES).unwrap());

    // Events recorded while paused are kept when the same URL is saved.
    assert!(matches!(
        store
            .append_mail_event(&account.id, r#"{"n":1}"#, None)
            .await
            .unwrap(),
        AppendOutcome::Stored(_)
    ));
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        store
            .record_delivery(&account.id, &record(false, false))
            .await
            .unwrap();
    }
    assert!(matches!(
        store
            .append_mail_event(&account.id, r#"{"n":2}"#, None)
            .await
            .unwrap(),
        AppendOutcome::Stored(_)
    ));
    let before = store.webhook(&account.id).await.unwrap().unwrap();
    assert!(before.is_paused());
    assert_eq!(before.delivered_sequence, 0);
    assert_eq!(before.last_sequence, 2);
    assert_eq!(
        store.pending_mail_event_count(&account.id).await.unwrap(),
        2
    );
    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert!(hook.settings.enabled);
    assert!(hook.paused_at.is_none());
    assert_eq!(hook.consecutive_failures, 0);
    assert_eq!(hook.delivered_sequence, 0, "a paused queue is kept");
    assert_eq!(
        store.pending_mail_event_count(&account.id).await.unwrap(),
        2
    );
    assert_eq!(hook.cursor, Some(cursor));

    // Changing the URL skips that queue. The cursor still survives.
    let mut changed = settings("https://a.example/other");
    changed.auth_header = None;
    changed.signing_secret = secret("whsec_two");
    store.save_webhook(&account.id, &changed).await.unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert!(hook.settings.enabled);
    assert_eq!(hook.consecutive_failures, 0);
    assert!(hook.disabled_reason.is_none());
    assert!(hook.paused_at.is_none());
    assert!(hook.settings.auth_header.is_none());
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_two");
    assert_eq!(hook.cursor, Some(cursor));
    assert_eq!(hook.delivered_sequence, hook.last_sequence);
    assert_eq!(
        store.pending_mail_event_count(&account.id).await.unwrap(),
        0
    );

    // Saving disabled keeps the failure count and does not pause.
    store
        .record_delivery(&account.id, &record(false, false))
        .await
        .unwrap();
    changed.enabled = false;
    store.save_webhook(&account.id, &changed).await.unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);
    assert_eq!(hook.consecutive_failures, 1);
    assert!(hook.paused_at.is_none());
    assert_eq!(hook.delivery_state(), "disabled");

    // Turning it off explicitly stays off. Failures do not pause it or
    // turn it back on, and it is left out of the watcher list.
    assert!(
        !store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account.id)
    );
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        assert_eq!(
            store
                .record_delivery(&account.id, &record(false, false))
                .await
                .unwrap(),
            DeliveryEffect::None
        );
    }
    store
        .record_delivery(&account.id, &record(true, false))
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);
    assert!(hook.paused_at.is_none());
    assert!(
        !store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account.id)
    );

    // Events kept while it was off are skipped when it is turned back on.
    // The cursor survives.
    assert!(matches!(
        store
            .append_mail_event(&account.id, r#"{"n":3}"#, None)
            .await
            .unwrap(),
        AppendOutcome::Stored(_)
    ));
    let before = store.webhook(&account.id).await.unwrap().unwrap();
    let resumed = ready_webhook(store.set_webhook_enabled(&account.id, true).await.unwrap());
    assert!(resumed.settings.enabled);
    assert!(resumed.paused_at.is_none());
    assert_eq!(resumed.consecutive_failures, 0);
    assert_eq!(resumed.delivered_sequence, before.last_sequence);
    assert_eq!(resumed.cursor, Some(cursor));
    assert_eq!(
        store.pending_mail_event_count(&account.id).await.unwrap(),
        0
    );
    assert!(
        store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account.id)
    );

    // Turning off through the same call clears a later pause and stays off.
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        store
            .record_delivery(&account.id, &record(false, false))
            .await
            .unwrap();
    }
    assert!(
        store
            .webhook(&account.id)
            .await
            .unwrap()
            .unwrap()
            .is_paused()
    );
    let disabled = ready_webhook(store.set_webhook_enabled(&account.id, false).await.unwrap());
    assert!(!disabled.settings.enabled);
    assert!(disabled.paused_at.is_none());
    assert!(disabled.consecutive_failures >= MAX_CONSECUTIVE_FAILURES);
    let missing = store
        .upsert_account(&format!("{}@example.com", unique("hook")), &secret("pw"))
        .await
        .unwrap();
    assert!(matches!(
        store.set_webhook_enabled(&missing.id, true).await.unwrap(),
        LoadedWebhook::Missing
    ));

    // Ciphertexts are bound to their account.
    let other = store
        .upsert_account(&format!("{}@icloud.com", unique("hook")), &secret("pw"))
        .await
        .unwrap();
    store
        .save_webhook(&other.id, &settings("https://b.example/h"))
        .await
        .unwrap();
    assert!(store.webhook(&other.id).await.unwrap().is_some());

    store.delete_webhook(&other.id).await.unwrap();
    assert!(store.webhook(&other.id).await.unwrap().is_none());
    assert!(store.delete_account(&account.id).await.unwrap());
    assert!(store.webhook(&account.id).await.unwrap().is_none());
    assert_eq!(
        store.recent_deliveries(&account.id).await.unwrap(),
        Vec::new()
    );
}

fn rule(pattern: &str) -> NewFilterRule {
    NewFilterRule {
        action: "allow".to_owned(),
        field: "subject".to_owned(),
        kind: "contains".to_owned(),
        pattern: secret(pattern),
    }
}

/// Adds a rule that the check lets through.
async fn add_rule(store: &Store, id: &AccountId, pattern: &str, limit: usize) -> AddedFilterRule {
    let new = rule(pattern);
    let added = store.add_webhook_filter_rule(id, &new, limit, |_| Ok(()));
    added.await.unwrap()
}

/// Adds a rule that must be stored, and returns its ID.
async fn added(store: &Store, id: &AccountId, pattern: &str, limit: usize) -> String {
    match add_rule(store, id, pattern, limit).await {
        AddedFilterRule::Added(rule) => rule,
        other => panic!("{pattern} was not added: {other:?}"),
    }
}

/// The patterns of the rules, each followed by `+` if the rule is active and
/// by `-` if not, and then by `0` if it is turned off.
fn marks(rules: &[FilterRule]) -> Vec<String> {
    let shown = |rule: &FilterRule| {
        let mark = if rule.active { '+' } else { '-' };
        let off = if rule.enabled { "" } else { "0" };
        format!("{}{mark}{off}", rule.pattern.expose_secret())
    };
    rules.iter().map(shown).collect()
}

/// The marks of an account's rules at `limit`, oldest first.
async fn rules_of(store: &Store, id: &AccountId, limit: usize) -> Vec<String> {
    marks(&store.webhook_filter_rules(id, limit).await.unwrap())
}

/// Turns a rule on or off with a check that lets everything through.
async fn turn(store: &Store, id: &AccountId, rule: &str, on: bool) -> ChangedFilterRule {
    let set = store.set_webhook_filter_rule_enabled(id, rule, on, 9, |_| Ok(()));
    set.await.unwrap()
}

async fn version(store: &Store, id: &AccountId) -> Option<i64> {
    store.webhook_filter_rules_version(id).await.unwrap()
}

/// Whether the account had that rule, which is now removed.
async fn rm(store: &Store, id: &AccountId, rule: &str) -> bool {
    store.remove_webhook_filter_rule(id, rule).await.unwrap()
}

/// Changes the rules whose `key` is `value`, to place them in time.
async fn set_rules(store: &Store, set: &str, key: &str, value: &str) {
    let sql = format!("UPDATE webhook_filter_rules SET {set} WHERE {key} = $1");
    let done = sqlx::query(sqlx::AssertSqlSafe(sql)).bind(value);
    done.execute(store.pool()).await.unwrap();
}

async fn mailbox(store: &Store, label: &str) -> AccountId {
    let email = format!("{}@icloud.com", unique(label));
    store
        .upsert_account(&email, &secret("pw"))
        .await
        .unwrap()
        .id
}

async fn exercise_held_sends(store: &Store) {
    use HeldSendMatch::{Differs, Matched, Missing};
    let (a, b) = (
        mailbox(store, "held-a").await,
        mailbox(store, "held-b").await,
    );
    let arguments = serde_json::json!({"to": ["a@example.com"], "body": "placeholder body"});
    let send = HeldSend {
        account: &a,
        principal: "caller",
        app: "app",
        id: "random-hold-id",
        tool: "send_message",
        arguments: &arguments,
    };
    assert!(store.hold_send(send, MINUTE, 1).await.unwrap().is_some());
    assert_eq!(
        store
            .hold_send(
                HeldSend {
                    id: "another",
                    ..send
                },
                MINUTE,
                1
            )
            .await
            .unwrap(),
        None
    );
    for wrong in [
        HeldSend {
            account: &b,
            ..send
        },
        HeldSend {
            principal: "other",
            ..send
        },
        HeldSend {
            app: "other-app",
            ..send
        },
        HeldSend {
            id: "unknown",
            ..send
        },
    ] {
        assert_eq!(store.take_held_send(wrong).await.unwrap(), Missing);
    }
    assert_eq!(
        store
            .take_held_send(HeldSend {
                tool: "reply_to_message",
                ..send
            })
            .await
            .unwrap(),
        Differs
    );
    let changed = serde_json::json!({"to": ["a@example.com"], "body": "changed body"});
    assert_eq!(
        store
            .take_held_send(HeldSend {
                arguments: &changed,
                ..send
            })
            .await
            .unwrap(),
        Differs
    );
    // Object order does not change the parsed arguments' fingerprint.
    let confirming =
        serde_json::from_str(r#"{"body":"placeholder body","to":["a@example.com"]}"#).unwrap();
    let take = HeldSend {
        arguments: &confirming,
        ..send
    };
    let (one, two) = tokio::join!(store.take_held_send(take), store.take_held_send(take));
    assert!(matches!(
        (one.unwrap(), two.unwrap()),
        (Matched, Missing) | (Missing, Matched)
    ));
    assert_eq!(store.take_held_send(send).await.unwrap(), Missing);
    let expired = HeldSend {
        id: "expired",
        ..send
    };
    store
        .hold_send(expired, Duration::ZERO, 1)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(store.take_held_send(expired).await.unwrap(), Missing);
    assert_eq!(
        store
            .take_held_send(HeldSend {
                arguments: &changed,
                ..expired
            })
            .await
            .unwrap(),
        Missing,
        "an expired hold is missing even when its arguments differ"
    );
    // Expired holds take no place in the cap; the cap is per caller and mailbox.
    for live in [
        send,
        HeldSend {
            principal: "other",
            ..send
        },
        HeldSend {
            account: &b,
            ..send
        },
    ] {
        let id = format!("{}-{}", live.account.0, live.principal);
        let live = HeldSend { id: &id, ..live };
        assert!(store.hold_send(live, MINUTE, 1).await.unwrap().is_some());
    }
    let expired_rows = || {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM held_sends WHERE account_id = $1 AND expires_at <= $2",
        )
        .bind(&a.0)
        .bind(postkeep_store::now())
        .fetch_one(store.pool())
    };
    assert_eq!(expired_rows().await.unwrap(), 1);
    store.purge_expired(PurgePolicy::default()).await.unwrap();
    assert_eq!(expired_rows().await.unwrap(), 0);
    store.delete_account(&a).await.unwrap();
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM held_sends WHERE account_id = $1")
            .bind(&a.0)
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(remaining, 0);
    store.delete_account(&b).await.unwrap();
}

#[tokio::test]
async fn sqlite_held_sends() {
    let (store, _dir) = sqlite().await;
    exercise_held_sends(&store).await;
}

/// The least an upload counts toward the stored bounds, as the server sets it.
const LEAST: i64 = 64 * 1024;

async fn tenant_mailbox(store: &Store, tenant: &str, label: &str) -> AccountId {
    let email = format!("{}@example.com", unique(label));
    let scoped = store.for_tenant(tenant);
    scoped
        .upsert_account(&email, &secret("pw"))
        .await
        .unwrap()
        .id
}

/// A new waiting upload of `owner` for `ttl`, as its id and token.
async fn upload(store: &Store, owner: UploadOwner<'_>, ttl: Duration) -> (String, String) {
    let (id, token) = (unique("id"), unique("token"));
    let made = store.create_upload(owner, &id, &token, ttl, 100).await;
    assert!(made.unwrap().is_some());
    (id, token)
}

async fn claim(store: &Store, token: &str, bounds: UploadBounds) -> Result<Claimed, ClaimRefused> {
    store
        .claim_upload(token, &unique("object"), 1, bounds)
        .await
        .unwrap()
}

async fn exercise_uploads(store: &Store, url: &str) {
    use ClaimRefused::{Server, Tenant, Unknown};
    let tenant = unique("uploads");
    let a = tenant_mailbox(store, &tenant, "up-a").await;
    let b = tenant_mailbox(store, &tenant, "up-b").await;
    let c = tenant_mailbox(store, &unique("uploads"), "up-c").await;
    let owner = UploadOwner {
        account: &a,
        principal: "caller",
        app: "app",
    };
    let (on_b, on_c) = (
        UploadOwner {
            account: &b,
            ..owner
        },
        UploadOwner {
            account: &c,
            ..owner
        },
    );
    let open = UploadBounds {
        tenant_arriving: 2,
        tenant_stored: i64::MAX / 4,
        server_arriving: i64::MAX,
        server_stored: i64::MAX / 4,
        least: LEAST,
        window: MINUTE,
    };

    // The tenant's waiting uploads are capped across its mailboxes; ended ones
    // take no place, and take no file.
    let ended = unique("ended");
    let made = store.create_upload(owner, "ended", &ended, Duration::ZERO, 2);
    assert!(made.await.unwrap().is_some());
    for (owner, waits) in [(owner, true), (on_b, true), (owner, false), (on_c, true)] {
        let (id, token) = (unique("id"), unique("token"));
        let made = store.create_upload(owner, &id, &token, MINUTE, 2);
        assert_eq!(made.await.unwrap().is_some(), waits);
    }
    assert_eq!(claim(store, &ended, open).await.unwrap_err(), Unknown);

    // Once its file is in, only its owner finds it, with its key and digest.
    let (id, token) = upload(store, owner, MINUTE).await;
    let claimed = claim(store, &token, open).await.unwrap();
    let found = store.upload_for(owner, &id, MINUTE).await.unwrap();
    assert!(matches!(found, UploadLookup::Arriving), "{found:?}");
    assert!(store.finish_upload(&claimed, 5, &[7; 32]).await.unwrap());
    let UploadLookup::Stored {
        object,
        key: opened,
        digest,
        size,
        ..
    } = store.upload_for(owner, &id, MINUTE).await.unwrap()
    else {
        panic!("not stored");
    };
    assert_eq!(
        (object.as_str(), opened.expose(), digest, size),
        (claimed.object(), claimed.key().expose(), [7; 32], 5)
    );
    let (other_app, other_principal) = (
        UploadOwner {
            app: "other-app",
            ..owner
        },
        UploadOwner {
            principal: "other",
            ..owner
        },
    );
    for stranger in [other_app, other_principal, on_b] {
        let found = store.upload_for(stranger, &id, MINUTE).await.unwrap();
        assert!(matches!(found, UploadLookup::Missing), "{found:?}");
    }

    // All or none: with one already used, neither is used. A used upload is
    // missing, but counts as stored, at least 64 KiB even when empty, until
    // its row is forgotten.
    let (empty, token) = upload(store, owner, MINUTE).await;
    let second = claim(store, &token, open).await.unwrap();
    assert!(store.finish_upload(&second, 0, &[0; 32]).await.unwrap());
    let first = store.use_uploads(owner, &[&id]).await.unwrap().unwrap();
    assert_eq!(
        store.use_uploads(owner, &[&empty, &id]).await.unwrap(),
        Err(1)
    );
    let found = store.upload_for(owner, &empty, MINUTE).await.unwrap();
    assert!(
        matches!(found, UploadLookup::Stored { size: 0, .. }),
        "{found:?}"
    );
    let used = store.use_uploads(owner, &[&empty]).await.unwrap().unwrap();
    for gone in [&id, &empty] {
        let found = store.upload_for(owner, gone, MINUTE).await.unwrap();
        assert!(matches!(found, UploadLookup::Missing), "{found:?}");
    }
    let small = UploadBounds {
        tenant_stored: 3 * LEAST - 1,
        ..open
    };
    let (_, token) = upload(store, owner, MINUTE).await;
    assert_eq!(claim(store, &token, small).await.unwrap_err(), Tenant);
    for done in first.iter().chain(&used) {
        store.forget_upload(done).await.unwrap();
    }
    // The refusal left the token working; a stopped upload uses it up.
    let stopped = claim(store, &token, small).await.unwrap();
    let done = store.use_attempt(&stopped).await.unwrap();
    assert_eq!(claim(store, &token, open).await.unwrap_err(), Unknown);
    store.forget_upload(&done).await.unwrap();

    // Of two claims of one token, one wins.
    let (_, token) = upload(store, owner, MINUTE).await;
    let (one, two) = tokio::join!(claim(store, &token, open), claim(store, &token, open));
    let won = match (one, two) {
        (Ok(won), Err(Unknown)) | (Err(Unknown), Ok(won)) => won,
        other => panic!("{other:?}"),
    };
    // The tenant's arrivals are counted across its mailboxes; another tenant's
    // go through, up to the server's bounds.
    let (_, token) = upload(store, on_b, MINUTE).await;
    claim(store, &token, open).await.unwrap();
    let (_, token) = upload(store, owner, MINUTE).await;
    assert_eq!(claim(store, &token, open).await.unwrap_err(), Tenant);
    let (_, elsewhere) = upload(store, on_c, MINUTE).await;
    for full in [
        UploadBounds {
            server_arriving: 0,
            ..open
        },
        UploadBounds {
            server_stored: 0,
            ..open
        },
    ] {
        assert_eq!(claim(store, &elsewhere, full).await.unwrap_err(), Server);
    }
    claim(store, &elsewhere, open).await.unwrap();

    // After a restart the claims left behind keep their reservations and stop
    // counting as arriving after their window. A stored upload past its hour
    // and the arrivals past their window are used by the next cleanup, which
    // deletes ended waiting uploads and returns at most `most`.
    let (late, ending) = upload(store, owner, Duration::from_secs(2)).await;
    let stored = store.claim_upload(
        &ending,
        "late-object",
        1,
        UploadBounds {
            window: Duration::ZERO,
            ..open
        },
    );
    let stored = stored.await.unwrap().unwrap();
    assert!(store.finish_upload(&stored, 9, &[9; 32]).await.unwrap());
    let restarted = Store::connect(url, &key()).await.unwrap();
    let kept = UploadBounds {
        tenant_arriving: i64::MAX,
        tenant_stored: 4 * LEAST - 1,
        ..open
    };
    assert_eq!(claim(&restarted, &token, kept).await.unwrap_err(), Tenant);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let window = Duration::from_secs(2);
    let found = restarted.upload_for(owner, &late, MINUTE).await.unwrap();
    assert!(matches!(found, UploadLookup::Missing), "{found:?}");
    assert_eq!(
        restarted.uploads_to_clean(window, 1).await.unwrap().len(),
        1
    );
    let cleaned = restarted.uploads_to_clean(window, 10_000).await.unwrap();
    let names: Vec<&str> = cleaned.iter().map(|used| used.object.as_str()).collect();
    for name in [won.object(), "late-object"] {
        assert!(names.contains(&name), "{name} not in {names:?}");
    }
    let late_key: Option<String> =
        sqlx::query_scalar("SELECT key_ciphertext FROM uploads WHERE object = $1")
            .bind("late-object")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(late_key, None);
    let ended: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads WHERE account_id = $1 AND claimed_at IS NULL AND expires_at <= $2")
        .bind(&a.0)
        .bind(postkeep_store::now())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(ended, 0);
    claim(&restarted, &token, open).await.unwrap();

    // With the account, its uploads go.
    for account in [&a, &b, &c] {
        store.delete_account(account).await.unwrap();
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM uploads WHERE account_id = $1")
            .bind(&account.0)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(left, 0);
    }
    restarted.close().await;
}

#[tokio::test]
async fn sqlite_uploads() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let store = Store::connect(&url, &key()).await.unwrap();
    exercise_uploads(&store, &url).await;
}

/// A piece opens only under its own key and number, whole; an empty one opens
/// to nothing.
#[test]
fn upload_pieces_open_only_as_sealed() {
    let (key, other) = (DataKey::generate().unwrap(), DataKey::generate().unwrap());
    let sealed = |bytes: &[u8]| {
        let mut buffer = Vec::with_capacity(bytes.len() + PIECE_TAG);
        buffer.extend_from_slice(bytes);
        seal_piece(&key, 3, &mut buffer).unwrap();
        buffer
    };
    let mut piece = sealed(b"piece");
    assert_eq!(piece.len(), 5 + PIECE_TAG);
    for (key, number, cut) in [(&key, 2, 0), (&other, 3, 0), (&key, 3, 1)] {
        let mut copy = piece[..piece.len() - cut].to_vec();
        assert!(open_piece(key, number, &mut copy).is_err());
    }
    open_piece(&key, 3, &mut piece).unwrap();
    assert_eq!(piece, b"piece");
    let mut empty = sealed(b"");
    assert_eq!(empty.len(), PIECE_TAG);
    open_piece(&key, 3, &mut empty).unwrap();
    assert_eq!(empty, Vec::<u8>::new());
}

/// The check sees the rules as they are, and can refuse the new one. It runs
/// again when an add or remove came in after it saw the rules.
async fn exercise_a_check_runs_again(store: &Store, a: &AccountId) {
    store.remove_webhook_filter_rules(a).await.unwrap();
    added(store, a, "kept", 4).await;
    let new = rule("big");
    let big = store.add_webhook_filter_rule(a, &new, 4, |rules| {
        assert_eq!(rules.len(), 1);
        Err("too large".to_owned())
    });
    let refused = AddedFilterRule::Refused("too large".to_owned());
    assert_eq!(big.await.unwrap(), refused);
    let (mut seen, new) = (Vec::new(), rule("late"));
    let late = store.add_webhook_filter_rule(a, &new, 4, |rules| {
        seen.push(rules.len());
        if seen.len() == 1 {
            let first = add_rule(store, a, "first", 4);
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(first));
        }
        Ok(())
    });
    assert!(matches!(late.await.unwrap(), AddedFilterRule::Added(_)));
    assert_eq!(seen, [1, 2]);
    assert_eq!(rules_of(store, a, 9).await, ["kept+", "first+", "late+"]);
}

/// Three adds for the one place left all see the same rules, because each
/// check waits once for the other two. Only the compare-and-set keeps the limit.
async fn exercise_adds_at_the_same_moment(store: &Store, a: &AccountId) {
    store.remove_webhook_filter_rules(a).await.unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let adds = ["p", "q", "r"].map(|pattern| {
        let (store, a, barrier) = (store.clone(), a.clone(), barrier.clone());
        tokio::spawn(async move {
            let (mut waited, new) = (false, rule(pattern));
            let check = |_: &[FilterRule]| {
                if !std::mem::replace(&mut waited, true) {
                    tokio::task::block_in_place(|| barrier.wait());
                }
                Ok(())
            };
            let added = store.add_webhook_filter_rule(&a, &new, 1, check);
            matches!(added.await.unwrap(), AddedFilterRule::Added(_))
        })
    });
    let mut stored = 0;
    for add in adds {
        stored += usize::from(add.await.unwrap());
    }
    assert_eq!((stored, rules_of(store, a, 9).await.len()), (1, 1));
}

/// A rule turned off keeps its place and counts toward the limit. Turning one
/// off always applies; turning one on is checked as an add is.
async fn exercise_rules_turned_off_and_on(store: &Store, a: &AccountId, b: &AccountId) {
    store.remove_webhook_filter_rules(a).await.unwrap();
    let mut ids = Vec::new();
    for pattern in ["one", "two", "three"] {
        ids.push(added(store, a, pattern, 9).await);
    }
    let c = version(store, a).await.unwrap();
    let (changed, refuse) = (ChangedFilterRule::Changed, |_: &[FilterRule]| {
        Err("no".to_owned())
    });

    // Off runs no check.
    let off = store.set_webhook_filter_rule_enabled(a, &ids[0], false, 9, refuse);
    assert_eq!(off.await.unwrap(), changed);
    assert_eq!(version(store, a).await, Some(c + 1));
    assert_eq!(rules_of(store, a, 2).await, ["one-0", "two+", "three-"]);
    assert_eq!(
        add_rule(store, a, "four", 3).await,
        AddedFilterRule::AtLimit
    );

    // On is given the rules as they would be, where only this rule changed.
    assert_eq!(turn(store, a, &ids[1], false).await, changed);
    assert_eq!(version(store, a).await, Some(c + 2));
    let mut given = Vec::new();
    let on = store.set_webhook_filter_rule_enabled(a, &ids[0], true, 2, |rules| {
        given = marks(rules);
        Err("too large".to_owned())
    });
    let refused = ChangedFilterRule::Refused("too large".to_owned());
    assert_eq!(on.await.unwrap(), refused);
    assert_eq!(given, ["one+", "two-0", "three-"]);
    assert_eq!(rules_of(store, a, 9).await, ["one-0", "two-0", "three+"]);
    assert_eq!(version(store, a).await, Some(c + 2));
    assert_eq!(turn(store, a, &ids[0], true).await, changed);
    assert_eq!(rules_of(store, a, 9).await, ["one+", "two-0", "three+"]);
    assert_eq!(version(store, a).await, Some(c + 3));

    // Only a mailbox's own rules, and nothing counts.
    let (missing, gone) = (AccountId(unique("missing")), ChangedFilterRule::NotFound);
    let other = version(store, b).await;
    for on in [true, false] {
        assert_eq!(turn(store, a, "no-such-rule", on).await, gone);
        assert_eq!(turn(store, b, &ids[0], on).await, gone);
    }
    assert_eq!(turn(store, &missing, &ids[0], true).await, gone);
    assert_eq!(rules_of(store, a, 9).await, ["one+", "two-0", "three+"]);
    assert_eq!(
        (version(store, a).await, version(store, b).await),
        (Some(c + 3), other)
    );

    // A rule turned on past the limit is inactive in the view.
    let mut given = Vec::new();
    let edge = store.set_webhook_filter_rule_enabled(a, &ids[1], true, 1, |rules| {
        given = marks(rules);
        Err("too large".to_owned())
    });
    assert_eq!(edge.await.unwrap(), refused);
    assert_eq!(given, ["one+", "two-", "three-"]);

    // The check runs again when another change came in after it saw the rules.
    let mut seen = Vec::new();
    let on = store.set_webhook_filter_rule_enabled(a, &ids[1], true, 9, |rules| {
        seen.push(rules.len());
        if seen.len() == 1 {
            let late = add_rule(store, a, "late", 9);
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(late));
        }
        Ok(())
    });
    assert_eq!(on.await.unwrap(), changed);
    assert_eq!(seen, [3, 4]);
    assert_eq!(
        rules_of(store, a, 9).await,
        ["one+", "two+", "three+", "late+"]
    );
}

/// A change keeps the rule's ID, place and on/off state, is checked on the
/// rules as they would be, and counts once.
async fn exercise_a_rule_changed_in_its_place(store: &Store, a: &AccountId, b: &AccountId) {
    store.remove_webhook_filter_rules(a).await.unwrap();
    let mut ids = Vec::new();
    for pattern in ["one", "two", "three"] {
        ids.push(added(store, a, pattern, 9).await);
    }
    assert_eq!(
        turn(store, a, &ids[1], false).await,
        ChangedFilterRule::Changed
    );
    let c = version(store, a).await.unwrap();
    let before = store.webhook_filter_rules(a, 9).await.unwrap();
    let new = NewFilterRule {
        action: "block".to_owned(),
        field: "from".to_owned(),
        kind: "equals".to_owned(),
        pattern: secret("x@example.com"),
    };
    let shown = |rule: &FilterRule| {
        let (action, field, kind) = (&rule.action, &rule.field, &rule.kind);
        let pattern = rule.pattern.expose_secret();
        format!("{action} {field} {kind} {pattern} {}", rule.enabled)
    };
    let refused = ChangedFilterRule::Refused("no".to_owned());

    // The check is given the new values at the rule's place, still off.
    let mut given = String::new();
    let edit = store.update_webhook_filter_rule(a, &ids[1], &new, 9, |rules| {
        given = shown(&rules[1]);
        Err("no".to_owned())
    });
    assert_eq!(edit.await.unwrap(), refused);
    assert_eq!(given, "block from equals x@example.com false");
    let rules = store.webhook_filter_rules(a, 9).await.unwrap();
    assert_eq!(shown(&rules[1]), "allow subject contains two false");
    assert_eq!(version(store, a).await, Some(c));

    // A rule that is off stays inactive in the view of another rule's change.
    let mut given = Vec::new();
    let uno = rule("uno");
    let edit = store.update_webhook_filter_rule(a, &ids[0], &uno, 9, |rules| {
        given = marks(rules);
        Err("no".to_owned())
    });
    assert_eq!(edit.await.unwrap(), refused);
    assert_eq!(given, ["uno+", "two-0", "three+"]);
    assert_eq!(rules_of(store, a, 9).await, ["one+", "two-0", "three+"]);
    assert_eq!(version(store, a).await, Some(c));

    let edit = store.update_webhook_filter_rule(a, &ids[1], &new, 9, |_| Ok(()));
    assert_eq!(edit.await.unwrap(), ChangedFilterRule::Changed);
    let after = store.webhook_filter_rules(a, 9).await.unwrap();
    let place = |rules: &[FilterRule]| -> Vec<(String, i64)> {
        rules.iter().map(|r| (r.id.clone(), r.added_at)).collect()
    };
    assert_eq!(place(&after), place(&before));
    assert_eq!(shown(&after[1]), "block from equals x@example.com false");
    assert_eq!(shown(&after[0]), "allow subject contains one true");
    assert_eq!(shown(&after[2]), "allow subject contains three true");
    assert_eq!(version(store, a).await, Some(c + 1));

    // Only a mailbox's own rules, and nothing counts.
    let (missing, gone) = (AccountId(unique("missing")), ChangedFilterRule::NotFound);
    let other = version(store, b).await;
    for (account, rule) in [(a, "no-such-rule"), (b, &ids[0]), (&missing, &ids[0])] {
        let edit = store.update_webhook_filter_rule(account, rule, &new, 9, |_| Ok(()));
        assert_eq!(edit.await.unwrap(), gone);
    }
    assert_eq!(
        rules_of(store, a, 9).await,
        ["one+", "x@example.com-0", "three+"]
    );
    assert_eq!(
        (version(store, a).await, version(store, b).await),
        (Some(c + 1), other)
    );
}

/// A build from before this change deletes a webhook and leaves its rules.
async fn exercise_rules_left_by_an_older_build(store: &Store) {
    let c = &mailbox(store, "left").await;
    let hook = settings("https://a.example/h");
    store.save_webhook(c, &hook).await.unwrap();
    let old = added(store, c, "old", 9).await;
    let delete = sqlx::query("DELETE FROM webhooks WHERE account_id = $1").bind(&c.0);
    delete.execute(store.pool()).await.unwrap();
    assert_eq!(rules_of(store, c, 9).await, ["old+"]);
    // With no webhook there is no count to change, so such a rule isn't turned on.
    assert_eq!(
        turn(store, c, &old, true).await,
        ChangedFilterRule::NotFound
    );
    // Saving a webhook where none is stored deletes them.
    store.save_webhook(c, &hook).await.unwrap();
    assert_eq!(rules_of(store, c, 9).await, Vec::<String>::new());
    // The one case left is an older build that deletes the webhook and makes it
    // again: the rules stay, the count starts from 0, and the next place still
    // does not collide with theirs.
    added(store, c, "kept", 9).await;
    let reset = "UPDATE webhooks SET filter_rules_version = 0 WHERE account_id = $1";
    let reset = sqlx::query(reset).bind(&c.0);
    reset.execute(store.pool()).await.unwrap();
    added(store, c, "next", 9).await;
    assert_eq!(rules_of(store, c, 9).await, ["kept+", "next+"]);
}

async fn exercise_filter_rules(store: &Store) {
    let a = &mailbox(store, "rules").await;
    let b = &mailbox(store, "other").await;
    // Without a webhook there is nothing to add to, and no count.
    let (unknown, no) = (AccountId(unique("missing")), || AddedFilterRule::NoWebhook);
    assert_eq!(add_rule(store, a, "x", 9).await, no());
    assert_eq!(add_rule(store, &unknown, "x", 9).await, no());
    assert_eq!(version(store, a).await, None);
    let hook = settings("https://a.example/h");
    for id in [a, b] {
        store.save_webhook(id, &hook).await.unwrap();
    }
    assert_eq!(version(store, a).await, Some(0));

    // Every add counts, until the mailbox has as many rules as the limit allows.
    let mut ids = Vec::new();
    for pattern in ["one", "two", "three"] {
        ids.push(added(store, a, pattern, 3).await);
    }
    assert_eq!(
        add_rule(store, a, "four", 3).await,
        AddedFilterRule::AtLimit
    );
    assert_eq!(version(store, a).await, Some(3));
    // A webhook saved again keeps its rules.
    store.save_webhook(a, &hook).await.unwrap();
    // The oldest rules are active up to the limit of the moment, and the others
    // count again when it rises.
    assert_eq!(rules_of(store, a, 2).await, ["one+", "two+", "three-"]);
    assert_eq!(rules_of(store, a, 0).await, ["one-", "two-", "three-"]);
    assert_eq!(rules_of(store, a, 9).await, ["one+", "two+", "three+"]);

    // A rule is removed from its own mailbox only, and a removal counts once.
    assert!(!rm(store, b, &ids[0]).await);
    assert!(rm(store, a, &ids[0]).await);
    assert!(!rm(store, a, &ids[0]).await);
    assert_eq!(version(store, a).await, Some(4));
    added(store, a, "four", 3).await;
    assert_eq!(rules_of(store, a, 9).await, ["two+", "three+", "four+"]);
    added(store, b, "mine", 3).await;
    assert_eq!(store.remove_webhook_filter_rules(a).await.unwrap(), 3);
    assert_eq!(store.remove_webhook_filter_rules(a).await.unwrap(), 0);
    assert_eq!(version(store, a).await, Some(6));
    assert_eq!(rules_of(store, b, 9).await, ["mine+"]);

    // Age is when a rule was added, and the order of adding breaks a tie.
    let mut ids = Vec::new();
    for pattern in ["a", "b", "c"] {
        ids.push(added(store, a, pattern, 9).await);
    }
    set_rules(store, "added_at = 1", "account_id", &a.0).await;
    set_rules(store, "seq = seq + 1000", "id", &ids[0]).await;
    assert_eq!(rules_of(store, a, 2).await, ["b+", "c+", "a-"]);
    set_rules(store, "added_at = 0", "id", &ids[0]).await;
    assert_eq!(rules_of(store, a, 2).await, ["a+", "b+", "c-"]);
    let copy = "INSERT INTO webhook_filter_rules \
                (id, account_id, seq, added_at, action, field, kind, pattern_ciphertext) \
                SELECT 'twice', account_id, seq, added_at, action, field, kind, \
                pattern_ciphertext FROM webhook_filter_rules WHERE id = $1";
    let twice = sqlx::query(copy).bind(&ids[1]).execute(store.pool()).await;
    assert!(twice.is_err(), "a mailbox's rules have distinct positions");

    exercise_a_check_runs_again(store, a).await;
    exercise_adds_at_the_same_moment(store, a).await;
    exercise_rules_turned_off_and_on(store, a, b).await;
    exercise_a_rule_changed_in_its_place(store, a, b).await;
    exercise_rules_left_by_an_older_build(store).await;

    // The rules go with the webhook, and with the account row, whoever deletes it.
    store.delete_webhook(a).await.unwrap();
    assert_eq!(
        (rules_of(store, a, 9).await.len(), version(store, a).await),
        (0, None)
    );
    assert!(store.delete_account(a).await.unwrap());
    let delete = sqlx::query("DELETE FROM accounts WHERE id = $1").bind(&b.0);
    delete.execute(store.pool()).await.unwrap();
    let rows = "SELECT COUNT(*) FROM webhook_filter_rules WHERE account_id = $1";
    let left: i64 = sqlx::query_scalar(rows)
        .bind(&b.0)
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sqlite_filter_rules() {
    let (store, _dir) = sqlite().await;
    exercise_filter_rules(&store).await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_filter_rules() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    exercise_filter_rules(&Store::connect(&url, &key()).await.unwrap()).await;
}

/// PostgreSQL aborts one of two writers that take an account's webhook row and
/// another of its rows in opposite orders (40P01). While a session holds the
/// webhook row, each writer waits for it before it has locked a rule, an event, a
/// delivery or the account's row, which an insert that points at the account
/// locks.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_writers_take_the_webhooks_row_first() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let hook = settings("https://a.example/h");
    let hold = "SELECT 1 FROM webhooks WHERE account_id = $1 FOR UPDATE";
    let rows = [
        "SELECT id FROM webhook_filter_rules WHERE account_id = $1 FOR UPDATE NOWAIT",
        "SELECT id FROM mail_events WHERE account_id = $1 FOR UPDATE NOWAIT",
        "SELECT id FROM webhook_deliveries WHERE account_id = $1 FOR UPDATE NOWAIT",
        "SELECT id FROM accounts WHERE id = $1 FOR UPDATE NOWAIT",
    ];
    // Older than the one that writer 5 logs, so that its trim deletes one of these.
    let old = DeliveryRecord {
        created_at: postkeep_store::now() - 60,
        ..record(true, false)
    };
    for which in 0..9 {
        let a = mailbox(&store, "locks").await;
        store.save_webhook(&a, &hook).await.unwrap();
        let new = rule("y");
        let rule = added(&store, &a, "x", 9).await;
        store
            .append_mail_event(&a, r#"{"n":1}"#, None)
            .await
            .unwrap();
        for _ in 0..KEPT_DELIVERIES {
            store.record_delivery(&a, &old).await.unwrap();
        }
        let (mut gate, pid) = lock_gate(&store, hold, &a).await;
        let (writer, id) = (store.clone(), a.clone());
        let task = tokio::spawn(async move {
            let on = |on| writer.set_webhook_filter_rule_enabled(&id, &rule, on, 9, |_| Ok(()));
            match which {
                0 => writer.remove_webhook_filter_rules(&id).await.map(drop),
                1 => writer.delete_webhook(&id).await,
                2 => writer.delete_account(&id).await.map(drop),
                3 => on(false).await.map(drop),
                4 => on(true).await.map(drop),
                5 => writer
                    .record_delivery(&id, &record(false, false))
                    .await
                    .map(drop),
                6 => writer
                    .append_mail_event(&id, r#"{"n":2}"#, None)
                    .await
                    .map(drop),
                7 => writer
                    .set_webhook_outbox_limits(
                        &id,
                        OutboxLimitChange::Keep,
                        OutboxLimitChange::Set(2),
                    )
                    .await
                    .map(drop),
                _ => writer
                    .add_webhook_filter_rule(&id, &new, 9, |_| Ok(()))
                    .await
                    .map(drop),
            }
            .unwrap();
        });
        assert!(
            waits_for(&store, pid).await,
            "writer {which} never waited for the webhook row"
        );
        for rows in rows {
            let locked = sqlx::query(rows)
                .bind(&a.0)
                .fetch_all(&mut *gate)
                .await
                .err();
            assert!(
                locked.is_none(),
                "writer {which} took a row before the webhook's ({rows}): {locked:?}"
            );
        }
        gate.commit().await.unwrap();
        task.await.unwrap();
    }
}

/// Opens a transaction that holds the rows that `hold` locks for `account`.
/// Returns it with its backend's pid.
#[cfg(feature = "postgres")]
async fn lock_gate(
    store: &Store,
    hold: &'static str,
    account: &AccountId,
) -> (sqlx::Transaction<'static, sqlx::Any>, i32) {
    #[expect(
        clippy::disallowed_methods,
        reason = "a PostgreSQL row lock, not a store write"
    )]
    let mut gate = store.pool().begin().await.unwrap();
    sqlx::query(hold)
        .bind(&account.0)
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let pid = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    (gate, pid)
}

/// Whether a connection waits for the gate with `pid` within five seconds.
/// The polls run on a connection of their own: `pg_stat_activity` keeps its
/// first read for the rest of a transaction.
#[cfg(feature = "postgres")]
async fn waits_for(store: &Store, pid: i32) -> bool {
    let blocked = "SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))";
    for _ in 0..250 {
        let waiting: Option<i32> = sqlx::query_scalar(blocked)
            .bind(pid)
            .fetch_optional(store.pool())
            .await
            .unwrap();
        if waiting.is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// PostgreSQL aborts one of two writers that take an account's row and its
/// sessions or tokens in opposite orders (40P01). A reconnect updates the
/// account's row before it ends the sessions (IMAP) or saves the tokens
/// (OAuth). While a transaction holds that row as an update does, each
/// reconnect and the account's deletion wait for it before they have locked a
/// session or the tokens.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_writers_take_the_accounts_row_before_its_sessions() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let ttl = SessionTtl {
        idle: Duration::from_hours(1),
        absolute: Duration::from_hours(12),
    };
    let tokens = UpstreamTokens {
        refresh_token: secret("refresh"),
        access_token: None,
        access_expires_at: None,
        scope: "Mail.Read".to_owned(),
    };
    // The lock that an update of the row takes, as a reconnect's does.
    let hold = "SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE";
    let rows = [
        "SELECT id_hash FROM account_sessions WHERE account_id = $1 FOR UPDATE NOWAIT",
        "SELECT account_id FROM upstream_tokens WHERE account_id = $1 FOR UPDATE NOWAIT",
    ];
    for which in 0..3 {
        // Writer 1 reconnects an IMAP account, the others an Outlook one.
        let email = format!("{}@example.com", unique("reconnect"));
        let subject = unique("subject");
        let outlook = OAuthAccount {
            provider: Provider::Graph,
            subject: &subject,
            email: &email,
        };
        let a = if which == 1 {
            let password = secret("pw-1");
            let imap = store.upsert_imap_account_ending_sessions(&email, &password, None);
            imap.await.unwrap().account.id
        } else {
            store
                .upsert_oauth_account(&outlook, &tokens)
                .await
                .unwrap()
                .id
        };
        store
            .create_session(&unique("session"), &a, ttl)
            .await
            .unwrap();
        let (mut gate, pid) = lock_gate(&store, hold, &a).await;
        let (writer, id, tokens) = (store.clone(), a.clone(), tokens.clone());
        let task = tokio::spawn(async move {
            let outlook = OAuthAccount {
                provider: Provider::Graph,
                subject: &subject,
                email: &email,
            };
            match which {
                0 => writer.delete_account(&id).await.map(drop),
                1 => writer
                    .upsert_imap_account_ending_sessions(&email, &secret("pw-2"), None)
                    .await
                    .map(drop),
                _ => writer
                    .upsert_oauth_account(&outlook, &tokens)
                    .await
                    .map(drop),
            }
            .unwrap();
        });
        assert!(
            waits_for(&store, pid).await,
            "writer {which} never waited for the account's row"
        );
        for rows in rows {
            let locked = sqlx::query(rows)
                .bind(&a.0)
                .fetch_all(&mut *gate)
                .await
                .err();
            assert!(
                locked.is_none(),
                "writer {which} took a row before the account's ({rows}): {locked:?}"
            );
        }
        gate.commit().await.unwrap();
        task.await.unwrap();
    }
}

/// While the account's deletion holds the account's row, an insert that points
/// at the account still gets through, as `save_webhook` needs when it inserts
/// the webhook while it holds filter rules that the deletion waits for. Here
/// the deletion waits for the account's session, and the gate that holds it
/// takes the lock that an insert's foreign key takes.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_deleting_an_account_does_not_hold_up_foreign_keys() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let ttl = SessionTtl {
        idle: Duration::from_hours(1),
        absolute: Duration::from_hours(12),
    };
    let a = mailbox(&store, "deleting").await;
    store
        .create_session(&unique("session"), &a, ttl)
        .await
        .unwrap();
    let hold = "SELECT 1 FROM account_sessions WHERE account_id = $1 FOR UPDATE";
    let (mut gate, pid) = lock_gate(&store, hold, &a).await;
    let (writer, id) = (store.clone(), a.clone());
    let task = tokio::spawn(async move { writer.delete_account(&id).await.unwrap() });
    assert!(
        waits_for(&store, pid).await,
        "the deletion never waited for the session"
    );
    let shared = sqlx::query("SELECT 1 FROM accounts WHERE id = $1 FOR KEY SHARE NOWAIT")
        .bind(&a.0)
        .fetch_one(&mut *gate)
        .await
        .err();
    assert!(
        shared.is_none(),
        "the deletion keeps inserts off the account's row: {shared:?}"
    );
    gate.commit().await.unwrap();
    assert!(task.await.unwrap(), "the deletion deleted nothing");
    assert!(store.account(&a).await.unwrap().is_none());
}

/// PostgreSQL aborts one of two writers that take a subject's authorization
/// codes, tokens and grants in opposite orders (40P01). A replayed code
/// learns its grant from the code's row, so every writer takes the codes
/// first: while a transaction holds a code, each writer waits for it before
/// it has locked a token or a grant. The account's deletion holds the codes
/// and deletes the account's row last, so no other writer may hold that
/// row, as a grant's foreign key does, while it waits for a code.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_writers_take_codes_before_tokens_and_grants() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let client_id = client(&store).await;
    // A code or a grant is for an account or for a principal.
    let hold = "SELECT 1 FROM authorization_codes WHERE $1 IN (account_id, principal) FOR UPDATE";
    let rows = [
        "SELECT 1 FROM access_tokens WHERE grant_id IN \
         (SELECT id FROM grants WHERE $1 IN (account_id, principal)) FOR UPDATE NOWAIT",
        "SELECT 1 FROM refresh_tokens WHERE grant_id IN \
         (SELECT id FROM grants WHERE $1 IN (account_id, principal)) FOR UPDATE NOWAIT",
        "SELECT 1 FROM grants WHERE $1 IN (account_id, principal) FOR UPDATE NOWAIT",
    ];
    // The lock that the account's deletion takes on its row at the end.
    let account_row = "SELECT 1 FROM accounts WHERE id = $1 FOR UPDATE NOWAIT";
    for which in 0..6 {
        let a = mailbox(&store, "codes").await;
        let principal = unique("principal");
        // Writer 3 revokes a principal's grants, the others an account's.
        let (subject, owner) = if which == 3 {
            (
                GrantSubject::Principal(principal.clone()),
                AccountId(principal.clone()),
            )
        } else {
            (GrantSubject::Account(a.clone()), a.clone())
        };
        let code = unique("code");
        let grant = CodeGrant {
            client_id: client_id.clone(),
            subject,
            redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
            code_challenge: "challenge".to_owned(),
            scope: "mail".to_owned(),
            resource: None,
        };
        store.save_code(&code, &grant, MINUTE).await.unwrap();
        assert!(store.take_code(&code).await.unwrap().valid().is_some());
        let (access, refresh) = (unique("access"), unique("refresh"));
        // Writer 5 creates the code's grant; the others find it made.
        if which != 5 {
            store
                .create_grant_for_code(&code, &grant, &access, MINUTE, &refresh, MINUTE)
                .await
                .unwrap()
                .unwrap();
        }
        let (mut gate, pid) = lock_gate(&store, hold, &owner).await;
        let (writer, id, client) = (store.clone(), a.clone(), client_id.clone());
        let task = tokio::spawn(async move {
            match which {
                0 => writer.delete_account(&id).await.map(drop),
                1 => writer.revoke_account_grants(&id).await.map(drop),
                2 => writer.revoke_client_grants(&id, &client).await.map(drop),
                3 => writer.revoke_principal_grants(&principal).await.map(drop),
                // The code's second use, which revokes its grant.
                4 => writer.take_code(&code).await.map(drop),
                _ => writer
                    .create_grant_for_code(&code, &grant, &access, MINUTE, &refresh, MINUTE)
                    .await
                    .map(|made| assert!(made.is_some(), "the code's grant was not made")),
            }
            .unwrap();
        });
        assert!(
            waits_for(&store, pid).await,
            "writer {which} never waited for the code"
        );
        for rows in rows {
            let locked = sqlx::query(rows)
                .bind(&owner.0)
                .fetch_all(&mut *gate)
                .await
                .err();
            assert!(
                locked.is_none(),
                "writer {which} took a row before the code ({rows}): {locked:?}"
            );
        }
        // The deletion itself holds the account's row from its start.
        if which != 0 {
            let account_lock = sqlx::query(account_row)
                .bind(&owner.0)
                .fetch_all(&mut *gate)
                .await
                .err();
            assert!(
                account_lock.is_none(),
                "writer {which} holds the account's row while it waits: {account_lock:?}"
            );
        }
        gate.commit().await.unwrap();
        task.await.unwrap();
    }
}

/// An Outlook or Gmail reconnect that waits behind its account's deletion
/// finds no account once the deletion commits. It saves nothing and says
/// so, and signing in again adds the account anew.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_a_reconnect_behind_its_accounts_deletion_saves_nothing() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let tokens = UpstreamTokens {
        refresh_token: secret("refresh"),
        access_token: None,
        access_expires_at: None,
        scope: "Mail.Read".to_owned(),
    };
    let email = format!("{}@example.com", unique("deleted"));
    let subject = unique("subject");
    let outlook = OAuthAccount {
        provider: Provider::Graph,
        subject: &subject,
        email: &email,
    };
    let a = store
        .upsert_oauth_account(&outlook, &tokens)
        .await
        .unwrap()
        .id;
    // The lock that `delete_account` takes on the row before it deletes it.
    let hold = "SELECT 1 FROM accounts WHERE id = $1 FOR NO KEY UPDATE";
    let (mut gate, pid) = lock_gate(&store, hold, &a).await;
    let task = {
        let (writer, email, subject, tokens) = (
            store.clone(),
            email.clone(),
            subject.clone(),
            tokens.clone(),
        );
        tokio::spawn(async move {
            let outlook = OAuthAccount {
                provider: Provider::Graph,
                subject: &subject,
                email: &email,
            };
            writer.upsert_oauth_account(&outlook, &tokens).await
        })
    };
    assert!(
        waits_for(&store, pid).await,
        "the reconnect never waited for the deletion"
    );
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(&a.0)
        .execute(&mut *gate)
        .await
        .unwrap();
    gate.commit().await.unwrap();
    let err = task.await.unwrap().unwrap_err();
    assert!(matches!(err, StoreError::AccountDeleted), "{err:?}");
    assert!(store.account(&a).await.unwrap().is_none());
    let again = store.upsert_oauth_account(&outlook, &tokens).await.unwrap();
    assert_ne!(again.id, a);
}

/// A token save that waits behind its account's deletion finds no account
/// once the deletion commits, and saves nothing, where its insert would fail
/// on its foreign key.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_a_token_save_behind_its_accounts_deletion_saves_nothing() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let tokens = UpstreamTokens {
        refresh_token: secret("refresh"),
        access_token: None,
        access_expires_at: None,
        scope: "Mail.Read".to_owned(),
    };
    let (email, subject) = (
        format!("{}@example.com", unique("saved")),
        unique("subject"),
    );
    let outlook = OAuthAccount {
        provider: Provider::Graph,
        subject: &subject,
        email: &email,
    };
    let a = store
        .upsert_oauth_account(&outlook, &tokens)
        .await
        .unwrap()
        .id;
    // The deletion's update of the row, which holds it until the deletion
    // commits, and then its last statement, which deletes the tokens with it.
    let hold = "UPDATE accounts SET updated_at = updated_at WHERE id = $1 RETURNING id";
    let (mut gate, pid) = lock_gate(&store, hold, &a).await;
    let (writer, id) = (store.clone(), a.clone());
    let task = tokio::spawn(async move { writer.save_upstream_tokens(&id, &tokens).await });
    assert!(
        waits_for(&store, pid).await,
        "the save never waited for the deletion"
    );
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(&a.0)
        .execute(&mut *gate)
        .await
        .unwrap();
    gate.commit().await.unwrap();
    let saved = task.await.unwrap();
    assert!(
        matches!(saved, Err(StoreError::InvalidInput("unknown account"))),
        "{saved:?}"
    );
    assert!(store.upstream_tokens(&a).await.unwrap().is_none());
}

/// A subscription save that waits behind its account's deletion, as a renewal
/// that the provider answers late does, is `AccountDeleted` once the deletion
/// commits, where it failed on its foreign key.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_a_subscription_save_behind_its_accounts_deletion_saves_nothing() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let a = mailbox(&store, "renewed").await;
    let subscription = PushSubscription {
        provider: Provider::Graph,
        subscription_id: Some(unique("subscription")),
        client_state_hash: None,
        expires_at: 1_900_000_000,
    };
    store
        .save_push_subscription(&a, &subscription)
        .await
        .unwrap();
    // The deletion's removal of the subscription, which holds its row until
    // the deletion commits, and then its last statement.
    let hold = "DELETE FROM push_subscriptions WHERE account_id = $1 RETURNING account_id";
    let (mut gate, pid) = lock_gate(&store, hold, &a).await;
    let renewed = PushSubscription {
        expires_at: 1_900_000_600,
        ..subscription
    };
    let (writer, id) = (store.clone(), a.clone());
    let task = tokio::spawn(async move { writer.save_push_subscription(&id, &renewed).await });
    assert!(
        waits_for(&store, pid).await,
        "the save never waited for the deletion"
    );
    sqlx::query("DELETE FROM accounts WHERE id = $1")
        .bind(&a.0)
        .execute(&mut *gate)
        .await
        .unwrap();
    gate.commit().await.unwrap();
    let saved = task.await.unwrap();
    assert!(
        matches!(saved, Err(StoreError::AccountDeleted)),
        "{saved:?}"
    );
    assert!(store.push_subscription(&a).await.unwrap().is_none());
}

/// An account's deletion returns the refresh token that it removes, read as it
/// removes it: here one that a reconnect stored while the deletion waited for
/// the webhook's row.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_a_deletion_returns_the_refresh_token_it_removes() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    let tokens = |refresh: &str| UpstreamTokens {
        refresh_token: secret(refresh),
        access_token: None,
        access_expires_at: None,
        scope: "Mail.Read".to_owned(),
    };
    let (email, subject) = (
        format!("{}@example.com", unique("removed")),
        unique("subject"),
    );
    let outlook = OAuthAccount {
        provider: Provider::Graph,
        subject: &subject,
        email: &email,
    };
    let a = store
        .upsert_oauth_account(&outlook, &tokens("old"))
        .await
        .unwrap()
        .id;
    let hook = settings("https://a.example/h");
    store.save_webhook(&a, &hook).await.unwrap();
    // The deletion's first lock.
    let hold = "SELECT account_id FROM webhooks WHERE account_id = $1 FOR UPDATE";
    let (gate, pid) = lock_gate(&store, hold, &a).await;
    let (deleter, id) = (store.clone(), a.clone());
    let task =
        tokio::spawn(async move { deleter.delete_account_returning_refresh_token(&id).await });
    assert!(
        waits_for(&store, pid).await,
        "the deletion never waited for the webhook"
    );
    // A reconnect while the deletion waits.
    store
        .upsert_oauth_account(&outlook, &tokens("new"))
        .await
        .unwrap();
    gate.commit().await.unwrap();
    let removed = task
        .await
        .unwrap()
        .unwrap()
        .expect("no refresh token was removed");
    let refresh = store.open_removed_refresh_token(&removed).await.unwrap();
    assert_eq!(refresh.expose_secret(), "new");
    assert!(store.account(&a).await.unwrap().is_none());
}

fn ready_webhook(loaded: LoadedWebhook) -> postkeep_store::Webhook {
    match loaded {
        LoadedWebhook::Ready(hook) => hook,
        other => panic!("expected a readable webhook, got {other:?}"),
    }
}

#[tokio::test]
async fn sqlite_webhooks() {
    let (store, _dir) = sqlite().await;
    exercise_webhooks(&store).await;
}

/// `shown` has neither stored value in it, nor the start of a value in either
/// stored format (`v1.` and `v2.`).
fn assert_no_ciphertext(shown: &str, stored: &[String]) {
    for value in stored {
        // What follows the last dot: `v1.<blob>` or `v2.<version>.<blob>`.
        let blob = value.rsplit('.').next().unwrap();
        assert!(blob.len() > 16, "{value}");
        assert!(!shown.contains(blob), "{shown}");
    }
    assert!(!shown.contains("v1.") && !shown.contains("v2."), "{shown}");
}

/// A row sealed under another key can be turned off, not on, and the
/// response never includes its secrets or ciphertext.
#[tokio::test]
async fn sqlite_unreadable_webhook_can_be_disabled_but_not_enabled() {
    let (store, dir) = sqlite().await;
    let email = format!("{}@example.com", unique("unreadable"));
    let account = store.upsert_account(&email, &secret("pw")).await.unwrap();
    let secret_text = "whsec_UNREADABLE-SECRET";
    let url = "https://hooks.example/UNREADABLE-PATH";
    store
        .save_webhook(
            &account.id,
            &WebhookSettings {
                enabled: true,
                url: url.to_owned(),
                auth_header: Some(("authorization".to_owned(), secret("Bearer UNREADABLE-AUTH"))),
                signing: true,
                signing_secret: secret(secret_text),
                include_sender: false,
            },
        )
        .await
        .unwrap();
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        store
            .record_delivery(&account.id, &record(false, false))
            .await
            .unwrap();
    }
    assert!(
        store
            .webhook(&account.id)
            .await
            .unwrap()
            .unwrap()
            .is_paused()
    );
    let account_id = account.id.clone();
    // The secrets as stored, in whatever format the writers use.
    let sealed = [
        SECRET.get(&store, &account_id.0).await,
        AUTH.get(&store, &account_id.0).await,
    ];
    store.close().await;

    let db = format!("sqlite://{}", dir.path().join("test.db").display());
    let store = Store::connect(&db, &random_key()).await.unwrap();
    let err = store.webhook(&account_id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
    assert!(!format!("{err}").contains(secret_text));
    assert_no_ciphertext(&format!("{err}"), &sealed);

    let loaded = store.load_webhook(&account_id).await.unwrap();
    let rendered = format!("{loaded:?}");
    assert!(!rendered.contains(secret_text), "{rendered}");
    assert!(!rendered.contains("UNREADABLE-PATH"), "{rendered}");
    assert!(!rendered.contains("UNREADABLE-AUTH"), "{rendered}");
    assert_no_ciphertext(&rendered, &sealed);
    assert!(matches!(
        loaded,
        LoadedWebhook::Unreadable { enabled: true }
    ));
    assert!(
        store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account_id),
        "refusing to enable must not clear the stored flag first"
    );

    let refused = store.set_webhook_enabled(&account_id, true).await.unwrap();
    assert!(matches!(
        refused,
        LoadedWebhook::Unreadable { enabled: true }
    ));
    assert!(!format!("{refused:?}").contains(secret_text));
    assert!(
        store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account_id)
    );

    let disabled = store.set_webhook_enabled(&account_id, false).await.unwrap();
    assert!(matches!(
        disabled,
        LoadedWebhook::Unreadable { enabled: false }
    ));
    assert!(
        !store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&account_id)
    );
    store.close().await;

    let store = Store::connect(&db, &key()).await.unwrap();
    let hook = store.webhook(&account_id).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);
    assert!(hook.paused_at.is_none());
    assert_eq!(hook.settings.url, url);
    assert_eq!(hook.settings.signing_secret.expose_secret(), secret_text);
    let (_, auth_value) = hook.settings.auth_header.unwrap();
    assert_eq!(auth_value.expose_secret(), "Bearer UNREADABLE-AUTH");
    store.close().await;
}

/// Per-app listing and revocation on the account page.
async fn exercise_account_clients(store: &Store) {
    let account = store
        .upsert_account(&format!("{}@icloud.com", unique("apps")), &secret("pw"))
        .await
        .unwrap();
    let other = store
        .upsert_account(&format!("{}@icloud.com", unique("apps")), &secret("pw"))
        .await
        .unwrap();
    assert_eq!(store.account_clients(&account.id).await.unwrap().len(), 0);
    let (first, second) = (client(store).await, client(store).await);
    let grant = |client_id: &str, account_id: &postkeep_store::AccountId| CodeGrant {
        client_id: client_id.to_owned(),
        subject: GrantSubject::Account(account_id.clone()),
        redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
        code_challenge: "challenge".to_owned(),
        scope: "mail".to_owned(),
        resource: None,
    };
    let first_grant = store
        .create_grant(&grant(&first, &account.id))
        .await
        .unwrap();
    let (access, refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&first_grant, &access, MINUTE, &refresh, MINUTE)
        .await
        .unwrap();
    store
        .create_grant(&grant(&second, &account.id))
        .await
        .unwrap();
    let shared = store.create_grant(&grant(&first, &other.id)).await.unwrap();
    let (other_access, other_refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&shared, &other_access, MINUTE, &other_refresh, MINUTE)
        .await
        .unwrap();
    // Another account refreshing the shared client doesn't count as use.
    assert!(
        store
            .take_refresh_token(&other_refresh, &first)
            .await
            .unwrap()
            .valid()
            .is_some()
    );

    let mut listed = store.account_clients(&account.id).await.unwrap();
    listed.sort_by(|a, b| a.id.cmp(&b.id));
    let mut expected = vec![first.clone(), second.clone()];
    expected.sort();
    assert_eq!(
        listed.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
        expected
    );
    for app in &listed {
        assert_eq!(app.name.as_deref(), Some("Test client"));
        assert_eq!(app.redirect_uris, ["http://127.0.0.1:9999/callback"]);
        assert!(app.authorized_at > 0);
        assert_eq!(app.last_active_at, app.authorized_at);
    }

    assert_eq!(
        store
            .revoke_client_grants(&account.id, &first)
            .await
            .unwrap(),
        1
    );
    assert!(store.access_token(&access).await.unwrap().is_none());
    let left = store.account_clients(&account.id).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].id, second);
    // The other account's grant to the same app survives.
    assert_eq!(store.account_clients(&other.id).await.unwrap().len(), 1);
    assert_eq!(
        store
            .revoke_client_grants(&account.id, &first)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        store
            .revoke_client_grants(&account.id, "unknown")
            .await
            .unwrap(),
        0
    );
    let overview = store.account_overview(&account.id).await.unwrap().unwrap();
    assert_eq!(overview.apps, 1);
}

#[tokio::test]
async fn sqlite_account_clients() {
    let (store, _dir) = sqlite().await;
    exercise_account_clients(&store).await;
}

#[tokio::test]
async fn sqlite_sessions() {
    let (store, _dir) = sqlite().await;
    exercise_sessions(&store).await;
    exercise_account_clients(&store).await;
    exercise_webhooks(&store).await;
}

#[tokio::test]
async fn sqlite_writes_for_a_deleted_account() {
    let (store, _dir) = sqlite().await;
    exercise_writes_for_a_deleted_account(&store).await;
}

/// A session or a code for an account that is gone, as when its deletion
/// commits just after a sign-in stored it, is `AccountDeleted`. Another
/// failure, for an account that is there, is not.
async fn exercise_writes_for_a_deleted_account(store: &Store) {
    let ttl = SessionTtl {
        idle: Duration::from_hours(1),
        absolute: Duration::from_hours(12),
    };
    let a = mailbox(store, "deleted").await;
    let token = unique("token");
    store.create_session(&token, &a, ttl).await.unwrap();
    let again = store.create_session(&token, &a, ttl).await;
    assert!(matches!(again, Err(StoreError::Database(_))), "{again:?}");
    let grant = CodeGrant {
        client_id: client(store).await,
        subject: GrantSubject::Account(a.clone()),
        redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
        code_challenge: "challenge".to_owned(),
        scope: "mail".to_owned(),
        resource: None,
    };
    assert!(store.delete_account(&a).await.unwrap());
    let session = store.create_session(&unique("token"), &a, ttl).await;
    assert!(
        matches!(session, Err(StoreError::AccountDeleted)),
        "{session:?}"
    );
    let code = store.save_code(&unique("code"), &grant, MINUTE).await;
    assert!(matches!(code, Err(StoreError::AccountDeleted)), "{code:?}");
}

#[tokio::test]
async fn sqlite_accounts() {
    let (store, _dir) = sqlite().await;
    exercise_accounts(&store).await;
    exercise_password_rejection(&store).await;
}

#[tokio::test]
async fn sqlite_clients() {
    let (store, _dir) = sqlite().await;
    exercise_clients(&store).await;
}

#[tokio::test]
async fn sqlite_oauth_flow() {
    let (store, _dir) = sqlite().await;
    exercise_oauth_flow(&store).await;
}

/// The grant created from an authorization code is stored with its first
/// access and refresh tokens in one call, so a purge cannot delete the
/// grant for having no tokens. A code replayed before that call creates
/// nothing.
async fn exercise_code_redemption_is_atomic(store: &Store) {
    let client_id = client(store).await;
    let account = store
        .upsert_account(&format!("{}@example.com", unique("redeem")), &secret("pw"))
        .await
        .unwrap();
    let grant = CodeGrant {
        client_id: client_id.clone(),
        subject: GrantSubject::Account(account.id.clone()),
        redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
        code_challenge: "challenge".to_owned(),
        scope: "mail".to_owned(),
        resource: None,
    };

    let code = unique("code");
    store.save_code(&code, &grant, MINUTE).await.unwrap();
    assert!(store.take_code(&code).await.unwrap().valid().is_some());
    let (access, refresh) = (unique("access"), unique("refresh"));
    let grant_id = store
        .create_grant_for_code(&code, &grant, &access, MINUTE, &refresh, MINUTE)
        .await
        .unwrap()
        .unwrap();
    // Both tokens are already stored, so a purge must leave the grant.
    store.purge_expired(PurgePolicy::default()).await.unwrap();
    let resolved = store.access_token(&access).await.unwrap().unwrap();
    assert_eq!(resolved.grant_id, grant_id);
    assert_eq!(resolved.subject, GrantSubject::Account(account.id.clone()));
    let rotated = store
        .take_refresh_token(&refresh, &client_id)
        .await
        .unwrap()
        .valid()
        .unwrap();
    assert_eq!(rotated.grant_id, grant_id);
    assert_eq!(
        store
            .account_overview(&account.id)
            .await
            .unwrap()
            .unwrap()
            .apps,
        1
    );

    let replay_account = store
        .upsert_account(&format!("{}@example.com", unique("replay")), &secret("pw"))
        .await
        .unwrap();
    let replay_grant = CodeGrant {
        subject: GrantSubject::Account(replay_account.id.clone()),
        ..grant
    };
    let replayed = unique("replayed");
    store
        .save_code(&replayed, &replay_grant, MINUTE)
        .await
        .unwrap();
    assert!(store.take_code(&replayed).await.unwrap().valid().is_some());
    assert_eq!(
        store.take_code(&replayed).await.unwrap(),
        Redemption::Replayed
    );
    let (lost_access, lost_refresh) = (unique("access"), unique("refresh"));
    assert_eq!(
        store
            .create_grant_for_code(
                &replayed,
                &replay_grant,
                &lost_access,
                MINUTE,
                &lost_refresh,
                MINUTE,
            )
            .await
            .unwrap(),
        None
    );
    assert!(store.access_token(&lost_access).await.unwrap().is_none());
    assert_eq!(
        store
            .take_refresh_token(&lost_refresh, &client_id)
            .await
            .unwrap(),
        Redemption::Invalid
    );
    assert_eq!(
        store
            .account_overview(&replay_account.id)
            .await
            .unwrap()
            .unwrap()
            .apps,
        0,
        "a replayed code must not create a grant"
    );
}

#[tokio::test]
async fn sqlite_code_redemption_is_atomic() {
    let (store, _dir) = sqlite().await;
    exercise_code_redemption_is_atomic(&store).await;
}

async fn pair_for(
    store: &Store,
    client_id: &str,
    account_id: &AccountId,
    ttl: Duration,
) -> (String, String, String) {
    let grant_id = store
        .create_grant(&CodeGrant {
            client_id: client_id.to_owned(),
            subject: GrantSubject::Account(account_id.clone()),
            redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
            code_challenge: "challenge".to_owned(),
            scope: "mail".to_owned(),
            resource: None,
        })
        .await
        .unwrap();
    let (access, refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&grant_id, &access, ttl, &refresh, ttl)
        .await
        .unwrap();
    (grant_id, access, refresh)
}

/// A successful rotation marks the old refresh token used and stores the new
/// pair in one commit. A failed insert rolls that back, so the old token
/// still rotates. A disallowed account consumes the old token and stores
/// nothing.
async fn exercise_refresh_rotation_is_atomic(store: &Store) {
    let client_id = client(store).await;
    let account = store
        .upsert_account(&format!("{}@example.com", unique("rotate")), &secret("pw"))
        .await
        .unwrap();
    let allow = |_: &str| true;

    let (grant_id, access, refresh) = pair_for(store, &client_id, &account.id, MINUTE).await;
    let (access2, refresh2) = (unique("access"), unique("refresh"));
    let rotated = store
        .rotate_refresh_token(
            &refresh,
            &client_id,
            &access2,
            MINUTE,
            &refresh2,
            MINUTE,
            Duration::ZERO,
            allow,
        )
        .await
        .unwrap();
    let RefreshRotation::Rotated(grant) = rotated else {
        panic!("expected a rotation, got {rotated:?}");
    };
    assert_eq!(grant.grant_id, grant_id);
    assert_eq!(grant.email.as_deref(), Some(account.email.as_str()));
    let resolved = store.access_token(&access2).await.unwrap().unwrap();
    assert_eq!(resolved.grant_id, grant_id);
    // The previous access token stays valid until it expires or the grant
    // is revoked. Rotation only marks the presented refresh token used.
    assert!(store.access_token(&access).await.unwrap().is_some());
    let (access3, refresh3) = (unique("access"), unique("refresh"));
    assert!(matches!(
        store
            .rotate_refresh_token(
                &refresh2,
                &client_id,
                &access3,
                MINUTE,
                &refresh3,
                MINUTE,
                Duration::ZERO,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Rotated(_)
    ));
    assert_eq!(
        store
            .rotate_refresh_token(
                &refresh,
                &client_id,
                &unique("access"),
                MINUTE,
                &unique("refresh"),
                MINUTE,
                Duration::ZERO,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Replayed,
        "the first refresh token was marked used"
    );
    assert!(store.access_token(&access2).await.unwrap().is_none());
    assert!(store.access_token(&access3).await.unwrap().is_none());
    assert_eq!(
        store
            .take_refresh_token(&refresh3, &client_id)
            .await
            .unwrap(),
        Redemption::Invalid,
        "revoking the grant deletes the replacement refresh token"
    );

    // The replacement refresh token collides with one already stored. The
    // insert fails and the claim rolls back with it.
    let (_kept_grant, kept_access, kept_refresh) =
        pair_for(store, &client_id, &account.id, MINUTE).await;
    let (_other_grant, other_access, other_refresh) =
        pair_for(store, &client_id, &account.id, MINUTE).await;
    let failed_access = unique("access");
    let err = store
        .rotate_refresh_token(
            &kept_refresh,
            &client_id,
            &failed_access,
            MINUTE,
            &other_refresh,
            MINUTE,
            Duration::ZERO,
            allow,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Database(_)), "{err}");
    assert!(store.access_token(&failed_access).await.unwrap().is_none());
    assert!(store.access_token(&other_access).await.unwrap().is_some());
    assert!(store.access_token(&kept_access).await.unwrap().is_some());
    let (retried_access, retried_refresh) = (unique("access"), unique("refresh"));
    let retried = store
        .rotate_refresh_token(
            &kept_refresh,
            &client_id,
            &retried_access,
            MINUTE,
            &retried_refresh,
            MINUTE,
            Duration::ZERO,
            allow,
        )
        .await
        .unwrap();
    assert!(
        matches!(retried, RefreshRotation::Rotated(_)),
        "the presented token is still unused after the failed insert, got {retried:?}"
    );
    assert!(store.access_token(&retried_access).await.unwrap().is_some());
    // The token whose hash collided was not consumed.
    assert!(matches!(
        store
            .take_refresh_token(&other_refresh, &client_id)
            .await
            .unwrap(),
        Redemption::Valid(_)
    ));

    // A disallowed account is refused without a new pair. The old refresh
    // token is consumed, and the grant stays until a second presentation.
    let (_refused_grant, refused_access, refused_refresh) =
        pair_for(store, &client_id, &account.id, MINUTE).await;
    let refused_new = unique("access");
    assert!(matches!(
        store
            .rotate_refresh_token(
                &refused_refresh,
                &client_id,
                &refused_new,
                MINUTE,
                &unique("refresh"),
                MINUTE,
                Duration::ZERO,
                |_| false,
            )
            .await
            .unwrap(),
        RefreshRotation::Refused(_)
    ));
    assert!(store.access_token(&refused_new).await.unwrap().is_none());
    assert!(store.access_token(&refused_access).await.unwrap().is_some());
    assert_eq!(
        store
            .rotate_refresh_token(
                &refused_refresh,
                &client_id,
                &unique("access"),
                MINUTE,
                &unique("refresh"),
                MINUTE,
                Duration::ZERO,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Replayed
    );
    assert!(store.access_token(&refused_access).await.unwrap().is_none());

    // A wrong client does not consume the token.
    let (_wrong_grant, _wrong_access, wrong_refresh) =
        pair_for(store, &client_id, &account.id, MINUTE).await;
    assert_eq!(
        store
            .rotate_refresh_token(
                &wrong_refresh,
                "other-client",
                &unique("access"),
                MINUTE,
                &unique("refresh"),
                MINUTE,
                Duration::ZERO,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Invalid
    );
    assert!(matches!(
        store
            .rotate_refresh_token(
                &wrong_refresh,
                &client_id,
                &unique("access"),
                MINUTE,
                &unique("refresh"),
                MINUTE,
                Duration::ZERO,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Rotated(_)
    ));

    // An expired token is unchanged and stores nothing.
    let (_expired_grant, _expired_access, expired_refresh) =
        pair_for(store, &client_id, &account.id, Duration::ZERO).await;
    let expired_new = unique("access");
    assert_eq!(
        store
            .rotate_refresh_token(
                &expired_refresh,
                &client_id,
                &expired_new,
                MINUTE,
                &unique("refresh"),
                MINUTE,
                Duration::ZERO,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Invalid
    );
    assert!(store.access_token(&expired_new).await.unwrap().is_none());
    assert_eq!(
        store
            .take_refresh_token(&expired_refresh, &client_id)
            .await
            .unwrap(),
        Redemption::Invalid
    );

    // Concurrent uses and later presentations share the first use's window.
    let grace = Duration::from_secs(30);
    let (grant_id, access, refresh) = pair_for(store, &client_id, &account.id, MINUTE).await;
    let rotate = async |token: &str, access: &str, refresh: &str, allowed: bool| {
        store
            .rotate_refresh_token(
                token,
                &client_id,
                access,
                MINUTE,
                refresh,
                MINUTE,
                grace,
                |_| allowed,
            )
            .await
            .unwrap()
    };
    let pairs = [
        (unique("access"), unique("refresh")),
        (unique("access"), unique("refresh")),
    ];
    let (one, two) = tokio::join!(
        rotate(&refresh, &pairs[0].0, &pairs[0].1, true),
        rotate(&refresh, &pairs[1].0, &pairs[1].1, true),
    );
    assert!(matches!(one, RefreshRotation::Rotated(_)), "{one:?}");
    assert!(matches!(two, RefreshRotation::Rotated(_)), "{two:?}");
    let used_at = async || {
        sqlx::query_scalar::<_, i64>(
            "SELECT used_at FROM refresh_tokens WHERE grant_id = $1 AND used_at IS NOT NULL",
        )
        .bind(&grant_id)
        .fetch_one(store.pool())
        .await
        .unwrap()
    };
    let first_use = used_at().await;
    // Another client cannot claim a used token through the grace path.
    let other_client = client(store).await;
    let foreign_access = unique("access");
    assert_eq!(
        store
            .rotate_refresh_token(
                &refresh,
                &other_client,
                &foreign_access,
                MINUTE,
                &unique("refresh"),
                MINUTE,
                grace,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Invalid,
        "grace must stay bound to the original client",
    );
    assert!(store.access_token(&foreign_access).await.unwrap().is_none());
    assert_eq!(used_at().await, first_use);
    // Age the first use without sleeping, and prove the third use cannot reset it.
    sqlx::query("UPDATE refresh_tokens SET used_at = used_at - 25 WHERE grant_id = $1")
        .bind(&grant_id)
        .execute(store.pool())
        .await
        .unwrap();
    let (third_access, third_refresh) = (unique("access"), unique("refresh"));
    assert!(matches!(
        rotate(&refresh, &third_access, &third_refresh, true).await,
        RefreshRotation::Rotated(_)
    ));
    assert_eq!(
        used_at().await,
        first_use - 25,
        "reuse must not extend the window"
    );
    let refused_access = unique("access");
    let refused_refresh = unique("refresh");
    assert!(matches!(
        rotate(&refresh, &refused_access, &refused_refresh, false).await,
        RefreshRotation::Refused(_)
    ));
    assert!(store.access_token(&refused_access).await.unwrap().is_none());
    assert_eq!(
        store
            .take_refresh_token(&refused_refresh, &client_id)
            .await
            .unwrap(),
        Redemption::Invalid
    );
    assert_eq!(used_at().await, first_use - 25);
    for token in [&access, &pairs[0].0, &pairs[1].0, &third_access] {
        assert!(store.access_token(token).await.unwrap().is_some());
    }
    sqlx::query("UPDATE refresh_tokens SET used_at = used_at - 10 WHERE grant_id = $1")
        .bind(&grant_id)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        rotate(&refresh, &unique("access"), &unique("refresh"), true).await,
        RefreshRotation::Replayed
    );
    for token in [&access, &pairs[0].0, &pairs[1].0, &third_access] {
        assert!(store.access_token(token).await.unwrap().is_none());
    }
    for token in [&refresh, &pairs[0].1, &pairs[1].1, &third_refresh] {
        assert_eq!(
            rotate(token, &unique("access"), &unique("refresh"), true).await,
            RefreshRotation::Invalid
        );
    }

    // Taking without a replacement still revokes, even inside the window.
    let (_, access, refresh) = pair_for(store, &client_id, &account.id, MINUTE).await;
    assert!(matches!(
        rotate(&refresh, &unique("access"), &unique("refresh"), true).await,
        RefreshRotation::Rotated(_)
    ));
    let (racing_access, racing_refresh) = (unique("access"), unique("refresh"));
    let (reused, taken) = tokio::join!(
        rotate(&refresh, &racing_access, &racing_refresh, true),
        store.take_refresh_token(&refresh, &client_id),
    );
    assert!(matches!(
        reused,
        RefreshRotation::Rotated(_) | RefreshRotation::Invalid
    ));
    assert_eq!(taken.unwrap(), Redemption::Replayed);
    assert!(store.access_token(&access).await.unwrap().is_none());
    assert!(store.access_token(&racing_access).await.unwrap().is_none());

    // A clock behind the first use fails closed, even within the grace.
    let long_grace = Duration::from_hours(2);
    let (grant_id, access, refresh) = pair_for(store, &client_id, &account.id, long_grace).await;
    assert!(matches!(
        rotate(&refresh, &unique("access"), &unique("refresh"), true).await,
        RefreshRotation::Rotated(_)
    ));
    sqlx::query("UPDATE refresh_tokens SET used_at = used_at + 3600 WHERE grant_id = $1")
        .bind(&grant_id)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store
            .rotate_refresh_token(
                &refresh,
                &client_id,
                &unique("access"),
                MINUTE,
                &unique("refresh"),
                MINUTE,
                long_grace,
                allow,
            )
            .await
            .unwrap(),
        RefreshRotation::Replayed,
        "a clock moving backward must fail closed",
    );
    assert!(store.access_token(&access).await.unwrap().is_none());
}

#[tokio::test]
async fn sqlite_refresh_rotation_is_atomic() {
    let (store, _dir) = sqlite().await;
    exercise_refresh_rotation_is_atomic(&store).await;
}

/// A principal's code and grant follow the same redemption, rotation and
/// replay rules as an account's, have no address for the allow-list, and
/// are revoked by principal alone.
async fn exercise_principal_grants(store: &Store) {
    let client_id = client(store).await;
    let principal = unique("member");
    let grant = CodeGrant {
        client_id: client_id.clone(),
        subject: GrantSubject::Principal(principal.clone()),
        redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
        code_challenge: "challenge".to_owned(),
        scope: "mail".to_owned(),
        resource: Some("https://acme.example.com/mcp".to_owned()),
    };
    let code = unique("code");
    store.save_code(&code, &grant, MINUTE).await.unwrap();
    assert_eq!(
        store.take_code(&code).await.unwrap(),
        Redemption::Valid(grant.clone())
    );
    let (access, refresh) = (unique("access"), unique("refresh"));
    store
        .create_grant_for_code(&code, &grant, &access, MINUTE, &refresh, MINUTE)
        .await
        .unwrap()
        .unwrap();
    let resolved = store.access_token(&access).await.unwrap().unwrap();
    assert_eq!(resolved.subject, GrantSubject::Principal(principal.clone()));
    assert_eq!(resolved.email, None);
    assert_eq!(resolved.resource, grant.resource);

    let (access2, refresh2) = (unique("access"), unique("refresh"));
    let rotated = store
        .rotate_refresh_token(
            &refresh,
            &client_id,
            &access2,
            MINUTE,
            &refresh2,
            MINUTE,
            Duration::ZERO,
            |_: &str| -> bool { panic!("the allow-list was asked about a principal") },
        )
        .await
        .unwrap();
    let RefreshRotation::Rotated(rotated) = rotated else {
        panic!("expected a rotation, got {rotated:?}");
    };
    assert_eq!(rotated.subject, GrantSubject::Principal(principal.clone()));
    assert_eq!(
        store
            .take_refresh_token(&refresh, &client_id)
            .await
            .unwrap(),
        Redemption::Replayed
    );
    assert!(store.access_token(&access2).await.unwrap().is_none());

    let empty = CodeGrant {
        subject: GrantSubject::Principal(String::new()),
        ..grant.clone()
    };
    assert!(matches!(
        store.save_code(&unique("code"), &empty, MINUTE).await,
        Err(StoreError::InvalidInput(_))
    ));
    assert!(matches!(
        store.create_grant(&empty).await,
        Err(StoreError::InvalidInput(_))
    ));

    let account = store
        .upsert_account(&format!("{}@example.com", unique("kept")), &secret("pw"))
        .await
        .unwrap();
    let (_, account_access, _) = pair_for(store, &client_id, &account.id, MINUTE).await;
    let other = CodeGrant {
        subject: GrantSubject::Principal(unique("member")),
        ..grant.clone()
    };
    let other_grant = store.create_grant(&other).await.unwrap();
    let other_access = unique("access");
    store
        .save_tokens(
            &other_grant,
            &other_access,
            MINUTE,
            &unique("refresh"),
            MINUTE,
        )
        .await
        .unwrap();
    let revoked_grant = store.create_grant(&grant).await.unwrap();
    let (revoked_access, revoked_refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(
            &revoked_grant,
            &revoked_access,
            MINUTE,
            &revoked_refresh,
            MINUTE,
        )
        .await
        .unwrap();
    let pending = unique("code");
    store.save_code(&pending, &grant, MINUTE).await.unwrap();

    assert_eq!(store.revoke_principal_grants(&principal).await.unwrap(), 1);
    assert!(store.access_token(&revoked_access).await.unwrap().is_none());
    assert_eq!(
        store
            .take_refresh_token(&revoked_refresh, &client_id)
            .await
            .unwrap(),
        Redemption::Invalid
    );
    assert_eq!(
        store.take_code(&pending).await.unwrap(),
        Redemption::Invalid,
        "a code not redeemed yet is revoked too"
    );
    assert!(store.access_token(&account_access).await.unwrap().is_some());
    assert!(store.access_token(&other_access).await.unwrap().is_some());
    assert_eq!(store.revoke_principal_grants(&principal).await.unwrap(), 0);
}

#[tokio::test]
async fn sqlite_principal_grants() {
    let (store, _dir) = sqlite().await;
    exercise_principal_grants(&store).await;
}

/// Two uses of one refresh token that overlap on SQLite must not surface as
/// a storage error: one redeems it, and the other revokes the grant.
#[tokio::test]
async fn sqlite_concurrent_refresh_use_revokes_the_grant() {
    let (store, _dir) = sqlite().await;
    let client_id = client(&store).await;
    let account = store
        .upsert_account(&format!("{}@icloud.com", unique("race")), &secret("pw"))
        .await
        .unwrap();
    let grant_id = store
        .create_grant(&CodeGrant {
            client_id: client_id.clone(),
            subject: GrantSubject::Account(account.id.clone()),
            redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
            code_challenge: "challenge".to_owned(),
            scope: "mail".to_owned(),
            resource: None,
        })
        .await
        .unwrap();
    let (access, refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&grant_id, &access, MINUTE, &refresh, MINUTE)
        .await
        .unwrap();

    let n = 8;
    let barrier = Arc::new(tokio::sync::Barrier::new(n));
    let mut tasks = Vec::with_capacity(n);
    for _ in 0..n {
        let store = store.clone();
        let refresh = refresh.clone();
        let client_id = client_id.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.take_refresh_token(&refresh, &client_id).await
        }));
    }
    let mut outcomes = Vec::with_capacity(n);
    for task in tasks {
        outcomes.push(task.await.unwrap().unwrap());
    }
    let valid = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Redemption::Valid(_)))
        .count();
    let replayed = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Redemption::Replayed))
        .count();
    assert_eq!(valid, 1, "{outcomes:?}");
    assert!(
        replayed >= 1,
        "a concurrent second use must revoke the grant, got {outcomes:?}"
    );
    assert!(
        store.access_token(&access).await.unwrap().is_none(),
        "the grant behind the reused refresh token must be gone"
    );
}

/// The rotation the token endpoint uses claims and inserts in one
/// transaction. A concurrent second use still sees zero rows and revokes
/// the grant, including the pair the winner stored.
#[tokio::test]
async fn sqlite_concurrent_refresh_rotation_revokes_the_grant() {
    let (store, _dir) = sqlite().await;
    let client_id = client(&store).await;
    let account = store
        .upsert_account(&format!("{}@example.com", unique("race")), &secret("pw"))
        .await
        .unwrap();
    let grant_id = store
        .create_grant(&CodeGrant {
            client_id: client_id.clone(),
            subject: GrantSubject::Account(account.id.clone()),
            redirect_uri: "http://127.0.0.1:9999/callback".to_owned(),
            code_challenge: "challenge".to_owned(),
            scope: "mail".to_owned(),
            resource: None,
        })
        .await
        .unwrap();
    let (access, refresh) = (unique("access"), unique("refresh"));
    store
        .save_tokens(&grant_id, &access, MINUTE, &refresh, MINUTE)
        .await
        .unwrap();

    let n = 8;
    let barrier = Arc::new(tokio::sync::Barrier::new(n));
    let mut tasks = Vec::with_capacity(n);
    for _ in 0..n {
        let store = store.clone();
        let refresh = refresh.clone();
        let client_id = client_id.clone();
        let barrier = Arc::clone(&barrier);
        let new_access = unique("access");
        let new_refresh = unique("refresh");
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let outcome = store
                .rotate_refresh_token(
                    &refresh,
                    &client_id,
                    &new_access,
                    MINUTE,
                    &new_refresh,
                    MINUTE,
                    Duration::ZERO,
                    |_| true,
                )
                .await;
            (outcome, new_access)
        }));
    }
    let mut outcomes = Vec::with_capacity(n);
    let mut rotated_access = None;
    for task in tasks {
        let (outcome, new_access) = task.await.unwrap();
        let outcome = outcome.unwrap();
        if matches!(outcome, RefreshRotation::Rotated(_)) {
            rotated_access = Some(new_access);
        }
        outcomes.push(outcome);
    }
    let valid = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RefreshRotation::Rotated(_)))
        .count();
    let replayed = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, RefreshRotation::Replayed))
        .count();
    assert_eq!(valid, 1, "{outcomes:?}");
    assert!(
        replayed >= 1,
        "a concurrent second use must revoke the grant, got {outcomes:?}"
    );
    assert!(
        store.access_token(&access).await.unwrap().is_none(),
        "the grant behind the reused refresh token must be gone"
    );
    let rotated_access = rotated_access.unwrap();
    assert!(
        store.access_token(&rotated_access).await.unwrap().is_none(),
        "the pair stored by the winner is revoked with the grant"
    );
}

#[tokio::test]
async fn sqlite_password_change_ends_only_that_accounts_sessions() {
    let (store, _dir) = sqlite().await;
    let ttl = SessionTtl {
        idle: Duration::from_hours(1),
        absolute: Duration::from_hours(12),
    };
    let email = format!("{}@icloud.com", unique("rotate"));
    let created = store
        .upsert_imap_account_ending_sessions(&email, &secret("aaaaaaaabbbbbbbb"), Some("icloud"))
        .await
        .unwrap();
    assert!(
        !created.password_changed,
        "a new account has no password to replace"
    );
    let current = unique("current");
    let other = unique("other");
    store
        .create_session(&current, &created.account.id, ttl)
        .await
        .unwrap();
    store
        .create_session(&other, &created.account.id, ttl)
        .await
        .unwrap();
    let foreign = store
        .upsert_account(
            &format!("{}@icloud.com", unique("foreign")),
            &secret("cccccccceeeeeeee"),
        )
        .await
        .unwrap();
    let foreign_token = unique("foreign-token");
    store
        .create_session(&foreign_token, &foreign.id, ttl)
        .await
        .unwrap();

    let same = store
        .upsert_imap_account_ending_sessions(&email, &secret("aaaaaaaabbbbbbbb"), Some("icloud"))
        .await
        .unwrap();
    assert!(!same.password_changed);
    assert_eq!(same.account.id, created.account.id);
    assert!(store.session(&current, ttl).await.unwrap().is_some());
    assert!(store.session(&other, ttl).await.unwrap().is_some());

    // Replacing the password without the session-ending entry point leaves
    // sessions for the account page's own "keep this browser" path.
    store
        .upsert_imap_account(&email, &secret("ddddddddffffffff"), Some("icloud"))
        .await
        .unwrap();
    assert!(store.session(&current, ttl).await.unwrap().is_some());

    let changed = store
        .upsert_imap_account_ending_sessions(&email, &secret("gggggggghhhhhhhh"), Some("icloud"))
        .await
        .unwrap();
    assert!(changed.password_changed);
    assert_eq!(
        store
            .credentials(&created.account.id)
            .await
            .unwrap()
            .unwrap()
            .password
            .expose_secret(),
        "gggggggghhhhhhhh"
    );
    assert!(store.session(&current, ttl).await.unwrap().is_none());
    assert!(store.session(&other, ttl).await.unwrap().is_none());
    assert_eq!(
        store.session(&foreign_token, ttl).await.unwrap().as_ref(),
        Some(&foreign),
        "another account's session stays"
    );

    // An OAuth account still conflicts, and its session stays.
    let oauth_email = format!("{}@outlook.com", unique("oauth"));
    let oauth = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: &unique("subject"),
                email: &oauth_email,
            },
            &UpstreamTokens {
                refresh_token: secret("refresh"),
                access_token: None,
                access_expires_at: None,
                scope: "Mail.Read".to_owned(),
            },
        )
        .await
        .unwrap();
    let oauth_session = unique("oauth-session");
    store
        .create_session(&oauth_session, &oauth.id, ttl)
        .await
        .unwrap();
    let err = store
        .upsert_imap_account_ending_sessions(&oauth_email, &secret("imap-password-value"), None)
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::AccountConflict), "{err:?}");
    assert!(store.session(&oauth_session, ttl).await.unwrap().is_some());

    // A password sealed under a different key cannot be compared. Replacing
    // it counts as a change and ends sessions. The stored password is v1 text
    // sealed here under a key the store does not have.
    let stranger = KnownKey::new(0x31);
    let account = &created.account;
    let (row, owner) = (&account.id.0, &account.email);
    PASSWORD
        .put(&store, &stranger, row, owner, "gggggggghhhhhhhh")
        .await;
    let err = store.credentials(&account.id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
    store
        .create_session(&current, &created.account.id, ttl)
        .await
        .unwrap();
    let unreadable = store
        .upsert_imap_account_ending_sessions(&email, &secret("iiiiiiiijjjjjjjj"), Some("icloud"))
        .await
        .unwrap();
    assert!(unreadable.password_changed);
    assert_eq!(
        store
            .credentials(&created.account.id)
            .await
            .unwrap()
            .unwrap()
            .password
            .expose_secret(),
        "iiiiiiiijjjjjjjj"
    );
    assert!(store.session(&current, ttl).await.unwrap().is_none());
    store.close().await;
}

#[tokio::test]
async fn sqlite_rejects_wrong_master_key() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let store = Store::connect(&url, &key()).await.unwrap();
    let account = store
        .upsert_account("a@icloud.com", &secret("pw"))
        .await
        .unwrap();
    store.close().await;

    let other = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let reopened = Store::connect(&url, &other).await.unwrap();
    let err = reopened.credentials(&account.id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
}

/// The master key is lost or replaced and no previous key is configured, so
/// nothing stored opens. Writing again recovers: signing in replaces the
/// password, saving replaces the webhook settings, and new events are stored
/// and read, while the events queued before are lost. This is the recovery the
/// deployment and configuration guides describe. A writer that seals under a
/// data key kept in the database must make a new key when the stored one can
/// never be unwrapped, or this fails.
#[tokio::test]
async fn sqlite_a_replaced_master_key_is_recovered_by_writing_again() {
    let (store, dir) = sqlite().await;
    let account = store
        .upsert_account("a@example.com", &secret("old-password"))
        .await
        .unwrap();
    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    let queued = store
        .append_mail_event(&account.id, r#"{"n":1}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert!(PAYLOAD.get(&store, &queued.id).await.starts_with("v2.1."));
    store.close().await;

    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let store = Store::connect(&url, &random_key()).await.unwrap();
    let err = store.credentials(&account.id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
    let err = store.webhook(&account.id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");

    let again = store
        .upsert_imap_account_ending_sessions(&account.email, &secret("new-password"), None)
        .await
        .unwrap();
    assert!(again.password_changed);
    assert_eq!(again.account.id, account.id);
    let found = store.credentials(&account.id).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "new-password");

    store
        .save_webhook(&account.id, &settings("https://b.example/h"))
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.settings.url, "https://b.example/h");
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_one");

    let event = store
        .append_mail_event(&account.id, r#"{"n":2}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert!(PAYLOAD.get(&store, &event.id).await.starts_with("v2.2."));
    // Saving the webhook for another address skipped the events kept so far.
    // Replaying them puts the queued one back in line: it is stored, cannot be
    // opened, and is passed over.
    let replayed = store.replay_mail_events(&account.id, queued.sequence).await;
    assert_eq!(replayed.unwrap(), 2);
    store.set_event_hold(Duration::ZERO); // it would be held for an hour
    let pending = store.pending_mail_events(&account.id, 10).await.unwrap();
    assert_eq!(pending.events, [event]);
    assert_eq!(pending.skip_through, None);
    store.close().await;
}

async fn data_keys(store: &Store) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM data_keys")
        .fetch_one(store.pool())
        .await
        .unwrap()
}

/// The password and the webhook secrets are v2 values under a data key that
/// the lost master key wrapped. A new master key alone cannot open them, makes
/// a data key of its own beside the first on the next write, and writes under it.
/// A process that still has the old key keeps to the first, so the versions do
/// not climb.
#[tokio::test]
async fn sqlite_a_new_master_key_alone_takes_new_secrets() {
    let (store, dir) = sqlite().await;
    let email = format!("{}@example.com", unique("lost"));
    let account = store.upsert_account(&email, &secret("old")).await.unwrap();
    let id = &account.id.0;
    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    for column in [PASSWORD, AUTH, SECRET] {
        assert!(column.get(&store, id).await.starts_with("v2.1."));
    }
    let queued = store
        .append_mail_event(&account.id, r#"{"n":1}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert!(PAYLOAD.get(&store, &queued.id).await.starts_with("v2.1."));
    store.close().await;

    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let new = Store::connect(&url, &random_key()).await.unwrap();
    let err = new.credentials(&account.id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
    let loaded = new.load_webhook(&account.id).await.unwrap();
    assert!(matches!(
        loaded,
        LoadedWebhook::Unreadable { enabled: true }
    ));
    assert_eq!(data_keys(&new).await, 1);

    let again = new
        .upsert_imap_account_ending_sessions(&email, &secret("new"), None)
        .await
        .unwrap();
    assert!(again.password_changed);
    assert_eq!(again.account.id, account.id);
    new.save_webhook(&account.id, &settings("https://b.example/h"))
        .await
        .unwrap();
    for column in [PASSWORD, AUTH, SECRET] {
        assert!(column.get(&new, id).await.starts_with("v2.2."));
    }
    let found = new.credentials(&account.id).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "new");
    let hook = new.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.settings.url, "https://b.example/h");
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_one");
    let event = new
        .append_mail_event(&account.id, r#"{"n":2}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert!(PAYLOAD.get(&new, &event.id).await.starts_with("v2.2."));
    assert_eq!(data_keys(&new).await, 2);
    new.close().await;

    let old = Store::connect(&url, &key()).await.unwrap();
    old.save_webhook(&account.id, &settings("https://c.example/h"))
        .await
        .unwrap();
    assert!(SECRET.get(&old, id).await.starts_with("v2.1."));
    let kept = old
        .append_mail_event(&account.id, r#"{"n":3}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert!(PAYLOAD.get(&old, &kept.id).await.starts_with("v2.1."));
    assert_eq!(data_keys(&old).await, 2);
    let err = old.credentials(&account.id).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
}

#[tokio::test]
async fn sqlite_rotates_master_random_key() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let old = KnownKey::new(0x21);
    let store = Store::connect(&url, &old.master()).await.unwrap();
    let account = store
        .upsert_account("a@icloud.com", &secret("pw"))
        .await
        .unwrap();
    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    // The sweep moves v1 values to the data key of their tenant, also from a
    // previous master key. These three are sealed here under the old key, so
    // they are v1 whatever the writers store; a fourth, of a second account,
    // is under a key that is never configured again.
    let id = &account.id.0;
    PASSWORD.put(&store, &old, id, &account.email, "pw").await;
    AUTH.put(&store, &old, id, id, "Bearer t").await;
    SECRET.put(&store, &old, id, id, "whsec_one").await;
    let lost = store
        .upsert_account("lost@example.com", &secret("pw-lost"))
        .await
        .unwrap();
    let lost_key = KnownKey::new(0x33);
    PASSWORD
        .put(&store, &lost_key, &lost.id.0, &lost.email, "pw-lost")
        .await;
    assert!(!store.rotating_keys());
    store.close().await;

    // The new key alone can't read the old value.
    let new = random_key();
    let store = Store::connect(&url, &new).await.unwrap();
    assert!(store.credentials(&account.id).await.is_err());
    store.close().await;

    // With the old key as a previous key it can, and the sweep moves the
    // values to a data key. The data key was wrapped under the old key, so
    // the re-wrap is what lets the new key alone read it.
    let stranger = random_key();
    let store = Store::connect_rotating(&url, &new, &[stranger, old.master()])
        .await
        .unwrap();
    assert!(store.rotating_keys());
    let credentials = store.credentials(&account.id).await.unwrap().unwrap();
    assert_eq!(credentials.password.expose_secret(), "pw");
    let report = store.reencrypt().await.unwrap();
    // The password, the webhook auth header value and its signing secret
    // move; the other password is under no configured key.
    assert_eq!((report.updated, report.unreadable), (3, 1));
    assert!(PASSWORD.get(&store, id).await.starts_with("v2.1."));
    assert_eq!(store.rewrap_data_keys().await.unwrap().rewrapped, 1);
    let again = store.reencrypt().await.unwrap();
    assert_eq!(
        (again.updated, again.already_v2, again.unreadable),
        (0, 3, 1)
    );
    store.close().await;

    let store = Store::connect(&url, &new).await.unwrap();
    let credentials = store.credentials(&account.id).await.unwrap().unwrap();
    assert_eq!(credentials.password.expose_secret(), "pw");
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_one");
    store.close().await;

    // Values no key can read are reported, not destroyed.
    let store = Store::connect_rotating(&url, &random_key(), &[random_key()])
        .await
        .unwrap();
    let before = PASSWORD.get(&store, &lost.id.0).await;
    let report = store.reencrypt().await.unwrap();
    assert_eq!(
        (report.updated, report.already_v2, report.unreadable),
        (0, 3, 1)
    );
    assert_eq!(PASSWORD.get(&store, &lost.id.0).await, before);
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_all() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    exercise_accounts(&store).await;
    exercise_password_rejection(&store).await;
    exercise_clients(&store).await;
    exercise_oauth_flow(&store).await;
    exercise_code_redemption_is_atomic(&store).await;
    exercise_refresh_rotation_is_atomic(&store).await;
    exercise_principal_grants(&store).await;
    exercise_client_expiry(&store).await;
    exercise_sessions(&store).await;
    exercise_writes_for_a_deleted_account(&store).await;
    exercise_account_clients(&store).await;
    exercise_held_sends(&store).await;
    exercise_uploads(&store, &url).await;
    exercise_webhooks(&store).await;
}
