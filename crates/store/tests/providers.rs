//! Tests for OAuth accounts, upstream tokens and sign-ins, push
//! subscriptions and the event outbox. The PostgreSQL variant is ignored
//! unless run explicitly with `TEST_POSTGRES_URL` set.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

mod common;

use std::time::{Duration, Instant};

use common::{
    ACCESS, CONTINUATION, KnownKey, PAYLOAD, REFRESH, REQUEST_ID, SECRET, VERIFIER, state_hash,
    unreadable,
};
use postkeep_store::{
    AppendOutcome, MailEvent, MasterKey, OAuthAccount, Provider, PurgePolicy, PushSubscription,
    Store, StoreError, UpstreamPurpose, UpstreamRequest, UpstreamTokens, WatchAdvance, WatchCursor,
    WebhookSettings,
};
use secrecy::{ExposeSecret, SecretString};

fn key() -> MasterKey {
    MasterKey::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap()
}

fn random_key() -> MasterKey {
    MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap()
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

fn unique(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4().simple())
}

async fn sqlite() -> (Store, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    (Store::connect(&url, &key()).await.unwrap(), dir, url)
}

fn tokens(refresh: &str) -> UpstreamTokens {
    UpstreamTokens {
        refresh_token: secret(refresh),
        access_token: Some(secret("access-1")),
        access_expires_at: Some(postkeep_store::now() + 3600),
        scope: "Mail.ReadWrite Mail.Send offline_access User.Read".to_owned(),
    }
}

fn settings(url: &str) -> WebhookSettings {
    WebhookSettings {
        enabled: true,
        url: url.to_owned(),
        auth_header: None,
        signing: true,
        signing_secret: secret("whsec_one"),
        include_sender: true,
    }
}

async fn exercise_oauth_accounts(store: &Store) {
    let email = format!("{}@Outlook.com", unique("user"));
    let subject = unique("subject");
    let account = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: &subject,
                email: &email,
            },
            &tokens("refresh-1"),
        )
        .await
        .unwrap();
    assert_eq!(account.provider, Provider::Graph);
    assert_eq!(account.email, email.to_lowercase());
    assert_eq!(
        store.account(&account.id).await.unwrap(),
        Some(account.clone())
    );
    assert_eq!(
        store
            .account_by_subject(Provider::Graph, &subject)
            .await
            .unwrap(),
        Some(account.clone())
    );
    assert_eq!(
        store
            .account_by_email(&email, Provider::Graph)
            .await
            .unwrap()
            .map(|found| found.id),
        Some(account.id.clone())
    );
    // OAuth accounts have no IMAP password.
    assert!(store.credentials(&account.id).await.unwrap().is_none());

    let stored = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-1");
    assert_eq!(
        stored
            .tokens
            .access_token
            .as_ref()
            .map(ExposeSecret::expose_secret),
        Some("access-1")
    );
    assert!(stored.invalid_reason.is_none());

    // Signing in again finds the same account and replaces the tokens.
    let again = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: &subject,
                email: &email,
            },
            &tokens("refresh-2"),
        )
        .await
        .unwrap();
    assert_eq!(again.id, account.id);
    let stored = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-2");

    // A rejected refresh token is recorded and cleared by a new sign-in.
    store
        .mark_upstream_tokens_invalid(&account.id, "invalid_grant")
        .await
        .unwrap();
    let stored = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert_eq!(stored.invalid_reason.as_deref(), Some("invalid_grant"));
    assert!(stored.tokens.access_token.is_none());
    let mut refreshed = tokens("refresh-3");
    refreshed.access_token = None;
    store
        .save_upstream_tokens(&account.id, &refreshed)
        .await
        .unwrap();
    let stored = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert!(stored.invalid_reason.is_none());
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-3");

    // Another user of the same provider, or another provider, can't take
    // over the address.
    for (provider, other_subject) in [
        (Provider::Graph, unique("other")),
        (Provider::Gmail, subject.clone()),
    ] {
        let err = store
            .upsert_oauth_account(
                &OAuthAccount {
                    provider,
                    subject: &other_subject,
                    email: &email,
                },
                &tokens("x"),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::AccountConflict), "{err:?}");
    }
    // Nor can an app-password sign-in.
    let err = store
        .upsert_imap_account(&email, &secret("pw"), Some("icloud"))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::AccountConflict), "{err:?}");
    // And an OAuth sign-in can't take over an IMAP account.
    let imap_email = format!("{}@icloud.com", unique("imap"));
    let imap = store
        .upsert_imap_account(&imap_email, &secret("pw"), Some("icloud"))
        .await
        .unwrap();
    assert_eq!(imap.provider, Provider::Imap);
    assert_eq!(imap.imap_server.as_deref(), Some("icloud"));
    let creds = store.credentials(&imap.id).await.unwrap().unwrap();
    assert_eq!(creds.imap_server.as_deref(), Some("icloud"));
    let err = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Gmail,
                subject: &unique("g"),
                email: &imap_email,
            },
            &tokens("x"),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::AccountConflict), "{err:?}");

    // A changed address at the provider follows the subject.
    let renamed = format!("{}@outlook.com", unique("renamed"));
    let moved = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: &subject,
                email: &renamed,
            },
            &tokens("refresh-4"),
        )
        .await
        .unwrap();
    assert_eq!(moved.id, account.id);
    assert_eq!(moved.email, renamed);

    assert!(store.delete_account(&account.id).await.unwrap());
    assert!(store.upstream_tokens(&account.id).await.unwrap().is_none());
    assert!(store.delete_account(&imap.id).await.unwrap());
}

async fn exercise_upstream_requests(store: &Store) {
    let state = unique("state");
    store
        .save_upstream_request(
            &state,
            &UpstreamRequest {
                provider: Provider::Gmail,
                purpose: UpstreamPurpose::Authorize {
                    request_id: secret("request-1"),
                },
                code_verifier: secret("verifier-1"),
                binding_hash: "binding".to_owned(),
            },
            Duration::from_mins(10),
        )
        .await
        .unwrap();
    assert!(
        store
            .take_upstream_request("other")
            .await
            .unwrap()
            .is_none()
    );
    let taken = store.take_upstream_request(&state).await.unwrap().unwrap();
    assert_eq!(taken.provider, Provider::Gmail);
    assert_eq!(taken.code_verifier.expose_secret(), "verifier-1");
    assert_eq!(taken.binding_hash, "binding");
    let UpstreamPurpose::Authorize { request_id } = taken.purpose else {
        panic!("wrong purpose");
    };
    assert_eq!(request_id.expose_secret(), "request-1");
    // Single use.
    assert!(store.take_upstream_request(&state).await.unwrap().is_none());

    // A sign-in an embedding started for one of its tenants.
    let continued = unique("state");
    store
        .save_upstream_request(
            &continued,
            &UpstreamRequest {
                provider: Provider::Graph,
                purpose: UpstreamPurpose::Continue {
                    tenant: "acme".to_owned(),
                    continuation: secret("connect-1"),
                },
                code_verifier: secret("verifier-2"),
                binding_hash: "binding-2".to_owned(),
            },
            Duration::from_mins(10),
        )
        .await
        .unwrap();
    let taken = store
        .take_upstream_request(&continued)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(taken.provider, Provider::Graph);
    assert_eq!(taken.code_verifier.expose_secret(), "verifier-2");
    let UpstreamPurpose::Continue {
        tenant,
        continuation,
    } = taken.purpose
    else {
        panic!("wrong purpose");
    };
    assert_eq!(
        (tenant.as_str(), continuation.expose_secret()),
        ("acme", "connect-1")
    );

    // Expired requests are not returned.
    let expired = unique("state");
    store
        .save_upstream_request(
            &expired,
            &UpstreamRequest {
                provider: Provider::Graph,
                purpose: UpstreamPurpose::Account,
                code_verifier: secret("v"),
                binding_hash: "b".to_owned(),
            },
            Duration::ZERO,
        )
        .await
        .unwrap();
    assert!(
        store
            .take_upstream_request(&expired)
            .await
            .unwrap()
            .is_none()
    );
}

async fn exercise_push(store: &Store) {
    let account = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: &unique("s"),
                email: &format!("{}@outlook.com", unique("push")),
            },
            &tokens("r"),
        )
        .await
        .unwrap();
    assert!(
        store
            .push_subscription(&account.id)
            .await
            .unwrap()
            .is_none()
    );
    let subscription_id = unique("sub");
    let subscription = PushSubscription {
        provider: Provider::Graph,
        subscription_id: Some(subscription_id.clone()),
        client_state_hash: Some(PushSubscription::hash_client_state("client-state")),
        expires_at: 1_900_000_000,
    };
    store
        .save_push_subscription(&account.id, &subscription)
        .await
        .unwrap();
    let (found_account, found) = store
        .push_subscription_by_id(&subscription_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found_account, account.id);
    assert_eq!(found, subscription);
    assert!(found.client_state_matches("client-state"));
    assert!(!found.client_state_matches("client-statf"));
    assert!(!found.client_state_matches(""));
    // Another account can't take the id: a failure that is not a deletion.
    let other = store
        .upsert_account(&format!("{}@icloud.com", unique("other")), &secret("pw"))
        .await
        .unwrap();
    let taken = store.save_push_subscription(&other.id, &subscription).await;
    assert!(matches!(taken, Err(StoreError::Database(_))), "{taken:?}");
    assert!(
        !store
            .delete_push_subscription_if_id(&account.id, Some("other-id"))
            .await
            .unwrap()
    );
    let replacement_id = unique("sub-new");
    let replacement = PushSubscription {
        provider: Provider::Graph,
        subscription_id: Some(replacement_id.clone()),
        client_state_hash: Some(PushSubscription::hash_client_state("next-state")),
        expires_at: 1_900_000_100,
    };
    store
        .save_push_subscription(&account.id, &replacement)
        .await
        .unwrap();
    assert!(
        !store
            .delete_push_subscription_if_id(&account.id, Some(&subscription_id))
            .await
            .unwrap(),
        "an older Graph subscription id must not delete the replacement row"
    );
    assert_eq!(
        store.push_subscription(&account.id).await.unwrap().as_ref(),
        Some(&replacement)
    );
    assert!(
        store
            .delete_push_subscription_if_id(&account.id, Some(&replacement_id))
            .await
            .unwrap()
    );
    assert!(
        store
            .push_subscription(&account.id)
            .await
            .unwrap()
            .is_none()
    );
    let gmail = PushSubscription {
        provider: Provider::Gmail,
        subscription_id: None,
        client_state_hash: None,
        expires_at: 1,
    };
    assert!(!gmail.client_state_matches(""));
    store
        .save_push_subscription(&account.id, &gmail)
        .await
        .unwrap();
    assert!(
        !store
            .delete_push_subscription_if_id(&account.id, Some("sub-old"))
            .await
            .unwrap()
    );
    assert!(
        store
            .delete_push_subscription_if_id(&account.id, None)
            .await
            .unwrap()
    );
    assert!(
        store
            .push_subscription(&account.id)
            .await
            .unwrap()
            .is_none()
    );
    store.delete_push_subscription(&account.id).await.unwrap();
    assert!(
        store
            .push_subscription(&account.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.delete_account(&account.id).await.unwrap());
    // A renewal that saves after the account's deletion committed.
    let renewed = store.save_push_subscription(&account.id, &gmail).await;
    assert!(
        matches!(renewed, Err(StoreError::AccountDeleted)),
        "{renewed:?}"
    );
    assert!(
        store
            .push_subscription(&account.id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.delete_account(&other.id).await.unwrap());
}

async fn exercise_events(store: &Store) {
    let account = store
        .upsert_account(&format!("{}@icloud.com", unique("events")), &secret("pw"))
        .await
        .unwrap();
    // Without a webhook there is no stream.
    assert!(matches!(
        store
            .append_mail_event(&account.id, "{}", None)
            .await
            .unwrap(),
        AppendOutcome::NoWebhook
    ));

    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    let first = store
        .append_mail_event(&account.id, r#"{"n":1}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    let second = store
        .append_mail_event(&account.id, r#"{"n":2}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert_eq!((first.sequence, second.sequence), (1, 2));
    let pending = store
        .pending_mail_events(&account.id, 10)
        .await
        .unwrap()
        .events;
    assert_eq!(pending, [first.clone(), second.clone()]);

    store
        .mark_mail_events_delivered(&account.id, 1)
        .await
        .unwrap();
    assert_eq!(
        store
            .pending_mail_events(&account.id, 10)
            .await
            .unwrap()
            .events,
        std::slice::from_ref(&second)
    );
    // Delivery positions never go backwards or past the end.
    store
        .mark_mail_events_delivered(&account.id, 0)
        .await
        .unwrap();
    store
        .mark_mail_events_delivered(&account.id, 99)
        .await
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!((hook.delivered_sequence, hook.last_sequence), (1, 2));

    // Replaying sends kept events again with their IDs.
    store
        .mark_mail_events_delivered(&account.id, 2)
        .await
        .unwrap();
    assert_eq!(store.replay_mail_events(&account.id, 1).await.unwrap(), 2);
    assert_eq!(
        store
            .pending_mail_events(&account.id, 10)
            .await
            .unwrap()
            .events,
        [first, second]
    );
    assert_eq!(store.oldest_mail_event(&account.id).await.unwrap(), Some(1));

    // Changing the URL skips what was not delivered.
    store
        .save_webhook(&account.id, &settings("https://b.example/h"))
        .await
        .unwrap();
    assert_eq!(
        store
            .pending_mail_events(&account.id, 10)
            .await
            .unwrap()
            .events,
        []
    );
    let third = store
        .append_mail_event(&account.id, r#"{"n":3}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert_eq!(third.sequence, 3);
    store.skip_mail_events(&account.id).await.unwrap();
    assert_eq!(
        store
            .pending_mail_events(&account.id, 10)
            .await
            .unwrap()
            .events,
        []
    );

    // The event and the new cursor or position commit together.
    let expected = WatchCursor {
        uid_validity: 7,
        last_uid: 1,
    };
    store.set_watch_cursor(&account.id, expected).await.unwrap();
    let moved = store
        .append_mail_event(
            &account.id,
            r#"{"n":4}"#,
            Some(WatchAdvance::Cursor {
                expected,
                next: WatchCursor {
                    uid_validity: 7,
                    last_uid: 42,
                },
            }),
        )
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert_eq!(moved.sequence, 4);
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(
        hook.cursor,
        Some(WatchCursor {
            uid_validity: 7,
            last_uid: 42,
        })
    );
    assert_eq!(hook.last_sequence, 4);
    store
        .append_mail_event(
            &account.id,
            r#"{"n":5}"#,
            Some(WatchAdvance::Position {
                expected: None,
                next: "h:12345".to_owned(),
            }),
        )
        .await
        .unwrap()
        .stored()
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.position.as_deref(), Some("h:12345"));
    assert_eq!(hook.cursor.unwrap().last_uid, 42);
    assert_eq!(hook.last_sequence, 5);
    // An event with no advance leaves the watch where it was.
    store
        .append_mail_event(&account.id, r#"{"n":6}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.cursor.unwrap().last_uid, 42);
    assert_eq!(hook.position.as_deref(), Some("h:12345"));
    assert_eq!(hook.last_sequence, 6);
    store.purge_expired(PurgePolicy::default()).await.unwrap();
    assert!(store.delete_account(&account.id).await.unwrap());
    assert_eq!(store.oldest_mail_event(&account.id).await.unwrap(), None);
}

/// A refresh may write or invalidate only while the refresh token it used
/// is still stored. A sign-in that replaced it is left alone.
/// A Graph or Gmail position advances only from the position the batch was
/// read from; two writers with the same `expected` record one event.
async fn exercise_position_compare_and_set(store: &Store) {
    let account = store
        .upsert_account(
            &format!("{}@example.com", unique("position-cas")),
            &secret("pw"),
        )
        .await
        .unwrap();
    let advance = |expected: Option<&str>, next: &str| WatchAdvance::Position {
        expected: expected.map(str::to_owned),
        next: next.to_owned(),
    };
    // No webhook row, so a failed claim is not a stale position.
    assert_eq!(
        store
            .append_mail_event(&account.id, r#"{"n":0}"#, Some(advance(None, "p1")))
            .await
            .unwrap(),
        AppendOutcome::NoWebhook
    );
    store
        .save_webhook(&account.id, &settings("https://hooks.example/p"))
        .await
        .unwrap();
    // Nothing stored yet: only `expected: None` matches.
    assert_eq!(
        store
            .append_mail_event(&account.id, r#"{"n":1}"#, Some(advance(Some("p0"), "p1")))
            .await
            .unwrap(),
        AppendOutcome::StaleCursor
    );
    let first = store
        .append_mail_event(&account.id, r#"{"n":2}"#, Some(advance(None, "p1")))
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert_eq!(first.sequence, 1);

    // A stale or missing `expected` writes nothing: no event, no sequence
    // number, and the position stays.
    for expected in [Some("p0"), None, Some("")] {
        assert_eq!(
            store
                .append_mail_event(&account.id, r#"{"n":3}"#, Some(advance(expected, "p9")))
                .await
                .unwrap(),
            AppendOutcome::StaleCursor,
            "{expected:?}"
        );
    }
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.position.as_deref(), Some("p1"));
    assert_eq!(hook.last_sequence, 1);

    // Two watchers read "p1" and publish at the same time: one event.
    let (a, b) = tokio::join!(
        store.append_mail_event(
            &account.id,
            r#"{"n":"a"}"#,
            Some(advance(Some("p1"), "p2a"))
        ),
        store.append_mail_event(
            &account.id,
            r#"{"n":"b"}"#,
            Some(advance(Some("p1"), "p2b"))
        ),
    );
    let outcomes = [a.unwrap(), b.unwrap()];
    let stored: Vec<&MailEvent> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            AppendOutcome::Stored(event) => Some(event),
            _ => None,
        })
        .collect();
    assert_eq!(stored.len(), 1, "{outcomes:?}");
    assert!(
        outcomes.contains(&AppendOutcome::StaleCursor),
        "{outcomes:?}"
    );
    let winner = if stored[0].payload == r#"{"n":"a"}"# {
        "p2a"
    } else {
        "p2b"
    };
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.position.as_deref(), Some(winner));
    assert_eq!(hook.last_sequence, 2);
    let pending = store
        .pending_mail_events(&account.id, 10)
        .await
        .unwrap()
        .events;
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[1].id, stored[0].id);

    // The next pass reads the winner's position and goes on from there.
    let next = store
        .append_mail_event(&account.id, r#"{"n":4}"#, Some(advance(Some(winner), "p3")))
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert_eq!(next.sequence, 3);
}

async fn exercise_conditional_token_writes(store: &Store) {
    let account = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: &unique("refresh-race"),
                email: &format!("{}@example.com", unique("refresh-race")),
            },
            &tokens("refresh-1"),
        )
        .await
        .unwrap();
    let original = store
        .upstream_tokens(&account.id)
        .await
        .unwrap()
        .unwrap()
        .tokens
        .refresh_token;
    assert!(
        store
            .save_upstream_tokens_if_current(&account.id, &original, &tokens("refresh-2"))
            .await
            .unwrap()
    );
    let current = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert_eq!(current.tokens.refresh_token.expose_secret(), "refresh-2");

    assert!(
        !store
            .save_upstream_tokens_if_current(&account.id, &original, &tokens("refresh-stale"))
            .await
            .unwrap()
    );
    assert!(
        !store
            .mark_upstream_tokens_invalid_if_current(&account.id, &original, "invalid_grant")
            .await
            .unwrap()
    );
    let kept = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert_eq!(kept.tokens.refresh_token.expose_secret(), "refresh-2");
    assert!(kept.invalid_reason.is_none());
    assert!(kept.tokens.access_token.is_some());

    let current_refresh = kept.tokens.refresh_token;
    assert!(
        store
            .mark_upstream_tokens_invalid_if_current(
                &account.id,
                &current_refresh,
                "invalid_grant",
            )
            .await
            .unwrap()
    );
    let invalid = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert_eq!(invalid.invalid_reason.as_deref(), Some("invalid_grant"));
    assert!(invalid.tokens.access_token.is_none());
    assert_eq!(invalid.tokens.refresh_token.expose_secret(), "refresh-2");

    // Signing in again still replaces the row unconditionally.
    store
        .save_upstream_tokens(&account.id, &tokens("refresh-3"))
        .await
        .unwrap();
    let signed_in = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert!(signed_in.invalid_reason.is_none());
    assert_eq!(signed_in.tokens.refresh_token.expose_secret(), "refresh-3");
}

#[tokio::test]
async fn sqlite_oauth_accounts() {
    let (store, _dir, _) = sqlite().await;
    exercise_oauth_accounts(&store).await;
}

#[tokio::test]
async fn sqlite_conditional_token_writes() {
    let (store, _dir, _) = sqlite().await;
    exercise_conditional_token_writes(&store).await;
}

#[tokio::test]
async fn sqlite_upstream_requests() {
    let (store, _dir, _) = sqlite().await;
    exercise_upstream_requests(&store).await;
}

#[tokio::test]
async fn sqlite_push() {
    let (store, _dir, _) = sqlite().await;
    exercise_push(&store).await;
}

#[tokio::test]
async fn sqlite_events() {
    let (store, _dir, _) = sqlite().await;
    exercise_events(&store).await;
}

#[tokio::test]
async fn sqlite_position_compare_and_set() {
    let (store, _dir, _) = sqlite().await;
    exercise_position_compare_and_set(&store).await;
}

/// Awaits `write` while another connection holds the write lock, which it
/// releases after 300 ms, and checks that `write` succeeded only after that.
async fn while_another_writer_holds<T: Send>(
    store: &Store,
    write: impl Future<Output = Result<T, StoreError>> + Send,
) -> T {
    let hold = Duration::from_millis(300);
    #[expect(clippy::disallowed_methods, reason = "the other writer")]
    let other = store.pool().begin_with("BEGIN IMMEDIATE").await.unwrap();
    let started = Instant::now();
    let release = tokio::spawn(async move {
        tokio::time::sleep(hold).await;
        other.commit().await.unwrap();
    });
    let written = write.await;
    let waited = started.elapsed();
    release.await.unwrap();
    let written = written.unwrap();
    assert!(waited >= hold, "the write did not wait: {waited:?}");
    written
}

/// Builds, and never runs, each way to begin a transaction that `clippy.toml`
/// refuses. Clippy only warns about a refused path that no longer resolves,
/// as after an sqlx upgrade that moves a method, and `-D warnings` lets that
/// pass. The expectation on the path's line here then goes unfulfilled, which
/// fails the lint job.
#[expect(dead_code, reason = "only clippy reads it")]
fn refused_begins(pool: &sqlx::AnyPool, conn: &mut sqlx::AnyConnection) {
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(pool.begin());
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(pool.try_begin());
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(pool.begin_with("BEGIN"));
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(pool.try_begin_with("BEGIN"));
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(sqlx::Acquire::begin(&mut *conn));
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(sqlx::Connection::begin(&mut *conn));
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(sqlx::Connection::begin_with(&mut *conn, "BEGIN"));
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(sqlx::Connection::transaction(&mut *conn, |_tx| {
        Box::pin(async { Ok::<(), sqlx::Error>(()) })
    }));
    #[expect(clippy::disallowed_methods, reason = "built, never run")]
    drop(sqlx::Transaction::<sqlx::Any>::begin(&mut *conn, None));
}

/// A sign-in and a token write, which read before they write, wait for
/// another connection's write lock instead of failing with "database is
/// locked": SQLite gives a transaction that has read no busy timeout when it
/// then writes.
#[tokio::test]
async fn sqlite_a_write_waits_for_another_writer() {
    let (store, _dir, _) = sqlite().await;
    let account = OAuthAccount {
        provider: Provider::Graph,
        subject: "subject",
        email: "user@outlook.com",
    };
    // The first sign-in also makes the tenant's data key, outside its
    // transaction, where a write waits anyway.
    let signed_in = store
        .upsert_oauth_account(&account, &tokens("refresh-1"))
        .await
        .unwrap();
    let again = while_another_writer_holds(
        &store,
        store.upsert_oauth_account(&account, &tokens("refresh-2")),
    )
    .await;
    assert_eq!(again.id, signed_in.id);
    while_another_writer_holds(
        &store,
        store.save_upstream_tokens(&signed_in.id, &tokens("refresh-3")),
    )
    .await;
    let stored = store.upstream_tokens(&signed_in.id).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh-3");
}

#[tokio::test]
async fn a_stale_cursor_appends_nothing() {
    let (store, _dir, _) = sqlite().await;
    let account = store
        .upsert_account(
            &format!("{}@example.com", unique("stale-cursor")),
            &secret("pw"),
        )
        .await
        .unwrap();
    let expected = WatchCursor {
        uid_validity: 7,
        last_uid: 1,
    };
    let advance = |last_uid| WatchAdvance::Cursor {
        expected,
        next: WatchCursor {
            uid_validity: 7,
            last_uid,
        },
    };
    // No webhook row, so the claim is not a stale cursor.
    assert!(matches!(
        store
            .append_mail_event(&account.id, r#"{"n":"no-hook"}"#, Some(advance(2)))
            .await
            .unwrap(),
        AppendOutcome::NoWebhook
    ));

    store
        .save_webhook(&account.id, &settings("https://hooks.example/h"))
        .await
        .unwrap();
    // The cursor columns are still null. The compare fails and writes nothing.
    assert!(matches!(
        store
            .append_mail_event(&account.id, r#"{"n":"null-cursor"}"#, Some(advance(2)))
            .await
            .unwrap(),
        AppendOutcome::StaleCursor
    ));
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.last_sequence, 0);
    assert_eq!(hook.cursor, None);
    assert_eq!(
        store
            .pending_mail_events(&account.id, 10)
            .await
            .unwrap()
            .events,
        []
    );

    store.set_watch_cursor(&account.id, expected).await.unwrap();
    let stored = store
        .append_mail_event(&account.id, r#"{"n":"claimed"}"#, Some(advance(42)))
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert_eq!(stored.sequence, 1);

    assert!(matches!(
        store
            .append_mail_event(&account.id, r#"{"n":"stale"}"#, Some(advance(99)))
            .await
            .unwrap(),
        AppendOutcome::StaleCursor
    ));
    assert!(matches!(
        store
            .append_mail_event(
                &account.id,
                r#"{"n":"wrong-validity"}"#,
                Some(WatchAdvance::Cursor {
                    expected: WatchCursor {
                        uid_validity: 8,
                        last_uid: 42,
                    },
                    next: WatchCursor {
                        uid_validity: 8,
                        last_uid: 50,
                    },
                }),
            )
            .await
            .unwrap(),
        AppendOutcome::StaleCursor
    ));

    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.last_sequence, 1);
    assert_eq!(
        hook.cursor,
        Some(WatchCursor {
            uid_validity: 7,
            last_uid: 42,
        })
    );
    let pending = store
        .pending_mail_events(&account.id, 10)
        .await
        .unwrap()
        .events;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].payload, r#"{"n":"claimed"}"#);
    assert_eq!(pending[0].id, stored.id);

    // The rejected claims did not consume a sequence number.
    let later = store
        .append_mail_event(&account.id, r#"{"n":"later"}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    assert_eq!(later.sequence, 2);
    let hook = store.webhook(&account.id).await.unwrap().unwrap();
    assert_eq!(hook.cursor.unwrap().last_uid, 42);
    assert_eq!(hook.last_sequence, 2);
}

#[tokio::test]
async fn rotation_covers_tokens_and_events() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("test.db").display());
    let old = KnownKey::new(0x21);
    let store = Store::connect(&url, &old.master()).await.unwrap();
    let account = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Gmail,
                subject: "sub-1",
                email: "a@gmail.com",
            },
            &tokens("refresh"),
        )
        .await
        .unwrap();
    store
        .save_webhook(&account.id, &settings("https://a.example/h"))
        .await
        .unwrap();
    let event = store
        .append_mail_event(&account.id, "{}", None)
        .await
        .unwrap()
        .stored()
        .unwrap();
    store
        .save_upstream_request(
            "state",
            &UpstreamRequest {
                provider: Provider::Gmail,
                purpose: UpstreamPurpose::Authorize {
                    request_id: secret("request"),
                },
                code_verifier: secret("verifier"),
                binding_hash: "b".to_owned(),
            },
            Duration::from_mins(10),
        )
        .await
        .unwrap();
    store
        .save_upstream_request(
            "continued",
            &UpstreamRequest {
                provider: Provider::Graph,
                purpose: UpstreamPurpose::Continue {
                    tenant: "acme".to_owned(),
                    continuation: secret("connect-1"),
                },
                code_verifier: secret("verifier"),
                binding_hash: "b".to_owned(),
            },
            Duration::from_mins(10),
        )
        .await
        .unwrap();
    // The sweep moves v1 values to a data key. These eight are sealed
    // here under the old key, so they are v1 whatever the writers store:
    // refresh and access token, webhook secret, event payload, both requests'
    // verifiers, a request ID and a continuation.
    let id = &account.id.0;
    let (state, continued) = (state_hash("state"), state_hash("continued"));
    REFRESH.put(&store, &old, id, id, "refresh").await;
    ACCESS.put(&store, &old, id, id, "access-1").await;
    SECRET.put(&store, &old, id, id, "whsec_one").await;
    let owner = format!("{id}/{}", event.id);
    PAYLOAD.put(&store, &old, &event.id, &owner, "{}").await;
    VERIFIER.put(&store, &old, &state, &state, "verifier").await;
    REQUEST_ID
        .put(&store, &old, &state, &state, "request")
        .await;
    VERIFIER
        .put(&store, &old, &continued, &continued, "verifier")
        .await;
    CONTINUATION
        .put(&store, &old, &continued, &continued, "connect-1")
        .await;
    store.close().await;

    let new = random_key();
    let store = Store::connect_rotating(&url, &new, &[old.master()])
        .await
        .unwrap();
    let report = store.reencrypt().await.unwrap();
    // The eight values; OAuth accounts have no password to move.
    assert_eq!((report.updated, report.unreadable), (8, 0));
    // They are under the keys of the default tenant and of `acme`, which the
    // old master key wrapped: the new key alone reads them once they are
    // wrapped again.
    assert_eq!(store.rewrap_data_keys().await.unwrap().rewrapped, 2);
    store.close().await;

    let store = Store::connect(&url, &new).await.unwrap();
    let stored = store.upstream_tokens(&account.id).await.unwrap().unwrap();
    assert_eq!(stored.tokens.refresh_token.expose_secret(), "refresh");
    assert_eq!(
        store
            .pending_mail_events(&account.id, 10)
            .await
            .unwrap()
            .events
            .len(),
        1
    );
    assert!(
        store
            .take_upstream_request("state")
            .await
            .unwrap()
            .is_some()
    );
    let continued = store
        .take_upstream_request("continued")
        .await
        .unwrap()
        .unwrap();
    let UpstreamPurpose::Continue { continuation, .. } = continued.purpose else {
        panic!("wrong purpose");
    };
    assert_eq!(continuation.expose_secret(), "connect-1");
}

/// The master key was lost and replaced, and no previous key is kept. What was
/// stored for a Microsoft or a Google account cannot be read, and neither a
/// refresh is written over it. Connecting the account again
/// replaces the tokens, under a data key that the new master key made, and they
/// read back.
#[tokio::test]
async fn sqlite_a_new_master_key_alone_takes_new_tokens() {
    for provider in [Provider::Graph, Provider::Gmail] {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("test.db").display());
        let store = Store::connect(&url, &key()).await.unwrap();
        let oauth = OAuthAccount {
            provider,
            subject: "lost-key-subject",
            email: "user@example.com",
        };
        let account = store
            .upsert_oauth_account(&oauth, &tokens("refresh-old"))
            .await
            .unwrap();
        let written = REFRESH.get(&store, &account.id.0).await;
        assert!(written.starts_with("v2.1."), "{written}");
        store.close().await;

        let store = Store::connect(&url, &random_key()).await.unwrap();
        let err = store.upstream_tokens(&account.id).await.unwrap_err();
        assert!(matches!(err, StoreError::Decrypt), "{err:?}");
        let old = secret("refresh-old");
        let lost = tokens("refresh-lost");
        let err = store.save_upstream_tokens_if_current(&account.id, &old, &lost);
        assert!(matches!(err.await.unwrap_err(), StoreError::Decrypt));
        assert_eq!(REFRESH.get(&store, &account.id.0).await, written);

        let again = store
            .upsert_oauth_account(&oauth, &tokens("refresh-new"))
            .await
            .unwrap();
        assert_eq!(again.id, account.id);
        let found = store.upstream_tokens(&account.id).await.unwrap().unwrap();
        assert_eq!(found.tokens.refresh_token.expose_secret(), "refresh-new");
        assert_eq!(
            found
                .tokens
                .access_token
                .as_ref()
                .map(ExposeSecret::expose_secret),
            Some("access-1")
        );
        assert!(found.invalid_reason.is_none());
        // Version 1 of the key stays; the new master key made version 2.
        let refresh = REFRESH.get(&store, &account.id.0).await;
        assert!(refresh.starts_with("v2.2."), "{refresh}");
        store.close().await;
    }
}

/// The master key was lost and replaced, and no previous key is kept; a
/// Microsoft or a Google account had connected. Its sign-ins in progress cannot
/// be opened: taking one removes it and says so, and reading makes no data key.
/// New sign-ins of all three purposes are saved and taken under the new key
/// alone, under version 2 of the key of their tenant, which the new master key
/// made. Connecting the account again replaces its tokens.
#[tokio::test]
async fn sqlite_a_new_master_key_alone_takes_new_sign_ins() {
    let continued = || UpstreamPurpose::Continue {
        tenant: "acme".to_owned(),
        continuation: secret("connect-1"),
    };
    let authorize = || UpstreamPurpose::Authorize {
        request_id: secret("request-1"),
    };
    let purposes = [
        ("authorize", authorize as fn() -> UpstreamPurpose),
        ("account", || UpstreamPurpose::Account),
        ("continue", continued),
    ];
    let keys = |store: Store| async move {
        let sql = "SELECT tenant, COUNT(*) FROM data_keys GROUP BY tenant ORDER BY tenant";
        sqlx::query_as::<_, (String, i64)>(sql)
            .fetch_all(store.pool())
            .await
            .unwrap()
    };
    let ttl = Duration::from_mins(10);

    for provider in [Provider::Graph, Provider::Gmail] {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("test.db").display());
        let request = |purpose| UpstreamRequest {
            provider,
            purpose,
            code_verifier: secret("verifier-1"),
            binding_hash: "binding".to_owned(),
        };
        let oauth = OAuthAccount {
            provider,
            subject: "lost-key-subject",
            email: "user@example.com",
        };

        let store = Store::connect(&url, &key()).await.unwrap();
        let account = store
            .upsert_oauth_account(&oauth, &tokens("refresh-old"))
            .await
            .unwrap();
        for (label, purpose) in &purposes {
            let state = format!("old-{label}");
            store
                .save_upstream_request(&state, &request(purpose()), ttl)
                .await
                .unwrap();
        }
        store.close().await;

        let store = Store::connect(&url, &random_key()).await.unwrap();
        for (label, _) in &purposes {
            let state = format!("old-{label}");
            let err = store.take_upstream_request(&state).await.unwrap_err();
            assert!(matches!(err, StoreError::Decrypt), "{label}: {err:?}");
            assert!(store.take_upstream_request(&state).await.unwrap().is_none());
        }
        let err = store.upstream_tokens(&account.id).await.unwrap_err();
        assert!(matches!(err, StoreError::Decrypt), "{err:?}");
        assert_eq!(
            keys(store.clone()).await,
            [("acme".to_owned(), 1), ("default".to_owned(), 1)]
        );
        for (label, purpose) in &purposes {
            let state = format!("new-{label}");
            store
                .save_upstream_request(&state, &request(purpose()), ttl)
                .await
                .unwrap();
            let written = VERIFIER.get(&store, &state_hash(&state)).await;
            assert!(written.starts_with("v2.2."), "{label}: {written}");
            let taken = store.take_upstream_request(&state).await.unwrap().unwrap();
            assert_eq!(taken.code_verifier.expose_secret(), "verifier-1", "{label}");
        }
        let again = store
            .upsert_oauth_account(&oauth, &tokens("refresh-new"))
            .await
            .unwrap();
        assert_eq!(again.id, account.id);
        let found = store.upstream_tokens(&account.id).await.unwrap().unwrap();
        assert_eq!(found.tokens.refresh_token.expose_secret(), "refresh-new");
        assert_eq!(
            keys(store.clone()).await,
            [("acme".to_owned(), 2), ("default".to_owned(), 2)]
        );
        store.close().await;
    }
}

#[tokio::test]
async fn unreadable_events_do_not_block_the_following_page() {
    let (store, _dir, _url) = sqlite().await;
    // Skipped at once, which is what this test is about: the hold is below.
    store.set_event_hold(Duration::ZERO);
    let account = store
        .upsert_account(&format!("{}@example.com", unique("gap")), &secret("pw"))
        .await
        .unwrap();
    store
        .save_webhook(&account.id, &settings("https://hooks.example/h"))
        .await
        .unwrap();
    let account_id = account.id.clone();

    // The leading page is text that no key opens, as if it were sealed under
    // a key the reader no longer has: one value in each format, the second
    // under a data key version that does not exist.
    for (n, unopenable) in [(1, unreadable()), (2, "v2.9.AAAA".to_owned())] {
        let event = store
            .append_mail_event(&account_id, &format!(r#"{{"n":{n}}}"#), None)
            .await
            .unwrap()
            .stored()
            .unwrap();
        PAYLOAD.set(&store, &event.id, &unopenable).await;
    }

    // The event after that page can be read.
    let later = store
        .append_mail_event(&account_id, r#"{"n":3}"#, None)
        .await
        .unwrap()
        .stored()
        .unwrap();

    let pending = store.pending_mail_events(&account_id, 2).await.unwrap();
    assert!(
        pending.events.is_empty(),
        "the unreadable page is not delivered"
    );
    assert_eq!(pending.skip_through, Some(2));
    let hook = store.webhook(&account_id).await.unwrap().unwrap();
    assert_eq!(hook.delivered_sequence, 0, "listing does not advance");

    store
        .mark_mail_events_delivered(&account_id, pending.skip_through.unwrap())
        .await
        .unwrap();
    let pending = store.pending_mail_events(&account_id, 2).await.unwrap();
    assert_eq!(pending.skip_through, None);
    assert_eq!(pending.events, [later]);
}

/// Sets the time an event was stored to `secs` ago.
async fn stored_ago(store: &Store, event: &MailEvent, secs: i64) {
    sqlx::query("UPDATE mail_events SET created_at = $1 WHERE id = $2")
        .bind(postkeep_store::now() - secs)
        .bind(&event.id)
        .execute(store.pool())
        .await
        .unwrap();
}

/// An event that cannot be opened ends the page while it is younger than the
/// hold: the events before it are returned, none after it is read, and nothing
/// moves the delivered position. Once it is as old as the hold it is skipped. A
/// newer format is never skipped for its age.
#[tokio::test]
async fn an_event_that_cannot_be_opened_is_held_then_skipped() {
    let (store, _dir, _url) = sqlite().await;
    assert_eq!(store.event_hold(), Duration::from_hours(1));
    let account = store
        .upsert_account(&format!("{}@example.com", unique("hold")), &secret("pw"))
        .await
        .unwrap();
    let id = &account.id;
    store
        .save_webhook(id, &settings("https://hooks.example/h"))
        .await
        .unwrap();
    let mut events = Vec::new();
    for n in 1..=5 {
        let payload = format!(r#"{{"n":{n}}}"#);
        let appended = store.append_mail_event(id, &payload, None).await.unwrap();
        events.push(appended.stored().unwrap());
    }
    // 2 cannot be opened by any key; 4 is in a format from a newer version.
    PAYLOAD.set(&store, &events[1].id, &unreadable()).await;
    PAYLOAD.set(&store, &events[3].id, "v3.AAAA").await;
    let page = || async {
        let page = store.pending_mail_events(id, 10).await.unwrap();
        (page.events, page.skip_through, page.held)
    };

    assert_eq!(page().await, (vec![events[0].clone()], None, Some(2)));
    store.mark_mail_events_delivered(id, 1).await.unwrap();
    // A quarter of the hour has passed, give or take a few seconds.
    stored_ago(&store, &events[1], 15 * 60).await;
    let left = store.pending_mail_events(id, 10).await.unwrap().held_for;
    assert!((2690..=2700).contains(&left.unwrap().as_secs()), "{left:?}");
    // As old as the hold: 2 is passed over and 3 goes out, but not 5.
    stored_ago(&store, &events[1], 60 * 60).await;
    assert_eq!(page().await, (vec![events[2].clone()], None, Some(4)));
    store.mark_mail_events_delivered(id, 3).await.unwrap();
    stored_ago(&store, &events[3], 400 * 24 * 60 * 60).await;
    assert_eq!(page().await, (vec![], None, Some(4)));
    let held = store.pending_mail_events(id, 10).await.unwrap();
    assert_eq!(held.held_for, None, "a newer format is held without an end");

    // With no hold an unreadable event is skipped, a fresh one too; a newer
    // format still is not. Every clone has the new hold.
    store.for_tenant("other").set_event_hold(Duration::ZERO);
    assert_eq!(store.event_hold(), Duration::ZERO);
    assert_eq!(page().await, (vec![], None, Some(4)));
    store.mark_mail_events_delivered(id, 5).await.unwrap();
    let fresh = store.append_mail_event(id, "{}", None).await.unwrap();
    let fresh = fresh.stored().unwrap();
    PAYLOAD.set(&store, &fresh.id, &unreadable()).await;
    assert_eq!(page().await, (vec![], Some(6), None));
    store.set_event_hold(Duration::from_hours(1));
    assert_eq!(page().await, (vec![], None, Some(6)));
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_providers() {
    let url = std::env::var("TEST_POSTGRES_URL").expect("set TEST_POSTGRES_URL");
    let store = Store::connect(&url, &key()).await.unwrap();
    exercise_oauth_accounts(&store).await;
    exercise_conditional_token_writes(&store).await;
    exercise_upstream_requests(&store).await;
    exercise_push(&store).await;
    exercise_events(&store).await;
    exercise_position_compare_and_set(&store).await;
}

#[tokio::test]
async fn pins_the_server_of_legacy_accounts() {
    let (store, _dir, _url) = sqlite().await;
    let legacy = store
        .upsert_account("old@icloud.com", &secret("abcdabcdabcdabcd"))
        .await
        .unwrap();
    let chosen = store
        .upsert_imap_account("new@fastmail.com", &secret("pw"), Some("fastmail"))
        .await
        .unwrap();
    assert_eq!(legacy.imap_server, None);
    assert_eq!(store.pin_imap_server("icloud").await.unwrap(), 1);
    assert_eq!(store.pin_imap_server("custom").await.unwrap(), 0);
    let server = |id| {
        let store = store.clone();
        async move { store.credentials(&id).await.unwrap().unwrap().imap_server }
    };
    assert_eq!(server(legacy.id).await.as_deref(), Some("icloud"));
    assert_eq!(server(chosen.id).await.as_deref(), Some("fastmail"));
}
