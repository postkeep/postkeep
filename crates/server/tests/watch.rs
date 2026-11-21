//! New-mail watcher tests. The IMAP tests run against GreenMail (ignored
//! by default; see CONTRIBUTING.md); each uses its own GreenMail user,
//! created by sending it mail, so tests don't see each other's messages.
//! The outbox tests need no mail server.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers should fail loudly"
)]

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep::watch::{WatchConfig, Watchers};
use postkeep_mail::{
    Credentials, EmailAddress, ImapSecurity, ImapServers, MailClient, MailConfig, OutgoingMessage,
    SendOptions, SmtpSecurity,
};
use postkeep_store::{
    AccountId, AppendOutcome, DeliveryRecord, MAX_CONSECUTIVE_FAILURES, MasterKey, Store,
    WebhookSettings,
};
use postkeep_webhook::sign;
use postkeep_webhook::testing::{Receiver, receiver};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

fn mail_config() -> MailConfig {
    let host = std::env::var("GREENMAIL_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let port = |name: &str, default: u16| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let mut mail = MailConfig::default();
    mail.imap.host.clone_from(&host);
    mail.imap.port = port("GREENMAIL_IMAP_PORT", 3143);
    mail.imap.security = ImapSecurity::Plaintext;
    mail.smtp.host = host;
    mail.smtp.port = port("GREENMAIL_SMTP_PORT", 3025);
    mail.smtp.security = SmtpSecurity::Plaintext;
    mail.timeout = Duration::from_secs(10);
    mail
}

/// Sends a message to `to` from a fixed sender.
async fn send(to: &str, subject: &str) {
    let password = SecretString::from("alicepass".to_owned());
    let alice = MailClient::new(
        mail_config(),
        Credentials::new("alice@example.com", &password).unwrap(),
    )
    .unwrap();
    let message = OutgoingMessage {
        to: vec![EmailAddress::new(to)],
        subject: subject.to_owned(),
        text_body: "hello".to_owned(),
        ..OutgoingMessage::default()
    };
    alice
        .send(
            &message,
            SendOptions {
                save_to_sent: false,
            },
        )
        .await
        .unwrap();
}

struct Setup {
    store: Store,
    account: AccountId,
    email: String,
    watchers: Watchers,
    receiver: Receiver,
    _dir: tempfile::TempDir,
}

/// A fresh GreenMail user with one existing message, a store holding its
/// account and an enabled webhook pointing at a local receiver.
async fn setup(include_sender: bool) -> Setup {
    let email = format!("w{}@example.com", uuid::Uuid::new_v4().simple());
    // GreenMail creates the user (password = address) on first delivery.
    send(&email, "old mail").await;

    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("watch.db").display());
    let store = Store::connect(
        &url,
        &MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap(),
    )
    .await
    .unwrap();
    let account = store
        .upsert_account(&email, &SecretString::from(email.clone()))
        .await
        .unwrap();
    let receiver = receiver(&[]).await;
    store
        .save_webhook(
            &account.id,
            &WebhookSettings {
                enabled: true,
                url: receiver.url("/hook"),
                auth_header: Some((
                    "authorization".to_owned(),
                    SecretString::from("Bearer t".to_owned()),
                )),
                signing: true,
                signing_secret: SecretString::from("whsec_test".to_owned()),
                include_sender,
            },
        )
        .await
        .unwrap();
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::custom_only("GreenMail", mail_config()),
        receiver.deliverer.clone(),
        WatchConfig {
            debounce: Duration::from_millis(1500),
            poll_interval: Duration::from_secs(1),
            retry_delays: vec![Duration::from_millis(50)],
            min_backoff: Duration::from_millis(200),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    );
    Setup {
        store,
        account: account.id,
        email,
        watchers,
        receiver,
        _dir: dir,
    }
}

/// Waits until the watcher has recorded its starting position.
async fn wait_until_watching(setup: &Setup) {
    for _ in 0..100 {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        if hook.cursor.is_some() {
            // Give IDLE a moment to start after EXAMINE.
            tokio::time::sleep(Duration::from_millis(300)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the watcher never started");
}

async fn next_event(receiver: &mut Receiver) -> postkeep_webhook::testing::Received {
    tokio::time::timeout(Duration::from_secs(20), receiver.requests.recv())
        .await
        .unwrap_or_else(|_| panic!("no webhook delivery within 20 s"))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn delivers_signed_events_for_new_mail_only() {
    let mut setup = setup(true).await;
    setup.watchers.refresh(&setup.account);
    wait_until_watching(&setup).await;
    assert_eq!(setup.watchers.running(), 1);

    let subject = format!("new-{}", uuid::Uuid::new_v4().simple());
    send(&setup.email, &subject).await;
    let got = next_event(&mut setup.receiver).await;
    let json = got.json();
    assert_eq!(json["event"], "new_mail");
    assert_eq!(json["account"], setup.email.as_str());
    assert_eq!(json["folder"], "INBOX");
    assert_eq!(json["subject"], subject.as_str());
    assert_eq!(
        json["count"], 1,
        "the existing message is not reported: {json}"
    );
    assert_eq!(json["from"], "alice@example.com");
    let (folder, uid, uid_validity) =
        postkeep::mailbox::id::parse_imap_id(json["id"].as_str().unwrap()).unwrap();
    assert_eq!(folder, "INBOX");
    assert_eq!(u64::from(uid), json["uid"].as_u64().unwrap());
    assert!(
        uid_validity.is_some(),
        "the event's id carries UIDVALIDITY: {json}"
    );
    assert!(json.get("test").is_none());
    assert_eq!(got.header("authorization"), Some("Bearer t"));
    let stamp: i64 = got.header("x-webhook-timestamp").unwrap().parse().unwrap();
    assert!(sign::verify(
        "whsec_test",
        stamp,
        &got.body,
        got.header("x-signature-256").unwrap(),
        stamp,
        300
    ));

    // A burst within the debounce window becomes one event.
    send(&setup.email, "burst one").await;
    send(&setup.email, "burst two").await;
    let mut total = 0;
    while total < 2 {
        let json = next_event(&mut setup.receiver).await.json();
        total += json["count"].as_u64().unwrap();
    }
    assert_eq!(total, 2);

    // The receiver sees a request before its outcome is stored.
    let mut hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    for _ in 0..50 {
        if setup
            .store
            .recent_deliveries(&setup.account)
            .await
            .unwrap()
            .len()
            >= 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    }
    assert!(hook.last_success_at.is_some());
    assert!(hook.last_error.is_none());

    // Disabling the webhook stops the watcher.
    let mut settings = hook.settings;
    settings.enabled = false;
    setup
        .store
        .save_webhook(&setup.account, &settings)
        .await
        .unwrap();
    setup.watchers.refresh(&setup.account);
    for _ in 0..50 {
        if setup.watchers.running() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(setup.watchers.running(), 0);
    setup.watchers.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn reports_mail_that_arrived_while_stopped_and_hides_the_sender() {
    let mut setup = setup(false).await;
    setup.watchers.refresh(&setup.account);
    wait_until_watching(&setup).await;
    setup.watchers.shutdown(Duration::from_secs(5)).await;
    assert_eq!(setup.watchers.running(), 0);

    // Mail arriving while no watcher runs is reported on the next start.
    send(&setup.email, "while stopped").await;
    let watchers = Watchers::new(
        setup.store.clone(),
        ImapServers::custom_only("GreenMail", mail_config()),
        setup.receiver.deliverer.clone(),
        WatchConfig::default(),
        CancellationToken::new(),
    );
    watchers.refresh(&setup.account);
    let json = next_event(&mut setup.receiver).await.json();
    assert_eq!(json["count"], 1);
    assert!(
        json.get("from").is_none() && json.get("subject").is_none(),
        "{json}"
    );
    watchers.shutdown(Duration::from_secs(5)).await;

    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    let secret = hook.settings.signing_secret;
    assert_eq!(secret.expose_secret(), "whsec_test");
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn failed_deliveries_are_recorded() {
    let mut setup = setup(false).await;
    setup.receiver.respond_with(&[500, 500]);
    setup.watchers.refresh(&setup.account);
    wait_until_watching(&setup).await;
    send(&setup.email, "will fail").await;
    // One attempt plus one retry.
    next_event(&mut setup.receiver).await;
    next_event(&mut setup.receiver).await;
    for _ in 0..50 {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        if hook.consecutive_failures == 1 {
            assert!(hook.last_error.unwrap().contains("HTTP 500"));
            setup.watchers.shutdown(Duration::from_secs(5)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the failure was not recorded");
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn accounts_off_the_allow_list_are_not_watched() {
    let setup = setup(true).await;
    let watchers = Watchers::new(
        setup.store.clone(),
        ImapServers::custom_only("GreenMail", mail_config()),
        setup.receiver.deliverer.clone(),
        WatchConfig {
            allowed_emails: Some(vec!["someone-else@example.com".to_owned()]),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    );
    watchers.start_all().await;
    for _ in 0..50 {
        if watchers.running() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(watchers.running(), 0, "the watcher should exit at once");
    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    assert!(hook.cursor.is_none(), "the mailbox was never opened");
    watchers.shutdown(Duration::from_secs(5)).await;
    setup.watchers.shutdown(Duration::from_secs(5)).await;
}

/// Deleting an IMAP account neither stops its watcher nor waits for it:
/// there is nothing to delete at the provider, and the watcher ends once
/// the account is gone. Needs no mail server.
#[tokio::test]
async fn deleting_an_imap_account_leaves_its_watcher_alone() {
    let setup = outbox_setup().await;
    // Accepts the session's connection and never greets it.
    let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut mail = mail_config();
    "127.0.0.1".clone_into(&mut mail.imap.host);
    mail.imap.port = silent.local_addr().unwrap().port();
    let watchers = Watchers::new(
        setup.store.clone(),
        ImapServers::custom_only("Silent", mail),
        setup.receiver.deliverer.clone(),
        WatchConfig::default(),
        CancellationToken::new(),
    );
    watchers.refresh(&setup.account);
    let connected = tokio::time::timeout(Duration::from_secs(10), silent.accept());
    let _session = connected.await.unwrap().unwrap();

    let started = std::time::Instant::now();
    watchers
        .unsubscribe_before_delete(&setup.account, Duration::from_secs(10))
        .await;
    let took = started.elapsed();
    assert!(took < Duration::from_secs(2), "{took:?}");
    assert_eq!(watchers.running(), 1);
    watchers.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn a_large_backlog_is_delivered_oldest_first_in_batches() {
    let mut setup = setup(true).await;
    setup.watchers.refresh(&setup.account);
    wait_until_watching(&setup).await;
    setup.watchers.shutdown(Duration::from_secs(5)).await;

    // 120 messages arrive while the watcher is stopped, after the cursor.
    for n in 1..=120 {
        send(&setup.email, &format!("backlog {n}")).await;
    }
    let watchers = Watchers::new(
        setup.store.clone(),
        ImapServers::custom_only("GreenMail", mail_config()),
        setup.receiver.deliverer.clone(),
        WatchConfig::default(),
        CancellationToken::new(),
    );
    watchers.refresh(&setup.account);

    let mut counts = Vec::new();
    let mut uids = Vec::new();
    let mut sequences = Vec::new();
    let mut subjects = Vec::new();
    for _ in 0..3 {
        let got = next_event(&mut setup.receiver).await;
        let json = got.json();
        counts.push(json["count"].as_u64().unwrap());
        uids.push(json["uid"].as_u64().unwrap());
        sequences.push(got.header("x-webhook-sequence").unwrap().to_owned());
        subjects.push(json["subject"].as_str().unwrap().to_owned());
    }
    assert_eq!(counts, vec![50, 50, 20]);
    assert!(uids[0] < uids[1] && uids[1] < uids[2], "{uids:?}");
    assert_eq!(sequences, vec!["1".to_owned(), "2".into(), "3".into()]);
    // Oldest first: each event describes the newest message of that chunk.
    assert_eq!(
        subjects,
        vec![
            "backlog 50".to_owned(),
            "backlog 100".to_owned(),
            "backlog 120".to_owned()
        ]
    );
    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    assert_eq!(hook.last_sequence, 3);
    assert_eq!(
        u64::from(hook.cursor.unwrap().last_uid),
        uids[2],
        "the cursor stops on the last delivered UID"
    );
    let extra =
        tokio::time::timeout(Duration::from_millis(500), setup.receiver.requests.recv()).await;
    assert!(extra.is_err(), "unexpected extra event: {extra:?}");
    watchers.shutdown(Duration::from_secs(5)).await;
}

/// A store with an account whose webhook points at a local receiver, and
/// watchers with short delays. Needs no mail server.
async fn outbox_setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("outbox.db").display());
    let store = Store::connect(
        &url,
        &MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap(),
    )
    .await
    .unwrap();
    let email = "outbox@example.com".to_owned();
    let account = store
        .upsert_account(&email, &SecretString::from("password".to_owned()))
        .await
        .unwrap();
    let receiver = receiver(&[]).await;
    store
        .save_webhook(
            &account.id,
            &WebhookSettings {
                enabled: true,
                url: receiver.url("/hook"),
                auth_header: None,
                signing: true,
                signing_secret: SecretString::from("whsec_test".to_owned()),
                include_sender: true,
            },
        )
        .await
        .unwrap();
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::custom_only("Unused", mail_config()),
        receiver.deliverer.clone(),
        WatchConfig {
            retry_delays: vec![Duration::from_millis(20)],
            outbox_min_backoff: Duration::from_millis(200),
            outbox_max_backoff: Duration::from_millis(400),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    );
    Setup {
        store,
        account: account.id,
        email,
        watchers,
        receiver,
        _dir: dir,
    }
}

fn event(email: &str, id: &str) -> postkeep_webhook::NewMailEvent {
    postkeep_webhook::NewMailEvent {
        event: postkeep_webhook::NEW_MAIL,
        test: false,
        account: email.to_owned(),
        folder: "INBOX".to_owned(),
        id: id.to_owned(),
        uid: None,
        message_id: None,
        from: None,
        from_unclear: false,
        subject: None,
        date: None,
        count: 1,
    }
}

#[tokio::test]
async fn unaccepted_events_are_kept_and_sent_again_in_order() {
    let mut setup = outbox_setup().await;
    // The first event fails its attempt and its retry.
    setup.receiver.respond_with(&[500, 500]);
    assert!(matches!(
        setup
            .watchers
            .publish(&setup.account, &event(&setup.email, "graph.A"), None)
            .await
            .unwrap(),
        AppendOutcome::Stored(_)
    ));
    assert!(matches!(
        setup
            .watchers
            .publish(&setup.account, &event(&setup.email, "graph.B"), None)
            .await
            .unwrap(),
        AppendOutcome::Stored(_)
    ));
    let mut seen = Vec::new();
    for _ in 0..4 {
        let got = next_event(&mut setup.receiver).await;
        let stamp: i64 = got.header("x-webhook-timestamp").unwrap().parse().unwrap();
        assert!(sign::verify(
            "whsec_test",
            stamp,
            &got.body,
            got.header("x-signature-256").unwrap(),
            stamp,
            300
        ));
        seen.push((
            got.json()["id"].as_str().unwrap().to_owned(),
            got.header("x-webhook-sequence").unwrap().to_owned(),
            got.header("x-webhook-id").unwrap().to_owned(),
        ));
    }
    let ids: Vec<(&str, &str)> = seen
        .iter()
        .map(|(id, sequence, _)| (id.as_str(), sequence.as_str()))
        .collect();
    assert_eq!(
        ids,
        [
            ("graph.A", "1"),
            ("graph.A", "1"),
            ("graph.A", "1"),
            ("graph.B", "2")
        ]
    );
    // The same event keeps its delivery id across attempts.
    assert_eq!(seen[0].2, seen[2].2);
    assert_ne!(seen[2].2, seen[3].2);
    for _ in 0..50 {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        if hook.delivered_sequence == 2 && setup.watchers.pumps() == 0 {
            assert_eq!(hook.consecutive_failures, 0);
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the events were not marked delivered");
}

fn paused_watchers(setup: &Setup, interval: Duration) -> Watchers {
    Watchers::new(
        setup.store.clone(),
        ImapServers::custom_only("Unused", mail_config()),
        setup.receiver.deliverer.clone(),
        WatchConfig {
            retry_delays: Vec::new(),
            outbox_min_backoff: Duration::from_millis(15),
            outbox_max_backoff: Duration::from_millis(30),
            webhook_retry_interval: interval,
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    )
}

async fn wait_until_paused(store: &Store, account: &AccountId) {
    for _ in 0..100 {
        let hook = store.webhook(account).await.unwrap().unwrap();
        if hook.is_paused() {
            assert!(hook.settings.enabled);
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the webhook was not paused");
}

/// Ten failures pause the webhook. The watcher path (`publish`) keeps
/// recording, but new events do not each cause a delivery. After the
/// interval the oldest event is tried again; a success clears the pause
/// and the backlog follows in order, with the original ids and sequences.
#[tokio::test]
async fn a_paused_webhook_retries_on_the_interval_and_then_drains() {
    let mut setup = outbox_setup().await;
    let interval = Duration::from_millis(500);
    let watchers = paused_watchers(&setup, interval);
    setup.receiver.respond_with(&[500_u16; 10]);
    let stored = watchers
        .publish(&setup.account, &event(&setup.email, "A"), None)
        .await
        .unwrap();
    let AppendOutcome::Stored(first) = stored else {
        panic!("event A was not stored");
    };

    let mut attempts = Vec::new();
    for _ in 0..10 {
        attempts.push(next_event(&mut setup.receiver).await);
    }
    let delivery_id = attempts[0].header("x-webhook-id").unwrap().to_owned();
    for attempt in &attempts {
        assert_eq!(attempt.header("x-webhook-id"), Some(delivery_id.as_str()));
        assert_eq!(attempt.header("x-webhook-sequence"), Some("1"));
        assert_eq!(attempt.json()["id"], "A");
    }
    wait_until_paused(&setup.store, &setup.account).await;

    watchers
        .publish(&setup.account, &event(&setup.email, "B"), None)
        .await
        .unwrap();
    watchers
        .publish(&setup.account, &event(&setup.email, "C"), None)
        .await
        .unwrap();
    let early =
        tokio::time::timeout(Duration::from_millis(200), setup.receiver.requests.recv()).await;
    assert!(early.is_err(), "retried before the interval: {early:?}");

    let recovered = next_event(&mut setup.receiver).await;
    assert_eq!(recovered.header("x-webhook-id"), Some(first.id.as_str()));
    assert_eq!(recovered.header("x-webhook-id"), Some(delivery_id.as_str()));
    assert_eq!(recovered.header("x-webhook-sequence"), Some("1"));
    assert_eq!(recovered.json()["id"], "A");
    let second = next_event(&mut setup.receiver).await;
    let third = next_event(&mut setup.receiver).await;
    assert_eq!(second.json()["id"], "B");
    assert_eq!(second.header("x-webhook-sequence"), Some("2"));
    assert_eq!(third.json()["id"], "C");
    assert_eq!(third.header("x-webhook-sequence"), Some("3"));

    for _ in 0..50 {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        if hook.delivered_sequence == 3
            && hook.paused_at.is_none()
            && hook.consecutive_failures == 0
        {
            assert!(hook.settings.enabled);
            assert!(hook.last_sequence >= 3);
            assert!(
                setup
                    .store
                    .enabled_webhooks()
                    .await
                    .unwrap()
                    .contains(&setup.account)
            );
            watchers.shutdown(Duration::from_secs(2)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the paused webhook did not recover");
}

/// `refresh` tries once without waiting out the rest of the pause interval.
/// A restart, saving the settings, turning the webhook back on, a
/// successful test, or signing in again all refresh.
#[tokio::test]
async fn refreshing_a_paused_webhook_retries_promptly() {
    let mut setup = outbox_setup().await;
    let interval = Duration::from_secs(3);
    let watchers = paused_watchers(&setup, interval);
    setup.receiver.respond_with(&[500_u16; 10]);
    watchers
        .publish(&setup.account, &event(&setup.email, "A"), None)
        .await
        .unwrap();
    for _ in 0..10 {
        let _ = next_event(&mut setup.receiver).await;
    }
    wait_until_paused(&setup.store, &setup.account).await;

    let started = std::time::Instant::now();
    watchers.refresh(&setup.account);
    let got = tokio::time::timeout(Duration::from_secs(1), setup.receiver.requests.recv())
        .await
        .expect("no prompt retry")
        .unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "waited {:?}, longer than a prompt retry",
        started.elapsed()
    );
    assert!(started.elapsed() < interval);
    assert_eq!(got.header("x-webhook-sequence"), Some("1"));
    assert_eq!(got.json()["id"], "A");
    watchers.shutdown(Duration::from_secs(2)).await;
}

/// The first event in a paused batch recovers the webhook. The next event's
/// failure must use the short delay, not the pause interval loaded with the
/// batch.
#[tokio::test]
async fn a_recovered_batch_does_not_keep_the_pause_after_one_failure() {
    let mut setup = outbox_setup().await;
    let interval = Duration::from_secs(30);
    let watchers = paused_watchers(&setup, interval);
    let failure = DeliveryRecord {
        created_at: postkeep_store::now(),
        test: false,
        succeeded: false,
        summary: "HTTP 500".to_owned(),
        elapsed_ms: None,
    };
    for _ in 0..MAX_CONSECUTIVE_FAILURES {
        setup
            .store
            .record_delivery(&setup.account, &failure)
            .await
            .unwrap();
    }
    assert!(
        setup
            .store
            .webhook(&setup.account)
            .await
            .unwrap()
            .unwrap()
            .is_paused()
    );
    for id in ["A", "B"] {
        let payload = String::from_utf8(event(&setup.email, id).to_body()).unwrap();
        setup
            .store
            .append_mail_event(&setup.account, &payload, None)
            .await
            .unwrap();
    }
    // Success, then failure, then the short-backoff retry of the failure.
    setup.receiver.respond_with(&[200, 500, 200]);
    let started = std::time::Instant::now();
    watchers.wake_prompt(&setup.account);
    let mut seen = Vec::new();
    for _ in 0..3 {
        let got = tokio::time::timeout(Duration::from_secs(2), setup.receiver.requests.recv())
            .await
            .unwrap_or_else(|_| panic!("delivery waited out the pause interval"))
            .unwrap();
        seen.push(got.json()["id"].as_str().unwrap().to_owned());
    }
    assert!(
        started.elapsed() < interval,
        "the failure after recovery waited {:?}, the pause interval",
        started.elapsed()
    );
    assert_eq!(seen, ["A", "B", "B"]);
    let mut recovered = false;
    for _ in 0..50 {
        let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
        if hook.delivered_sequence == 2
            && hook.paused_at.is_none()
            && hook.consecutive_failures == 0
        {
            assert!(hook.settings.enabled);
            recovered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        recovered,
        "the batch did not recover and then deliver both events"
    );
    watchers.shutdown(Duration::from_secs(2)).await;
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

/// A webhook the user turned off is not delivered and does not recover.
#[tokio::test]
async fn a_user_disabled_webhook_gets_no_deliveries() {
    let mut setup = outbox_setup().await;
    let mut settings = setup
        .store
        .webhook(&setup.account)
        .await
        .unwrap()
        .unwrap()
        .settings;
    settings.enabled = false;
    setup
        .store
        .save_webhook(&setup.account, &settings)
        .await
        .unwrap();
    setup.watchers.refresh(&setup.account);
    assert!(matches!(
        setup
            .watchers
            .publish(&setup.account, &event(&setup.email, "A"), None)
            .await
            .unwrap(),
        AppendOutcome::Stored(_)
    ));
    let early =
        tokio::time::timeout(Duration::from_millis(400), setup.receiver.requests.recv()).await;
    assert!(early.is_err(), "a disabled webhook delivered: {early:?}");
    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);
    assert!(hook.paused_at.is_none());
    assert_eq!(hook.delivered_sequence, 0);
    assert!(hook.last_sequence >= 1);
    assert!(
        !setup
            .store
            .enabled_webhooks()
            .await
            .unwrap()
            .contains(&setup.account)
    );
    setup.watchers.shutdown(Duration::from_secs(2)).await;
}

#[tokio::test]
async fn accounts_without_a_webhook_record_nothing() {
    let setup = outbox_setup().await;
    setup.store.delete_webhook(&setup.account).await.unwrap();
    assert!(matches!(
        setup
            .watchers
            .publish(&setup.account, &event(&setup.email, "graph.A"), None)
            .await
            .unwrap(),
        AppendOutcome::NoWebhook
    ));
    assert_eq!(setup.watchers.pumps(), 0);
}

fn event_with_sender(email: &str, id: &str) -> postkeep_webhook::NewMailEvent {
    postkeep_webhook::NewMailEvent {
        from: Some("Ann <ann@example.com>".to_owned()),
        subject: Some("Lunch".to_owned()),
        ..event(email, id)
    }
}

fn watchers_for(setup: &Setup, allowed: Option<Vec<String>>) -> Watchers {
    Watchers::new(
        setup.store.clone(),
        ImapServers::custom_only("Unused", mail_config()),
        setup.receiver.deliverer.clone(),
        WatchConfig {
            allowed_emails: allowed,
            retry_delays: vec![Duration::from_millis(20)],
            outbox_min_backoff: Duration::from_millis(200),
            outbox_max_backoff: Duration::from_millis(400),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    )
}

fn assert_signed(got: &postkeep_webhook::testing::Received) {
    let stamp: i64 = got.header("x-webhook-timestamp").unwrap().parse().unwrap();
    assert!(sign::verify(
        "whsec_test",
        stamp,
        &got.body,
        got.header("x-signature-256").unwrap(),
        stamp,
        300
    ));
}

async fn wait_until_idle(watchers: &Watchers) {
    for _ in 0..50 {
        if watchers.pumps() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the pump did not finish");
}

#[tokio::test]
async fn queued_events_stay_pending_when_the_account_is_not_allowed() {
    let mut setup = outbox_setup().await;
    let payload = String::from_utf8(event(&setup.email, "graph.held").to_body()).unwrap();
    setup
        .store
        .append_mail_event(&setup.account, &payload, None)
        .await
        .unwrap();
    let watchers = watchers_for(&setup, Some(vec!["someone-else@example.com".to_owned()]));
    watchers.start_all().await;
    // `wake` inserts the pump before spawning it, so a second wake still
    // runs the allow-list check even if the first pass already finished.
    watchers.wake(&setup.account);
    for _ in 0..40 {
        if let Ok(got) = setup.receiver.requests.try_recv() {
            panic!(
                "a disallowed account's event was delivered: {}",
                String::from_utf8_lossy(&got.body)
            );
        }
        if watchers.pumps() == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if watchers.pumps() == 0 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(watchers.pumps(), 0);
    assert!(
        setup.receiver.requests.try_recv().is_err(),
        "a disallowed account's event was delivered"
    );
    let pending = setup
        .store
        .pending_mail_events(&setup.account, 10)
        .await
        .unwrap()
        .events;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].payload, payload);
    watchers.shutdown(Duration::from_secs(5)).await;
    setup.watchers.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn queued_events_for_an_allowed_account_are_still_delivered() {
    let mut setup = outbox_setup().await;
    let payload = String::from_utf8(event(&setup.email, "graph.ok").to_body()).unwrap();
    setup
        .store
        .append_mail_event(&setup.account, &payload, None)
        .await
        .unwrap();
    let watchers = watchers_for(&setup, Some(vec![setup.email.clone()]));
    watchers.start_all().await;
    let got = next_event(&mut setup.receiver).await;
    assert_eq!(got.json()["id"], "graph.ok");
    assert_signed(&got);
    watchers.shutdown(Duration::from_secs(5)).await;
    setup.watchers.shutdown(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn include_sender_is_applied_when_the_event_is_sent() {
    let mut setup = outbox_setup().await;
    let stored = event_with_sender(&setup.email, "graph.A").to_body();
    let payload = String::from_utf8(stored.clone()).unwrap();
    setup
        .store
        .append_mail_event(&setup.account, &payload, None)
        .await
        .unwrap();
    setup.watchers.wake(&setup.account);
    let got = next_event(&mut setup.receiver).await;
    assert_eq!(got.body, stored, "an opted-in event keeps its stored bytes");
    assert_eq!(got.json()["from"], "Ann <ann@example.com>");
    assert_eq!(got.json()["subject"], "Lunch");
    assert_signed(&got);
    wait_until_idle(&setup.watchers).await;

    let mut settings = setup
        .store
        .webhook(&setup.account)
        .await
        .unwrap()
        .unwrap()
        .settings;
    settings.include_sender = false;
    setup
        .store
        .save_webhook(&setup.account, &settings)
        .await
        .unwrap();
    let queued = event_with_sender(&setup.email, "graph.B").to_body();
    setup
        .store
        .append_mail_event(
            &setup.account,
            &String::from_utf8(queued.clone()).unwrap(),
            None,
        )
        .await
        .unwrap();
    setup.watchers.wake(&setup.account);
    let got = next_event(&mut setup.receiver).await;
    let json = got.json();
    assert_eq!(json["id"], "graph.B");
    assert!(json.get("from").is_none(), "{json}");
    assert!(json.get("subject").is_none(), "{json}");
    assert_ne!(got.body, queued);
    assert_signed(&got);
    wait_until_idle(&setup.watchers).await;
    let pending = setup
        .store
        .pending_mail_events(&setup.account, 10)
        .await
        .unwrap()
        .events;
    assert!(pending.is_empty(), "both events were delivered");
    setup.watchers.shutdown(Duration::from_secs(5)).await;
}

/// The pump loads 20 rows at a time. A full page that cannot be decrypted
/// must not look like an empty outbox, or the readable event after it waits
/// until those rows age out.
#[tokio::test]
async fn unreadable_outbox_rows_do_not_stall_later_events() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("outbox.db").display());
    let email = "outbox@example.com".to_owned();
    let mut receiver = receiver(&[]).await;
    let payload = |id: &str| String::from_utf8(event(&email, id).to_body()).unwrap();

    let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
    let store = Store::connect(&url, &key).await.unwrap();
    let account = store
        .upsert_account(&email, &SecretString::from("password".to_owned()))
        .await
        .unwrap();
    let account_id = account.id.clone();
    store
        .save_webhook(
            &account_id,
            &WebhookSettings {
                enabled: true,
                url: receiver.url("/hook"),
                auth_header: None,
                signing: true,
                signing_secret: SecretString::from("whsec_test".to_owned()),
                include_sender: true,
            },
        )
        .await
        .unwrap();
    store
        .append_mail_event(&account_id, &payload("first"), None)
        .await
        .unwrap();
    for n in 0..20 {
        store
            .append_mail_event(&account_id, &payload(&format!("gap-{n}")), None)
            .await
            .unwrap();
    }
    store
        .append_mail_event(&account_id, &payload("last"), None)
        .await
        .unwrap();
    // The 20 events between them, sequences 2 to 21, are text that no key
    // opens, as if they were sealed under a key this process no longer has, and
    // were stored two hours ago: past the hour they are held.
    let unreadable = format!("v1.{}", URL_SAFE_NO_PAD.encode([0x5a_u8; 40]));
    let replaced = sqlx::query(
        "UPDATE mail_events SET payload_ciphertext = $1, created_at = created_at - 7200 \
         WHERE account_id = $2 AND sequence BETWEEN 2 AND 21",
    )
    .bind(&unreadable)
    .bind(&account_id.0)
    .execute(store.pool())
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(replaced, 20);

    let watchers = Watchers::new(
        store.clone(),
        ImapServers::custom_only("Unused", mail_config()),
        receiver.deliverer.clone(),
        WatchConfig {
            retry_delays: vec![Duration::from_millis(20)],
            outbox_min_backoff: Duration::from_millis(200),
            outbox_max_backoff: Duration::from_millis(400),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    );
    watchers.wake(&account_id);
    let first = next_event(&mut receiver).await;
    let trailing = next_event(&mut receiver).await;
    assert_eq!(first.json()["id"], "first");
    assert_eq!(first.header("x-webhook-sequence"), Some("1"));
    assert_eq!(trailing.json()["id"], "last");
    assert_eq!(trailing.header("x-webhook-sequence"), Some("22"));
    assert_signed(&first);
    assert_signed(&trailing);
    wait_until_idle(&watchers).await;
    let hook = store.webhook(&account_id).await.unwrap().unwrap();
    assert_eq!(hook.delivered_sequence, 22);
    assert_eq!(hook.consecutive_failures, 0);
    assert!(receiver.requests.try_recv().is_err());
    watchers.shutdown(Duration::from_secs(2)).await;
}

/// Replaces the text in `(table, column, key)` of the row `row`, and returns the
/// text that was there.
async fn swap_text(store: &Store, column: (&str, &str, &str), row: &str, text: &str) -> String {
    let (table, name, key) = column;
    let read = format!("SELECT {name} FROM {table} WHERE {key} = $1");
    let old = sqlx::query_scalar(sqlx::AssertSqlSafe(read)).bind(row);
    let old: String = old.fetch_one(store.pool()).await.unwrap();
    let write = format!("UPDATE {table} SET {name} = $1 WHERE {key} = $2");
    let write = sqlx::query(sqlx::AssertSqlSafe(write)).bind(text).bind(row);
    write.execute(store.pool()).await.unwrap();
    old
}

/// Wakes the pump, and shows that in a second it sends nothing and keeps going.
async fn assert_held(setup: &mut Setup) {
    setup.watchers.wake(&setup.account);
    let sent = tokio::time::timeout(Duration::from_secs(1), setup.receiver.requests.recv());
    let sent = sent.await;
    assert!(sent.is_err(), "sent while a row cannot be read: {sent:?}");
    assert_eq!(setup.watchers.pumps(), 1, "the pump gave up");
    let pending = setup.store.pending_mail_event_count(&setup.account).await;
    assert_eq!(pending.unwrap(), 2, "an event was marked delivered");
}

/// The settings and the first event were written by a newer version. They are
/// held, not skipped: the pump keeps trying, marks nothing delivered and sends
/// nothing after them. Once they can be read, the events go out in order.
#[tokio::test]
async fn rows_in_a_newer_format_are_held_not_skipped() {
    let mut setup = outbox_setup().await;
    let (store, account) = (setup.store.clone(), setup.account.0.clone());
    let mut ids = Vec::new();
    for id in ["graph.A", "graph.B"] {
        let payload = String::from_utf8(event(&setup.email, id).to_body()).unwrap();
        let appended = store.append_mail_event(&setup.account, &payload, None);
        ids.push(appended.await.unwrap().stored().unwrap().id);
    }
    let secret = ("webhooks", "signing_secret_ciphertext", "account_id");
    let payload = ("mail_events", "payload_ciphertext", "id");
    let secret_text = swap_text(&store, secret, &account, "v3.AAAA").await;
    let payload_text = swap_text(&store, payload, &ids[0], "v3.AAAA").await;
    assert_held(&mut setup).await;
    // The settings read again, and now the event is what cannot be read.
    swap_text(&store, secret, &account, &secret_text).await;
    assert_held(&mut setup).await;

    swap_text(&store, payload, &ids[0], &payload_text).await;
    for id in ["graph.A", "graph.B"] {
        assert_eq!(next_event(&mut setup.receiver).await.json()["id"], id);
    }
    wait_until_idle(&setup.watchers).await;
    let hook = setup.store.webhook(&setup.account).await.unwrap().unwrap();
    assert_eq!(hook.delivered_sequence, 2);
    setup.watchers.shutdown(Duration::from_secs(5)).await;
}

/// An event that no key opens is held while it is younger than the hold, and so
/// are the events after it, but not the one before it. The pump records no
/// failure of the receiver and wakes when the hold ends, not at its next retry;
/// it then passes the event and sends the rest in order.
#[tokio::test]
async fn an_unreadable_event_is_held_then_passed_over() {
    let mut setup = outbox_setup().await;
    let (store, account) = (setup.store.clone(), setup.account.clone());
    // A pump that waits half a minute after a failure.
    let watchers = Watchers::new(
        store.clone(),
        ImapServers::custom_only("Unused", mail_config()),
        setup.receiver.deliverer.clone(),
        WatchConfig {
            outbox_min_backoff: Duration::from_secs(30),
            outbox_max_backoff: Duration::from_secs(30),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    );
    let mut ids = Vec::new();
    for id in ["graph.A", "graph.B", "graph.C"] {
        let payload = String::from_utf8(event(&setup.email, id).to_body()).unwrap();
        let appended = store.append_mail_event(&account, &payload, None);
        ids.push(appended.await.unwrap().stored().unwrap().id);
    }
    let text = format!("v1.{}", URL_SAFE_NO_PAD.encode([0x5a_u8; 40]));
    let payload = ("mail_events", "payload_ciphertext", "id");
    swap_text(&store, payload, &ids[1], &text).await;
    watchers.wake(&account);

    let first = next_event(&mut setup.receiver).await;
    assert_eq!(first.json()["id"], "graph.A");
    let sent = tokio::time::timeout(Duration::from_secs(1), setup.receiver.requests.recv());
    let sent = sent.await;
    assert!(sent.is_err(), "sent while held: {sent:?}");
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert_eq!((hook.delivered_sequence, hook.consecutive_failures), (1, 0));

    // The event is now 4 s short of the hold, and the pump would sleep half a
    // minute: it has to wake when the hold ends.
    let aged = sqlx::query("UPDATE mail_events SET created_at = $1 WHERE id = $2");
    let stored = postkeep_store::now() - 3600 + 4;
    aged.bind(stored)
        .bind(&ids[1])
        .execute(store.pool())
        .await
        .unwrap();
    watchers.wake_prompt(&account);
    let got = next_event(&mut setup.receiver).await;
    assert_eq!(got.json()["id"], "graph.C");
    assert_eq!(got.header("x-webhook-sequence"), Some("3"));
    wait_until_idle(&watchers).await;
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert_eq!((hook.delivered_sequence, hook.consecutive_failures), (3, 0));
    watchers.shutdown(Duration::from_secs(5)).await;
}

/// Settings sealed under a key this process does not have must not pin a
/// watcher or delivery pump in a retry loop.
#[tokio::test]
async fn unreadable_webhook_settings_do_not_keep_the_watcher_retrying() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}", dir.path().join("watch.db").display());
    let current = MasterKey::generate_encoded().unwrap();
    let lost = MasterKey::generate_encoded().unwrap();
    let parse = |encoded: &str| MasterKey::parse(encoded).unwrap();

    let store = Store::connect(&url, &parse(&lost)).await.unwrap();
    let account = store
        .upsert_account(
            "unreadable-hook@example.com",
            &SecretString::from("password".to_owned()),
        )
        .await
        .unwrap();
    let account_id = account.id.clone();
    store
        .save_webhook(
            &account_id,
            &WebhookSettings {
                enabled: true,
                url: "https://hooks.example/hook".to_owned(),
                auth_header: Some((
                    "authorization".to_owned(),
                    SecretString::from("Bearer secret".to_owned()),
                )),
                signing: true,
                signing_secret: SecretString::from("whsec_lost".to_owned()),
                include_sender: false,
            },
        )
        .await
        .unwrap();
    store.close().await;

    let store = Store::connect(&url, &parse(&current)).await.unwrap();
    let err = store.webhook(&account_id).await.unwrap_err();
    assert!(
        matches!(err, postkeep_store::StoreError::Decrypt),
        "{err:?}"
    );
    let mut receiver = receiver(&[]).await;
    let watchers = Watchers::new(
        store,
        ImapServers::custom_only("Unused", mail_config()),
        receiver.deliverer.clone(),
        WatchConfig {
            min_backoff: Duration::from_secs(30),
            max_backoff: Duration::from_secs(30),
            outbox_min_backoff: Duration::from_secs(30),
            outbox_max_backoff: Duration::from_secs(30),
            ..WatchConfig::default()
        },
        CancellationToken::new(),
    );
    watchers.refresh(&account_id);
    watchers.wake(&account_id);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        watchers.running(),
        0,
        "the watcher must not retry an unreadable webhook"
    );
    assert_eq!(
        watchers.pumps(),
        0,
        "the pump must not retry an unreadable webhook"
    );
    assert!(receiver.requests.try_recv().is_err());
    watchers.shutdown(Duration::from_secs(2)).await;
}
