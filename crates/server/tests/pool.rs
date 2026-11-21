//! IMAP pool tests against GreenMail (ignored by default; see CONTRIBUTING.md).

#![allow(clippy::unwrap_used, reason = "test helpers should fail loudly")]

use std::time::Duration;

use postkeep::pool::{Fingerprint, ImapPool, PoolConfig};
use postkeep_mail::{Credentials, ImapSecurity, MailClient, MailConfig};
use postkeep_store::AccountId;
use secrecy::SecretString;

fn client() -> MailClient {
    let mut mail = MailConfig::default();
    mail.imap.host = std::env::var("GREENMAIL_HOST").unwrap_or_else(|_| "127.0.0.1".to_owned());
    mail.imap.port = std::env::var("GREENMAIL_IMAP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3143);
    mail.imap.security = ImapSecurity::Plaintext;
    mail.timeout = Duration::from_secs(10);
    let password = SecretString::from("abcdabcdabcdabcd".to_owned());
    MailClient::new(
        mail,
        Credentials::new("bob@example.com", &password).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn reuses_sessions_only_for_the_same_account_and_credentials() {
    let pool = ImapPool::new(PoolConfig::default());
    let account = AccountId("bob".to_owned());
    let other = AccountId("eve".to_owned());
    let fingerprint = Fingerprint::new("custom", "bob@example.com", "abcdabcdabcdabcd");
    let client = client();

    let session = client.connect_imap().await.unwrap();
    pool.give_back(&account, fingerprint, session, true);
    assert_eq!(pool.idle_count(), 1);

    assert!(
        pool.take(&other, fingerprint).await.is_none(),
        "never crosses accounts"
    );
    let stale = Fingerprint::new("custom", "bob@example.com", "changed-password");
    assert!(
        pool.take(&account, stale).await.is_none(),
        "a changed password drops the session"
    );
    assert_eq!(pool.idle_count(), 0);

    let session = client.connect_imap().await.unwrap();
    pool.give_back(&account, fingerprint, session, true);
    let mut reused = pool.take(&account, fingerprint).await.unwrap();
    reused.list_folders().await.unwrap();

    // Sessions that failed mid-operation are not kept.
    pool.give_back(&account, fingerprint, reused, false);
    assert_eq!(pool.idle_count(), 0);
}

#[tokio::test]
#[ignore = "requires GreenMail"]
async fn expires_idle_sessions_and_respects_limits() {
    let pool = ImapPool::new(PoolConfig {
        idle_timeout: Duration::from_millis(200),
        per_account: 1,
        total: 10,
    });
    let account = AccountId("bob".to_owned());
    let fingerprint = Fingerprint::new("custom", "bob@example.com", "abcdabcdabcdabcd");
    let client = client();
    pool.give_back(
        &account,
        fingerprint,
        client.connect_imap().await.unwrap(),
        true,
    );
    pool.give_back(
        &account,
        fingerprint,
        client.connect_imap().await.unwrap(),
        true,
    );
    assert_eq!(pool.idle_count(), 1, "per-account limit");
    tokio::time::sleep(Duration::from_millis(300)).await;
    pool.reap();
    assert_eq!(pool.idle_count(), 0);
    assert!(pool.take(&account, fingerprint).await.is_none());

    let disabled = ImapPool::new(PoolConfig {
        idle_timeout: Duration::ZERO,
        ..PoolConfig::default()
    });
    disabled.give_back(
        &account,
        fingerprint,
        client.connect_imap().await.unwrap(),
        true,
    );
    assert_eq!(disabled.idle_count(), 0, "pooling disabled");
}
