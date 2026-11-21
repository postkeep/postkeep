//! A database written by version 0.1.0 (migrations 0001
//! to 0005). Every value below was produced with the 0.1.0 formats: the
//! ciphertexts use the key `[7; 32]`, the token rows store SHA-256 hashes.
//! After the upgrade the account, its password, its OAuth tokens and its
//! webhook (secrets and watch position) must all still work.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use std::fmt::Write as _;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use postkeep_store::{
    AccountId, CodeGrant, GrantSubject, MasterKey, Migrations, NewClient, OAuthAccount,
    PoolSettings, Provider, PushSubscription, Redemption, RefreshRotation, STORAGE_LEVEL_READS,
    STORAGE_LEVEL_WRITES, Store, StoreError, TokenGrant, UpstreamTokens, WatchCursor,
    WebhookSettings,
};
use secrecy::ExposeSecret;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::any::{AnyPoolOptions, install_default_drivers};

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
const PASSWORD: &str = "v1.AAECAwQFBgcICQoLeeOKFHxrui0W0Ib4gzoPnpoIGEwd-_0hdUaq2rZR4IQ";
const SIGNING_SECRET: &str = "v1.DA0ODxAREhMUFRYX1rOjCjNvJvaXzOR-pCzFmMU4pFa4kWR-ukEO9w";
const AUTH_VALUE: &str = "v1.GBkaGxwdHh8gISIjcy1ceBCbtRmhhpIIfSxM_LQ6azyVTuescZtypg4";
/// SHA-256 of `legacy-access-token` and `legacy-refresh-token`.
const ACCESS_HASH: &str = "EC8TcZqPhiKMTCrB8fpWYOBGMmkoG3XHPz8ODws4RAw";
const REFRESH_HASH: &str = "kqkb9j9C1P2ZkgqHWQJITL6vxMB74ijX_axTlo1-Aaw";

#[tokio::test]
async fn sqlite_upgrades_a_0_1_0_database() {
    exercise_0_1_0(Backend::Sqlite).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_upgrades_a_0_1_0_database() {
    exercise_0_1_0(Backend::Postgres).await;
}

/// The rows of an IMAP account and its webhook as 0.1.0 stored them, every secret
/// a `v1.` value under `KEY`. They are inserted before the store opens the
/// database, so they are in the default tenant, with no data key.
fn v1_rows() -> [String; 2] {
    [
        format!(
            "INSERT INTO accounts (id, email, password_ciphertext, created_at, updated_at) \
             VALUES ('acct-1', 'a@icloud.com', '{PASSWORD}', 1, 1)"
        ),
        format!(
            "INSERT INTO webhooks (account_id, enabled, url, auth_header_name, \
             auth_header_value_ciphertext, signing, signing_secret_ciphertext, include_sender, \
             consecutive_failures, uid_validity, last_uid, created_at, updated_at) \
             VALUES ('acct-1', 1, 'https://hooks.example.com/in', 'authorization', '{AUTH_VALUE}', \
             1, '{SIGNING_SECRET}', 1, 0, 7, 41, 1, 1)"
        ),
    ]
}

/// The three `v1.` values of `v1_rows`, in the database of `store`.
async fn v1_texts(store: &Store) -> Vec<String> {
    let sql = "SELECT password_ciphertext FROM accounts WHERE id = 'acct-1' UNION ALL \
               SELECT auth_header_value_ciphertext FROM webhooks WHERE account_id = 'acct-1' \
               UNION ALL SELECT signing_secret_ciphertext FROM webhooks WHERE account_id = 'acct-1'";
    sqlx::query_scalar(sql)
        .fetch_all(store.pool())
        .await
        .unwrap()
}

/// The sweep moves the three values of `v1_rows` to the default tenant's data
/// key, made if there is none, and they read as before. `others` already are v2.
async fn assert_swept(store: &Store, others: u64) {
    let [account, hook] = ["acct-1"; 2].map(|id| AccountId(id.to_owned()));
    let sweep = || async {
        let pass = tokio::time::timeout(Duration::from_secs(30), store.reencrypt());
        let pass = pass.await.map_err(|_| "the sweep does not end");
        pass.unwrap().unwrap()
    };
    assert!(
        v1_texts(store)
            .await
            .iter()
            .all(|text| text.starts_with("v1."))
    );
    let report = sweep().await;
    assert_eq!(
        (report.updated, report.already_v2, report.unreadable),
        (3, others, 0)
    );
    let texts = v1_texts(store).await;
    assert!(
        texts.iter().all(|text| text.starts_with("v2.1.")),
        "{texts:?}"
    );
    let credentials = store.credentials(&account).await.unwrap().unwrap();
    assert_eq!(credentials.password.expose_secret(), "abcdabcdabcdabcd");
    let hook = store.webhook(&hook).await.unwrap().unwrap();
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_legacy");
    let (_, value) = hook.settings.auth_header.unwrap();
    assert_eq!(value.expose_secret(), "Bearer legacy");
    assert_eq!(sweep().await.updated, 0);
}

async fn exercise_0_1_0(backend: Backend) {
    let db = Database::fresh(backend).await;
    db.migrate_through(&FIRST_FIVE).await;
    let url = db.url.clone();
    let pool = db.pool().await;
    let far = 4_000_000_000_i64;
    let [account_row, webhook_row] = v1_rows();
    for statement in [
        account_row,
        "INSERT INTO oauth_clients (id, secret_hash, name, redirect_uris, created_at, last_used_at) \
         VALUES ('client-1', NULL, 'Client', '[\"http://127.0.0.1:9/cb\"]', 1, 1)"
            .to_owned(),
        "INSERT INTO grants (id, client_id, account_id, scope, resource, created_at) \
         VALUES ('grant-1', 'client-1', 'acct-1', 'mail', NULL, 1)"
            .to_owned(),
        format!(
            "INSERT INTO access_tokens (token_hash, grant_id, expires_at) \
             VALUES ('{ACCESS_HASH}', 'grant-1', {far})"
        ),
        format!(
            "INSERT INTO refresh_tokens (token_hash, grant_id, expires_at) \
             VALUES ('{REFRESH_HASH}', 'grant-1', {far})"
        ),
        webhook_row,
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;

    let store = Store::connect(&url, &MasterKey::parse(KEY).unwrap())
        .await
        .unwrap();
    let account_id = AccountId("acct-1".to_owned());
    let account = store.account(&account_id).await.unwrap().unwrap();
    assert_eq!(account.provider, Provider::Imap);
    assert_eq!(account.imap_server, None, "the server default, as before");
    let credentials = store.credentials(&account_id).await.unwrap().unwrap();
    assert_eq!(credentials.password.expose_secret(), "abcdabcdabcdabcd");

    let grant = store
        .access_token("legacy-access-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(grant.subject, GrantSubject::Account(account_id.clone()));
    assert!(
        store
            .take_refresh_token("legacy-refresh-token", "client-1")
            .await
            .unwrap()
            .valid()
            .is_some()
    );

    let hook = store.webhook(&account_id).await.unwrap().unwrap();
    assert!(hook.settings.enabled);
    assert!(hook.paused_at.is_none(), "an enabled row is not paused");
    assert_eq!(hook.delivery_state(), "active");
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_legacy");
    let (name, value) = hook.settings.auth_header.unwrap();
    assert_eq!(
        (name.as_str(), value.expose_secret()),
        ("authorization", "Bearer legacy")
    );
    assert_eq!(
        hook.cursor,
        Some(WatchCursor {
            uid_validity: 7,
            last_uid: 41
        })
    );
    assert_eq!((hook.last_sequence, hook.delivered_sequence), (0, 0));
    assert!(hook.position.is_none());
    assert_swept(&store, 0).await;
    store.close().await;
    db.remove().await;
}

/// Migrations 0001 through `through`, applied to a fresh SQLite file.
async fn migrated_to(through: &[&str]) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let migrations = dir.path().join("migrations");
    std::fs::create_dir(&migrations).unwrap();
    for name in through {
        std::fs::copy(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("migrations")
                .join("sqlite")
                .join(name),
            migrations.join(name),
        )
        .unwrap();
    }
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("postkeep.db").display()
    );
    install_default_drivers();
    let pool = AnyPoolOptions::new().connect(&url).await.unwrap();
    sqlx::migrate::Migrator::new(migrations.as_path())
        .await
        .unwrap()
        .run(&pool)
        .await
        .unwrap();
    pool.close().await;
    (dir, url)
}

/// A database from just before pause existed: one webhook an older version
/// turned off after failures, and one the user turned off. Connecting runs
/// 0007. Only the failure row starts watching again, paused.
#[tokio::test]
async fn pauses_webhooks_an_older_version_disabled() {
    let (_dir, url) = migrated_to(&[
        "0001_initial.sql",
        "0002_client_activity.sql",
        "0003_account_sessions.sql",
        "0004_webhooks.sql",
        "0005_token_reuse.sql",
        "0006_providers.sql",
    ])
    .await;
    install_default_drivers();
    let pool = AnyPoolOptions::new().connect(&url).await.unwrap();
    let last_attempt_at = 1_700_000_000_i64;
    let updated_at = 1_650_000_000_i64;
    for statement in [
        format!(
            "INSERT INTO accounts (id, email, password_ciphertext, created_at, updated_at) \
             VALUES ('acct-1', 'user@example.com', '{PASSWORD}', 1, 1)"
        ),
        format!(
            "INSERT INTO accounts (id, email, password_ciphertext, created_at, updated_at) \
             VALUES ('acct-2', 'alice@example.com', '{PASSWORD}', 1, 1)"
        ),
        format!(
            "INSERT INTO webhooks (account_id, enabled, url, auth_header_name, \
             auth_header_value_ciphertext, signing, signing_secret_ciphertext, include_sender, \
             consecutive_failures, disabled_reason, last_attempt_at, last_error, \
             uid_validity, last_uid, created_at, updated_at) \
             VALUES ('acct-1', 0, 'https://hooks.example/in', 'authorization', '{AUTH_VALUE}', \
             1, '{SIGNING_SECRET}', 0, 10, 'Disabled after 10 failed deliveries in a row.', \
             {last_attempt_at}, 'HTTP 500', 9, 100, 1, {updated_at})"
        ),
        format!(
            "INSERT INTO webhooks (account_id, enabled, url, signing, signing_secret_ciphertext, \
             include_sender, consecutive_failures, disabled_reason, last_attempt_at, \
             uid_validity, last_uid, created_at, updated_at) \
             VALUES ('acct-2', 0, 'https://hooks.example/off', 1, '{SIGNING_SECRET}', \
             0, 2, NULL, {last_attempt_at}, 3, 4, 1, {updated_at})"
        ),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;

    let store = Store::connect(&url, &MasterKey::parse(KEY).unwrap())
        .await
        .unwrap();
    let failed = store
        .webhook(&postkeep_store::AccountId("acct-1".to_owned()))
        .await
        .unwrap()
        .unwrap();
    assert!(
        failed.settings.enabled,
        "failure-disabled rows start watching again"
    );
    assert_eq!(failed.paused_at, Some(last_attempt_at));
    assert!(failed.disabled_reason.is_none());
    assert!(failed.is_paused());
    assert_eq!(failed.consecutive_failures, 10);
    assert_eq!(
        failed.cursor,
        Some(WatchCursor {
            uid_validity: 9,
            last_uid: 100
        })
    );

    let pool = AnyPoolOptions::new().connect(&url).await.unwrap();
    let row = sqlx::query(
        "SELECT enabled, paused_at, disabled_reason, consecutive_failures, uid_validity, last_uid \
         FROM webhooks WHERE account_id = $1",
    )
    .bind("acct-2")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.try_get::<i64, _>("enabled").unwrap(), 0);
    assert!(
        row.try_get::<Option<i64>, _>("paused_at")
            .unwrap()
            .is_none()
    );
    assert!(
        row.try_get::<Option<String>, _>("disabled_reason")
            .unwrap()
            .is_none()
    );
    assert_eq!(row.try_get::<i64, _>("consecutive_failures").unwrap(), 2);
    assert_eq!(row.try_get::<i64, _>("uid_validity").unwrap(), 3);
    assert_eq!(row.try_get::<i64, _>("last_uid").unwrap(), 4);
}

/// A database from just before rules could be turned off. Connecting runs
/// 0016: the rule stored before it is on, and so is one added afterwards with
/// the column list of an earlier version.
#[tokio::test]
async fn filter_rules_from_before_0016_are_on() {
    let later = [
        "0009_tenant_scope.sql",
        "0010_external_principals.sql",
        "0011_upstream_continuation.sql",
        "0012_data_keys.sql",
        "0013_webhook_filter_rules.sql",
        "0014_storage_level.sql",
        "0015_password_rejected.sql",
    ];
    let (_dir, url) = migrated_to(&[&RELEASED[..], &later].concat()).await;
    let insert = |id: &str, seq: i64| {
        format!(
            "INSERT INTO webhook_filter_rules \
             (id, account_id, seq, added_at, action, field, kind, pattern_ciphertext) \
             VALUES ('{id}', 'acct-1', {seq}, 1, 'allow', 'subject', 'contains', 'x')"
        )
    };
    let pool = AnyPoolOptions::new().connect(&url).await.unwrap();
    for statement in [
        format!(
            "INSERT INTO accounts (id, email, password_ciphertext, created_at, updated_at) \
             VALUES ('acct-1', 'user@example.com', '{PASSWORD}', 1, 1)"
        ),
        insert("before", 1),
    ] {
        let run = sqlx::query(sqlx::AssertSqlSafe(statement));
        run.execute(&pool).await.unwrap();
    }
    pool.close().await;

    let store = Store::connect(&url, &MasterKey::parse(KEY).unwrap()).await;
    store.unwrap().close().await;
    let pool = AnyPoolOptions::new().connect(&url).await.unwrap();
    let after = sqlx::query(sqlx::AssertSqlSafe(insert("after", 2)));
    after.execute(&pool).await.unwrap();
    let enabled = "SELECT enabled FROM webhook_filter_rules ORDER BY seq";
    let enabled: Vec<i64> = sqlx::query_scalar(enabled).fetch_all(&pool).await.unwrap();
    assert_eq!(enabled, [1, 1]);
}

/// A database from just before outbox limits existed. Connecting adds the
/// nullable columns without changing the webhook or its events. NULL means
/// the server default, and a later limit change prunes that old queue.
#[tokio::test]
async fn adds_nullable_outbox_limits_to_an_older_database() {
    let (_dir, url) = migrated_to(&[
        "0001_initial.sql",
        "0002_client_activity.sql",
        "0003_account_sessions.sql",
        "0004_webhooks.sql",
        "0005_token_reuse.sql",
        "0006_providers.sql",
        "0007_webhook_pause.sql",
    ])
    .await;
    install_default_drivers();
    let pool = AnyPoolOptions::new().connect(&url).await.unwrap();
    for statement in [
        format!(
            "INSERT INTO accounts (id, email, password_ciphertext, created_at, updated_at) \
             VALUES ('acct-1', 'user@example.com', '{PASSWORD}', 1, 1)"
        ),
        format!(
            "INSERT INTO webhooks (account_id, enabled, url, signing, signing_secret_ciphertext, \
             include_sender, consecutive_failures, last_sequence, delivered_sequence, \
             uid_validity, last_uid, created_at, updated_at) \
             VALUES ('acct-1', 1, 'https://hooks.example/in', 1, '{SIGNING_SECRET}', \
             1, 0, 2, 0, 4, 8, 1, 1)"
        ),
        "INSERT INTO mail_events (id, account_id, sequence, payload_ciphertext, created_at) \
         VALUES ('evt-1', 'acct-1', 1, 'legacy-ciphertext', 4000000000)"
            .to_owned(),
        "INSERT INTO mail_events (id, account_id, sequence, payload_ciphertext, created_at) \
         VALUES ('evt-2', 'acct-1', 2, 'legacy-ciphertext', 4000000001)"
            .to_owned(),
    ] {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;

    let store = Store::connect(&url, &MasterKey::parse(KEY).unwrap())
        .await
        .unwrap();
    let account = postkeep_store::AccountId("acct-1".to_owned());
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_legacy");
    assert_eq!((hook.last_sequence, hook.delivered_sequence), (2, 0));
    assert_eq!(
        hook.cursor,
        Some(WatchCursor {
            uid_validity: 4,
            last_uid: 8
        })
    );
    assert_eq!(hook.outbox_retention_secs, None);
    assert_eq!(hook.outbox_max_events, None);
    assert_eq!(store.oldest_mail_event(&account).await.unwrap(), Some(1));

    let pool = AnyPoolOptions::new().connect(&url).await.unwrap();
    let row = sqlx::query(
        "SELECT outbox_retention_secs, outbox_max_events FROM webhooks WHERE account_id = $1",
    )
    .bind("acct-1")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        row.try_get::<Option<i64>, _>("outbox_retention_secs")
            .unwrap()
            .is_none()
    );
    assert!(
        row.try_get::<Option<i64>, _>("outbox_max_events")
            .unwrap()
            .is_none()
    );
    pool.close().await;

    let applied = store
        .set_webhook_outbox_limits(
            &account,
            postkeep_store::OutboxLimitChange::Keep,
            postkeep_store::OutboxLimitChange::Set(1),
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(applied.pruned, 1);
    assert_eq!(applied.limits.max_events, 1);
    assert!(!applied.limits.max_events_is_default);
    assert!(applied.limits.retention_is_default);
    assert_eq!(store.oldest_mail_event(&account).await.unwrap(), Some(2));
    let hook = store.webhook(&account).await.unwrap().unwrap();
    assert_eq!(hook.outbox_max_events, Some(1));
    assert_eq!(hook.outbox_retention_secs, None);
    assert_eq!((hook.last_sequence, hook.delivered_sequence), (2, 0));
    assert_eq!(hook.cursor.unwrap().last_uid, 8);
}

const FIRST_FIVE: [&str; 5] = [
    "0001_initial.sql",
    "0002_client_activity.sql",
    "0003_account_sessions.sql",
    "0004_webhooks.sql",
    "0005_token_reuse.sql",
];

/// The migrations of version 0.3.2.
const RELEASED: [&str; 8] = [
    "0001_initial.sql",
    "0002_client_activity.sql",
    "0003_account_sessions.sql",
    "0004_webhooks.sql",
    "0005_token_reuse.sql",
    "0006_providers.sql",
    "0007_webhook_pause.sql",
    "0008_webhook_outbox_limits.sql",
];

/// SHA-384 of each released migration, as 0.3.2 recorded it in
/// `_sqlx_migrations.checksum`. Changing a byte of 0001 to 0008 in either
/// folder would make every existing database refuse to start.
const RELEASED_CHECKSUMS: [&str; 8] = [
    "e3f1357c70cbf97ae0768987e78b36d0b3d13b4e6a7b06d6fe744972a15244fc507f956d6fbc33fbe885d0aed0983f6b",
    "245d5a562d0d63605e66701d9357bee0a54aac13fa0592a5bc0c6ca377f252d361a382cfdace363b3b4bd9a8d2567567",
    "a791ec597c15106aaf05bbb808df654fe1847328c610bbab9efb425b48aca6a1cb0c0142c0f4de6db4d8824040a5d771",
    "c38f6fa6e49f5de68a590015a757ef856caafefec327d7234e711141465572d3ca02e75d2cc626637b6891ed7df9e50c",
    "81e6f6853b3380218e44af02caa00cd57cdea761c6e4bb54a658a7f5cbf8394643183d9c63389bb071f2a6df7bbb5738",
    "cb2c70b2bdffbd2ea2be7a9b1efc7f6f9118b554a8d8b029ff49e8c4e3c3d93c94d8c11fdb31ecccdc5cf75f63cd9ba6",
    "ea9013a1d22442a5549397094608a3721fb8379a15d5b175f3e8ec15125894f62f18f674c1d1a1152fb7f45ae32bf35d",
    "1ddc49bf63984a894c9a4c8cf58eb6f81c40572c28fe55cf85b26177b0286581da4b60b386f9a811fd1af15782a8a934",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn migrations_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
}

#[derive(Debug, Clone, Copy)]
enum Backend {
    Sqlite,
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    Postgres,
}

impl Backend {
    const fn folder(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

/// An empty database: a SQLite file in a temporary directory, or a new
/// PostgreSQL database next to the one in `TEST_POSTGRES_URL`.
struct Database {
    backend: Backend,
    url: String,
    _dir: Option<tempfile::TempDir>,
    postgres: Option<(String, String)>,
}

impl Database {
    async fn fresh(backend: Backend) -> Self {
        install_default_drivers();
        match backend {
            Backend::Sqlite => {
                let dir = tempfile::tempdir().unwrap();
                let url = format!(
                    "sqlite://{}?mode=rwc",
                    dir.path().join("postkeep.db").display()
                );
                Self {
                    backend,
                    url,
                    _dir: Some(dir),
                    postgres: None,
                }
            }
            Backend::Postgres => {
                let admin = std::env::var("TEST_POSTGRES_URL")
                    .unwrap_or_else(|_| panic!("set TEST_POSTGRES_URL"));
                let name = format!("postkeep_upgrade_{}", uuid::Uuid::new_v4().simple());
                let pool = AnyPoolOptions::new()
                    .max_connections(1)
                    .connect(&admin)
                    .await
                    .unwrap();
                sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                    .execute(&pool)
                    .await
                    .unwrap();
                pool.close().await;
                let (base, query) = admin
                    .split_once('?')
                    .map_or((admin.as_str(), None), |(base, query)| (base, Some(query)));
                let (server, _) = base.rsplit_once('/').unwrap();
                let url = query.map_or_else(
                    || format!("{server}/{name}"),
                    |query| format!("{server}/{name}?{query}"),
                );
                Self {
                    backend,
                    url,
                    _dir: None,
                    postgres: Some((admin, name)),
                }
            }
        }
    }

    async fn pool(&self) -> sqlx::AnyPool {
        AnyPoolOptions::new().connect(&self.url).await.unwrap()
    }

    /// Applies `names` from this backend's folder, the way the version that
    /// shipped them did.
    async fn migrate_through(&self, names: &[&str]) {
        let dir = tempfile::tempdir().unwrap();
        for name in names {
            std::fs::copy(
                migrations_root().join(self.backend.folder()).join(name),
                dir.path().join(name),
            )
            .unwrap();
        }
        let pool = self.pool().await;
        sqlx::migrate::Migrator::new(dir.path())
            .await
            .unwrap()
            .run(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    /// `(version, checksum)` of every applied migration.
    async fn applied(&self) -> Vec<(i64, String)> {
        let pool = self.pool().await;
        let rows = sqlx::query("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pool)
            .await
            .unwrap();
        pool.close().await;
        rows.iter()
            .map(|row| {
                (
                    row.get::<i64, _>("version"),
                    hex(&row.get::<Vec<u8>, _>("checksum")),
                )
            })
            .collect()
    }

    async fn remove(self) {
        if let Some((admin, name)) = &self.postgres {
            let pool = AnyPoolOptions::new()
                .max_connections(1)
                .connect(admin)
                .await
                .unwrap();
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
            )))
            .execute(&pool)
            .await
            .unwrap();
            pool.close().await;
        }
    }
}

#[tokio::test]
async fn both_folders_start_with_the_released_migrations_byte_for_byte() {
    let root = migrations_root();
    for name in RELEASED {
        assert_eq!(
            std::fs::read(root.join("sqlite").join(name)).unwrap(),
            std::fs::read(root.join("postgres").join(name)).unwrap(),
            "{name}"
        );
    }
    let released = |migrator: &sqlx::migrate::Migrator| {
        migrator
            .iter()
            .filter(|migration| migration.version <= 8)
            .map(|migration| {
                (
                    migration.version,
                    migration.description.to_string(),
                    hex(&migration.checksum),
                )
            })
            .collect::<Vec<_>>()
    };
    let sqlite = sqlx::migrate::Migrator::new(root.join("sqlite").as_path())
        .await
        .unwrap();
    let postgres = sqlx::migrate::Migrator::new(root.join("postgres").as_path())
        .await
        .unwrap();
    assert_eq!(released(&sqlite), released(&postgres));
    let released = released(&sqlite);
    assert_eq!(
        released
            .iter()
            .map(|(version, ..)| *version)
            .collect::<Vec<_>>(),
        (1..=8).collect::<Vec<_>>()
    );
    assert_eq!(
        released
            .iter()
            .map(|(.., checksum)| checksum.as_str())
            .collect::<Vec<_>>(),
        RELEASED_CHECKSUMS
    );
}

#[tokio::test]
async fn sqlite_keeps_a_filled_0_3_2_database() {
    exercise_filled_0_3_2(Backend::Sqlite).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_keeps_a_filled_0_3_2_database() {
    exercise_filled_0_3_2(Backend::Postgres).await;
}

/// A database created and filled by 0.3.2 opens with the per-backend
/// migrators: nothing is applied again, the recorded checksums stay, and
/// every kind of row still reads.
async fn exercise_filled_0_3_2(backend: Backend) {
    let db = Database::fresh(backend).await;
    db.migrate_through(&RELEASED).await;
    let created = db.applied().await;
    assert_eq!(
        created
            .iter()
            .map(|(_, checksum)| checksum.as_str())
            .collect::<Vec<_>>(),
        RELEASED_CHECKSUMS
    );

    // Rows that 0.3.2 stored, with `v1.` secrets, next to the ones written below.
    let pool = db.pool().await;
    for statement in v1_rows() {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
    let key = MasterKey::parse(KEY).unwrap();
    let store = Store::connect(&db.url, &key).await.unwrap();
    // Connecting applied the migrations added since 0.3.2 and left the
    // released ones as they were.
    let upgraded = db.applied().await;
    assert_eq!(upgraded[..created.len()], created[..]);
    assert_eq!(
        upgraded
            .iter()
            .map(|(version, _)| *version)
            .collect::<Vec<_>>(),
        (1..=19).collect::<Vec<_>>()
    );
    let imap = store
        .upsert_account("filled@example.com", &secret("abcdabcdabcdabcd"))
        .await
        .unwrap();
    let graph = store
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: "subject-1",
                email: "outlook@example.com",
            },
            &UpstreamTokens {
                refresh_token: secret("upstream-refresh"),
                access_token: None,
                access_expires_at: None,
                scope: "Mail.ReadWrite offline_access".to_owned(),
            },
        )
        .await
        .unwrap();
    let client = store
        .create_client(&NewClient {
            name: Some("Filled".to_owned()),
            redirect_uris: vec!["http://127.0.0.1/cb".to_owned()],
            secret: None,
        })
        .await
        .unwrap();
    let grant = store
        .create_grant(&CodeGrant {
            client_id: client.id.clone(),
            subject: GrantSubject::Account(imap.id.clone()),
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
            "filled-access",
            Duration::from_hours(1),
            "filled-refresh",
            Duration::from_hours(24),
        )
        .await
        .unwrap();
    store
        .save_webhook(
            &imap.id,
            &WebhookSettings {
                enabled: true,
                url: "https://hooks.example.com/in".to_owned(),
                auth_header: None,
                signing: true,
                signing_secret: secret("whsec_filled"),
                include_sender: true,
            },
        )
        .await
        .unwrap();
    store
        .set_watch_cursor(
            &imap.id,
            WatchCursor {
                uid_validity: 9,
                last_uid: 99,
            },
        )
        .await
        .unwrap();
    store
        .append_mail_event(&imap.id, r#"{"n":1}"#, None)
        .await
        .unwrap();
    store
        .save_push_subscription(
            &graph.id,
            &PushSubscription {
                provider: Provider::Graph,
                subscription_id: Some("subscription-1".to_owned()),
                client_state_hash: None,
                expires_at: 4_000_000_000,
            },
        )
        .await
        .unwrap();
    store.close().await;

    let store = Store::connect(&db.url, &key).await.unwrap();
    assert_eq!(db.applied().await, upgraded, "nothing was applied again");
    // Rows from before the tenant column are in the default tenant.
    assert_eq!(store.accounts_in_tenant().await.unwrap().len(), 3);
    let credentials = store.credentials(&imap.id).await.unwrap().unwrap();
    assert_eq!(credentials.password.expose_secret(), "abcdabcdabcdabcd");
    // The column of 0015 is there, and empty on a row that 0.3.2 stored.
    let stored_by_0_3_2 = AccountId("acct-1".to_owned());
    assert_eq!(
        store.password_rejected_at(&stored_by_0_3_2).await.unwrap(),
        None
    );
    let token = store.access_token("filled-access").await.unwrap().unwrap();
    assert_eq!(token.subject, GrantSubject::Account(imap.id.clone()));
    let hook = store.webhook(&imap.id).await.unwrap().unwrap();
    assert_eq!(hook.cursor.unwrap().last_uid, 99);
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_filled");
    assert_eq!(
        store
            .pending_mail_events(&imap.id, 10)
            .await
            .unwrap()
            .events
            .len(),
        1
    );
    let push = store.push_subscription(&graph.id).await.unwrap().unwrap();
    assert_eq!(push.subscription_id.as_deref(), Some("subscription-1"));
    let upstream = store.upstream_tokens(&graph.id).await.unwrap().unwrap();
    assert_eq!(
        upstream.tokens.refresh_token.expose_secret(),
        "upstream-refresh"
    );
    // The `data_keys` table of 0012 is there, and takes a key.
    assert_eq!(store.data_key().await.unwrap().0, 1);
    // The four values written above are v2 already.
    assert_swept(&store, 4).await;
    store.close().await;
    db.remove().await;
}

fn secret(value: &str) -> secrecy::SecretString {
    secrecy::SecretString::from(value.to_owned())
}

#[tokio::test]
async fn sqlite_migrates_on_request_only() {
    exercise_migrate(Backend::Sqlite).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_migrates_on_request_only() {
    exercise_migrate(Backend::Postgres).await;
}

/// `Store::migrate` applies what is pending and is idempotent;
/// `Migrations::RequireCurrent` refuses a database that is behind and
/// changes nothing.
async fn exercise_migrate(backend: Backend) {
    let connect = |url: String| async move {
        let key = MasterKey::parse(KEY).unwrap();
        Store::connect_with(
            &url,
            &key,
            &[],
            PoolSettings::default(),
            Migrations::RequireCurrent,
        )
        .await
    };

    let behind = Database::fresh(backend).await;
    behind.migrate_through(&FIRST_FIVE).await;
    let err = connect(behind.url.clone()).await.unwrap_err();
    assert!(
        matches!(&err, StoreError::PendingMigrations(pending) if pending.as_slice() == [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]),
        "{err}"
    );
    assert_eq!(
        err.to_string(),
        "the database is missing migrations 0006, 0007, 0008, 0009, 0010, 0011, 0012, 0013, 0014, 0015, 0016, 0017, 0018, 0019"
    );
    assert_eq!(behind.applied().await.len(), 5, "nothing was applied");
    assert_eq!(
        Store::migrate(&behind.url).await.unwrap(),
        [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
    );
    assert_eq!(
        Store::migrate(&behind.url).await.unwrap(),
        Vec::<i64>::new()
    );
    let store = connect(behind.url.clone()).await.unwrap();
    assert_eq!(store.pending_migrations().await.unwrap(), Vec::<i64>::new());
    // A migration only a newer version has doesn't count; a missing one does.
    let pool = behind.pool().await;
    for statement in [
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         SELECT 9999, description, success, checksum, execution_time \
         FROM _sqlx_migrations WHERE version = 9",
        "DELETE FROM _sqlx_migrations WHERE version = 9",
    ] {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    pool.close().await;
    assert_eq!(store.pending_migrations().await.unwrap(), [9]);
    store.close().await;
    behind.remove().await;

    let empty = Database::fresh(backend).await;
    let err = connect(empty.url.clone()).await.unwrap_err();
    assert!(
        matches!(&err, StoreError::PendingMigrations(pending) if pending.len() == 19),
        "{err}"
    );
    assert_eq!(
        Store::migrate(&empty.url).await.unwrap(),
        (1..=19).collect::<Vec<_>>()
    );
    let applied = empty.applied().await;
    assert_eq!(
        applied[..8]
            .iter()
            .map(|(_, checksum)| checksum.as_str())
            .collect::<Vec<_>>(),
        RELEASED_CHECKSUMS
    );
    connect(empty.url.clone()).await.unwrap().close().await;
    empty.remove().await;
}

#[tokio::test]
async fn sqlite_refuses_a_database_above_its_storage_level() {
    exercise_storage_level(Backend::Sqlite).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_refuses_a_database_above_its_storage_level() {
    exercise_storage_level(Backend::Postgres).await;
}

/// A new database records level 1 in one row. A store opens a database
/// recorded at its level or below, and refuses one above it, whichever way it
/// connects. It applies no migration to a database above its level, and where
/// sqlx would stop at a migration of the newer version the error is the level.
async fn exercise_storage_level(backend: Backend) {
    // Changing a number decides what a level holds: see the migration.
    assert_eq!((STORAGE_LEVEL_READS, STORAGE_LEVEL_WRITES), (1, 1));
    let db = Database::fresh(backend).await;
    let key = MasterKey::parse(KEY).unwrap();
    let (url, key) = (&db.url, &key);
    // The error a connection ends with, if any.
    let open = |migrations| async move {
        match Store::connect_with(url, key, &[], PoolSettings::default(), migrations).await {
            Ok(store) => {
                store.close().await;
                None
            }
            Err(err) => Some(err),
        }
    };
    // The same for each way of connecting, as text.
    let attempts = || async {
        let ends = [
            Store::migrate(url).await.err(),
            open(Migrations::Apply).await,
            open(Migrations::RequireCurrent).await,
        ];
        ends.map(|err| format!("{err:?}"))
    };
    let ahead = "Some(StorageLevelAhead { database: 2, build: 1 })";

    // Five migrations applied and a level of 2: none of the rest is applied.
    db.migrate_through(&FIRST_FIVE).await;
    let pool = db.pool().await;
    let run = |sql: &'static str| sqlx::query(sql).execute(&pool);
    run("CREATE TABLE storage_level (level BIGINT)")
        .await
        .unwrap();
    run("INSERT INTO storage_level VALUES (2)").await.unwrap();
    assert_eq!(format!("{:?}", open(Migrations::Apply).await), ahead);
    assert_eq!(db.applied().await.len(), 5, "nothing was applied");
    run("DROP TABLE storage_level").await.unwrap();

    assert!(open(Migrations::Apply).await.is_none());
    let levels = sqlx::query_scalar::<_, i64>("SELECT level FROM storage_level");
    assert_eq!(levels.fetch_all(&pool).await.unwrap(), [1]);
    for sql in [
        "INSERT INTO storage_level VALUES (2, 1)",
        "INSERT INTO storage_level VALUES (NULL, 1)",
        "UPDATE storage_level SET level = -1",
        "UPDATE storage_level SET level = NULL",
    ] {
        run(sql).await.unwrap_err();
    }

    for (level, refused) in [(0, false), (1, false), (2, true)] {
        let set = sqlx::query("UPDATE storage_level SET level = $1");
        set.bind(level).execute(&pool).await.unwrap();
        let want = if refused { ahead } else { "None" };
        for end in attempts().await {
            assert_eq!(end, want, "recorded {level}");
        }
    }

    // A database that cannot tell its level is not opened.
    run("DELETE FROM storage_level").await.unwrap();
    for end in attempts().await {
        assert_eq!(end, "Some(Database(RowNotFound))");
    }
    run("INSERT INTO storage_level SELECT 1, 2").await.unwrap();

    // sqlx stops at a migration of the newer version when it applies
    // migrations, yet the error names the level that version recorded.
    run(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         SELECT 9999, description, success, checksum, execution_time \
         FROM _sqlx_migrations WHERE version = 9",
    )
    .await
    .unwrap();
    for end in attempts().await {
        assert_eq!(end, ahead);
    }
    run("UPDATE storage_level SET level = 1").await.unwrap();
    let missing = "Some(Migrate(VersionMissing(9999)))";
    assert_eq!(attempts().await, [missing, missing, "None"]);
    pool.close().await;
    db.remove().await;
}

#[tokio::test]
async fn sqlite_raises_its_storage_level_and_never_lowers_it() {
    exercise_storage_level_raise(Backend::Sqlite).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_raises_its_storage_level_and_never_lowers_it() {
    exercise_storage_level_raise(Backend::Postgres).await;
}

/// A raise goes up to the level this version reads and never down, two at
/// once raise it once, and a format above the default write level waits for
/// its level.
async fn exercise_storage_level_raise(backend: Backend) {
    let db = Database::fresh(backend).await;
    let url = &db.url;
    Store::migrate(url).await.unwrap();
    assert_eq!(Store::read_storage_level(url).await.unwrap(), 1);
    assert_eq!(Store::raise_storage_level(url).await.unwrap(), (1, 1));

    let pool = db.pool().await;
    let set = |level: i64| {
        sqlx::query("UPDATE storage_level SET level = $1")
            .bind(level)
            .execute(&pool)
    };
    set(0).await.unwrap();
    let store = Store::connect(url, &MasterKey::parse(KEY).unwrap())
        .await
        .unwrap();
    let gate = || async {
        let mut allowed = Vec::new();
        for level in 0..=2 {
            allowed.push(store.may_write_level(level).await.unwrap());
        }
        allowed
    };
    assert_eq!(gate().await, [true, true, false]);

    let (first, second) = tokio::join!(
        Store::raise_storage_level(url),
        Store::raise_storage_level(url)
    );
    let mut both = [first.unwrap(), second.unwrap()];
    both.sort_unstable();
    assert_eq!(both, [(0, 1), (1, 1)]);
    assert_eq!(Store::read_storage_level(url).await.unwrap(), 1);
    assert_eq!(gate().await, [true, true, false]);

    set(2).await.unwrap();
    let raised = Store::raise_storage_level(url).await;
    assert!(
        matches!(
            raised,
            Err(StoreError::StorageLevelAhead {
                database: 2,
                build: 1
            })
        ),
        "{raised:?}"
    );
    assert_eq!(Store::read_storage_level(url).await.unwrap(), 2);
    store.close().await;
    pool.close().await;
    db.remove().await;
}

#[tokio::test]
async fn sqlite_keeps_one_tenant_per_address() {
    exercise_tenant_scope(Backend::Sqlite).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_scopes_addresses_by_tenant() {
    exercise_tenant_scope(Backend::Postgres).await;
}

async fn graph_account(tenant: &Store) -> Result<postkeep_store::Account, StoreError> {
    tenant
        .upsert_oauth_account(
            &OAuthAccount {
                provider: Provider::Graph,
                subject: "same-subject",
                email: "outlook@example.com",
            },
            &UpstreamTokens {
                refresh_token: secret("refresh"),
                access_token: None,
                access_expires_at: None,
                scope: "Mail.ReadWrite".to_owned(),
            },
        )
        .await
}

/// Addresses and provider identities are unique per tenant on PostgreSQL.
/// SQLite keeps them globally unique, so a second tenant is refused.
async fn exercise_tenant_scope(backend: Backend) {
    let db = Database::fresh(backend).await;
    let store = Store::connect(&db.url, &MasterKey::parse(KEY).unwrap())
        .await
        .unwrap();
    let a = store.for_tenant("tenant-a");
    let b = store.for_tenant("tenant-b");
    assert_eq!((store.tenant(), a.tenant()), ("default", "tenant-a"));

    let in_a = a
        .upsert_account("shared@example.com", &secret("abcdabcdabcdabcd"))
        .await
        .unwrap();
    let in_b = b
        .upsert_account("shared@example.com", &secret("zzzzzzzzzzzzzzzz"))
        .await;
    let graph_a = graph_account(&a).await.unwrap();
    let graph_b = graph_account(&b).await;
    match backend {
        Backend::Postgres => {
            let in_b = in_b.unwrap();
            assert_ne!(in_a.id, in_b.id);
            assert_ne!(graph_a.id, graph_b.unwrap().id);
            let found = b
                .account_by_email("shared@example.com", Provider::Imap)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(found.id, in_b.id);
            let password = b.credentials(&in_b.id).await.unwrap().unwrap().password;
            assert_eq!(password.expose_secret(), "zzzzzzzzzzzzzzzz");
            assert_eq!(b.accounts_in_tenant().await.unwrap().len(), 2);
        }
        Backend::Sqlite => {
            assert!(matches!(in_b, Err(StoreError::AccountConflict)), "{in_b:?}");
            assert!(
                matches!(graph_b, Err(StoreError::AccountConflict)),
                "{graph_b:?}"
            );
            assert!(
                b.account_by_email("shared@example.com", Provider::Imap)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(b.accounts_in_tenant().await.unwrap().len(), 0);
        }
    }
    // Updating within a tenant still works, and the default tenant sees
    // none of this.
    let again = a
        .upsert_account("shared@example.com", &secret("newnewnewnewnewn"))
        .await
        .unwrap();
    assert_eq!(again.id, in_a.id);
    assert_eq!(
        a.accounts_in_tenant()
            .await
            .unwrap()
            .iter()
            .map(|account| account.email.as_str())
            .collect::<Vec<_>>(),
        ["outlook@example.com", "shared@example.com"]
    );
    assert_eq!(store.accounts_in_tenant().await.unwrap().len(), 0);
    assert!(
        store
            .account_by_subject(Provider::Graph, "same-subject")
            .await
            .unwrap()
            .is_none()
    );

    // `find_account` takes an ID or an address, and stays in its tenant.
    for key in [in_a.id.0.as_str(), " Shared@Example.com "] {
        let found = a.find_account(key).await.unwrap().unwrap();
        assert_eq!(found.id, in_a.id, "{key}");
        assert!(store.find_account(key).await.unwrap().is_none(), "{key}");
    }
    let in_b = b.find_account("shared@example.com").await.unwrap();
    match backend {
        Backend::Postgres => assert_ne!(in_b.unwrap().id, in_a.id),
        Backend::Sqlite => assert!(in_b.is_none()),
    }
    assert!(b.find_account(&in_a.id.0).await.unwrap().is_none());
    assert!(
        a.find_account("nobody@example.com")
            .await
            .unwrap()
            .is_none()
    );
    store.close().await;
    db.remove().await;
}

/// The migrations before external principals.
const BEFORE_0010: [&str; 9] = [
    "0001_initial.sql",
    "0002_client_activity.sql",
    "0003_account_sessions.sql",
    "0004_webhooks.sql",
    "0005_token_reuse.sql",
    "0006_providers.sql",
    "0007_webhook_pause.sql",
    "0008_webhook_outbox_limits.sql",
    "0009_tenant_scope.sql",
];

const REDIRECT_URI: &str = "http://127.0.0.1:9/cb";
const RESOURCE: &str = "https://mail.example.com/mcp";
const FAR: i64 = 4_000_000_000;

/// A token or a code as the store keeps it.
fn hashed(raw: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(raw.as_bytes()))
}

/// The rows in `grants`, `access_tokens`, `refresh_tokens` and
/// `authorization_codes`.
async fn oauth_rows(pool: &sqlx::AnyPool) -> [i64; 4] {
    let mut rows = [0; 4];
    for (count, table) in rows.iter_mut().zip([
        "grants",
        "access_tokens",
        "refresh_tokens",
        "authorization_codes",
    ]) {
        *count = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT count(*) AS n FROM {table}"
        )))
        .fetch_one(pool)
        .await
        .unwrap()
        .get::<i64, _>("n");
    }
    rows
}

/// A database at 0009 with an account, a client, two grants with an access
/// and a refresh token each, a code waiting to be redeemed and a code
/// already redeemed for the second grant.
async fn fill_before_0010(db: &Database) {
    db.migrate_through(&BEFORE_0010).await;
    let mut statements = vec![
        format!(
            "INSERT INTO accounts (id, email, password_ciphertext, created_at, updated_at) \
             VALUES ('acct-1', 'user@example.com', '{PASSWORD}', 1, 1)"
        ),
        format!(
            "INSERT INTO oauth_clients (id, secret_hash, name, redirect_uris, created_at, \
             last_used_at) VALUES ('client-1', NULL, 'Client', '[\"{REDIRECT_URI}\"]', 1, 1)"
        ),
        "INSERT INTO grants (id, client_id, account_id, scope, resource, created_at) \
         VALUES ('grant-1', 'client-1', 'acct-1', 'mail', NULL, 1)"
            .to_owned(),
        format!(
            "INSERT INTO grants (id, client_id, account_id, scope, resource, created_at) \
             VALUES ('grant-2', 'client-1', 'acct-1', 'mail', '{RESOURCE}', 2)"
        ),
    ];
    for (table, token, grant) in [
        ("access_tokens", "legacy-access-token", "grant-1"),
        ("access_tokens", "second-access-token", "grant-2"),
        ("refresh_tokens", "legacy-refresh-token", "grant-1"),
        ("refresh_tokens", "second-refresh-token", "grant-2"),
    ] {
        statements.push(format!(
            "INSERT INTO {table} (token_hash, grant_id, expires_at) \
             VALUES ('{}', '{grant}', {FAR})",
            hashed(token)
        ));
    }
    for (code, used_at, grant) in [
        ("waiting-code", "NULL", "NULL"),
        ("redeemed-code", "1", "'grant-2'"),
    ] {
        statements.push(format!(
            "INSERT INTO authorization_codes (code_hash, client_id, account_id, redirect_uri, \
             code_challenge, scope, resource, expires_at, used_at, grant_id) \
             VALUES ('{}', 'client-1', 'acct-1', '{REDIRECT_URI}', 'challenge', 'mail', \
             '{RESOURCE}', {FAR}, {used_at}, {grant})",
            hashed(code)
        ));
    }
    let pool = db.pool().await;
    for statement in statements {
        sqlx::query(sqlx::AssertSqlSafe(statement))
            .execute(&pool)
            .await
            .unwrap();
    }
    pool.close().await;
}

#[tokio::test]
async fn sqlite_keeps_every_token_through_0010() {
    exercise_external_principals(Backend::Sqlite).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_keeps_every_token_through_0010() {
    exercise_external_principals(Backend::Postgres).await;
}

/// 0010 lets a grant or a code be for a principal instead of an account.
/// On SQLite that rebuilds `grants` and `authorization_codes`, which must
/// not cascade to the tokens: every row stays, and the old tokens and codes
/// still work.
async fn exercise_external_principals(backend: Backend) {
    let db = Database::fresh(backend).await;
    fill_before_0010(&db).await;
    let pool = db.pool().await;
    assert_eq!(oauth_rows(&pool).await, [2, 2, 2, 2]);
    pool.close().await;

    // One connection, so everything below runs on the connection that
    // applied 0010.
    let store = Store::connect_with(
        &db.url,
        &MasterKey::parse(KEY).unwrap(),
        &[],
        PoolSettings {
            max_connections: 1,
            ..PoolSettings::default()
        },
        Migrations::Apply,
    )
    .await
    .unwrap();
    assert_eq!(db.applied().await.len(), 19);
    assert_eq!(oauth_rows(store.pool()).await, [2, 2, 2, 2]);
    let created = sqlx::query("SELECT created_at FROM grants ORDER BY id")
        .fetch_all(store.pool())
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<i64, _>("created_at"))
        .collect::<Vec<_>>();
    assert_eq!(created, [1, 2]);

    let account_id = AccountId("acct-1".to_owned());
    assert_eq!(
        store
            .access_token("legacy-access-token")
            .await
            .unwrap()
            .unwrap(),
        TokenGrant {
            grant_id: "grant-1".to_owned(),
            client_id: "client-1".to_owned(),
            subject: GrantSubject::Account(account_id.clone()),
            email: Some("user@example.com".to_owned()),
            scope: "mail".to_owned(),
            resource: None,
            expires_at: FAR,
        }
    );
    let second = store
        .access_token("second-access-token")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (second.grant_id.as_str(), second.resource.as_deref()),
        ("grant-2", Some(RESOURCE))
    );
    let rotated = store
        .rotate_refresh_token(
            "legacy-refresh-token",
            "client-1",
            "rotated-access-token",
            Duration::from_hours(1),
            "rotated-refresh-token",
            Duration::from_hours(1),
            Duration::ZERO,
            |email| email == "user@example.com",
        )
        .await
        .unwrap();
    let RefreshRotation::Rotated(rotated) = rotated else {
        panic!("expected a rotation, got {rotated:?}");
    };
    assert_eq!(rotated.grant_id, "grant-1");
    assert_eq!(
        store.take_code("waiting-code").await.unwrap(),
        Redemption::Valid(CodeGrant {
            client_id: "client-1".to_owned(),
            subject: GrantSubject::Account(account_id),
            redirect_uri: REDIRECT_URI.to_owned(),
            code_challenge: "challenge".to_owned(),
            scope: "mail".to_owned(),
            resource: Some(RESOURCE.to_owned()),
        })
    );
    // The redeemed code still knows its grant, so redeeming it again
    // revokes that grant.
    assert_eq!(
        store.take_code("redeemed-code").await.unwrap(),
        Redemption::Replayed
    );
    assert!(
        store
            .access_token("second-access-token")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(oauth_rows(store.pool()).await, [1, 2, 2, 2]);

    if matches!(backend, Backend::Sqlite) {
        let foreign_keys = sqlx::query("PRAGMA foreign_keys")
            .fetch_one(store.pool())
            .await
            .unwrap()
            .get::<i64, _>(0);
        assert_eq!(foreign_keys, 1, "0010 turns foreign keys back on");
    }
    // The tokens belong to the new `grants`: deleting a grant deletes them.
    sqlx::query("DELETE FROM grants WHERE id = 'grant-1'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(oauth_rows(store.pool()).await, [0, 0, 0, 2]);

    for (statement, constraint) in [
        (
            "INSERT INTO grants (id, client_id, account_id, principal, scope, created_at) \
             VALUES ('both', 'client-1', 'acct-1', 'member-1', 'mail', 1)",
            "grants_one_subject",
        ),
        (
            "INSERT INTO grants (id, client_id, account_id, principal, scope, created_at) \
             VALUES ('neither', 'client-1', NULL, NULL, 'mail', 1)",
            "grants_one_subject",
        ),
        (
            "INSERT INTO authorization_codes (code_hash, client_id, account_id, principal, \
             redirect_uri, code_challenge, scope, expires_at) \
             VALUES ('both', 'client-1', 'acct-1', 'member-1', 'http://127.0.0.1:9/cb', \
             'challenge', 'mail', 1)",
            "authorization_codes_one_subject",
        ),
        (
            "INSERT INTO authorization_codes (code_hash, client_id, account_id, principal, \
             redirect_uri, code_challenge, scope, expires_at) \
             VALUES ('neither', 'client-1', NULL, NULL, 'http://127.0.0.1:9/cb', \
             'challenge', 'mail', 1)",
            "authorization_codes_one_subject",
        ),
    ] {
        let err = sqlx::query(statement)
            .execute(store.pool())
            .await
            .unwrap_err();
        assert!(err.to_string().contains(constraint), "{statement}: {err}");
    }
    store.close().await;
    db.remove().await;
}

/// A foreign key that was already broken stops 0010 before it commits. The
/// failed attempt leaves nothing behind, not even its lock, and the next
/// start tries again. Applying 0010 a second time, as after a crash between
/// its COMMIT and sqlx recording it, keeps every row.
#[tokio::test]
async fn sqlite_0010_rolls_back_on_a_broken_foreign_key_and_runs_again_safely() {
    let db = Database::fresh(Backend::Sqlite).await;
    fill_before_0010(&db).await;
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&db.url)
        .await
        .unwrap();
    for statement in [
        "PRAGMA foreign_keys = OFF",
        "INSERT INTO access_tokens (token_hash, grant_id, expires_at) \
         VALUES ('orphan', 'grant-gone', 4000000000)",
    ] {
        sqlx::query(statement).execute(&pool).await.unwrap();
    }
    pool.close().await;

    let key = MasterKey::parse(KEY).unwrap();
    let err = Store::connect(&db.url, &key).await.unwrap_err();
    assert!(
        matches!(err, StoreError::Migrate(_))
            && err.to_string().contains("no_foreign_key_violations"),
        "{err}"
    );
    assert_eq!(db.applied().await.len(), 9, "0010 is not recorded");
    // A write that cannot wait succeeds, so the failed attempt's connection
    // is closed, and none of its changes are left.
    let pool = AnyPoolOptions::new()
        .max_connections(1)
        .connect(&db.url)
        .await
        .unwrap();
    sqlx::query("PRAGMA busy_timeout = 0")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM access_tokens WHERE token_hash = 'orphan'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(oauth_rows(&pool).await, [2, 2, 2, 2]);
    let columns = sqlx::query("SELECT name FROM pragma_table_info('grants')")
        .fetch_all(&pool)
        .await
        .unwrap()
        .iter()
        .map(|row| row.get::<String, _>("name"))
        .collect::<Vec<_>>();
    assert!(
        !columns.iter().any(|name| name == "principal"),
        "{columns:?}"
    );
    pool.close().await;

    Store::connect(&db.url, &key).await.unwrap().close().await;
    assert_eq!(db.applied().await.len(), 19);
    let pool = db.pool().await;
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 10")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let store = Store::connect(&db.url, &key).await.unwrap();
    assert_eq!(db.applied().await.len(), 19, "0010 ran again");
    assert_eq!(oauth_rows(store.pool()).await, [2, 2, 2, 2]);
    assert_eq!(
        store
            .access_token("legacy-access-token")
            .await
            .unwrap()
            .unwrap()
            .subject,
        GrantSubject::Account(AccountId("acct-1".to_owned()))
    );
    store.close().await;
}
