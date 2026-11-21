//! Per-account outbox retention and event caps. The PostgreSQL variant is
//! ignored unless run explicitly with `TEST_POSTGRES_URL` set.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

use postkeep_store::{
    AccountId, AppendOutcome, DeliveryRecord, MasterKey, OutboxLimitChange, OutboxPolicy,
    PurgePolicy, Store, StoreError, WatchCursor, WebhookSettings,
};
use secrecy::SecretString;
use sqlx::Executor;
use sqlx::Row;
use sqlx::any::AnyPoolOptions;

fn key() -> MasterKey {
    MasterKey::parse("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap()
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

fn unique(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4().simple())
}

fn settings(enabled: bool) -> WebhookSettings {
    WebhookSettings {
        enabled,
        url: "https://hooks.example/in".to_owned(),
        auth_header: None,
        signing: true,
        signing_secret: secret("whsec_one"),
        include_sender: false,
    }
}

async fn sqlite() -> (Store, tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}?mode=rwc", dir.path().join("test.db").display());
    (Store::connect(&url, &key()).await.unwrap(), dir, url)
}

fn policy() -> OutboxPolicy {
    // 2 hours / 4 events by default. An account may go up to 48 hours / 6 events.
    OutboxPolicy::try_new(2 * 3600, 4, 48 * 3600, 6).unwrap()
}

async fn account(store: &Store) -> AccountId {
    store
        .upsert_account(&format!("{}@example.com", unique("outbox")), &secret("pw"))
        .await
        .unwrap()
        .id
}

async fn sequences(url: &str, account: &AccountId) -> Vec<i64> {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                if conn.backend_name() == "SQLite" {
                    conn.execute("PRAGMA busy_timeout = 5000").await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap();
    let rows =
        sqlx::query("SELECT sequence FROM mail_events WHERE account_id = $1 ORDER BY sequence")
            .bind(&account.0)
            .fetch_all(&pool)
            .await
            .unwrap();
    let sequences = rows
        .iter()
        .map(|row| row.try_get("sequence").unwrap())
        .collect();
    pool.close().await;
    sequences
}

async fn backdate(url: &str, account: &AccountId, sequence: i64, created_at: i64) {
    sqlx::any::install_default_drivers();
    let pool = AnyPoolOptions::new()
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                if conn.backend_name() == "SQLite" {
                    conn.execute("PRAGMA busy_timeout = 5000").await?;
                }
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap();
    sqlx::query("UPDATE mail_events SET created_at = $1 WHERE account_id = $2 AND sequence = $3")
        .bind(created_at)
        .bind(&account.0)
        .bind(sequence)
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
}

async fn append_n(store: &Store, account: &AccountId, count: i64) {
    for n in 1..=count {
        let stored = store
            .append_mail_event(account, &format!(r#"{{"n":{n}}}"#), None)
            .await
            .unwrap();
        assert!(
            matches!(stored, AppendOutcome::Stored(_)),
            "append {n} wrote nothing"
        );
    }
}

async fn exercise(store: &Store, url: &str) {
    let limits = policy();
    store.set_outbox_policy(limits).unwrap();
    let mut bad = limits;
    bad.retention_secs = 60;
    let err = store.set_outbox_policy(bad).unwrap_err();
    assert!(
        matches!(err, StoreError::OutboxLimit(ref message) if message.contains("POSTKEEP_WEBHOOK_OUTBOX_RETENTION")),
        "{err}"
    );
    assert_eq!(store.outbox_policy(), limits);

    let missing = account(store).await;
    assert!(
        store
            .set_webhook_outbox_limits(
                &missing,
                OutboxLimitChange::Set(3600),
                OutboxLimitChange::Keep,
            )
            .await
            .unwrap()
            .is_none()
    );

    let capped = account(store).await;
    store.save_webhook(&capped, &settings(true)).await.unwrap();
    let hook = store.webhook(&capped).await.unwrap().unwrap();
    assert_eq!(
        (hook.outbox_retention_secs, hook.outbox_max_events),
        (None, None)
    );
    let applied = store
        .set_webhook_outbox_limits(&capped, OutboxLimitChange::Keep, OutboxLimitChange::Set(3))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(applied.pruned, 0);
    assert_eq!(applied.limits.max_events, 3);
    assert!(!applied.limits.max_events_is_default);
    append_n(store, &capped, 5).await;
    assert_eq!(
        sequences(url, &capped).await,
        vec![3, 4, 5],
        "the cap keeps the newest events, delivered or not"
    );

    let ordered = account(store).await;
    store.save_webhook(&ordered, &settings(true)).await.unwrap();
    let cursor = WatchCursor {
        uid_validity: 9,
        last_uid: 40,
    };
    store.set_watch_cursor(&ordered, cursor).await.unwrap();
    append_n(store, &ordered, 3).await;
    store.mark_mail_events_delivered(&ordered, 1).await.unwrap();
    let applied = store
        .set_webhook_outbox_limits(&ordered, OutboxLimitChange::Keep, OutboxLimitChange::Set(1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(applied.pruned, 2);
    assert_eq!(sequences(url, &ordered).await, vec![3]);
    let hook = store.webhook(&ordered).await.unwrap().unwrap();
    assert_eq!((hook.delivered_sequence, hook.last_sequence), (1, 3));
    assert_eq!(hook.cursor, Some(cursor));
    assert_eq!(
        store
            .pending_mail_events(&ordered, 10)
            .await
            .unwrap()
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![3]
    );
    // A cap of 1 would drop sequence 3 when event 4 arrives. Raising it
    // shows the kept event and the new one are still delivered in order.
    store
        .set_webhook_outbox_limits(&ordered, OutboxLimitChange::Keep, OutboxLimitChange::Set(2))
        .await
        .unwrap()
        .unwrap();
    append_n(store, &ordered, 1).await;
    assert_eq!(sequences(url, &ordered).await, vec![3, 4]);
    let hook = store.webhook(&ordered).await.unwrap().unwrap();
    assert_eq!((hook.delivered_sequence, hook.last_sequence), (1, 4));
    assert_eq!(hook.cursor, Some(cursor));
    assert_eq!(
        store
            .pending_mail_events(&ordered, 10)
            .await
            .unwrap()
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![3, 4]
    );

    let tight = account(store).await;
    let loose = account(store).await;
    store.save_webhook(&tight, &settings(true)).await.unwrap();
    store.save_webhook(&loose, &settings(true)).await.unwrap();
    store
        .set_webhook_outbox_limits(&tight, OutboxLimitChange::Keep, OutboxLimitChange::Set(2))
        .await
        .unwrap()
        .unwrap();
    append_n(store, &tight, 4).await;
    append_n(store, &loose, 4).await;
    assert_eq!(sequences(url, &tight).await, vec![3, 4]);
    assert_eq!(
        sequences(url, &loose).await,
        vec![1, 2, 3, 4],
        "the other account still uses the server default of 4"
    );

    let short = account(store).await;
    let long = account(store).await;
    store.save_webhook(&short, &settings(true)).await.unwrap();
    store.save_webhook(&long, &settings(true)).await.unwrap();
    store
        .set_webhook_outbox_limits(
            &short,
            OutboxLimitChange::Set(3600),
            OutboxLimitChange::Keep,
        )
        .await
        .unwrap()
        .unwrap();
    store
        .set_webhook_outbox_limits(
            &long,
            OutboxLimitChange::Set(48 * 3600),
            OutboxLimitChange::Keep,
        )
        .await
        .unwrap()
        .unwrap();
    append_n(store, &short, 1).await;
    append_n(store, &long, 1).await;
    let stale = postkeep_store::now() - 7200;
    backdate(url, &short, 1, stale).await;
    backdate(url, &long, 1, stale).await;
    store.purge_expired(PurgePolicy::default()).await.unwrap();
    assert_eq!(sequences(url, &short).await, Vec::<i64>::new());
    assert_eq!(sequences(url, &long).await, vec![1]);

    let aged = account(store).await;
    store.save_webhook(&aged, &settings(true)).await.unwrap();
    store
        .set_webhook_outbox_limits(&aged, OutboxLimitChange::Set(3600), OutboxLimitChange::Keep)
        .await
        .unwrap()
        .unwrap();
    append_n(store, &aged, 1).await;
    backdate(url, &aged, 1, postkeep_store::now() - 7200).await;
    append_n(store, &aged, 1).await;
    assert_eq!(
        sequences(url, &aged).await,
        vec![2],
        "appending prunes events older than the account retention"
    );

    let rejected = account(store).await;
    store
        .save_webhook(&rejected, &settings(true))
        .await
        .unwrap();
    store
        .set_webhook_outbox_limits(
            &rejected,
            OutboxLimitChange::Set(7200),
            OutboxLimitChange::Set(2),
        )
        .await
        .unwrap()
        .unwrap();
    let too_short = store
        .set_webhook_outbox_limits(
            &rejected,
            OutboxLimitChange::Set(1800),
            OutboxLimitChange::Set(5),
        )
        .await
        .unwrap_err();
    match too_short {
        StoreError::OutboxLimit(message) => {
            assert!(
                message.contains("3600 seconds (1 hour)")
                    && message.contains("172800 seconds (2 days)")
                    && message.contains("1800 seconds (30 minutes)"),
                "{message}"
            );
        }
        other => panic!("expected a range error, got {other}"),
    }
    let too_many = store
        .set_webhook_outbox_limits(
            &rejected,
            OutboxLimitChange::Keep,
            OutboxLimitChange::Set(7),
        )
        .await
        .unwrap_err();
    match too_many {
        StoreError::OutboxLimit(message) => {
            assert_eq!(message, "outbox max events must be from 1 to 6, not 7");
        }
        other => panic!("expected a range error, got {other}"),
    }
    let hook = store.webhook(&rejected).await.unwrap().unwrap();
    assert_eq!(
        (hook.outbox_retention_secs, hook.outbox_max_events),
        (Some(7200), Some(2)),
        "a rejected change leaves the stored limits"
    );

    store
        .save_webhook(&rejected, &settings(true))
        .await
        .unwrap();
    let hook = store.webhook(&rejected).await.unwrap().unwrap();
    assert_eq!(
        (hook.outbox_retention_secs, hook.outbox_max_events),
        (Some(7200), Some(2)),
        "saving the webhook leaves the overrides"
    );

    let reset = store
        .set_webhook_outbox_limits(
            &rejected,
            OutboxLimitChange::Default,
            OutboxLimitChange::Default,
        )
        .await
        .unwrap()
        .unwrap();
    assert!(reset.limits.retention_is_default && reset.limits.max_events_is_default);
    assert_eq!(reset.limits.max_events, 4);
    assert_eq!(reset.limits.retention_secs, 2 * 3600);
    let hook = store.webhook(&rejected).await.unwrap().unwrap();
    assert_eq!(
        (hook.outbox_retention_secs, hook.outbox_max_events),
        (None, None)
    );

    let paused = account(store).await;
    store.save_webhook(&paused, &settings(true)).await.unwrap();
    let failure = DeliveryRecord {
        created_at: postkeep_store::now(),
        test: false,
        succeeded: false,
        summary: "HTTP 500".to_owned(),
        elapsed_ms: Some(5),
    };
    for _ in 0..postkeep_store::MAX_CONSECUTIVE_FAILURES {
        store.record_delivery(&paused, &failure).await.unwrap();
    }
    assert!(store.webhook(&paused).await.unwrap().unwrap().is_paused());
    store
        .set_webhook_outbox_limits(
            &paused,
            OutboxLimitChange::Set(3600),
            OutboxLimitChange::Set(1),
        )
        .await
        .unwrap()
        .unwrap();
    assert!(store.webhook(&paused).await.unwrap().unwrap().is_paused());

    let disabled = account(store).await;
    store
        .save_webhook(&disabled, &settings(false))
        .await
        .unwrap();
    store
        .set_webhook_outbox_limits(
            &disabled,
            OutboxLimitChange::Keep,
            OutboxLimitChange::Set(1),
        )
        .await
        .unwrap()
        .unwrap();
    let hook = store.webhook(&disabled).await.unwrap().unwrap();
    assert!(!hook.settings.enabled);
    assert_eq!(hook.outbox_max_events, Some(1));

    let clamped = account(store).await;
    store.save_webhook(&clamped, &settings(true)).await.unwrap();
    store
        .set_webhook_outbox_limits(&clamped, OutboxLimitChange::Keep, OutboxLimitChange::Set(6))
        .await
        .unwrap()
        .unwrap();
    append_n(store, &clamped, 6).await;
    store
        .set_outbox_policy(OutboxPolicy::try_new(2 * 3600, 2, 48 * 3600, 2).unwrap())
        .unwrap();
    let applied = store
        .set_webhook_outbox_limits(&clamped, OutboxLimitChange::Keep, OutboxLimitChange::Keep)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(applied.limits.max_events, 2);
    assert!(!applied.limits.max_events_is_default);
    assert_eq!(applied.pruned, 4);
    let hook = store.webhook(&clamped).await.unwrap().unwrap();
    assert_eq!(
        hook.outbox_max_events,
        Some(6),
        "a lowered ceiling clamps at read time and leaves the stored override"
    );
    assert_eq!(sequences(url, &clamped).await, vec![5, 6]);
}

#[tokio::test]
async fn sqlite_outbox_limits() {
    let (store, _dir, url) = sqlite().await;
    exercise(&store, &url).await;
}

/// A purge prunes an outbox that a lowered default cap leaves too full, with
/// no event past its retention, and passes over a webhook with no event.
#[tokio::test]
async fn sqlite_purge_applies_a_lowered_default_cap() {
    let (store, _dir, url) = sqlite().await;
    store.set_outbox_policy(policy()).unwrap();
    let full = account(&store).await;
    store.save_webhook(&full, &settings(true)).await.unwrap();
    append_n(&store, &full, 3).await;
    store
        .set_outbox_policy(OutboxPolicy::try_new(2 * 3600, 2, 48 * 3600, 6).unwrap())
        .unwrap();
    // A webhook with no event: the purge's read finds no oldest event for
    // it and passes it over.
    let empty = account(&store).await;
    store.save_webhook(&empty, &settings(true)).await.unwrap();
    store.purge_expired(PurgePolicy::default()).await.unwrap();
    assert_eq!(sequences(&url, &full).await, vec![2, 3]);
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_outbox_limits() {
    let Ok(url) = std::env::var("TEST_POSTGRES_URL") else {
        panic!("set TEST_POSTGRES_URL");
    };
    let store = Store::connect(&url, &key()).await.unwrap();
    exercise(&store, &url).await;
}

/// A purge reads each account's limits under the webhook row and prunes
/// before it lets go. One that read every account's limits first went on
/// pruning with them after the account had raised its cap from 2 to 4 and
/// received events 3 and 4: it deleted event 2. SQLite runs one write
/// transaction at a time, so there the two never overlap.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_purge_keeps_what_a_raised_cap_keeps() {
    in_a_database_of_its_own(purge_keeps_what_a_raised_cap_keeps).await;
}

#[cfg(feature = "postgres")]
async fn purge_keeps_what_a_raised_cap_keeps(url: String) {
    let store = Store::connect(&url, &key()).await.unwrap();
    store.set_outbox_policy(policy()).unwrap();
    let raised = account(&store).await;
    store.save_webhook(&raised, &settings(true)).await.unwrap();
    store
        .set_webhook_outbox_limits(&raised, OutboxLimitChange::Keep, OutboxLimitChange::Set(2))
        .await
        .unwrap()
        .unwrap();
    append_n(&store, &raised, 2).await;
    // Past the default retention of 2 hours, not past the 24 hours set below,
    // so only the purge's prune deletes event 1, and holding it stops the
    // purge at this account after it has read the limits.
    backdate(&url, &raised, 1, postkeep_store::now() - 3 * 3600).await;
    #[expect(
        clippy::disallowed_methods,
        reason = "a PostgreSQL row lock, not a store write"
    )]
    let mut gate = store.pool().begin().await.unwrap();
    let hold =
        sqlx::query("SELECT 1 FROM mail_events WHERE account_id = $1 AND sequence = 1 FOR UPDATE");
    hold.bind(&raised.0).fetch_one(&mut *gate).await.unwrap();
    let purge = tokio::spawn({
        let store = store.clone();
        async move { store.purge_expired(PurgePolicy::default()).await.unwrap() }
    });
    // The session the gate blocks is the purge, stopped at this account. The
    // polls run on another connection: pg_stat_activity keeps its first read
    // for the rest of a transaction.
    let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let blocked = "SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))";
    let mut purge_pid: Option<i32> = None;
    for _ in 0..250 {
        purge_pid = sqlx::query_scalar(blocked)
            .bind(gate_pid)
            .fetch_optional(store.pool())
            .await
            .unwrap();
        if purge_pid.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let Some(purge_pid) = purge_pid else {
        panic!("the purge never reached the held event");
    };
    let change = tokio::spawn({
        let (store, raised) = (store.clone(), raised.clone());
        async move {
            store
                .set_webhook_outbox_limits(
                    &raised,
                    OutboxLimitChange::Set(24 * 3600),
                    OutboxLimitChange::Set(4),
                )
                .await
                .unwrap()
                .unwrap();
            append_n(&store, &raised, 2).await;
        }
    });
    // The change either finishes or waits behind the purge.
    let queued = "SELECT COUNT(*) FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))";
    for _ in 0..250 {
        let count: i64 = sqlx::query_scalar(queued)
            .bind(purge_pid)
            .fetch_one(store.pool())
            .await
            .unwrap();
        if change.is_finished() || count > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    gate.commit().await.unwrap();
    purge.await.unwrap();
    change.await.unwrap();
    assert_eq!(
        sequences(&url, &raised).await,
        vec![2, 3, 4],
        "event 1 was past the old retention; the cap of 4 keeps the rest"
    );
}

/// A purge claims only the outboxes it prunes: one whose only event is
/// inside its limits does not hold it up, even while another transaction
/// holds its webhook row.
#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_purge_passes_an_outbox_with_nothing_to_remove() {
    in_a_database_of_its_own(purge_passes_an_outbox_with_nothing_to_remove).await;
}

#[cfg(feature = "postgres")]
async fn purge_passes_an_outbox_with_nothing_to_remove(url: String) {
    let store = Store::connect(&url, &key()).await.unwrap();
    store.set_outbox_policy(policy()).unwrap();
    let quiet = account(&store).await;
    store.save_webhook(&quiet, &settings(true)).await.unwrap();
    append_n(&store, &quiet, 1).await;
    // A webhook with no event: the purge's read finds no oldest event for
    // it and passes it over.
    let empty = account(&store).await;
    store.save_webhook(&empty, &settings(true)).await.unwrap();
    #[expect(
        clippy::disallowed_methods,
        reason = "a PostgreSQL row lock, not a store write"
    )]
    let mut gate = store.pool().begin().await.unwrap();
    sqlx::query("SELECT 1 FROM webhooks WHERE account_id = $1 FOR UPDATE")
        .bind(&quiet.0)
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let purge = store.purge_expired(PurgePolicy::default());
    let finished = tokio::time::timeout(std::time::Duration::from_secs(10), purge).await;
    gate.rollback().await.unwrap();
    assert!(
        matches!(finished, Ok(Ok(_))),
        "the purge waited for the webhook row of an outbox it had nothing to remove from, or failed: {finished:?}"
    );
    assert_eq!(sequences(&url, &quiet).await, vec![1]);
}

/// Runs `run` on a PostgreSQL database that it alone uses, created next to
/// the one in `TEST_POSTGRES_URL` and dropped when it is done, also when an
/// assertion fails, as in `data_keys.rs`. A purge goes over every outbox in
/// its database, and that one holds every suite's.
#[cfg(feature = "postgres")]
async fn in_a_database_of_its_own<F>(run: impl FnOnce(String) -> F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let server =
        std::env::var("TEST_POSTGRES_URL").unwrap_or_else(|_| panic!("set TEST_POSTGRES_URL"));
    let name = format!("postkeep_outbox_{}", uuid::Uuid::new_v4().simple());
    on_server(&server, format!("CREATE DATABASE {name}")).await;
    let (base, query) = server
        .split_once('?')
        .map_or((server.as_str(), String::new()), |(base, query)| {
            (base, format!("?{query}"))
        });
    let url = format!("{}/{name}{query}", base.rsplit_once('/').unwrap().0);
    let ran = tokio::spawn(run(url)).await;
    let drop = format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)");
    on_server(&server, drop).await;
    ran.unwrap();
}

/// Runs `sql` on the PostgreSQL server at `server`.
#[cfg(feature = "postgres")]
async fn on_server(server: &str, sql: String) {
    sqlx::any::install_default_drivers();
    let admin = AnyPoolOptions::new()
        .max_connections(1)
        .connect(server)
        .await
        .unwrap();
    sqlx::query(sqlx::AssertSqlSafe(sql))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}
