//! Data keys: made once for a tenant, stored only wrapped, and unwrapped
//! through the store's key wrapper, and the values in the data-key format
//! that the store reads. The SQLite test always runs; the PostgreSQL ones are
//! ignored unless run explicitly with `TEST_POSTGRES_URL` set, as in
//! `store.rs`. Each of them runs one group of the exercises, so that none takes
//! long on a loaded machine.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test helpers should fail loudly"
)]

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aes_gcm::aead::{Aead, Generate, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::KnownKey;
use postkeep_store::{
    AccountId, AddedFilterRule, AppendOutcome, ChangedFilterRule, DEFAULT_TENANT, DataKey,
    FilterRule, Kek, KeyWrapper, LoadedWebhook, LocalKeyWrapper, MailEvent, MasterKey, Migrations,
    NewFilterRule, OAuthAccount, PoolSettings, Provider, Reencrypted, Rewrapped, Store, StoreError,
    UpstreamPurpose, UpstreamRequest, UpstreamTokens, WatchAdvance, WebhookSettings, WrapFuture,
    Wrapped, now,
};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use sqlx::{AssertSqlSafe, Row};

const MASTER: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
/// The ID of `MASTER` in `data_keys.kek_id`.
const MASTER_ID: &str = "63f17ae25d2e14d7";
/// The ID of `other_master()`.
const OTHER_ID: &str = "387dda51afa8f203";
/// The key `[0xa5; 32]` of tenant `tenant-a` wrapped under `MASTER`: AES-256-GCM
/// with the nonce in front and `postkeep/data-key/v1/tenant-a` as associated data.
const WRAPPED: &str =
    "9yQcoWiHdSmt4UlEbiuWh_sxK8NeGCzN2CBRRMbiKf-c5kYuGjzIiZx35OwwH-rGsUeqx3_2yRk1CX50";

fn master() -> MasterKey {
    MasterKey::parse(MASTER).unwrap()
}

fn other_master() -> MasterKey {
    MasterKey::parse(&"11".repeat(32)).unwrap()
}

fn random_master() -> MasterKey {
    MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap()
}

/// A unique tenant, so tests can share one PostgreSQL database.
fn unique_tenant() -> String {
    format!("tenant-{}", uuid::Uuid::new_v4().simple())
}

/// Runs `sql` on the PostgreSQL server at `server`.
#[cfg(feature = "postgres")]
async fn on_server(server: &str, sql: String) {
    sqlx::any::install_default_drivers();
    let admin = sqlx::any::AnyPoolOptions::new()
        .max_connections(1)
        .connect(server)
        .await
        .unwrap();
    sqlx::query(AssertSqlSafe(sql))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
}

/// The database of one test: a SQLite file of its own, or the shared
/// PostgreSQL database.
struct Db {
    url: String,
    _dir: Option<tempfile::TempDir>,
}

impl Db {
    fn sqlite() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("test.db").display());
        Self {
            url,
            _dir: Some(dir),
        }
    }

    #[cfg(feature = "postgres")]
    fn postgres() -> Self {
        let url =
            std::env::var("TEST_POSTGRES_URL").unwrap_or_else(|_| panic!("set TEST_POSTGRES_URL"));
        Self { url, _dir: None }
    }

    async fn open(&self, key: &MasterKey) -> Store {
        Store::connect(&self.url, key).await.unwrap()
    }
}

/// Version 1 of a tenant's key as the table holds it: provider, KEK ID, KEK
/// version, wrapped value and creation time.
async fn stored(store: &Store, tenant: &str) -> (String, String, i64, String, i64) {
    sqlx::query_as(
        "SELECT provider, kek_id, kek_version, wrapped, created_at FROM data_keys \
         WHERE tenant = $1 AND version = 1",
    )
    .bind(tenant)
    .fetch_one(store.pool())
    .await
    .unwrap()
}

async fn rows(store: &Store, tenant: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM data_keys WHERE tenant = $1")
        .bind(tenant)
        .fetch_one(store.pool())
        .await
        .unwrap()
}

/// Stores a row in `data_keys` as it is given, or changes what the row holds
/// of the wrapping, as another process's pass would.
async fn set_key(store: &Store, tenant: &str, version: i64, kek: &Kek, wrapped: &str) {
    sqlx::query(
        "INSERT INTO data_keys (tenant, version, provider, kek_id, kek_version, wrapped, \
         created_at) VALUES ($1, $2, $3, $4, $5, $6, 1) ON CONFLICT (tenant, version) DO UPDATE \
         SET provider = excluded.provider, kek_id = excluded.kek_id, \
         kek_version = excluded.kek_version, wrapped = excluded.wrapped",
    )
    .bind(tenant)
    .bind(version)
    .bind(&kek.provider)
    .bind(&kek.id)
    .bind(kek.version)
    .bind(wrapped)
    .execute(store.pool())
    .await
    .unwrap();
}

/// A wrapper with a KEK of its own, which notes each call. It masks the key
/// and puts the tenant in front, which is all it takes to bind the two. While
/// `down`, it fails like a key service that does not answer.
#[derive(Default)]
struct Masking {
    calls: Mutex<Vec<String>>,
    down: AtomicBool,
    /// While set, only `unwrap` fails, like a key service that refuses to
    /// decrypt for now but still encrypts.
    deaf: AtomicBool,
    /// `unwrap` answers `Decrypt` for a KEK version below this one, like a
    /// service that no longer has the old versions, or `KeyWrap` if `unreachable`
    /// is set, like a service that is down for them.
    oldest_kek: AtomicI64,
    unreachable: AtomicBool,
    /// Holds every `wrap` until this many callers are in it.
    gate: Option<tokio::sync::Barrier>,
    /// The KEK that `wrap` reports instead of `current`, like a key service
    /// that rotated after `current` was answered.
    rotated: Option<Kek>,
    trouble: Option<Trouble>,
}

/// What can go wrong in a [`Masking`], besides `down`.
enum Trouble {
    /// The key service fails for this tenant only.
    FailsFor(String),
    /// `wrap` returns these bytes for a tenant instead of its key's.
    Returns(fn(&str) -> Vec<u8>),
    /// While `wrap` runs, another process stores the key `[0x77; 32]` in the
    /// tenant's row, through this pool.
    Replaces(sqlx::AnyPool),
    /// While `wrap` runs, another process stores the next version, in text
    /// that nothing unwraps, through this pool.
    Occupies(sqlx::AnyPool),
}

/// What `Masking` makes of a key: the tenant, then the key's bytes masked.
fn mask(tenant: &str, key: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{tenant}/").into_bytes();
    bytes.extend(key.iter().map(|byte| byte ^ 0x5a));
    bytes
}

impl Masking {
    fn calls(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.lock().unwrap())
    }

    fn up(&self, tenant: &str) -> Result<(), StoreError> {
        let fails = matches!(&self.trouble, Some(Trouble::FailsFor(one)) if one == tenant);
        if fails || self.down.load(Ordering::SeqCst) {
            return Err(StoreError::KeyWrap("the key service is down".to_owned()));
        }
        Ok(())
    }
}

impl KeyWrapper for Masking {
    fn current(&self) -> Kek {
        Kek {
            provider: "masking".to_owned(),
            id: "kek-1".to_owned(),
            version: 3,
        }
    }

    fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(format!("wrap {tenant}"));
            if let Some(gate) = &self.gate {
                gate.wait().await;
            }
            self.up(tenant)?;
            let bytes = match &self.trouble {
                Some(Trouble::Returns(bytes)) => bytes(tenant),
                Some(Trouble::Replaces(pool)) => {
                    let other = URL_SAFE_NO_PAD.encode(mask(tenant, &[0x77; 32]));
                    sqlx::query("UPDATE data_keys SET wrapped = $1 WHERE tenant = $2")
                        .bind(other)
                        .bind(tenant)
                        .execute(pool)
                        .await?;
                    mask(tenant, key.expose())
                }
                Some(Trouble::Occupies(pool)) => {
                    sqlx::query(
                        "INSERT INTO data_keys (tenant, version, provider, kek_id, kek_version, \
                         wrapped, created_at) SELECT $1, COALESCE(MAX(version), 0) + 1, 'other', \
                         'key', 1, '!', 1 FROM data_keys WHERE tenant = $1",
                    )
                    .bind(tenant)
                    .execute(pool)
                    .await?;
                    mask(tenant, key.expose())
                }
                _ => mask(tenant, key.expose()),
            };
            let kek = self.rotated.clone().unwrap_or_else(|| self.current());
            Ok(Wrapped { kek, bytes })
        })
    }

    fn unwrap<'a>(
        &'a self,
        tenant: &'a str,
        kek: &'a Kek,
        wrapped: &'a [u8],
    ) -> WrapFuture<'a, DataKey> {
        let call = format!("unwrap {tenant} {} {}", kek.id, kek.version);
        self.calls.lock().unwrap().push(call);
        let key = self.up(tenant).and_then(|()| {
            if self.deaf.load(Ordering::SeqCst) {
                return Err(StoreError::KeyWrap("the key service refuses".to_owned()));
            }
            if kek.version < self.oldest_kek.load(Ordering::SeqCst) {
                return Err(if self.unreachable.load(Ordering::SeqCst) {
                    StoreError::KeyWrap("the key service is down for this KEK".to_owned())
                } else {
                    StoreError::Decrypt
                });
            }
            let masked = wrapped
                .strip_prefix(format!("{tenant}/").as_bytes())
                .ok_or(StoreError::Decrypt)?;
            DataKey::from_bytes(&masked.iter().map(|byte| byte ^ 0x5a).collect::<Vec<_>>())
        });
        Box::pin(std::future::ready(key))
    }
}

#[test]
fn a_data_key_is_32_bytes_and_never_printed() {
    assert!(matches!(
        DataKey::from_bytes(&[0; 31]),
        Err(StoreError::KeyWrap(_))
    ));
    let key = DataKey::from_bytes(&[7; 32]).unwrap();
    assert_eq!(key.expose(), &[7; 32]);
    assert_eq!(format!("{key:?}"), "DataKey([REDACTED])");
}

/// A key is made on first use and read back after that, also by a process
/// that starts later; another tenant gets a key of its own.
async fn exercise_a_key_is_made_once_and_read_back(db: &Db) {
    let store = db.open(&master()).await;
    let (tenant, other) = (unique_tenant(), unique_tenant());
    let (version, key) = store.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(version, 1);
    let (version, again) = store.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, again.expose()), (1, key.expose()));
    let by_version = store.for_tenant(&tenant).data_key_version(1).await;
    assert_eq!(by_version.unwrap().expose(), key.expose());
    let missing = store.for_tenant(&tenant).data_key_version(2).await;
    assert!(matches!(missing, Err(StoreError::Decrypt)));
    assert_eq!(rows(&store, &tenant).await, 1);

    let (_, others) = store.for_tenant(&other).data_key().await.unwrap();
    assert_ne!(others.expose(), key.expose());

    store.close().await;
    let restarted = db.open(&master()).await;
    let (version, found) = restarted.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (1, key.expose()));
    assert_eq!(rows(&restarted, &tenant).await, 1);
}

/// The row names the wrapper and the master key, and holds a nonce, the key
/// encrypted and a tag, but not the key.
async fn exercise_the_row_names_its_wrapper_and_hides_the_key(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let before = now();
    let (_, key) = store.for_tenant(&tenant).data_key().await.unwrap();
    let after = now();
    let (provider, kek_id, kek_version, wrapped, created_at) = stored(&store, &tenant).await;
    let named = (provider.as_str(), kek_id.as_str(), kek_version);
    assert_eq!(named, ("local", MASTER_ID, 1));
    assert!((before..=after).contains(&created_at));

    let wrapped = URL_SAFE_NO_PAD.decode(&wrapped).unwrap();
    assert_eq!(wrapped.len(), 12 + 32 + 16);
    assert!(wrapped.windows(32).all(|window| window != key.expose()));
}

/// The master key unwraps after a restart. Another cannot, so version 1 stays
/// unreadable for it and its own key is made as version 2, beside the first
/// row, which is not touched. A previous master key unwraps what the master
/// key wrapped, and the newest version it can unwrap is the one it uses.
async fn exercise_master_keys(db: &Db) {
    let tenant = unique_tenant();
    let store = db.open(&master()).await;
    let (_, key) = store.for_tenant(&tenant).data_key().await.unwrap();
    let first = stored(&store, &tenant).await;
    store.close().await;

    let restarted = db.open(&master()).await;
    let (_, found) = restarted.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(found.expose(), key.expose());

    let stranger = db.open(&random_master()).await;
    assert_decrypt(stranger.for_tenant(&tenant).data_key_version(1).await);
    let (version, made) = stranger.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(version, 2);
    assert_ne!(made.expose(), key.expose());
    assert_eq!(rows(&stranger, &tenant).await, 2);
    assert_eq!(stored(&stranger, &tenant).await, first);

    let rotating = Store::connect_rotating(&db.url, &other_master(), &[master()])
        .await
        .unwrap();
    // Version 2 is the stranger's, so it keeps to version 1.
    let (version, found) = rotating.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (1, key.expose()));
    // Keys made while rotating are wrapped under the new master key.
    let fresh = unique_tenant();
    let (_, made) = rotating.for_tenant(&fresh).data_key().await.unwrap();
    let new_only = db.open(&other_master()).await;
    let (version, found) = new_only.for_tenant(&fresh).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (1, made.expose()));
    // Without the previous key it unwraps neither version of the other tenant.
    assert_decrypt(new_only.for_tenant(&tenant).data_key_version(1).await);
    assert_eq!(new_only.for_tenant(&tenant).data_key().await.unwrap().0, 3);
    assert_eq!(stored(&new_only, &tenant).await, first);
}

/// The tenant is associated data: a row copied to another tenant does not
/// unwrap, even in a process that holds the original. The tenant gets a key
/// of its own as version 2, and the copied row is not touched.
async fn exercise_a_copied_row_does_not_unwrap(db: &Db) {
    let store = db.open(&master()).await;
    let (from, to) = (unique_tenant(), unique_tenant());
    let (_, key) = store.for_tenant(&from).data_key().await.unwrap();
    sqlx::query(
        "INSERT INTO data_keys (tenant, version, provider, kek_id, kek_version, wrapped, \
         created_at) SELECT $1, version, provider, kek_id, kek_version, wrapped, created_at \
         FROM data_keys WHERE tenant = $2",
    )
    .bind(&to)
    .bind(&from)
    .execute(store.pool())
    .await
    .unwrap();
    let copied = stored(&store, &to).await;
    assert_decrypt(store.for_tenant(&to).data_key_version(1).await);
    let (version, made) = store.for_tenant(&to).data_key().await.unwrap();
    assert_eq!(version, 2);
    assert_ne!(made.expose(), key.expose());
    assert_eq!(rows(&store, &to).await, 2);
    assert_eq!(stored(&store, &to).await, copied);
}

/// A custom wrapper wraps and unwraps, and the master key plays no part. The
/// default wrapper does not take its keys, so it makes one of its own beside
/// them. A wrapper that cannot answer fails with `KeyWrap`, which may pass:
/// nothing is stored, and no key is made in place of one that could not be read.
async fn exercise_a_custom_wrapper(db: &Db) {
    let tenant = unique_tenant();
    let wrapper = Arc::new(Masking::default());
    let store = db.open(&master()).await.with_key_wrapper(wrapper.clone());
    let (version, key) = store.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(version, 1);
    // A new key is read back through `unwrap`, so the key in use is the one
    // `unwrap` returns, and a wrapper that cannot unwrap fails at once.
    let unwrap = format!("unwrap {tenant} kek-1 3");
    assert_eq!(wrapper.calls(), [format!("wrap {tenant}"), unwrap.clone()]);
    let (provider, kek_id, kek_version, ..) = stored(&store, &tenant).await;
    assert_eq!(
        (provider.as_str(), kek_id.as_str(), kek_version),
        ("masking", "kek-1", 3)
    );
    store.for_tenant(&tenant).data_key().await.unwrap();
    assert!(
        wrapper.calls().is_empty(),
        "a known key is not unwrapped again"
    );

    let other = db.open(&random_master()).await;
    let other = other.with_key_wrapper(wrapper.clone());
    let (_, found) = other.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(found.expose(), key.expose());
    assert_eq!(wrapper.calls(), [unwrap]);

    wrapper.down.store(true, Ordering::SeqCst);
    let fresh = unique_tenant();
    let down = db.open(&master()).await.with_key_wrapper(wrapper.clone());
    for tenant in [&tenant, &fresh] {
        let err = down.for_tenant(tenant).data_key().await.unwrap_err();
        assert!(matches!(err, StoreError::KeyWrap(_)), "{err:?}");
    }
    assert_eq!(
        (rows(&down, &tenant).await, rows(&down, &fresh).await),
        (1, 0)
    );
    wrapper.down.store(false, Ordering::SeqCst);
    let (_, found) = down.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(found.expose(), key.expose());
    assert_eq!(down.for_tenant(&fresh).data_key().await.unwrap().0, 1);

    // The default wrapper cannot unwrap version 1, and makes version 2 beside
    // it. The custom wrapper cannot unwrap that, and keeps to version 1.
    let first = stored(&store, &tenant).await;
    let local = db.open(&master()).await;
    assert_decrypt(local.for_tenant(&tenant).data_key_version(1).await);
    assert_eq!(local.for_tenant(&tenant).data_key().await.unwrap().0, 2);
    assert_eq!(stored(&local, &tenant).await, first);
    let (version, found) = down.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (1, key.expose()));
}

/// The row names the KEK that `wrap` reports, not the one `current` answers,
/// and `unwrap` is given it back.
async fn exercise_the_row_names_the_kek_that_wrapped(db: &Db) {
    let tenant = unique_tenant();
    let wrapper = Arc::new(Masking {
        rotated: Some(Kek {
            provider: "masking".to_owned(),
            id: "kek-1".to_owned(),
            version: 4,
        }),
        ..Masking::default()
    });
    assert_eq!(wrapper.current().version, 3);
    let store = db.open(&master()).await.with_key_wrapper(wrapper.clone());
    store.for_tenant(&tenant).data_key().await.unwrap();
    let (provider, kek_id, kek_version, ..) = stored(&store, &tenant).await;
    assert_eq!(
        (provider.as_str(), kek_id.as_str(), kek_version),
        ("masking", "kek-1", 4)
    );
    let calls = [format!("wrap {tenant}"), format!("unwrap {tenant} kek-1 4")];
    assert_eq!(wrapper.calls(), calls);
}

/// The local wrapper answers `Decrypt` for a key that another provider
/// wrapped, even when the KEK ID and the bytes are its own: it makes a key of
/// its own as version 2, and leaves that row as it was.
async fn exercise_another_providers_key_is_not_unwrapped(db: &Db) {
    let tenant = unique_tenant();
    let store = db.open(&master()).await;
    store.for_tenant(&tenant).data_key().await.unwrap();
    sqlx::query("UPDATE data_keys SET provider = 'other' WHERE tenant = $1")
        .bind(&tenant)
        .execute(store.pool())
        .await
        .unwrap();
    let first = stored(&store, &tenant).await;
    let fresh = db.open(&master()).await;
    assert_decrypt(fresh.for_tenant(&tenant).data_key_version(1).await);
    assert_eq!(fresh.for_tenant(&tenant).data_key().await.unwrap().0, 2);
    assert_eq!(stored(&fresh, &tenant).await, first);
}

/// The warning-level events that the thread logs, as `name=value` text, from
/// when this is made until it is dropped.
struct Warnings {
    lines: Arc<Mutex<Vec<String>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl Warnings {
    fn start() -> Self {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let guard = tracing::subscriber::set_default(Collect(lines.clone()));
        Self {
            lines,
            _guard: guard,
        }
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.lines.lock().unwrap())
    }
}

struct Collect(Arc<Mutex<Vec<String>>>);

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write as _;
        write!(self.0, "{}={value:?} ", field.name()).unwrap();
    }
}

impl tracing::Subscriber for Collect {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        // Not the database driver's, which also warns when a statement is slow.
        *metadata.level() <= tracing::Level::WARN && metadata.target().starts_with("postkeep")
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn event(&self, event: &tracing::Event<'_>) {
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0.lock().unwrap().push(fields.0);
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// Callers that all find no key to use at once each make one, store one, and
/// agree on it, whether they are separate processes or tasks of one. On first
/// use that is version 1 and nothing is logged. When the tenant has a key that
/// the wrapper cannot unwrap (`lost`), it is version 2, and only the caller
/// whose key was stored logs a warning, with the tenant and version.
async fn race_for_a_key(db: &Db, lost: bool) {
    const CALLERS: usize = 6;
    // The version it ends with, which is also the number of rows.
    let (expected, warnings) = (1 + i64::from(lost), Warnings::start());
    for separate in [true, false] {
        let tenant = unique_tenant();
        if lost {
            // Made under the master key, which the wrapper below lacks.
            let first = db.open(&master()).await;
            first.for_tenant(&tenant).data_key().await.unwrap();
        }
        let wrapper = Arc::new(Masking {
            gate: Some(tokio::sync::Barrier::new(CALLERS)),
            ..Masking::default()
        });
        let shared = db.open(&master()).await.with_key_wrapper(wrapper.clone());
        let mut tasks = Vec::new();
        for _ in 0..CALLERS {
            let store = if separate {
                db.open(&master()).await.with_key_wrapper(wrapper.clone())
            } else {
                shared.clone()
            };
            let tenant = tenant.clone();
            tasks.push(tokio::spawn(async move {
                let (version, key) = store.for_tenant(&tenant).data_key().await.unwrap();
                (version, *key.expose())
            }));
        }
        let mut found = Vec::new();
        for task in tasks {
            found.push(task.await.unwrap());
        }
        assert!(found.iter().all(|one| *one == found[0]), "the keys differ");
        assert_eq!(found[0].0, expected);
        assert_eq!(rows(&shared, &tenant).await, expected);
        let calls = wrapper.calls();
        let wraps = calls.iter().filter(|call| call.starts_with("wrap")).count();
        assert_eq!(wraps, CALLERS, "every caller made a key: {calls:?}");
        let logged = warnings.take();
        assert_eq!(logged.len(), usize::from(lost), "{logged:?}");
        if lost {
            assert!(logged[0].contains(&tenant), "{logged:?}");
            assert!(logged[0].contains("version=2 "), "{logged:?}");
            // The event has these fields and no other, so no key among them.
            let parts = logged[0].split(' ').filter_map(|part| part.split_once('='));
            let mut names: Vec<_> = parts.map(|(name, _)| name).collect();
            names.sort_unstable();
            assert_eq!(names, ["message", "tenant", "version"], "{logged:?}");
        }
    }
}

async fn exercise_concurrent_first_use(db: &Db) {
    race_for_a_key(db, false).await;
}

async fn exercise_two_processes_without_a_key_agree_on_the_new_one(db: &Db) {
    race_for_a_key(db, true).await;
}

/// A store with a new master key alone cannot unwrap a tenant's key, so it
/// makes one as the next version, and finds it again after a restart. A value
/// under version 1 stays unreadable for it and readable for the old master
/// key, and a store that holds both keys uses the newest.
async fn exercise_a_new_master_key_alone_gets_a_new_data_key(db: &Db) {
    let tenant = unique_tenant();
    let old = db.open(&master()).await;
    let fixture = fill(db, &old, &tenant).await;
    to_v2(&old, &fixture, |_, owner| owner == tenant).await;
    let (_, first) = old.for_tenant(&tenant).data_key().await.unwrap();
    let before = stored(&old, &tenant).await;

    let new_only = db.open(&other_master()).await;
    let (version, second) = new_only.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(version, 2);
    assert_ne!(second.expose(), first.expose());
    assert_eq!(rows(&new_only, &tenant).await, 2);
    assert_eq!(stored(&new_only, &tenant).await, before);
    assert_decrypt(new_only.for_tenant(&tenant).data_key_version(1).await);
    assert_decrypt(new_only.credentials(&fixture.imap).await);
    new_only.close().await;

    let restarted = db.open(&other_master()).await;
    let (version, found) = restarted.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (2, second.expose()));
    assert_eq!(rows(&restarted, &tenant).await, 2);

    let (version, found) = old.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (1, first.expose()));
    check_reads(&old, &fixture).await;
    let both = Store::connect_rotating(&db.url, &other_master(), &[master()])
        .await
        .unwrap();
    let (version, found) = both.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (2, second.expose()));
    check_reads(&both, &fixture).await;
}

/// A stray version, made by a process with another master key, does not move
/// the right one. Each process keeps to the newest version it can unwrap and
/// adds none, however often both call and whenever they start, so the versions
/// do not climb. A third key adds one version, and no more.
async fn exercise_a_stray_key_does_not_move_the_right_one(db: &Db) {
    let (tenant, warnings) = (unique_tenant(), Warnings::start());
    let (good, stray) = (db.open(&master()).await, db.open(&other_master()).await);
    let (_, mine) = good.for_tenant(&tenant).data_key().await.unwrap();
    let (version, theirs) = stray.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(version, 2);
    for _ in 0..3 {
        let (version, found) = good.for_tenant(&tenant).data_key().await.unwrap();
        assert_eq!((version, found.expose()), (1, mine.expose()));
        let (version, found) = stray.for_tenant(&tenant).data_key().await.unwrap();
        assert_eq!((version, found.expose()), (2, theirs.expose()));
    }
    assert_eq!(rows(&good, &tenant).await, 2);
    for (key, expected) in [(master(), 1), (other_master(), 2), (random_master(), 3)] {
        let process = db.open(&key).await;
        let (version, _) = process.for_tenant(&tenant).data_key().await.unwrap();
        assert_eq!(version, expected);
    }
    // The first two keep their versions, though a third key has joined them.
    for (store, expected) in [(&good, 1), (&stray, 2)] {
        let (version, _) = store.for_tenant(&tenant).data_key().await.unwrap();
        assert_eq!(version, expected);
    }
    assert_eq!(rows(&good, &tenant).await, 3);
    // One warning for each version added, not one for each call.
    assert_eq!(warnings.take().len(), 2);
}

/// A store that has unwrapped nothing yet, behind `wrapper`.
async fn cold(db: &Db, wrapper: &Arc<Masking>) -> Store {
    db.open(&master()).await.with_key_wrapper(wrapper.clone())
}

/// A wrapper that fails with `KeyWrap` is no reason to pass over a key or to
/// make one: not for the newest row, not for an older row behind one that
/// cannot be unwrapped, and not when only `unwrap` fails while `wrap` works,
/// for every KEK or for the old ones. When it answers again, the old key is back.
async fn exercise_a_failing_wrapper_never_gets_a_new_key(db: &Db) {
    let tenant = unique_tenant();
    let wrapper = Arc::new(Masking::default());
    let newer = Arc::new(Masking {
        rotated: Some(kek(4)),
        ..Masking::default()
    });
    newer.oldest_kek.store(4, Ordering::SeqCst);
    newer.unreachable.store(true, Ordering::SeqCst);
    let store = cold(db, &wrapper).await;
    let (_, key) = store.for_tenant(&tenant).data_key().await.unwrap();
    for count in 1..=2 {
        if count == 2 {
            // A newer row that no wrapper unwraps: its text is not base64.
            set_key(&store, &tenant, 2, &kek(3), "!").await;
        }
        for (down, deaf) in [(true, false), (false, true)] {
            wrapper.down.store(down, Ordering::SeqCst);
            wrapper.deaf.store(deaf, Ordering::SeqCst);
            let failing = cold(db, &wrapper).await;
            assert_key_wrap(failing.for_tenant(&tenant).data_key().await);
            assert_eq!(rows(&failing, &tenant).await, count);
        }
        // The KEK of the stored keys is out of reach, and a newer one is not.
        let failing = cold(db, &newer).await;
        assert_key_wrap(failing.for_tenant(&tenant).data_key().await);
        assert_eq!(rows(&failing, &tenant).await, count);
        wrapper.deaf.store(false, Ordering::SeqCst);
        let again = cold(db, &wrapper).await;
        let (version, found) = again.for_tenant(&tenant).data_key().await.unwrap();
        assert_eq!((version, found.expose()), (1, key.expose()));
        assert_eq!(rows(&again, &tenant).await, count);
    }
}

/// A row that answered `Decrypt` is asked about again once it has changed, and
/// the next call uses it and adds nothing. That holds when a pass wraps it
/// again under this process's key, which changes its KEK and its text; when
/// only the KEK changes; and when only the text changes.
async fn exercise_a_rewrapped_row_is_tried_again(db: &Db) {
    // Version 2 is another process's, under a master key this store lacks.
    let tenant = unique_tenant();
    let ours = db.open(&other_master()).await;
    ours.for_tenant(&tenant).data_key().await.unwrap();
    let other = db.open(&master()).await;
    let (version, theirs) = other.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!(version, 2);
    assert_eq!(ours.for_tenant(&tenant).data_key().await.unwrap().0, 1);
    let wrapper = LocalKeyWrapper::new(&other_master(), &[]);
    let again = wrapper.wrap(&tenant, &theirs).await.unwrap();
    let text = URL_SAFE_NO_PAD.encode(&again.bytes);
    set_key(&ours, &tenant, 2, &again.kek, &text).await;
    let (version, found) = ours.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (2, theirs.expose()));
    assert_eq!(rows(&ours, &tenant).await, 2);

    // Only the KEK changes: the wrapper has dropped KEK 2, and has KEK 3.
    let tenant = unique_tenant();
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    store.for_tenant(&tenant).data_key().await.unwrap();
    let text = URL_SAFE_NO_PAD.encode(mask(&tenant, &[0x33; 32]));
    set_key(&store, &tenant, 2, &kek(2), &text).await;
    wrapper.oldest_kek.store(3, Ordering::SeqCst);
    assert_eq!(store.for_tenant(&tenant).data_key().await.unwrap().0, 1);
    set_key(&store, &tenant, 2, &kek(3), &text).await;
    let (version, found) = store.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (2, &[0x33; 32]));
    assert_eq!(rows(&store, &tenant).await, 2);

    // Only the text changes.
    let tenant = unique_tenant();
    let store = cold(db, &Arc::new(Masking::default())).await;
    store.for_tenant(&tenant).data_key().await.unwrap();
    set_key(&store, &tenant, 2, &kek(3), "!").await;
    assert_eq!(store.for_tenant(&tenant).data_key().await.unwrap().0, 1);
    let text = URL_SAFE_NO_PAD.encode(mask(&tenant, &[0x44; 32]));
    set_key(&store, &tenant, 2, &kek(3), &text).await;
    let (version, found) = store.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (2, &[0x44; 32]));
    assert_eq!(rows(&store, &tenant).await, 2);
}

/// A row that answered `Decrypt` is not asked about again while it stays as it
/// is: over several calls the wrapper sees one `unwrap` for it, and one for the
/// older row that is used. That row's key is used only while the row is as it
/// was, not once another key is in it.
async fn exercise_a_dead_row_is_asked_once(db: &Db) {
    let tenant = unique_tenant();
    let wrapper = Arc::new(Masking::default());
    let first = cold(db, &wrapper).await;
    let (_, key) = first.for_tenant(&tenant).data_key().await.unwrap();
    // The default wrapper cannot unwrap version 1, and adds version 2, which
    // the wrapper above cannot unwrap.
    let local = db.open(&master()).await;
    assert_eq!(local.for_tenant(&tenant).data_key().await.unwrap().0, 2);
    wrapper.calls();
    let store = cold(db, &wrapper).await;
    for _ in 0..4 {
        let (version, found) = store.for_tenant(&tenant).data_key().await.unwrap();
        assert_eq!((version, found.expose()), (1, key.expose()));
    }
    let asked = [
        format!("unwrap {tenant} {MASTER_ID} 1"),
        format!("unwrap {tenant} kek-1 3"),
    ];
    assert_eq!(wrapper.calls(), asked);

    let text = URL_SAFE_NO_PAD.encode(mask(&tenant, &[0x55; 32]));
    set_key(&store, &tenant, 1, &kek(3), &text).await;
    let (version, found) = store.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (1, &[0x55; 32]));
}

/// A wrapper that cannot unwrap what it has just wrapped, for good or for now,
/// gets no key stored: its calls fail with `KeyWrap` and leave no row and no
/// warning, in a new store too. One that is wrong like that for a moment adds
/// nothing then, and one version above the highest when it is right again.
async fn exercise_a_wrapper_that_cannot_read_its_keys_stores_none(db: &Db) {
    let (tenant, warnings) = (unique_tenant(), Warnings::start());
    let broken = Arc::new(Masking {
        trouble: Some(Trouble::Returns(|_| vec![0; 5])),
        ..Masking::default()
    });
    let deaf = Arc::new(Masking::default());
    deaf.deaf.store(true, Ordering::SeqCst);
    for wrapper in [&broken, &deaf] {
        for store in [cold(db, wrapper).await, cold(db, wrapper).await] {
            for _ in 0..2 {
                assert_key_wrap(store.for_tenant(&tenant).data_key().await);
            }
            assert_eq!(rows(&store, &tenant).await, 0);
        }
    }

    // Versions 1 and 5 are under the master key, which this wrapper lacks.
    let (tenant, made) = (unique_tenant(), db.open(&master()).await);
    made.for_tenant(&tenant).data_key().await.unwrap();
    let (kek, (.., text, _)) = (kek_in(&made, &tenant).await, stored(&made, &tenant).await);
    set_key(&made, &tenant, 5, &kek, &text).await;
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    wrapper.oldest_kek.store(i64::MAX, Ordering::SeqCst);
    for _ in 0..2 {
        assert_key_wrap(store.for_tenant(&tenant).data_key().await);
    }
    assert_eq!(rows(&store, &tenant).await, 2);
    assert_eq!(warnings.take(), Vec::<String>::new());
    wrapper.oldest_kek.store(0, Ordering::SeqCst);
    assert_eq!(store.for_tenant(&tenant).data_key().await.unwrap().0, 6);
    assert_eq!(rows(&store, &tenant).await, 3);
    assert_eq!(warnings.take().len(), 1);

    // Another process stores each next version first, in text that nothing
    // here unwraps: three keys are made, and then there is an error.
    let trouble = Trouble::Occupies(made.pool().clone());
    let wrapper = Arc::new(Masking {
        trouble: Some(trouble),
        ..Masking::default()
    });
    let (tenant, store) = (unique_tenant(), cold(db, &wrapper).await);
    assert_key_wrap(store.for_tenant(&tenant).data_key().await);
    let calls = wrapper.calls();
    let wraps = calls.iter().filter(|call| call.starts_with("wrap")).count();
    assert_eq!((wraps, rows(&store, &tenant).await), (3, 3), "{calls:?}");
    // The keys that lost are not kept for reading.
    assert_decrypt(store.for_tenant(&tenant).data_key_version(1).await);
}

/// A key in hand still reads after another process wraps its row again under a
/// key this one lacks, though this process then passes over the row and adds one.
async fn exercise_a_key_in_hand_is_read_with_after_its_row_changes(db: &Db) {
    let (tenant, store) = (unique_tenant(), db.open(&master()).await);
    let (_, key) = store.for_tenant(&tenant).data_key().await.unwrap();
    let other = LocalKeyWrapper::new(&other_master(), &[]);
    let again = other.wrap(&tenant, &key).await.unwrap();
    let text = URL_SAFE_NO_PAD.encode(&again.bytes);
    set_key(&store, &tenant, 1, &again.kek, &text).await;
    assert_eq!(store.for_tenant(&tenant).data_key().await.unwrap().0, 2);
    let kept = store.for_tenant(&tenant).data_key_version(1).await.unwrap();
    assert_eq!(kept.expose(), key.expose());
}

/// A row that answered `Decrypt` for a moment, and that a read has unwrapped
/// since, is used by the next call: no version is added beside it.
async fn exercise_a_dead_row_that_a_read_unwrapped_is_used_again(db: &Db) {
    let (tenant, wrapper) = (unique_tenant(), Arc::new(Masking::default()));
    let first = cold(db, &wrapper).await;
    let (_, key) = first.for_tenant(&tenant).data_key().await.unwrap();
    let store = cold(db, &wrapper).await;
    wrapper.oldest_kek.store(i64::MAX, Ordering::SeqCst);
    assert_key_wrap(store.for_tenant(&tenant).data_key().await);
    wrapper.oldest_kek.store(0, Ordering::SeqCst);
    store.for_tenant(&tenant).data_key_version(1).await.unwrap();
    let (version, found) = store.for_tenant(&tenant).data_key().await.unwrap();
    assert_eq!((version, found.expose()), (1, key.expose()));
    assert_eq!(rows(&store, &tenant).await, 1);
}

// Values in the data-key format (`v2.`). Every writer makes them, and these tests
// also seal values themselves, and open what the writers made, from the documented
// layout: `v2.<version>.<base64url of the nonce and the ciphertext>`, AES-256-GCM
// under the tenant's key, with `postkeep/v2/<tenant>/<table>.<column>/<row key>`
// as associated data.

/// The table, the encrypted column, and the column that keys the table's rows.
type Column = (&'static str, &'static str, &'static str);

const PASSWORD: Column = ("accounts", "password_ciphertext", "id");
const AUTH: Column = ("webhooks", "auth_header_value_ciphertext", "account_id");
const SIGNING: Column = ("webhooks", "signing_secret_ciphertext", "account_id");
const REFRESH: Column = ("upstream_tokens", "refresh_token_ciphertext", "account_id");
const ACCESS: Column = ("upstream_tokens", "access_token_ciphertext", "account_id");
const VERIFIER: Column = ("upstream_requests", "verifier_ciphertext", "state_hash");
const REQUEST_ID: Column = ("upstream_requests", "request_id_ciphertext", "state_hash");
const CONTINUATION: Column = ("upstream_requests", "continuation_ciphertext", "state_hash");
const PAYLOAD: Column = ("mail_events", "payload_ciphertext", "id");
/// Not in `COLUMNS`: no earlier version wrote it, so no fixture has it as a v1 value.
const PATTERN: Column = ("webhook_filter_rules", "pattern_ciphertext", "id");

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

fn unique(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4().simple())
}

fn assert_decrypt<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    let err = result.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
}

fn assert_key_wrap<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    let err = result.unwrap_err();
    assert!(matches!(err, StoreError::KeyWrap(_)), "{err:?}");
}

fn assert_newer<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    let err = result.unwrap_err();
    assert!(matches!(err, StoreError::NewerFormat), "{err:?}");
}

async fn text(store: &Store, (table, column, key): Column, row: &str) -> String {
    let sql = format!("SELECT {column} AS stored FROM {table} WHERE {key} = $1");
    let found = sqlx::query(AssertSqlSafe(sql.as_str()))
        .bind(row)
        .fetch_one(store.pool())
        .await
        .unwrap();
    found.try_get("stored").unwrap()
}

async fn set_text(store: &Store, (table, column, key): Column, row: &str, text: &str) {
    let sql = format!("UPDATE {table} SET {column} = $1 WHERE {key} = $2");
    sqlx::query(AssertSqlSafe(sql.as_str()))
        .bind(text)
        .bind(row)
        .execute(store.pool())
        .await
        .unwrap();
}

/// The tenant as the associated data spells it: `%` and `/` percent-encoded.
fn escape(tenant: &str) -> String {
    let mut escaped = String::new();
    for character in tenant.chars() {
        match character {
            '%' => escaped.push_str("%25"),
            '/' => escaped.push_str("%2F"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// `plaintext` sealed for `row_key` of `column` in `tenant`, with version 1 of
/// the tenant's key.
async fn seal(
    store: &Store,
    tenant: &str,
    (table, column, _): Column,
    row_key: &str,
    plaintext: &str,
) -> String {
    let (version, key) = store.for_tenant(tenant).data_key().await.unwrap();
    assert_eq!(version, 1);
    let context = format!("postkeep/v2/{}/{table}.{column}/{row_key}", escape(tenant));
    let nonce = Nonce::try_generate().unwrap();
    let payload = Payload {
        msg: plaintext.as_bytes(),
        aad: context.as_bytes(),
    };
    let sealed = Aes256Gcm::new(key.expose().into())
        .encrypt(&nonce, payload)
        .unwrap();
    let blob = [nonce.as_slice(), &sealed].concat();
    format!("v2.{version}.{}", URL_SAFE_NO_PAD.encode(blob))
}

/// What the v2 value `stored` of `row_key` in `column` of `tenant` holds,
/// opened from the documented layout alone, as `seal` makes it.
async fn unseal(
    store: &Store,
    tenant: &str,
    (table, column, _): Column,
    row_key: &str,
    stored: &str,
) -> String {
    let rest = stored.strip_prefix("v2.").unwrap();
    let (version, blob) = rest.split_once('.').unwrap();
    let scoped = store.for_tenant(tenant);
    let key = scoped.data_key_version(version.parse().unwrap()).await;
    let blob = URL_SAFE_NO_PAD.decode(blob).unwrap();
    let (nonce, sealed) = blob.split_at(12);
    let context = format!("postkeep/v2/{}/{table}.{column}/{row_key}", escape(tenant));
    let payload = Payload {
        msg: sealed,
        aad: context.as_bytes(),
    };
    let opened = Aes256Gcm::new(key.unwrap().expose().into())
        .decrypt(&Nonce::try_from(nonce).unwrap(), payload)
        .unwrap();
    String::from_utf8(opened).unwrap()
}

/// The texts stored for the password and the webhook secrets of `account`.
async fn written(store: &Store, account: &AccountId) -> Vec<String> {
    let mut found = Vec::new();
    for column in [PASSWORD, AUTH, SIGNING] {
        found.push(text(store, column, &account.0).await);
    }
    found
}

/// The refresh token of `account` put back as a v1 value under the master key,
/// as an earlier build stored it.
async fn put_v1_refresh(store: &Store, account: &AccountId, plaintext: &str) {
    let known = KnownKey::from_hex(MASTER);
    let (column, id) = (common::REFRESH, &account.0);
    column.put(store, &known, id, id, plaintext).await;
}

/// The columns, in the order of `common`'s.
const COLUMNS: [Column; 9] = [
    PASSWORD,
    AUTH,
    SIGNING,
    REFRESH,
    ACCESS,
    VERIFIER,
    REQUEST_ID,
    CONTINUATION,
    PAYLOAD,
];

/// The values of `fixture` in the columns `which` picks, put back as v1 values
/// under the master key, as an earlier version stored them.
async fn put_v1(store: &Store, fixture: &Fixture, which: impl Fn(Column) -> bool) {
    let known = KnownKey::from_hex(MASTER);
    let v1 = [
        common::PASSWORD,
        common::AUTH,
        common::SECRET,
        common::REFRESH,
        common::ACCESS,
        common::VERIFIER,
        common::REQUEST_ID,
        common::CONTINUATION,
        common::PAYLOAD,
    ];
    for (column, row, row_key, plaintext, _) in &fixture.values {
        if which(*column) {
            let at = COLUMNS.iter().position(|one| one == column).unwrap();
            // An event's v1 text is bound to its account as well as its ID.
            let owner = if *column == PAYLOAD {
                format!("{}/{row}", fixture.imap.0)
            } else {
                row_key.clone()
            };
            v1[at].put(store, &known, row, &owner, plaintext).await;
        }
    }
}

/// Five columns of `fixture` as v1 values, and how many values that makes.
async fn put_some_v1(store: &Store, fixture: &Fixture) -> u64 {
    let v1 = [PAYLOAD, REFRESH, ACCESS, VERIFIER, CONTINUATION];
    put_v1(store, fixture, |column| v1.contains(&column)).await;
    let mut found = 0;
    for (column, row, ..) in &fixture.values {
        found += u64::from(text(store, *column, row).await.starts_with("v1."));
    }
    found
}

fn webhook(url: &str, auth: &str, signing: &str) -> WebhookSettings {
    WebhookSettings {
        enabled: true,
        url: url.to_owned(),
        auth_header: Some(("authorization".to_owned(), secret(auth))),
        signing: true,
        signing_secret: secret(signing),
        include_sender: true,
    }
}

fn tokens(refresh: &str) -> UpstreamTokens {
    UpstreamTokens {
        refresh_token: secret(refresh),
        access_token: Some(secret("access-1")),
        access_expires_at: None,
        scope: "Mail.Read".to_owned(),
    }
}

const TTL: Duration = Duration::from_mins(10);

fn request(purpose: UpstreamPurpose) -> UpstreamRequest {
    UpstreamRequest {
        provider: Provider::Gmail,
        purpose,
        code_verifier: secret("verifier-1"),
        binding_hash: "binding".to_owned(),
    }
}

/// A sign-in that an embedding started for `tenant`.
fn continued(tenant: &str) -> UpstreamPurpose {
    UpstreamPurpose::Continue {
        tenant: tenant.to_owned(),
        continuation: secret("connect-1"),
    }
}

/// Saves a sign-in of `purpose` for `state` through `store`, as the writer stores it.
async fn try_save(
    store: &Store,
    state: &str,
    purpose: UpstreamPurpose,
    ttl: Duration,
) -> Result<(), StoreError> {
    let request = request(purpose);
    store.save_upstream_request(state, &request, ttl).await
}

/// A sign-in of `tenant` whose values the test sealed itself as v2 values of the
/// tenant, whatever format the writer uses.
async fn save_v2(store: &Store, state: &str, tenant: &str, ttl: Duration) {
    try_save(store, state, continued(tenant), ttl)
        .await
        .unwrap();
    let hash = common::state_hash(state);
    for (column, plaintext) in [(VERIFIER, "verifier-1"), (CONTINUATION, "connect-1")] {
        let sealed = seal(store, tenant, column, &hash, plaintext).await;
        set_text(store, column, &hash, &sealed).await;
    }
}

async fn save(store: &Store, state: &str, purpose: UpstreamPurpose) {
    try_save(store, state, purpose, TTL).await.unwrap();
}

/// Whether a sign-in is stored for `state`.
async fn present(store: &Store, state: &str) -> bool {
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM upstream_requests WHERE state_hash = $1")
            .bind(common::state_hash(state))
            .fetch_one(store.pool())
            .await
            .unwrap();
    rows == 1
}

/// The purpose of a sign-in as text, with the secrets it holds.
fn describe(purpose: &UpstreamPurpose) -> String {
    match purpose {
        UpstreamPurpose::Authorize { request_id } => {
            format!("authorize {}", request_id.expose_secret())
        }
        UpstreamPurpose::Account => "account".to_owned(),
        UpstreamPurpose::Continue {
            tenant,
            continuation,
        } => format!("continue {tenant} {}", continuation.expose_secret()),
    }
}

/// A stored value: its column and row, the row key that a v2 value binds
/// (not always the row), what it holds, and the tenant of its row.
type Value = (Column, String, String, &'static str, String);

fn value(column: Column, row: &str, row_key: &str, plaintext: &'static str, tenant: &str) -> Value {
    (
        column,
        row.to_owned(),
        row_key.to_owned(),
        plaintext,
        tenant.to_owned(),
    )
}

struct Fixture {
    email: String,
    imap: AccountId,
    event: MailEvent,
    oauth: AccountId,
    states: Vec<String>,
    values: Vec<Value>,
}

/// Rows in all nine columns, made by the public writers of `store`. The sign-ins
/// that no tenant started (the first two) belong to the default tenant, whose key
/// the shared PostgreSQL database must keep to one master key and the local
/// wrapper: they are saved through a store of that kind, whatever `store` is.
async fn fill(db: &Db, store: &Store, tenant: &str) -> Fixture {
    let scoped = store.for_tenant(tenant);
    let email = format!("{}@example.com", unique("imap"));
    let imap = scoped
        .upsert_account(&email, &secret("app-password"))
        .await
        .unwrap()
        .id;
    let hook = WebhookSettings {
        enabled: true,
        url: "https://hooks.example/h".to_owned(),
        auth_header: Some(("authorization".to_owned(), secret("Bearer one"))),
        signing: true,
        signing_secret: secret("whsec_one"),
        include_sender: true,
    };
    store.save_webhook(&imap, &hook).await.unwrap();
    let appended = store.append_mail_event(&imap, "{}", None).await.unwrap();
    let event = appended.stored().unwrap();
    let account = OAuthAccount {
        provider: Provider::Graph,
        subject: &unique("subject"),
        email: &format!("{}@example.com", unique("oauth")),
    };
    let oauth = scoped
        .upsert_oauth_account(&account, &tokens("refresh-1"))
        .await
        .unwrap()
        .id;
    let mut values = vec![
        value(PASSWORD, &imap.0, &email, "app-password", tenant),
        value(AUTH, &imap.0, &imap.0, "Bearer one", tenant),
        value(SIGNING, &imap.0, &imap.0, "whsec_one", tenant),
        value(PAYLOAD, &event.id, &event.id, "{}", tenant),
        value(REFRESH, &oauth.0, &oauth.0, "refresh-1", tenant),
        value(ACCESS, &oauth.0, &oauth.0, "access-1", tenant),
    ];
    // Only a sign-in that an embedding started has a tenant. The others belong
    // to the default one.
    let authorize = UpstreamPurpose::Authorize {
        request_id: secret("request-1"),
    };
    let sign_ins = [
        (authorize, DEFAULT_TENANT, Some((REQUEST_ID, "request-1"))),
        (UpstreamPurpose::Account, DEFAULT_TENANT, None),
        (continued(tenant), tenant, Some((CONTINUATION, "connect-1"))),
    ];
    let common = db.open(&master()).await;
    let mut states = Vec::new();
    for (purpose, owner, extra) in sign_ins {
        let state = unique("state");
        let writer = if owner == DEFAULT_TENANT {
            &common
        } else {
            store
        };
        save(writer, &state, purpose).await;
        let hash = URL_SAFE_NO_PAD.encode(Sha256::digest(state.as_bytes()));
        values.push(value(VERIFIER, &hash, &hash, "verifier-1", owner));
        if let Some((column, plaintext)) = extra {
            values.push(value(column, &hash, &hash, plaintext, owner));
        }
        states.push(state);
    }
    common.close().await;
    Fixture {
        email,
        imap,
        event,
        oauth,
        states,
        values,
    }
}

/// Rewrites the values that `which` picks, by column and tenant, as v2 values
/// of their rows' tenants.
async fn to_v2(store: &Store, fixture: &Fixture, which: impl Fn(Column, &str) -> bool + Sync) {
    for (column, row, row_key, plaintext, tenant) in &fixture.values {
        if which(*column, tenant) {
            let sealed = seal(store, tenant, *column, row_key, plaintext).await;
            set_text(store, *column, row, &sealed).await;
        }
    }
}

/// Every public reader but the sign-in one returns what `fill` wrote.
async fn check_reads(store: &Store, fixture: &Fixture) {
    let found = store.credentials(&fixture.imap).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "app-password");
    let hook = store.webhook(&fixture.imap).await.unwrap().unwrap();
    let auth = hook.settings.auth_header.unwrap().1;
    assert_eq!(auth.expose_secret(), "Bearer one");
    assert_eq!(hook.settings.signing_secret.expose_secret(), "whsec_one");
    let pending = store.pending_mail_events(&fixture.imap, 10).await.unwrap();
    assert_eq!(pending.events, std::slice::from_ref(&fixture.event));
    let found = store
        .upstream_tokens(&fixture.oauth)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.tokens.refresh_token.expose_secret(), "refresh-1");
    assert_eq!(
        found.tokens.access_token.unwrap().expose_secret(),
        "access-1"
    );
}

/// The sign-in reader, which removes what it returns.
async fn check_sign_ins(store: &Store, fixture: &Fixture, tenant: &str) {
    let expected = [
        "authorize request-1".to_owned(),
        "account".to_owned(),
        format!("continue {tenant} connect-1"),
    ];
    for (state, expected) in fixture.states.iter().zip(expected) {
        let taken = store.take_upstream_request(state).await.unwrap().unwrap();
        assert_eq!(describe(&taken.purpose), expected);
        assert_eq!(taken.code_verifier.expose_secret(), "verifier-1");
    }
}

/// Every public writer stores v2 values and makes the tenant's key for them: no
/// column of the nine is v1 any more, which only an earlier version wrote. They
/// open from the documented layout alone, bound to the tenant of their row. Then
/// all nine columns open as v2 values that the test sealed, read through a store
/// that is not scoped to the tenant, and a row can hold both formats.
async fn exercise_v2_values_open_in_every_column(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    assert_eq!(fixture.values.len(), 11);
    let columns: Vec<_> = fixture.values.iter().map(|value| value.0).collect();
    for column in COLUMNS {
        assert!(columns.contains(&column), "no value in {column:?}");
    }
    for (column, row, row_key, plaintext, owner) in &fixture.values {
        let stored = text(&store, *column, row).await;
        assert!(
            stored.starts_with("v2.1."),
            "{column:?} is not v2: {stored}"
        );
        let opened = unseal(&store, owner, *column, row_key, &stored).await;
        assert_eq!(opened, *plaintext, "{column:?}");
    }
    assert_eq!(rows(&store, &tenant).await, 1);
    check_reads(&store, &fixture).await;

    // The refresh token put back under the master key: its row holds both
    // formats.
    put_v1_refresh(&store, &fixture.oauth, "refresh-1").await;
    let access = text(&store, ACCESS, &fixture.oauth.0).await;
    assert!(access.starts_with("v2.1."), "{access}");
    check_reads(&store, &fixture).await;
    // A refresh token that is v1 text is replaced by a v2 one.
    let oauth = &fixture.oauth;
    assert_refresh_replaced(&store, &tenant, oauth, "refresh-1", "refresh-2").await;

    to_v2(&store, &fixture, |_, _| true).await;
    for (column, row, ..) in &fixture.values {
        let stored = text(&store, *column, row).await;
        assert!(stored.starts_with("v2.1."), "{column:?}");
    }
    assert_eq!(store.tenant(), "default");
    check_reads(&store, &fixture).await;
    check_sign_ins(&store, &fixture, &tenant).await;

    let oauth = &fixture.oauth;
    assert_refresh_replaced(&store, &tenant, oauth, "refresh-1", "refresh-2").await;
}

/// A v2 value copied to another row or column does not open, and opens again
/// where it belongs.
async fn exercise_a_moved_v2_value_does_not_open(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let (one, two) = (
        fill(db, &store, &tenant).await,
        fill(db, &store, &tenant).await,
    );
    let (a, b) = (&one.imap, &two.imap);
    for fixture in [&one, &two] {
        to_v2(&store, fixture, |_, owner| owner == tenant).await;
    }

    let kept = text(&store, AUTH, &b.0).await;
    set_text(&store, AUTH, &b.0, &text(&store, AUTH, &a.0).await).await;
    assert_decrypt(store.webhook(b).await);
    set_text(&store, AUTH, &b.0, &kept).await;
    store.webhook(b).await.unwrap().unwrap();

    let kept = text(&store, AUTH, &a.0).await;
    set_text(&store, AUTH, &a.0, &text(&store, SIGNING, &a.0).await).await;
    assert_decrypt(store.webhook(a).await);
    set_text(&store, AUTH, &a.0, &kept).await;
}

/// A wrapper with one key for every tenant, so that only the associated data
/// can tell tenants apart. `wrap` ignores the key it is given: the store uses
/// what `unwrap` returns, so every tenant ends up with this one.
struct OneKey;

impl KeyWrapper for OneKey {
    fn current(&self) -> Kek {
        Kek {
            provider: "one".to_owned(),
            id: "key".to_owned(),
            version: 1,
        }
    }

    fn wrap<'a>(&'a self, _tenant: &'a str, _key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
        let kek = self.current();
        let wrapped = Wrapped {
            kek,
            bytes: vec![0x42; 32],
        };
        Box::pin(std::future::ready(Ok(wrapped)))
    }

    fn unwrap<'a>(
        &'a self,
        _tenant: &'a str,
        _kek: &'a Kek,
        wrapped: &'a [u8],
    ) -> WrapFuture<'a, DataKey> {
        Box::pin(std::future::ready(DataKey::from_bytes(wrapped)))
    }
}

/// The tenant is part of the associated data, and its name cannot run into the
/// rest of it. With one key for every tenant, a value does not open in the row
/// of another tenant: not when the tenant names and the emails split the same
/// text in two ways, and not when its account moves to the other tenant.
async fn exercise_tenants_are_told_apart_by_the_associated_data(db: &Db) {
    let store = db.open(&master()).await.with_key_wrapper(Arc::new(OneKey));
    let short = unique_tenant();
    let long = format!("{short}/accounts.password_ciphertext");
    let tail = format!("{}@example.com", unique("x"));
    let email_a = format!("accounts.password_ciphertext/{tail}");
    let a = store
        .for_tenant(&short)
        .upsert_account(&email_a, &secret("pw"))
        .await
        .unwrap()
        .id;
    let b = store
        .for_tenant(&long)
        .upsert_account(&tail, &secret("pw"))
        .await
        .unwrap()
        .id;
    let sealed_a = seal(&store, &short, PASSWORD, &email_a, "pw-a").await;
    let sealed_b = seal(&store, &long, PASSWORD, &tail, "pw-b").await;
    set_text(&store, PASSWORD, &a.0, &sealed_a).await;
    set_text(&store, PASSWORD, &b.0, &sealed_b).await;
    let found = store.credentials(&a).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "pw-a");
    let found = store.credentials(&b).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "pw-b");

    // The first value in the second row: both would have the same associated
    // data if the tenant were not escaped.
    set_text(&store, PASSWORD, &b.0, &sealed_a).await;
    assert_decrypt(store.credentials(&b).await);
    set_text(&store, PASSWORD, &b.0, &sealed_b).await;

    // The first account moves to the other tenant, and its value stays behind.
    for (to, opens) in [(&long, false), (&short, true)] {
        sqlx::query("UPDATE accounts SET tenant = $1 WHERE id = $2")
            .bind(to)
            .bind(&a.0)
            .execute(store.pool())
            .await
            .unwrap();
        let result = store.credentials(&a).await;
        if opens {
            result.unwrap().unwrap();
        } else {
            assert_decrypt(result);
        }
    }
}

/// A value whose key version does not exist, or whose text is malformed, is
/// unreadable for good: `Decrypt`, `Unreadable`, a skipped event, an access
/// token that gets refreshed. Reading never makes a key.
async fn exercise_a_missing_data_key_version_is_unreadable_not_an_error(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    to_v2(&store, &fixture, |_, owner| owner == tenant).await;
    let (imap, event, oauth) = (&fixture.imap, &fixture.event, &fixture.oauth);
    for (column, row) in [(SIGNING, &imap.0), (PAYLOAD, &event.id), (ACCESS, &oauth.0)] {
        let sealed = text(&store, column, row).await;
        set_text(&store, column, row, &sealed.replacen("v2.1.", "v2.7.", 1)).await;
    }
    assert_decrypt(store.webhook(imap).await);
    let loaded = store.load_webhook(imap).await.unwrap();
    assert!(matches!(
        loaded,
        LoadedWebhook::Unreadable { enabled: true }
    ));
    store.set_event_hold(Duration::ZERO);
    let pending = store.pending_mail_events(imap, 10).await.unwrap();
    assert_eq!(
        (pending.events.len(), pending.skip_through),
        (0, Some(event.sequence))
    );
    let tokens = store.upstream_tokens(oauth).await.unwrap().unwrap().tokens;
    assert_eq!(tokens.refresh_token.expose_secret(), "refresh-1");
    assert!(tokens.access_token.is_none());

    for malformed in [
        "v2.",
        "v2.0.AAAA",
        "v2.01.AAAA",
        "v2.+1.AAAA",
        "v2.1",
        "v2.1.!!!!",
    ] {
        set_text(&store, PASSWORD, &imap.0, malformed).await;
        assert_decrypt(store.credentials(imap).await);
    }
    assert_eq!(rows(&store, &tenant).await, 1);
}

/// A wrapper that fails for now gives an error, never "unreadable": no webhook
/// is reported unreadable, no event is skipped, no password is overwritten, no
/// sign-in is taken away. When it answers again, everything reads and the
/// sign-in can be finished.
async fn exercise_a_failing_wrapper_is_an_error_not_unreadable(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let store = db.open(&master()).await.with_key_wrapper(wrapper.clone());
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    // The refresh token is put back under the master key: the access token is
    // the first value of its row that needs the key service.
    put_v1_refresh(&store, &fixture.oauth, "refresh-1").await;
    to_v2(&store, &fixture, |column, owner| {
        owner == tenant && column != REFRESH
    })
    .await;

    // A store that has unwrapped nothing yet, while the key service is down.
    wrapper.down.store(true, Ordering::SeqCst);
    let cold = db.open(&master()).await.with_key_wrapper(wrapper.clone());
    let (imap, oauth) = (&fixture.imap, &fixture.oauth);
    assert_key_wrap(cold.credentials(imap).await);
    assert_key_wrap(cold.load_webhook(imap).await);
    assert_key_wrap(cold.pending_mail_events(imap, 10).await);
    assert_key_wrap(cold.upstream_tokens(oauth).await);
    let again = cold.for_tenant(&tenant);
    assert_key_wrap(again.upsert_account(&fixture.email, &secret("new")).await);
    // A sign-in that cannot be opened for now is still there afterwards.
    let continued = &fixture.states[2];
    assert_key_wrap(cold.take_upstream_request(continued).await);
    assert!(present(&store, continued).await, "the sign-in was removed");

    wrapper.down.store(false, Ordering::SeqCst);
    check_reads(&cold, &fixture).await;
    let taken = cold
        .take_upstream_request(continued)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        describe(&taken.purpose),
        format!("continue {tenant} connect-1")
    );
    assert!(!present(&store, continued).await);
}

/// A value in a format newer than this build reads (`v3.`) is not unreadable:
/// reading it is `NewerFormat`, and no password is overwritten, no event
/// skipped, no sign-in removed and no access token dropped for a refresh to
/// replace. With the old texts back, everything reads as before.
async fn exercise_a_newer_format_is_held_not_treated_as_unreadable(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    let (imap, oauth) = (&fixture.imap, &fixture.oauth);
    let fixtures = std::slice::from_ref(&fixture);
    let original = all_texts(&store, fixtures).await;
    // All but the refresh token, so that the access token is the first to fail.
    for (column, row, ..) in fixture.values.iter().filter(|value| value.0 != REFRESH) {
        set_text(&store, *column, row, "v3.AAAA").await;
    }
    let planted = all_texts(&store, fixtures).await;

    assert_newer(store.credentials(imap).await);
    assert_newer(store.webhook(imap).await);
    assert_newer(store.load_webhook(imap).await);
    assert_newer(store.upstream_tokens(oauth).await);
    let (sign_in, new) = (store.for_tenant(&tenant), secret("new"));
    let again = sign_in.upsert_imap_account_ending_sessions(&fixture.email, &new, None);
    assert_newer(again.await);
    // The event is held, whatever the hold.
    store.set_event_hold(Duration::ZERO);
    let pending = store.pending_mail_events(imap, 10).await.unwrap();
    assert_eq!(pending.held, Some(fixture.event.sequence));
    assert_eq!(store.pending_mail_event_count(imap).await.unwrap(), 1);
    for state in &fixture.states {
        assert_newer(store.take_upstream_request(state).await);
        assert!(present(&store, state).await, "the sign-in was removed");
    }
    assert_eq!(all_texts(&store, fixtures).await, planted);

    for ((column, row, ..), old) in fixture.values.iter().zip(&original) {
        set_text(&store, *column, row, old).await;
    }
    check_reads(&store, &fixture).await;
    check_sign_ins(&store, &fixture, &tenant).await;
}

/// Another master key cannot unwrap the data key, which is `Decrypt`; a
/// previous master key can.
async fn exercise_the_wrong_master_key_reports_decrypt_for_v2(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    to_v2(&store, &fixture, |_, owner| owner == tenant).await;

    let stranger = db.open(&random_master()).await;
    assert_decrypt(stranger.credentials(&fixture.imap).await);
    assert_decrypt(stranger.upstream_tokens(&fixture.oauth).await);
    // A replica without the key holds the event and moves nothing; the first
    // skips it only once the hold is over. One with the key reads it below.
    let warnings = Warnings::start();
    let (imap, event) = (&fixture.imap, fixture.event.sequence);
    let held = stranger.pending_mail_events(imap, 10).await.unwrap();
    assert_eq!((held.skip_through, held.held), (None, Some(event)));
    stranger.set_event_hold(Duration::ZERO);
    let skipped = stranger.pending_mail_events(imap, 10).await.unwrap();
    assert_eq!((skipped.skip_through, skipped.held), (Some(event), None));
    let lines = warnings.take();
    let warned = lines.len() == 2 && lines[1].contains("skipping it");
    assert!(warned, "{lines:?}");

    let rotating = Store::connect_rotating(&db.url, &random_master(), &[master()])
        .await
        .unwrap();
    check_reads(&rotating, &fixture).await;
}

/// A password is written as a v2 value of the store's tenant, and the secrets
/// of a webhook as v2 values of the tenant of their account, whichever store
/// saves them. Each can be opened from the documented layout, bound to its
/// column and row, also when the tenant's name has what the associated data
/// escapes. Only the account's tenant gets a key, and an account that does
/// not exist gets no webhook.
async fn exercise_passwords_and_webhook_secrets_are_written_as_v2(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    let tenant = format!("{}/a%b", unique_tenant());
    let email = format!("{}@example.com", unique("v2"));
    let scoped = store.for_tenant(&tenant);
    let account = scoped
        .upsert_account(&email, &secret("pw-1"))
        .await
        .unwrap();
    // The base store saves the webhook of an account in another tenant.
    let hook = webhook("https://hooks.example/h", "Bearer one", "whsec_one");
    store.save_webhook(&account.id, &hook).await.unwrap();

    let id = &account.id;
    let stored = written(&store, id).await;
    let expected = [
        (PASSWORD, email.as_str(), "pw-1"),
        (AUTH, id.0.as_str(), "Bearer one"),
        (SIGNING, id.0.as_str(), "whsec_one"),
    ];
    for ((column, row_key, plaintext), stored) in expected.into_iter().zip(&stored) {
        assert!(stored.starts_with("v2.1."), "{column:?}");
        assert_eq!(
            unseal(&store, &tenant, column, row_key, stored).await,
            plaintext
        );
    }
    assert_eq!(rows(&store, &tenant).await, 1);
    let found = store.credentials(id).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "pw-1");
    let found = store.webhook(id).await.unwrap().unwrap();
    assert_eq!(found.settings.signing_secret.expose_secret(), "whsec_one");

    let missing = AccountId(unique("missing"));
    let err = store.save_webhook(&missing, &hook).await.unwrap_err();
    assert!(
        matches!(err, StoreError::InvalidInput("unknown account")),
        "{err:?}"
    );
    // The wrapper was asked about this tenant only, not about `default`.
    let calls = wrapper.calls();
    assert!(!calls.is_empty() && calls.iter().all(|call| call.contains(&tenant)));
}

/// Over a v2 password, the same password is not a change and another one is.
async fn exercise_a_changed_password_is_still_detected(db: &Db) {
    let store = db.open(&master()).await.for_tenant(&unique_tenant());
    let email = format!("{}@example.com", unique("same"));
    let mut changed = Vec::new();
    for password in ["one", "one", "two"] {
        let secret = secret(password);
        let written = store.upsert_imap_account_ending_sessions(&email, &secret, None);
        let written = written.await.unwrap();
        let stored = text(&store, PASSWORD, &written.account.id.0).await;
        assert!(stored.starts_with("v2.1."), "{stored}");
        changed.push(written.password_changed);
    }
    assert_eq!(changed, [false, false, true]);
    let account = store.account_by_email(&email, Provider::Imap).await;
    let found = store.credentials(&account.unwrap().unwrap().id).await;
    assert_eq!(found.unwrap().unwrap().password.expose_secret(), "two");
}

/// A wrapper that fails for now stops a write with `KeyWrap`. Nothing is
/// stored, the old values stay as they are and no key is made. A password
/// that could not be opened because the wrapper failed is not taken for an
/// unreadable one and overwritten, also when the write could go on with the
/// key of another version. When the wrapper answers, the writes go through.
async fn exercise_a_failing_wrapper_stops_the_write(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let (tenant, fresh) = (unique_tenant(), unique_tenant());
    let store = cold(db, &wrapper).await;
    let email = format!("{}@example.com", unique("down"));
    let account = store
        .for_tenant(&tenant)
        .upsert_account(&email, &secret("old"))
        .await
        .unwrap();
    let old = webhook("https://hooks.example/old", "Bearer old", "whsec_old");
    store.save_webhook(&account.id, &old).await.unwrap();
    let kept = written(&store, &account.id).await;

    let new = webhook("https://hooks.example/new", "Bearer new", "whsec_new");
    let fresh_email = format!("{}@example.com", unique("fresh"));
    // Nothing is unwrapped yet in these stores. The key service is down, or it
    // wraps and will not unwrap: the stored password cannot be opened, the key
    // cannot be found, and a first key is neither made nor stored.
    for (down, deaf) in [(true, false), (false, true)] {
        wrapper.down.store(down, Ordering::SeqCst);
        wrapper.deaf.store(deaf, Ordering::SeqCst);
        let failing = cold(db, &wrapper).await;
        let scoped = failing.for_tenant(&tenant);
        let other = failing.for_tenant(&fresh);
        assert_key_wrap(scoped.upsert_account(&email, &secret("new")).await);
        assert_key_wrap(failing.save_webhook(&account.id, &new).await);
        assert_key_wrap(other.upsert_account(&fresh_email, &secret("pw")).await);
        assert_eq!(written(&failing, &account.id).await, kept);
        assert_eq!(other.accounts_in_tenant().await.unwrap(), Vec::new());
        assert_eq!(rows(&failing, &fresh).await, 0);
    }

    wrapper.deaf.store(false, Ordering::SeqCst);
    let down = cold(db, &wrapper).await;
    let (scoped, other) = (down.for_tenant(&tenant), down.for_tenant(&fresh));
    scoped.upsert_account(&email, &secret("new")).await.unwrap();
    down.save_webhook(&account.id, &new).await.unwrap();
    other
        .upsert_account(&fresh_email, &secret("pw"))
        .await
        .unwrap();
    let found = down.credentials(&account.id).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "new");
    assert_eq!(rows(&down, &fresh).await, 1);

    // Version 2 of the tenant's key is unwrapped, and only `unwrap` fails
    // from now on: the password is under version 1, which it cannot open.
    let tenant = unique_tenant();
    let email = format!("{}@example.com", unique("deaf"));
    let store = cold(db, &wrapper).await;
    let account = store
        .for_tenant(&tenant)
        .upsert_account(&email, &secret("old"))
        .await
        .unwrap();
    let key = URL_SAFE_NO_PAD.encode(mask(&tenant, &[0x66; 32]));
    set_key(&store, &tenant, 2, &kek(3), &key).await;
    let process = cold(db, &wrapper).await;
    assert_eq!(process.for_tenant(&tenant).data_key().await.unwrap().0, 2);
    let kept = text(&store, PASSWORD, &account.id.0).await;
    wrapper.deaf.store(true, Ordering::SeqCst);
    let again = process.for_tenant(&tenant);
    assert_key_wrap(again.upsert_account(&email, &secret("new")).await);
    assert_eq!(text(&store, PASSWORD, &account.id.0).await, kept);
    wrapper.deaf.store(false, Ordering::SeqCst);
    again.upsert_account(&email, &secret("new")).await.unwrap();
    let rewritten = text(&store, PASSWORD, &account.id.0).await;
    assert!(rewritten.starts_with("v2.2."), "{rewritten}");
}

/// An event is written as a v2 value of the tenant of its account, whichever
/// store appends it, with the event's ID as row key. It opens from the
/// documented layout and through the reader, whether or not the append moves a
/// position. A key in hand needs no call to the wrapper, and an account that
/// does not exist gets no event.
async fn exercise_events_are_written_as_v2(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    let tenant = format!("{}/a%b", unique_tenant());
    let email = format!("{}@example.com", unique("event"));
    let scoped = store.for_tenant(&tenant);
    let id = scoped
        .upsert_account(&email, &secret("pw"))
        .await
        .unwrap()
        .id;
    let hook = webhook("https://hooks.example/h", "Bearer one", "whsec_one");
    store.save_webhook(&id, &hook).await.unwrap();
    wrapper.calls();

    // The base store appends for an account in another tenant.
    let payloads = [r#"{"n":1}"#, r#"{"n":2}"#];
    let position = WatchAdvance::Position {
        expected: None,
        next: "p1".to_owned(),
    };
    let mut events = Vec::new();
    for (payload, advance) in payloads.into_iter().zip([None, Some(position)]) {
        let appended = store.append_mail_event(&id, payload, advance).await;
        let event = appended.unwrap().stored().unwrap();
        let stored = text(&store, PAYLOAD, &event.id).await;
        assert!(stored.starts_with("v2.1."), "{stored}");
        let opened = unseal(&store, &tenant, PAYLOAD, &event.id, &stored).await;
        assert_eq!(opened, payload);
        events.push(event);
    }
    assert_eq!(rows(&store, &tenant).await, 1);
    let pending = store.pending_mail_events(&id, 10).await.unwrap();
    assert_eq!((pending.events, pending.skip_through), (events, None));
    assert_eq!(wrapper.calls(), Vec::<String>::new(), "the key is in hand");

    let missing = AccountId(unique("missing"));
    let outcome = store.append_mail_event(&missing, "{}", None).await;
    assert_eq!(outcome.unwrap(), AppendOutcome::NoWebhook);
    assert_eq!(wrapper.calls(), Vec::<String>::new());
}

/// Adds a filter rule to an account, and returns its ID.
async fn add_rule(store: &Store, id: &AccountId, pattern: &str) -> String {
    let new = NewFilterRule {
        action: "block".to_owned(),
        field: "from".to_owned(),
        kind: "equals".to_owned(),
        pattern: secret(pattern),
    };
    let added = store.add_webhook_filter_rule(id, &new, 9, |_| Ok(()));
    match added.await.unwrap() {
        AddedFilterRule::Added(rule) => rule,
        other => panic!("{pattern} was not added: {other:?}"),
    }
}

/// The patterns of an account's filter rules, oldest first.
async fn patterns_of(store: &Store, id: &AccountId) -> Vec<String> {
    let rules = store.webhook_filter_rules(id, 9).await.unwrap();
    let expose = |rule: &FilterRule| rule.pattern.expose_secret().to_owned();
    rules.iter().map(expose).collect()
}

/// A filter rule's pattern is written as a v2 value of the tenant of its
/// account, whichever store adds it, with the rule's ID as row key. It opens
/// from the documented layout and through the reader, and one moved to another
/// rule's row does not open.
async fn exercise_filter_patterns_are_written_as_v2(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = format!("{}/a%b", unique_tenant());
    let email = format!("{}@example.com", unique("rule"));
    let (scoped, pw) = (store.for_tenant(&tenant), secret("pw"));
    let id = scoped.upsert_account(&email, &pw).await.unwrap().id;
    let hook = webhook("https://hooks.example/h", "Bearer one", "whsec_one");
    store.save_webhook(&id, &hook).await.unwrap();

    // The base store adds to an account in another tenant.
    let patterns = ["a@example.com", "b"];
    let mut rules = Vec::new();
    for pattern in patterns {
        let rule = add_rule(&store, &id, pattern).await;
        let stored = text(&store, PATTERN, &rule).await;
        assert!(stored.starts_with("v2.1."), "{stored}");
        let opened = unseal(&store, &tenant, PATTERN, &rule, &stored).await;
        assert_eq!(opened, pattern);
        rules.push(rule);
    }
    assert_eq!(rows(&store, &tenant).await, 1);
    assert_eq!(patterns_of(&store, &id).await, patterns);
    let edit = NewFilterRule {
        action: "block".to_owned(),
        field: "from".to_owned(),
        kind: "equals".to_owned(),
        pattern: secret("c@example.com"),
    };
    let changed = store.update_webhook_filter_rule(&id, &rules[0], &edit, 9, |_| Ok(()));
    assert_eq!(changed.await.unwrap(), ChangedFilterRule::Changed);
    let stored = text(&store, PATTERN, &rules[0]).await;
    assert!(stored.starts_with("v2.1."), "{stored}");
    let opened = unseal(&store, &tenant, PATTERN, &rules[0], &stored).await;
    assert_eq!(opened, "c@example.com");
    // An unknown account is not found before any key is looked up or made.
    let wrapper = Arc::new(Masking::default());
    let missing = AccountId(unique("missing"));
    let unwrapped = cold(db, &wrapper).await;
    let found = unwrapped.update_webhook_filter_rule(&missing, "x", &edit, 9, |_| Ok(()));
    assert_eq!(found.await.unwrap(), ChangedFilterRule::NotFound);
    assert_eq!(
        wrapper.calls(),
        Vec::<String>::new(),
        "no key for no tenant"
    );

    let first = text(&store, PATTERN, &rules[0]).await;
    set_text(&store, PATTERN, &rules[1], &first).await;
    assert_decrypt(store.webhook_filter_rules(&id, 9).await);
}

/// A wrapper that fails for now stops an append with `KeyWrap`: the event is
/// not stored or taken for unreadable, no sequence number is used and the
/// position stays where the batch was read from, so the same call stores the
/// event once the wrapper answers. That holds when the wrapper is down and when
/// it wraps but will not unwrap.
async fn exercise_an_event_is_not_stored_while_the_wrapper_fails(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    let email = format!("{}@example.com", unique("down"));
    let scoped = store.for_tenant(&unique_tenant());
    let id = scoped
        .upsert_account(&email, &secret("pw"))
        .await
        .unwrap()
        .id;
    let hook = webhook("https://hooks.example/h", "Bearer one", "whsec_one");
    store.save_webhook(&id, &hook).await.unwrap();
    let moving = |from: Option<&str>, next: &str| WatchAdvance::Position {
        expected: from.map(str::to_owned),
        next: next.to_owned(),
    };
    let first = store.append_mail_event(&id, "{}", Some(moving(None, "p1")));
    let first = first.await.unwrap().stored().unwrap();

    // Nothing is unwrapped yet in these stores. The key service is down, or it
    // wraps and will not unwrap.
    for (down, deaf) in [(true, false), (false, true)] {
        wrapper.down.store(down, Ordering::SeqCst);
        wrapper.deaf.store(deaf, Ordering::SeqCst);
        let failing = cold(db, &wrapper).await;
        let advance = Some(moving(Some("p1"), "p2"));
        assert_key_wrap(failing.append_mail_event(&id, "{}", advance).await);
    }

    // Had a failed attempt used a sequence number or moved the position, this
    // would be sequence 3, or a stale position.
    wrapper.deaf.store(false, Ordering::SeqCst);
    let back = cold(db, &wrapper).await;
    let second = back.append_mail_event(&id, "{}", Some(moving(Some("p1"), "p2")));
    let second = second.await.unwrap().stored().unwrap();
    assert_eq!(second.sequence, 2);
    let pending = back.pending_mail_events(&id, 10).await.unwrap();
    assert_eq!(pending.events, [first, second]);
    let found = back.webhook(&id).await.unwrap().unwrap();
    assert_eq!(found.position.as_deref(), Some("p2"));
}

/// What the tokens of `account` are stored as: both columns v2 values of
/// `tenant`'s key version 1 bound to the account's ID, opened from the
/// documented layout, and read back through the reader.
async fn assert_tokens(
    store: &Store,
    tenant: &str,
    account: &AccountId,
    refresh: &str,
    access: Option<&str>,
) {
    let stored = text(store, REFRESH, &account.0).await;
    assert!(stored.starts_with("v2.1."), "{stored}");
    assert_eq!(
        unseal(store, tenant, REFRESH, &account.0, &stored).await,
        refresh
    );
    let cached: Option<String> = sqlx::query_scalar(
        "SELECT access_token_ciphertext FROM upstream_tokens WHERE account_id = $1",
    )
    .bind(&account.0)
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(cached.is_some(), access.is_some(), "{cached:?}");
    if let (Some(stored), Some(plaintext)) = (&cached, access) {
        assert!(stored.starts_with("v2.1."), "{stored}");
        let opened = unseal(store, tenant, ACCESS, &account.0, stored).await;
        assert_eq!(opened, plaintext);
    }
    let found = store.upstream_tokens(account).await.unwrap().unwrap();
    assert_eq!(found.tokens.refresh_token.expose_secret(), refresh);
    let read = found.tokens.access_token.as_ref();
    assert_eq!(read.map(ExposeSecret::expose_secret), access);
}

/// Replaces the refresh token `from` of `account` by `to` if it is still the
/// stored one: a caller that holds another is turned away, and the new token is
/// a v2 value of the account's row.
async fn assert_refresh_replaced(
    store: &Store,
    tenant: &str,
    account: &AccountId,
    from: &str,
    to: &str,
) {
    let renewed = tokens(to);
    let (stale, held) = (secret("stale"), secret(from));
    let missed = store.save_upstream_tokens_if_current(account, &stale, &renewed);
    assert!(!missed.await.unwrap());
    let replaced = store.save_upstream_tokens_if_current(account, &held, &renewed);
    assert!(replaced.await.unwrap());
    assert_tokens(store, tenant, account, to, Some("access-1")).await;
}

/// The tokens of a provider account are written as v2 values of the tenant of
/// their account, bound to the account's ID, whichever store writes them: by a
/// sign-in that creates the account and by one that finds it, by the
/// unconditional save and by the conditional one. An access token that is not
/// cached is stored as nothing. Only the account's tenant gets a key, also when
/// the name has what the associated data escapes. A cached access token that
/// cannot be opened is dropped, not an error.
async fn exercise_tokens_are_written_as_v2(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    let tenant = format!("{}/a%b", unique_tenant());
    let scoped = store.for_tenant(&tenant);
    let (subject, email) = (
        unique("subject"),
        format!("{}@example.com", unique("oauth")),
    );
    let sign_in = OAuthAccount {
        provider: Provider::Gmail,
        subject: &subject,
        email: &email,
    };

    let created = scoped
        .upsert_oauth_account(&sign_in, &tokens("refresh-1"))
        .await
        .unwrap();
    let id = created.id;
    assert_tokens(&store, &tenant, &id, "refresh-1", Some("access-1")).await;
    assert_eq!(rows(&store, &tenant).await, 1);

    // The same person signs in again: the row key is the ID that was found.
    let uncached = UpstreamTokens {
        access_token: None,
        ..tokens("refresh-2")
    };
    let again = scoped.upsert_oauth_account(&sign_in, &uncached).await;
    assert_eq!(again.unwrap().id, id);
    assert_tokens(&store, &tenant, &id, "refresh-2", None).await;

    // The base store is not in the account's tenant.
    assert_eq!(store.tenant(), DEFAULT_TENANT);
    store
        .save_upstream_tokens(&id, &tokens("refresh-3"))
        .await
        .unwrap();
    assert_tokens(&store, &tenant, &id, "refresh-3", Some("access-1")).await;
    assert_refresh_replaced(&store, &tenant, &id, "refresh-3", "refresh-4").await;

    // The wrapper was asked about this tenant only, not about `default`.
    assert_eq!(rows(&store, &tenant).await, 1);
    let calls = wrapper.calls();
    assert!(!calls.is_empty() && calls.iter().all(|call| call.contains(&tenant)));

    // Another process, with a master key this one lacks, adds a newer key
    // version. Writes go on under the version this process can unwrap.
    let stray = db.open(&other_master()).await;
    assert_eq!(stray.for_tenant(&tenant).data_key().await.unwrap().0, 2);
    let saved = store.save_upstream_tokens(&id, &tokens("refresh-5")).await;
    saved.unwrap();
    assert_tokens(&store, &tenant, &id, "refresh-5", Some("access-1")).await;
    assert_eq!(rows(&store, &tenant).await, 2);

    // A cached access token that cannot be opened is refreshed, not an error.
    set_text(&store, ACCESS, &id.0, &common::unreadable()).await;
    let found = store.upstream_tokens(&id).await.unwrap().unwrap();
    assert_eq!(found.tokens.refresh_token.expose_secret(), "refresh-5");
    assert!(found.tokens.access_token.is_none());
}

/// The conditional write seals for the tenant of the account's row before it
/// reads the stored token, whichever store is asked, and compares the plaintext.
/// An account that has no tokens gets no write and no key.
async fn exercise_the_compare_and_set_seals_for_the_accounts_tenant(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let setup = cold(db, &wrapper).await;
    let tenant = unique_tenant();
    let email = format!("{}@example.com", unique("cas"));
    let oauth = OAuthAccount {
        provider: Provider::Graph,
        subject: &unique("subject"),
        email: &email,
    };
    let scoped = setup.for_tenant(&tenant);
    let id = scoped
        .upsert_oauth_account(&oauth, &tokens("refresh-1"))
        .await
        .unwrap()
        .id;
    let imap_email = format!("{}@example.com", unique("imap"));
    let imap = scoped.upsert_account(&imap_email, &secret("pw")).await;
    let imap = imap.unwrap().id;
    wrapper.calls();

    // A process that has unwrapped nothing, and a store of the default tenant.
    let store = cold(db, &wrapper).await;
    assert_eq!(store.tenant(), DEFAULT_TENANT);
    let (first, other) = (secret("refresh-1"), tokens("x"));
    let missing = AccountId(unique("missing"));
    for absent in [&missing, &imap] {
        let saved = store.save_upstream_tokens_if_current(absent, &first, &other);
        assert!(!saved.await.unwrap());
    }
    assert_eq!(wrapper.calls(), Vec::<String>::new(), "nothing to seal");

    assert_refresh_replaced(&store, &tenant, &id, "refresh-1", "refresh-2").await;
    let calls = wrapper.calls();
    assert!(!calls.is_empty() && calls.iter().all(|call| call.contains(&tenant)));
    assert_eq!(rows(&store, &tenant).await, 1);
}

/// A wrapper that fails for now stops a token write with `KeyWrap`, whichever
/// way the tokens are written: nothing is stored, the old tokens stay as they
/// are and no key is made. A refresh that could not be saved is neither
/// reported as lost to a newer sign-in nor recorded as rejected. When the
/// wrapper answers, the same calls go through.
async fn exercise_a_failing_wrapper_stops_a_token_write(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let (tenant, fresh) = (unique_tenant(), unique_tenant());
    let store = cold(db, &wrapper).await;
    let (email, subject) = (format!("{}@example.com", unique("down")), unique("subject"));
    let (fresh_email, fresh_subject) = (format!("{}@example.com", unique("new")), unique("sub"));
    let oauth = OAuthAccount {
        provider: Provider::Graph,
        subject: &subject,
        email: &email,
    };
    let in_fresh = OAuthAccount {
        provider: Provider::Graph,
        subject: &fresh_subject,
        email: &fresh_email,
    };
    let scoped = store.for_tenant(&tenant);
    let first = scoped.upsert_oauth_account(&oauth, &tokens("old")).await;
    let id = first.unwrap().id;
    let kept = (
        text(&store, REFRESH, &id.0).await,
        text(&store, ACCESS, &id.0).await,
    );

    let (old, new) = (secret("old"), tokens("new"));
    for (down, deaf) in [(true, false), (false, true)] {
        wrapper.down.store(down, Ordering::SeqCst);
        wrapper.deaf.store(deaf, Ordering::SeqCst);
        let failing = cold(db, &wrapper).await;
        let (scoped, other) = (failing.for_tenant(&tenant), failing.for_tenant(&fresh));
        assert_key_wrap(scoped.upsert_oauth_account(&oauth, &new).await);
        assert_key_wrap(failing.save_upstream_tokens(&id, &new).await);
        let conditional = failing.save_upstream_tokens_if_current(&id, &old, &new);
        assert_key_wrap(conditional.await);
        assert_key_wrap(other.upsert_oauth_account(&in_fresh, &new).await);
        assert_eq!(other.accounts_in_tenant().await.unwrap(), Vec::new());
        assert_eq!(rows(&failing, &fresh).await, 0);
        let now = (
            text(&failing, REFRESH, &id.0).await,
            text(&failing, ACCESS, &id.0).await,
        );
        assert_eq!(now, kept);
    }

    wrapper.deaf.store(false, Ordering::SeqCst);
    let back = cold(db, &wrapper).await;
    let conditional = back.save_upstream_tokens_if_current(&id, &old, &new);
    assert!(conditional.await.unwrap());
    assert_tokens(&back, &tenant, &id, "new", Some("access-1")).await;
    // A tenant of its own gets its key once the wrapper answers.
    let other = back.for_tenant(&fresh);
    other.upsert_oauth_account(&in_fresh, &new).await.unwrap();
    assert_eq!(rows(&back, &fresh).await, 1);
}

/// The first key of a tenant is made before the transaction of the write
/// opens, and so is the key of an event that is appended afterwards. A pool of
/// one connection has none left for it inside: the write would wait for the
/// connection that its own transaction holds.
#[tokio::test]
async fn sqlite_the_first_key_is_made_outside_the_transaction() {
    let db = Db::sqlite();
    let pool = PoolSettings {
        max_connections: 1,
        acquire_timeout: Duration::from_secs(10),
        ..PoolSettings::default()
    };
    let store = Store::connect_with(&db.url, &master(), &[], pool, Migrations::Apply)
        .await
        .unwrap();
    let tenant = unique_tenant();
    let scoped = store.for_tenant(&tenant);
    let account = scoped
        .upsert_account("a@example.com", &secret("pw"))
        .await
        .unwrap_or_else(|err| panic!("the write has no connection of its own: {err:?}"));
    assert_eq!(rows(&store, &tenant).await, 1);
    let found = store.credentials(&account.id).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "pw");

    let hook = webhook("https://hooks.example/h", "Bearer one", "whsec_one");
    store.save_webhook(&account.id, &hook).await.unwrap();
    let appended = store.append_mail_event(&account.id, "{}", None).await;
    let outcome = appended.unwrap_or_else(|err| panic!("the append has no connection: {err:?}"));
    let pending = store.pending_mail_events(&account.id, 10).await.unwrap();
    assert_eq!(pending.events, [outcome.stored().unwrap()]);
}

/// The first key of a tenant is made before the transaction of a token write
/// opens, whether the sign-in creates the account or finds it, or the tokens
/// are saved for an account whose tenant has no key yet: a pool of one
/// connection has none left for it inside.
#[tokio::test]
async fn sqlite_a_new_oauth_account_makes_its_key_outside_the_transaction() {
    let db = Db::sqlite();
    let pool = PoolSettings {
        max_connections: 1,
        acquire_timeout: Duration::from_secs(10),
        ..PoolSettings::default()
    };
    let key = master();
    let opened = Store::connect_with(&db.url, &key, &[], pool, Migrations::Apply);
    let store = opened.await.unwrap();
    let sign_in = |store: &Store, subject: &str| {
        let (store, subject) = (store.clone(), subject.to_owned());
        let email = format!("{}@example.com", unique("pool"));
        async move {
            let account = OAuthAccount {
                provider: Provider::Gmail,
                subject: &subject,
                email: &email,
            };
            let signed = store
                .upsert_oauth_account(&account, &tokens("refresh-1"))
                .await;
            signed.unwrap_or_else(|err| panic!("the sign-in has no connection: {err:?}"))
        }
    };

    // A tenant with no key: the sign-in makes it, and a second one finds it.
    let tenant = unique_tenant();
    let (scoped, subject) = (store.for_tenant(&tenant), unique("subject"));
    let id = sign_in(&scoped, &subject).await.id;
    assert_eq!(rows(&store, &tenant).await, 1);
    assert_eq!(sign_in(&scoped, &subject).await.id, id);
    assert_tokens(&store, &tenant, &id, "refresh-1", Some("access-1")).await;

    // Tokens that an earlier build stored under the master key, in a tenant
    // that has no key: the save makes it.
    for conditional in [false, true] {
        let tenant = unique_tenant();
        let scoped = store.for_tenant(&tenant);
        let id = sign_in(&scoped, &unique("subject")).await.id;
        sqlx::query("DELETE FROM data_keys WHERE tenant = $1")
            .bind(&tenant)
            .execute(store.pool())
            .await
            .unwrap();
        put_v1_refresh(&store, &id, "refresh-1").await;
        assert_eq!(rows(&store, &tenant).await, 0);

        let renewed = tokens("refresh-2");
        let saved = if conditional {
            let first = secret("refresh-1");
            store
                .save_upstream_tokens_if_current(&id, &first, &renewed)
                .await
        } else {
            store
                .save_upstream_tokens(&id, &renewed)
                .await
                .map(|()| true)
        };
        assert!(saved.unwrap_or_else(|err| panic!("the save has no connection: {err:?}")));
        assert_eq!(rows(&store, &tenant).await, 1);
        assert_tokens(&store, &tenant, &id, "refresh-2", Some("access-1")).await;
    }
}

/// Keys made once, stored wrapped, unwrapped through the store's wrapper.
async fn exercise_keys(db: &Db) {
    exercise_a_key_is_made_once_and_read_back(db).await;
    exercise_the_row_names_its_wrapper_and_hides_the_key(db).await;
    exercise_master_keys(db).await;
    exercise_a_copied_row_does_not_unwrap(db).await;
    exercise_a_custom_wrapper(db).await;
    exercise_the_row_names_the_kek_that_wrapped(db).await;
    exercise_another_providers_key_is_not_unwrapped(db).await;
    exercise_concurrent_first_use(db).await;
    exercise_two_processes_without_a_key_agree_on_the_new_one(db).await;
}

/// A tenant whose keys the store cannot unwrap, and a wrapper that fails.
async fn exercise_new_versions(db: &Db) {
    exercise_a_new_master_key_alone_gets_a_new_data_key(db).await;
    exercise_a_stray_key_does_not_move_the_right_one(db).await;
    exercise_a_failing_wrapper_never_gets_a_new_key(db).await;
    exercise_a_rewrapped_row_is_tried_again(db).await;
    exercise_a_dead_row_is_asked_once(db).await;
    exercise_a_dead_row_that_a_read_unwrapped_is_used_again(db).await;
    exercise_a_wrapper_that_cannot_read_its_keys_stores_none(db).await;
    exercise_a_key_in_hand_is_read_with_after_its_row_changes(db).await;
}

/// The values in the data-key format: how the readers see them, and what the
/// writers of the password, the webhook secrets, the events and the filter
/// patterns make.
async fn exercise_values(db: &Db) {
    exercise_v2_values_open_in_every_column(db).await;
    exercise_a_moved_v2_value_does_not_open(db).await;
    exercise_tenants_are_told_apart_by_the_associated_data(db).await;
    exercise_a_missing_data_key_version_is_unreadable_not_an_error(db).await;
    exercise_a_failing_wrapper_is_an_error_not_unreadable(db).await;
    exercise_a_newer_format_is_held_not_treated_as_unreadable(db).await;
    exercise_the_wrong_master_key_reports_decrypt_for_v2(db).await;
    exercise_passwords_and_webhook_secrets_are_written_as_v2(db).await;
    exercise_a_changed_password_is_still_detected(db).await;
    exercise_a_failing_wrapper_stops_the_write(db).await;
    exercise_events_are_written_as_v2(db).await;
    exercise_an_event_is_not_stored_while_the_wrapper_fails(db).await;
    exercise_filter_patterns_are_written_as_v2(db).await;
}

/// A local wrapper that holds each `unwrap` until `parties` callers are in it and
/// `hold` is not set, so that takes which overlap have all read their sign-in
/// before any of them removes it, or a test can change the database while a take
/// is opening. If the condition is not met, a caller goes on after a while, with
/// `missed` set.
struct Meeting {
    local: LocalKeyWrapper,
    parties: usize,
    arrived: AtomicUsize,
    hold: AtomicBool,
    missed: AtomicBool,
}

impl Meeting {
    fn new(parties: usize, hold: bool) -> Self {
        Self {
            local: LocalKeyWrapper::new(&master(), &[]),
            parties,
            arrived: AtomicUsize::new(0),
            hold: AtomicBool::new(hold),
            missed: AtomicBool::new(false),
        }
    }

    /// Waits until `parties` callers are in `unwrap`.
    async fn wait_for_callers(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while self.arrived.load(Ordering::SeqCst) < self.parties {
            assert!(
                std::time::Instant::now() < deadline,
                "nobody opened a value"
            );
            tokio::task::yield_now().await;
        }
    }
}

impl KeyWrapper for Meeting {
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
        Box::pin(async move {
            self.arrived.fetch_add(1, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while self.arrived.load(Ordering::SeqCst) < self.parties
                || self.hold.load(Ordering::SeqCst)
            {
                if std::time::Instant::now() > deadline {
                    self.missed.store(true, Ordering::SeqCst);
                    break;
                }
                tokio::task::yield_now().await;
            }
            self.local.unwrap(tenant, kek, wrapped).await
        })
    }
}

/// Of several takes at once, exactly one gets the sign-in. The takes meet at the
/// key service after they all read the row, so each would return the sign-in if
/// the result of its removal did not decide.
async fn exercise_a_sign_in_is_taken_once(db: &Db) {
    let store = db.open(&master()).await;
    let (tenant, state) = (unique_tenant(), unique("state"));
    save_v2(&store, &state, &tenant, TTL).await;
    let meeting = Arc::new(Meeting::new(3, false));
    let mut stores = Vec::new();
    for _ in 0..3 {
        stores.push(db.open(&master()).await.with_key_wrapper(meeting.clone()));
    }
    let mut running = Vec::new();
    for cold_store in stores {
        let state = state.clone();
        running.push(tokio::spawn(async move {
            cold_store.take_upstream_request(&state).await
        }));
    }
    let mut got = Vec::new();
    for take in running {
        got.push(take.await.unwrap().unwrap());
    }
    assert!(
        !meeting.missed.load(Ordering::SeqCst),
        "the takes did not all read the sign-in before one removed it"
    );
    let won: Vec<_> = got.iter().flatten().collect();
    assert_eq!(won.len(), 1, "{} of 3 takes got the sign-in", won.len());
    assert_eq!(
        describe(&won[0].purpose),
        format!("continue {tenant} connect-1")
    );
    assert!(!present(&store, &state).await);
    assert!(store.take_upstream_request(&state).await.unwrap().is_none());
}

/// A sign-in that vanishes while a take opens it, because expiry cleanup removed
/// it, gives `None`, not an error. One that expires meanwhile was live when read
/// and is returned.
async fn exercise_a_sign_in_changed_while_it_is_opened(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    for removed in [true, false] {
        let state = unique("state");
        save_v2(&store, &state, &tenant, TTL).await;
        let meeting = Arc::new(Meeting::new(1, true));
        let cold_store = db.open(&master()).await.with_key_wrapper(meeting.clone());
        let name = state.clone();
        let taking = tokio::spawn(async move { cold_store.take_upstream_request(&name).await });
        meeting.wait_for_callers().await;
        let sql = if removed {
            "DELETE FROM upstream_requests WHERE state_hash = $1"
        } else {
            "UPDATE upstream_requests SET expires_at = 1 WHERE state_hash = $1"
        };
        let hash = common::state_hash(&state);
        let changed = sqlx::query(sql)
            .bind(&hash)
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(changed.rows_affected(), 1, "removed meanwhile: {removed}");
        meeting.hold.store(false, Ordering::SeqCst);
        let taken = taking.await.unwrap().unwrap();
        assert!(!meeting.missed.load(Ordering::SeqCst), "the take never met");
        assert_eq!(taken.is_none(), removed, "removed meanwhile: {removed}");
        assert!(!present(&store, &state).await);
    }
}

/// An expired sign-in is removed without being opened: with the key service
/// down, taking it answers `None`, not an error, and asks the service nothing.
async fn exercise_an_expired_sign_in_is_removed_unopened(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    let (tenant, state) = (unique_tenant(), unique("state"));
    save_v2(&store, &state, &tenant, Duration::ZERO).await;
    assert!(present(&store, &state).await);

    wrapper.down.store(true, Ordering::SeqCst);
    wrapper.calls();
    let down = cold(db, &wrapper).await;
    assert!(down.take_upstream_request(&state).await.unwrap().is_none());
    assert!(!present(&down, &state).await, "the expired sign-in stayed");
    let calls = wrapper.calls();
    assert!(calls.is_empty(), "an expired sign-in was opened: {calls:?}");
}

/// What a take does with a sign-in it cannot finish, by where the error arises.
/// A value that can never be opened (`Decrypt`), and a row of a known purpose
/// that lacks what it needs (`InvalidInput`), are removed and the error is
/// returned, so that the person starts again. A row with a provider or purpose
/// this version does not know is left in place with the same error, as a newer
/// release may have written it; it goes when it expires.
async fn exercise_what_a_take_does_with_a_sign_in_it_cannot_finish(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let authorize = UpstreamPurpose::Authorize {
        request_id: secret("request-1"),
    };
    let update = "UPDATE upstream_requests SET";
    // What happened to the row, the error class, and whether the row is removed.
    let cases = [
        ("a data key version that does not exist", None, true, true),
        ("malformed v1 text", None, true, true),
        (
            "an unknown purpose",
            Some("purpose = 'other'"),
            false,
            false,
        ),
        (
            "an unknown provider",
            Some("provider = 'other'"),
            false,
            false,
        ),
        (
            "an authorization request without its ID",
            Some("request_id_ciphertext = NULL"),
            false,
            true,
        ),
        (
            "a continuation without its text",
            Some("continuation_ciphertext = NULL"),
            false,
            true,
        ),
        (
            "a continuation without its tenant",
            Some("tenant = NULL"),
            false,
            true,
        ),
    ];
    for (what, change, decrypt, removed) in cases {
        let state = unique("state");
        let hash = common::state_hash(&state);
        if what.starts_with("an authorization") {
            try_save(&store, &state, authorize.clone(), TTL)
                .await
                .unwrap();
        } else {
            save_v2(&store, &state, &tenant, TTL).await;
        }
        match (what, change) {
            (_, Some(change)) => {
                let sql = format!("{update} {change} WHERE state_hash = $1");
                let query = sqlx::query(AssertSqlSafe(sql)).bind(&hash);
                query.execute(store.pool()).await.unwrap();
            }
            ("malformed v1 text", None) => set_text(&store, VERIFIER, &hash, "v1.AAAA").await,
            _ => set_text(&store, VERIFIER, &hash, "v2.9.AAAA").await,
        }
        let err = store.take_upstream_request(&state).await.unwrap_err();
        if decrypt {
            assert!(matches!(err, StoreError::Decrypt), "{what}: {err:?}");
        } else {
            assert!(
                matches!(err, StoreError::InvalidInput(_)),
                "{what}: {err:?}"
            );
        }
        assert_eq!(present(&store, &state).await, !removed, "{what}");
        if removed {
            assert!(store.take_upstream_request(&state).await.unwrap().is_none());
        } else {
            // Left in place, it fails the same way until it expires.
            let again = store.take_upstream_request(&state).await.unwrap_err();
            assert!(
                matches!(again, StoreError::InvalidInput(_)),
                "{what}: {again:?}"
            );
            let expire = "UPDATE upstream_requests SET expires_at = 1 WHERE state_hash = $1";
            sqlx::query(expire)
                .bind(&hash)
                .execute(store.pool())
                .await
                .unwrap();
            assert!(store.take_upstream_request(&state).await.unwrap().is_none());
            assert!(
                !present(&store, &state).await,
                "{what}: stayed after expiry"
            );
        }
    }
}

/// If removing a sign-in that can never be opened fails, the error that made it
/// unopenable is still what the take returns, not the failure of the removal. A
/// table that refers to the row makes the removal fail.
async fn exercise_a_failed_removal_does_not_replace_the_error(db: &Db) {
    let store = db.open(&master()).await;
    let (tenant, state) = (unique_tenant(), unique("state"));
    save_v2(&store, &state, &tenant, TTL).await;
    let hash = common::state_hash(&state);
    set_text(&store, VERIFIER, &hash, "v1.AAAA").await;
    let blocker = format!("blocker_{}", uuid::Uuid::new_v4().simple());
    let statements = [
        format!("CREATE TABLE {blocker} (h TEXT REFERENCES upstream_requests (state_hash))"),
        format!("INSERT INTO {blocker} (h) VALUES ('{hash}')"),
    ];
    for statement in statements {
        let created = sqlx::query(AssertSqlSafe(statement)).execute(store.pool());
        created.await.unwrap();
    }
    let err = store.take_upstream_request(&state).await.unwrap_err();
    let dropped = sqlx::query(AssertSqlSafe(format!("DROP TABLE {blocker}")));
    dropped.execute(store.pool()).await.unwrap();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
    assert!(
        present(&store, &state).await,
        "the removal should have failed"
    );
    let err = store.take_upstream_request(&state).await.unwrap_err();
    assert!(matches!(err, StoreError::Decrypt), "{err:?}");
    assert!(!present(&store, &state).await);
}

/// A wrapper that answers `unwrap` with `InvalidInput`.
struct Refusing {
    local: LocalKeyWrapper,
    refusing: AtomicBool,
}

impl KeyWrapper for Refusing {
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
        if self.refusing.load(Ordering::SeqCst) {
            let refusal = StoreError::InvalidInput("the key service refuses");
            return Box::pin(std::future::ready(Err(refusal)));
        }
        self.local.unwrap(tenant, kek, wrapped)
    }
}

/// Only `Decrypt` from opening a value removes a sign-in, whatever else a
/// wrapper answers: one that answers `InvalidInput` leaves it, and a later take
/// finishes it.
async fn exercise_a_wrapper_error_of_any_class_leaves_the_sign_in(db: &Db) {
    let store = db.open(&master()).await;
    let (tenant, state) = (unique_tenant(), unique("state"));
    save_v2(&store, &state, &tenant, TTL).await;
    let wrapper = Arc::new(Refusing {
        local: LocalKeyWrapper::new(&master(), &[]),
        refusing: AtomicBool::new(true),
    });
    let cold = db.open(&master()).await.with_key_wrapper(wrapper.clone());
    let err = cold.take_upstream_request(&state).await.unwrap_err();
    assert!(matches!(err, StoreError::InvalidInput(_)), "{err:?}");
    assert!(present(&store, &state).await, "the sign-in was removed");

    wrapper.refusing.store(false, Ordering::SeqCst);
    let taken = cold.take_upstream_request(&state).await.unwrap().unwrap();
    assert_eq!(
        describe(&taken.purpose),
        format!("continue {tenant} connect-1")
    );
}

/// A key wrapper that does not answer leaves the sign-in where it is, for a
/// try that the person makes with the same link while it has not expired; when
/// the wrapper answers, that try finishes it once. Also when only `unwrap`
/// fails.
async fn exercise_a_failing_wrapper_leaves_the_sign_in(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let store = cold(db, &wrapper).await;
    let (tenant, state) = (unique_tenant(), unique("state"));
    save_v2(&store, &state, &tenant, TTL).await;
    for (down, deaf) in [(true, false), (false, true)] {
        wrapper.down.store(down, Ordering::SeqCst);
        wrapper.deaf.store(deaf, Ordering::SeqCst);
        for _ in 0..2 {
            let failing = cold(db, &wrapper).await;
            assert_key_wrap(failing.take_upstream_request(&state).await);
            assert!(present(&failing, &state).await, "down {down}, deaf {deaf}");
        }
    }
    wrapper.deaf.store(false, Ordering::SeqCst);
    let back = cold(db, &wrapper).await;
    let taken = back.take_upstream_request(&state).await.unwrap().unwrap();
    assert_eq!(
        describe(&taken.purpose),
        format!("continue {tenant} connect-1")
    );
    assert!(back.take_upstream_request(&state).await.unwrap().is_none());
}

/// Sign-ins that an earlier version stored under the master key are still taken,
/// for all three purposes.
async fn exercise_sign_ins_of_an_earlier_version_are_taken(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    let sign_in_columns = [VERIFIER, REQUEST_ID, CONTINUATION];
    put_v1(&store, &fixture, |column| sign_in_columns.contains(&column)).await;
    for (column, row, ..) in &fixture.values {
        if sign_in_columns.contains(column) {
            let stored = text(&store, *column, row).await;
            assert!(stored.starts_with("v1."), "{column:?} is not v1: {stored}");
        }
    }
    check_sign_ins(&store, &fixture, &tenant).await;
}

/// A sign-in is written as v2 values of the tenant it belongs to: the tenant of
/// an embedding's sign-in, else the default one, whichever tenant the store that
/// saves it is scoped to. The values open from the documented layout, bound to
/// the column and the state's hash, and the reader returns them. Only that
/// tenant gets a key, and the default tenant keeps the one key it has.
async fn exercise_sign_ins_are_written_as_v2(db: &Db) {
    let store = db.open(&master()).await;
    let (tenant, elsewhere) = (unique_tenant(), unique_tenant());
    let scoped = store.for_tenant(&elsewhere);
    let authorize = UpstreamPurpose::Authorize {
        request_id: secret("request-1"),
    };
    let verifier = (VERIFIER, "verifier-1");
    let cases = [
        (
            authorize,
            DEFAULT_TENANT,
            vec![verifier, (REQUEST_ID, "request-1")],
        ),
        (UpstreamPurpose::Account, DEFAULT_TENANT, vec![verifier]),
        (
            continued(&tenant),
            tenant.as_str(),
            vec![verifier, (CONTINUATION, "connect-1")],
        ),
    ];
    let mut states = Vec::new();
    for (purpose, owner, columns) in &cases {
        let state = unique("state");
        save(&scoped, &state, purpose.clone()).await;
        let hash = common::state_hash(&state);
        for (column, plaintext) in columns {
            let stored = text(&store, *column, &hash).await;
            assert!(
                stored.starts_with("v2.1."),
                "{column:?} for {owner}: {stored}"
            );
            let opened = unseal(&store, owner, *column, &hash, &stored).await;
            assert_eq!(opened, *plaintext, "{column:?} for {owner}");
        }
        states.push(state);
    }
    assert_eq!(
        rows(&store, &elsewhere).await,
        0,
        "the saving store's tenant got a key"
    );
    assert_eq!(rows(&store, &tenant).await, 1);
    let default_keys = rows(&store, DEFAULT_TENANT).await;
    assert_eq!(
        default_keys, 1,
        "the default tenant must keep one key version"
    );

    let expected = [
        "authorize request-1",
        "account",
        &format!("continue {tenant} connect-1"),
    ];
    for (state, expected) in states.iter().zip(expected) {
        let taken = store.take_upstream_request(state).await.unwrap().unwrap();
        assert_eq!(describe(&taken.purpose), expected);
        assert_eq!(taken.code_verifier.expose_secret(), "verifier-1");
        assert!(!present(&store, state).await);
    }
}

/// A key wrapper that does not answer stops a sign-in from being saved: nothing
/// is stored and no key is made, also when only `unwrap` fails; when it answers,
/// saving works.
async fn exercise_a_failing_wrapper_stops_a_sign_in_write(db: &Db) {
    let wrapper = Arc::new(Masking::default());
    let (tenant, fresh) = (unique_tenant(), unique_tenant());
    let store = cold(db, &wrapper).await;
    save(&store, &unique("state"), continued(&tenant)).await;
    // A tenant with a key that cannot be unwrapped, and one with no key yet.
    let failures = [
        (true, false, &tenant),
        (false, true, &tenant),
        (true, false, &fresh),
    ];
    for (down, deaf, owner) in failures {
        wrapper.down.store(down, Ordering::SeqCst);
        wrapper.deaf.store(deaf, Ordering::SeqCst);
        let failing = cold(db, &wrapper).await;
        let state = unique("state");
        assert_key_wrap(try_save(&failing, &state, continued(owner), TTL).await);
        assert!(
            !present(&failing, &state).await,
            "a failed save stored a sign-in"
        );
    }
    assert_eq!(rows(&store, &fresh).await, 0, "a failed save made a key");

    wrapper.down.store(false, Ordering::SeqCst);
    wrapper.deaf.store(false, Ordering::SeqCst);
    let back = cold(db, &wrapper).await;
    let state = unique("state");
    save(&back, &state, continued(&fresh)).await;
    assert_eq!(rows(&back, &fresh).await, 1);
    assert!(back.take_upstream_request(&state).await.unwrap().is_some());
}

/// Sign-ins: what the writer stores, and when the reader removes one, who gets it,
/// and what a failure leaves.
async fn exercise_sign_ins(db: &Db) {
    exercise_sign_ins_are_written_as_v2(db).await;
    exercise_sign_ins_of_an_earlier_version_are_taken(db).await;
    exercise_a_failing_wrapper_stops_a_sign_in_write(db).await;
    exercise_a_sign_in_is_taken_once(db).await;
    exercise_a_sign_in_changed_while_it_is_opened(db).await;
    exercise_an_expired_sign_in_is_removed_unopened(db).await;
    exercise_what_a_take_does_with_a_sign_in_it_cannot_finish(db).await;
    exercise_a_wrapper_error_of_any_class_leaves_the_sign_in(db).await;
    exercise_a_failed_removal_does_not_replace_the_error(db).await;
    exercise_a_failing_wrapper_leaves_the_sign_in(db).await;
}

/// A database that fails while the sign-in is opened leaves it where it is: the
/// table of the data keys is gone for a moment.
#[tokio::test]
async fn sqlite_a_database_error_leaves_the_sign_in() {
    let db = Db::sqlite();
    let store = db.open(&master()).await;
    let (tenant, state) = (unique_tenant(), unique("state"));
    save_v2(&store, &state, &tenant, TTL).await;
    let rename = |from: &str, to: &str| format!("ALTER TABLE {from} RENAME TO {to}");
    let moved = rename("data_keys", "data_keys_away");
    sqlx::query(AssertSqlSafe(moved))
        .execute(store.pool())
        .await
        .unwrap();
    let failing = db.open(&master()).await;
    let err = failing.take_upstream_request(&state).await.unwrap_err();
    assert!(matches!(err, StoreError::Database(_)), "{err:?}");
    assert!(present(&failing, &state).await, "the sign-in was removed");
    let back = rename("data_keys_away", "data_keys");
    sqlx::query(AssertSqlSafe(back))
        .execute(store.pool())
        .await
        .unwrap();
    let taken = failing
        .take_upstream_request(&state)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        describe(&taken.purpose),
        format!("continue {tenant} connect-1")
    );
}

/// A row that cannot be read is a failure of the database, not of the sign-in,
/// and the sign-in is left where it is. SQLite lets a text column hold a blob,
/// which does not read as text; PostgreSQL turns a value into text on the way
/// in, so this is a SQLite test.
#[tokio::test]
async fn sqlite_a_row_that_cannot_be_read_is_left_in_place() {
    let db = Db::sqlite();
    let store = db.open(&master()).await;
    let (tenant, state) = (unique_tenant(), unique("state"));
    save_v2(&store, &state, &tenant, TTL).await;
    let blob = "UPDATE upstream_requests SET provider = x'00' WHERE state_hash = $1";
    sqlx::query(blob)
        .bind(common::state_hash(&state))
        .execute(store.pool())
        .await
        .unwrap();
    let err = store.take_upstream_request(&state).await.unwrap_err();
    assert!(matches!(err, StoreError::Database(_)), "{err:?}");
    assert!(present(&store, &state).await, "the sign-in was removed");
}

/// A wrapper that needs a connection of the store's pool while it unwraps.
struct UsesPool {
    local: LocalKeyWrapper,
    pool: sqlx::AnyPool,
    unwraps: AtomicUsize,
}

impl KeyWrapper for UsesPool {
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
        Box::pin(async move {
            self.unwraps.fetch_add(1, Ordering::SeqCst);
            sqlx::query("SELECT 1")
                .execute(&self.pool)
                .await
                .map_err(|err| {
                    StoreError::KeyWrap(format!("the take held the only connection: {err}"))
                })?;
            self.local.unwrap(tenant, kek, wrapped).await
        })
    }
}

/// The key of a sign-in's tenant is found without a second connection: a pool
/// of one connection has none to spare for the insert.
#[tokio::test]
async fn sqlite_a_sign_in_for_a_new_tenant_is_saved_with_one_connection() {
    let db = Db::sqlite();
    let pool = PoolSettings {
        max_connections: 1,
        acquire_timeout: Duration::from_secs(10),
        ..PoolSettings::default()
    };
    let store = Store::connect_with(&db.url, &master(), &[], pool, Migrations::Apply)
        .await
        .unwrap();
    for purpose in [continued(&unique_tenant()), UpstreamPurpose::Account] {
        let state = unique("state");
        let saved = try_save(&store, &state, purpose, TTL).await;
        saved.unwrap_or_else(|err| panic!("the save has no connection: {err:?}"));
        assert!(store.take_upstream_request(&state).await.unwrap().is_some());
    }
}

/// A take holds no connection while it opens the sign-in: a key wrapper that
/// needs one from a pool of one gets it, and the take, the removal of an
/// expired sign-in and the removal after the open all work.
#[tokio::test]
async fn sqlite_a_take_holds_no_connection_while_the_wrapper_answers() {
    let db = Db::sqlite();
    let pool = PoolSettings {
        max_connections: 1,
        acquire_timeout: Duration::from_secs(10),
        ..PoolSettings::default()
    };
    let base = Store::connect_with(&db.url, &master(), &[], pool, Migrations::Apply)
        .await
        .unwrap();
    let local = LocalKeyWrapper::new(&master(), &[]);
    let wrapper = Arc::new(UsesPool {
        local,
        pool: base.pool().clone(),
        unwraps: AtomicUsize::new(0),
    });
    let store = base.with_key_wrapper(wrapper.clone());
    let tenant = unique_tenant();
    for ttl in [TTL, Duration::ZERO] {
        let state = unique("state");
        save_v2(&store, &state, &tenant, ttl).await;
        let cold_store = store.clone().with_key_wrapper(wrapper.clone());
        let before = wrapper.unwraps.load(Ordering::SeqCst);
        let taken = cold_store.take_upstream_request(&state).await.unwrap();
        let asked = wrapper.unwraps.load(Ordering::SeqCst) - before;
        assert_eq!(taken.is_some(), ttl == TTL);
        assert_eq!(asked, usize::from(ttl == TTL), "unwraps for a take");
        assert!(!present(&store, &state).await);
    }
}

/// What the writers of the provider tokens make.
async fn exercise_tokens(db: &Db) {
    exercise_tokens_are_written_as_v2(db).await;
    exercise_the_compare_and_set_seals_for_the_accounts_tenant(db).await;
    exercise_a_failing_wrapper_stops_a_token_write(db).await;
}

#[tokio::test]
async fn sqlite_all() {
    let db = Db::sqlite();
    exercise_keys(&db).await;
    exercise_new_versions(&db).await;
    exercise_values(&db).await;
    exercise_tokens(&db).await;
    exercise_sign_ins(&db).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_keys() {
    exercise_keys(&Db::postgres()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_new_versions() {
    exercise_new_versions(&Db::postgres()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_values() {
    exercise_values(&Db::postgres()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_tokens() {
    exercise_tokens(&Db::postgres()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_sign_ins() {
    exercise_sign_ins(&Db::postgres()).await;
}

// A tenant whose data keys were destroyed: its `data_keys` rows hold no key,
// with one at `DESTROYED` that marks it. The tests of what the mark means write
// it themselves, in the layout that `Store::destroy_data_keys` leaves; the first
// test of the destroy pins that the two match.

const DESTROYED: i64 = i64::MAX;

fn dead_kek() -> Kek {
    Kek {
        provider: "destroyed".to_owned(),
        id: String::new(),
        version: 0,
    }
}

/// The versions a destruction leaves rows at: 1, one above each deleted version,
/// and `DESTROYED`.
fn mark_versions(deleted: &[i64]) -> Vec<i64> {
    let mut versions: Vec<i64> = std::iter::once(1)
        .chain(deleted.iter().map(|version| version.saturating_add(1)))
        .chain(std::iter::once(DESTROYED))
        .collect();
    versions.sort_unstable();
    versions.dedup();
    versions
}

/// Destroys `tenant`'s keys as a destruction does: its rows are replaced by the
/// mark.
async fn mark_destroyed(store: &Store, tenant: &str) {
    let versions: Vec<i64> = sqlx::query_scalar("SELECT version FROM data_keys WHERE tenant = $1")
        .bind(tenant)
        .fetch_all(store.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM data_keys WHERE tenant = $1")
        .bind(tenant)
        .execute(store.pool())
        .await
        .unwrap();
    for version in mark_versions(&versions) {
        set_key(store, tenant, version, &dead_kek(), "").await;
    }
}

/// The `key_rows` of a mark at `versions`.
fn dead(versions: &[i64]) -> Vec<(i64, String, String)> {
    let dead = |version: &i64| (*version, "destroyed".to_owned(), String::new());
    versions.iter().map(dead).collect()
}

fn assert_destroyed<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    let err = result.unwrap_err();
    assert!(matches!(err, StoreError::KeysDestroyed), "{err:?}");
}

/// A tenant's rows: version, provider and wrapped key, by version.
async fn key_rows(store: &Store, tenant: &str) -> Vec<(i64, String, String)> {
    sqlx::query_as(
        "SELECT version, provider, wrapped FROM data_keys WHERE tenant = $1 ORDER BY version",
    )
    .bind(tenant)
    .fetch_all(store.pool())
    .await
    .unwrap()
}

/// How many rows the insert of a new key at `version` stores, as `add_key` of
/// this build and of the one before makes it.
async fn insert_key(store: &Store, tenant: &str, version: i64) -> u64 {
    sqlx::query(
        "INSERT INTO data_keys (tenant, version, provider, kek_id, kek_version, wrapped, \
         created_at) VALUES ($1, $2, 'local', 'kek', 1, 'x', 1) \
         ON CONFLICT (tenant, version) DO NOTHING",
    )
    .bind(tenant)
    .bind(version)
    .execute(store.pool())
    .await
    .unwrap()
    .rows_affected()
}

/// No key is made for a destroyed tenant, and one made by hand beside the mark
/// is deleted when a key is asked for. The insert that the build before this
/// one would try stores nothing.
async fn exercise_a_destroyed_tenant_gets_no_key_and_keeps_none(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    mark_destroyed(&store, &tenant).await;
    let scoped = store.for_tenant(&tenant);
    assert_destroyed(scoped.data_key().await);
    assert_destroyed(scoped.data_key_version(1).await);
    assert_eq!(key_rows(&store, &tenant).await, dead(&[1, DESTROYED]));

    let live = LocalKeyWrapper::new(&master(), &[]).current();
    set_key(&store, &tenant, 2, &live, "x").await;
    // A row is dead by its provider and its empty key together.
    set_key(&store, &tenant, 3, &dead_kek(), "x").await;
    assert_destroyed(scoped.data_key().await);
    assert_eq!(key_rows(&store, &tenant).await, dead(&[1, DESTROYED]));
    for version in [1, DESTROYED] {
        assert_eq!(insert_key(&store, &tenant, version).await, 0, "{version}");
    }
}

/// A cold store reads none of a destroyed tenant's values and writes no secret
/// for it; a write that touches no secret still works, and another tenant is
/// untouched.
async fn exercise_readers_and_writers_refuse_a_destroyed_tenant(db: &Db) {
    let store = db.open(&master()).await;
    let (tenant, other) = (unique_tenant(), unique_tenant());
    let mine = fill(db, &store, &tenant).await;
    let theirs = fill(db, &store, &other).await;
    let rule = add_rule(&store, &mine.imap, "a@example.com").await;
    add_rule(&store, &theirs.imap, "b@example.com").await;
    let texts = all_texts(&store, std::slice::from_ref(&mine)).await;
    let pattern = text(&store, PATTERN, &rule).await;
    let their_key = key_rows(&store, &other).await;
    let cold = db.open(&master()).await;
    mark_destroyed(&store, &tenant).await;
    assert_eq!(key_rows(&store, &tenant).await, dead(&[1, 2, DESTROYED]));

    let (imap, oauth) = (&mine.imap, &mine.oauth);
    assert_destroyed(cold.credentials(imap).await);
    assert_destroyed(cold.webhook(imap).await);
    assert_destroyed(cold.load_webhook(imap).await);
    assert_destroyed(cold.pending_mail_events(imap, 10).await);
    assert_destroyed(cold.upstream_tokens(oauth).await);
    assert_destroyed(cold.webhook_filter_rules(imap, 9).await);
    assert_destroyed(cold.take_upstream_request(&mine.states[2]).await);

    let scoped = cold.for_tenant(&tenant);
    let email = format!("{}@example.com", unique("imap"));
    assert_destroyed(scoped.upsert_account(&email, &secret("new-password")).await);
    let account = OAuthAccount {
        provider: Provider::Graph,
        subject: &unique("subject"),
        email: &format!("{}@example.com", unique("oauth")),
    };
    assert_destroyed(
        scoped
            .upsert_oauth_account(&account, &tokens("refresh-2"))
            .await,
    );
    let hook = webhook("https://hooks.example/2", "Bearer two", "whsec_two");
    assert_destroyed(cold.save_webhook(imap, &hook).await);
    assert_destroyed(cold.append_mail_event(imap, "{}", None).await);
    assert_destroyed(cold.save_upstream_tokens(oauth, &tokens("refresh-2")).await);
    let (current, fresh) = (secret("refresh-1"), tokens("refresh-2"));
    assert_destroyed(
        cold.save_upstream_tokens_if_current(oauth, &current, &fresh)
            .await,
    );
    let state = unique("state");
    assert_destroyed(try_save(&cold, &state, continued(&tenant), TTL).await);
    let edit = NewFilterRule {
        action: "block".to_owned(),
        field: "from".to_owned(),
        kind: "equals".to_owned(),
        pattern: secret("c@example.com"),
    };
    assert_destroyed(
        cold.add_webhook_filter_rule(imap, &edit, 9, |_| Ok(()))
            .await,
    );
    let updated = cold.update_webhook_filter_rule(imap, &rule, &edit, 9, |_| Ok(()));
    assert_destroyed(updated.await);
    assert_destroyed(cold.set_webhook_enabled(imap, false).await);
    let on = cold.set_webhook_filter_rule_enabled(imap, &rule, true, 9, |_| Ok(()));
    assert_destroyed(on.await);
    let off = cold.set_webhook_filter_rule_enabled(imap, &rule, false, 9, |_| Ok(()));
    assert_eq!(off.await.unwrap(), ChangedFilterRule::Changed);

    assert_eq!(all_texts(&store, std::slice::from_ref(&mine)).await, texts);
    assert_eq!(text(&store, PATTERN, &rule).await, pattern);
    assert!(!present(&store, &state).await);
    assert_eq!(key_rows(&store, &tenant).await, dead(&[1, 2, DESTROYED]));
    // The sign-ins that no tenant started are the default tenant's.
    for state in &mine.states[..2] {
        assert!(cold.take_upstream_request(state).await.unwrap().is_some());
    }
    check_reads(&cold, &theirs).await;
    cold.save_webhook(&theirs.imap, &hook).await.unwrap();
    assert_eq!(key_rows(&store, &other).await, their_key);
}

/// A store that holds a destroyed tenant's key reads with it until it next asks
/// for a key of that tenant, and then forgets that tenant's keys only.
async fn exercise_a_store_that_holds_the_key_forgets_it_at_its_next_key_request(db: &Db) {
    let masking = Arc::new(Masking::default());
    let store = db.open(&master()).await.with_key_wrapper(masking.clone());
    let tenant = unique_tenant();
    // A name that starts with the other, so that forgetting by prefix shows.
    let other = format!("{tenant}-2");
    let mine = fill(db, &store, &tenant).await;
    let theirs = fill(db, &store, &other).await;
    check_reads(&store, &mine).await;
    check_reads(&store, &theirs).await;
    mark_destroyed(&store, &tenant).await;

    let found = store.credentials(&mine.imap).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "app-password");
    assert_destroyed(store.for_tenant(&tenant).data_key().await);
    assert_destroyed(store.credentials(&mine.imap).await);

    masking.calls();
    check_reads(&store, &theirs).await;
    let asked = format!("unwrap {other} ");
    let calls = masking.calls();
    assert!(
        !calls.iter().any(|call| call.starts_with(&asked)),
        "{calls:?}"
    );
}

/// A key that a read unwraps from a row it read before the tenant was destroyed
/// is returned to that read, and not kept for the next one.
async fn exercise_a_key_unwrapped_while_the_tenant_is_destroyed_is_not_kept(db: &Db) {
    let plain = db.open(&master()).await;
    let tenant = unique_tenant();
    let mine = fill(db, &plain, &tenant).await;
    let wrapper = Interrupted::new();
    let store = wrapper.store(db).await;
    let scoped = store.for_tenant(&tenant);
    let destroyed = tenant.clone();
    *wrapper.meanwhile.lock().unwrap() = Some(hook(move || async move {
        mark_destroyed(&plain, &destroyed).await;
        assert_destroyed(scoped.data_key().await);
    }));

    let found = store.credentials(&mine.imap).await.unwrap().unwrap();
    assert_eq!(found.password.expose_secret(), "app-password");
    assert_destroyed(store.credentials(&mine.imap).await);
}

fn assert_invalid<T: std::fmt::Debug>(result: Result<T, StoreError>) {
    let err = result.unwrap_err();
    assert!(matches!(err, StoreError::InvalidInput(_)), "{err:?}");
}

/// A tenant's rows: version, KEK ID, KEK version and creation time, by version.
async fn key_details(store: &Store, tenant: &str) -> Vec<(i64, String, i64, i64)> {
    sqlx::query_as(
        "SELECT version, kek_id, kek_version, created_at FROM data_keys WHERE tenant = $1 \
         ORDER BY version",
    )
    .bind(tenant)
    .fetch_all(store.pool())
    .await
    .unwrap()
}

/// Every reader of a destroyed tenant's values, and every key request for it,
/// answers `KeysDestroyed` through `store`.
async fn check_destroyed(store: &Store, fixture: &Fixture, tenant: &str) {
    let (imap, oauth) = (&fixture.imap, &fixture.oauth);
    assert_destroyed(store.credentials(imap).await);
    assert_destroyed(store.webhook(imap).await);
    assert_destroyed(store.load_webhook(imap).await);
    assert_destroyed(store.pending_mail_events(imap, 10).await);
    assert_destroyed(store.upstream_tokens(oauth).await);
    assert_destroyed(store.webhook_filter_rules(imap, 9).await);
    assert_destroyed(store.take_upstream_request(&fixture.states[2]).await);
    let scoped = store.for_tenant(tenant);
    assert_destroyed(scoped.data_key().await);
    for version in [1, 2, 5] {
        assert_destroyed(scoped.data_key_version(version).await);
    }
}

/// Destroying deletes the tenant's keys, wherever their versions are, and leaves
/// the mark: the store that destroys reads none of its values at once, and nor
/// does a cold one. Other tenants and the default one's sign-ins are untouched,
/// a repeat changes nothing, accounts can be deleted afterwards, and two
/// destroys at once delete each key once.
async fn exercise_destroying_makes_every_value_of_the_tenant_unreadable_at_once(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    // A name that starts with the other, so that deleting by prefix shows.
    let other = format!("{tenant}-2");
    let mine = fill(db, &store, &tenant).await;
    let theirs = fill(db, &store, &other).await;
    add_rule(&store, &mine.imap, "a@example.com").await;
    add_rule(&store, &theirs.imap, "b@example.com").await;
    check_reads(&store, &mine).await;
    // A master key that unwraps no row adds a version; a row made by hand leaves a gap.
    let stranger = db.open(&other_master()).await.for_tenant(&tenant);
    assert_eq!(stranger.data_key().await.unwrap().0, 2);
    let live = LocalKeyWrapper::new(&master(), &[]).current();
    set_key(&store, &tenant, 5, &live, "x").await;
    let their_key = key_rows(&store, &other).await;

    let scoped = store.for_tenant(&tenant);
    assert_eq!(scoped.destroy_data_keys().await.unwrap(), 3);
    let mark = mark_versions(&[1, 2, 5]);
    assert_eq!(mark, [1, 2, 3, 6, DESTROYED]);
    assert_eq!(key_rows(&store, &tenant).await, dead(&mark));
    let details = key_details(&store, &tenant).await;
    for (_, kek_id, kek_version, _) in &details {
        assert_eq!((kek_id.as_str(), *kek_version), ("", 0));
    }
    // What a store that read the rows before the commit, or after it, would insert.
    for version in mark {
        assert_eq!(insert_key(&store, &tenant, version).await, 0, "{version}");
    }

    let cold = db.open(&master()).await;
    check_destroyed(&store, &mine, &tenant).await;
    check_destroyed(&cold, &mine, &tenant).await;
    // The sign-ins that no tenant started are the default tenant's.
    for state in &mine.states[..2] {
        assert!(store.take_upstream_request(state).await.unwrap().is_some());
    }
    for reader in [&store, &cold] {
        check_reads(reader, &theirs).await;
        assert_eq!(patterns_of(reader, &theirs.imap).await, ["b@example.com"]);
    }
    assert_eq!(key_rows(&store, &other).await, their_key);

    assert_eq!(scoped.destroy_data_keys().await.unwrap(), 0);
    assert_eq!(key_details(&store, &tenant).await, details);
    assert!(store.delete_account(&mine.imap).await.unwrap());
    assert!(store.delete_account(&mine.oauth).await.unwrap());

    let both = unique_tenant();
    fill(db, &store, &both).await;
    let (first, second) = (store.for_tenant(&both), cold.for_tenant(&both));
    let (first, second) = tokio::join!(first.destroy_data_keys(), second.destroy_data_keys());
    let mut counts = [first.unwrap(), second.unwrap()];
    counts.sort_unstable();
    assert_eq!(counts, [0, 1]);
    assert_eq!(key_rows(&store, &both).await, dead(&[1, 2, DESTROYED]));
}

/// Destroying is refused, and changes nothing, while any of the tenant's values
/// is under the master key, in whichever column. Deleting the account that holds
/// it lets the destroy go ahead, and another tenant's such value does not stop it.
async fn exercise_destroying_is_refused_while_a_value_is_under_the_master_key(db: &Db) {
    let store = db.open(&master()).await;
    let (tenant, other) = (unique_tenant(), unique_tenant());
    let mine = fill(db, &store, &tenant).await;
    let theirs = fill(db, &store, &other).await;
    let rule = add_rule(&store, &mine.imap, "a@example.com").await;
    let scoped = store.for_tenant(&tenant);
    let key = key_rows(&store, &tenant).await;
    assert_eq!(key.len(), 1);
    let own = mine.values.iter().filter(|value| value.4 == tenant);
    let mut values: Vec<(Column, String)> = own.map(|value| (value.0, value.1.clone())).collect();
    values.push((PATTERN, rule));
    assert_eq!(values.len(), 9);
    for (column, row) in &values {
        let saved = text(&store, *column, row).await;
        // No key opens it, so the sweep never moves it: the check reads the prefix only.
        set_text(&store, *column, row, "v1.x").await;
        assert_invalid(scoped.destroy_data_keys().await);
        assert_eq!(key_rows(&store, &tenant).await, key, "{column:?}");
        scoped.data_key_version(1).await.unwrap();
        set_text(&store, *column, row, &saved).await;
    }
    check_reads(&store, &mine).await;

    let password = text(&store, PASSWORD, &theirs.imap.0).await;
    set_text(&store, PASSWORD, &mine.imap.0, "v1.x").await;
    set_text(&store, PASSWORD, &theirs.imap.0, "v1.x").await;
    assert_invalid(scoped.destroy_data_keys().await);
    assert!(store.delete_account(&mine.imap).await.unwrap());
    assert_eq!(scoped.destroy_data_keys().await.unwrap(), 1);
    set_text(&store, PASSWORD, &theirs.imap.0, &password).await;
    check_reads(&store, &theirs).await;
}

/// A store that finds no key for a tenant, and adds the first while the tenant
/// is destroyed, stores none: version 1 is taken by the mark.
async fn exercise_a_first_key_made_while_the_tenant_is_destroyed_is_never_stored(db: &Db) {
    let tenant = unique_tenant();
    let wrapper = Interrupted::new();
    let other = db.open(&master()).await;
    let destroyed = tenant.clone();
    *wrapper.in_wrap.lock().unwrap() = Some(hook(move || async move {
        let scoped = other.for_tenant(&destroyed);
        assert_eq!(scoped.destroy_data_keys().await.unwrap(), 0);
    }));
    let store = wrapper.store(db).await;

    assert_destroyed(store.for_tenant(&tenant).data_key().await);
    assert_eq!(key_rows(&store, &tenant).await, dead(&[1, DESTROYED]));
}

/// A store that unwraps none of a tenant's keys, and adds a version while the
/// tenant is destroyed, stores none: one above the version it read is taken.
async fn exercise_a_version_made_while_the_tenant_is_destroyed_is_never_stored(db: &Db) {
    let tenant = unique_tenant();
    let stranger = db.open(&other_master()).await.for_tenant(&tenant);
    assert_eq!(stranger.data_key().await.unwrap().0, 1);
    let wrapper = Interrupted::new();
    let other = db.open(&master()).await;
    let destroyed = tenant.clone();
    *wrapper.in_wrap.lock().unwrap() = Some(hook(move || async move {
        let scoped = other.for_tenant(&destroyed);
        assert_eq!(scoped.destroy_data_keys().await.unwrap(), 1);
    }));
    let store = wrapper.store(db).await;
    let scoped = store.for_tenant(&tenant);

    assert_destroyed(scoped.data_key().await);
    assert_eq!(key_rows(&store, &tenant).await, dead(&[1, 2, DESTROYED]));
    assert_destroyed(scoped.data_key_version(2).await);
}

/// A write that took its key before the destroy, and writes after it, leaves a
/// value that only that store, which still holds the key, opens; and it forgets
/// the key when it next asks for one.
async fn exercise_a_write_racing_the_destroy_leaves_nothing_readable(db: &Db) {
    let plain = db.open(&master()).await;
    let tenant = unique_tenant();
    let mine = fill(db, &plain, &tenant).await;
    let wrapper = Interrupted::new();
    let destroying = db.open(&master()).await;
    let (inside, destroyed) = (destroying.clone(), tenant.clone());
    *wrapper.meanwhile.lock().unwrap() = Some(hook(move || async move {
        let scoped = inside.for_tenant(&destroyed);
        assert_eq!(scoped.destroy_data_keys().await.unwrap(), 1);
    }));
    let store = wrapper.store(db).await;

    let settings = webhook("https://hooks.example/2", "Bearer two", "whsec_two");
    store.save_webhook(&mine.imap, &settings).await.unwrap();
    let cold = db.open(&master()).await;
    assert_destroyed(destroying.webhook(&mine.imap).await);
    assert_destroyed(cold.webhook(&mine.imap).await);
    assert_eq!(key_rows(&plain, &tenant).await, dead(&[1, 2, DESTROYED]));
    let held = store.webhook(&mine.imap).await.unwrap().unwrap();
    assert_eq!(held.settings.signing_secret.expose_secret(), "whsec_two");
    assert_destroyed(store.for_tenant(&tenant).data_key().await);
    assert_destroyed(store.webhook(&mine.imap).await);
}

/// A tenant that never had a key can be destroyed, and gets none afterwards.
async fn exercise_a_tenant_without_keys_can_be_destroyed(db: &Db) {
    let store = db.open(&master()).await;
    let tenant = unique_tenant();
    let scoped = store.for_tenant(&tenant);
    assert_eq!(scoped.destroy_data_keys().await.unwrap(), 0);
    assert_eq!(key_rows(&store, &tenant).await, dead(&[1, DESTROYED]));
    let email = format!("{}@example.com", unique("imap"));
    assert_destroyed(scoped.upsert_account(&email, &secret("app-password")).await);
    let state = unique("state");
    assert_destroyed(try_save(&store, &state, continued(&tenant), TTL).await);
}

async fn exercise_destroyed(db: &Db) {
    exercise_a_destroyed_tenant_gets_no_key_and_keeps_none(db).await;
    exercise_readers_and_writers_refuse_a_destroyed_tenant(db).await;
    exercise_a_store_that_holds_the_key_forgets_it_at_its_next_key_request(db).await;
    exercise_a_key_unwrapped_while_the_tenant_is_destroyed_is_not_kept(db).await;
    exercise_destroying_makes_every_value_of_the_tenant_unreadable_at_once(db).await;
    exercise_destroying_is_refused_while_a_value_is_under_the_master_key(db).await;
    exercise_a_first_key_made_while_the_tenant_is_destroyed_is_never_stored(db).await;
    exercise_a_version_made_while_the_tenant_is_destroyed_is_never_stored(db).await;
    exercise_a_write_racing_the_destroy_leaves_nothing_readable(db).await;
    exercise_a_tenant_without_keys_can_be_destroyed(db).await;
}

/// The default tenant holds every sign-in that no tenant started, so its keys
/// are never destroyed. SQLite only: a broken refusal must never destroy the
/// default tenant of the shared PostgreSQL database.
#[tokio::test]
async fn sqlite_the_default_tenants_keys_cannot_be_destroyed() {
    let db = Db::sqlite();
    let store = db.open(&master()).await;
    let fixture = fill(&db, &store, DEFAULT_TENANT).await;
    let key = key_rows(&store, DEFAULT_TENANT).await;
    assert_invalid(store.destroy_data_keys().await);
    assert_eq!(key_rows(&store, DEFAULT_TENANT).await, key);
    check_reads(&store, &fixture).await;
}

#[tokio::test]
async fn sqlite_destroyed() {
    exercise_destroyed(&Db::sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_destroyed() {
    exercise_destroyed(&Db::postgres()).await;
}

/// The associated data, the master key's ID and the layout of a wrapped key
/// are stored data: a key wrapped by an earlier build must still unwrap.
#[tokio::test]
async fn sqlite_unwraps_a_key_wrapped_by_an_earlier_build() {
    let db = Db::sqlite();
    let store = db.open(&master()).await;
    sqlx::query(
        "INSERT INTO data_keys (tenant, version, provider, kek_id, kek_version, wrapped, \
         created_at) VALUES ('tenant-a', 1, 'local', $1, 1, $2, 1)",
    )
    .bind(MASTER_ID)
    .bind(WRAPPED)
    .execute(store.pool())
    .await
    .unwrap();
    let (version, key) = store.for_tenant("tenant-a").data_key().await.unwrap();
    assert_eq!((version, key.expose()), (1, &[0xa5; 32]));
}

/// The sweep moves the v1 values to data keys, also those that a previous master
/// key sealed, and leaves v2 values alone, still readable through the previous
/// key that wrapped their data key. It visits every row of the database, so it
/// runs on SQLite only; `exercise_sweep_all` covers both backends.
#[tokio::test]
async fn sqlite_the_sweep_leaves_v2_values_alone() {
    let db = Db::sqlite();
    let old = master();
    let store = db.open(&old).await;
    let tenant = unique_tenant();
    let fixture = fill(&db, &store, &tenant).await;
    let v1 = put_some_v1(&store, &fixture).await;
    assert_eq!(v1, 7, "seven of the eleven values are v1 and four are v2");
    let before = written(&store, &fixture.imap).await;
    store.close().await;

    let rotating = Store::connect_rotating(&db.url, &random_master(), &[old])
        .await
        .unwrap();
    // The values that are v1 move; the v2 ones are not touched.
    assert_eq!(swept(rotating.reencrypt().await.unwrap()), (v1, 4, 0, 0));
    assert_eq!(swept(rotating.reencrypt().await.unwrap()), (0, 11, 0, 0));
    assert_eq!(before, written(&rotating, &fixture.imap).await);
    check_reads(&rotating, &fixture).await;
    check_sign_ins(&rotating, &fixture, &tenant).await;

    // Text that starts with `v2.` counts as v2, whatever follows, and is not
    // read. The sign-ins are gone, taken above, so five of the other values
    // are left.
    set_text(&rotating, PAYLOAD, &fixture.event.id, "v2.0.AAAA").await;
    assert_eq!(swept(rotating.reencrypt().await.unwrap()), (0, 6, 0, 0));
    // Not even fetched: SQLite keeps text that is not valid UTF-8 (here `v2.1`
    // and the byte 0xFF), and a statement that returned this row would fail.
    let poison = "UPDATE mail_events SET payload_ciphertext = CAST(X'76322E31FF' AS TEXT) \
                  WHERE id = $1";
    let poisoned = sqlx::query(poison).bind(&fixture.event.id);
    poisoned.execute(rotating.pool()).await.unwrap();
    assert_eq!(swept(rotating.reencrypt().await.unwrap()), (0, 6, 0, 0));
    // The prefix is matched with its case, as SQLite's `LIKE` would not: this
    // text is not v2, so it is read, and no key opens it.
    set_text(&rotating, PAYLOAD, &fixture.event.id, "V2.1.AAAA").await;
    assert_eq!(swept(rotating.reencrypt().await.unwrap()), (0, 5, 1, 0));
}

// The sweep. It goes over every row of the database, so each exercise starts
// from an empty one, and PostgreSQL gets a database of its own.

/// What a pass reports: values moved, already v2, unreadable and lost to a
/// writer.
const fn swept(report: Reencrypted) -> (u64, u64, u64, u64) {
    (
        report.updated,
        report.already_v2,
        report.unreadable,
        report.lost_races,
    )
}

/// A store with no accounts, sign-ins or data keys in its database.
async fn empty(db: &Db, key: &MasterKey) -> Store {
    let store = db.open(key).await;
    for table in ["accounts", "upstream_requests", "data_keys"] {
        let delete = format!("DELETE FROM {table}");
        let done = sqlx::query(AssertSqlSafe(delete)).execute(store.pool());
        done.await.unwrap();
    }
    store
}

async fn all_keys(store: &Store) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM data_keys")
        .fetch_one(store.pool())
        .await
        .unwrap()
}

/// A fixture for each of `tenants`, all of whose values are v1, as an earlier
/// version stored them.
async fn old_fixtures(db: &Db, store: &Store, tenants: &[String]) -> Vec<Fixture> {
    let mut found = Vec::new();
    for tenant in tenants {
        let fixture = fill(db, store, tenant).await;
        put_v1(store, &fixture, |_| true).await;
        found.push(fixture);
    }
    found
}

/// The text of every value of `fixtures`.
async fn all_texts(store: &Store, fixtures: &[Fixture]) -> Vec<String> {
    let mut found = Vec::new();
    for (column, row, ..) in fixtures.iter().flat_map(|fixture| &fixture.values) {
        found.push(text(store, *column, row).await);
    }
    found
}

/// Every column moves to the data key of its row's tenant, as the writer of the
/// column would seal it: in a tenant and in one whose name is percent-encoded,
/// with the sign-ins that no tenant started in the default one. An upgraded
/// database has no data keys yet, so the sweep makes them. Each value opens
/// through its reader and from the documented layout alone.
async fn exercise_every_column_moves_to_the_data_key_of_its_rows_tenant(db: &Db) {
    let store = empty(db, &master()).await;
    let tenants = [unique_tenant(), format!("acme/{}%", unique("team"))];
    let fixtures = old_fixtures(db, &store, &tenants).await;
    sqlx::query("DELETE FROM data_keys")
        .execute(store.pool())
        .await
        .unwrap();
    for stored in all_texts(&store, &fixtures).await {
        assert!(stored.starts_with("v1."), "{stored}");
    }

    assert_eq!(swept(store.reencrypt().await.unwrap()), (22, 0, 0, 0));
    for (column, row, row_key, plaintext, owner) in fixtures.iter().flat_map(|one| &one.values) {
        let stored = text(&store, *column, row).await;
        assert!(stored.starts_with("v2.1."), "{column:?} {row}: {stored}");
        let opened = unseal(&store, owner, *column, row_key, &stored).await;
        assert_eq!(opened, *plaintext, "{column:?} of {owner}");
    }
    for tenant in [tenants[0].as_str(), tenants[1].as_str(), DEFAULT_TENANT] {
        assert_eq!(rows(&store, tenant).await, 1, "one key for {tenant}");
    }
    assert_eq!(swept(store.reencrypt().await.unwrap()), (0, 22, 0, 0));
    for (fixture, tenant) in fixtures.iter().zip(&tenants) {
        check_reads(&store, fixture).await;
        check_sign_ins(&store, fixture, tenant).await;
    }
}

/// A value opens only with a key that is configured: a store with another
/// master key counts every v1 value unreadable, leaves it as it is, and makes
/// no data key, since it looks for the key only after it opened a value. The
/// current master key moves them as well as a previous one.
async fn exercise_values_move_only_with_the_key_that_opens_them(db: &Db) {
    let store = empty(db, &master()).await;
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    assert_eq!(put_some_v1(&store, &fixture).await, 7);
    let before = all_texts(&store, std::slice::from_ref(&fixture)).await;
    let key_rows = all_keys(&store).await;

    let stranger = db.open(&random_master()).await;
    assert_eq!(swept(stranger.reencrypt().await.unwrap()), (0, 4, 7, 0));
    assert_eq!(
        all_texts(&store, std::slice::from_ref(&fixture)).await,
        before
    );
    assert_eq!(all_keys(&store).await, key_rows, "no data key was made");

    assert_eq!(swept(store.reencrypt().await.unwrap()), (7, 4, 0, 0));
    check_reads(&store, &fixture).await;
}

/// A pass over values that are v2 opens none of them: the database counts them.
/// After a full pass every value becomes text that starts with `v2.1.` and that
/// no key opens. The next pass counts them all as v2 and changes no text, where
/// a pass that read them would report them unreadable.
async fn exercise_a_pass_over_migrated_values_opens_none(db: &Db) {
    let store = empty(db, &master()).await;
    let tenants = [unique_tenant()];
    let fixtures = old_fixtures(db, &store, &tenants).await;
    assert_eq!(swept(store.reencrypt().await.unwrap()), (11, 0, 0, 0));
    for (column, row, ..) in fixtures.iter().flat_map(|one| &one.values) {
        set_text(&store, *column, row, "v2.1.AAAA").await;
    }
    // An OAuth account stores no password and the pass skips its row, so what
    // is there is not counted either.
    set_text(&store, PASSWORD, &fixtures[0].oauth.0, "v2.1.AAAA").await;
    let before = all_texts(&store, &fixtures).await;
    assert_eq!(swept(store.reencrypt().await.unwrap()), (0, 11, 0, 0));
    assert_eq!(all_texts(&store, &fixtures).await, before);
}

/// A value in a newer format is left as it is: not moved, not rewritten and not
/// counted unreadable, and the values around it move.
async fn exercise_a_newer_format_is_left_by_the_sweep(db: &Db) {
    let store = empty(db, &master()).await;
    let fixtures = old_fixtures(db, &store, &[unique_tenant()]).await;
    let (password, payload) = (&fixtures[0].imap.0, &fixtures[0].event.id);
    set_text(&store, PASSWORD, password, "v3.AAAA").await;
    set_text(&store, PAYLOAD, payload, "v10.AAAA").await;
    assert_eq!(swept(store.reencrypt().await.unwrap()), (9, 0, 0, 0));
    // The nine are v2 now. The two are found again and are still not counted.
    assert_eq!(swept(store.reencrypt().await.unwrap()), (0, 9, 0, 0));
    assert_eq!(text(&store, PASSWORD, password).await, "v3.AAAA");
    assert_eq!(text(&store, PAYLOAD, payload).await, "v10.AAAA");
}

/// A filter rule's pattern is v2 from its first write, so the sweep, which
/// lists its column, counts it and leaves it as it is. Put back under the
/// master key, as no version ever wrote it, it moves to the data key of its
/// account's tenant like the other columns.
async fn exercise_the_sweep_lists_the_filter_pattern_column(db: &Db) {
    let store = empty(db, &master()).await;
    let tenant = unique_tenant();
    let fixtures = old_fixtures(db, &store, std::slice::from_ref(&tenant)).await;
    let imap = &fixtures[0].imap;
    let rule = add_rule(&store, imap, "invoice").await;
    let written = text(&store, PATTERN, &rule).await;
    // The eleven v1 values move, and the pattern is counted and not touched.
    assert_eq!(swept(store.reencrypt().await.unwrap()), (11, 1, 0, 0));
    assert_eq!(text(&store, PATTERN, &rule).await, written);

    let v1 = KnownKey::from_hex(MASTER).seal(&format!("webhook/filter/{rule}"), "invoice");
    set_text(&store, PATTERN, &rule, &v1).await;
    assert_eq!(swept(store.reencrypt().await.unwrap()), (1, 11, 0, 0));
    let moved = text(&store, PATTERN, &rule).await;
    let opened = unseal(&store, &tenant, PATTERN, &rule, &moved).await;
    assert_eq!(opened, "invoice");
    assert_eq!(patterns_of(&store, imap).await, ["invoice"]);
}

/// The sweep leaves the v1 values of a tenant whose data keys were destroyed,
/// counts them unreadable and completes; the other values move.
async fn exercise_the_sweep_leaves_the_values_of_a_destroyed_tenant(db: &Db) {
    let store = empty(db, &master()).await;
    let tenants = [unique_tenant(), unique_tenant()];
    let fixtures = old_fixtures(db, &store, &tenants).await;
    mark_destroyed(&store, &tenants[0]).await;
    let mark = key_rows(&store, &tenants[0]).await;
    let own: Vec<&Value> = fixtures[0]
        .values
        .iter()
        .filter(|value| value.4 == tenants[0])
        .collect();
    assert_eq!(own.len(), 8);
    let mut before = Vec::new();
    for (column, row, ..) in &own {
        before.push(text(&store, *column, row).await);
    }

    // The other tenant's 11 values and the 3 of the default tenant move.
    assert_eq!(swept(store.reencrypt().await.unwrap()), (14, 0, 8, 0));
    for ((column, row, ..), was) in own.iter().zip(&before) {
        let now = text(&store, *column, row).await;
        assert!(now.starts_with("v1."), "{now}");
        assert_eq!(&now, was);
    }
    assert_eq!(key_rows(&store, &tenants[0]).await, mark);
    assert_eq!(swept(store.reencrypt().await.unwrap()), (0, 14, 8, 0));
}

async fn exercise_sweep_all(db: &Db) {
    exercise_every_column_moves_to_the_data_key_of_its_rows_tenant(db).await;
    exercise_values_move_only_with_the_key_that_opens_them(db).await;
    exercise_a_pass_over_migrated_values_opens_none(db).await;
    exercise_a_newer_format_is_left_by_the_sweep(db).await;
    exercise_the_sweep_lists_the_filter_pattern_column(db).await;
    exercise_the_sweep_leaves_the_values_of_a_destroyed_tenant(db).await;
}

#[tokio::test]
async fn sqlite_sweep_all() {
    exercise_sweep_all(&Db::sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_sweep_all() {
    in_a_database_of_its_own("postkeep_sweep", |db| async move {
        exercise_sweep_all(&db).await;
    })
    .await;
}

// The sweep while something else acts: a writer, a second sweep, a key service
// that does not answer. A store given an `Interrupted` wrapper is stopped in
// `unwrap`, which a sweep calls after it read a page and before it replaces a
// value, and the test acts there. These too go over every row of the database,
// so PostgreSQL gives them a database of their own, and a runner of their own
// keeps each PostgreSQL test short.

type Hook = Box<dyn FnOnce() -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

fn hook<F: Future<Output = ()> + Send + 'static>(run: impl FnOnce() -> F + Send + 'static) -> Hook {
    Box::new(move || Box::pin(run()))
}

/// The local wrapper, which a test can interrupt. It is asked when a store
/// first needs a key it has not unwrapped, which for the sweep is after it read
/// a page and before it replaces a value.
struct Interrupted {
    local: LocalKeyWrapper,
    /// Runs once, in the first `unwrap`, as another process would act meanwhile.
    meanwhile: Mutex<Option<Hook>>,
    /// Runs once, at the start of the first `wrap`, as another process would act
    /// while a key is made.
    in_wrap: Mutex<Option<Hook>>,
    /// Awaited once, in the first `unwrap`, so that two sweeps are in it together.
    gate: Mutex<Option<Arc<tokio::sync::Barrier>>>,
    /// The tenant that the key service does not answer for, as `KeyWrap`.
    down_for: Mutex<Option<String>>,
}

impl Interrupted {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            local: LocalKeyWrapper::new(&master(), &[]),
            meanwhile: Mutex::new(None),
            in_wrap: Mutex::new(None),
            gate: Mutex::new(None),
            down_for: Mutex::new(None),
        })
    }

    fn up(&self, tenant: &str) -> Result<(), StoreError> {
        if self.down_for.lock().unwrap().as_deref() == Some(tenant) {
            return Err(StoreError::KeyWrap("the key service is down".to_owned()));
        }
        Ok(())
    }

    /// A store on `db` that asks this wrapper.
    async fn store(self: &Arc<Self>, db: &Db) -> Store {
        db.open(&master()).await.with_key_wrapper(self.clone())
    }
}

impl KeyWrapper for Interrupted {
    fn current(&self) -> Kek {
        self.local.current()
    }

    fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
        Box::pin(async move {
            let in_wrap = self.in_wrap.lock().unwrap().take();
            if let Some(run) = in_wrap {
                run().await;
            }
            self.up(tenant)?;
            self.local.wrap(tenant, key).await
        })
    }

    fn unwrap<'a>(
        &'a self,
        tenant: &'a str,
        kek: &'a Kek,
        wrapped: &'a [u8],
    ) -> WrapFuture<'a, DataKey> {
        Box::pin(async move {
            let gate = self.gate.lock().unwrap().take();
            if let Some(gate) = gate {
                gate.wait().await;
            }
            let meanwhile = self.meanwhile.lock().unwrap().take();
            if let Some(run) = meanwhile {
                run().await;
            }
            self.up(tenant)?;
            self.local.unwrap(tenant, kek, wrapped).await
        })
    }
}

/// A writer that gets in between the sweep's read and its replacement wins: the
/// sweep replaces a value only if it is still what it read. A token refresh is
/// kept, a v1 value that an older build wrote meanwhile is left for the next
/// pass, and nothing the writer stored is lost.
async fn exercise_a_writer_that_gets_in_first_is_not_overwritten(db: &Db) {
    let store = empty(db, &master()).await;
    let tenant = unique_tenant();
    let fixtures = old_fixtures(db, &store, std::slice::from_ref(&tenant)).await;
    let fixture = &fixtures[0];
    // Only the refresh token and the event are v1: all that the sweep has to move.
    to_v2(&store, fixture, |column, _| {
        column != REFRESH && column != PAYLOAD
    })
    .await;

    // A refresh stores both tokens as v2 while the sweep waits for the key.
    let (writer, oauth) = (db.open(&master()).await, fixture.oauth.clone());
    let wrapper = Interrupted::new();
    *wrapper.meanwhile.lock().unwrap() = Some(hook(move || async move {
        let refresh = tokens("refresh-2");
        writer.save_upstream_tokens(&oauth, &refresh).await.unwrap();
    }));
    let sweeper = wrapper.store(db).await;
    assert_eq!(swept(sweeper.reencrypt().await.unwrap()), (1, 9, 0, 1));
    let found = store
        .upstream_tokens(&fixture.oauth)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.tokens.refresh_token.expose_secret(), "refresh-2");
    assert!(
        text(&store, REFRESH, &fixture.oauth.0)
            .await
            .starts_with("v2.1.")
    );

    // The event is v1 again, and an older build stores it once more while the
    // sweep, which read it as v1, waits for the key.
    put_v1(&store, fixture, |column| column == PAYLOAD).await;
    let (older, event) = (db.open(&master()).await, fixture.event.id.clone());
    let owner = format!("{}/{event}", fixture.imap.0);
    let wrapper = Interrupted::new();
    *wrapper.meanwhile.lock().unwrap() = Some(hook(move || async move {
        let known = KnownKey::from_hex(MASTER);
        common::PAYLOAD
            .put(&older, &known, &event, &owner, "{\"n\":9}")
            .await;
    }));
    let sweeper = wrapper.store(db).await;
    assert_eq!(swept(sweeper.reencrypt().await.unwrap()), (0, 10, 0, 1));
    assert!(
        text(&store, PAYLOAD, &fixture.event.id)
            .await
            .starts_with("v1.")
    );
    assert_eq!(swept(sweeper.reencrypt().await.unwrap()), (1, 10, 0, 0));
    let pending = store.pending_mail_events(&fixture.imap, 10).await.unwrap();
    assert_eq!(pending.events[0].payload, "{\"n\":9}");
}

/// Two sweeps meet where they first need a key, so that both have read the first
/// value before either replaces it. Between them they move each value once, one
/// of them loses the race for the first, and every value reads back.
async fn exercise_two_sweeps_at_once_move_each_value_once(db: &Db) {
    let store = empty(db, &master()).await;
    let tenants = [unique_tenant(), unique_tenant()];
    let fixtures = old_fixtures(db, &store, &tenants).await;
    let gate = Arc::new(tokio::sync::Barrier::new(2));
    let (one, two) = (Interrupted::new(), Interrupted::new());
    for wrapper in [&one, &two] {
        *wrapper.gate.lock().unwrap() = Some(gate.clone());
    }
    let (first, second) = (one.store(db).await, two.store(db).await);
    let (first, second) = tokio::join!(first.reencrypt(), second.reencrypt());
    let (first, second) = (swept(first.unwrap()), swept(second.unwrap()));
    assert_eq!(first.0 + second.0, 22, "{first:?} {second:?}");
    assert!(
        first.3 + second.3 >= 1,
        "no race was lost for the first value"
    );
    // A value that the other sweep moved after this one counted the column and
    // before it read a page is in none of its counts.
    for report in [first, second] {
        assert!(report.0 + report.1 + report.3 <= 22, "{report:?}");
        assert_eq!(report.2, 0, "{report:?}");
    }
    for stored in all_texts(&store, &fixtures).await {
        assert!(stored.starts_with("v2.1."), "{stored}");
    }
    for (fixture, tenant) in fixtures.iter().zip(&tenants) {
        check_reads(&store, fixture).await;
        check_sign_ins(&store, fixture, tenant).await;
    }
}

/// A wrapper that does not answer stops the pass with its error, not as
/// "unreadable": what it moved stays moved, what it did not move is untouched
/// and readable, and the next pass moves the rest.
async fn exercise_a_wrapper_that_does_not_answer_stops_the_sweep(db: &Db) {
    let store = empty(db, &master()).await;
    let tenants = [unique_tenant(), unique_tenant()];
    let fixtures = old_fixtures(db, &store, &tenants).await;
    // The passwords come first, in the order of the account IDs. The key service
    // does not answer for the tenant of the later account, so that the pass has
    // moved the earlier password when it stops.
    let by_id: Vec<String> =
        sqlx::query_scalar("SELECT tenant FROM accounts WHERE provider = 'imap' ORDER BY id")
            .fetch_all(store.pool())
            .await
            .unwrap();
    let (earlier, later) = (&by_id[0], &by_id[1]);
    let wrapper = Interrupted::new();
    *wrapper.down_for.lock().unwrap() = Some(later.clone());
    let sweeper = wrapper.store(db).await;
    assert_key_wrap(sweeper.reencrypt().await);

    let mut left = 0;
    for (column, row, _, _, owner) in fixtures.iter().flat_map(|one| &one.values) {
        let stored = text(&store, *column, row).await;
        let v1 = stored.starts_with("v1.");
        assert!(v1 || stored.starts_with("v2.1."), "{stored}");
        let moved = *column == PASSWORD && owner == earlier;
        assert_eq!(!v1, moved, "{column:?} of {owner}: {stored}");
        left += u64::from(v1);
    }
    assert_eq!(left, 21, "all but the earlier password are still v1");
    for (fixture, tenant) in fixtures.iter().zip(&tenants) {
        check_reads(&store, fixture).await;
        // A key service that does not answer is not a key that nobody can read:
        // no new key version was made.
        assert_eq!(rows(&store, tenant).await, 1);
    }
    // The key service answers again.
    *wrapper.down_for.lock().unwrap() = None;
    assert_eq!(swept(sweeper.reencrypt().await.unwrap()), (21, 1, 0, 0));
    assert_eq!(swept(sweeper.reencrypt().await.unwrap()), (0, 22, 0, 0));
    for (fixture, tenant) in fixtures.iter().zip(&tenants) {
        check_sign_ins(&store, fixture, tenant).await;
    }
}

async fn exercise_sweep_races(db: &Db) {
    exercise_a_writer_that_gets_in_first_is_not_overwritten(db).await;
    exercise_two_sweeps_at_once_move_each_value_once(db).await;
    exercise_a_wrapper_that_does_not_answer_stops_the_sweep(db).await;
}

#[tokio::test]
async fn sqlite_sweep_races() {
    exercise_sweep_races(&Db::sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_sweep_races() {
    in_a_database_of_its_own("postkeep_sweep_races", |db| async move {
        exercise_sweep_races(&db).await;
    })
    .await;
}

// The sweep in pages, across a crash, on a pool of one connection and for a tenant
// whose keys are lost. A runner of its own and, on PostgreSQL, a database of its
// own keep each test short.

/// A pass that does not end within this is stuck, say in a loop over a page: it
/// fails the test here, not at the test profile's kill after 120 s.
const PASS_LIMIT: Duration = Duration::from_secs(30);

/// A pass of the sweep, which fails the test if it takes longer than `PASS_LIMIT`.
async fn sweep_in_time(store: &Store) -> Result<Reencrypted, StoreError> {
    let pass = tokio::time::timeout(PASS_LIMIT, store.reencrypt());
    pass.await
        .unwrap_or_else(|_| panic!("the sweep does not end within {PASS_LIMIT:?}"))
}

/// The sweep writes like a writer: a tenant none of whose keys this process can
/// unwrap gets a new version, and its values are sealed under it.
async fn exercise_a_tenant_without_a_readable_key_gets_a_new_one(db: &Db) {
    let store = empty(db, &master()).await;
    let tenant = unique_tenant();
    let fixtures = old_fixtures(db, &store, std::slice::from_ref(&tenant)).await;
    sqlx::query("UPDATE data_keys SET kek_id = 'lost'")
        .execute(store.pool())
        .await
        .unwrap();
    // A store that has unwrapped no key of the tenant.
    let store = db.open(&master()).await;
    assert_eq!(swept(sweep_in_time(&store).await.unwrap()), (11, 0, 0, 0));
    for (column, row, row_key, plaintext, owner) in &fixtures[0].values {
        let stored = text(&store, *column, row).await;
        assert!(stored.starts_with("v2.2."), "{column:?}: {stored}");
        let opened = unseal(&store, owner, *column, row_key, &stored).await;
        assert_eq!(opened, *plaintext, "{column:?} of {owner}");
    }
    // The lost key stays beside the new one, for the tenant and for the default
    // tenant, which the sign-ins use.
    assert_eq!(rows(&store, &tenant).await, 2);
    assert_eq!(rows(&store, DEFAULT_TENANT).await, 2);
    check_reads(&store, &fixtures[0]).await;
}

/// The events of `account` that a key opens read back what was stored for
/// them, in whichever format they are, and no others are among them.
async fn check_events(store: &Store, account: &AccountId, payloads: &HashMap<String, String>) {
    store.set_event_hold(Duration::ZERO);
    let pending = store.pending_mail_events(account, 500).await.unwrap();
    assert_eq!(pending.events.len(), payloads.len());
    for event in &pending.events {
        assert_eq!(event.payload, payloads[&event.id], "event {}", event.id);
    }
}

/// Makes the database refuse a v2 payload for an event whose ID is `from` or
/// above, so that the sweep, which goes in the order of the IDs, fails there as
/// a crash would after the events below it. A trigger on SQLite, a check
/// constraint on PostgreSQL, which needs no trigger function for it.
async fn crash_at(store: &Store, from: &str, postgres: bool) {
    let statement = if postgres {
        format!(
            "ALTER TABLE mail_events ADD CONSTRAINT crash CHECK \
             (id < '{from}' OR payload_ciphertext NOT LIKE 'v2.%')"
        )
    } else {
        format!(
            "CREATE TRIGGER crash BEFORE UPDATE ON mail_events \
             WHEN NEW.id >= '{from}' AND NEW.payload_ciphertext LIKE 'v2.%' \
             BEGIN SELECT RAISE(ABORT, 'crash'); END"
        )
    };
    let done = sqlx::query(AssertSqlSafe(statement)).execute(store.pool());
    done.await.unwrap();
}

/// The sweep reads 100 rows at a time and goes past unreadable rows at the end
/// and at the start of a page. A crash in the second page leaves every event in
/// its old or its new form, and the next pass finishes the rest.
async fn exercise_the_sweep_pages_and_a_crash_loses_nothing(db: &Db) {
    let store = empty(db, &master()).await;
    let scoped = store.for_tenant(&unique_tenant());
    let email = format!("{}@example.com", unique("pages"));
    let password = secret("pw");
    let imap = scoped.upsert_account(&email, &password).await.unwrap().id;
    let settings = webhook("https://hooks.example/h", "Bearer one", "whsec_one");
    store.save_webhook(&imap, &settings).await.unwrap();
    // Two pages and a rest of events, each with a payload of its own, as an
    // earlier version stored them: v1, under the master key, which no writer
    // makes any more. One transaction puts them in.
    let known = KnownKey::from_hex(MASTER);
    let mut payloads = HashMap::new();
    #[expect(
        clippy::disallowed_methods,
        reason = "the fixture writes alone, on either database"
    )]
    let mut tx = store.pool().begin().await.unwrap();
    for number in 1..=230_i64 {
        let id = uuid::Uuid::new_v4().to_string();
        let payload = format!("{{\"n\":{number}}}");
        let sealed = known.seal(&format!("event/{}/{id}", imap.0), &payload);
        let insert = sqlx::query(
            "INSERT INTO mail_events (id, account_id, sequence, payload_ciphertext, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        );
        let bound = insert.bind(&id).bind(&imap.0).bind(number).bind(sealed);
        bound.bind(now()).execute(&mut *tx).await.unwrap();
        payloads.insert(id, payload);
    }
    let numbered = sqlx::query("UPDATE webhooks SET last_sequence = 230 WHERE account_id = $1");
    numbered.bind(&imap.0).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();

    // The sweep goes in the order of the IDs, as the database orders them. Three
    // events are ones that no key opens: the last of the first page, the first of
    // the second page and its last.
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM mail_events ORDER BY id")
        .fetch_all(store.pool())
        .await
        .unwrap();
    let lost = [99, 100, 199];
    for at in lost {
        let unreadable = common::unreadable();
        common::PAYLOAD.set(&store, &ids[at], &unreadable).await;
        payloads.remove(&ids[at]);
    }

    let postgres = db.url.starts_with("postgres");
    crash_at(&store, &ids[120], postgres).await;
    let err = sweep_in_time(&store).await.unwrap_err();
    assert!(matches!(err, StoreError::Database(_)), "{err:?}");
    assert!(err.to_string().contains("crash"), "{err}");
    // The 120 events before the one that failed were moved, but two of them
    // cannot be; the rest are as they were.
    let moved: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM mail_events WHERE payload_ciphertext LIKE 'v2.%'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(moved, 118);
    let undo = if postgres {
        "ALTER TABLE mail_events DROP CONSTRAINT crash"
    } else {
        "DROP TRIGGER crash"
    };
    sqlx::query(undo).execute(store.pool()).await.unwrap();
    check_events(&store, &imap, &payloads).await;

    // 121 values are v2 already: the 118 events and the account's password and
    // webhook secrets.
    assert_eq!(
        swept(sweep_in_time(&store).await.unwrap()),
        (109, 121, 3, 0)
    );
    assert_eq!(swept(sweep_in_time(&store).await.unwrap()), (0, 230, 3, 0));
    for at in lost {
        let left = common::PAYLOAD.get(&store, &ids[at]).await;
        assert_eq!(left, common::unreadable(), "left as it was");
    }
    check_events(&store, &imap, &payloads).await;
}

/// The sweep finds and makes keys between its statements: it works on a pool of
/// one connection, for tenants that have no key yet, as in a database that an
/// earlier version wrote.
async fn exercise_the_sweep_works_on_a_pool_of_one(db: &Db) {
    let store = empty(db, &master()).await;
    let tenants = [unique_tenant()];
    let fixtures = old_fixtures(db, &store, &tenants).await;
    sqlx::query("DELETE FROM data_keys")
        .execute(store.pool())
        .await
        .unwrap();
    let settings = PoolSettings {
        max_connections: 1,
        acquire_timeout: Duration::from_secs(10),
        ..PoolSettings::default()
    };
    let key = master();
    let one = Store::connect_with(&db.url, &key, &[], settings, Migrations::Apply);
    let one = one.await.unwrap();
    let pass = sweep_in_time(&one).await;
    let report = pass.unwrap_or_else(|err| panic!("the sweep has no connection: {err:?}"));
    assert_eq!(swept(report), (11, 0, 0, 0));
    // A key for the tenant and one for the default tenant, made on the way.
    assert_eq!(all_keys(&one).await, 2);
    check_reads(&one, &fixtures[0]).await;
}

async fn exercise_sweep_pages(db: &Db) {
    exercise_a_tenant_without_a_readable_key_gets_a_new_one(db).await;
    exercise_the_sweep_pages_and_a_crash_loses_nothing(db).await;
    exercise_the_sweep_works_on_a_pool_of_one(db).await;
}

#[tokio::test]
async fn sqlite_sweep_pages() {
    exercise_sweep_pages(&Db::sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_sweep_pages() {
    in_a_database_of_its_own("postkeep_sweep_pages", |db| async move {
        exercise_sweep_pages(&db).await;
    })
    .await;
}

// Wrapping the data keys again. The pass goes over every key in the database,
// so each exercise starts with none, and PostgreSQL gets a database of its own.

const fn counts(report: Rewrapped) -> (u64, u64) {
    (report.rewrapped, report.unreadable)
}

fn kek(version: i64) -> Kek {
    Kek {
        provider: "masking".to_owned(),
        id: "kek-1".to_owned(),
        version,
    }
}

/// The KEK that a tenant's first data key names.
async fn kek_in(store: &Store, tenant: &str) -> Kek {
    let (provider, id, version, ..) = stored(store, tenant).await;
    Kek {
        provider,
        id,
        version,
    }
}

/// A store with no data keys in its database.
async fn clean(db: &Db, key: &MasterKey) -> Store {
    let store = db.open(key).await;
    sqlx::query("DELETE FROM data_keys")
        .execute(store.pool())
        .await
        .unwrap();
    store
}

/// A wrapper that wraps for KEK version 2, which `current` has moved past.
fn at_version_2() -> Arc<Masking> {
    Arc::new(Masking {
        rotated: Some(kek(2)),
        ..Masking::default()
    })
}

async fn make_keys(store: &Store, tenants: &[&str]) -> Vec<[u8; 32]> {
    let mut keys = Vec::new();
    for tenant in tenants {
        let (_, key) = store.for_tenant(tenant).data_key().await.unwrap();
        keys.push(*key.expose());
    }
    keys
}

/// A store that has unwrapped nothing finds these keys, through a wrapper
/// that takes any KEK.
async fn assert_keys(db: &Db, tenants: &[&str], keys: &[[u8; 32]]) {
    let wrapper = Arc::new(Masking::default());
    let cold = db.open(&master()).await.with_key_wrapper(wrapper);
    for (tenant, key) in tenants.iter().zip(keys) {
        let (_, found) = cold.for_tenant(tenant).data_key().await.unwrap();
        assert_eq!(found.expose(), key, "{tenant}");
    }
}

/// After a master key change, the data keys of all tenants are wrapped again,
/// one row each: before, only the old key unwraps them; after, the new key
/// alone does, also for a store that held one already, and values still open.
async fn exercise_a_new_master_key_rewraps_one_row_per_tenant(db: &Db) {
    let store = clean(db, &master()).await;
    assert_eq!(counts(store.rewrap_data_keys().await.unwrap()), (0, 0));
    let tenants = ["tenant-a", "tenant-b", "tenant-c"];
    let keys = make_keys(&store, &tenants).await;
    let fixture = fill(db, &store, tenants[0]).await;
    to_v2(&store, &fixture, |_, owner| owner == tenants[0]).await;

    let new_only = db.open(&other_master()).await;
    assert_decrypt(new_only.for_tenant(tenants[1]).data_key_version(1).await);
    let rotating = Store::connect_rotating(&db.url, &other_master(), &[master()])
        .await
        .unwrap();
    rotating.for_tenant(tenants[0]).data_key().await.unwrap();
    let before = stored(&rotating, tenants[1]).await.3;
    // The three tenants, and the default one, which the sign-ins of `fill` use.
    assert_eq!(counts(rotating.rewrap_data_keys().await.unwrap()), (4, 0));

    for tenant in tenants {
        assert_eq!(stored(&rotating, tenant).await.1, OTHER_ID);
    }
    assert_ne!(stored(&rotating, tenants[1]).await.3, before);
    // The previous key can go.
    for (tenant, key) in tenants.iter().zip(&keys) {
        for reader in [&new_only, &rotating] {
            let (_, found) = reader.for_tenant(tenant).data_key().await.unwrap();
            assert_eq!(found.expose(), key);
        }
    }
    check_reads(&new_only, &fixture).await;
    let old_only = db.open(&master()).await;
    assert_decrypt(old_only.for_tenant(tenants[1]).data_key_version(1).await);
}

/// Two passes that both wrap the key before either stores it leave one valid
/// row and count it once. A pass with nothing to do calls no wrapper and
/// writes nothing.
async fn exercise_rewrap_is_idempotent_and_safe_twice_at_once(db: &Db) {
    let store = clean(db, &master()).await.with_key_wrapper(at_version_2());
    let keys = make_keys(&store, &["tenant-a"]).await;

    let gate = tokio::sync::Barrier::new(2);
    let wrapper = Arc::new(Masking {
        gate: Some(gate),
        ..Masking::default()
    });
    let one = db.open(&master()).await.with_key_wrapper(wrapper.clone());
    let two = db.open(&master()).await.with_key_wrapper(wrapper);
    let (first, second) = tokio::join!(one.rewrap_data_keys(), two.rewrap_data_keys());
    assert_eq!(first.unwrap().rewrapped + second.unwrap().rewrapped, 1);
    assert_eq!(rows(&store, "tenant-a").await, 1);
    assert_eq!(kek_in(&store, "tenant-a").await, kek(3));
    assert_keys(db, &["tenant-a"], &keys).await;

    let idle = Arc::new(Masking::default());
    let again = db.open(&master()).await.with_key_wrapper(idle.clone());
    let before = stored(&again, "tenant-a").await;
    assert_eq!(counts(again.rewrap_data_keys().await.unwrap()), (0, 0));
    assert!(idle.calls().is_empty(), "nothing to do, nothing asked");
    assert_eq!(stored(&again, "tenant-a").await, before);
}

/// A key that no configured key unwraps, or whose text is garbled, is counted
/// and left as it is, and the pass goes on. Configuring the key that wrapped
/// it makes a later pass wrap it.
async fn exercise_rewrap_leaves_what_it_cannot_unwrap(db: &Db) {
    let lost = MasterKey::generate_encoded().unwrap();
    let store = clean(db, &master()).await;
    let stranger = db.open(&MasterKey::parse(&lost).unwrap()).await;
    stranger.for_tenant("tenant-a").data_key().await.unwrap();
    make_keys(&store, &["tenant-b", "tenant-c"]).await;
    sqlx::query("UPDATE data_keys SET wrapped = '!' WHERE tenant = 'tenant-c'")
        .execute(store.pool())
        .await
        .unwrap();
    let left = [
        stored(&store, "tenant-a").await,
        stored(&store, "tenant-c").await,
    ];

    let rotating = Store::connect_rotating(&db.url, &other_master(), &[master()])
        .await
        .unwrap();
    for expected in [(1, 2), (0, 2)] {
        assert_eq!(counts(rotating.rewrap_data_keys().await.unwrap()), expected);
        let unchanged = [
            stored(&rotating, "tenant-a").await,
            stored(&rotating, "tenant-c").await,
        ];
        assert_eq!(unchanged, left);
    }

    let previous = [master(), MasterKey::parse(&lost).unwrap()];
    let found = Store::connect_rotating(&db.url, &other_master(), &previous)
        .await
        .unwrap();
    assert_eq!(counts(found.rewrap_data_keys().await.unwrap()), (1, 1));
    let new_only = db.open(&other_master()).await;
    assert_eq!(
        new_only.for_tenant("tenant-a").data_key().await.unwrap().0,
        1
    );
}

/// A wrapper is asked to unwrap with the KEK in the row, to wrap, and to
/// unwrap what it wrapped. The row names the KEK that `wrap` returned, not
/// `current`, which may lag; a key already at that KEK is not written again,
/// and a key at the KEK that `current` names is not visited at all.
async fn exercise_a_custom_wrapper_rewraps_through_unwrap_and_wrap(db: &Db) {
    let tenants = ["tenant-a", "tenant-b"];
    let store = clean(db, &master()).await.with_key_wrapper(at_version_2());
    let keys = make_keys(&store, &tenants).await;
    // A key made at KEK 3, the one `current` names below.
    let current = Arc::new(Masking::default());
    let at_current = db.open(&master()).await.with_key_wrapper(current);
    make_keys(&at_current, &["tenant-c"]).await;

    // `current` says 3 while the key service is at 4 already.
    let lagging = Arc::new(Masking {
        rotated: Some(kek(4)),
        ..Masking::default()
    });
    let store = db.open(&master()).await.with_key_wrapper(lagging.clone());
    // The first pass moves the keys to 4; the second finds them there, though
    // `current` still differs, and writes and counts nothing.
    for (from, moved) in [(2, 2), (4, 0)] {
        assert_eq!(counts(store.rewrap_data_keys().await.unwrap()), (moved, 0));
        let calls = tenants.iter().flat_map(|one| {
            let mut asked = vec![format!("unwrap {one} kek-1 {from}"), format!("wrap {one}")];
            if moved > 0 {
                asked.push(format!("unwrap {one} kek-1 4"));
            }
            asked
        });
        assert_eq!(lagging.calls(), calls.collect::<Vec<_>>());
        for tenant in tenants {
            assert_eq!(kek_in(&store, tenant).await, kek(4));
        }
        assert_eq!(kek_in(&store, "tenant-c").await, kek(3));
        assert_keys(db, &tenants, &keys).await;
    }

    let steady = Arc::new(Masking::default());
    let store = db.open(&master()).await.with_key_wrapper(steady.clone());
    assert_eq!(counts(store.rewrap_data_keys().await.unwrap()), (2, 0));
    assert_eq!(steady.calls().len(), 6);
    assert_eq!(kek_in(&store, "tenant-a").await, kek(3));
    assert_eq!(counts(store.rewrap_data_keys().await.unwrap()), (0, 0));
    assert!(steady.calls().is_empty(), "nothing to do, nothing asked");
    assert_keys(db, &tenants, &keys).await;
}

/// A wrapper that fails ends the pass with its error, not as "unreadable", and
/// no key is lost. Output that does not unwrap to the key replaces nothing.
async fn exercise_a_failing_wrapper_stops_the_pass_without_losing_a_key(db: &Db) {
    let tenants = ["tenant-a", "tenant-b", "tenant-c"];
    let store = clean(db, &master()).await.with_key_wrapper(at_version_2());
    let keys = make_keys(&store, &tenants).await;
    let troubles = [
        Trouble::Returns(|_| vec![0; 5]),
        Trouble::Returns(|tenant| mask(tenant, &[0x11; 32])),
        Trouble::FailsFor("tenant-b".to_owned()),
    ];
    for trouble in troubles {
        let wrapper = Arc::new(Masking {
            trouble: Some(trouble),
            ..Masking::default()
        });
        let broken = db.open(&master()).await.with_key_wrapper(wrapper);
        assert_key_wrap(broken.rewrap_data_keys().await);
        assert_keys(db, &tenants, &keys).await;
    }
    // Only the key before the failing one was wrapped again.
    let mut versions = Vec::new();
    for tenant in tenants {
        versions.push(kek_in(&store, tenant).await.version);
    }
    assert_eq!(versions, [3, 2, 2]);

    let back = Arc::new(Masking::default());
    let store = db.open(&master()).await.with_key_wrapper(back);
    assert_eq!(counts(store.rewrap_data_keys().await.unwrap()), (2, 0));
    assert_keys(db, &tenants, &keys).await;
}

/// A row that another process changes while the pass wraps its key stays as
/// that process made it: the pass replaces a row only if it still holds what
/// it read, or it would put back a key that was replaced.
async fn exercise_a_row_changed_meanwhile_is_not_overwritten(db: &Db) {
    let store = clean(db, &master()).await.with_key_wrapper(at_version_2());
    make_keys(&store, &["tenant-a"]).await;
    let replacing = Arc::new(Masking {
        trouble: Some(Trouble::Replaces(store.pool().clone())),
        ..Masking::default()
    });
    let pass = db.open(&master()).await.with_key_wrapper(replacing);
    assert_eq!(counts(pass.rewrap_data_keys().await.unwrap()), (0, 0));
    assert_eq!(kek_in(&store, "tenant-a").await, kek(2));
    assert_keys(db, &["tenant-a"], &[[0x77; 32]]).await;
}

/// A pass goes through every row, page after page, also past a row it cannot
/// unwrap that ends a page (a page is 100 rows).
async fn exercise_rewrap_pages_through_all_rows(db: &Db) {
    let store = clean(db, &master())
        .await
        .with_key_wrapper(Arc::new(OneKey));
    let insert = "INSERT INTO data_keys (tenant, version, provider, kek_id, kek_version, \
                  wrapped, created_at) VALUES ($1, 1, 'one', 'old', 1, $2, 1)";
    let good = URL_SAFE_NO_PAD.encode([0x42; 32]);
    for number in 0..250 {
        let garbled = [0, 99, 199, 249].contains(&number);
        let wrapped = if garbled { "!" } else { &good };
        let tenant = format!("tenant-{number:03}");
        let row = sqlx::query(insert).bind(tenant).bind(wrapped);
        row.execute(store.pool()).await.unwrap();
    }
    assert_eq!(counts(store.rewrap_data_keys().await.unwrap()), (246, 4));
    assert_eq!(counts(store.rewrap_data_keys().await.unwrap()), (0, 4));
}

/// The rotation the docs describe, on what the writers made. With the new master
/// key and the old one as previous, the sweep moves the values that are v1 and
/// leaves the v2 ones alone, which the new key alone cannot read until the
/// re-wrap has wrapped their data key again. Then it reads everything. The sweep
/// goes over every row of the database, so this runs first, on an empty one.
async fn exercise_a_master_key_change_keeps_what_the_writers_made(db: &Db) {
    let store = clean(db, &master()).await;
    let tenant = unique_tenant();
    let fixture = fill(db, &store, &tenant).await;
    let v1 = put_some_v1(&store, &fixture).await;
    assert_eq!(v1, 7, "seven of the eleven values are v1 and four are v2");
    let kept = written(&store, &fixture.imap).await;

    let rotating = Store::connect_rotating(&db.url, &other_master(), &[master()])
        .await
        .unwrap();
    check_reads(&rotating, &fixture).await;
    let report = rotating.reencrypt().await.unwrap();
    assert_eq!((report.updated, report.unreadable), (v1, 0));
    assert_eq!(written(&rotating, &fixture.imap).await, kept);

    // The previous key cannot go before the data key is wrapped again.
    let early = db.open(&other_master()).await;
    assert_decrypt(early.credentials(&fixture.imap).await);
    assert_decrypt(early.webhook(&fixture.imap).await);
    // The keys of the tenant and of the default tenant, which the sign-ins use.
    assert_eq!(counts(rotating.rewrap_data_keys().await.unwrap()), (2, 0));
    assert_eq!(counts(rotating.rewrap_data_keys().await.unwrap()), (0, 0));
    let new_only = db.open(&other_master()).await;
    check_reads(&new_only, &fixture).await;
    check_sign_ins(&new_only, &fixture, &tenant).await;
}

/// A pass neither visits nor counts the rows of a destroyed tenant, and wraps
/// the other keys again.
async fn exercise_a_pass_leaves_the_rows_of_a_destroyed_tenant(db: &Db) {
    let store = clean(db, &master()).await;
    let (tenant, other) = (unique_tenant(), unique_tenant());
    let keys = make_keys(&store, &[&tenant, &other]).await;
    mark_destroyed(&store, &tenant).await;
    let mark: Vec<(String, String, i64, String, i64)> = sqlx::query_as(
        "SELECT provider, kek_id, kek_version, wrapped, created_at FROM data_keys \
         WHERE tenant = $1 ORDER BY version",
    )
    .bind(&tenant)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(mark.len(), 3);

    let rotating = Store::connect_rotating(&db.url, &other_master(), &[master()])
        .await
        .unwrap();
    assert_eq!(counts(rotating.rewrap_data_keys().await.unwrap()), (1, 0));
    let after: Vec<(String, String, i64, String, i64)> = sqlx::query_as(
        "SELECT provider, kek_id, kek_version, wrapped, created_at FROM data_keys \
         WHERE tenant = $1 ORDER BY version",
    )
    .bind(&tenant)
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(after, mark);
    let new_only = db.open(&other_master()).await;
    let (_, found) = new_only.for_tenant(&other).data_key().await.unwrap();
    assert_eq!(found.expose(), &keys[1]);
    assert_destroyed(new_only.for_tenant(&tenant).data_key().await);
}

async fn exercise_rewrap_all(db: &Db) {
    exercise_a_master_key_change_keeps_what_the_writers_made(db).await;
    exercise_a_new_master_key_rewraps_one_row_per_tenant(db).await;
    exercise_rewrap_is_idempotent_and_safe_twice_at_once(db).await;
    exercise_rewrap_leaves_what_it_cannot_unwrap(db).await;
    exercise_a_custom_wrapper_rewraps_through_unwrap_and_wrap(db).await;
    exercise_a_failing_wrapper_stops_the_pass_without_losing_a_key(db).await;
    exercise_a_row_changed_meanwhile_is_not_overwritten(db).await;
    exercise_rewrap_pages_through_all_rows(db).await;
    exercise_a_pass_leaves_the_rows_of_a_destroyed_tenant(db).await;
}

#[tokio::test]
async fn sqlite_rewrap_all() {
    exercise_rewrap_all(&Db::sqlite()).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "requires TEST_POSTGRES_URL"]
async fn postgres_rewrap_all() {
    in_a_database_of_its_own("postkeep_rewrap", |db| async move {
        exercise_rewrap_all(&db).await;
    })
    .await;
}

/// Runs `run` on a PostgreSQL database that it alone uses, created next to the
/// one in `TEST_POSTGRES_URL` and dropped when it is done, also when an
/// assertion fails. For what goes over every row or every key.
#[cfg(feature = "postgres")]
async fn in_a_database_of_its_own<F>(prefix: &str, run: impl FnOnce(Db) -> F)
where
    F: Future<Output = ()> + Send + 'static,
{
    let server =
        std::env::var("TEST_POSTGRES_URL").unwrap_or_else(|_| panic!("set TEST_POSTGRES_URL"));
    let name = format!("{prefix}_{}", uuid::Uuid::new_v4().simple());
    on_server(&server, format!("CREATE DATABASE {name}")).await;
    let (base, query) = server
        .split_once('?')
        .map_or((server.as_str(), String::new()), |(base, query)| {
            (base, format!("?{query}"))
        });
    let url = format!("{}/{name}{query}", base.rsplit_once('/').unwrap().0);
    // The database is dropped when an assertion fails too.
    let ran = tokio::spawn(run(Db { url, _dir: None })).await;
    let drop = format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)");
    on_server(&server, drop).await;
    ran.unwrap();
}
