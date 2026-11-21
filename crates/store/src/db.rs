//! Connection management and migrations.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sqlx::any::{AnyPoolOptions, install_default_drivers};
use sqlx::migrate::Migrator;
use sqlx::{AnyPool, Executor};

use crate::crypto::{Cipher, MasterKey};
use crate::{Result, StoreError};

/// What [`Store::purge_expired`] removes besides expired codes and tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgePolicy {
    /// Clients that never obtained a token are deleted this long after
    /// registering.
    pub unused_client_ttl: Duration,
    /// Clients without any live grant are deleted this long after they last
    /// obtained a token.
    pub idle_client_ttl: Duration,
}

impl Default for PurgePolicy {
    fn default() -> Self {
        Self {
            unused_client_ttl: Duration::from_hours(24),
            idle_client_ttl: Duration::from_hours(30 * 24),
        }
    }
}

/// Handle to the database. Cheap to clone.
#[derive(Clone)]
pub struct Store {
    pub(crate) pool: AnyPool,
    pub(crate) cipher: std::sync::Arc<Cipher>,
    /// Data keys: the wrapper, and the keys unwrapped so far.
    pub(crate) keys: std::sync::Arc<crate::envelope::DataKeys>,
    /// Server outbox defaults and ceilings. Shared by every clone.
    pub(crate) outbox: std::sync::Arc<std::sync::RwLock<crate::events::OutboxPolicy>>,
    /// Seconds an event that cannot be opened is held. Shared by every clone.
    pub(crate) event_hold: std::sync::Arc<std::sync::atomic::AtomicU64>,
    /// Tenant that address and provider lookups and new accounts use.
    pub(crate) tenant: std::sync::Arc<str>,
}

/// Tenant of a [`Store`] that was not scoped with [`Store::for_tenant`].
pub const DEFAULT_TENANT: &str = "default";

/// The highest storage level this build reads.
///
/// The database records a level (`storage_level`), and a build refuses one
/// recorded above this, because a newer version used it
/// ([`StoreError::StorageLevelAhead`]). Level 1 is the formats written since
/// data keys: values under the master key (`v1.`) and under a tenant's data
/// key (`v2.`).
pub const STORAGE_LEVEL_READS: i64 = 1;

/// The storage level this build writes at by default.
///
/// Never above [`STORAGE_LEVEL_READS`]: a format of a higher level is written
/// only once the database is recorded at that level, where
/// [`Store::may_write_level`] allows it. There is none yet.
pub const STORAGE_LEVEL_WRITES: i64 = 1;
const _: () = assert!(STORAGE_LEVEL_WRITES <= STORAGE_LEVEL_READS);

/// Size and timeouts of the database connection pool. The defaults are
/// sqlx's, which is what every earlier version used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSettings {
    /// Most connections open at once.
    pub max_connections: u32,
    /// How long a query waits for a free connection before it fails.
    pub acquire_timeout: Duration,
    /// How long an unused connection stays open; `None` keeps it.
    pub idle_timeout: Option<Duration>,
    /// How long a connection is used before it is replaced; `None` keeps it.
    pub max_lifetime: Option<Duration>,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout: Duration::from_secs(30),
            idle_timeout: Some(Duration::from_mins(10)),
            max_lifetime: Some(Duration::from_mins(30)),
        }
    }
}

fn pool_options(settings: PoolSettings) -> AnyPoolOptions {
    AnyPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(settings.idle_timeout)
        .max_lifetime(settings.max_lifetime)
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    /// Connects to `database_url`, creating a SQLite database file if it does
    /// not exist, and applies pending migrations.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is unsupported, the database cannot be
    /// reached, or a migration fails.
    pub async fn connect(database_url: &str, key: &MasterKey) -> Result<Self> {
        Self::connect_rotating(database_url, key, &[]).await
    }

    /// Like [`Store::connect`], but values written under any of `previous`
    /// keys can still be read, and so can the data keys they wrapped. New
    /// values are written under a tenant's data key, which `key` wraps; call
    /// [`Store::reencrypt`] to move the values still under a master key to
    /// data keys, and [`Store::rewrap_data_keys`] to wrap the data keys under
    /// `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is unsupported, the database cannot be
    /// reached, or a migration fails.
    pub async fn connect_rotating(
        database_url: &str,
        key: &MasterKey,
        previous: &[MasterKey],
    ) -> Result<Self> {
        Self::connect_with(
            database_url,
            key,
            previous,
            PoolSettings::default(),
            Migrations::Apply,
        )
        .await
    }

    /// Like [`Store::connect_rotating`], with the connection pool sized and
    /// timed by `pool`, and pending migrations applied or refused as
    /// `migrations` says.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is unsupported, the database cannot be
    /// reached, or a migration fails. With [`Migrations::RequireCurrent`],
    /// [`StoreError::PendingMigrations`] lists the migrations not applied yet.
    /// [`StoreError::StorageLevelAhead`] means a newer version used the
    /// database, which is then left as it is.
    pub async fn connect_with(
        database_url: &str,
        key: &MasterKey,
        previous: &[MasterKey],
        pool: PoolSettings,
        migrations: Migrations,
    ) -> Result<Self> {
        install_default_drivers();
        let url = normalize_url(database_url);
        let pool = with_connection_setup(pool_options(pool))
            .connect(&url)
            .await?;
        match migrations {
            Migrations::Apply => {
                // A migration that runs outside a transaction can fail with
                // its own still open; closing the pool rolls it back before
                // the caller tries again.
                if let Err(err) = apply_migrations(&pool, &url).await {
                    pool.close().await;
                    return Err(err);
                }
            }
            Migrations::RequireCurrent => {
                let pending = pending_migrations(&pool, &url).await?;
                if !pending.is_empty() {
                    pool.close().await;
                    return Err(StoreError::PendingMigrations(pending));
                }
            }
        }
        if let Err(err) = check_level(&pool).await {
            pool.close().await;
            return Err(err);
        }
        tracing::debug!(backend = %backend(&url), "database ready");
        Ok(Self {
            pool,
            cipher: std::sync::Arc::new(key.cipher(previous)),
            keys: std::sync::Arc::new(crate::envelope::DataKeys::new(std::sync::Arc::new(
                crate::envelope::LocalKeyWrapper::new(key, previous),
            ))),
            outbox: crate::events::default_policy(),
            event_hold: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(60 * 60)),
            tenant: std::sync::Arc::from(DEFAULT_TENANT),
        })
    }

    /// Applies the pending migrations of the database at `database_url` and
    /// returns their versions, oldest first. An up-to-date database returns
    /// an empty list, so running it again is harmless. Needs no master key.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is unsupported, the database cannot be
    /// reached, or a migration fails. A database recorded above
    /// [`STORAGE_LEVEL_READS`] is [`StoreError::StorageLevelAhead`].
    pub async fn migrate(database_url: &str) -> Result<Vec<i64>> {
        install_default_drivers();
        let url = normalize_url(database_url);
        let pool = with_connection_setup(AnyPoolOptions::new().max_connections(1))
            .connect(&url)
            .await?;
        let result = async {
            let pending = pending_migrations(&pool, &url).await?;
            apply_migrations(&pool, &url).await?;
            check_level(&pool).await?;
            Ok(pending)
        }
        .await;
        pool.close().await;
        result
    }

    /// The storage level the database at `database_url` records. Needs no
    /// master key, and neither creates nor migrates the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is unsupported, the database cannot be
    /// reached, or it records no level.
    pub async fn read_storage_level(database_url: &str) -> Result<i64> {
        let pool = level_pool(database_url).await?;
        let level = read_level(&pool).await;
        pool.close().await;
        level
    }

    /// Raises the storage level of the database at `database_url` to
    /// [`STORAGE_LEVEL_READS`] if it is lower, and returns the level found
    /// and the level now. It never lowers the level. Run it only once every
    /// instance runs a version that reads that level. Needs no master key,
    /// and neither creates nor migrates the database.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is unsupported, the database cannot be
    /// reached or records no level, or the update fails. A database recorded
    /// above [`STORAGE_LEVEL_READS`] is [`StoreError::StorageLevelAhead`] and
    /// stays as it is.
    pub async fn raise_storage_level(database_url: &str) -> Result<(i64, i64)> {
        let pool = level_pool(database_url).await?;
        let result = async { raise_from(&pool, read_level(&pool).await?).await }.await;
        pool.close().await;
        result
    }

    /// Whether a stored format of storage `level` may be written now: one at
    /// or below [`STORAGE_LEVEL_WRITES`] always, one up to
    /// [`STORAGE_LEVEL_READS`] once the database records its level, none
    /// above. It reads the level on every call, so a raise counts at once.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn may_write_level(&self, level: i64) -> Result<bool> {
        let recorded = read_level(&self.pool).await?;
        Ok(writable(
            level,
            recorded,
            STORAGE_LEVEL_WRITES,
            STORAGE_LEVEL_READS,
        ))
    }

    /// The same store, with address and provider lookups and new accounts
    /// in `tenant`. Lookups by account ID are not scoped: IDs are unique.
    #[must_use]
    pub fn for_tenant(&self, tenant: &str) -> Self {
        Self {
            tenant: std::sync::Arc::from(tenant),
            ..self.clone()
        }
    }

    /// The tenant this store looks addresses up in.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// The connection pool, for an embedding's own tables in the same
    /// database. Its queries share the pool's size and timeouts with the
    /// store's. The store's tables are not a stable interface: use its
    /// methods for them.
    #[must_use]
    pub const fn pool(&self) -> &AnyPool {
        &self.pool
    }

    /// Begins a transaction that writes. On SQLite it takes the write lock
    /// as it begins (`BEGIN IMMEDIATE`), so it waits up to the busy timeout
    /// for another writer. A plain `BEGIN` that reads first does not: its
    /// first write fails at once with "database is locked" while another
    /// connection writes. PostgreSQL begins as before. `clippy.toml` refuses
    /// every other sqlx call that begins a transaction.
    pub(crate) async fn begin_write(&self) -> Result<sqlx::Transaction<'static, sqlx::Any>> {
        let options = self.pool.connect_options();
        let url = options.database_url.as_str();
        if matches!(backend(url), "postgres" | "postgresql") {
            #[expect(clippy::disallowed_methods, reason = "PostgreSQL begins plainly")]
            let tx = self.pool.begin().await?;
            return Ok(tx);
        }
        #[expect(clippy::disallowed_methods, reason = "SQLite takes the write lock")]
        let tx = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        Ok(tx)
    }

    /// Deletes expired authorization requests, codes and tokens, expired
    /// sign-ins at Microsoft or Google, held sends, events past each
    /// account's outbox limits, grants without tokens,
    /// and client registrations that are unused or idle
    /// according to `policy`. Returns the number of removed rows.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn purge_expired(&self, policy: PurgePolicy) -> Result<u64> {
        let now = now();
        let mut removed = 0;
        for statement in [
            "DELETE FROM authorization_requests WHERE expires_at <= $1",
            "DELETE FROM authorization_codes WHERE expires_at <= $1",
            "DELETE FROM access_tokens WHERE expires_at <= $1",
            "DELETE FROM refresh_tokens WHERE expires_at <= $1",
            "DELETE FROM account_sessions WHERE expires_at <= $1",
            "DELETE FROM upstream_requests WHERE expires_at <= $1",
            "DELETE FROM held_sends WHERE expires_at <= $1",
        ] {
            removed += sqlx::query(statement)
                .bind(now)
                .execute(&self.pool)
                .await?
                .rows_affected();
        }
        // Grants without any remaining refresh or access token are dead.
        removed += sqlx::query(
            "DELETE FROM grants WHERE NOT EXISTS \
             (SELECT 1 FROM refresh_tokens r WHERE r.grant_id = grants.id) \
             AND NOT EXISTS (SELECT 1 FROM access_tokens a WHERE a.grant_id = grants.id)",
        )
        .execute(&self.pool)
        .await?
        .rows_affected();
        // Clients with no grant, code or pending request that were never
        // used (or not used for a long time) are abandoned registrations.
        removed += sqlx::query(
            "DELETE FROM oauth_clients WHERE \
             NOT EXISTS (SELECT 1 FROM grants g WHERE g.client_id = oauth_clients.id) \
             AND NOT EXISTS (SELECT 1 FROM authorization_codes c WHERE c.client_id = oauth_clients.id) \
             AND NOT EXISTS (SELECT 1 FROM authorization_requests r WHERE r.client_id = oauth_clients.id) \
             AND ((last_used_at IS NULL AND created_at <= $1) OR last_used_at <= $2)",
        )
        .bind(before(now, policy.unused_client_ttl))
        .bind(before(now, policy.idle_client_ttl))
        .execute(&self.pool)
        .await?
        .rows_affected();
        removed += self.purge_old_events().await?;
        Ok(removed)
    }

    /// Checks that the database answers queries.
    ///
    /// # Errors
    ///
    /// Returns an error if the database is unreachable.
    pub async fn ping(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Versions this build has that the database has not applied, oldest
    /// first; empty when the database is current. Migrations the database
    /// has and this build lacks, written by a newer version, don't count.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn pending_migrations(&self) -> Result<Vec<i64>> {
        let options = self.pool.connect_options();
        pending_migrations(&self.pool, options.database_url.as_str()).await
    }

    /// Closes all connections.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}

/// Lets SQLite create the database file when it does not exist yet.
fn normalize_url(url: &str) -> String {
    let is_sqlite = url.starts_with("sqlite:");
    let is_memory = url.contains(":memory:") || url.contains("mode=memory");
    if is_sqlite && !is_memory && !url.contains("mode=") {
        let separator = if url.contains('?') { '&' } else { '?' };
        format!("{url}{separator}mode=rwc")
    } else {
        url.to_owned()
    }
}

/// Whether connecting applies pending migrations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Migrations {
    /// Apply them, as every earlier version did.
    #[default]
    Apply,
    /// Refuse to start while any is pending; `postkeep migrate` applies
    /// them, for example from a release command on a direct connection.
    RequireCurrent,
}

/// Sets up every new connection: on SQLite, WAL, foreign keys and a busy
/// timeout.
fn with_connection_setup(options: AnyPoolOptions) -> AnyPoolOptions {
    options.after_connect(|conn, _meta| {
        Box::pin(async move {
            if conn.backend_name() == "SQLite" {
                conn.execute("PRAGMA journal_mode = WAL").await?;
                conn.execute("PRAGMA foreign_keys = ON").await?;
                // Wait for another writer instead of failing at once.
                // Refresh-token rotation claims the row with a
                // conditional UPDATE; without this the loser of two
                // concurrent uses gets SQLITE_BUSY instead of reaching
                // the grace or replay path.
                conn.execute("PRAGMA busy_timeout = 5000").await?;
            }
            Ok(())
        })
    })
}

/// Applies the pending migrations, unless a newer version used the database:
/// then nothing in it changes, and the level is the error even where sqlx
/// would stop at a migration this build lacks. A database from before the
/// storage level has no level to read yet; migration 0014 records level 1.
async fn apply_migrations(pool: &AnyPool, url: &str) -> Result<()> {
    if let Err(ahead @ StoreError::StorageLevelAhead { .. }) = check_level(pool).await {
        return Err(ahead);
    }
    Ok(migrator(url).run(pool).await?)
}

/// Refuses a database recorded above [`STORAGE_LEVEL_READS`], or one that does
/// not answer with its level.
async fn check_level(pool: &AnyPool) -> Result<()> {
    refuse_ahead(read_level(pool).await?)
}

/// The level the database records.
async fn read_level(pool: &AnyPool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT level FROM storage_level")
        .fetch_one(pool)
        .await?)
}

/// Refuses a `level` above [`STORAGE_LEVEL_READS`].
const fn refuse_ahead(level: i64) -> Result<()> {
    if level > STORAGE_LEVEL_READS {
        return Err(StoreError::StorageLevelAhead {
            database: level,
            build: STORAGE_LEVEL_READS,
        });
    }
    Ok(())
}

/// One connection for reading or raising the level. Without
/// [`normalize_url`], so a wrong SQLite path is an error, not a new file.
async fn level_pool(database_url: &str) -> Result<AnyPool> {
    install_default_drivers();
    Ok(
        with_connection_setup(AnyPoolOptions::new().max_connections(1))
            .connect(database_url)
            .await?,
    )
}

/// The raise once its first read found `found`.
async fn raise_from(pool: &AnyPool, found: i64) -> Result<(i64, i64)> {
    refuse_ahead(found)?;
    // The condition keeps a newer release's raise since the read from going
    // back down.
    let changed = sqlx::query("UPDATE storage_level SET level = $1 WHERE level < $2")
        .bind(STORAGE_LEVEL_READS)
        .bind(STORAGE_LEVEL_READS)
        .execute(pool)
        .await?
        .rows_affected();
    if changed == 1 {
        return Ok((found, STORAGE_LEVEL_READS));
    }
    // Already raised, by another raise or by a newer release since the read.
    let now = read_level(pool).await?;
    refuse_ahead(now)?;
    Ok((now, now))
}

/// Whether a format of storage `level` may be written to a database recorded
/// at `recorded`, by a build that writes at `writes` by default and reads up
/// to `reads`.
const fn writable(level: i64, recorded: i64, writes: i64, reads: i64) -> bool {
    level <= writes || (level <= reads && level <= recorded)
}

/// Versions this build has that the database has not applied, oldest
/// first.
async fn pending_migrations(pool: &AnyPool, url: &str) -> Result<Vec<i64>> {
    let table = if matches!(backend(url), "postgres" | "postgresql") {
        "SELECT 1 FROM information_schema.tables \
         WHERE table_name = '_sqlx_migrations' AND table_schema = current_schema()"
    } else {
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'"
    };
    let applied: Vec<i64> = if sqlx::query(table).fetch_optional(pool).await?.is_some() {
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations")
            .fetch_all(pool)
            .await?
    } else {
        Vec::new()
    };
    Ok(migrator(url)
        .iter()
        .map(|migration| migration.version)
        .filter(|version| !applied.contains(version))
        .collect())
}

/// Migrations for SQLite. 0001 to 0008 are byte-identical to the
/// PostgreSQL folder and to the single folder of earlier versions, so the
/// checksums they recorded in `_sqlx_migrations` stay valid.
static SQLITE_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/sqlite");

/// Migrations for PostgreSQL; see [`SQLITE_MIGRATIONS`].
static POSTGRES_MIGRATIONS: Migrator = sqlx::migrate!("./migrations/postgres");

/// The migrations for the database at `url`.
fn migrator(url: &str) -> &'static Migrator {
    if matches!(backend(url), "postgres" | "postgresql") {
        &POSTGRES_MIGRATIONS
    } else {
        &SQLITE_MIGRATIONS
    }
}

fn backend(url: &str) -> &str {
    url.split_once(':').map_or("unknown", |(scheme, _)| scheme)
}

/// Current Unix time in seconds.
#[must_use]
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// Unix time `age` before `now`.
pub fn before(now: i64, age: Duration) -> i64 {
    now.saturating_sub(i64::try_from(age.as_secs()).unwrap_or(i64::MAX))
}

/// Unix time `ttl` from now.
pub fn expires_in(ttl: Duration) -> i64 {
    now().saturating_add(i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX))
}

/// Returns `error` after `ROLLBACK` has finished.
///
/// Dropping a sqlx transaction only queues the rollback on the connection's
/// worker. The caller can open another connection, read, and then write
/// before that rollback runs. SQLite then returns "database is locked" at
/// once: a transaction that has already read does not wait for
/// `busy_timeout`. Waiting here releases the write lock first.
pub async fn rollback_then<T>(
    tx: sqlx::Transaction<'_, sqlx::Any>,
    error: StoreError,
) -> Result<T> {
    if let Err(err) = tx.rollback().await {
        tracing::debug!(%err, "rollback after a failed write");
    }
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pool_settings_build_the_options_used_before() {
        // Earlier versions used sqlx's defaults with `max_connections(10)`.
        let before = AnyPoolOptions::new().max_connections(10);
        let now = pool_options(PoolSettings::default());
        assert_eq!(now.get_max_connections(), before.get_max_connections());
        assert_eq!(now.get_acquire_timeout(), before.get_acquire_timeout());
        assert_eq!(now.get_idle_timeout(), before.get_idle_timeout());
        assert_eq!(now.get_max_lifetime(), before.get_max_lifetime());
        assert_eq!(now.get_min_connections(), before.get_min_connections());
    }

    #[test]
    fn pool_settings_reach_the_options() {
        let options = pool_options(PoolSettings {
            max_connections: 4,
            acquire_timeout: Duration::from_secs(5),
            idle_timeout: Some(Duration::from_secs(300)),
            max_lifetime: None,
        });
        assert_eq!(options.get_max_connections(), 4);
        assert_eq!(options.get_acquire_timeout(), Duration::from_secs(5));
        assert_eq!(options.get_idle_timeout(), Some(Duration::from_secs(300)));
        assert_eq!(options.get_max_lifetime(), None);
    }

    #[test]
    fn a_format_above_the_default_write_level_waits_for_its_level() {
        for (level, recorded, expected) in [
            (1, 0, true),
            (1, 1, true),
            (2, 1, false),
            (2, 2, true),
            (2, 3, true),
            (3, 2, false),
            (3, 3, true),
            (4, 9, false),
        ] {
            assert_eq!(
                writable(level, recorded, 1, 3),
                expected,
                "level {level}, recorded {recorded}"
            );
        }
    }

    /// A raise that read this version's level, while a newer release raised
    /// the database above it, is refused and leaves the level as it is.
    async fn exercise_a_raise_racing_a_newer_raise(url: &str) {
        Store::migrate(url).await.unwrap();
        let pool = level_pool(url).await.unwrap();
        let newer = STORAGE_LEVEL_READS + 1;
        sqlx::query("UPDATE storage_level SET level = $1")
            .bind(newer)
            .execute(&pool)
            .await
            .unwrap();
        let raised = raise_from(&pool, STORAGE_LEVEL_READS).await;
        assert!(
            matches!(
                raised,
                Err(StoreError::StorageLevelAhead { database, build })
                    if database == newer && build == STORAGE_LEVEL_READS
            ),
            "{raised:?}"
        );
        assert_eq!(read_level(&pool).await.unwrap(), newer);
        pool.close().await;
    }

    #[tokio::test]
    async fn sqlite_a_raise_racing_a_newer_raise_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("postkeep.db").display());
        exercise_a_raise_racing_a_newer_raise(&url).await;
    }

    /// In a database of its own: the tests in `data_keys.rs` use the one in
    /// `TEST_POSTGRES_URL`.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[ignore = "requires TEST_POSTGRES_URL"]
    async fn postgres_a_raise_racing_a_newer_raise_changes_nothing() {
        install_default_drivers();
        let admin_url =
            std::env::var("TEST_POSTGRES_URL").unwrap_or_else(|_| panic!("set TEST_POSTGRES_URL"));
        let admin = AnyPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .unwrap();
        let name = format!("postkeep_level_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&admin)
            .await
            .unwrap();
        let (base, query) = admin_url
            .split_once('?')
            .map_or((admin_url.as_str(), None), |(base, query)| {
                (base, Some(query))
            });
        let (server, _) = base.rsplit_once('/').unwrap();
        let url = query.map_or_else(
            || format!("{server}/{name}"),
            |query| format!("{server}/{name}?{query}"),
        );
        exercise_a_raise_racing_a_newer_raise(&url).await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE {name} WITH (FORCE)"
        )))
        .execute(&admin)
        .await
        .unwrap();
        admin.close().await;
    }

    #[test]
    fn sqlite_urls_get_create_mode() {
        assert_eq!(
            normalize_url("sqlite://db.sqlite"),
            "sqlite://db.sqlite?mode=rwc"
        );
        assert_eq!(
            normalize_url("sqlite://db.sqlite?cache=shared"),
            "sqlite://db.sqlite?cache=shared&mode=rwc"
        );
        assert_eq!(
            normalize_url("sqlite://db.sqlite?mode=ro"),
            "sqlite://db.sqlite?mode=ro"
        );
        assert_eq!(normalize_url("sqlite::memory:"), "sqlite::memory:");
        assert_eq!(normalize_url("postgres://u@h/db"), "postgres://u@h/db");
    }
}
