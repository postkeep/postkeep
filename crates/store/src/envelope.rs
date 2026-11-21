//! Envelope encryption: a data key per tenant, wrapped by a key encryption
//! key (KEK) that a [`KeyWrapper`] holds.
//!
//! Data keys are 32 random bytes, numbered by version for each tenant, and
//! stored only wrapped, in `data_keys`, next to the name of the KEK that
//! wrapped them. The tenant is bound to every wrapped key, so a key copied
//! to another tenant's row does not unwrap. The default wrapper,
//! [`LocalKeyWrapper`], wraps with the master key; an embedding can keep its
//! KEK in a key service instead ([`Store::with_key_wrapper`]).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};

use aes_gcm::aead::{Aead, Generate, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use sqlx::Row;
use sqlx::any::AnyRow;
use zeroize::Zeroizing;

use crate::crypto::{KEY_LEN, MasterKey, Slot, Stored, open_v2, seal_v2, v2_context};
use crate::{DEFAULT_TENANT, Result, Store, StoreError, now};

/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// How many rows [`Store::rewrap_data_keys`] reads at a time.
const REWRAP_BATCH: i64 = 100;

/// How many keys one call adds to a tenant at most. A call needs more than one
/// only when another process stored that version first, with a key that this
/// store cannot unwrap.
const NEW_KEY_TRIES: usize = 3;

/// The version of the row that marks a tenant whose data keys were destroyed.
/// It is the highest there is, so every store sees it first. A build from
/// before this one, which adds one above the highest version when it can
/// unwrap none, tries exactly this version, finds it taken and stores no key.
const DESTROYED_VERSION: i64 = i64::MAX;

/// The provider of the rows a destruction leaves, which hold no key
/// (`wrapped` is empty).
const DESTROYED_PROVIDER: &str = "destroyed";

/// Deletes every row of `tenant` that holds a key, and returns their versions.
/// The rows a destruction leaves stay.
async fn delete_keys_of<'e, E: sqlx::Executor<'e, Database = sqlx::Any>>(
    executor: E,
    tenant: &str,
) -> Result<Vec<i64>> {
    let rows = sqlx::query(
        "DELETE FROM data_keys WHERE tenant = $1 AND NOT (provider = $2 AND wrapped = '') \
         RETURNING version",
    )
    .bind(tenant)
    .bind(DESTROYED_PROVIDER)
    .fetch_all(executor)
    .await?;
    rows.iter()
        .map(|row| row.try_get("version").map_err(StoreError::from))
        .collect()
}

/// What a [`KeyWrapper`] call returns.
pub type WrapFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// A tenant's data key, unwrapped, in memory only.
pub struct DataKey(Zeroizing<[u8; KEY_LEN]>);

impl DataKey {
    /// A new random key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Random`] if the system RNG fails.
    pub fn generate() -> Result<Self> {
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        getrandom::fill(key.as_mut_slice()).map_err(|_| StoreError::Random)?;
        Ok(Self(key))
    }

    /// The key in `bytes`, for a wrapper that unwrapped it.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::KeyWrap`] unless `bytes` is 32 bytes long. When
    /// `bytes` came out of an authenticated unwrap, a wrong length never
    /// goes away: the wrapper should answer [`StoreError::Decrypt`] then, as
    /// [`LocalKeyWrapper`] does.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_LEN {
            return Err(StoreError::KeyWrap(
                "a data key must be 32 bytes".to_owned(),
            ));
        }
        // Copied straight into the zeroized array, so no plain copy is left.
        let mut key = Zeroizing::new([0_u8; KEY_LEN]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// The key's bytes, for a wrapper to wrap.
    #[must_use]
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Whether two keys are the same, in constant time.
    fn same_as(&self, other: &Self) -> bool {
        crate::crypto::constant_time_eq(self.0.as_slice(), other.0.as_slice())
    }
}

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey([REDACTED])")
    }
}

/// The key encryption key that wrapped a data key, as `data_keys` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kek {
    /// Which wrapper: `local` for [`LocalKeyWrapper`].
    pub provider: String,
    /// The KEK's name within the provider.
    pub id: String,
    /// The KEK's version, for providers that rotate keys under one name.
    pub version: i64,
}

/// A wrapped data key, as `wrap` returns it and `data_keys` stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapped {
    /// The KEK that wrapped the key. A key service tells which version it
    /// used only in its answer, and may have rotated since
    /// [`KeyWrapper::current`] was asked, so this is what the store records.
    pub kek: Kek,
    /// The wrapper's output, which [`KeyWrapper::unwrap`] is given back
    /// together with `kek`.
    pub bytes: Vec<u8>,
}

/// The outcome of [`Store::rewrap_data_keys`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Rewrapped {
    /// Data keys that another KEK had wrapped and that now are wrapped by the
    /// KEK that `wrap` returned.
    pub rewrapped: u64,
    /// Data keys that the wrapper can never unwrap, such as one that a master
    /// key wrapped that is no longer configured. They are left as they are.
    pub unreadable: u64,
}

/// Wraps and unwraps data keys with a key encryption key it holds.
///
/// `wrap` must bind `tenant` to the result, so that only `unwrap` with the
/// same tenant returns the key. The calls may take time, such as a request
/// to a key service; the store keeps the keys it unwrapped, so `unwrap`
/// normally runs once per key and process.
///
/// A failure is a [`StoreError`], and which one matters: postkeep takes
/// [`StoreError::Decrypt`] to mean that a stored value is unreadable for
/// good, and any other error to be a failure that a later attempt may get
/// past. The text of a [`StoreError::KeyWrap`] can reach logs and callers:
/// keep key material out of it.
pub trait KeyWrapper: Send + Sync {
    /// The KEK that new wraps would use, as far as this wrapper knows.
    ///
    /// Answer from memory, without asking a key service. The answer may lag
    /// behind a rotation made elsewhere, so a caller can only use it to tell
    /// whether a stored key was wrapped by another KEK. The KEK stored with
    /// a new key is not this one but [`Wrapped::kek`], which `wrap` returns.
    fn current(&self) -> Kek;

    /// Wraps `key` for `tenant`, and returns the result with the KEK that
    /// wrapped it. A failure is [`StoreError::KeyWrap`].
    fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped>;

    /// Unwraps a key that `kek` wrapped for `tenant`.
    ///
    /// The store hands over a stored key as it is, whatever its
    /// `kek.provider`, so also a key that an earlier wrapper made if the
    /// wrapper was replaced. Answer [`StoreError::Decrypt`] for a provider
    /// you do not know, or pass the key on to the wrapper that made it.
    ///
    /// Return [`StoreError::Decrypt`] only when `wrapped` can never be
    /// unwrapped with the keys this wrapper holds: it is another tenant's,
    /// corrupt, or wrapped by a KEK this wrapper does not have. Anything that
    /// may succeed on a later call, such as a key service that is
    /// unreachable, sealed or refuses for now, is [`StoreError::KeyWrap`].
    ///
    /// The difference decides what the store does. When `Decrypt` is the
    /// answer for every data key of a tenant, [`Store::data_key`] makes a new
    /// one for it, unless the tenant's keys were destroyed, so a wrong `Decrypt` costs an extra key version, and
    /// `data_key` does not ask about that row again until it changes or the
    /// process restarts (a read under that version does, unless the store
    /// holds its key, and `data_key` uses what a read unwraps). `KeyWrap` is
    /// returned to the caller: no key is skipped or made. A new key is unwrapped
    /// before it is stored, and a `Decrypt` for it is returned as `KeyWrap`.
    fn unwrap<'a>(
        &'a self,
        tenant: &'a str,
        kek: &'a Kek,
        wrapped: &'a [u8],
    ) -> WrapFuture<'a, DataKey>;
}

/// The default [`KeyWrapper`]: AES-256-GCM under the master key, with the
/// tenant as associated data. Keys wrapped under a previous master key still
/// unwrap while that key is configured as previous.
pub struct LocalKeyWrapper {
    /// The current key first, then the previous ones, each with its id.
    keys: Vec<(String, Aes256Gcm)>,
}

impl LocalKeyWrapper {
    /// The provider name in `data_keys`.
    pub const PROVIDER: &'static str = "local";

    /// Wraps with `key`, and unwraps with `key` or any of `previous`.
    #[must_use]
    pub fn new(key: &MasterKey, previous: &[MasterKey]) -> Self {
        let keys = std::iter::once(key)
            .chain(previous)
            .map(|key| (key.id(), key.aead()))
            .collect();
        Self { keys }
    }
}

impl std::fmt::Debug for LocalKeyWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKeyWrapper").finish_non_exhaustive()
    }
}

/// Associated data of a data key wrapped by [`LocalKeyWrapper`].
fn wrap_context(tenant: &str) -> String {
    format!("postkeep/data-key/v1/{tenant}")
}

impl KeyWrapper for LocalKeyWrapper {
    fn current(&self) -> Kek {
        Kek {
            provider: Self::PROVIDER.to_owned(),
            id: self.keys[0].0.clone(),
            version: 1,
        }
    }

    fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
        Box::pin(async move {
            let nonce = Nonce::try_generate()
                .map_err(|_| StoreError::KeyWrap("could not generate a nonce".to_owned()))?;
            let context = wrap_context(tenant);
            let sealed = self.keys[0]
                .1
                .encrypt(
                    &nonce,
                    Payload {
                        msg: key.expose(),
                        aad: context.as_bytes(),
                    },
                )
                .map_err(|_| StoreError::KeyWrap("could not encrypt the data key".to_owned()))?;
            Ok(Wrapped {
                kek: self.current(),
                bytes: [nonce.as_slice(), &sealed].concat(),
            })
        })
    }

    fn unwrap<'a>(
        &'a self,
        tenant: &'a str,
        kek: &'a Kek,
        wrapped: &'a [u8],
    ) -> WrapFuture<'a, DataKey> {
        Box::pin(async move {
            // This wrapper holds its keys and asks no one, so a failure is
            // final and always `Decrypt`, as for a value under an unknown
            // master key. A key that another provider wrapped is not ours.
            if kek.provider != Self::PROVIDER {
                return Err(StoreError::Decrypt);
            }
            let Some((_, aead)) = self.keys.iter().find(|(id, _)| *id == kek.id) else {
                tracing::debug!(kek_id = %kek.id, "no configured master key has this id");
                return Err(StoreError::Decrypt);
            };
            if wrapped.len() <= NONCE_LEN {
                return Err(StoreError::Decrypt);
            }
            let (nonce, sealed) = wrapped.split_at(NONCE_LEN);
            let nonce = Nonce::try_from(nonce).map_err(|_| StoreError::Decrypt)?;
            let context = wrap_context(tenant);
            let plain = aead
                .decrypt(
                    &nonce,
                    Payload {
                        msg: sealed,
                        aad: context.as_bytes(),
                    },
                )
                .map(Zeroizing::new)
                .map_err(|_| StoreError::Decrypt)?;
            DataKey::from_bytes(&plain).map_err(|_| StoreError::Decrypt)
        })
    }
}

/// What a `data_keys` row holds of the wrapping: the KEK it names and the
/// wrapper's output as stored. What the store learned by asking the wrapper
/// holds only while the row stays as it was: a re-wrap changes the KEK, and the
/// text too unless the wrapper is deterministic.
#[derive(Clone, PartialEq, Eq)]
struct Wrapping {
    kek: Kek,
    wrapped: String,
}

impl Wrapping {
    fn of(row: &AnyRow) -> Result<Self> {
        let kek = Kek {
            provider: row.try_get("provider")?,
            id: row.try_get("kek_id")?,
            version: row.try_get("kek_version")?,
        };
        Ok(Self {
            kek,
            wrapped: row.try_get("wrapped")?,
        })
    }
}

/// A key that the wrapper unwrapped, with the row it came from.
type Unwrapped = (Wrapping, Arc<DataKey>);

/// What a tenant's rows come to for this process.
enum Newest {
    /// The newest version it can unwrap, and its key.
    Key(i64, Arc<DataKey>),
    /// There is no row: first use.
    NoRows,
    /// There are rows and it can unwrap none; the highest version.
    NoneUnwraps(i64),
}

/// The wrapper a store uses, and what it learned about the rows it asked about.
#[allow(
    clippy::redundant_pub_crate,
    reason = "every module of this crate is private; this says the type is not API"
)]
pub(crate) struct DataKeys {
    wrapper: Arc<dyn KeyWrapper>,
    /// By tenant and version, with the row as it was when the wrapper answered.
    keys: Mutex<HashMap<(String, i64), Unwrapped>>,
    /// The rows the wrapper answered [`StoreError::Decrypt`] for, as they were
    /// then. Kept apart from the keys: a row that cannot be unwrapped now takes
    /// nothing from a key that was unwrapped from it before.
    dead: Mutex<HashMap<(String, i64), Wrapping>>,
    /// Tenants whose keys this store found or made destroyed. Locked after
    /// `keys`, never before.
    destroyed: Mutex<HashSet<String>>,
}

impl DataKeys {
    pub(crate) fn new(wrapper: Arc<dyn KeyWrapper>) -> Self {
        Self {
            wrapper,
            keys: Mutex::default(),
            dead: Mutex::default(),
            destroyed: Mutex::default(),
        }
    }

    /// The key of a version that the wrapper unwrapped, whatever its row holds
    /// now: a read goes by the version in the value and does not look at the row.
    fn cached(&self, tenant: &str, version: i64) -> Option<Arc<DataKey>> {
        let keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        keys.get(&(tenant.to_owned(), version))
            .map(|(_, key)| Arc::clone(key))
    }

    /// The key the wrapper unwrapped from exactly this row, if it was asked.
    fn recall(&self, tenant: &str, version: i64, wrapping: &Wrapping) -> Option<Arc<DataKey>> {
        let keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        keys.get(&(tenant.to_owned(), version))
            .filter(|(seen, _)| seen == wrapping)
            .map(|(_, key)| Arc::clone(key))
    }

    /// Whether the wrapper answered `Decrypt` for exactly this row.
    fn is_dead(&self, tenant: &str, version: i64, wrapping: &Wrapping) -> bool {
        let dead = self.dead.lock().unwrap_or_else(PoisonError::into_inner);
        dead.get(&(tenant.to_owned(), version)) == Some(wrapping)
    }

    // Both take `keys` before `destroyed`, so a key unwrapped from a row read
    // before the destruction is never kept after `forget`.
    fn remember(&self, tenant: &str, version: i64, wrapping: Wrapping, key: Arc<DataKey>) {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        let destroyed = self
            .destroyed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if !destroyed.contains(tenant) {
            keys.insert((tenant.to_owned(), version), (wrapping, key));
        }
    }

    /// Drops every key and dead row of `tenant`, and keeps no key of it again.
    fn forget(&self, tenant: &str) {
        let mut keys = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        self.destroyed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(tenant.to_owned());
        keys.retain(|(t, _), _| t != tenant);
        drop(keys);
        let mut dead = self.dead.lock().unwrap_or_else(PoisonError::into_inner);
        dead.retain(|(t, _), _| t != tenant);
    }

    fn bury(&self, tenant: &str, version: i64, wrapping: Wrapping) {
        let mut dead = self.dead.lock().unwrap_or_else(PoisonError::into_inner);
        dead.insert((tenant.to_owned(), version), wrapping);
    }
}

impl Store {
    /// The same store with data keys wrapped and unwrapped by `wrapper`
    /// instead of [`LocalKeyWrapper`]. Keys already unwrapped are forgotten,
    /// and clones made earlier, such as from [`Store::for_tenant`], keep the
    /// wrapper they had.
    #[must_use]
    pub fn with_key_wrapper(mut self, wrapper: Arc<dyn KeyWrapper>) -> Self {
        self.keys = Arc::new(DataKeys::new(wrapper));
        self
    }

    /// The newest data key of this store's tenant that this store can unwrap,
    /// and its version. On first use, version 1 is made, wrapped, unwrapped to
    /// check that the wrapper can, and stored. If another process stored it
    /// first, that key is the one, so that every process uses the stored key.
    /// A wrapper that cannot unwrap fails before anything is stored or
    /// encrypted. Each call reads the tenant's rows, so a version that
    /// another process added is found; only the wrapper's answers are remembered.
    ///
    /// A process writes under the newest version it can unwrap, and adds one
    /// only when it can unwrap none, such as after the master key was lost or
    /// replaced. Then [`StoreError::Decrypt`] for every row makes the next
    /// version, one above the highest, which is made like the first, and a
    /// warning is logged. The older versions stay: a process that cannot
    /// unwrap them cannot read the values under them until they are entered
    /// again, and one that can falls back to its newest, so two processes with
    /// different keys keep a version each and add no more.
    ///
    /// # Errors
    ///
    /// Returns an error if the database fails or the wrapper cannot wrap or
    /// unwrap a key. Only [`StoreError::Decrypt`] passes over a version, and
    /// only when it is the answer for every version is one added. Any other
    /// error, such as [`StoreError::KeyWrap`] from a key service that does not
    /// answer, is returned at once, whatever the other versions are. So is a
    /// `Decrypt` for the key just made, as `KeyWrap`, and nothing is stored.
    /// [`StoreError::KeysDestroyed`] if the tenant's keys were destroyed; no
    /// key is made then.
    pub async fn data_key(&self) -> Result<(i64, Arc<DataKey>)> {
        self.newest_key_of(&self.tenant).await
    }

    /// Version `version` of this store's tenant's data key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Decrypt`] if there is no such key, and an error
    /// if the database fails or the wrapper cannot unwrap the key.
    /// [`StoreError::KeysDestroyed`] if the tenant's keys were destroyed; no
    /// key is made then.
    pub async fn data_key_version(&self, version: i64) -> Result<Arc<DataKey>> {
        self.key_of(&self.tenant, version).await
    }

    /// The newest data key of `tenant` that this store can unwrap, made on
    /// first use, or when it can unwrap none, as [`Store::data_key`] says. A
    /// value is bound to the tenant of its row, which is not always the tenant
    /// of the store that reads or writes it.
    async fn newest_key_of(&self, tenant: &str) -> Result<(i64, Arc<DataKey>)> {
        for _ in 0..NEW_KEY_TRIES {
            match self.newest_stored_key_of(tenant).await? {
                Newest::Key(version, key) => return Ok((version, key)),
                Newest::NoRows => {
                    self.add_key(tenant, 1).await?;
                }
                // One above every version there is, readable or not.
                Newest::NoneUnwraps(highest) => {
                    let version = highest.saturating_add(1);
                    if self.add_key(tenant, version).await? {
                        tracing::warn!(
                            tenant,
                            version,
                            "no data key of this tenant can be unwrapped, so a new one was made; \
                             values under the older keys stay unreadable until they are entered again"
                        );
                    }
                }
            }
        }
        // The key added last is looked up too.
        match self.newest_stored_key_of(tenant).await? {
            Newest::Key(version, key) => Ok((version, key)),
            Newest::NoRows | Newest::NoneUnwraps(_) => Err(StoreError::KeyWrap(
                "could not store a new data key".to_owned(),
            )),
        }
    }

    /// Stores a new key as `version` of `tenant`, wrapped, unless that version
    /// exists. Whether it is this call's key that was stored.
    ///
    /// The wrapper must unwrap what it wrapped before anything is stored. One
    /// that answers `Decrypt` for it would be given a row at every call, none of
    /// which it can read.
    async fn add_key(&self, tenant: &str, version: i64) -> Result<bool> {
        let key = DataKey::generate()?;
        // The row names the KEK that `wrap` says it used, not `current`: a key
        // service may have rotated between the two calls.
        let Wrapped { kek, bytes } = self.keys.wrapper.wrap(tenant, &key).await?;
        // The key in use is the one that `unwrap` returns.
        let key = match self.keys.wrapper.unwrap(tenant, &kek, &bytes).await {
            Ok(key) => Arc::new(key),
            Err(StoreError::Decrypt) => {
                let message = "the wrapper does not unwrap the data key it just wrapped";
                return Err(StoreError::KeyWrap(message.to_owned()));
            }
            Err(err) => return Err(err),
        };
        let wrapped = URL_SAFE_NO_PAD.encode(bytes);
        // Another process may store the version first; then its key is the one.
        let stored = sqlx::query(
            "INSERT INTO data_keys \
             (tenant, version, provider, kek_id, kek_version, wrapped, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (tenant, version) DO NOTHING",
        )
        .bind(tenant)
        .bind(version)
        .bind(&kek.provider)
        .bind(&kek.id)
        .bind(kek.version)
        .bind(&wrapped)
        .bind(now())
        .execute(&self.pool)
        .await?
        .rows_affected();
        if stored > 0 {
            // What was just checked is the key of the row, so it is not unwrapped again.
            let wrapping = Wrapping { kek, wrapped };
            self.keys.remember(tenant, version, wrapping, key);
        }
        Ok(stored > 0)
    }

    /// Version `version` of `tenant`'s data key. It never makes a key.
    async fn key_of(&self, tenant: &str, version: i64) -> Result<Arc<DataKey>> {
        if let Some(key) = self.keys.cached(tenant, version) {
            return Ok(key);
        }
        let rows = sqlx::query(
            "SELECT version, provider, kek_id, kek_version, wrapped FROM data_keys \
             WHERE tenant = $1 AND version IN ($2, $3)",
        )
        .bind(tenant)
        .bind(version)
        .bind(DESTROYED_VERSION)
        .fetch_all(&self.pool)
        .await?;
        let mut found = None;
        for row in rows {
            match row.try_get::<i64, _>("version")? {
                DESTROYED_VERSION => return Err(StoreError::KeysDestroyed),
                _ => found = Some(row),
            }
        }
        let row = found.ok_or(StoreError::Decrypt)?;
        self.unwrap_row(tenant, version, &row).await
    }

    /// The rows of `tenant`, newest first, up to the first that this store can
    /// unwrap. A row that answered `Decrypt` is passed over, and not asked
    /// about again while it stays as it is, unless a read has unwrapped it
    /// since. Any other error is returned: no row is passed over on its account.
    async fn newest_stored_key_of(&self, tenant: &str) -> Result<Newest> {
        let rows = sqlx::query(
            "SELECT version, provider, kek_id, kek_version, wrapped FROM data_keys \
             WHERE tenant = $1 ORDER BY version DESC",
        )
        .bind(tenant)
        .fetch_all(&self.pool)
        .await?;
        let Some(newest) = rows.first() else {
            return Ok(Newest::NoRows);
        };
        let highest: i64 = newest.try_get("version")?;
        if highest == DESTROYED_VERSION {
            self.keys.forget(tenant);
            // A key row made by hand, or brought back with part of a backup, goes too.
            let healed = delete_keys_of(&self.pool, tenant).await?;
            if !healed.is_empty() {
                tracing::warn!(tenant, versions = ?healed, "deleted data keys found beside a destroyed tenant's mark");
            }
            return Err(StoreError::KeysDestroyed);
        }
        for row in &rows {
            let version: i64 = row.try_get("version")?;
            let wrapping = Wrapping::of(row)?;
            // A key that a read unwrapped from exactly this row is a later answer
            // than the `Decrypt` that made it dead, so it comes first.
            if let Some(key) = self.keys.recall(tenant, version, &wrapping) {
                return Ok(Newest::Key(version, key));
            }
            if self.keys.is_dead(tenant, version, &wrapping) {
                continue;
            }
            match self.unwrap_row(tenant, version, row).await {
                Ok(key) => return Ok(Newest::Key(version, key)),
                Err(StoreError::Decrypt) => self.keys.bury(tenant, version, wrapping),
                Err(err) => return Err(err),
            }
        }
        Ok(Newest::NoneUnwraps(highest))
    }

    /// The key a `data_keys` row holds: the one unwrapped before if the row is
    /// as it was then, else unwrapped now and remembered.
    async fn unwrap_row(&self, tenant: &str, version: i64, row: &AnyRow) -> Result<Arc<DataKey>> {
        let wrapping = Wrapping::of(row)?;
        if let Some(key) = self.keys.recall(tenant, version, &wrapping) {
            return Ok(key);
        }
        let (_, key) = self.unwrap_stored(tenant, row).await?;
        let key = Arc::new(key);
        self.keys
            .remember(tenant, version, wrapping, Arc::clone(&key));
        Ok(key)
    }

    /// The key a `data_keys` row holds, unwrapped but not remembered, and the
    /// KEK the row names.
    async fn unwrap_stored(&self, tenant: &str, row: &AnyRow) -> Result<(Kek, DataKey)> {
        let Wrapping { kek, wrapped } = Wrapping::of(row)?;
        // Malformed input is `Decrypt`, as `crypto.rs` treats a bad v1 value.
        let wrapped = URL_SAFE_NO_PAD
            .decode(wrapped)
            .map_err(|_| StoreError::Decrypt)?;
        let key = self.keys.wrapper.unwrap(tenant, &kek, &wrapped).await?;
        Ok((kek, key))
    }

    /// Wraps again every data key, of all tenants, that a KEK other than
    /// [`KeyWrapper::current`] wrapped, so that the old KEK can go. A key under
    /// the KEK that `current` names is not visited, so `current` must name the
    /// new KEK for a pass to mean anything. After a master key changes, remove
    /// the previous master keys only once a pass in every process, with them
    /// configured, has wrapped nothing again: a process still on the old key
    /// may have made a key since the last pass. The server runs it before it
    /// serves when previous master keys are set, and, with or without them,
    /// shortly after it starts and then every hour, so a change of the KEK of
    /// your own wrapper is picked up within the hour.
    ///
    /// Each key is unwrapped with the KEK its row names, and wrapped. If `wrap`
    /// returns that same KEK, as it can while `current` lags, nothing is
    /// written or counted. Otherwise the new wrapping is unwrapped again to
    /// check that the wrapper reads it back, and one statement stores the new
    /// bytes and the KEK that `wrap` returned, only if the row still holds what
    /// was read. So passes in several processes, and a crash, leave each row
    /// with its old wrapping or a checked new one. The key does not change.
    ///
    /// A key that [`StoreError::Decrypt`] says can never be unwrapped is left
    /// as it is and counted as unreadable. Any other error ends the pass, with
    /// the keys done already wrapped again and the rest as they were.
    ///
    /// # Errors
    ///
    /// Returns an error if the database fails, if the wrapper fails other than
    /// with [`StoreError::Decrypt`] for a stored key, or if it does not read
    /// back the key it wrapped.
    pub async fn rewrap_data_keys(&self) -> Result<Rewrapped> {
        let current = self.keys.wrapper.current();
        let mut report = Rewrapped::default();
        // Paged by primary key, so rows wrapped meanwhile are not visited twice.
        let mut after = (String::new(), i64::MIN);
        loop {
            let rows = sqlx::query(
                "SELECT tenant, version, provider, kek_id, kek_version, wrapped FROM data_keys \
                 WHERE (tenant, version) > ($1, $2) \
                 AND NOT (provider = $3 AND kek_id = $4 AND kek_version = $5) \
                 AND NOT (provider = $7 AND wrapped = '') \
                 ORDER BY tenant, version LIMIT $6",
            )
            .bind(&after.0)
            .bind(after.1)
            .bind(&current.provider)
            .bind(&current.id)
            .bind(current.version)
            .bind(REWRAP_BATCH)
            .bind(DESTROYED_PROVIDER)
            .fetch_all(&self.pool)
            .await?;
            let Some(last) = rows.last() else {
                return Ok(report);
            };
            after = (last.try_get("tenant")?, last.try_get("version")?);
            for row in &rows {
                self.rewrap_row(row, &mut report).await?;
            }
        }
    }

    /// Destroys the data keys of the store's tenant, so that nothing sealed
    /// under them opens again, through the database or from a logical dump
    /// taken afterwards: the passwords, webhook secrets, filter patterns,
    /// events and tokens of the tenant's accounts, and the sign-ins in
    /// progress started for it.
    ///
    /// In one transaction, which on PostgreSQL locks `data_keys` against other
    /// writes, it deletes the tenant's keys and leaves rows that hold none
    /// (provider `destroyed`): at version 1, one above each version deleted,
    /// and at the highest version, which marks the tenant destroyed. It returns
    /// how many keys it deleted, 0 when there were none or they were destroyed
    /// before. It is safe to call again, and to call again after restoring a
    /// backup from before.
    ///
    /// From then on [`Store::data_key`], [`Store::data_key_version`], every
    /// read of such a value, and every write that stores or reads a secret of
    /// the tenant answer [`StoreError::KeysDestroyed`]. Writes that touch no
    /// secret still work, among them [`Store::delete_account`]. No key is made
    /// for the tenant again, by this build or by one from before it, which
    /// can unwrap none of those rows and finds every version it could add
    /// taken. It asks the key wrapper nothing, so it works while a key service
    /// is sealed.
    ///
    /// Call it on a clone of the store that serves the tenant (such as
    /// [`Store::for_tenant`] on it): clones share one cache of keys, which
    /// forgets the tenant's at once. A store with a cache of its own (another
    /// process, or another `connect` or [`Store::with_key_wrapper`]) reads
    /// with the keys it holds until it next asks for one of the tenant's keys
    /// or restarts.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidInput`] for the default tenant, which holds
    /// every sign-in that no tenant started, and for a tenant that still has a
    /// value under the master key. [`Store::reencrypt`] moves each such value
    /// that a configured master key opens; for one that no key opens, delete
    /// the account that holds it (a sign-in in progress goes when it expires),
    /// then call this again. Returns [`StoreError::Database`] if a query
    /// fails. Nothing changes on an error.
    pub async fn destroy_data_keys(&self) -> Result<u64> {
        let tenant = self.tenant();
        if tenant == DEFAULT_TENANT {
            return Err(StoreError::InvalidInput(
                "the default tenant's data keys cannot be destroyed",
            ));
        }
        if self.holds_master_key_value(tenant).await? {
            return Err(StoreError::InvalidInput(
                "the tenant still has values under the master key; move them with \
                 Store::reencrypt, or delete the accounts that hold them",
            ));
        }
        let mut tx = self.begin_write().await?;
        // Other writes to `data_keys` wait until the commit and reads go on, so
        // no key lands between the DELETE and the COMMIT; the lock conflicts
        // with itself, so two destroys run one after the other. On SQLite the
        // write lock that the transaction takes as it begins does the same.
        if tx.backend_name() != "SQLite" {
            sqlx::query("LOCK TABLE data_keys IN SHARE ROW EXCLUSIVE MODE")
                .execute(&mut *tx)
                .await?;
        }
        // First, so that `RETURNING` counts the keys destroyed and gives the
        // versions the mark needs.
        let deleted = delete_keys_of(&mut *tx, tenant).await?;
        // Every version a store that read the rows before the commit could add
        // (1, or one above what it read), and the newest, which every store sees first.
        let mark: BTreeSet<i64> = std::iter::once(1)
            .chain(deleted.iter().map(|version| version.saturating_add(1)))
            .chain(std::iter::once(DESTROYED_VERSION))
            .collect();
        let at = now();
        for version in mark {
            // `DO UPDATE` is a second guard: without the lock it would overwrite
            // as dead a key that landed at a mark version after the DELETE.
            sqlx::query(
                "INSERT INTO data_keys \
                 (tenant, version, provider, kek_id, kek_version, wrapped, created_at) \
                 VALUES ($1, $2, $3, '', 0, '', $4) ON CONFLICT (tenant, version) DO UPDATE \
                 SET provider = excluded.provider, kek_id = excluded.kek_id, \
                 kek_version = excluded.kek_version, wrapped = excluded.wrapped",
            )
            .bind(tenant)
            .bind(version)
            .bind(DESTROYED_PROVIDER)
            .bind(at)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        self.keys.forget(tenant);
        let destroyed = u64::try_from(deleted.len()).unwrap_or(u64::MAX);
        tracing::info!(tenant, destroyed, "destroyed the data keys of a tenant");
        Ok(destroyed)
    }

    async fn rewrap_row(&self, row: &AnyRow, report: &mut Rewrapped) -> Result<()> {
        let tenant: String = row.try_get("tenant")?;
        let version: i64 = row.try_get("version")?;
        let (recorded, key) = match self.unwrap_stored(&tenant, row).await {
            Ok(found) => found,
            Err(StoreError::Decrypt) => {
                tracing::info!(
                    tenant,
                    version,
                    "no configured key unwraps this data key; it is left as it is"
                );
                report.unreadable += 1;
                return Ok(());
            }
            Err(err) => return Err(err),
        };
        let fresh = self.keys.wrapper.wrap(&tenant, &key).await?;
        // `current` can lag behind the key service: a key already at the KEK
        // that `wrap` returns has nothing to change.
        if fresh.kek == recorded {
            return Ok(());
        }
        // The old wrapping is replaced only by one that reads back to the key.
        let back = self
            .keys
            .wrapper
            .unwrap(&tenant, &fresh.kek, &fresh.bytes)
            .await;
        match back {
            Ok(back) if back.same_as(&key) => {}
            Ok(_) | Err(StoreError::Decrypt) => {
                let message = "the wrapper does not unwrap the data key it just wrapped";
                return Err(StoreError::KeyWrap(message.to_owned()));
            }
            Err(err) => return Err(err),
        }
        // Only if the row is still what was read: the loser of two passes changes nothing.
        report.rewrapped += sqlx::query(
            "UPDATE data_keys SET provider = $1, kek_id = $2, kek_version = $3, wrapped = $4 \
             WHERE tenant = $5 AND version = $6 \
             AND provider = $7 AND kek_id = $8 AND kek_version = $9 AND wrapped = $10",
        )
        .bind(&fresh.kek.provider)
        .bind(&fresh.kek.id)
        .bind(fresh.kek.version)
        .bind(URL_SAFE_NO_PAD.encode(&fresh.bytes))
        .bind(&tenant)
        .bind(version)
        .bind(&recorded.provider)
        .bind(&recorded.id)
        .bind(recorded.version)
        .bind(row.try_get::<String, _>("wrapped")?)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(())
    }

    /// Opens a stored value of either format. `tenant`, `slot` and `row_key`
    /// say where it is stored: the tenant of its row, which is not always the
    /// store's, the column, and the row's key. A v2 value is bound to all
    /// three and opens with the data key it names. A v1 value is bound to
    /// `legacy_context` and opens with the master key, as it always did.
    ///
    /// Only [`StoreError::Decrypt`] means that the value is unreadable for
    /// good: it is malformed, bound to another tenant, column or row, or its
    /// data key is missing or can never be unwrapped. Any other error, such
    /// as a wrapper that does not answer, may pass on a later call, and a
    /// caller must not treat it as unreadable.
    ///
    /// A value in a format newer than this version reads is not unreadable
    /// either: it is [`StoreError::NewerFormat`], whichever column it is in.
    pub(crate) async fn open_value(
        &self,
        tenant: &str,
        slot: Slot,
        row_key: &str,
        legacy_context: &str,
        stored: &str,
    ) -> Result<Zeroizing<Vec<u8>>> {
        match Stored::parse(stored)? {
            Stored::V1 => self
                .cipher
                .open(legacy_context, stored)
                .map(|(plaintext, _)| plaintext),
            Stored::V2 { version, blob } => {
                let key = self.key_of(tenant, version).await?;
                open_v2(&key, &v2_context(tenant, slot, row_key), blob)
            }
        }
    }

    /// As [`Store::open_value`], for a value that is text.
    pub(crate) async fn open_secret(
        &self,
        tenant: &str,
        slot: Slot,
        row_key: &str,
        legacy_context: &str,
        stored: &str,
    ) -> Result<SecretString> {
        let plaintext = self
            .open_value(tenant, slot, row_key, legacy_context, stored)
            .await?;
        let text = std::str::from_utf8(&plaintext).map_err(|_| StoreError::Decrypt)?;
        Ok(SecretString::from(text.to_owned()))
    }

    /// A [`Sealer`] for the rows of `tenant`, the tenant of the row that is
    /// written, which is not always this store's, with the key that
    /// [`Store::data_key`] finds or makes for it.
    ///
    /// Call it before a write opens its transaction: it reads `data_keys` and
    /// may insert a key or delete one found beside a destroyed tenant's mark,
    /// which inside the transaction would wait for the connection that the
    /// transaction holds (a pool of one) or for its write lock (SQLite).
    /// Sealing with the result needs neither. A wrapper that does not answer is
    /// [`StoreError::KeyWrap`]: the write stops, nothing is stored. It is
    /// [`StoreError::KeysDestroyed`] if the tenant's keys were destroyed, and
    /// nothing is stored.
    pub(crate) async fn sealer(&self, tenant: &str) -> Result<Sealer> {
        let (version, key) = self.newest_key_of(tenant).await?;
        Ok(Sealer {
            tenant: tenant.to_owned(),
            version,
            key,
        })
    }
}

/// Seals values for the rows of one tenant under a data key, as `v2.` text.
/// [`Store::sealer`] makes it, with the key already found, so that sealing does
/// not touch the database or the wrapper.
pub struct Sealer {
    tenant: String,
    version: i64,
    key: Arc<DataKey>,
}

impl Sealer {
    /// `plaintext` sealed for the row `row_key` of the column `slot`, bound to
    /// the tenant, the column and the row, as [`Store::open_value`] reads it.
    pub fn seal(&self, slot: Slot, row_key: &str, plaintext: &[u8]) -> Result<String> {
        let context = v2_context(&self.tenant, slot, row_key);
        seal_v2(&self.key, self.version, &context, plaintext)
    }

    /// As [`Sealer::seal`], for a value that is text.
    pub fn seal_secret(&self, slot: Slot, row_key: &str, secret: &SecretString) -> Result<String> {
        self.seal(slot, row_key, secret.expose_secret().as_bytes())
    }
}
