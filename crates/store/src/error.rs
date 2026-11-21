//! The store's error type.

/// Convenient result alias for this crate.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Errors returned by the store. They never contain secrets.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The database rejected a query or could not be reached.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Applying schema migrations failed.
    #[error("database migration failed: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),

    /// Migrations this build has are not applied yet, and connecting was
    /// told not to apply them.
    #[error("the database is missing migrations {}", format_versions(.0))]
    PendingMigrations(Vec<i64>),

    /// The database records a storage level above the newest this build
    /// reads, so a newer version used it.
    #[error(
        "the database is at storage level {database} and this version reads up to level {build}; \
         run the newer release that raised it"
    )]
    StorageLevelAhead {
        /// The level the database records.
        database: i64,
        /// The newest level this build reads, [`crate::STORAGE_LEVEL_READS`].
        build: i64,
    },

    /// The master key is malformed.
    #[error("invalid master key: {0}")]
    InvalidKey(&'static str),

    /// Encryption or decryption failed, for example because the data was
    /// encrypted with a different master key.
    #[error("could not decrypt stored credentials (wrong master key?)")]
    Decrypt,

    /// A stored value is in a format newer than this version reads: its text
    /// starts `v<number>.` with a number above the newest format this version
    /// knows. A newer version may have written it, and one that reads the
    /// format may open it, so this is not unreadable for good: a caller does not
    /// skip, overwrite or remove the value because of this error. A value that
    /// is malformed or that no configured key opens is [`StoreError::Decrypt`]
    /// instead.
    #[error("a stored value is in a newer format than this version reads")]
    NewerFormat,

    /// The key wrapper failed in a way a later attempt may get past, such as
    /// a key service that does not answer or is sealed. A data key that can
    /// never be unwrapped is [`StoreError::Decrypt`] instead. The store passes
    /// over no data key and makes none on this error, whereas `Decrypt` for
    /// every key of a tenant makes a new one.
    #[error("the key wrapper failed: {0}")]
    KeyWrap(String),

    /// The tenant's data keys were destroyed
    /// ([`crate::Store::destroy_data_keys`]): its `data_keys` rows hold no key
    /// and mark it destroyed. A value under them never opens again, and no
    /// secret is stored for the tenant any more. It is final, but it is not
    /// [`StoreError::Decrypt`]: a caller does not skip, overwrite or remove a
    /// value because of it.
    #[error("the data keys of this tenant were destroyed")]
    KeysDestroyed,

    /// Generating random bytes failed.
    #[error("the system random number generator failed")]
    Random,

    /// The email address belongs to a different account: one created with
    /// another provider, or another user at the same provider.
    #[error("the address is already connected another way")]
    AccountConflict,

    /// The account was deleted before this write finished, so nothing was
    /// written. Signing in again adds the account anew.
    #[error("the account was deleted before this write finished")]
    AccountDeleted,

    /// A value was rejected before reaching the database.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),

    /// An outbox limit is outside the range this server allows.
    ///
    /// The message names the allowed range and the rejected value. It does
    /// not contain secrets, URLs, or ciphertext.
    #[error("{0}")]
    OutboxLimit(String),
}

fn format_versions(versions: &[i64]) -> String {
    versions
        .iter()
        .map(|version| format!("{version:04}"))
        .collect::<Vec<_>>()
        .join(", ")
}
