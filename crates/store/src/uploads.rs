//! One-time uploads: a file an agent sends to postkeep to attach to one message.
//!
//! The file's bytes wait in the operator's bucket, cut into pieces that
//! [`seal_piece`] seals under the upload's own key; its row here holds who may
//! attach it, what the bounds count and that key, never a byte of the file. The
//! id and the token are stored as hashes; the key and the file's SHA-256 are
//! `v2.` values under the data key of the mailbox's tenant, set once the file is
//! in and cleared when the upload is used. An upload is waiting (not claimed),
//! arriving (claimed), stored (its key set) or used, until its row goes.

use std::time::Duration;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{AeadInOut, KeyInit, Nonce};
use serde_json::json;
use sqlx::Row;

use crate::accounts::AccountId;
use crate::crypto::{Slot, hash_secret};
use crate::db::{before, expires_in, now};
use crate::envelope::{DataKey, Sealer};
use crate::{Result, Store, StoreError};

/// The column of an upload's sealed key.
pub const KEY_SLOT: Slot = Slot::new("uploads", "key_ciphertext");

/// The associated data of a `v1.` key. No version stored one, so no value is
/// bound to it; the readers and the sweep still ask for one.
pub fn key_context(id_hash: &str) -> String {
    format!("upload/key/{id_hash}")
}

/// The column of an upload's sealed SHA-256.
pub const DIGEST_SLOT: Slot = Slot::new("uploads", "digest_ciphertext");

/// The associated data of a `v1.` digest, which no version stored either.
pub fn digest_context(id_hash: &str) -> String {
    format!("upload/digest/{id_hash}")
}

/// The one `SET` clause that uses an upload up, `$1` being the time: it can't
/// be attached or written again, and its key and digest are cleared.
macro_rules! used {
    () => {
        "used_at = $1, key_ciphertext = NULL, digest_ciphertext = NULL"
    };
}

/// The length of the tag that [`seal_piece`] adds to a piece.
pub const PIECE_TAG: usize = 16;

/// The associated data of every piece, which names the pieces' format.
const PIECE_CONTEXT: &[u8] = b"postkeep/upload-piece/1";

/// Who an upload is for: only this mailbox, principal and app attach it.
#[derive(Debug, Clone, Copy)]
pub struct UploadOwner<'a> {
    /// The mailbox.
    pub account: &'a AccountId,
    /// The caller's principal.
    pub principal: &'a str,
    /// The caller's app (`client_id`).
    pub app: &'a str,
}

/// What a claim may not pass, per tenant and for the whole database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadBounds {
    /// Uploads of one tenant arriving at once.
    pub tenant_arriving: i64,
    /// Bytes the claimed uploads of one tenant may count.
    pub tenant_stored: i64,
    /// Uploads arriving at once in the whole database.
    pub server_arriving: i64,
    /// Bytes all claimed uploads may count.
    pub server_stored: i64,
    /// The least an upload counts toward the stored bounds.
    pub least: i64,
    /// How long a claim counts as arriving.
    pub window: Duration,
}

/// A claimed upload, which takes its file under `key` as pieces named after
/// `object`. Only this value holds the key until [`Store::finish_upload`].
pub struct Claimed {
    id_hash: String,
    sealer: Sealer,
    key: DataKey,
    object: String,
    reserved: i64,
    expires_at: i64,
}

impl Claimed {
    /// The key the file's pieces are sealed under.
    #[must_use]
    pub const fn key(&self) -> &DataKey {
        &self.key
    }

    /// The name its pieces are stored under.
    #[must_use]
    pub fn object(&self) -> &str {
        &self.object
    }

    /// When the upload's hour ends (Unix seconds).
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl std::fmt::Debug for Claimed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Claimed")
            .field("reserved", &self.reserved)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Why a claim took nothing. The token still works after `Tenant` and `Server`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimRefused {
    /// No waiting upload has this token: unknown, claimed, used or ended.
    Unknown,
    /// The tenant's bounds are reached.
    Tenant,
    /// The bounds of the whole database are reached.
    Server,
}

/// What a caller finds for an upload id.
#[derive(Debug)]
pub enum UploadLookup {
    /// The file is in.
    Stored {
        /// The name its pieces are stored under.
        object: String,
        /// The key its pieces are sealed under.
        key: DataKey,
        /// The file's SHA-256, taken as it arrived.
        digest: [u8; 32],
        /// The file's size in bytes.
        size: i64,
        /// When the upload's hour ends (Unix seconds).
        expires_at: i64,
    },
    /// Not sent yet, or arriving within its window.
    Arriving,
    /// Unknown to this caller, used, ended, or claimed and never finished.
    Missing,
}

/// A used upload, whose pieces are to be deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Used {
    id_hash: String,
    /// The name its pieces are stored under.
    pub object: String,
    /// The size its pieces are counted from: the file's, or the reservation of
    /// one that never finished.
    pub size: i64,
}

fn id_hash(app: &str, id: &str) -> String {
    hash_secret(&json!([app, id]).to_string())
}

fn piece_cipher(key: &DataKey, number: u64) -> (Aes256Gcm, Nonce<Aes256Gcm>) {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&number.to_be_bytes());
    (
        Aes256Gcm::new(key.expose().into()),
        Nonce::<Aes256Gcm>::from(nonce),
    )
}

/// Seals piece `number` of a file, counted from 0, in place under `key`: the
/// piece's number is its nonce, so each number is sealed once. `buffer` gains
/// the [`PIECE_TAG`]; with that room reserved it is not moved.
///
/// # Errors
///
/// Returns [`StoreError::Decrypt`] if the piece is too long to seal.
pub fn seal_piece(key: &DataKey, number: u64, buffer: &mut Vec<u8>) -> Result<()> {
    let (cipher, nonce) = piece_cipher(key, number);
    cipher
        .encrypt_in_place(&nonce, PIECE_CONTEXT, buffer)
        .map_err(|_| StoreError::Decrypt)
}

/// Opens piece `number` of a file in place, leaving `buffer` without its tag.
///
/// # Errors
///
/// Returns [`StoreError::Decrypt`] for a piece sealed under another key or
/// number, changed, or cut short.
pub fn open_piece(key: &DataKey, number: u64, buffer: &mut Vec<u8>) -> Result<()> {
    let (cipher, nonce) = piece_cipher(key, number);
    cipher
        .decrypt_in_place(&nonce, PIECE_CONTEXT, buffer)
        .map_err(|_| StoreError::Decrypt)
}

impl Store {
    /// Makes a waiting upload for `owner` with a random `id` and `token`,
    /// returning its expiry (Unix seconds), or `None` when `most` uploads of
    /// the mailbox's tenant already wait for their files. This is a soft cap:
    /// concurrent inserts can pass it.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn create_upload(
        &self,
        owner: UploadOwner<'_>,
        id: &str,
        token: &str,
        ttl: Duration,
        most: i64,
    ) -> Result<Option<i64>> {
        let waiting: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM uploads u JOIN accounts a ON a.id = u.account_id \
             WHERE a.tenant = (SELECT tenant FROM accounts WHERE id = $1) \
             AND u.claimed_at IS NULL AND u.expires_at > $2",
        )
        .bind(&owner.account.0)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        if waiting >= most {
            return Ok(None);
        }
        let expires_at = expires_in(ttl);
        sqlx::query(
            "INSERT INTO uploads \
             (id_hash, token_hash, account_id, principal, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id_hash(owner.app, id))
        .bind(hash_secret(token))
        .bind(&owner.account.0)
        .bind(owner.principal)
        .bind(now())
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(Some(expires_at))
    }

    /// Claims the waiting upload of `token` for one attempt to take its file,
    /// stored as pieces named after `object`, counting `reserve` bytes toward
    /// the stored bounds until the file's size is known.
    ///
    /// The bounds are checked and the upload claimed in one write transaction,
    /// which on PostgreSQL first locks `uploads` against other writes, so two
    /// claims can't both pass a bound and a token is claimed once. Each upload
    /// counts at least `bounds.least`; arriving ones count for `bounds.window`
    /// from their claim. A refusal changes nothing. The claim's key is made
    /// here and stored only by [`Store::finish_upload`].
    ///
    /// # Errors
    ///
    /// Returns an error if a query, the key's tenant or the random source fails.
    pub async fn claim_upload(
        &self,
        token: &str,
        object: &str,
        reserve: i64,
        bounds: UploadBounds,
    ) -> Result<Result<Claimed, ClaimRefused>> {
        let row = sqlx::query(
            "SELECT u.id_hash, u.expires_at, a.tenant FROM uploads u \
             JOIN accounts a ON a.id = u.account_id \
             WHERE u.token_hash = $1 AND u.claimed_at IS NULL AND u.expires_at > $2",
        )
        .bind(hash_secret(token))
        .bind(now())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(Err(ClaimRefused::Unknown));
        };
        let id_hash: String = row.try_get("id_hash")?;
        let expires_at: i64 = row.try_get("expires_at")?;
        let tenant: String = row.try_get("tenant")?;
        // Found, or made, before the transaction opens, as an event's key is.
        let sealer = self.sealer(&tenant).await?;
        let at = now();
        let counted = reserve.max(bounds.least);
        let mut tx = self.begin_write().await?;
        if tx.backend_name() != "SQLite" {
            sqlx::query("LOCK TABLE uploads IN SHARE ROW EXCLUSIVE MODE")
                .execute(&mut *tx)
                .await?;
        }
        let totals = sqlx::query(
            "SELECT \
             CAST(COALESCE(SUM(CASE WHEN a.tenant = $1 AND u.key_ciphertext IS NULL \
             AND u.used_at IS NULL AND u.claimed_at > $2 THEN 1 ELSE 0 END), 0) AS BIGINT) AS ta, \
             CAST(COALESCE(SUM(CASE WHEN a.tenant <> $1 THEN 0 \
             WHEN COALESCE(u.size, u.reserved) < $3 THEN $3 \
             ELSE COALESCE(u.size, u.reserved) END), 0) AS BIGINT) AS ts, \
             CAST(COALESCE(SUM(CASE WHEN u.key_ciphertext IS NULL AND u.used_at IS NULL \
             AND u.claimed_at > $2 THEN 1 ELSE 0 END), 0) AS BIGINT) AS sa, \
             CAST(COALESCE(SUM(CASE WHEN COALESCE(u.size, u.reserved) < $3 THEN $3 \
             ELSE COALESCE(u.size, u.reserved) END), 0) AS BIGINT) AS ss \
             FROM uploads u JOIN accounts a ON a.id = u.account_id \
             WHERE u.claimed_at IS NOT NULL",
        )
        .bind(&tenant)
        .bind(before(at, bounds.window))
        .bind(bounds.least)
        .fetch_one(&mut *tx)
        .await?;
        let total = |name: &str| totals.try_get::<i64, _>(name);
        let refused = if total("ta")? >= bounds.tenant_arriving
            || total("ts")? + counted > bounds.tenant_stored
        {
            Some(ClaimRefused::Tenant)
        } else if total("sa")? >= bounds.server_arriving
            || total("ss")? + counted > bounds.server_stored
        {
            Some(ClaimRefused::Server)
        } else {
            None
        };
        let claimed = if refused.is_none() {
            sqlx::query(
                "UPDATE uploads SET claimed_at = $1, reserved = $2, object = $3 \
                 WHERE id_hash = $4 AND claimed_at IS NULL AND expires_at > $1",
            )
            .bind(at)
            .bind(reserve)
            .bind(object)
            .bind(&id_hash)
            .execute(&mut *tx)
            .await?
            .rows_affected()
        } else {
            0
        };
        if claimed == 0 {
            tx.rollback().await?;
            return Ok(Err(refused.unwrap_or(ClaimRefused::Unknown)));
        }
        tx.commit().await?;
        Ok(Ok(Claimed {
            id_hash,
            sealer,
            key: DataKey::generate()?,
            object: object.to_owned(),
            reserved: reserve,
            expires_at,
        }))
    }

    /// Stores the key and SHA-256 of a claimed upload whose `size` bytes are
    /// all in the bucket, sealed for its row, so that it can be attached.
    /// Returns `false` when the upload was used meanwhile, by the cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error if sealing or the query fails.
    pub async fn finish_upload(
        &self,
        claimed: &Claimed,
        size: i64,
        digest: &[u8; 32],
    ) -> Result<bool> {
        let row = &claimed.id_hash;
        let key = claimed.sealer.seal(KEY_SLOT, row, claimed.key.expose())?;
        let digest = claimed.sealer.seal(DIGEST_SLOT, row, digest)?;
        let done = sqlx::query(
            "UPDATE uploads SET size = $1, key_ciphertext = $2, digest_ciphertext = $3 \
             WHERE id_hash = $4 AND object = $5 AND used_at IS NULL AND key_ciphertext IS NULL",
        )
        .bind(size)
        .bind(key)
        .bind(digest)
        .bind(row)
        .bind(&claimed.object)
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected() == 1)
    }

    /// Uses up a claimed upload whose file stopped arriving, so its token
    /// takes nothing more, and returns its pieces to delete.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn use_attempt(&self, claimed: &Claimed) -> Result<Used> {
        sqlx::query(concat!(
            "UPDATE uploads SET ",
            used!(),
            " WHERE id_hash = $2 AND used_at IS NULL"
        ))
        .bind(now())
        .bind(&claimed.id_hash)
        .execute(&self.pool)
        .await?;
        Ok(Used {
            id_hash: claimed.id_hash.clone(),
            object: claimed.object.clone(),
            size: claimed.reserved,
        })
    }

    /// The upload `id` of `owner`, with its key and digest opened once its
    /// file is in. An upload claimed longer than `window` ago whose file never
    /// came is missing, as are used and ended ones.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails, and [`StoreError::Decrypt`] if the
    /// key or digest does not open.
    pub async fn upload_for(
        &self,
        owner: UploadOwner<'_>,
        id: &str,
        window: Duration,
    ) -> Result<UploadLookup> {
        let id_hash = id_hash(owner.app, id);
        let at = now();
        let row = sqlx::query(
            "SELECT u.object, u.size, u.key_ciphertext, u.digest_ciphertext, u.claimed_at, \
             u.expires_at, a.tenant FROM uploads u JOIN accounts a ON a.id = u.account_id \
             WHERE u.id_hash = $1 AND u.account_id = $2 AND u.principal = $3 \
             AND u.used_at IS NULL AND u.expires_at > $4",
        )
        .bind(&id_hash)
        .bind(&owner.account.0)
        .bind(owner.principal)
        .bind(at)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(UploadLookup::Missing);
        };
        let (Some(key), Some(digest), Some(size)) = (
            row.try_get::<Option<String>, _>("key_ciphertext")?,
            row.try_get::<Option<String>, _>("digest_ciphertext")?,
            row.try_get::<Option<i64>, _>("size")?,
        ) else {
            let claimed: Option<i64> = row.try_get("claimed_at")?;
            let arriving = claimed.is_none_or(|claimed| claimed > before(at, window));
            return Ok(if arriving {
                UploadLookup::Arriving
            } else {
                UploadLookup::Missing
            });
        };
        let tenant: String = row.try_get("tenant")?;
        let open = async |slot, context: String, stored: &str| {
            self.open_value(&tenant, slot, &id_hash, &context, stored)
                .await
        };
        let key = open(KEY_SLOT, key_context(&id_hash), &key).await?;
        let digest = open(DIGEST_SLOT, digest_context(&id_hash), &digest).await?;
        Ok(UploadLookup::Stored {
            object: row
                .try_get::<Option<String>, _>("object")?
                .unwrap_or_default(),
            key: DataKey::from_bytes(&key).map_err(|_| StoreError::Decrypt)?,
            digest: digest
                .as_slice()
                .try_into()
                .map_err(|_| StoreError::Decrypt)?,
            size,
            expires_at: row.try_get("expires_at")?,
        })
    }

    /// Uses up every stored upload `ids` names for `owner`, all or none, in
    /// one write transaction, and returns them to have their pieces deleted.
    /// When one is not a stored upload of `owner` any more, nothing changes
    /// and its place in `ids` comes back instead. Give each id once.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails; nothing is used then.
    pub async fn use_uploads(
        &self,
        owner: UploadOwner<'_>,
        ids: &[&str],
    ) -> Result<Result<Vec<Used>, usize>> {
        let at = now();
        let mut used = Vec::with_capacity(ids.len());
        let mut tx = self.begin_write().await?;
        for (place, id) in ids.iter().enumerate() {
            let id_hash = id_hash(owner.app, id);
            let row = sqlx::query(concat!(
                "UPDATE uploads SET ",
                used!(),
                " WHERE id_hash = $2 AND account_id = $3 AND principal = $4 \
                 AND used_at IS NULL AND key_ciphertext IS NOT NULL AND expires_at > $1 \
                 RETURNING object, size"
            ))
            .bind(at)
            .bind(&id_hash)
            .bind(&owner.account.0)
            .bind(owner.principal)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(row) = row else {
                tx.rollback().await?;
                return Ok(Err(place));
            };
            used.push(Used {
                id_hash,
                object: row.try_get("object")?,
                size: row.try_get("size")?,
            });
        }
        tx.commit().await?;
        Ok(Ok(used))
    }

    /// Deletes the row of a used upload once its pieces are gone.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn forget_upload(&self, used: &Used) -> Result<()> {
        sqlx::query("DELETE FROM uploads WHERE id_hash = $1 AND used_at IS NOT NULL")
            .bind(&used.id_hash)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The cleanup's statements: uses up stored uploads past their hour and
    /// arriving ones claimed longer than `window` ago, deletes waiting ones past
    /// their hour, which have no pieces, and returns up to `most` used uploads,
    /// the longest used first, to have their pieces deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn uploads_to_clean(&self, window: Duration, most: i64) -> Result<Vec<Used>> {
        let at = now();
        sqlx::query(concat!(
            "UPDATE uploads SET ",
            used!(),
            " WHERE used_at IS NULL AND ((key_ciphertext IS NOT NULL AND expires_at <= $1) \
             OR (key_ciphertext IS NULL AND claimed_at <= $2))"
        ))
        .bind(at)
        .bind(before(at, window))
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM uploads WHERE claimed_at IS NULL AND expires_at <= $1")
            .bind(at)
            .execute(&self.pool)
            .await?;
        let rows = sqlx::query(
            "SELECT id_hash, object, COALESCE(size, reserved) AS counted FROM uploads \
             WHERE used_at IS NOT NULL ORDER BY used_at, id_hash LIMIT $1",
        )
        .bind(most)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(Used {
                    id_hash: row.try_get("id_hash")?,
                    object: row
                        .try_get::<Option<String>, _>("object")?
                        .unwrap_or_default(),
                    size: row
                        .try_get::<Option<i64>, _>("counted")?
                        .unwrap_or_default(),
                })
            })
            .collect()
    }
}
