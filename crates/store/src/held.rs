//! Single-use holds for calls an embedding asks the user to confirm.

use std::time::Duration;

use serde_json::{Value, json};
use sqlx::Row;

use crate::crypto::{constant_time_eq, hash_secret};
use crate::db::expires_in;
use crate::{AccountId, Result, Store, now};

/// A call held for one caller, app and mailbox. Arguments are parsed JSON;
/// the store keeps only a fingerprint and never the message or the raw id.
#[derive(Clone, Copy)]
pub struct HeldSend<'a> {
    /// The mailbox the call acts on.
    pub account: &'a AccountId,
    /// The caller's principal.
    pub principal: &'a str,
    /// The caller's app (`client_id`).
    pub app: &'a str,
    /// A random, high-entropy id returned only to the caller.
    pub id: &'a str,
    /// The tool that holds and takes the call.
    pub tool: &'a str,
    /// The call's arguments, without its mailbox selector or hold handle.
    pub arguments: &'a Value,
}

/// Whether a held call was taken for sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeldSendMatch {
    /// Taken once; only this caller may now send it.
    Matched,
    /// The arguments differ. The hold stays for another try.
    Differs,
    /// No live hold for this caller, app and mailbox, or already taken.
    Missing,
}

fn hashes(send: HeldSend<'_>) -> (String, String) {
    let id = hash_secret(&json!([send.app, send.id]).to_string());
    let tag = format!("postkeep/held-send/v1/{}", send.tool);
    let fingerprint = hash_secret(&json!([tag, send.id, send.arguments]).to_string());
    (id, fingerprint)
}

impl Store {
    /// Holds `send` for `ttl`, returning its expiry (Unix seconds), or
    /// `None` when `most` unexpired holds already wait for this principal
    /// on this mailbox. This is a soft cap: concurrent inserts can pass it.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn hold_send(
        &self,
        send: HeldSend<'_>,
        ttl: Duration,
        most: i64,
    ) -> Result<Option<i64>> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM held_sends \
             WHERE account_id = $1 AND principal = $2 AND expires_at > $3",
        )
        .bind(&send.account.0)
        .bind(send.principal)
        .bind(now())
        .fetch_one(&self.pool)
        .await?;
        if count >= most {
            return Ok(None);
        }
        let (id, fingerprint) = hashes(send);
        let expires_at = expires_in(ttl);
        sqlx::query(
            "INSERT INTO held_sends \
             (id_hash, account_id, principal, fingerprint, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(&send.account.0)
        .bind(send.principal)
        .bind(fingerprint)
        .bind(now())
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(Some(expires_at))
    }

    /// Takes a live hold only if its caller, app, mailbox, tool and
    /// arguments match. A mismatch leaves it; whoever deletes a matching
    /// row owns the send, so two concurrent takes cannot both match.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn take_held_send(&self, send: HeldSend<'_>) -> Result<HeldSendMatch> {
        let (id, fingerprint) = hashes(send);
        let row = sqlx::query(
            "SELECT fingerprint FROM held_sends \
             WHERE id_hash = $1 AND account_id = $2 AND principal = $3 AND expires_at > $4",
        )
        .bind(&id)
        .bind(&send.account.0)
        .bind(send.principal)
        .bind(now())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(HeldSendMatch::Missing);
        };
        let stored: String = row.try_get("fingerprint")?;
        if !constant_time_eq(stored, fingerprint) {
            return Ok(HeldSendMatch::Differs);
        }
        let taken = sqlx::query("DELETE FROM held_sends WHERE id_hash = $1 AND expires_at > $2")
            .bind(id)
            .bind(now())
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(if taken == 0 {
            HeldSendMatch::Missing
        } else {
            HeldSendMatch::Matched
        })
    }
}
