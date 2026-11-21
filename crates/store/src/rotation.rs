//! The sweep: moving stored secrets from the master key to data keys.

use std::collections::HashMap;

use sqlx::any::AnyRow;
use sqlx::{AssertSqlSafe, Row};

use crate::accounts::AccountId;
use crate::crypto::{FORMAT_V1, FORMAT_V2, PASSWORD_SLOT, Slot, Stored, password_context};
use crate::envelope::Sealer;
use crate::{DEFAULT_TENANT, Result, Store, StoreError, events, filters, upstream, webhooks};

/// How many rows [`Store::reencrypt`] reads at a time. A page is all that is
/// held in memory. An event payload describes one message, the newest of at
/// most 50 that it covers, so a page of events stays small.
const BATCH: i64 = 100;

/// The outcome of [`Store::reencrypt`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Reencrypted {
    /// Values that were under the master key and are now sealed under a data
    /// key. Called `updated` since the sweep re-encrypted between master keys.
    pub updated: u64,
    /// Values that already were in the data-key format. The database counts
    /// the texts that start with `v2.` when the pass reaches their column, and
    /// the pass never reads them. A text that starts that way but is not a
    /// valid value is counted here too, not as `unreadable`; opening it still
    /// fails with [`StoreError::Decrypt`].
    pub already_v2: u64,
    /// Values that no configured key can decrypt, and those of a tenant whose
    /// data keys were destroyed. They are left alone; the affected users have
    /// to sign in again.
    ///
    /// A value in a format newer than this version reads is not one of them,
    /// and no field counts it: it is left alone too.
    pub unreadable: u64,
    /// Values that changed between being read and being replaced, so that the
    /// replacement was skipped. The next pass looks at them again.
    pub lost_races: u64,
}

/// What became of one value.
enum Outcome {
    Moved,
    Unreadable,
    Lost,
    /// In a format newer than this version reads: left as it is, and not
    /// counted, for a newer version may have written it.
    Newer,
}

/// An encrypted column, and where its associated data comes from.
struct Encrypted {
    slot: Slot,
    /// Unique key used for paging and for the update.
    key: &'static str,
    /// SQL for the row key that a v2 value is bound to.
    row_key: &'static str,
    /// SQL for the tenant of the row. A v2 value is bound to it; a sign-in
    /// that no tenant started has none, and is bound to the default tenant.
    tenant: &'static str,
    /// Whether a row with no tenant is the default tenant's (the sign-in
    /// columns). For the other columns the account gives the row its tenant;
    /// a row without one is left as it is and counted as unreadable.
    unowned_is_default: bool,
    /// Another column the context needs, if any.
    extra: &'static str,
    /// Extra condition for the rows to visit.
    filter: &'static str,
    /// The associated data of a v1 value, from the row key and the row.
    context: fn(&str, &AnyRow) -> Result<String>,
}

fn account_column(row: &AnyRow, name: &str) -> Result<AccountId> {
    Ok(AccountId(row.try_get(name)?))
}

/// The tenant of the account that owns a webhook, as the readers join it.
const WEBHOOK_TENANT: &str = "(SELECT a.tenant FROM accounts a WHERE a.id = webhooks.account_id)";
/// The tenant of the account that owns the tokens, as the readers join it.
const TOKEN_TENANT: &str =
    "(SELECT a.tenant FROM accounts a WHERE a.id = upstream_tokens.account_id)";
/// The tenant of the account that owns an event, as the readers join it.
const EVENT_TENANT: &str = "(SELECT a.tenant FROM accounts a WHERE a.id = mail_events.account_id)";
/// The tenant of the account that owns a filter rule, as the readers join it.
const FILTER_TENANT: &str =
    "(SELECT a.tenant FROM accounts a WHERE a.id = webhook_filter_rules.account_id)";

const COLUMNS: &[Encrypted] = &[
    Encrypted {
        slot: PASSWORD_SLOT,
        key: "id",
        row_key: "email",
        tenant: "tenant",
        unowned_is_default: false,
        extra: "",
        // OAuth accounts store no password.
        filter: "AND provider = 'imap'",
        context: |email, _| Ok(password_context(email)),
    },
    Encrypted {
        slot: webhooks::AUTH_SLOT,
        key: "account_id",
        row_key: "account_id",
        tenant: WEBHOOK_TENANT,
        unowned_is_default: false,
        extra: "",
        filter: "",
        context: |account, _| Ok(webhooks::auth_context(&AccountId(account.to_owned()))),
    },
    Encrypted {
        slot: webhooks::SECRET_SLOT,
        key: "account_id",
        row_key: "account_id",
        tenant: WEBHOOK_TENANT,
        unowned_is_default: false,
        extra: "",
        filter: "",
        context: |account, _| Ok(webhooks::secret_context(&AccountId(account.to_owned()))),
    },
    Encrypted {
        slot: upstream::REFRESH_SLOT,
        key: "account_id",
        row_key: "account_id",
        tenant: TOKEN_TENANT,
        unowned_is_default: false,
        extra: "",
        filter: "",
        context: |account, _| Ok(upstream::refresh_context(&AccountId(account.to_owned()))),
    },
    Encrypted {
        slot: upstream::ACCESS_SLOT,
        key: "account_id",
        row_key: "account_id",
        tenant: TOKEN_TENANT,
        unowned_is_default: false,
        extra: "",
        filter: "",
        context: |account, _| Ok(upstream::access_context(&AccountId(account.to_owned()))),
    },
    Encrypted {
        slot: upstream::VERIFIER_SLOT,
        key: "state_hash",
        row_key: "state_hash",
        tenant: "tenant",
        unowned_is_default: true,
        extra: "",
        filter: "",
        context: |state_hash, _| Ok(upstream::verifier_context(state_hash)),
    },
    Encrypted {
        slot: upstream::REQUEST_ID_SLOT,
        key: "state_hash",
        row_key: "state_hash",
        tenant: "tenant",
        unowned_is_default: true,
        extra: "",
        filter: "",
        context: |state_hash, _| Ok(upstream::request_id_context(state_hash)),
    },
    Encrypted {
        slot: upstream::CONTINUATION_SLOT,
        key: "state_hash",
        row_key: "state_hash",
        tenant: "tenant",
        unowned_is_default: true,
        extra: "",
        filter: "",
        context: |state_hash, _| Ok(upstream::continuation_context(state_hash)),
    },
    Encrypted {
        slot: events::PAYLOAD_SLOT,
        key: "id",
        row_key: "id",
        tenant: EVENT_TENANT,
        unowned_is_default: false,
        extra: "account_id",
        filter: "",
        context: |id, row| {
            Ok(events::payload_context(
                &account_column(row, "account_id")?,
                id,
            ))
        },
    },
    Encrypted {
        slot: filters::PATTERN_SLOT,
        key: "id",
        row_key: "id",
        tenant: FILTER_TENANT,
        unowned_is_default: false,
        extra: "",
        filter: "",
        // No earlier version stored a pattern, so no value is under the master key.
        context: |id, _| Ok(filters::pattern_context(id)),
    },
];

impl Store {
    /// Whether previous master keys are configured.
    #[must_use]
    pub fn rotating_keys(&self) -> bool {
        self.cipher.rotating()
    }

    /// The sweep: moves every stored secret that is still under the master key
    /// (IMAP passwords, webhook secrets, Microsoft and Google tokens, sign-ins
    /// in progress and stored events) to the data key of its row's tenant, as
    /// the writer of that column would have stored it. The master key that
    /// opens a value is the current one or a previous one, so this also ends a
    /// master-key rotation for those values. Safe to run repeatedly, in several
    /// processes at once, and while the server is serving.
    ///
    /// The server runs it before it serves when previous master keys are set,
    /// and, with or without them, shortly after it starts and then every hour;
    /// an embedding may call it at any time. Values already in
    /// the data-key format (`v2.`) are left as they are and never read: the
    /// database counts them as `already_v2` when the pass reaches their
    /// column. A text that starts with `v2.` is counted there whatever follows
    /// it, so one that is not a valid value is not `unreadable`; opening it
    /// fails with [`StoreError::Decrypt`]. [`Store::rewrap_data_keys`] is what
    /// lets a previous master key go for them. A value that no configured key
    /// opens is `unreadable` and is left as it is; each is named at `debug`
    /// level, since the server's pass repeats every hour. After a pass, a build
    /// from before data keys cannot read what it moved.
    ///
    /// A value in a format newer than this version reads (`v3.` and up) is not
    /// unreadable, for a newer version may have written it: it is left as it
    /// is, a warning names it, and no count includes it.
    ///
    /// Each value is replaced by one statement that applies only if the stored
    /// text is still what was read, so a writer, a token refresh or a sweep in
    /// another process is never overwritten; the value is counted in
    /// `lost_races` and the next pass looks at it again. A crash leaves each
    /// value in its old or its new form. The rows whose value is not `v2.` are
    /// read in pages of 100, and the tenant's key is found, and made if the
    /// tenant has none, once for a tenant and page, between statements and
    /// never inside a transaction. A key that another process adds meanwhile
    /// is not used until the next page, and the older version stays readable.
    ///
    /// The key is only looked for after a value was opened, so a process whose
    /// master key is wrong, which opens nothing, makes no data key. A tenant
    /// whose data keys none can be unwrapped is given a new one, as for any
    /// writer ([`Store::data_key`]). A tenant whose data keys were destroyed is
    /// given none: its values are counted as unreadable and left as they are.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails, or if the key wrapper does not
    /// answer ([`StoreError::KeyWrap`]); the pass stops there, what it moved
    /// stays moved, and nothing is marked unreadable on account of it.
    pub async fn reencrypt(&self) -> Result<Reencrypted> {
        let mut report = Reencrypted::default();
        for column in COLUMNS {
            self.sweep_column(column, &mut report).await?;
        }
        Ok(report)
    }

    /// Whether a value of `tenant` is still under the master key, which no
    /// data key covers. Only `v1.` text opens under the master key. Runs on the
    /// pool, outside any transaction.
    pub(crate) async fn holds_master_key_value(&self, tenant: &str) -> Result<bool> {
        for spec in COLUMNS {
            let Slot { table, column } = spec.slot;
            let Encrypted {
                tenant: owner,
                filter,
                ..
            } = spec;
            // Built only from the constant table above, never from input;
            // `substr`, because SQLite's `LIKE` ignores case.
            let query = format!(
                "SELECT 1 FROM {table} WHERE {column} IS NOT NULL \
                 AND substr({column}, 1, {}) = '{FORMAT_V1}' AND {owner} = $1 {filter} LIMIT 1",
                FORMAT_V1.len()
            );
            let found = sqlx::query(AssertSqlSafe(query))
                .bind(tenant)
                .fetch_optional(&self.pool)
                .await?;
            if found.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn sweep_column(&self, spec: &Encrypted, report: &mut Reencrypted) -> Result<()> {
        let Slot { table, column } = spec.slot;
        let Encrypted {
            key,
            row_key,
            tenant,
            extra,
            filter,
            ..
        } = spec;
        let extra = if extra.is_empty() {
            String::new()
        } else {
            format!(", {extra}")
        };
        // Built only from the constant table above, never from input. The
        // database tells a value in the data-key format by its first
        // characters: `substr`, because SQLite's `LIKE` ignores case.
        let head = format!("substr({column}, 1, {})", FORMAT_V2.len());
        let count = format!(
            "SELECT COUNT(*) FROM {table} \
             WHERE {column} IS NOT NULL AND {head} = '{FORMAT_V2}' {filter}"
        );
        let select = format!(
            "SELECT {key} AS row_key, {column} AS stored, {row_key} AS owner, \
             {tenant} AS row_tenant{extra} FROM {table} \
             WHERE {key} > $1 AND {column} IS NOT NULL AND {head} <> '{FORMAT_V2}' {filter} \
             ORDER BY {key} LIMIT $2"
        );
        let update = format!("UPDATE {table} SET {column} = $1 WHERE {key} = $2 AND {column} = $3");
        // The database counts the values that are v2, and sends none of them.
        let counted: i64 = sqlx::query_scalar(AssertSqlSafe(count))
            .fetch_one(&self.pool)
            .await?;
        report.already_v2 += u64::try_from(counted).unwrap_or(0);
        let mut after = String::new();
        loop {
            let rows = sqlx::query(AssertSqlSafe(select.as_str()))
                .bind(&after)
                .bind(BATCH)
                .fetch_all(&self.pool)
                .await?;
            let Some(last) = rows.last() else {
                return Ok(());
            };
            after = last.try_get("row_key")?;
            // No connection is held now: finding a key may need one.
            let mut sealers = HashMap::new();
            for row in &rows {
                match self.sweep_row(spec, &update, row, &mut sealers).await? {
                    Outcome::Moved => report.updated += 1,
                    Outcome::Unreadable => report.unreadable += 1,
                    Outcome::Lost => report.lost_races += 1,
                    Outcome::Newer => {}
                }
            }
        }
    }

    async fn sweep_row(
        &self,
        spec: &Encrypted,
        update: &str,
        row: &AnyRow,
        sealers: &mut HashMap<String, Sealer>,
    ) -> Result<Outcome> {
        let Slot { table, column } = spec.slot;
        let stored: String = row.try_get("stored")?;
        let row_key: String = row.try_get("row_key")?;
        let owner: String = row.try_get("owner")?;
        let context = (spec.context)(&owner, row)?;
        let opened = Stored::parse(&stored).and_then(|_| self.cipher.open(&context, &stored));
        let plaintext = match opened {
            Ok((plaintext, _)) => plaintext,
            Err(StoreError::NewerFormat) => {
                tracing::warn!(table, column, key = %row_key, "stored secret is in a newer format than this version reads, so it is left as it is");
                return Ok(Outcome::Newer);
            }
            Err(StoreError::Decrypt) => {
                tracing::debug!(table, column, key = %row_key, "stored secret is unreadable with every configured key");
                return Ok(Outcome::Unreadable);
            }
            Err(err) => return Err(err),
        };
        let row_tenant: Option<String> = row.try_get("row_tenant")?;
        let tenant = match (row_tenant.as_deref(), spec.unowned_is_default) {
            (Some(tenant), _) => tenant,
            (None, true) => DEFAULT_TENANT,
            (None, false) => {
                tracing::debug!(table, column, key = %row_key, "stored secret has no tenant, so it is left as it is");
                return Ok(Outcome::Unreadable);
            }
        };
        if !sealers.contains_key(tenant) {
            match self.sealer(tenant).await {
                Ok(sealer) => sealers.insert(tenant.to_owned(), sealer),
                Err(StoreError::KeysDestroyed) => {
                    tracing::debug!(table, column, key = %row_key, "the data keys of the row's tenant were destroyed, so the value is left as it is");
                    return Ok(Outcome::Unreadable);
                }
                Err(err) => return Err(err),
            };
        }
        let fresh = sealers[tenant].seal(spec.slot, &owner, &plaintext)?;
        let moved = sqlx::query(AssertSqlSafe(update))
            .bind(fresh)
            .bind(&row_key)
            .bind(&stored)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(if moved == 1 {
            Outcome::Moved
        } else {
            tracing::debug!(table, column, key = %row_key, "stored secret changed meanwhile, so it is left for the next pass");
            Outcome::Lost
        })
    }
}

#[cfg(test)]
mod tests {
    use super::COLUMNS;
    use crate::crypto::{PASSWORD_SLOT, v2_context};
    use crate::{events, filters, upstream, webhooks};

    /// The associated data of a v2 value is stored data: these ten strings
    /// must never change. The sweep visits the columns that the readers name.
    #[test]
    fn the_associated_data_of_all_ten_columns_is_pinned() {
        let slots = [
            PASSWORD_SLOT,
            webhooks::AUTH_SLOT,
            webhooks::SECRET_SLOT,
            upstream::REFRESH_SLOT,
            upstream::ACCESS_SLOT,
            upstream::VERIFIER_SLOT,
            upstream::REQUEST_ID_SLOT,
            upstream::CONTINUATION_SLOT,
            events::PAYLOAD_SLOT,
            filters::PATTERN_SLOT,
        ];
        let actual: Vec<String> = slots
            .iter()
            .map(|slot| v2_context("tenant-a", *slot, "row-1"))
            .collect();
        assert_eq!(
            actual,
            [
                "postkeep/v2/tenant-a/accounts.password_ciphertext/row-1",
                "postkeep/v2/tenant-a/webhooks.auth_header_value_ciphertext/row-1",
                "postkeep/v2/tenant-a/webhooks.signing_secret_ciphertext/row-1",
                "postkeep/v2/tenant-a/upstream_tokens.refresh_token_ciphertext/row-1",
                "postkeep/v2/tenant-a/upstream_tokens.access_token_ciphertext/row-1",
                "postkeep/v2/tenant-a/upstream_requests.verifier_ciphertext/row-1",
                "postkeep/v2/tenant-a/upstream_requests.request_id_ciphertext/row-1",
                "postkeep/v2/tenant-a/upstream_requests.continuation_ciphertext/row-1",
                "postkeep/v2/tenant-a/mail_events.payload_ciphertext/row-1",
                "postkeep/v2/tenant-a/webhook_filter_rules.pattern_ciphertext/row-1",
            ]
        );
        // In the tenant `%` and `/` are escaped; the row key is as it is.
        assert_eq!(
            v2_context("tenant/a%b", PASSWORD_SLOT, "row/1"),
            "postkeep/v2/tenant%2Fa%25b/accounts.password_ciphertext/row/1"
        );
        let swept: Vec<_> = COLUMNS.iter().map(|c| c.slot).collect();
        assert_eq!(
            swept, slots,
            "the sweep visits the columns the readers name"
        );
    }

    /// Which row key and tenant describe each column, and whether a row with no
    /// tenant is the default tenant's. The readers and writers bind a v2 value
    /// to the same ones, and the stored values depend on it.
    #[test]
    fn the_sweep_describes_each_column_by_the_tenant_and_row_key_of_its_readers() {
        let account = |table: &str| {
            format!("(SELECT a.tenant FROM accounts a WHERE a.id = {table}.account_id)")
        };
        let expected = [
            // (row key, tenant, a row without a tenant is the default tenant's)
            ("email", "tenant".to_owned(), false),
            ("account_id", account("webhooks"), false),
            ("account_id", account("webhooks"), false),
            ("account_id", account("upstream_tokens"), false),
            ("account_id", account("upstream_tokens"), false),
            ("state_hash", "tenant".to_owned(), true),
            ("state_hash", "tenant".to_owned(), true),
            ("state_hash", "tenant".to_owned(), true),
            ("id", account("mail_events"), false),
            ("id", account("webhook_filter_rules"), false),
        ];
        let actual: Vec<_> = COLUMNS
            .iter()
            .map(|c| (c.row_key, c.tenant.to_owned(), c.unowned_is_default))
            .collect();
        assert_eq!(actual, expected);
        // Rows are paged and updated by a unique key of their table. For
        // passwords that is the account's ID, and its row key is its email
        // address.
        let paged: Vec<_> = COLUMNS.iter().map(|c| c.key).collect();
        assert_eq!(
            paged,
            [
                "id",
                "account_id",
                "account_id",
                "account_id",
                "account_id",
                "state_hash",
                "state_hash",
                "state_hash",
                "id",
                "id",
            ]
        );
    }
}
