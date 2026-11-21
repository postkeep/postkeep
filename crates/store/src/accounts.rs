//! Accounts: IMAP accounts with an encrypted app password, and OAuth
//! accounts (Microsoft Graph, Gmail) identified by provider and subject.

use secrecy::{ExposeSecret, SecretString};
use sqlx::Row;
use sqlx::any::AnyRow;

use crate::crypto::{PASSWORD_SLOT, constant_time_eq, password_context};
use crate::db::{now, rollback_then};
use crate::upstream::{self, UpstreamTokens};
use crate::{Result, Store, StoreError};

/// Identifier of a stored account.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId(pub String);

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// How postkeep reaches an account's mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// IMAP and SMTP with an app password.
    Imap,
    /// Microsoft Graph (Outlook.com, Microsoft 365).
    Graph,
    /// The Gmail API.
    Gmail,
}

impl Provider {
    /// The value stored in the database.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Imap => "imap",
            Self::Graph => "graph",
            Self::Gmail => "gmail",
        }
    }

    /// Parses a stored value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "imap" => Some(Self::Imap),
            "graph" => Some(Self::Graph),
            "gmail" => Some(Self::Gmail),
            _ => None,
        }
    }

    /// Whether accounts of this provider sign in with OAuth.
    #[must_use]
    pub const fn is_oauth(self) -> bool {
        !matches!(self, Self::Imap)
    }
}

impl std::fmt::Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A stored account without its secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Account identifier.
    pub id: AccountId,
    /// Email address (lowercase).
    pub email: String,
    /// How the mailbox is reached.
    pub provider: Provider,
    /// IMAP accounts: the server preset name, `None` for the server's
    /// default (accounts created before presets existed).
    pub imap_server: Option<String>,
}

/// Decrypted credentials of an IMAP account.
#[derive(Debug, Clone)]
pub struct StoredCredentials {
    /// Email address, used as the IMAP and SMTP user name.
    pub email: String,
    /// The app-specific password.
    pub password: SecretString,
    /// The server preset name; `None` for the server's default.
    pub imap_server: Option<String>,
}

/// Result of [`Store::upsert_imap_account_ending_sessions`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpsertedImapAccount {
    /// The account after the write.
    pub account: Account,
    /// Whether an existing IMAP password was replaced with a different one.
    ///
    /// `false` for a new account and when the plaintext matched. A stored
    /// password that no configured key can decrypt counts as changed: it is
    /// overwritten, and it cannot be shown to be the same.
    pub password_changed: bool,
}

/// What an IMAP account's stored password was, compared with the one about
/// to be written. Read before the write so the insert stays one statement.
enum ObservedPassword {
    /// No IMAP row (missing, or an OAuth account the write will reject).
    None,
    /// The plaintext matches.
    Same,
    /// The plaintext differs, or the stored value cannot be decrypted.
    Different,
}

/// An OAuth account to create or update after a sign-in at its provider.
#[derive(Debug, Clone)]
pub struct OAuthAccount<'a> {
    /// [`Provider::Graph`] or [`Provider::Gmail`].
    pub provider: Provider,
    /// The provider's stable user identifier.
    pub subject: &'a str,
    /// The mailbox address.
    pub email: &'a str,
}

pub fn account_from_row(row: &AnyRow) -> Result<Account> {
    let provider: String = row.try_get("provider")?;
    Ok(Account {
        id: AccountId(row.try_get("id")?),
        email: row.try_get("email")?,
        provider: Provider::parse(&provider).ok_or(StoreError::InvalidInput("unknown provider"))?,
        imap_server: row.try_get("imap_server")?,
    })
}

fn normalize_email(email: &str) -> Result<String> {
    let email = email.trim().to_lowercase();
    if email.is_empty() {
        return Err(StoreError::InvalidInput("email must not be empty"));
    }
    Ok(email)
}

impl Store {
    /// Creates the IMAP account for `email` on the server's default IMAP
    /// server, or replaces its password. See
    /// [`Store::upsert_imap_account`].
    ///
    /// # Errors
    ///
    /// As [`Store::upsert_imap_account`].
    pub async fn upsert_account(&self, email: &str, password: &SecretString) -> Result<Account> {
        self.upsert_imap_account(email, password, None).await
    }

    /// Creates the IMAP account for `email` or replaces its password and
    /// server preset, returning the account. Email addresses are compared
    /// case-insensitively. `imap_server` names a preset; `None` keeps the
    /// server's default.
    ///
    /// Account-page sessions are left as they are. To end them when the
    /// password changes, use [`Store::upsert_imap_account_ending_sessions`].
    /// Either way, storing a password clears the record that the mail server
    /// rejected the old one ([`Store::password_rejected_at`]).
    ///
    /// The password is stored under the data key that [`Store::data_key`] finds
    /// or makes for this store's tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AccountConflict`] if the address belongs to an
    /// OAuth account, or an error if encryption or the query fails. A key
    /// wrapper that does not answer is [`StoreError::KeyWrap`] and nothing is
    /// written.
    pub async fn upsert_imap_account(
        &self,
        email: &str,
        password: &SecretString,
        imap_server: Option<&str>,
    ) -> Result<Account> {
        Ok(self
            .write_imap_account(email, password, imap_server, false)
            .await?
            .account)
    }

    /// As [`Store::upsert_imap_account`], and reports whether the stored
    /// password changed.
    ///
    /// When it did, every account-page session for that account is deleted
    /// in the same transaction as the password write. OAuth grants and
    /// tokens are left as they are. A new account, and a sign-in with the
    /// same password, do not end sessions. An address that belongs to an
    /// OAuth account is still [`StoreError::AccountConflict`], and its
    /// sessions are kept.
    ///
    /// A stored password that no configured key can decrypt counts as
    /// changed: it is overwritten and cannot be shown to be the same. One that
    /// a key wrapper failed to open, because it does not answer, does not:
    /// that is [`StoreError::KeyWrap`] and nothing is written.
    ///
    /// A stored password in a format newer than this version reads is not
    /// overwritten either: that is [`StoreError::NewerFormat`] and nothing is
    /// written.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AccountConflict`] if the address belongs to an
    /// OAuth account, or an error if encryption or a query fails.
    pub async fn upsert_imap_account_ending_sessions(
        &self,
        email: &str,
        password: &SecretString,
        imap_server: Option<&str>,
    ) -> Result<UpsertedImapAccount> {
        self.write_imap_account(email, password, imap_server, true)
            .await
    }

    /// The shared IMAP upsert. `end_sessions_on_change` deletes account-page
    /// sessions only when the plaintext password actually changes.
    async fn write_imap_account(
        &self,
        email: &str,
        password: &SecretString,
        imap_server: Option<&str>,
        end_sessions_on_change: bool,
    ) -> Result<UpsertedImapAccount> {
        let email = normalize_email(email)?;
        // Compared outside the write. The insert below is the first
        // statement of its transaction, so a concurrent writer does not
        // turn that transaction into a snapshot conflict.
        let observed = self.observed_imap_password(&email, password).await?;
        // The statement below writes the row in this store's tenant, and the
        // address is its key, which `credentials` reads back. The data key is
        // found, or made, before the transaction opens.
        let ciphertext =
            self.sealer(self.tenant())
                .await?
                .seal_secret(PASSWORD_SLOT, &email, password)?;
        let now = now();
        let new_id = uuid::Uuid::new_v4().to_string();
        let mut tx = self.begin_write().await?;
        let inserted = sqlx::query(
            "INSERT INTO accounts (id, email, password_ciphertext, provider, imap_server, created_at, updated_at, tenant) \
             VALUES ($1, $2, $3, 'imap', $4, $5, $5, $6) \
             ON CONFLICT (tenant, email) DO UPDATE SET \
             password_ciphertext = excluded.password_ciphertext, imap_server = excluded.imap_server, \
             updated_at = excluded.updated_at, password_rejected_at = NULL \
             WHERE accounts.provider = 'imap' \
             RETURNING id",
        )
        .bind(&new_id)
        .bind(&email)
        .bind(&ciphertext)
        .bind(imap_server)
        .bind(now)
        .bind(self.tenant())
        .fetch_optional(&mut *tx)
        .await;
        let row = match inserted {
            Ok(row) => row,
            // Includes the global email unique index on SQLite, which is not
            // the ON CONFLICT target. Roll back before the caller continues.
            Err(err) => return rollback_then(tx, conflict_on_unique(err)).await,
        };
        let Some(row) = row else {
            return rollback_then(tx, StoreError::AccountConflict).await;
        };
        let id: String = row.try_get("id")?;
        // `id != new_id` means the statement updated an existing row. A
        // fresh insert did not replace a password. When the read saw no
        // IMAP password but the write updated a row, that row appeared in
        // between and its password was overwritten.
        let password_changed = match observed {
            ObservedPassword::Same => false,
            ObservedPassword::Different | ObservedPassword::None => id != new_id,
        };
        if end_sessions_on_change && password_changed {
            sqlx::query("DELETE FROM account_sessions WHERE account_id = $1")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(UpsertedImapAccount {
            account: Account {
                id: AccountId(id),
                email,
                provider: Provider::Imap,
                imap_server: imap_server.map(str::to_owned),
            },
            password_changed,
        })
    }

    /// Compares `password` with the IMAP password stored for `email`.
    ///
    /// `email` is already normalized. The comparison does not stop at the
    /// first differing byte.
    async fn observed_imap_password(
        &self,
        email: &str,
        password: &SecretString,
    ) -> Result<ObservedPassword> {
        let row = sqlx::query(
            "SELECT provider, password_ciphertext FROM accounts WHERE email = $1 AND tenant = $2",
        )
        .bind(email)
        .bind(self.tenant())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(ObservedPassword::None);
        };
        let provider: String = row.try_get("provider")?;
        if provider != Provider::Imap.as_str() {
            return Ok(ObservedPassword::None);
        }
        let stored: String = row.try_get("password_ciphertext")?;
        // The row is in this store's tenant: the query above asks for it.
        let legacy = password_context(email);
        let open = self.open_secret(self.tenant(), PASSWORD_SLOT, email, &legacy, &stored);
        match open.await {
            Ok(current) if constant_time_eq(current.expose_secret(), password.expose_secret()) => {
                Ok(ObservedPassword::Same)
            }
            // Only a password that can never be read is overwritten. Any
            // other error, such as a key wrapper that does not answer, stops
            // the write.
            Ok(_) | Err(StoreError::Decrypt) => Ok(ObservedPassword::Different),
            Err(err) => Err(err),
        }
    }

    /// Creates or updates an OAuth account after a successful sign-in and
    /// stores its tokens, returning the account.
    ///
    /// The account is found by provider and subject. A new account is only
    /// created when no other account uses the address, so signing in with
    /// a provider can never take over an account created another way, nor
    /// one belonging to a different user of the same provider. When the
    /// provider reports a new address for a known subject, the address is
    /// updated if it is free. Tokens that can no longer be read are replaced.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::AccountConflict`] if the address belongs to a
    /// different account, or an error if encryption or a query fails. A key
    /// wrapper that does not answer is [`StoreError::KeyWrap`]: nothing is
    /// written. An account that was deleted while this call waited to
    /// update it is [`StoreError::AccountDeleted`], and nothing is written
    /// either: signing in again adds it anew.
    pub async fn upsert_oauth_account(
        &self,
        account: &OAuthAccount<'_>,
        tokens: &UpstreamTokens,
    ) -> Result<Account> {
        if !account.provider.is_oauth() {
            return Err(StoreError::InvalidInput("not an OAuth provider"));
        }
        if account.subject.is_empty() {
            return Err(StoreError::InvalidInput("subject must not be empty"));
        }
        let email = normalize_email(account.email)?;
        // The account is in this store's tenant, but its ID, which binds the
        // tokens, is learned inside the transaction. So the key is found, or
        // made, now, and the tokens are sealed with it once the ID is known.
        let sealer = self.sealer(self.tenant()).await?;
        let now = now();
        let mut tx = self.begin_write().await?;
        let existing = sqlx::query(
            "SELECT id FROM accounts WHERE provider = $1 AND subject = $2 AND tenant = $3",
        )
        .bind(account.provider.as_str())
        .bind(account.subject)
        .bind(self.tenant())
        .fetch_optional(&mut *tx)
        .await?;
        let by_email = sqlx::query("SELECT id FROM accounts WHERE email = $1 AND tenant = $2")
            .bind(&email)
            .bind(self.tenant())
            .fetch_optional(&mut *tx)
            .await?
            .map(|row| row.try_get::<String, _>("id"))
            .transpose()?;
        let id = if let Some(row) = existing {
            let id: String = row.try_get("id")?;
            if by_email.as_ref().is_some_and(|other| *other != id) {
                return rollback_then(tx, StoreError::AccountConflict).await;
            }
            let updated =
                sqlx::query("UPDATE accounts SET email = $1, updated_at = $2 WHERE id = $3")
                    .bind(&email)
                    .bind(now)
                    .bind(&id)
                    .execute(&mut *tx)
                    .await;
            match updated {
                // The account's deletion held the row and has committed: the
                // tokens would have no account to belong to.
                Ok(done) if done.rows_affected() == 0 => {
                    return rollback_then(tx, StoreError::AccountDeleted).await;
                }
                Ok(_) => {}
                Err(err) => return rollback_then(tx, conflict_on_unique(err)).await,
            }
            id
        } else {
            if by_email.is_some() {
                return rollback_then(tx, StoreError::AccountConflict).await;
            }
            let id = uuid::Uuid::new_v4().to_string();
            if let Err(err) = sqlx::query(
                "INSERT INTO accounts (id, email, password_ciphertext, provider, subject, created_at, updated_at, tenant) \
                 VALUES ($1, $2, '', $3, $4, $5, $5, $6)",
            )
            .bind(&id)
            .bind(&email)
            .bind(account.provider.as_str())
            .bind(account.subject)
            .bind(now)
            .bind(self.tenant())
            .execute(&mut *tx)
            .await
            {
                return rollback_then(tx, conflict_on_unique(err)).await;
            }
            id
        };
        let id = AccountId(id);
        upstream::write_tokens(&sealer, &mut tx, &id, tokens).await?;
        tx.commit().await?;
        Ok(Account {
            id,
            email,
            provider: account.provider,
            imap_server: None,
        })
    }

    /// Returns an account, if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn account(&self, id: &AccountId) -> Result<Option<Account>> {
        let row =
            sqlx::query("SELECT id, email, provider, imap_server FROM accounts WHERE id = $1")
                .bind(&id.0)
                .fetch_optional(&self.pool)
                .await?;
        row.as_ref().map(account_from_row).transpose()
    }

    /// The tenant of an account, if it exists. A value stored for an account is
    /// bound to the tenant of its row, which is not always this store's:
    /// lookups by ID are not scoped.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn account_tenant(&self, account: &AccountId) -> Result<Option<String>> {
        let row = sqlx::query("SELECT tenant FROM accounts WHERE id = $1")
            .bind(&account.0)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| row.try_get("tenant")).transpose()?)
    }

    /// `err`, of a write for the account `id`, or
    /// [`StoreError::AccountDeleted`] if that account is gone: its deletion
    /// committed first, and the write failed on its foreign key.
    pub(crate) async fn unless_deleted(&self, id: &str, err: sqlx::Error) -> StoreError {
        let gone = sqlx::query("SELECT 1 FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .is_ok_and(|row| row.is_none());
        if gone {
            StoreError::AccountDeleted
        } else {
            StoreError::Database(err)
        }
    }

    /// Finds the account with an address and provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn account_by_email(
        &self,
        email: &str,
        provider: Provider,
    ) -> Result<Option<Account>> {
        let row = sqlx::query(
            "SELECT id, email, provider, imap_server FROM accounts \
             WHERE email = $1 AND provider = $2 AND tenant = $3",
        )
        .bind(email.trim().to_lowercase())
        .bind(provider.as_str())
        .bind(self.tenant())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(account_from_row).transpose()
    }

    /// Finds an OAuth account by provider and subject.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn account_by_subject(
        &self,
        provider: Provider,
        subject: &str,
    ) -> Result<Option<Account>> {
        let row = sqlx::query(
            "SELECT id, email, provider, imap_server FROM accounts \
             WHERE provider = $1 AND subject = $2 AND tenant = $3",
        )
        .bind(provider.as_str())
        .bind(subject)
        .bind(self.tenant())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(account_from_row).transpose()
    }

    /// Finds the account in this store's tenant whose address (compared
    /// without case) or, for a key without `@`, whose ID is `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn find_account(&self, key: &str) -> Result<Option<Account>> {
        let key = key.trim();
        let query = if key.contains('@') {
            sqlx::query(
                "SELECT id, email, provider, imap_server FROM accounts \
                 WHERE email = $1 AND tenant = $2",
            )
            .bind(key.to_lowercase())
        } else {
            sqlx::query(
                "SELECT id, email, provider, imap_server FROM accounts \
                 WHERE id = $1 AND tenant = $2",
            )
            .bind(key.to_owned())
        };
        let row = query.bind(self.tenant()).fetch_optional(&self.pool).await?;
        row.as_ref().map(account_from_row).transpose()
    }

    /// Every account in this store's tenant, ordered by address.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn accounts_in_tenant(&self) -> Result<Vec<Account>> {
        let rows = sqlx::query(
            "SELECT id, email, provider, imap_server FROM accounts WHERE tenant = $1 \
             ORDER BY email, id",
        )
        .bind(self.tenant())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(account_from_row).collect()
    }

    /// Returns the decrypted credentials of an IMAP account, if it exists.
    /// OAuth accounts have none: see [`Store::upstream_tokens`].
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Decrypt`] if the password cannot be decrypted
    /// with the configured keys, and another error if the database fails or
    /// the key wrapper does not answer.
    /// A password in a format newer than this version reads is
    /// [`StoreError::NewerFormat`].
    pub async fn credentials(&self, id: &AccountId) -> Result<Option<StoredCredentials>> {
        let row = sqlx::query(
            "SELECT email, password_ciphertext, imap_server, tenant FROM accounts \
             WHERE id = $1 AND provider = 'imap'",
        )
        .bind(&id.0)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let email: String = row.try_get("email")?;
        let ciphertext: String = row.try_get("password_ciphertext")?;
        // Lookups by ID are not scoped, so the tenant is the row's, not this
        // store's.
        let tenant: String = row.try_get("tenant")?;
        let legacy = password_context(&email);
        let password = self
            .open_secret(&tenant, PASSWORD_SLOT, &email, &legacy, &ciphertext)
            .await?;
        Ok(Some(StoredCredentials {
            email,
            password,
            imap_server: row.try_get("imap_server")?,
        }))
    }

    /// When the mail server last rejected the account's stored password
    /// (Unix seconds), or `None` if it has not since the password was stored
    /// or last worked. The watcher records it when it gives up on the
    /// password, and a tool call when its login is rejected. The account page
    /// and `get_webhook_status` show it; an embedding that turns the page off
    /// can read it for its own.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn password_rejected_at(&self, id: &AccountId) -> Result<Option<i64>> {
        let row = sqlx::query("SELECT password_rejected_at FROM accounts WHERE id = $1")
            .bind(&id.0)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row
            .map(|row| row.try_get("password_rejected_at"))
            .transpose()?
            .flatten())
    }

    /// Records that the mail server rejected the account's stored password now.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn mark_password_rejected(&self, id: &AccountId) -> Result<()> {
        sqlx::query("UPDATE accounts SET password_rejected_at = $2 WHERE id = $1")
            .bind(&id.0)
            .bind(now())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Clears the record of a rejected password, because a login with it
    /// worked. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn clear_password_rejected(&self, id: &AccountId) -> Result<bool> {
        let cleared = sqlx::query(
            "UPDATE accounts SET password_rejected_at = NULL \
             WHERE id = $1 AND password_rejected_at IS NOT NULL",
        )
        .bind(&id.0)
        .execute(&self.pool)
        .await?;
        Ok(cleared.rows_affected() > 0)
    }

    /// Sets the server of IMAP accounts that name none (accounts created
    /// before servers were recorded) to `server`. Returns how many changed.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn pin_imap_server(&self, server: &str) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE accounts SET imap_server = $1 WHERE provider = 'imap' AND imap_server IS NULL",
        )
        .bind(server)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Deletes an account together with its codes, grants, tokens,
    /// sessions, webhook, filter rules, events and upstream state. Returns
    /// whether an account was deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn delete_account(&self, id: &AccountId) -> Result<bool> {
        Ok(self.delete_account_rows(id).await?.0)
    }

    /// Deletes an account as [`Store::delete_account`] does, and returns the
    /// refresh token that the deletion removed, if the account had one. The
    /// deletion reads it in the statement that removes it, so it is the
    /// latest one: also one that a reconnect stored after the caller last read
    /// the tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails: nothing is deleted then.
    pub async fn delete_account_returning_refresh_token(
        &self,
        id: &AccountId,
    ) -> Result<Option<RemovedRefreshToken>> {
        Ok(self.delete_account_rows(id).await?.1)
    }

    /// Reads a refresh token that an account's deletion removed, under the
    /// key of the account's tenant.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Decrypt`] if it can't be decrypted, and another
    /// error if the database fails or the key wrapper does not answer.
    pub async fn open_removed_refresh_token(
        &self,
        removed: &RemovedRefreshToken,
    ) -> Result<SecretString> {
        let (account, sealed) = (&removed.account, &removed.ciphertext);
        let legacy = upstream::refresh_context(account);
        let slot = upstream::REFRESH_SLOT;
        self.open_secret(&removed.tenant, slot, &account.0, &legacy, sealed)
            .await
    }

    /// Whether there was an account to delete, and the refresh token that
    /// its deletion removed.
    async fn delete_account_rows(
        &self,
        id: &AccountId,
    ) -> Result<(bool, Option<RemovedRefreshToken>)> {
        let mut tx = self.begin_write().await?;
        // The webhook's row first, as every writer of the webhook's rows takes
        // it. Then the account's row, which a reconnect updates before it ends
        // the sessions or saves the tokens, and `save_upstream_tokens` before
        // it saves them. The update changes nothing, and on PostgreSQL an
        // insert's foreign-key lock gets past its lock. Then the codes, the
        // tokens and the grants, in the order that every writer of them keeps.
        // The row itself is deleted last.
        for statement in [
            "DELETE FROM webhooks WHERE account_id = $1",
            "UPDATE accounts SET updated_at = updated_at WHERE id = $1",
            "DELETE FROM authorization_codes WHERE account_id = $1",
            "DELETE FROM access_tokens WHERE grant_id IN (SELECT id FROM grants WHERE account_id = $1)",
            "DELETE FROM refresh_tokens WHERE grant_id IN (SELECT id FROM grants WHERE account_id = $1)",
            "DELETE FROM grants WHERE account_id = $1",
            "DELETE FROM account_sessions WHERE account_id = $1",
            "DELETE FROM held_sends WHERE account_id = $1",
            "DELETE FROM webhook_deliveries WHERE account_id = $1",
            "DELETE FROM mail_events WHERE account_id = $1",
            "DELETE FROM webhook_filter_rules WHERE account_id = $1",
            "DELETE FROM push_subscriptions WHERE account_id = $1",
        ] {
            sqlx::query(statement).bind(&id.0).execute(&mut *tx).await?;
        }
        // Read as it is removed, so that a caller can revoke the latest grant.
        let sealed: Option<String> = sqlx::query_scalar(
            "DELETE FROM upstream_tokens WHERE account_id = $1 RETURNING refresh_token_ciphertext",
        )
        .bind(&id.0)
        .fetch_optional(&mut *tx)
        .await?;
        let tenant: Option<String> =
            sqlx::query_scalar("DELETE FROM accounts WHERE id = $1 RETURNING tenant")
                .bind(&id.0)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        let deleted = tenant.is_some();
        let removed = tenant
            .zip(sealed)
            .map(|(tenant, ciphertext)| RemovedRefreshToken {
                tenant,
                account: id.clone(),
                ciphertext,
            });
        Ok((deleted, removed))
    }
}

/// A refresh token that an account's deletion removed, still sealed.
/// [`Store::open_removed_refresh_token`] reads it once the deletion has
/// committed.
#[derive(Debug)]
pub struct RemovedRefreshToken {
    tenant: String,
    account: AccountId,
    ciphertext: String,
}

/// A unique-constraint failure on an account write is the address or
/// provider identity being taken. On SQLite, which keeps one global tenant
/// per address, that includes another tenant holding it.
fn conflict_on_unique(err: sqlx::Error) -> StoreError {
    match &err {
        sqlx::Error::Database(db) if db.is_unique_violation() => StoreError::AccountConflict,
        _ => StoreError::Database(err),
    }
}
