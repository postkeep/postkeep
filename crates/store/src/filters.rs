//! Webhook filter rules: one row for each rule of a mailbox, with the pattern
//! sealed under the data key of the mailbox's tenant.
//!
//! The store keeps the action, field and kind as the caller gives them and
//! checks none of them, so a name from a newer build reads back as written.
//! Every add, removal, change and turn on or off counts in the mailbox's
//! `filter_rules_version`. A rule's `seq` is one more than the largest in its
//! mailbox. `save_webhook` deletes the
//! rules that an older build left when it deleted a webhook. If an older build
//! also makes the webhook again, they stay with a count that starts from 0, and
//! a new rule's `seq` still does not collide with theirs.

use secrecy::SecretString;
use sqlx::Row;

use crate::accounts::AccountId;
use crate::crypto::Slot;
use crate::db::now;
use crate::{Result, Store};

/// The column of an encrypted rule pattern.
pub const PATTERN_SLOT: Slot = Slot::new("webhook_filter_rules", "pattern_ciphertext");

/// The associated data of a `v1.` pattern. No earlier version stored one, so
/// no value is bound to it; the readers and the sweep still ask for one.
pub fn pattern_context(rule: &str) -> String {
    format!("webhook/filter/{rule}")
}

/// A rule to add.
#[derive(Debug, Clone)]
pub struct NewFilterRule {
    /// `allow` or `block`.
    pub action: String,
    /// What the pattern is matched against, such as `subject`.
    pub field: String,
    /// How the pattern is matched, such as `contains`.
    pub kind: String,
    /// The pattern, which can hold addresses and names.
    pub pattern: SecretString,
}

/// A stored rule.
#[derive(Debug, Clone)]
pub struct FilterRule {
    /// The rule's ID.
    pub id: String,
    /// When it was added (Unix seconds).
    pub added_at: i64,
    /// As it was added.
    pub action: String,
    /// As it was added.
    pub field: String,
    /// As it was added.
    pub kind: String,
    /// The pattern.
    pub pattern: SecretString,
    /// Whether the rule is on. A rule that is off judges nothing, but keeps its
    /// place among the oldest rules and counts toward the limit.
    pub enabled: bool,
    /// Whether the rule judges new mail: it is on, and among the oldest rules,
    /// as many as the limit.
    pub active: bool,
}

/// What [`Store::add_webhook_filter_rule`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddedFilterRule {
    /// The rule was stored under this ID.
    Added(String),
    /// The mailbox has as many rules as the limit allows. Nothing was stored.
    AtLimit,
    /// The caller's check refused the rule, with this reason. Nothing was stored.
    Refused(String),
    /// The account has no webhook, or does not exist. Nothing was stored.
    NoWebhook,
}

/// What [`Store::set_webhook_filter_rule_enabled`] or
/// [`Store::update_webhook_filter_rule`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangedFilterRule {
    /// The rule was changed, which counts in `filter_rules_version`.
    Changed,
    /// The caller's check refused the change, with this reason. Nothing was written.
    Refused(String),
    /// The mailbox has no rule with that ID (its rules go with its webhook).
    /// Nothing was written.
    NotFound,
}

impl Store {
    /// The filter rules of a mailbox, oldest first: by when they were added,
    /// then in the order they were added. The oldest `limit` rules, on or off,
    /// are inside the limit, and those of them that are on are `active`; the
    /// others are kept, and count again when the limit allows more. Nothing is
    /// stored for that, so a caller passes the limit of the moment.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails or a pattern can't be decrypted
    /// ([`StoreError::Decrypt`](crate::StoreError::Decrypt) if it never can be).
    pub async fn webhook_filter_rules(
        &self,
        account: &AccountId,
        limit: usize,
    ) -> Result<Vec<FilterRule>> {
        let rows = sqlx::query(
            "SELECT r.id, r.added_at, r.action, r.field, r.kind, r.pattern_ciphertext, \
             r.enabled, a.tenant AS tenant FROM webhook_filter_rules r \
             JOIN accounts a ON a.id = r.account_id \
             WHERE r.account_id = $1 ORDER BY r.added_at, r.seq",
        )
        .bind(&account.0)
        .fetch_all(&self.pool)
        .await?;
        let mut rules = Vec::with_capacity(rows.len());
        for (index, row) in rows.iter().enumerate() {
            let id: String = row.try_get("id")?;
            let tenant: String = row.try_get("tenant")?;
            let stored: String = row.try_get("pattern_ciphertext")?;
            let enabled = row.try_get::<i64, _>("enabled")? != 0;
            let legacy = pattern_context(&id);
            let open = self.open_secret(&tenant, PATTERN_SLOT, &id, &legacy, &stored);
            rules.push(FilterRule {
                pattern: open.await?,
                added_at: row.try_get("added_at")?,
                action: row.try_get("action")?,
                field: row.try_get("field")?,
                kind: row.try_get("kind")?,
                enabled,
                active: index < limit && enabled,
                id,
            });
        }
        Ok(rules)
    }

    /// Adds a rule unless the mailbox has `limit` rules already, on or off,
    /// active or not. A new rule is on.
    ///
    /// `check` is given the mailbox's rules as they are, decrypted, to refuse
    /// the new one with a reason, for example because they would not compile
    /// together with it. No other change to the mailbox's rules can come between
    /// the check and the insert: when one does, the check runs again on the new
    /// rules. So adds to one mailbox take effect one after another, on every
    /// backend, with no lock held while `check` runs.
    ///
    /// The pattern is sealed under the data key of the account's tenant,
    /// whichever tenant this store is scoped to, with the rule's ID as row key.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or a query fails. A key wrapper that
    /// does not answer is [`StoreError::KeyWrap`](crate::StoreError::KeyWrap)
    /// and nothing is written.
    pub async fn add_webhook_filter_rule(
        &self,
        account: &AccountId,
        rule: &NewFilterRule,
        limit: usize,
        mut check: impl FnMut(&[FilterRule]) -> Result<(), String>,
    ) -> Result<AddedFilterRule> {
        let Some(tenant) = self.account_tenant(account).await? else {
            return Ok(AddedFilterRule::NoWebhook);
        };
        // The key is found, or made, before any transaction opens.
        let sealer = self.sealer(&tenant).await?;
        let id = uuid::Uuid::new_v4().to_string();
        let pattern = sealer.seal_secret(PATTERN_SLOT, &id, &rule.pattern)?;
        // A pass ends when this add is stored or refused, or when another add or
        // remove came first, which the next pass sees.
        loop {
            // The count comes first: the rules read after it are as they were
            // at that count or newer, and the update below needs that count.
            let Some(seen) = self.webhook_filter_rules_version(account).await? else {
                return Ok(AddedFilterRule::NoWebhook);
            };
            let rules = self.webhook_filter_rules(account, limit).await?;
            if rules.len() >= limit {
                return Ok(AddedFilterRule::AtLimit);
            }
            if let Err(reason) = check(&rules) {
                return Ok(AddedFilterRule::Refused(reason));
            }
            let mut tx = self.begin_write().await?;
            let counted = sqlx::query(
                "UPDATE webhooks SET filter_rules_version = filter_rules_version + 1 \
                 WHERE account_id = $1 AND filter_rules_version = $2",
            )
            .bind(&account.0)
            .bind(seen)
            .execute(&mut *tx)
            .await?;
            if counted.rows_affected() == 0 {
                tx.rollback().await?;
                continue;
            }
            sqlx::query(
                "INSERT INTO webhook_filter_rules \
                 (id, account_id, seq, added_at, action, field, kind, pattern_ciphertext) \
                 VALUES ($1, $2, (SELECT COALESCE(MAX(seq), 0) + 1 FROM webhook_filter_rules \
                 WHERE account_id = $2), $3, $4, $5, $6, $7)",
            )
            .bind(&id)
            .bind(&account.0)
            .bind(now())
            .bind(&rule.action)
            .bind(&rule.field)
            .bind(&rule.kind)
            .bind(pattern)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(AddedFilterRule::Added(id));
        }
    }

    /// Turns one rule of a mailbox on or off. A rule that is off judges
    /// nothing, but keeps its place among the oldest rules and counts toward
    /// the limit.
    ///
    /// Turning a rule off always applies: `check` and `limit` are not used.
    /// Turning one on gives `check` the mailbox's rules, decrypted, as they
    /// would be with this rule on, to refuse it with a reason, for example
    /// because they would not compile together. No other change to the
    /// mailbox's rules can come between the check and the write, as for
    /// [`Store::add_webhook_filter_rule`].
    ///
    /// Both count in `filter_rules_version`, so a running watcher judges with
    /// the change from its next batch. A watcher that its rules stopped reads
    /// them again only when it starts again, and starting it is the caller's
    /// job after [`ChangedFilterRule::Changed`].
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails or, when turning a rule on, a pattern
    /// can't be decrypted.
    pub async fn set_webhook_filter_rule_enabled(
        &self,
        account: &AccountId,
        id: &str,
        enabled: bool,
        limit: usize,
        check: impl FnMut(&[FilterRule]) -> Result<(), String>,
    ) -> Result<ChangedFilterRule> {
        if !enabled {
            let mut tx = self.begin_write().await?;
            // The webhook's row before the rule, as `remove_filter_rules` takes them. A rule
            // that isn't there is rolled back, count and all.
            sqlx::query(
                "UPDATE webhooks SET filter_rules_version = filter_rules_version + 1 \
                 WHERE account_id = $1",
            )
            .bind(&account.0)
            .execute(&mut *tx)
            .await?;
            let changed = sqlx::query(
                "UPDATE webhook_filter_rules SET enabled = 0 WHERE account_id = $1 AND id = $2",
            )
            .bind(&account.0)
            .bind(id)
            .execute(&mut *tx)
            .await?;
            if changed.rows_affected() == 0 {
                tx.rollback().await?;
                return Ok(ChangedFilterRule::NotFound);
            }
            tx.commit().await?;
            return Ok(ChangedFilterRule::Changed);
        }
        self.change_filter_rule(account, id, limit, None, check)
            .await
    }

    /// Changes the action, field, kind and pattern of one rule of a mailbox,
    /// and keeps its ID, its place and whether it is on.
    ///
    /// `check` is given the mailbox's rules, decrypted, as they would be after
    /// the change, to refuse it with a reason, for example because they would
    /// not compile together. Checking the new rule on its own is the caller's
    /// job, as for [`Store::add_webhook_filter_rule`], because the store keeps
    /// names as given. No other change to the mailbox's rules can come between
    /// the check and the write.
    ///
    /// The pattern is sealed again under the data key of the account's tenant,
    /// whichever tenant this store is scoped to, with the rule's ID as row key.
    ///
    /// The change counts in `filter_rules_version`, so a running watcher judges
    /// with it from its next batch. A watcher that its rules stopped reads them
    /// again only when it starts again, and starting it is the caller's job
    /// after [`ChangedFilterRule::Changed`].
    ///
    /// # Errors
    ///
    /// Returns an error if encryption or a query fails. A key wrapper that
    /// does not answer is [`StoreError::KeyWrap`](crate::StoreError::KeyWrap)
    /// and nothing is written.
    pub async fn update_webhook_filter_rule(
        &self,
        account: &AccountId,
        id: &str,
        rule: &NewFilterRule,
        limit: usize,
        check: impl FnMut(&[FilterRule]) -> Result<(), String>,
    ) -> Result<ChangedFilterRule> {
        let Some(tenant) = self.account_tenant(account).await? else {
            return Ok(ChangedFilterRule::NotFound);
        };
        // The key is found, or made, before any transaction opens.
        let sealer = self.sealer(&tenant).await?;
        let pattern = sealer.seal_secret(PATTERN_SLOT, id, &rule.pattern)?;
        self.change_filter_rule(account, id, limit, Some((rule, &pattern)), check)
            .await
    }

    /// Turns a rule on (`edit` is `None`), or gives it the new rule and its
    /// sealed pattern, once `check` passes on the rules as they would be.
    async fn change_filter_rule(
        &self,
        account: &AccountId,
        id: &str,
        limit: usize,
        edit: Option<(&NewFilterRule, &str)>,
        mut check: impl FnMut(&[FilterRule]) -> Result<(), String>,
    ) -> Result<ChangedFilterRule> {
        // As in `add_webhook_filter_rule`: a pass ends with a write or an answer, or starts
        // again when another change came first.
        loop {
            let Some(seen) = self.webhook_filter_rules_version(account).await? else {
                return Ok(ChangedFilterRule::NotFound);
            };
            let mut rules = self.webhook_filter_rules(account, limit).await?;
            let Some(index) = rules.iter().position(|rule| rule.id == id) else {
                return Ok(ChangedFilterRule::NotFound);
            };
            // Only this rule changes in the view: the others keep the `active` they were read
            // with, so a rule that is off stays inactive.
            let changed = &mut rules[index];
            match edit {
                None => {
                    changed.enabled = true;
                    changed.active = index < limit;
                }
                Some((new, _)) => {
                    changed.action.clone_from(&new.action);
                    changed.field.clone_from(&new.field);
                    changed.kind.clone_from(&new.kind);
                    changed.pattern.clone_from(&new.pattern);
                }
            }
            if let Err(reason) = check(&rules) {
                return Ok(ChangedFilterRule::Refused(reason));
            }
            let mut tx = self.begin_write().await?;
            let counted = sqlx::query(
                "UPDATE webhooks SET filter_rules_version = filter_rules_version + 1 \
                 WHERE account_id = $1 AND filter_rules_version = $2",
            )
            .bind(&account.0)
            .bind(seen)
            .execute(&mut *tx)
            .await?;
            if counted.rows_affected() == 0 {
                tx.rollback().await?;
                continue;
            }
            let write = match edit {
                None => sqlx::query(
                    "UPDATE webhook_filter_rules SET enabled = 1 WHERE account_id = $1 AND id = $2",
                )
                .bind(&account.0)
                .bind(id),
                Some((new, pattern)) => sqlx::query(
                    "UPDATE webhook_filter_rules SET action = $3, field = $4, kind = $5, \
                     pattern_ciphertext = $6 WHERE account_id = $1 AND id = $2",
                )
                .bind(&account.0)
                .bind(id)
                .bind(&new.action)
                .bind(&new.field)
                .bind(&new.kind)
                .bind(pattern),
            };
            write.execute(&mut *tx).await?;
            tx.commit().await?;
            return Ok(ChangedFilterRule::Changed);
        }
    }

    /// Removes one rule of a mailbox. `false` means it has no such rule. The
    /// limit does not matter: removing always works.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn remove_webhook_filter_rule(&self, account: &AccountId, id: &str) -> Result<bool> {
        Ok(self.remove_filter_rules(account, Some(id)).await? > 0)
    }

    /// Removes every rule of a mailbox, and returns how many there were.
    ///
    /// # Errors
    ///
    /// Returns an error if a query fails.
    pub async fn remove_webhook_filter_rules(&self, account: &AccountId) -> Result<u64> {
        self.remove_filter_rules(account, None).await
    }

    async fn remove_filter_rules(&self, account: &AccountId, id: Option<&str>) -> Result<u64> {
        let mut tx = self.begin_write().await?;
        // The webhook's row first, as `delete_webhook` and `delete_account` take it: PostgreSQL
        // aborts one of two writers that take it and the rules in opposite orders. A removal
        // that removes nothing is rolled back, count and all.
        sqlx::query(
            "UPDATE webhooks SET filter_rules_version = filter_rules_version + 1 \
             WHERE account_id = $1",
        )
        .bind(&account.0)
        .execute(&mut *tx)
        .await?;
        let removed = match id {
            Some(id) => {
                sqlx::query("DELETE FROM webhook_filter_rules WHERE account_id = $1 AND id = $2")
                    .bind(&account.0)
                    .bind(id)
                    .execute(&mut *tx)
                    .await?
            }
            None => {
                sqlx::query("DELETE FROM webhook_filter_rules WHERE account_id = $1")
                    .bind(&account.0)
                    .execute(&mut *tx)
                    .await?
            }
        }
        .rows_affected();
        if removed == 0 {
            tx.rollback().await?;
            return Ok(0);
        }
        tx.commit().await?;
        Ok(removed)
    }

    /// How many times the rules of a mailbox changed (added, removed, changed,
    /// or turned on or off), or `None` if the account has no webhook. A watcher that read the rules at
    /// one count reads them again when it has changed; it reads the count
    /// first, so a change in between shows at the next look. The limit does
    /// not change the count.
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn webhook_filter_rules_version(&self, account: &AccountId) -> Result<Option<i64>> {
        let row = sqlx::query("SELECT filter_rules_version FROM webhooks WHERE account_id = $1")
            .bind(&account.0)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row
            .map(|row| row.try_get("filter_rules_version"))
            .transpose()?)
    }
}
