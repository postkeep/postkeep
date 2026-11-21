//! The webhook filter rule tools: list, add and remove the rules that choose
//! which new mail calls the webhook.

use axum::http::request::Parts;
use postkeep_auth::{UnreadableRules, parse_filter_rules};
use postkeep_store::{AddedFilterRule, FilterRule, NewFilterRule, StoreError};
use postkeep_webhook::filter::{Action, CompiledRules, Field, Kind, Rule};
use schemars::JsonSchema;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::{
    DEFAULT_LIMIT, FilterRuleCounts, MAX_LIMIT, MailTools, WebhookProblemKind, next_page_offset,
    rfc3339, webhook_store_error,
};

/// Parameters for `list_webhook_filters`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListWebhookFiltersParams {
    /// Number of oldest rules to skip, for paging.
    #[serde(default)]
    pub offset: usize,
    /// Maximum number of rules to return (default 20, maximum 100).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Parameters for `add_webhook_filter`. No `Debug`: the pattern can hold
/// addresses and names.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddWebhookFilterParams {
    /// What a match does.
    #[schemars(with = "ActionWire")]
    pub action: Action,
    /// The part of a new message that is compared.
    #[schemars(with = "FieldWire")]
    pub field: Field,
    /// How the pattern is compared.
    #[schemars(with = "KindWire")]
    pub kind: Kind,
    /// 1 to 512 bytes. Matching ignores case.
    pub pattern: String,
}

/// Schema stand-in: what a rule does to mail that matches it.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(
    dead_code,
    reason = "the variants exist so the MCP schema lists the names"
)]
enum ActionWire {
    /// Once the mailbox has an active allow rule, only mail that matches one calls the webhook.
    Allow,
    /// Mail that matches never calls the webhook, whatever else matches.
    Block,
}

/// Schema stand-in: the part of a new message a rule compares.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(
    dead_code,
    reason = "the variants exist so the MCP schema lists the names"
)]
enum FieldWire {
    /// The sender's address.
    From,
    /// The sender's domain: what follows the last @.
    FromDomain,
    /// The addresses in To and Cc; the rule matches if any does.
    To,
    /// The decoded subject.
    Subject,
}

/// Schema stand-in: how a rule compares its pattern.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
#[allow(
    dead_code,
    reason = "the variants exist so the MCP schema lists the names"
)]
enum KindWire {
    /// The whole text is the pattern.
    Equals,
    /// The text contains the pattern.
    Contains,
    /// The address's domain, or the domain itself, is the pattern or a
    /// subdomain of it. A plain domain such as example.com; not for subject.
    Domain,
    /// A regular expression in Rust syntax, without look-around or back-references.
    Regex,
}

/// Parameters for `remove_webhook_filter`: exactly one of `id` or `all`.
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoveWebhookFilterParams {
    /// The id of the rule to remove, from `list_webhook_filters`.
    #[serde(default)]
    pub id: Option<String>,
    /// `true` removes every rule of the mailbox.
    #[serde(default)]
    pub all: bool,
}

/// One filter rule, with its names as stored.
#[derive(Debug, Serialize, JsonSchema)]
pub struct WebhookFilter {
    /// The rule's id, for `remove_webhook_filter`.
    pub id: String,
    /// `allow` or `block`.
    pub action: String,
    /// `from`, `from_domain`, `to` or `subject`.
    pub field: String,
    /// `equals`, `contains`, `domain` or `regex`.
    pub kind: String,
    /// The pattern.
    pub pattern: String,
    /// When it was added, RFC 3339.
    pub added_at: String,
    /// Whether it is turned on. A rule turned off judges nothing, but keeps its
    /// place and counts toward the limit.
    pub enabled: bool,
    /// Whether it judges new mail: it is turned on and among the oldest rules,
    /// as many as the limit.
    pub active: bool,
}

/// Result of `list_webhook_filters`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct WebhookFilterList {
    /// Offset of the first returned rule.
    pub offset: usize,
    /// Rules, oldest first.
    pub filters: Vec<WebhookFilter>,
    /// Offset for the next page, if there are more rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// The counts of all the mailbox's rules.
    #[serde(flatten)]
    #[schemars(flatten)]
    pub counts: FilterRuleCounts,
}

/// Result of `add_webhook_filter`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct WebhookFilterAdded {
    /// The new rule's id.
    pub id: String,
    /// The counts with the new rule.
    #[serde(flatten)]
    #[schemars(flatten)]
    pub counts: FilterRuleCounts,
}

/// Result of `remove_webhook_filter`.
#[derive(Debug, Serialize, JsonSchema)]
pub struct WebhookFilterRemoval {
    /// How many rules were removed.
    pub removed: u64,
}

/// Runs `work` off the async workers of a multi-thread runtime, and in place
/// on any other, where `block_in_place` panics.
fn off_runtime<T>(work: impl FnOnce() -> T) -> T {
    use tokio::runtime::{Handle, RuntimeFlavor};
    let flavor = Handle::try_current().map(|handle| handle.runtime_flavor());
    if matches!(flavor, Ok(RuntimeFlavor::MultiThread)) {
        tokio::task::block_in_place(work)
    } else {
        work()
    }
}

/// The name serde gives `value`, which the watchers parse back.
fn stored_name(value: impl Serialize) -> String {
    let value = serde_json::to_value(value).ok();
    value
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

impl MailTools {
    /// The body of `list_webhook_filters`.
    pub(super) async fn list_filters(
        &self,
        parts: &Parts,
        params: ListWebhookFiltersParams,
    ) -> Result<WebhookFilterList, String> {
        let account = Self::require_account(parts)?;
        let limit = self.mailbox_limits(parts, &account).await.filter_rules;
        let store = &self.context.store;
        if store
            .webhook_filter_rules_version(&account)
            .await
            .map_err(webhook_store_error)?
            .is_none()
        {
            return Err(self.problem_words(parts, &account, &WebhookProblemKind::NoWebhook));
        }
        let rules = match store.webhook_filter_rules(&account, limit).await {
            Ok(rules) => rules,
            Err(StoreError::Decrypt) => {
                let kind = WebhookProblemKind::RulesUndecryptable;
                return Err(self.problem_words(parts, &account, &kind));
            }
            Err(err) => return Err(webhook_store_error(err)),
        };
        let page = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let filters: Vec<_> = rules
            .iter()
            .skip(params.offset)
            .take(page)
            .map(|rule| WebhookFilter {
                id: rule.id.clone(),
                action: rule.action.clone(),
                field: rule.field.clone(),
                kind: rule.kind.clone(),
                pattern: rule.pattern.expose_secret().to_owned(),
                added_at: rfc3339(rule.added_at).unwrap_or_default(),
                enabled: rule.enabled,
                active: rule.active,
            })
            .collect();
        let end = params.offset.saturating_add(filters.len());
        Ok(WebhookFilterList {
            offset: params.offset,
            next_offset: next_page_offset(params.offset, filters.len(), end < rules.len()),
            filters,
            counts: FilterRuleCounts::of(&rules, limit).0,
        })
    }

    /// The body of `add_webhook_filter`.
    pub(super) async fn add_filter(
        &self,
        parts: &Parts,
        params: AddWebhookFilterParams,
    ) -> Result<WebhookFilterAdded, String> {
        let account = Self::require_account(parts)?;
        let limit = self.mailbox_limits(parts, &account).await.filter_rules;
        let rule = Rule {
            action: params.action,
            field: params.field,
            kind: params.kind,
            pattern: params.pattern,
        };
        off_runtime(|| rule.validate()).map_err(|error| error.to_string())?;
        let new = NewFilterRule {
            action: stored_name(rule.action),
            field: stored_name(rule.field),
            kind: stored_name(rule.kind),
            pattern: SecretString::from(rule.pattern.clone()),
        };
        let (mut seen, mut active) = (0, 0);
        let check = |stored: &[FilterRule]| {
            seen = stored.len();
            active = stored.iter().filter(|rule| rule.active).count();
            let mut rules = parse_filter_rules(stored).ok_or_else(|| {
                let kind = WebhookProblemKind::Rules(UnreadableRules::UnknownName);
                self.problem_words(parts, &account, &kind)
            })?;
            rules.push(rule.clone());
            let compiled = off_runtime(|| CompiledRules::new(&rules, limit));
            compiled.map(drop).map_err(|error| error.to_string())
        };
        let added = self
            .context
            .store
            .add_webhook_filter_rule(&account, &new, limit, check);
        let id = match added.await {
            Ok(AddedFilterRule::Added(id)) => id,
            Ok(AddedFilterRule::AtLimit) => {
                return Err(format!(
                    "This mailbox may have at most {limit} filter rules."
                ));
            }
            Ok(AddedFilterRule::Refused(reason)) => return Err(reason),
            Ok(AddedFilterRule::NoWebhook) => {
                return Err(self.problem_words(parts, &account, &WebhookProblemKind::NoWebhook));
            }
            Err(StoreError::Decrypt) => {
                let kind = WebhookProblemKind::RulesUndecryptable;
                return Err(self.problem_words(parts, &account, &kind));
            }
            Err(err) => return Err(webhook_store_error(err)),
        };
        // A watcher that its rules stopped starts again, and records the mail it held.
        if let Some(control) = &self.context.webhooks {
            (control.changed)(&account);
        }
        // The store adds only under the limit, so the new rule is active and the
        // stored ones that are not are exactly those turned off.
        let counts = FilterRuleCounts {
            filter_rules_active: active + 1,
            filter_rules_disabled: seen - active,
            filter_rules_limit: limit,
            filter_rules_unreadable: false,
        };
        Ok(WebhookFilterAdded { id, counts })
    }

    /// The body of `remove_webhook_filter`.
    pub(super) async fn remove_filter(
        &self,
        parts: &Parts,
        params: RemoveWebhookFilterParams,
    ) -> Result<WebhookFilterRemoval, String> {
        let account = Self::require_account(parts)?;
        let id = match (params.id, params.all) {
            (Some(id), false) => Some(id),
            (None, true) => None,
            _ => return Err("Give either id or all: true.".to_owned()),
        };
        let store = &self.context.store;
        if store
            .webhook_filter_rules_version(&account)
            .await
            .map_err(webhook_store_error)?
            .is_none()
        {
            return Err(self.problem_words(parts, &account, &WebhookProblemKind::NoWebhook));
        }
        let removed = match id {
            Some(id) => store
                .remove_webhook_filter_rule(&account, &id)
                .await
                .map(u64::from),
            None => store.remove_webhook_filter_rules(&account).await,
        }
        .map_err(webhook_store_error)?;
        // Rules that stopped a watcher may be gone: it starts again.
        if removed > 0
            && let Some(control) = &self.context.webhooks
        {
            (control.changed)(&account);
        }
        Ok(WebhookFilterRemoval { removed })
    }
}
