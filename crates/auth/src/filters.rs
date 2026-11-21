//! The filter rules in the account page's Webhook section.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, LazyLock, Mutex, OnceLock, PoisonError};

use axum::Form;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::HeaderMap;
use axum::response::Response;
use postkeep_mail::invisible::hidden;
use postkeep_store::{
    AccountId, AddedFilterRule, ChangedFilterRule, FilterRule, NewFilterRule, Store, StoreError,
};
use postkeep_webhook::filter::{Action, CompiledRules, Field, Kind, Rule, RuleError};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::account::{ACCOUNT_PATH, Session, see_other};
use crate::state::AuthState;
use crate::webhook::{self, CardForm, OutboxRules, Time};

/// What the Filter rules block shows.
#[derive(Debug, Default)]
pub enum FilterList {
    /// No webhook is saved, so there is no block.
    #[default]
    NoWebhook,
    /// A pattern can't be decrypted.
    Unreadable,
    /// The mailbox's rules, oldest first.
    Rules(FilterRules),
}

/// A mailbox's rules and how many of them count.
#[derive(Debug)]
pub struct FilterRules {
    /// Oldest first, the order that decides which rules count.
    pub rules: Vec<FilterRuleView>,
    /// How many of the oldest rules count.
    pub limit: usize,
    /// The Add a rule form.
    pub add_form: FilterFormView,
}

impl FilterRules {
    /// The block's summary: `None`, `1 rule` or `{n} rules`.
    #[must_use]
    pub fn summary(&self) -> String {
        match self.rules.len() {
            0 => "None".to_owned(),
            1 => "1 rule".to_owned(),
            n => format!("{n} rules"),
        }
    }

    /// Whether some rules are past the limit.
    #[must_use]
    pub const fn past_limit(&self) -> bool {
        self.rules.len() > self.limit
    }

    /// Whether a form in the block was refused, so the block opens.
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.add_form.error.is_some() || self.rules.iter().any(|rule| rule.form.error.is_some())
    }

    /// What the block says when its rules hold new mail: why, from the first
    /// rule that holds it.
    #[must_use]
    pub fn unreadable_text(&self) -> Option<&'static str> {
        let problem = self.rules.iter().find_map(|rule| rule.problem)?;
        Some(match problem {
            RuleProblem::UnknownName => {
                "A rule that's on has an action, field or kind this server doesn't know, so new mail waits and doesn't call the webhook. Turn off or remove each rule marked Can't be read."
            }
            RuleProblem::WontCompile => {
                "A rule that's on doesn't compile on this server, so new mail waits and doesn't call the webhook. Turn off or remove the rule marked Doesn't compile."
            }
            RuleProblem::TooLarge => {
                "A rule that's on doesn't fit with the older rules that are on: together they're too large to compile, so new mail waits and doesn't call the webhook. Turn off or remove the rule marked Doesn't compile."
            }
        })
    }
}

/// A rule form's values, as stored or as posted.
pub struct FilterFormView {
    /// The edited rule, `None` for the add form.
    pub id: Option<String>,
    /// The stored or posted action name.
    pub action: String,
    /// The stored or posted field name.
    pub field: String,
    /// The stored or posted kind name.
    pub kind: String,
    /// The pattern field's value.
    pub pattern: String,
    /// Why the form was refused, with nothing stored.
    pub error: Option<String>,
    /// Why the pattern isn't filled in.
    pub note: Option<&'static str>,
}

impl FilterFormView {
    /// The add form's start: block, from, equals, no pattern.
    fn blank() -> Self {
        Self {
            id: None,
            action: "block".to_owned(),
            field: "from".to_owned(),
            kind: "equals".to_owned(),
            pattern: String::new(),
            error: None,
            note: None,
        }
    }

    /// The edit form of a stored rule. A pattern that isn't [`plain`] isn't
    /// filled in, so the page never carries such a character raw.
    fn stored(rule: &FilterRule) -> Self {
        let raw = rule.pattern.expose_secret();
        let (pattern, note) = if plain(raw) {
            (raw.to_owned(), None)
        } else {
            (String::new(), Some(STORED_NOTE))
        };
        Self {
            id: Some(rule.id.clone()),
            action: rule.action.clone(),
            field: rule.field.clone(),
            kind: rule.kind.clone(),
            pattern,
            error: None,
            note,
        }
    }

    /// The ID of the form's element `name`: `filter-{rule id, or new}-{name}`.
    #[must_use]
    pub fn dom_id(&self, name: &str) -> String {
        format!("filter-{}-{name}", self.id.as_deref().unwrap_or("new"))
    }
}

// The pattern can hold addresses and names, as `Rule`'s Debug leaves out.
impl fmt::Debug for FilterFormView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilterFormView")
            .field("id", &self.id)
            .field("action", &self.action)
            .field("field", &self.field)
            .field("kind", &self.kind)
            .field("error", &self.error)
            .field("note", &self.note)
            .finish_non_exhaustive()
    }
}

/// The note for a typed pattern that isn't filled in again.
const TYPED_NOTE: &str = "The pattern you typed has characters that don't show, so it isn't filled in again. Type or paste it again.";

/// The note for a stored pattern that isn't filled in.
const STORED_NOTE: &str = "This pattern has characters that don't show, written as \\u{…} in the rule, so it isn't filled in. Type it again to change this rule.";

/// A piece of a pattern as the account page draws it.
pub enum PatternPart {
    /// Characters drawn as they are.
    Text(String),
    /// One character that would hide or reorder text, as a `\u{…}` escape.
    Escape(String),
}

/// Why a rule that judges mail holds the mailbox's new mail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleProblem {
    /// Its action, field or kind is one this version doesn't know.
    UnknownName,
    /// It is the rule [`UnreadableRules::WontCompile`] names, and it doesn't
    /// compile on its own.
    WontCompile,
    /// It is the rule [`UnreadableRules::WontCompile`] names, and the rules
    /// up to it are too large together.
    TooLarge,
}

/// One rule's row.
pub struct FilterRuleView {
    /// The rule's ID, for its forms.
    pub id: String,
    /// As stored.
    pub action: String,
    /// As stored.
    pub field: String,
    /// As stored.
    pub kind: String,
    /// The pattern in parts, with characters that would hide or reorder text as escapes.
    pub pattern: Vec<PatternPart>,
    /// When it was added.
    pub added: Time,
    /// Whether the rule is on.
    pub enabled: bool,
    /// Whether it judges new mail: on and inside the limit.
    pub active: bool,
    /// Why it holds new mail, if it does.
    pub problem: Option<RuleProblem>,
    /// The Edit form.
    pub form: FilterFormView,
}

impl FilterRuleView {
    /// `Off`, `Can't be read`, `Doesn't compile`, `On` or `Past the limit`;
    /// off wins, then why it holds new mail.
    #[must_use]
    pub const fn state_label(&self) -> &'static str {
        match (self.enabled, self.problem, self.active) {
            (false, ..) => "Off",
            (true, Some(RuleProblem::UnknownName), _) => "Can't be read",
            (true, Some(RuleProblem::WontCompile | RuleProblem::TooLarge), _) => "Doesn't compile",
            (true, None, true) => "On",
            (true, None, false) => "Past the limit",
        }
    }

    /// The badge class for [`Self::state_label`].
    #[must_use]
    pub const fn state_badge(&self) -> &'static str {
        match (self.enabled, self.problem, self.active) {
            (false, ..) => "badge--muted",
            (true, Some(_), _) => "badge--danger",
            (true, None, true) => "badge--success",
            (true, None, false) => "badge--warning",
        }
    }
}

impl From<&FilterRule> for FilterRuleView {
    fn from(rule: &FilterRule) -> Self {
        Self {
            id: rule.id.clone(),
            action: rule.action.clone(),
            field: rule.field.clone(),
            kind: rule.kind.clone(),
            pattern: parts(rule.pattern.expose_secret()),
            added: Time::new(rule.added_at),
            enabled: rule.enabled,
            active: rule.active,
            problem: None,
            form: FilterFormView::stored(rule),
        }
    }
}

// The pattern can hold addresses and names, as `Rule`'s Debug leaves out.
impl fmt::Debug for FilterRuleView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilterRuleView")
            .field("action", &self.action)
            .field("field", &self.field)
            .field("kind", &self.kind)
            .field("added", &self.added)
            .field("enabled", &self.enabled)
            .field("active", &self.active)
            .field("problem", &self.problem)
            .finish_non_exhaustive()
    }
}

/// Whether the list shows `c` as an escape: a control or [`hidden`] character.
fn escaped(c: char) -> bool {
    c.is_control() || hidden(c)
}

/// Splits `pattern` into text and escapes for control or hidden characters.
/// Embedders can draw patterns as the account page does, without invisible
/// characters hiding or reordering text.
#[must_use]
pub fn parts(pattern: &str) -> Vec<PatternPart> {
    let mut parts = Vec::new();
    let mut text = String::new();
    for c in pattern.chars() {
        if escaped(c) {
            if !text.is_empty() {
                parts.push(PatternPart::Text(std::mem::take(&mut text)));
            }
            parts.push(PatternPart::Escape(c.escape_unicode().to_string()));
        } else {
            text.push(c);
        }
    }
    if !text.is_empty() {
        parts.push(PatternPart::Text(text));
    }
    parts
}

/// Whether `pattern` has no control or hidden characters and may fill an input.
/// Embedders can apply the account page's rule when filling pattern inputs.
#[must_use]
pub fn plain(pattern: &str) -> bool {
    !pattern.chars().any(escaped)
}

/// The block for `account`, with the oldest `limit` rules counting.
pub async fn load(
    store: &Store,
    account: &AccountId,
    limit: usize,
) -> Result<FilterList, StoreError> {
    if store.webhook_filter_rules_version(account).await?.is_none() {
        return Ok(FilterList::NoWebhook);
    }
    let rules = match store.webhook_filter_rules(account, limit).await {
        Ok(rules) => rules,
        Err(StoreError::Decrypt) => return Ok(FilterList::Unreadable),
        Err(error) => return Err(error),
    };
    let unreadable = unreadable_rules(&rules, limit);
    let problem = |rule: &FilterRule| match &unreadable {
        Some(UnreadableRules::UnknownName)
            if parse_filter_rules(std::slice::from_ref(rule)).is_none() =>
        {
            Some(RuleProblem::UnknownName)
        }
        Some(UnreadableRules::WontCompile { id, alone }) if *id == rule.id => Some(if *alone {
            RuleProblem::WontCompile
        } else {
            RuleProblem::TooLarge
        }),
        _ => None,
    };
    let view = |rule| FilterRuleView {
        problem: problem(rule),
        ..FilterRuleView::from(rule)
    };
    Ok(FilterList::Rules(FilterRules {
        rules: rules.iter().map(view).collect(),
        limit,
        add_form: FilterFormView::blank(),
    }))
}

/// The Remove and Remove all forms.
#[derive(Deserialize)]
pub struct RemoveFilterForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    id: String,
    /// `yes` removes every rule.
    #[serde(default)]
    all: String,
}

impl CardForm for RemoveFilterForm {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// `POST /account/webhook/filters/remove`
pub async fn remove(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<RemoveFilterForm>, FormRejection>,
) -> Response {
    let (session, form) = match webhook::authorize(&state, &headers, form).await {
        Ok(authorized) => authorized,
        Err(response) => return *response,
    };
    let account = &session.account.id;
    let all = form.all == "yes";
    // Scoped to the session's account: another mailbox's rule ID removes nothing.
    let removed = if all {
        state.store().remove_webhook_filter_rules(account).await
    } else {
        state
            .store()
            .remove_webhook_filter_rule(account, &form.id)
            .await
            .map(u64::from)
    };
    let removed = match removed {
        Ok(removed) => removed,
        Err(err) => return webhook::storage_error(&err),
    };
    if removed == 0 {
        return see_other(&format!("{ACCOUNT_PATH}?notice=filter-gone#filters"));
    }
    tracing::info!(account_id = %account, removed, "webhook filter rules removed");
    state.notify_account_changed(account);
    let key = if all {
        "filters-removed"
    } else {
        "filter-removed"
    };
    see_other(&format!("{ACCOUNT_PATH}?notice={key}#filters"))
}

/// The rules that judge new mail (`active`: on and inside the limit), or `None`
/// if one of them has an action, field or kind this version does not know.
#[must_use]
pub fn parse_filter_rules(stored: &[FilterRule]) -> Option<Vec<Rule>> {
    let rule = |r: &FilterRule| {
        let (action, field, kind) = (&r.action, &r.field, &r.kind);
        let pattern = r.pattern.expose_secret();
        let json =
            serde_json::json!({"action": action, "field": field, "kind": kind, "pattern": pattern});
        serde_json::from_value(json).ok()
    };
    stored.iter().filter(|r| r.active).map(rule).collect()
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

/// Why the rules that would judge mail were refused.
enum SetRefusal {
    /// One has an action, field or kind this version doesn't know.
    UnknownName,
    /// They don't compile together.
    WontCompile(RuleError),
}

/// The rules that judge mail in `rules`, plus `extra`, must all be known and
/// compile together.
fn set_check(rules: &[FilterRule], extra: Option<&Rule>, limit: usize) -> Result<(), SetRefusal> {
    let mut active = parse_filter_rules(rules).ok_or(SetRefusal::UnknownName)?;
    active.extend(extra.cloned());
    let compiled = off_runtime(|| CompiledRules::new(&active, limit));
    compiled.map(drop).map_err(SetRefusal::WontCompile)
}

/// Why a mailbox's filter rules can't judge its new mail, which then waits.
/// Patterns that can't be decrypted are the store's [`StoreError::Decrypt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnreadableRules {
    /// A rule that judges mail has an action, field or kind this version
    /// doesn't know.
    UnknownName,
    /// The rules that judge mail don't compile together.
    WontCompile {
        /// The oldest of them that doesn't compile with the ones before it.
        id: String,
        /// Whether it doesn't compile on its own either. If it does, the
        /// rules are too large together.
        alone: bool,
    },
}

/// How many answers of [`unreadable_rules`] are kept, each about 200 bytes
/// with its key. The oldest goes first.
const KEPT_ANSWERS: usize = 4_096;

/// An answer of [`unreadable_rules`], worked out once for every caller.
type Answer = Arc<OnceLock<Option<UnreadableRules>>>;

/// Kept answers of [`unreadable_rules`], each under the digest of what it read
/// ([`answer_key`]), and those digests oldest first.
#[derive(Default)]
struct Answers {
    by_key: HashMap<[u8; 32], Answer>,
    order: VecDeque<[u8; 32]>,
}

impl Answers {
    /// The answer kept under `key`, or a new one to work out, which drops the
    /// oldest past [`KEPT_ANSWERS`].
    fn slot(&mut self, key: [u8; 32]) -> Answer {
        if let Some(answer) = self.by_key.get(&key) {
            return Arc::clone(answer);
        }
        let answer = Answer::default();
        self.by_key.insert(key, Arc::clone(&answer));
        self.order.push_back(key);
        if self.order.len() > KEPT_ANSWERS
            && let Some(oldest) = self.order.pop_front()
        {
            self.by_key.remove(&oldest);
        }
        answer
    }
}

/// The answers of [`unreadable_rules`] on this server.
static ANSWERS: LazyLock<Mutex<Answers>> = LazyLock::new(Mutex::default);

/// A digest of what [`unreadable_rules`] reads: `limit`, then the id, action,
/// field, kind and pattern of each rule that judges mail, oldest first, each
/// after its length, so that two different inputs never give the same bytes.
fn answer_key(stored: &[FilterRule], limit: usize) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(limit.to_le_bytes());
    for rule in stored.iter().filter(|rule| rule.active) {
        let parts = [
            rule.id.as_str(),
            rule.action.as_str(),
            rule.field.as_str(),
            rule.kind.as_str(),
            rule.pattern.expose_secret(),
        ];
        for part in parts {
            digest.update(part.len().to_le_bytes());
            digest.update(part);
        }
    }
    digest.finalize().into()
}

/// What keeps the rules that judge mail in `stored`, with the oldest `limit`
/// counting, from judging it as the watchers do, or `None` when nothing does.
///
/// It compiles them off the async workers, once for the same rules and limit:
/// the answer is kept, and a caller that asks while it is worked out waits for
/// it.
#[must_use]
pub fn unreadable_rules(stored: &[FilterRule], limit: usize) -> Option<UnreadableRules> {
    let compiles = |rules: &[Rule]| CompiledRules::new(rules, limit).is_ok();
    kept_answer(&ANSWERS, stored, limit, compiles)
}

/// [`unreadable_rules`] with the answers kept in `answers`, and `compiles`
/// saying whether rules compile together.
fn kept_answer(
    answers: &Mutex<Answers>,
    stored: &[FilterRule],
    limit: usize,
    compiles: impl Fn(&[Rule]) -> bool,
) -> Option<UnreadableRules> {
    if !stored.iter().any(|rule| rule.active) {
        return None;
    }
    let key = answer_key(stored, limit);
    let answer = answers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .slot(key);
    // The first caller works the answer out; the others wait for it.
    off_runtime(|| answer.get_or_init(|| judged(stored, compiles)).clone())
}

/// What [`unreadable_rules`] answers for `stored`, compiling with `compiles`.
fn judged(stored: &[FilterRule], compiles: impl Fn(&[Rule]) -> bool) -> Option<UnreadableRules> {
    let Some(rules) = parse_filter_rules(stored) else {
        return Some(UnreadableRules::UnknownName);
    };
    if compiles(&rules) {
        return None;
    }
    // The oldest `fits` rules compile together and the oldest `fails` don't.
    let (mut fits, mut fails) = (0, rules.len());
    while fails - fits > 1 {
        let half = fits + (fails - fits) / 2;
        if compiles(&rules[..half]) {
            fits = half;
        } else {
            fails = half;
        }
    }
    let rule = stored.iter().filter(|rule| rule.active).nth(fits)?;
    let alone = !compiles(&rules[fits..fails]);
    Some(UnreadableRules::WontCompile {
        id: rule.id.clone(),
        alone,
    })
}

/// A refusal of [`set_check`] as a sentence for the form.
fn refusal_text(refusal: SetRefusal) -> String {
    match refusal {
        SetRefusal::UnknownName => "A rule that's on has an action, field or kind this server doesn't know. Turn that rule off or remove it, then try again.".to_owned(),
        SetRefusal::WontCompile(error) => webhook::capitalize(&error.to_string()),
    }
}

/// The check of a turn-on, on the rules as they would be. The refusal is a
/// notice key.
fn turn_on_check(rules: &[FilterRule], limit: usize) -> Result<(), String> {
    set_check(rules, None, limit).map_err(|refusal| {
        match refusal {
            SetRefusal::UnknownName => "filter-unknown",
            SetRefusal::WontCompile(_) => "filter-wont-compile",
        }
        .to_owned()
    })
}

/// The check of an edit: the changed rule, from the store's view `after`, is
/// compiled with the rules that judge mail as an add is, even while it is off.
fn edit_check(after: &[FilterRule], id: &str, rule: &Rule, limit: usize) -> Result<(), String> {
    let others: Vec<FilterRule> = after.iter().filter(|r| r.id != id).cloned().collect();
    set_check(&others, Some(rule), limit).map_err(refusal_text)
}

/// The name serde gives `value`, which the watchers parse back.
fn stored_name(value: impl Serialize) -> String {
    let value = serde_json::to_value(value).ok();
    value
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// `rule` as the store takes it, with the names the tools store.
fn new_rule(rule: &Rule) -> NewFilterRule {
    NewFilterRule {
        action: stored_name(rule.action),
        field: stored_name(rule.field),
        kind: stored_name(rule.kind),
        pattern: SecretString::from(rule.pattern.clone()),
    }
}

/// The Add a rule and Edit forms. A name outside the lists doesn't parse.
#[derive(Deserialize)]
pub struct FilterRuleForm {
    #[serde(default)]
    csrf_token: String,
    /// The edited rule; the add form has none.
    #[serde(default)]
    id: String,
    action: Action,
    field: Field,
    kind: Kind,
    // Not trimmed: spaces are part of a pattern.
    #[serde(default)]
    pattern: String,
}

impl CardForm for FilterRuleForm {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

impl FilterRuleForm {
    /// The posted rule, checked on its own as the tools check it.
    fn rule(&self) -> Result<Rule, String> {
        let rule = Rule {
            action: self.action,
            field: self.field,
            kind: self.kind,
            pattern: self.pattern.clone(),
        };
        off_runtime(|| rule.validate()).map_err(|error| webhook::capitalize(&error.to_string()))?;
        Ok(rule)
    }

    /// The form shown again with `error`. A pattern that isn't [`plain`] comes
    /// back empty, so the page never carries such a character raw.
    fn view(&self, id: Option<String>, error: String) -> FilterFormView {
        let (pattern, note) = if plain(&self.pattern) {
            (self.pattern.clone(), None)
        } else {
            (String::new(), Some(TYPED_NOTE))
        };
        FilterFormView {
            id,
            action: stored_name(self.action),
            field: stored_name(self.field),
            kind: stored_name(self.kind),
            pattern,
            error: Some(error),
            note,
        }
    }
}

/// `POST /account/webhook/filters/add`
pub async fn add(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<FilterRuleForm>, FormRejection>,
) -> Response {
    let (session, form) = match webhook::authorize(&state, &headers, form).await {
        Ok(authorized) => authorized,
        Err(response) => return *response,
    };
    let account = &session.account.id;
    let rules = OutboxRules::for_account(&state, account).await;
    let limit = rules.filter_rules;
    let rule = match form.rule() {
        Ok(rule) => rule,
        Err(error) => return shown_again(&state, &session, rules, form.view(None, error)).await,
    };
    let check = |stored: &[FilterRule]| set_check(stored, Some(&rule), limit).map_err(refusal_text);
    let added = state
        .store()
        .add_webhook_filter_rule(account, &new_rule(&rule), limit, check)
        .await;
    let reason = match added {
        Ok(AddedFilterRule::Added(_)) => {
            tracing::info!(account_id = %account, "webhook filter rule added");
            state.notify_account_changed(account);
            return see_other(&format!("{ACCOUNT_PATH}?notice=filter-added#filters"));
        }
        Ok(AddedFilterRule::AtLimit) => {
            format!("This mailbox may have at most {limit} filter rules.")
        }
        Ok(AddedFilterRule::Refused(reason)) => reason,
        // The block then shows its unreadable state, or isn't there.
        Ok(AddedFilterRule::NoWebhook) | Err(StoreError::Decrypt) => {
            return see_other(&format!("{ACCOUNT_PATH}#filters"));
        }
        Err(err) => return webhook::storage_error(&err),
    };
    shown_again(&state, &session, rules, form.view(None, reason)).await
}

/// `POST /account/webhook/filters/edit`
pub async fn edit(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<FilterRuleForm>, FormRejection>,
) -> Response {
    let (session, form) = match webhook::authorize(&state, &headers, form).await {
        Ok(authorized) => authorized,
        Err(response) => return *response,
    };
    let account = &session.account.id;
    let rules = OutboxRules::for_account(&state, account).await;
    let limit = rules.filter_rules;
    let id = Some(form.id.clone());
    let rule = match form.rule() {
        Ok(rule) => rule,
        Err(error) => return shown_again(&state, &session, rules, form.view(id, error)).await,
    };
    let check = |after: &[FilterRule]| edit_check(after, &form.id, &rule, limit);
    // Scoped to the session's account: another mailbox's rule ID changes nothing.
    let changed = state
        .store()
        .update_webhook_filter_rule(account, &form.id, &new_rule(&rule), limit, check)
        .await;
    let reason = match changed {
        Ok(ChangedFilterRule::Changed) => {
            tracing::info!(account_id = %account, "webhook filter rule changed");
            state.notify_account_changed(account);
            return see_other(&format!("{ACCOUNT_PATH}?notice=filter-saved#filters"));
        }
        Ok(ChangedFilterRule::Refused(reason)) => reason,
        Ok(ChangedFilterRule::NotFound) => {
            return see_other(&format!("{ACCOUNT_PATH}?notice=filter-gone#filters"));
        }
        // The block then shows its unreadable state.
        Err(StoreError::Decrypt) => return see_other(&format!("{ACCOUNT_PATH}#filters")),
        Err(err) => return webhook::storage_error(&err),
    };
    shown_again(&state, &session, rules, form.view(id, reason)).await
}

/// The page again (400) with `form` open in the block and nothing stored, or
/// the block as it is when it can't show the form. An edit of a rule that's
/// gone goes to `filter-gone`.
async fn shown_again(
    state: &AuthState,
    session: &Session,
    rules: OutboxRules,
    form: FilterFormView,
) -> Response {
    let mut view = match webhook::load_view_with(state, &session.account.id, rules).await {
        Ok(view) => view,
        Err(err) => return webhook::storage_error(&err),
    };
    let FilterList::Rules(list) = &mut view.filters else {
        return see_other(&format!("{ACCOUNT_PATH}#filters"));
    };
    if let Some(id) = &form.id {
        let Some(row) = list.rules.iter_mut().find(|rule| &rule.id == id) else {
            return see_other(&format!("{ACCOUNT_PATH}?notice=filter-gone#filters"));
        };
        row.form = form;
    } else {
        list.add_form = form;
    }
    webhook::invalid_page(state, session, view).await
}

/// The Turn on and Turn off forms.
#[derive(Deserialize)]
pub struct SwitchFilterForm {
    #[serde(default)]
    csrf_token: String,
    #[serde(default)]
    id: String,
    /// `on` or `off`.
    #[serde(default)]
    enabled: String,
}

impl CardForm for SwitchFilterForm {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// `POST /account/webhook/filters/enabled`
pub async fn set_enabled(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<SwitchFilterForm>, FormRejection>,
) -> Response {
    let (session, form) = match webhook::authorize(&state, &headers, form).await {
        Ok(authorized) => authorized,
        Err(response) => return *response,
    };
    let account = &session.account.id;
    let on = match form.enabled.as_str() {
        "on" => true,
        "off" => false,
        _ => return see_other(&format!("{ACCOUNT_PATH}#filters")),
    };
    let store = state.store();
    // Scoped to the session's account: another mailbox's rule ID changes nothing.
    let changed = if on {
        let limit = OutboxRules::for_account(&state, account).await.filter_rules;
        let check = |rules: &[FilterRule]| turn_on_check(rules, limit);
        store
            .set_webhook_filter_rule_enabled(account, &form.id, true, limit, check)
            .await
    } else {
        // Turning off uses neither the limit nor the check, so the hook isn't asked.
        store
            .set_webhook_filter_rule_enabled(account, &form.id, false, 0, |_| Ok(()))
            .await
    };
    let key = match &changed {
        Ok(ChangedFilterRule::Changed) => {
            tracing::info!(account_id = %account, enabled = on, "webhook filter rule turned on or off");
            state.notify_account_changed(account);
            if on { "filter-on" } else { "filter-off" }
        }
        // A key of `turn_on_check`.
        Ok(ChangedFilterRule::Refused(key)) => key,
        Ok(ChangedFilterRule::NotFound) => "filter-gone",
        // The block then shows its unreadable state.
        Err(StoreError::Decrypt) => return see_other(&format!("{ACCOUNT_PATH}#filters")),
        Err(err) => return webhook::storage_error(err),
    };
    see_other(&format!("{ACCOUNT_PATH}?notice={key}#filters"))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    /// `pattern`'s parts, with each escape in brackets.
    fn marked(pattern: &str) -> String {
        let part = |part: PatternPart| match part {
            PatternPart::Text(text) => text,
            PatternPart::Escape(escape) => format!("[{escape}]"),
        };
        parts(pattern).into_iter().map(part).collect()
    }

    #[test]
    fn patterns_show_hidden_characters_as_escapes() {
        assert_eq!(marked("a\u{202E}b\nc"), "a[\\u{202e}]b[\\u{a}]c");
        assert_eq!(marked("a\u{061C}b\u{00AD}c"), "a[\\u{61c}]b[\\u{ad}]c");
        assert_eq!(
            marked("\u{034F}\u{180E}\u{FFF9}\u{FFFB}\u{E0001}\u{E007F}"),
            "[\\u{34f}][\\u{180e}][\\u{fff9}][\\u{fffb}][\\u{e0001}][\\u{e007f}]"
        );
        assert_eq!(marked("news@example.com"), "news@example.com");
        assert_eq!(marked("Rechnung fällig 注文"), "Rechnung fällig 注文");
        // A typed escape is text, so it looks unlike the character it names.
        assert_eq!(marked("\\u{202e}x"), "\\u{202e}x");
        assert_eq!(parts("a\u{202E}bc").len(), 3);
    }

    #[test]
    fn only_plain_patterns_go_into_an_input() {
        assert!(plain("news@example.com"));
        assert!(plain("\\w+\\.example"));
        for pattern in ["a\u{202E}b", "a\u{0}b", "a\rb", "a\u{FE0F}"] {
            assert!(!plain(pattern), "{pattern:?}");
        }
    }

    fn posted(pattern: &str) -> FilterRuleForm {
        FilterRuleForm {
            csrf_token: String::new(),
            id: String::new(),
            action: Action::Allow,
            field: Field::FromDomain,
            kind: Kind::Regex,
            pattern: pattern.to_owned(),
        }
    }

    #[test]
    fn a_refused_form_keeps_only_a_plain_pattern() {
        let view = posted("news@example.com").view(None, "No.".to_owned());
        assert_eq!(view.pattern, "news@example.com");
        assert_eq!(view.note, None);
        for pattern in ["a\u{202E}b", "a\u{0}b", "a\rb"] {
            let view = posted(pattern).view(None, "No.".to_owned());
            assert_eq!(view.pattern, "", "{pattern:?}");
            assert_eq!(view.note, Some(TYPED_NOTE));
            let names = [view.action, view.field, view.kind];
            assert_eq!(names, ["allow", "from_domain", "regex"]);
            assert_eq!(view.error.as_deref(), Some("No."));
        }
    }

    #[test]
    fn names_are_stored_as_the_tools_store_them() {
        assert_eq!(stored_name(Field::FromDomain), "from_domain");
        assert_eq!(stored_name(Action::Block), "block");
        assert_eq!(stored_name(Kind::Regex), "regex");
    }

    #[test]
    fn a_refused_add_form_opens_the_block() {
        let mut list = FilterRules {
            rules: Vec::new(),
            limit: 9,
            add_form: FilterFormView::blank(),
        };
        assert!(!list.has_error());
        list.add_form.error = Some("No.".to_owned());
        assert!(list.has_error());
    }

    fn rule(field: &str, kind: &str, pattern: &str, active: bool) -> FilterRule {
        FilterRule {
            id: String::new(),
            added_at: 0,
            action: "block".to_owned(),
            field: field.to_owned(),
            kind: kind.to_owned(),
            pattern: pattern.to_owned().into(),
            enabled: active,
            active,
        }
    }

    #[test]
    fn a_turn_on_is_refused_for_unknown_names_and_rules_that_do_not_compile() {
        let known = rule("from", "equals", "news@example.com", true);
        let unknown = rule("body", "equals", "x", true);
        assert_eq!(
            turn_on_check(&[known.clone(), unknown], 9),
            Err("filter-unknown".to_owned())
        );
        let inactive = rule("body", "equals", "x", false);
        assert_eq!(turn_on_check(&[known.clone(), inactive], 9), Ok(()));
        let lookahead = rule("subject", "regex", "(?=x)", true);
        assert_eq!(
            turn_on_check(&[known.clone(), lookahead], 9),
            Err("filter-wont-compile".to_owned())
        );
        let regex = rule("subject", "regex", "^invoice [0-9]+$", true);
        assert_eq!(turn_on_check(&[known, regex], 9), Ok(()));
    }

    fn new(pattern: &str) -> Rule {
        let (action, field, kind) = (Action::Block, Field::Subject, Kind::Regex);
        let pattern = pattern.to_owned();
        Rule {
            action,
            field,
            kind,
            pattern,
        }
    }

    #[test]
    fn an_add_is_checked_with_the_rules_that_judge_mail() {
        let known = rule("from", "equals", "news@example.com", true);
        let extra = new("^invoice [0-9]+$");
        assert!(set_check(std::slice::from_ref(&known), Some(&extra), 9).is_ok());
        let lookahead = new("(?=x)");
        let refused = set_check(std::slice::from_ref(&known), Some(&lookahead), 9);
        assert!(matches!(refused, Err(SetRefusal::WontCompile(_))));
        let unknown = rule("body", "equals", "x", true);
        let refused = set_check(&[known.clone(), unknown], Some(&extra), 9);
        assert!(matches!(refused, Err(SetRefusal::UnknownName)));
        let inactive = rule("body", "equals", "x", false);
        assert!(set_check(&[known, inactive], Some(&extra), 9).is_ok());
    }

    #[test]
    fn a_stored_pattern_fills_the_edit_form_only_when_plain() {
        let view = FilterFormView::stored(&rule("from", "equals", "news@example.com", true));
        assert_eq!(view.pattern, "news@example.com");
        assert_eq!(view.note, None);
        for pattern in ["a\u{202E}b", "a\nb"] {
            let view = FilterFormView::stored(&rule("subject", "contains", pattern, true));
            assert_eq!(view.pattern, "", "{pattern:?}");
            assert_eq!(view.note, Some(STORED_NOTE));
            assert_eq!([view.field, view.kind], ["subject", "contains"]);
        }
    }

    #[test]
    fn a_refused_edit_form_opens_the_block() {
        let stored = rule("from", "equals", "news@example.com", true);
        let mut list = FilterRules {
            rules: vec![FilterRuleView::from(&stored)],
            limit: 9,
            add_form: FilterFormView::blank(),
        };
        assert!(!list.has_error());
        list.rules[0].form.error = Some("No.".to_owned());
        assert!(list.has_error());
    }

    /// An `allow subject regex` rule with `id`, which weighs about 0.6 MiB
    /// compiled for `\w{12}-…`.
    fn heavy(id: &str, pattern: &str, active: bool) -> FilterRule {
        FilterRule {
            id: id.to_owned(),
            action: "allow".to_owned(),
            ..rule("subject", "regex", pattern, active)
        }
    }

    #[test]
    fn an_edit_is_checked_with_the_rules_that_judge_mail_even_while_off() {
        let changed = Rule {
            action: Action::Allow,
            ..new(r"\w{24}-x")
        };
        assert_eq!(changed.validate(), Ok(()));
        let too_large =
            "The rules of this mailbox are too large to compile; remove some or simplify them.";
        // Six rules fit; the off rule `g`, changed to weigh about two, doesn't.
        let mut after: Vec<_> = (0..6)
            .map(|i| heavy(&i.to_string(), &format!(r"\w{{12}}-{i}"), true))
            .collect();
        after.push(heavy("g", r"\w{24}-x", false));
        assert_eq!(
            edit_check(&after, "g", &changed, 9),
            Err(too_large.to_owned())
        );
        // The after view's own copy of the changed rule isn't counted twice.
        let mut after: Vec<_> = (0..4)
            .map(|i| heavy(&i.to_string(), &format!(r"\w{{12}}-{i}"), true))
            .collect();
        after.push(heavy("e", r"\w{24}-x", true));
        assert_eq!(edit_check(&after, "e", &changed, 9), Ok(()));
        after.push(rule("body", "equals", "x", true));
        assert_eq!(
            edit_check(&after, "e", &changed, 9),
            Err(refusal_text(SetRefusal::UnknownName))
        );
    }

    #[test]
    fn refusals_read_as_sentences() {
        assert_eq!(
            refusal_text(SetRefusal::UnknownName),
            "A rule that's on has an action, field or kind this server doesn't know. Turn that rule off or remove it, then try again."
        );
        assert_eq!(
            refusal_text(SetRefusal::WontCompile(RuleError::TooLarge)),
            "The rules of this mailbox are too large to compile; remove some or simplify them."
        );
    }

    #[test]
    fn unreadable_rules_name_the_cause_and_the_oldest_rule_that_does_not_compile() {
        let named = |id: &str, rule: FilterRule| FilterRule {
            id: id.to_owned(),
            ..rule
        };
        let known = named("a", rule("from", "equals", "news@example.com", true));
        let off = [
            known.clone(),
            rule("body", "equals", "x", false),
            rule("subject", "regex", "(?=x)", false),
        ];
        assert_eq!(unreadable_rules(&off, 9), None);
        let unknown = [
            known.clone(),
            rule("subject", "regex", "(?=x)", true),
            rule("body", "equals", "x", true),
        ];
        assert_eq!(
            unreadable_rules(&unknown, 9),
            Some(UnreadableRules::UnknownName)
        );
        let wont = |id: &str, alone| {
            let id = id.to_owned();
            Some(UnreadableRules::WontCompile { id, alone })
        };
        let alone = [
            known.clone(),
            named("b", rule("subject", "regex", "(?=x)", true)),
            named("c", rule("subject", "regex", "(a{1000}){1000}", true)),
        ];
        assert_eq!(unreadable_rules(&alone, 9), wont("b", true));
        assert_eq!(unreadable_rules(&alone[2..], 9), wont("c", true));
        let mut together = vec![known];
        let heavy = (0..4).map(|i| heavy(&i.to_string(), &format!(r"\w{{24}}-{i}"), true));
        together.extend(heavy);
        assert_eq!(unreadable_rules(&together[..4], 9), None);
        assert_eq!(unreadable_rules(&together, 9), wont("3", false));
    }

    /// A rule with `id` that blocks mail from `address`.
    fn sender(id: &str, address: &str) -> FilterRule {
        FilterRule {
            id: id.to_owned(),
            ..rule("from", "equals", address, true)
        }
    }

    #[test]
    fn a_burst_of_reads_compiles_the_same_rules_once() {
        let answers = Mutex::<Answers>::default();
        let count = Cell::new(0);
        let compiles = |rules: &[Rule]| {
            count.set(count.get() + 1);
            CompiledRules::new(rules, 9).is_ok()
        };
        let fine = [sender("a", "news@example.com")];
        for _ in 0..20 {
            assert_eq!(kept_answer(&answers, &fine, 9, compiles), None);
        }
        assert_eq!(count.get(), 1);
        // Finding the rule that doesn't compile takes two more, once.
        let lookahead = FilterRule {
            id: "b".to_owned(),
            ..rule("subject", "regex", "(?=x)", true)
        };
        let broken = [sender("a", "news@example.com"), lookahead];
        let id = "b".to_owned();
        let wont = Some(UnreadableRules::WontCompile { id, alone: true });
        for _ in 0..20 {
            assert_eq!(kept_answer(&answers, &broken, 9, compiles), wont);
        }
        assert_eq!(count.get(), 4);
        // Changed rules are read afresh.
        let fixed = [
            sender("a", "news@example.com"),
            sender("b", "x@example.com"),
        ];
        assert_eq!(kept_answer(&answers, &fixed, 9, compiles), None);
        assert_eq!(count.get(), 5);
    }

    #[test]
    fn reads_at_once_wait_for_the_one_that_compiles() {
        let answers = Mutex::<Answers>::default();
        let count = AtomicUsize::new(0);
        let compiles = |rules: &[Rule]| {
            count.fetch_add(1, Ordering::Relaxed);
            // Long enough for every reader to ask meanwhile.
            std::thread::sleep(Duration::from_millis(200));
            CompiledRules::new(rules, 9).is_ok()
        };
        let rules = [sender("a", "news@example.com")];
        let start = Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    start.wait();
                    assert_eq!(kept_answer(&answers, &rules, 9, compiles), None);
                });
            }
        });
        assert_eq!(count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn an_answer_is_kept_under_what_it_reads() {
        let rules = [
            sender("a", "news@example.com"),
            sender("b", "shop@example.com"),
        ];
        let key = answer_key(&rules, 9);
        assert_ne!(answer_key(&rules, 10), key);
        let changed = |change: fn(&mut FilterRule)| {
            let mut rules = rules.clone();
            change(&mut rules[1]);
            answer_key(&rules, 9)
        };
        assert_ne!(changed(|rule| rule.id = "c".to_owned()), key);
        assert_ne!(changed(|rule| rule.action = "allow".to_owned()), key);
        assert_ne!(changed(|rule| rule.field = "to".to_owned()), key);
        assert_ne!(changed(|rule| rule.kind = "contains".to_owned()), key);
        let other = |rule: &mut FilterRule| rule.pattern = "x@example.com".to_owned().into();
        assert_ne!(changed(other), key);
        assert_ne!(changed(|rule| rule.active = false), key);
        assert_ne!(answer_key(&[rules[1].clone(), rules[0].clone()], 9), key);
        // A rule that judges nothing isn't read.
        let mut off = rules.to_vec();
        off.push(rule("body", "equals", "x", false));
        assert_eq!(answer_key(&off, 9), key);
        // Each part counts with its length: these two run together the same.
        let split = |kind: &str, address: &str| {
            let rule = FilterRule {
                kind: kind.to_owned(),
                ..sender("a", address)
            };
            answer_key(&[rule], 9)
        };
        let whole = split("equals", "a@example.com");
        assert_ne!(split("equalsa", "@example.com"), whole);
    }

    #[test]
    fn past_the_limit_the_oldest_answer_goes() {
        let mut answers = Answers::default();
        let key = |n: usize| {
            let (mut key, bytes) = ([0; 32], n.to_le_bytes());
            key[..bytes.len()].copy_from_slice(&bytes);
            key
        };
        let first = answers.slot(key(0));
        assert!(Arc::ptr_eq(&answers.slot(key(0)), &first));
        for n in 1..=KEPT_ANSWERS {
            answers.slot(key(n));
        }
        assert_eq!(answers.by_key.len(), KEPT_ANSWERS);
        assert_eq!(answers.order.len(), KEPT_ANSWERS);
        assert!(!answers.by_key.contains_key(&key(0)));
        assert!(answers.by_key.contains_key(&key(1)));
        assert!(answers.by_key.contains_key(&key(KEPT_ANSWERS)));
    }
}
