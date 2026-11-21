//! The account page's new-mail webhook card: settings, test events,
//! signing secret rotation and its filter rules ([`crate::filters`]).

use axum::Form;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use postkeep_store::{
    AccountId, DeliveryRecord, MAX_CONSECUTIVE_FAILURES, OutboxPolicy, Webhook, WebhookSettings,
    format_outbox_retention,
};
use postkeep_webhook::{AuthHeader, NewMailEvent, WebhookUrl, deliver, parse_header_name, sign};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use crate::account::{
    ACCOUNT_PATH, PageExtras, Session, authorize_post, render_account, see_other,
};
use crate::filters::{self, FilterList};
use crate::pages;
use crate::state::AuthState;
use crate::usage::{DEFAULT_MAX_FILTER_RULES, Outbox, filter_rule_limit};

/// Seconds between test events per account.
const TEST_INTERVAL_SECS: i64 = 10;

/// What the webhook card shows.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a template view model mirroring the form's switches"
)]
pub struct WebhookView {
    /// Whether a webhook was ever saved.
    pub configured: bool,
    /// The row is stored, but no configured key can decrypt it. The form
    /// shows no saved values; saving replaces the row.
    pub unreadable: bool,
    pub enabled: bool,
    pub url: String,
    pub auth_header_name: String,
    pub has_auth_value: bool,
    /// The last four characters of a long saved header value.
    pub auth_value_hint: Option<String>,
    pub signing: bool,
    pub signing_secret: Option<String>,
    pub include_sender: bool,
    pub status: Status,
    pub last_success: Option<Time>,
    pub last_error: Option<String>,
    /// When the pause began, if delivery is paused.
    pub paused_since: Option<Time>,
    /// When the next attempt is due, if that time is still in the future.
    pub next_retry: Option<Time>,
    /// Failures in a row that pause delivery.
    pub failure_threshold: i64,
    /// Phrase such as `about once an hour`, for the paused alert.
    pub retry_phrase: String,
    pub recent: Vec<DeliveryView>,
    pub errors: FieldErrors,
    /// The result line of a test event just sent.
    pub test_result: Option<TestResult>,
    /// How long events are kept, the cap, and the ceilings. Read only.
    pub outbox_summary: String,
    /// The Filter rules block.
    pub filters: FilterList,
    /// The result line at the top of the Filter rules block, which opens it.
    pub filter_notice: Option<pages::Notice>,
}

impl WebhookView {
    /// The Delivery history summary: when mail was last delivered and how
    /// many of the listed deliveries failed.
    #[must_use]
    pub fn history_digest(&self) -> String {
        let failures = self.recent.iter().filter(|d| !d.succeeded).count();
        let mut parts = Vec::new();
        if let Some(time) = &self.last_success {
            parts.push(format!("Last delivered {}", time.label));
        }
        match failures {
            0 => {}
            1 => parts.push("1 recent failure".to_owned()),
            n => parts.push(format!("{n} recent failures")),
        }
        parts.join(" · ")
    }
}

/// The overall delivery state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Never saved.
    #[default]
    NotSetUp,
    /// Turned off by the user.
    Off,
    /// Enabled, but paused after repeated failures. The watcher keeps
    /// recording and delivery retries slowly.
    Paused,
    /// On, nothing sent yet.
    Waiting,
    /// On, last delivery succeeded.
    Delivering,
    /// On, last delivery failed.
    Failing,
}

/// A time with its machine-readable form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Time {
    pub label: String,
    pub iso: String,
}

impl Time {
    pub(crate) fn new(unix: i64) -> Self {
        Self {
            label: pages::format_date_time(unix),
            iso: pages::format_rfc3339(unix),
        }
    }
}

/// One row of the delivery history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryView {
    pub time: Time,
    /// `test` or `new_mail`.
    pub event: &'static str,
    /// The endpoint's HTTP status, if it answered.
    pub status_code: Option<u16>,
    pub succeeded: bool,
    /// For example `164 ms` or `30.0 s`; empty when unknown.
    pub duration: String,
    /// The full outcome, such as `HTTP 503 Service Unavailable (after 3
    /// attempts)` or a connection error.
    pub detail: String,
}

impl From<&DeliveryRecord> for DeliveryView {
    fn from(record: &DeliveryRecord) -> Self {
        Self {
            time: Time::new(record.created_at),
            event: if record.test { "test" } else { "new_mail" },
            status_code: status_code(&record.summary),
            succeeded: record.succeeded,
            duration: record.elapsed_ms.map(format_duration).unwrap_or_default(),
            detail: record.summary.clone(),
        }
    }
}

/// The HTTP status at the start of a delivery summary (`HTTP 200 OK ...`).
fn status_code(summary: &str) -> Option<u16> {
    let rest = summary.strip_prefix("HTTP ")?;
    let code = rest.get(..3)?;
    let after = rest.get(3..)?;
    if !(after.is_empty() || after.starts_with(' ')) {
        return None;
    }
    code.parse().ok().filter(|code| (100..=599).contains(code))
}

/// `182 ms` below a second, `30.0 s` above.
fn format_duration(ms: i64) -> String {
    if ms < 1_000 {
        format!("{} ms", ms.max(0))
    } else {
        let tenths = ms / 100;
        format!("{}.{} s", tenths / 10, tenths % 10)
    }
}

/// The outcome of the last test event, shown under the buttons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestResult {
    pub ok: bool,
    /// `200 OK` when the endpoint answered.
    pub status: Option<String>,
    /// For example `182 ms`.
    pub duration: Option<String>,
    /// The outcome when there was no answer (or it was refused).
    pub detail: String,
}

impl TestResult {
    /// The result of the most recent test delivery among `recent`.
    #[must_use]
    pub fn latest(recent: &[DeliveryRecord]) -> Option<Self> {
        let record = recent.iter().find(|record| record.test)?;
        let status = record.summary.strip_prefix("HTTP ").and_then(|rest| {
            status_code(&record.summary)?;
            Some(
                rest.split(" (after")
                    .next()
                    .unwrap_or(rest)
                    .trim()
                    .to_owned(),
            )
        });
        Some(Self {
            ok: record.succeeded,
            status,
            duration: record.elapsed_ms.map(format_duration),
            detail: record.summary.clone(),
        })
    }
}

/// Per-field problems of a submitted form.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FieldErrors {
    pub url: Option<String>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
}

impl FieldErrors {
    const fn any(&self) -> bool {
        self.url.is_some() || self.header_name.is_some() || self.header_value.is_some()
    }
}

/// Builds the card for an account, or `None` when webhooks are off on this
/// server.
pub async fn load_view(
    state: &AuthState,
    account: &AccountId,
) -> Result<Option<WebhookView>, postkeep_store::StoreError> {
    if state.webhook_deliverer().is_none() {
        return Ok(None);
    }
    let rules = OutboxRules::for_account(state, account).await;
    load_view_with(state, account, rules).await.map(Some)
}

/// Builds the card for an account with `rules`, the usage hook's answer the
/// caller already has.
pub async fn load_view_with(
    state: &AuthState,
    account: &AccountId,
    rules: OutboxRules,
) -> Result<WebhookView, postkeep_store::StoreError> {
    let store = state.store();
    let filters = filters::load(store, account, rules.filter_rules).await?;
    let hook = match store.webhook(account).await {
        Ok(hook) => hook,
        // The row is still there. Showing an empty form lets the user
        // replace it; other storage errors still fail the page. The outbox
        // columns are plaintext, so the summary does not need the secrets.
        Err(postkeep_store::StoreError::Decrypt) => {
            tracing::warn!(
                account_id = %account,
                "webhook settings can't be read; the account page will ask for new ones"
            );
            let recent = store.recent_deliveries(account).await?;
            let (retention, max_events) = store
                .webhook_outbox_overrides(account)
                .await?
                .unwrap_or((None, None));
            let view = unreadable_view(&recent, rules, retention, max_events);
            return Ok(WebhookView { filters, ..view });
        }
        Err(err) => return Err(err),
    };
    let Some(hook) = hook else {
        // Defaults for a new webhook: signing on, sender and subject off.
        return Ok(WebhookView {
            signing: true,
            outbox_summary: outbox_summary(rules, None, None),
            filters,
            ..WebhookView::default()
        });
    };
    let recent = store.recent_deliveries(account).await?;
    let view = view(&hook, &recent, state.webhook_retry_secs(), &rules);
    Ok(WebhookView { filters, ..view })
}

/// An empty card for a row no configured key can decrypt.
fn unreadable_view(
    recent: &[DeliveryRecord],
    rules: OutboxRules,
    retention_secs: Option<i64>,
    max_events: Option<i64>,
) -> WebhookView {
    WebhookView {
        unreadable: true,
        signing: true,
        recent: recent.iter().map(DeliveryView::from).collect(),
        outbox_summary: outbox_summary(rules, retention_secs, max_events),
        ..WebhookView::default()
    }
}

fn view(
    hook: &Webhook,
    recent: &[DeliveryRecord],
    retry_interval_secs: i64,
    rules: &OutboxRules,
) -> WebhookView {
    let settings = &hook.settings;
    // A pause keeps the webhook enabled. `disabled_reason` is only what an
    // older version wrote before pausing existed; migration clears it.
    let status = if !settings.enabled {
        Status::Off
    } else if hook.is_paused() {
        Status::Paused
    } else if hook.last_attempt_at.is_none() {
        Status::Waiting
    } else if hook.last_error.is_some() {
        Status::Failing
    } else {
        Status::Delivering
    };
    let now = postkeep_store::now();
    let next_retry = hook
        .next_retry_at(retry_interval_secs)
        .filter(|next| *next > now)
        .map(Time::new);
    let (auth_header_name, auth_value_hint) = settings.auth_header.as_ref().map_or_else(
        || (String::new(), None),
        |(name, value)| {
            let value = value.expose_secret();
            // Only hint at long values, so the hint gives little away.
            let hint = (value.chars().count() >= 20).then(|| {
                let tail: String = value.chars().rev().take(4).collect();
                tail.chars().rev().collect()
            });
            (name.clone(), hint)
        },
    );
    WebhookView {
        configured: true,
        unreadable: false,
        enabled: settings.enabled,
        url: settings.url.clone(),
        has_auth_value: settings.auth_header.is_some(),
        auth_header_name,
        auth_value_hint,
        signing: settings.signing,
        signing_secret: Some(settings.signing_secret.expose_secret().to_owned()),
        include_sender: settings.include_sender,
        status,
        last_success: hook.last_success_at.map(Time::new),
        last_error: hook.last_error.clone(),
        paused_since: hook.paused_at.map(Time::new),
        next_retry,
        failure_threshold: MAX_CONSECUTIVE_FAILURES,
        retry_phrase: retry_phrase(retry_interval_secs),
        recent: recent.iter().map(DeliveryView::from).collect(),
        errors: FieldErrors::default(),
        test_result: None,
        outbox_summary: outbox_summary(*rules, hook.outbox_retention_secs, hook.outbox_max_events),
        // The caller loads the filter rules.
        filters: FilterList::default(),
        filter_notice: None,
    }
}

#[derive(Deserialize)]
pub struct WebhookForm {
    #[serde(default)]
    csrf_token: String,
    enabled: Option<String>,
    #[serde(default)]
    webhook_url: String,
    #[serde(default)]
    auth_header_name: String,
    auth_header_value: Option<SecretString>,
    hmac_signing: Option<String>,
    include_sender_subject: Option<String>,
}

/// Checks a submitted form against the stored webhook. Blank header value
/// keeps the stored one; a blank header name removes the header.
fn validate(
    form: &WebhookForm,
    existing: Option<&Webhook>,
    retry_interval_secs: i64,
    rules: &OutboxRules,
) -> Result<WebhookSettings, Box<WebhookView>> {
    let enabled = form.enabled.is_some();
    let url = form.webhook_url.trim();
    let mut errors = FieldErrors::default();
    if url.is_empty() {
        if enabled {
            errors.url = Some("Enter the URL to send events to.".to_owned());
        }
    } else if let Err(err) = WebhookUrl::parse(url) {
        errors.url = Some(capitalize(&err.to_string()));
    }

    let name = form.auth_header_name.trim();
    let new_value = form
        .auth_header_value
        .as_ref()
        .map(|value| value.expose_secret().trim().to_owned())
        .filter(|value| !value.is_empty());
    let stored_value = existing
        .and_then(|hook| hook.settings.auth_header.as_ref())
        .map(|(_, value)| value.clone());
    let auth_header = if name.is_empty() {
        None
    } else if let Err(err) = parse_header_name(name) {
        errors.header_name = Some(capitalize(&err.to_string()));
        None
    } else if let Some(value) = new_value {
        match AuthHeader::new(name, &value) {
            Ok(header) => Some((header.name.as_str().to_owned(), SecretString::from(value))),
            Err(err) => {
                errors.header_value = Some(capitalize(&err.to_string()));
                None
            }
        }
    } else if let Some(value) = stored_value {
        Some((name.to_ascii_lowercase(), value))
    } else {
        errors.header_value = Some("Enter the header value.".to_owned());
        None
    };

    if errors.any() {
        let mut view = existing.map_or_else(
            || WebhookView {
                outbox_summary: outbox_summary(*rules, None, None),
                ..WebhookView::default()
            },
            |hook| view(hook, &[], retry_interval_secs, rules),
        );
        view.enabled = enabled;
        url.clone_into(&mut view.url);
        name.clone_into(&mut view.auth_header_name);
        view.signing = form.hmac_signing.is_some();
        view.include_sender = form.include_sender_subject.is_some();
        view.errors = errors;
        return Err(Box::new(view));
    }
    let signing_secret = match existing {
        Some(hook) => hook.settings.signing_secret.clone(),
        None => match sign::generate_secret() {
            Ok(secret) => SecretString::from(secret),
            Err(_) => {
                return Err(Box::new(WebhookView {
                    errors: FieldErrors {
                        url: Some("Could not create a signing secret. Try again.".to_owned()),
                        ..FieldErrors::default()
                    },
                    outbox_summary: outbox_summary(*rules, None, None),
                    ..WebhookView::default()
                }));
            }
        },
    };
    Ok(WebhookSettings {
        enabled,
        url: url.to_owned(),
        auth_header,
        signing: form.hmac_signing.is_some(),
        signing_secret,
        include_sender: form.include_sender_subject.is_some(),
    })
}

/// What the card says about the outbox: the server's policy, which decides
/// what pruning keeps, and the ceilings this account may set, which the
/// usage hook can lower; and how many of the account's filter rules count.
#[derive(Debug, Clone, Copy)]
pub struct OutboxRules {
    policy: OutboxPolicy,
    ceilings: OutboxPolicy,
    pub(crate) filter_rules: usize,
}

impl From<OutboxPolicy> for OutboxRules {
    fn from(policy: OutboxPolicy) -> Self {
        Self {
            policy,
            ceilings: policy,
            filter_rules: DEFAULT_MAX_FILTER_RULES,
        }
    }
}

impl OutboxRules {
    /// The server's policy and filter rule setting, with the usage hook's
    /// answer for `account`, which it is asked once for.
    pub(crate) async fn for_account(state: &AuthState, account: &AccountId) -> Self {
        let store = state.store();
        let policy = store.outbox_policy();
        // Account-page sessions are for accounts in the server's own tenant.
        let outbox = Outbox::new(store.tenant(), account);
        let answer = match state.usage_hook() {
            Some(hook) => hook.outbox_ceilings(outbox).await,
            None => None,
        };
        Self {
            policy,
            ceilings: answer.map_or(policy, |ceilings| {
                policy.with_ceilings(ceilings.max_retention_secs, ceilings.max_events_limit)
            }),
            filter_rules: filter_rule_limit(answer, state.max_filter_rules()),
        }
    }
}

/// One line for the alerts card. An override is marked as this account's
/// setting; a null column is the server default.
fn outbox_summary(
    rules: OutboxRules,
    retention_secs: Option<i64>,
    max_events: Option<i64>,
) -> String {
    let limits = rules.policy.effective(retention_secs, max_events);
    let retention = if limits.retention_is_default {
        format!(
            "{} (server default)",
            format_outbox_retention(limits.retention_secs)
        )
    } else {
        format!(
            "{} (this account)",
            format_outbox_retention(limits.retention_secs)
        )
    };
    let events = if limits.max_events_is_default {
        format!("{} (server default)", limits.max_events)
    } else {
        format!("{} (this account)", limits.max_events)
    };
    format!(
        "Events are kept for {retention}, at most {events}. Up to {} and {} events.",
        format_outbox_retention(rules.ceilings.max_retention_secs),
        rules.ceilings.max_events_limit
    )
}

/// `about once an hour` for 3600, and the same shape for other intervals.
fn retry_phrase(secs: i64) -> String {
    if secs <= 0 {
        return "soon".to_owned();
    }
    if secs % 3600 == 0 {
        let hours = secs / 3600;
        if hours == 1 {
            "about once an hour".to_owned()
        } else {
            format!("about every {hours} hours")
        }
    } else if secs % 60 == 0 {
        let minutes = secs / 60;
        if minutes == 1 {
            "about once a minute".to_owned()
        } else {
            format!("about every {minutes} minutes")
        }
    } else if secs == 1 {
        "about once a second".to_owned()
    } else {
        format!("about every {secs} seconds")
    }
}

pub fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        let mut out: String = first.to_uppercase().collect();
        out.push_str(chars.as_str());
        if !out.ends_with('.') {
            out.push('.');
        }
        out
    })
}

pub fn storage_error(err: &postkeep_store::StoreError) -> Response {
    tracing::error!(error = %err, "storage error");
    pages::server_error()
}

/// Settings from a valid form, plus the row they were checked against.
struct PreparedForm {
    settings: WebhookSettings,
    /// The readable stored webhook, when there was one.
    existing: Option<Webhook>,
    /// The stored row could not be decrypted and will be replaced on save.
    unreadable: bool,
}

/// Validates the form. On invalid input, returns the page to show instead.
async fn prepared_form(
    state: &AuthState,
    session: &Session,
    form: &WebhookForm,
) -> Result<PreparedForm, Box<Response>> {
    let store = state.store();
    let account = &session.account.id;
    // An unreadable row is treated as having no saved settings: the user
    // re-enters the URL and header, and a new signing secret is generated.
    // The save overwrites that row. Other storage errors still fail.
    let (existing, unreadable) = match store.webhook(account).await {
        Ok(hook) => (hook, false),
        Err(postkeep_store::StoreError::Decrypt) => {
            tracing::warn!(
                account_id = %account,
                "replacing webhook settings that can't be read"
            );
            (None, true)
        }
        Err(err) => return Err(Box::new(storage_error(&err))),
    };
    let rules = OutboxRules::for_account(state, account).await;
    match validate(form, existing.as_ref(), state.webhook_retry_secs(), &rules) {
        Ok(settings) => Ok(PreparedForm {
            settings,
            existing,
            unreadable,
        }),
        Err(mut view) => {
            view.unreadable = unreadable;
            view.recent = store
                .recent_deliveries(account)
                .await
                .map_err(|err| Box::new(storage_error(&err)))?
                .iter()
                .map(DeliveryView::from)
                .collect();
            view.filters = filters::load(store, account, rules.filter_rules)
                .await
                .map_err(|err| Box::new(storage_error(&err)))?;
            Err(Box::new(invalid_page(state, session, *view).await))
        }
    }
}

/// Whether a test submission would store the same settings.
///
/// The signing secret is copied from the stored row, and a blank auth
/// value keeps the stored one, so submitting the form unchanged compares
/// equal. A URL change does not.
fn same_settings(stored: &WebhookSettings, next: &WebhookSettings) -> bool {
    stored.enabled == next.enabled
        && stored.url == next.url
        && stored.signing == next.signing
        && stored.include_sender == next.include_sender
        && same_auth(stored.auth_header.as_ref(), next.auth_header.as_ref())
        && stored.signing_secret.expose_secret() == next.signing_secret.expose_secret()
}

fn same_auth(
    stored: Option<&(String, SecretString)>,
    next: Option<&(String, SecretString)>,
) -> bool {
    match (stored, next) {
        (None, None) => true,
        (Some((stored_name, stored_value)), Some((next_name, next_value))) => {
            stored_name == next_name && stored_value.expose_secret() == next_value.expose_secret()
        }
        _ => false,
    }
}

/// Validates and saves the form. On invalid input, returns the page to
/// show instead.
async fn save_form(
    state: &AuthState,
    session: &Session,
    form: &WebhookForm,
) -> Result<WebhookSettings, Box<Response>> {
    let prepared = prepared_form(state, session, form).await?;
    let account = &session.account.id;
    state
        .store()
        .save_webhook(account, &prepared.settings)
        .await
        .map_err(|err| Box::new(storage_error(&err)))?;
    tracing::info!(account_id = %account, enabled = prepared.settings.enabled, "webhook settings saved");
    state.notify_account_changed(account);
    Ok(prepared.settings)
}

pub async fn invalid_page(state: &AuthState, session: &Session, view: WebhookView) -> Response {
    let mut response = render_account(
        state,
        session,
        PageExtras {
            webhook: Some(view),
            ..PageExtras::default()
        },
    )
    .await;
    if response.status().is_success() {
        *response.status_mut() = StatusCode::BAD_REQUEST;
    }
    response
}

/// A form posted from the alerts card.
pub trait CardForm {
    /// The form's CSRF token.
    fn csrf_token(&self) -> &str;
}

impl CardForm for WebhookForm {
    fn csrf_token(&self) -> &str {
        &self.csrf_token
    }
}

/// Signs the form's session in, or explains why not.
pub async fn authorize<F: CardForm>(
    state: &AuthState,
    headers: &HeaderMap,
    form: Result<Form<F>, FormRejection>,
) -> Result<(Session, F), Box<Response>> {
    if state.webhook_deliverer().is_none() {
        return Err(Box::new(StatusCode::NOT_FOUND.into_response()));
    }
    let Ok(Form(form)) = form else {
        return Err(Box::new(crate::account::forbidden()));
    };
    let session = authorize_post(state, headers, form.csrf_token())
        .await
        .map_err(|rejection| Box::new(rejection.into_response()))?;
    Ok((session, form))
}

/// `POST /account/webhook`
pub async fn save(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<WebhookForm>, FormRejection>,
) -> Response {
    let (session, form) = match authorize(&state, &headers, form).await {
        Ok(ok) => ok,
        Err(response) => return *response,
    };
    match save_form(&state, &session, &form).await {
        Ok(_) => see_other(&format!("{ACCOUNT_PATH}?notice=webhook-saved#alerts")),
        Err(response) => *response,
    }
}

/// `POST /account/webhook/test`: sends one sample event without retries.
///
/// Submitting the form unchanged does not write the row, so a pause and
/// the failure count stay until a real delivery succeeds or the user saves
/// or turns the webhook on. A failed test never clears a pause. A
/// successful test of those unchanged settings wakes the pump so real
/// events are tried once now; that attempt, not the test, decides whether
/// the pause ends. Changing the URL still saves first, which clears a
/// pause and skips events queued for the previous URL, the same as Save.
pub async fn test(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<WebhookForm>, FormRejection>,
) -> Response {
    let (session, form) = match authorize(&state, &headers, form).await {
        Ok(ok) => ok,
        Err(response) => return *response,
    };
    let account = &session.account.id;
    let store = state.store();
    let now = postkeep_store::now();
    match store.recent_deliveries(account).await {
        Ok(recent)
            if recent
                .iter()
                .any(|record| record.test && now - record.created_at < TEST_INTERVAL_SECS) =>
        {
            return see_other(&format!("{ACCOUNT_PATH}?notice=webhook-wait#alerts"));
        }
        Ok(_) => {}
        Err(err) => return storage_error(&err),
    }
    // Recorded rows only exist after `deliver` returns, so parallel requests
    // all used to pass the check above. The in-process slot is taken before
    // the send and refuses the others with the same notice. The guard
    // releases the slot if this handler is dropped before the send finishes.
    let Some(reservation) = state.try_begin_webhook_test(account, now, TEST_INTERVAL_SECS) else {
        return see_other(&format!("{ACCOUNT_PATH}?notice=webhook-wait#alerts"));
    };
    let prepared = match prepared_form(&state, &session, &form).await {
        Ok(prepared) => prepared,
        Err(response) => return *response,
    };
    // An unchanged test must not clear a pause or reset the failure count.
    // A URL change, turning alerts on, or replacing an unreadable row still
    // goes through the same save as the account page.
    let unchanged = !prepared.unreadable
        && prepared
            .existing
            .as_ref()
            .is_some_and(|hook| same_settings(&hook.settings, &prepared.settings));
    if !unchanged {
        if let Err(err) = store.save_webhook(account, &prepared.settings).await {
            return storage_error(&err);
        }
        tracing::info!(account_id = %account, enabled = prepared.settings.enabled, "webhook settings saved");
        state.notify_account_changed(account);
    }
    let settings = prepared.settings;
    let Ok(url) = WebhookUrl::parse(&settings.url) else {
        return see_other(&format!("{ACCOUNT_PATH}?notice=webhook-no-url#alerts"));
    };
    let auth = settings
        .auth_header
        .as_ref()
        .and_then(|(name, value)| AuthHeader::new(name, value.expose_secret()).ok());
    let secret = settings
        .signing
        .then(|| settings.signing_secret.expose_secret());
    let request = NewMailEvent::sample(&session.account.email).request(
        url,
        &uuid_like(),
        now,
        auth.as_ref(),
        secret,
    );
    let Some(deliverer) = state.webhook_deliverer() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let delivery = deliver(deliverer, &request, &[]).await;
    reservation.finish(postkeep_store::now());
    let record = DeliveryRecord {
        created_at: postkeep_store::now(),
        test: true,
        succeeded: delivery.succeeded(),
        summary: delivery.summary(),
        elapsed_ms: delivery
            .result
            .as_ref()
            .ok()
            .and_then(|response| i64::try_from(response.elapsed.as_millis()).ok()),
    };
    if let Err(err) = store.record_delivery(account, &record).await {
        return storage_error(&err);
    }
    // Unchanged settings were not saved, so a successful test is the cue to
    // try real events once now. The test delivery itself does not clear a
    // pause. A failed test does not wake the pump. A changed form already
    // notified listeners when it was saved.
    if record.succeeded && unchanged {
        state.notify_account_changed(account);
    }
    let notice = if record.succeeded {
        "webhook-test-sent"
    } else {
        "webhook-test-failed"
    };
    see_other(&format!("{ACCOUNT_PATH}?notice={notice}#alerts"))
}

/// A random id for a test event.
fn uuid_like() -> String {
    crate::random::token().unwrap_or_default()
}

/// `POST /account/webhook/rotate-secret`: replaces the signing secret and
/// keeps every other stored setting (the rest of the form is ignored).
pub async fn rotate_secret(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<WebhookForm>, FormRejection>,
) -> Response {
    let (session, _) = match authorize(&state, &headers, form).await {
        Ok(ok) => ok,
        Err(response) => return *response,
    };
    let account = &session.account.id;
    let store = state.store();
    let mut settings = match store.webhook(account).await {
        Ok(Some(hook)) => hook.settings,
        Ok(None) => return see_other(&format!("{ACCOUNT_PATH}?notice=webhook-save-first#alerts")),
        Err(postkeep_store::StoreError::Decrypt) => {
            tracing::warn!(
                account_id = %account,
                "cannot rotate a signing secret that can't be read"
            );
            return see_other(&format!("{ACCOUNT_PATH}?notice=webhook-unreadable#alerts"));
        }
        Err(err) => return storage_error(&err),
    };
    let Ok(secret) = sign::generate_secret() else {
        return pages::server_error();
    };
    settings.signing_secret = SecretString::from(secret);
    if let Err(err) = store.save_webhook(account, &settings).await {
        return storage_error(&err);
    }
    tracing::info!(account_id = %account, "webhook signing secret rotated");
    state.notify_account_changed(account);
    see_other(&format!("{ACCOUNT_PATH}?notice=secret-rotated#alerts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(url: &str, name: &str, value: Option<&str>) -> WebhookForm {
        WebhookForm {
            csrf_token: String::new(),
            enabled: Some("on".to_owned()),
            webhook_url: url.to_owned(),
            auth_header_name: name.to_owned(),
            auth_header_value: value.map(|value| SecretString::from(value.to_owned())),
            hmac_signing: Some("on".to_owned()),
            include_sender_subject: None,
        }
    }

    #[test]
    fn validates_the_form() {
        let settings = validate(
            &form(
                "https://hooks.example.com/x",
                "Authorization",
                Some("Bearer t"),
            ),
            None,
            3600,
            &OutboxRules::from(postkeep_store::OutboxPolicy::default()),
        )
        .unwrap_or_else(|_| unreachable!("valid form"));
        assert!(settings.enabled && settings.signing && !settings.include_sender);
        assert!(
            settings
                .signing_secret
                .expose_secret()
                .starts_with("whsec_")
        );
        assert_eq!(
            settings.auth_header.as_ref().map(|(name, _)| name.as_str()),
            Some("authorization")
        );

        for (url, name, value, field) in [
            ("", "", None, "url"),
            ("http://hooks.example.com/", "", None, "url"),
            ("https://10.0.0.1/", "", None, "url"),
            ("https://hooks.example.com/", "Host", Some("x"), "name"),
            ("https://hooks.example.com/", "Authorization", None, "value"),
            (
                "https://hooks.example.com/",
                "Authorization",
                Some("a\r\nb"),
                "value",
            ),
        ] {
            let Err(view) = validate(
                &form(url, name, value),
                None,
                3600,
                &OutboxRules::from(postkeep_store::OutboxPolicy::default()),
            ) else {
                unreachable!("{url} {name} should fail");
            };
            let errors = &view.errors;
            match field {
                "url" => assert!(errors.url.is_some()),
                "name" => assert!(errors.header_name.is_some()),
                _ => assert!(errors.header_value.is_some()),
            }
            assert_eq!(view.url, url.trim());
        }

        // Disabled with no URL is fine.
        let mut off = form("", "", None);
        off.enabled = None;
        let rules = OutboxRules::from(postkeep_store::OutboxPolicy::default());
        assert!(validate(&off, None, 3600, &rules).is_ok());
    }

    #[test]
    fn capitalizes_messages() {
        assert_eq!(
            capitalize("the URL must use https"),
            "The URL must use https."
        );
        assert_eq!(capitalize(""), "");
    }

    #[test]
    fn delivery_rows() {
        assert_eq!(status_code("HTTP 200 OK (after 1 attempt)"), Some(200));
        assert_eq!(
            status_code("HTTP 503 Service Unavailable (after 3 attempts)"),
            Some(503)
        );
        assert_eq!(status_code("HTTP 299"), Some(299));
        assert_eq!(status_code("HTTP 2000 (after 1 attempt)"), None);
        assert_eq!(status_code("HTTP 099 x"), None);
        assert_eq!(status_code("connection refused (after 3 attempts)"), None);
        assert_eq!(status_code("HTTP é"), None);
        assert_eq!(format_duration(182), "182 ms");
        assert_eq!(format_duration(-5), "0 ms");
        assert_eq!(format_duration(30_000), "30.0 s");
        assert_eq!(format_duration(1_250), "1.2 s");
    }

    fn record(test: bool, succeeded: bool, summary: &str) -> DeliveryRecord {
        DeliveryRecord {
            created_at: 1_800_000_000,
            test,
            succeeded,
            summary: summary.to_owned(),
            elapsed_ms: Some(164),
        }
    }

    #[test]
    fn test_results() {
        let records = [
            record(false, true, "HTTP 200 OK (after 1 attempt)"),
            record(true, false, "HTTP 401 Unauthorized (after 1 attempt)"),
            record(true, true, "HTTP 200 OK (after 1 attempt)"),
        ];
        let result = TestResult::latest(&records).unwrap();
        assert!(!result.ok);
        assert_eq!(result.status.as_deref(), Some("401 Unauthorized"));
        assert_eq!(result.duration.as_deref(), Some("164 ms"));
        let refused =
            TestResult::latest(&[record(true, false, "connection refused (after 1 attempt)")])
                .unwrap();
        assert_eq!(refused.status, None);
        assert_eq!(refused.detail, "connection refused (after 1 attempt)");
        assert_eq!(TestResult::latest(&records[..1]), None);
    }

    #[test]
    fn history_digest() {
        let mut view = WebhookView::default();
        assert_eq!(view.history_digest(), "");
        view.recent = [
            record(
                false,
                false,
                "HTTP 503 Service Unavailable (after 3 attempts)",
            ),
            record(false, false, "timed out (after 3 attempts)"),
        ]
        .iter()
        .map(DeliveryView::from)
        .collect();
        assert_eq!(view.history_digest(), "2 recent failures");
        view.last_success = Some(Time::new(1_800_000_000));
        assert!(view.history_digest().starts_with("Last delivered "));
        assert!(view.history_digest().ends_with(" · 2 recent failures"));
        assert_eq!(view.recent[0].status_code, Some(503));
        assert_eq!(view.recent[1].status_code, None);
        assert_eq!(view.recent[0].event, "new_mail");
    }
}
