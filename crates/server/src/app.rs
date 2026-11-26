//! Assembles the HTTP application.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::IntoResponse;
use axum::routing::get;
use postkeep_auth::{
    AllowedHosts, AuthConfig, AuthState, ContinuationHook, CredentialVerifier, InvalidRequestPage,
    PrincipalResolver, RequestHost, ResourcePrefix, SignInHook, UsageHook, require_bearer,
};
use postkeep_store::{PurgePolicy, Reencrypted, Rewrapped, Store};
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;

use crate::bucket::Bucket;
use crate::limits::{ACCOUNT_WAIT, AccountLimit, GlobalLimit, limit_account, limit_global};
use crate::metrics::Metrics;
use crate::pool::{ImapPool, PoolConfig};
use crate::readiness::{Readiness, ReadinessCheck, readyz};
use crate::selector::select_mailbox;
use crate::tools::{MailTools, ToolExtension};
use crate::watch::{SharedJob, WatchOwnership, Watchers};

/// Path of the MCP endpoint.
pub const MCP_PATH: &str = "/mcp";

/// Everything needed to build the application.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Authorization server settings (public URL, token lifetimes, ...).
    pub auth: AuthConfig,
    /// Extra `Host` header values accepted on the MCP endpoint.
    pub extra_allowed_hosts: Vec<String>,
    /// Extra `Origin` header values accepted on the MCP endpoint besides the
    /// public URL's origin, such as `https://app.example.com`. Values that
    /// are not origins are left out.
    pub extra_allowed_origins: Vec<String>,
    /// Request size, time and concurrency limits.
    pub limits: RequestLimits,
    /// IMAP session pool settings.
    pub pool: PoolConfig,
    /// New-mail webhook watchers; `None` hides webhooks.
    pub watchers: Option<Watchers>,
    /// Sign-in with Microsoft and Google; `None` hides both buttons.
    pub upstream: Option<postkeep_upstream::OAuthClient>,
    /// Gmail push through Cloud Pub/Sub: the topic and what push tokens
    /// must say. Needs `upstream` with Google configured.
    pub google_push: Option<(String, postkeep_upstream::PushExpectations)>,
    /// The bucket uploaded files wait in; `None` turns uploads off, while
    /// `upload_attachment` and `/upload` stay, refusing.
    pub bucket: Option<Arc<dyn Bucket>>,
}

/// Limits applied to every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestLimits {
    /// Largest accepted request body in bytes (OAuth endpoints accept at
    /// most 16 KiB regardless).
    pub max_body_bytes: usize,
    /// Time a request may take, including reading its body, before the
    /// server answers `503`.
    pub request_timeout: Duration,
    /// Requests handled at once; more are answered with `503`.
    pub max_concurrent_requests: usize,
    /// MCP requests handled at once per account.
    pub account_concurrency: usize,
}

impl Default for RequestLimits {
    fn default() -> Self {
        Self {
            max_body_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(120),
            max_concurrent_requests: 256,
            account_concurrency: 4,
        }
    }
}

/// What an embedding adds to the application or leaves out of it.
///
/// The default adds nothing, so [`router_with`] builds exactly what
/// [`router`] builds.
#[derive(Clone)]
pub struct Extensions {
    routes: Vec<Router>,
    default_pages: bool,
    principal_resolver: Option<Arc<dyn PrincipalResolver>>,
    sign_in_hook: Option<Arc<dyn SignInHook>>,
    continuation_hook: Option<Arc<dyn ContinuationHook>>,
    invalid_request_page: Option<Arc<dyn InvalidRequestPage>>,
    tool_extension: Option<Arc<dyn ToolExtension>>,
    usage_hook: Option<Arc<dyn UsageHook>>,
    watch_ownership: Option<Arc<dyn WatchOwnership>>,
    per_request_resources: bool,
    resource_prefix: Option<ResourcePrefix>,
    readiness_checks: Vec<Arc<dyn ReadinessCheck>>,
    draining: CancellationToken,
    metrics: Metrics,
}

impl std::fmt::Debug for Extensions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extensions")
            .field("routes", &self.routes.len())
            .field("default_pages", &self.default_pages)
            .field("principal_resolver", &self.principal_resolver.is_some())
            .field("sign_in_hook", &self.sign_in_hook.is_some())
            .field("continuation_hook", &self.continuation_hook.is_some())
            .field("invalid_request_page", &self.invalid_request_page.is_some())
            .field("tool_extension", &self.tool_extension.is_some())
            .field("usage_hook", &self.usage_hook.is_some())
            .field("watch_ownership", &self.watch_ownership.is_some())
            .field("per_request_resources", &self.per_request_resources)
            .field("resource_prefix", &self.resource_prefix)
            .field("readiness_checks", &self.readiness_checks.len())
            .field("draining", &self.draining.is_cancelled())
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl Default for Extensions {
    fn default() -> Self {
        Self {
            routes: Vec::new(),
            default_pages: true,
            principal_resolver: None,
            sign_in_hook: None,
            continuation_hook: None,
            invalid_request_page: None,
            tool_extension: None,
            usage_hook: None,
            watch_ownership: None,
            per_request_resources: false,
            resource_prefix: None,
            readiness_checks: Vec::new(),
            draining: CancellationToken::new(),
            metrics: Metrics::default(),
        }
    }
}

impl Extensions {
    /// Nothing added, every default page served.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves `routes` beside the built-in ones, behind the same request
    /// size, time and concurrency limits. A path the server already serves
    /// panics when the router is built, as `axum` does for overlapping
    /// routes. Handlers can extract the server's [`AuthState`] as
    /// `axum::Extension<AuthState>`, for example to finish a sign-in that a
    /// [`SignInHook`] started, or to start a Microsoft or Google sign-in
    /// with [`AuthState::start_upstream_sign_in`].
    #[must_use]
    pub fn route(mut self, routes: Router) -> Self {
        self.routes.push(routes);
        self
    }

    /// Decides who a bearer token on the MCP endpoint belongs to, instead
    /// of [`postkeep_auth::TokenResolver`]. If
    /// [`PrincipalResolver::selects_mailboxes`] is true, every tool also
    /// takes an optional `mailbox` argument naming one of the caller's
    /// mailboxes.
    #[must_use]
    pub fn principal_resolver(mut self, resolver: Arc<dyn PrincipalResolver>) -> Self {
        self.principal_resolver = Some(resolver);
        self
    }

    /// Hands `/authorize` requests for the resources `hook` handles to it
    /// instead of the mailbox sign-in page. Their tokens act for a
    /// principal, so this goes with a [`principal_resolver`] that accepts
    /// them.
    ///
    /// [`principal_resolver`]: Self::principal_resolver
    #[must_use]
    pub fn sign_in_hook(mut self, hook: Arc<dyn SignInHook>) -> Self {
        self.sign_in_hook = Some(hook);
        self
    }

    /// Finishes the Microsoft or Google sign-ins that the embedding's own
    /// pages start with [`AuthState::start_upstream_sign_in`] to add a
    /// mailbox to one of its tenants.
    #[must_use]
    pub fn continuation_hook(mut self, hook: Arc<dyn ContinuationHook>) -> Self {
        self.continuation_hook = Some(hook);
        self
    }

    /// Shows `page` for the requests `/authorize` refuses, in place of the
    /// server's own "This link can't be used" page, and for the server's own
    /// pages at `/oauth/{provider}/callback`; see [`InvalidRequestPage`].
    #[must_use]
    pub fn invalid_request_page(mut self, page: Arc<dyn InvalidRequestPage>) -> Self {
        self.invalid_request_page = Some(page);
        self
    }

    /// Lists the extension's tools beside the server's to the callers it
    /// picks, adds its paragraph to the instructions and runs its check
    /// before every tool call; see [`ToolExtension`].
    #[must_use]
    pub fn tool_extension(mut self, extension: Arc<dyn ToolExtension>) -> Self {
        self.tool_extension = Some(extension);
        self
    }

    /// Asks `hook` before a sign-in adds a mailbox to a tenant, before every
    /// tool call and before every message the tools send, and for a
    /// mailbox's outbox ceilings and how many of its filter rules count,
    /// which the webhook tools and the watchers use, and tells it how each
    /// call it allowed ended; see [`UsageHook`].
    #[must_use]
    pub fn usage_hook(mut self, hook: Arc<dyn UsageHook>) -> Self {
        self.usage_hook = Some(hook);
        self
    }

    /// Decides which mailboxes this process watches and which shared jobs
    /// it runs, for an embedding that runs several processes on one
    /// database; see [`WatchOwnership`]. Without it, the process watches
    /// every mailbox with an enabled webhook and runs every job.
    #[must_use]
    pub fn watch_ownership(mut self, ownership: Arc<dyn WatchOwnership>) -> Self {
        self.watch_ownership = Some(ownership);
        self
    }

    /// The hook from [`Self::watch_ownership`], for the shared jobs.
    pub(crate) fn ownership(&self) -> Option<Arc<dyn WatchOwnership>> {
        self.watch_ownership.clone()
    }

    /// Makes every allowed host its own protected resource with strict
    /// audience binding; see [`AuthConfig::per_request_resources`].
    #[must_use]
    pub const fn per_request_resources(mut self, enabled: bool) -> Self {
        self.per_request_resources = enabled;
        self
    }

    /// Also serves the MCP endpoint at `<prefix>/<name>/mcp`, each name its
    /// own protected resource with its own RFC 9728 document, and turns on
    /// [`per_request_resources`](Self::per_request_resources); see
    /// [`AuthConfig::resource_prefix`]. The [`PrincipalResolver`] sees the
    /// resource a request addresses in
    /// [`BearerRequest::resource`](postkeep_auth::BearerRequest::resource).
    #[must_use]
    pub fn resource_prefix(mut self, prefix: ResourcePrefix) -> Self {
        self.resource_prefix = Some(prefix);
        self.per_request_resources = true;
        self
    }

    fn selects_mailboxes(&self) -> bool {
        self.principal_resolver
            .as_ref()
            .is_some_and(|resolver| resolver.selects_mailboxes())
    }

    fn tenant_argument(&self) -> Option<&'static str> {
        self.principal_resolver.as_ref()?.tenant_argument()
    }

    /// Serves or leaves out the default pages at `/` and under `/account`.
    ///
    /// Disabling them also removes the upstream OAuth start route and buttons.
    /// The sign-in page at `/authorize`, the MCP OAuth endpoints, the provider
    /// callback, the MCP endpoint, `/healthz` and `/readyz` always stay.
    #[must_use]
    pub const fn default_pages(mut self, enabled: bool) -> Self {
        self.default_pages = enabled;
        self
    }

    /// Makes `/readyz` also wait for `check`, for example an embedding's
    /// warm-up. Checks run after the database checks, in the order they
    /// were added; `/readyz` answers `503` with the reason of the first one
    /// that fails.
    #[must_use]
    pub fn readiness_check(mut self, check: Arc<dyn ReadinessCheck>) -> Self {
        self.readiness_checks.push(check);
        self
    }

    /// Makes `/readyz` answer `503 draining` once `draining` is cancelled.
    pub(crate) fn drain_on(mut self, draining: CancellationToken) -> Self {
        self.draining = draining;
        self
    }

    /// Counts this server's requests into `metrics`, which `serve`
    /// publishes on `POSTKEEP_METRICS_BIND`.
    pub(crate) fn count_into(mut self, metrics: Metrics) -> Self {
        self.metrics = metrics;
        self
    }
}

/// Builds the router: OAuth endpoints, the sign-in page, the protected MCP
/// endpoint, `/healthz`, `/readyz` and a short landing page at `/`.
///
/// `cancel` stops in-flight MCP streams when the server shuts down.
pub fn router(
    config: AppConfig,
    store: Store,
    verifier: impl CredentialVerifier,
    cancel: CancellationToken,
) -> Router {
    router_with(config, store, verifier, cancel, Extensions::default())
}

/// [`router`] with an embedding's [`Extensions`].
pub fn router_with(
    config: AppConfig,
    store: Store,
    verifier: impl CredentialVerifier,
    cancel: CancellationToken,
    extensions: Extensions,
) -> Router {
    let mut config = config;
    let mut extensions = extensions;
    let request_log =
        middleware::from_fn_with_state(extensions.metrics.clone(), crate::request_log::log);
    let probes = probe_routes(&store, &mut extensions);
    let hosts = allowed_hosts(config.auth.issuer(), &config.extra_allowed_hosts);
    let origins = allowed_origins(config.auth.issuer(), &config.extra_allowed_origins);
    config.auth.allowed_hosts = AllowedHosts::new(hosts.iter().map(String::as_str));
    if extensions.per_request_resources {
        config.auth.per_request_resources = true;
    }
    if let Some(prefix) = extensions.resource_prefix.take() {
        config.auth.resource_prefix = Some(prefix);
    }
    let limits = config.limits;
    let servers = config.auth.imap_servers.clone();
    let selecting = extensions.selects_mailboxes();
    let tenant_arg = extensions.tenant_argument();
    let auth = AuthState::new(store.clone(), config.auth, verifier);
    install_auth_extensions(&auth, &extensions);

    let pool = ImapPool::new(config.pool);
    tokio::spawn(pool.clone().run_reaper(cancel.clone()));
    {
        let pool = pool.clone();
        auth.add_account_listener(std::sync::Arc::new(move |account| pool.evict(account)));
    }
    let tokens = config.upstream.map(|upstream| {
        auth.enable_upstream(upstream.clone());
        postkeep_upstream::TokenManager::new(store.clone(), upstream)
    });
    let push_routes =
        config
            .watchers
            .as_ref()
            .zip(tokens.as_ref())
            .and_then(|(watchers, tokens)| {
                let public_url = url::Url::parse(auth.config().issuer()).ok()?;
                let google =
                    config
                        .google_push
                        .clone()
                        .map(|(topic, expected)| crate::watch::GooglePush {
                            topic,
                            expected,
                            verifier: postkeep_upstream::PushVerifier::new(
                                tokens.oauth().http().clone(),
                                tokens.oauth().endpoints().clone(),
                            ),
                        });
                watchers.enable_push(crate::watch::PushConfig {
                    tokens: tokens.clone(),
                    public_url,
                    google,
                });
                Some(crate::push::router(watchers.clone()))
            });
    let webhook_control = config.watchers.as_ref().map(|watchers| {
        let interval = watchers.retry_interval();
        auth.set_webhook_retry_interval(interval);
        auth.set_max_filter_rules(watchers.max_filter_rules());
        let auth = auth.clone();
        crate::tools::WebhookControl {
            retry_interval: interval,
            // The same notification the account page sends after a save.
            changed: Arc::new(move |account| auth.notify_account_changed(account)),
            max_filter_rules: watchers.max_filter_rules(),
        }
    });
    if let Some(watchers) = config.watchers {
        install_watch_extensions(&watchers, &extensions);
        auth.enable_webhooks(watchers.deliverer().clone());
        auth.add_deletion_listener(watchers.deletion_listener());
        auth.add_account_listener(std::sync::Arc::new(move |account| {
            watchers.refresh(account);
        }));
    }
    let uploads = crate::upload::router(store.clone(), config.bucket.clone(), auth.clone());
    let upload_url = format!("{}{}", auth.config().issuer(), crate::upload::UPLOAD_PATH);
    let tools = MailTools::new(store, servers, pool, tokens, webhook_control, selecting)
        .with_uploads(upload_url, config.bucket);
    let tools = install_tool_extensions(tools, &extensions);
    let protected = mcp_routes(tools, &auth, hosts, origins, limits, cancel, tenant_arg);

    let limited = Router::new()
        .merge(protected)
        .merge(page_routes(&auth, extensions))
        .merge(push_routes.unwrap_or_default())
        .layer(axum::Extension(auth))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            limits.request_timeout,
        ))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            limits.max_body_bytes,
        ))
        // Uploads keep their own size and time limits, inside the global cap.
        .merge(uploads)
        .layer(middleware::from_fn_with_state(
            GlobalLimit::new(limits.max_concurrent_requests),
            limit_global,
        ))
        // Outermost, so the request line also sees the limits' answers.
        .layer(request_log);
    // The health and readiness checks stay outside the limits so a busy
    // server is not mistaken for a dead or unready one, and outside the
    // request log, which would get a line every few seconds from them.
    probes.merge(limited)
}

/// Hands the embedding's watch ownership and usage hook to the watchers.
fn install_watch_extensions(watchers: &Watchers, extensions: &Extensions) {
    if let Some(ownership) = extensions.ownership() {
        watchers.set_ownership(ownership);
    }
    if let Some(hook) = extensions.usage_hook.clone() {
        watchers.set_usage_hook(hook);
    }
    watchers.set_metrics(extensions.metrics.clone());
}

/// The tools with the embedding's tools and usage hook, counting into the
/// server's metrics.
fn install_tool_extensions(tools: MailTools, extensions: &Extensions) -> MailTools {
    let mut tools = tools.with_metrics(extensions.metrics.clone());
    if let Some(extension) = extensions.tool_extension.clone() {
        tools = tools.with_extension(extension);
    }
    if let Some(hook) = extensions.usage_hook.clone() {
        tools = tools.with_usage_hook(hook);
    }
    tools
}

/// Hands the embedding's principal resolver and hooks to the OAuth side.
fn install_auth_extensions(auth: &AuthState, extensions: &Extensions) {
    if let Some(resolver) = extensions.principal_resolver.clone() {
        auth.set_principal_resolver(resolver);
    }
    if let Some(hook) = extensions.sign_in_hook.clone() {
        auth.set_sign_in_hook(hook);
    }
    if let Some(hook) = extensions.continuation_hook.clone() {
        auth.set_continuation_hook(hook);
    }
    if let Some(page) = extensions.invalid_request_page.clone() {
        auth.set_invalid_request_page(page);
    }
    if let Some(hook) = extensions.usage_hook.clone() {
        auth.set_usage_hook(hook);
    }
}

/// `/healthz`, and `/readyz` with the embedding's readiness checks.
fn probe_routes(store: &Store, extensions: &mut Extensions) -> Router {
    let readiness = Readiness::new(
        store.clone(),
        std::mem::take(&mut extensions.readiness_checks),
        extensions.draining.clone(),
    );
    Router::new()
        .route("/healthz", get(healthz))
        .with_state(store.clone())
        .merge(
            Router::new()
                .route("/readyz", get(readyz))
                .with_state(Arc::new(readiness)),
        )
}

/// The MCP endpoint behind its host and Origin checks, bearer check, mailbox
/// selector (when the tools take a `mailbox` argument) and per-account
/// limit.
fn mcp_routes(
    tools: MailTools,
    auth: &AuthState,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: RequestLimits,
    cancel: CancellationToken,
    tenant_argument: Option<&'static str>,
) -> Router {
    let host_check = auth.config().allowed_hosts.clone();
    let selector = tools.mailbox_selector(limits.max_body_bytes, tenant_argument);
    // rmcp only compares exact names; with a `*.` pattern the check below
    // is the only one.
    let mcp_config = if host_check.has_patterns() {
        StreamableHttpServerConfig::default().disable_allowed_hosts()
    } else {
        StreamableHttpServerConfig::default().with_allowed_hosts(allowed_hosts)
    };
    let mcp_config = mcp_config
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_max_request_body_bytes(limits.max_body_bytes)
        .with_cancellation_token(cancel);
    let mcp = StreamableHttpService::new(
        move || Ok(tools.clone()),
        Arc::new(NeverSessionManager::default()),
        mcp_config,
    );

    // Layers run outside-in in reverse order of `route_layer` calls: the
    // host and Origin checks first (before any token is looked at), then
    // the bearer check, then the request log's note of the caller, then the
    // mailbox selector, then the per-account limit, which counts the
    // selected mailbox.
    let mut routes = Router::new();
    if let Some(prefixed) = auth.config().prefixed_resource_route() {
        routes = routes.route_service(&prefixed, mcp.clone());
    }
    let mut routes =
        routes
            .route_service(MCP_PATH, mcp)
            .route_layer(middleware::from_fn_with_state(
                AccountLimit::new(limits.account_concurrency, ACCOUNT_WAIT),
                limit_account,
            ));
    if let Some(selector) = selector {
        routes = routes.route_layer(middleware::from_fn_with_state(selector, select_mailbox));
    }
    routes
        .route_layer(middleware::from_fn(crate::request_log::note_caller))
        .route_layer(middleware::from_fn_with_state(auth.clone(), require_bearer))
        .route_layer(middleware::from_fn_with_state(
            Arc::<[String]>::from(allowed_origins),
            require_allowed_origin,
        ))
        .route_layer(middleware::from_fn_with_state(
            host_check,
            require_allowed_host,
        ))
}

/// The landing page, the OAuth endpoints and account page, and an
/// embedding's routes.
fn page_routes(auth: &AuthState, extensions: Extensions) -> Router {
    let mut routes = Router::new();
    if extensions.default_pages {
        routes = routes.route("/", get(landing));
    }
    let mut options = postkeep_auth::RouterOptions::default();
    options.account_pages = extensions.default_pages;
    routes = routes.merge(postkeep_auth::router_with(auth.clone(), options));
    for extra in extensions.routes {
        routes = routes.merge(extra);
    }
    routes
}

/// Refuses a request whose `Host` this server does not serve, with the
/// answer rmcp gives, before the bearer token is looked at.
async fn require_allowed_host(
    axum::extract::State(hosts): axum::extract::State<AllowedHosts>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    match RequestHost::from_headers(request.headers()) {
        Some(host) if hosts.allows(&host) => next.run(request).await,
        _ => {
            tracing::warn!("refused an MCP request for a host this server does not serve");
            (
                StatusCode::FORBIDDEN,
                "Forbidden: Host header is not allowed",
            )
                .into_response()
        }
    }
}

/// Refuses a request from a page whose origin this server does not allow,
/// with the answer rmcp gives, before the bearer token is looked at (rmcp's
/// own check would run after it). Requests without an `Origin` pass.
async fn require_allowed_origin(
    axum::extract::State(origins): axum::extract::State<Arc<[String]>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let allowed = request.headers().get(header::ORIGIN).is_none_or(|value| {
        value
            .to_str()
            .ok()
            .and_then(origin)
            .is_some_and(|origin| origins.contains(&origin))
    });
    if allowed {
        next.run(request).await
    } else {
        tracing::warn!("refused an MCP request from an origin this server does not allow");
        (
            StatusCode::FORBIDDEN,
            "Forbidden: Origin header is not allowed",
        )
            .into_response()
    }
}

/// The public URL's host (with and without an explicit port) plus extras.
fn allowed_hosts(issuer: &str, extra: &[String]) -> Vec<String> {
    let mut hosts = Vec::new();
    if let Ok(url) = url::Url::parse(issuer)
        && let Some(host) = url.host_str()
    {
        hosts.push(host.to_owned());
        if let Some(port) = url.port() {
            hosts.push(format!("{host}:{port}"));
        }
    }
    hosts.extend(
        extra
            .iter()
            .map(|host| host.trim().to_owned())
            .filter(|host| !host.is_empty()),
    );
    hosts
}

/// The public URL's origin plus the extras that are origins.
fn allowed_origins(issuer: &str, extra: &[String]) -> Vec<String> {
    std::iter::once(issuer)
        .chain(extra.iter().map(String::as_str))
        .filter_map(origin)
        .collect()
}

/// `value` as an origin: `scheme://host`, with the port unless it is the
/// scheme's default. `None` when `value` has a path, query, fragment,
/// credentials or wildcard, or no host.
pub(crate) fn origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value.trim()).ok()?;
    let host = url
        .host_str()
        .filter(|host| !host.is_empty() && !host.contains('*'))?
        .to_ascii_lowercase();
    let bare = matches!(url.path(), "" | "/")
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    bare.then(|| {
        let port = url
            .port()
            .map_or_else(String::new, |port| format!(":{port}"));
        format!("{}://{host}{port}", url.scheme())
    })
}

async fn landing(axum::Extension(auth): axum::Extension<AuthState>) -> impl IntoResponse {
    let endpoint = auth.config().resource();
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!(
            "postkeep {}\n\nAdd this MCP server URL to your MCP client:\n\n    {endpoint}\n\n\
             The client opens a sign-in page where you connect your mail account: iCloud \
             Mail with an app-specific password, Fastmail or Yahoo Mail with an app \
             password, or Outlook and Gmail with your Microsoft or Google account when the \
             server offers them.\n\nDocs: {}\nSource: {}\n",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_HOMEPAGE"),
            env!("CARGO_PKG_REPOSITORY"),
        ),
    )
}

async fn healthz(State(store): State<Store>) -> impl IntoResponse {
    match store.ping().await {
        Ok(()) => (StatusCode::OK, "ok"),
        Err(err) => {
            tracing::error!(error = %err, "health check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
    }
}

/// Removes expired codes and tokens and abandoned client registrations
/// every `period` until `cancel` fires. With uploads on, use
/// [`purge_on_schedule`] with the bucket, so their pieces are deleted too.
pub async fn purge_expired(
    store: Store,
    policy: PurgePolicy,
    period: Duration,
    cancel: CancellationToken,
) {
    purge_on_schedule(store, policy, period, None, None, cancel).await;
}

/// [`purge_expired`], skipping the runs `ownership` leaves to another
/// process, and then the uploads' cleanup, which deletes the pieces of used
/// uploads in `bucket`.
///
/// A cleanup under way when `cancel` fires is dropped: the uploads it had not
/// forgotten yet wait for the next one.
pub async fn purge_on_schedule(
    store: Store,
    policy: PurgePolicy,
    period: Duration,
    ownership: Option<Arc<dyn WatchOwnership>>,
    bucket: Option<Arc<dyn Bucket>>,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(period);
    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = interval.tick() => {
                if ownership.as_ref().is_some_and(|ownership| !ownership.runs(SharedJob::Purge)) {
                    continue;
                }
                match store.purge_expired(policy).await {
                    Ok(0) => {}
                    Ok(removed) => tracing::debug!(removed, "purged expired OAuth records"),
                    Err(err) => tracing::warn!(error = %err, "could not purge expired OAuth records"),
                }
                let clean = async {
                    match store.uploads_to_clean(crate::upload::UPLOAD_TIME, crate::upload::CLEAN_BATCH).await {
                        Ok(used) => crate::upload::delete_pieces(&store, bucket.as_deref(), &used).await,
                        Err(err) => tracing::warn!(error = %err, "could not clean up uploads"),
                    }
                };
                tokio::select! {
                    () = cancel.cancelled() => break,
                    () = clean => {}
                }
            }
        }
    }
}

/// How often the values still under the master key are moved to data keys and
/// data keys are wrapped again.
const REENCRYPT_PERIOD: Duration = Duration::from_hours(1);

/// Moves the values still stored under the master key to data keys, and wraps
/// data keys again, shortly after the process starts and then every
/// [`REENCRYPT_PERIOD`] until `cancel` fires, except for the runs `ownership`
/// leaves to another process. A pass under way when `cancel` fires is stopped at
/// its next await: what it did stays done, and the next pass does the rest.
pub(crate) async fn reencrypt_on_schedule(
    store: Store,
    ownership: Option<Arc<dyn WatchOwnership>>,
    cancel: CancellationToken,
) {
    let (ownership, pass) = (ownership.as_deref(), || migrate_stored_values(&store));
    let job = SharedJob::Reencrypt;
    on_schedule(job, REENCRYPT_PERIOD, ownership, &cancel, pass).await;
}

/// Calls `pass` at the first tick and then every `period` until `cancel`
/// fires, unless `ownership` leaves `job` to another process: it is asked
/// before each run. A pass under way when `cancel` fires is dropped at its next
/// await, so shutdown does not wait for it.
async fn on_schedule<Pass, Done>(
    job: SharedJob,
    period: Duration,
    ownership: Option<&dyn WatchOwnership>,
    cancel: &CancellationToken,
    mut pass: Pass,
) where
    Pass: FnMut() -> Done + Send,
    Done: Future<Output = ()> + Send,
{
    let mut interval = tokio::time::interval(period);
    // A pass that outlasts the period, as the first can on a large database,
    // is not made up for with passes one after the other.
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        // `biased`: a shutdown that has fired wins over a tick that is due.
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = interval.tick() => {
                if ownership.is_some_and(|ownership| !ownership.runs(job)) {
                    continue;
                }
                // A pass that shutdown cuts short loses nothing: every change it
                // makes is one statement.
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    () = pass() => {}
                }
            }
        }
    }
}

/// One pass: the sweep and then, whatever its result, the re-wrap. A part that
/// fails is logged and left for the next pass.
async fn migrate_stored_values(store: &Store) {
    let swept = store.reencrypt().await;
    if let Err(err) = &swept {
        tracing::warn!(error = %err, "could not move stored secrets to data keys");
    }
    let wrapped = store.rewrap_data_keys().await;
    if let Err(err) = &wrapped {
        tracing::warn!(error = %err, "could not re-wrap data keys");
    }
    if let (Ok(swept), Ok(wrapped)) = (swept, wrapped) {
        log_pass(&swept, &wrapped, store.rotating_keys());
    }
}

/// The line of a pass that ended without an error: `info` while previous master
/// keys are set, because whoever rolls the key waits for a line that says
/// nothing is left; else `info` when it moved a value, lost a race to a writer
/// or wrapped a key again, and `debug` when it found nothing to do, since that
/// pass runs every hour.
fn log_pass(swept: &Reencrypted, wrapped: &Rewrapped, rotating: bool) {
    macro_rules! line {
        ($level:ident) => {
            tracing::$level!(
                converted = swept.updated,
                already_v2 = swept.already_v2,
                unreadable = swept.unreadable,
                lost_races = swept.lost_races,
                rewrapped = wrapped.rewrapped,
                unreadable_keys = wrapped.unreadable,
                "migrated stored values"
            )
        };
    }
    if rotating || swept.updated > 0 || swept.lost_races > 0 || wrapped.rewrapped > 0 {
        line!(info);
    } else {
        line!(debug);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests should fail loudly")]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use postkeep_store::{
        DataKey, Kek, KeyWrapper, LocalKeyWrapper, MasterKey, NewClient, StoreError, WrapFuture,
        Wrapped,
    };

    use super::*;

    /// Gives this process the purge while `turn` is set.
    #[derive(Default)]
    struct Turns {
        turn: AtomicBool,
        asked: AtomicUsize,
    }

    impl WatchOwnership for Turns {
        fn runs(&self, job: SharedJob) -> bool {
            assert_eq!(job, SharedJob::Purge);
            self.asked.fetch_add(1, Ordering::SeqCst);
            self.turn.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn the_purge_skips_the_runs_the_ownership_hook_leaves_to_another_process() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("purge.db").display());
        let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
        let store = Store::connect(&url, &key).await.unwrap();
        let client = store
            .create_client(&NewClient {
                redirect_uris: vec!["http://127.0.0.1/callback".to_owned()],
                ..NewClient::default()
            })
            .await
            .unwrap();
        let policy = PurgePolicy {
            unused_client_ttl: Duration::ZERO,
            idle_client_ttl: Duration::ZERO,
        };
        let turns = Arc::new(Turns::default());
        let cancel = CancellationToken::new();
        let purge = tokio::spawn(purge_on_schedule(
            store.clone(),
            policy,
            Duration::from_millis(20),
            Some(turns.clone()),
            None,
            cancel.clone(),
        ));

        for _ in 0..100 {
            if turns.asked.load(Ordering::SeqCst) >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(turns.asked.load(Ordering::SeqCst) >= 3);
        assert!(
            store.client(&client.id).await.unwrap().is_some(),
            "purged on another process's turn"
        );

        turns.turn.store(true, Ordering::SeqCst);
        for _ in 0..100 {
            if store.client(&client.id).await.unwrap().is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(store.client(&client.id).await.unwrap().is_none());
        cancel.cancel();
        purge.await.unwrap();
    }

    const HOUR: Duration = Duration::from_hours(1);

    /// The key `[7; 32]`, and the `v1.` text that it gives for the app password
    /// of `a@icloud.com`, as the store's upgrade test has them: this crate
    /// cannot seal a value under the master key itself.
    const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    const PASSWORD: &str = "v1.AAECAwQFBgcICQoLeeOKFHxrui0W0Ib4gzoPnpoIGEwd-_0hdUaq2rZR4IQ";
    /// The key that a rotation moves to.
    const NEW_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn key(text: &str) -> MasterKey {
        MasterKey::parse(text).unwrap()
    }

    /// Leaves the shared jobs to another process while `turn` is clear, and
    /// keeps what it is asked.
    #[derive(Default)]
    struct Gate {
        turn: AtomicBool,
        asked: Mutex<Vec<SharedJob>>,
        heard: tokio::sync::Notify,
    }

    impl Gate {
        fn asked(&self) -> Vec<SharedJob> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl WatchOwnership for Gate {
        fn runs(&self, job: SharedJob) -> bool {
            self.asked.lock().unwrap().push(job);
            self.heard.notify_one();
            self.turn.load(Ordering::SeqCst)
        }
    }

    struct Sink(Arc<Mutex<Vec<u8>>>, Arc<tokio::sync::Notify>);

    impl std::io::Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            self.1.notify_waiters();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// What this thread logs at `debug` level and above while it lives.
    struct Captured {
        text: Arc<Mutex<Vec<u8>>>,
        written: Arc<tokio::sync::Notify>,
        _scope: tracing::subscriber::DefaultGuard,
        _idle: tracing::Dispatch,
    }

    impl Captured {
        fn new() -> Self {
            let text = Arc::new(Mutex::new(Vec::new()));
            let written = Arc::new(tokio::sync::Notify::new());
            let (writer, wake) = (Arc::clone(&text), Arc::clone(&written));
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .without_time()
                .with_writer(move || Sink(Arc::clone(&writer), Arc::clone(&wake)))
                .finish();
            // Another dispatcher alive makes tracing ask every one about a
            // callsite, not only the default of the thread that reached it first.
            let idle = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
            Self {
                text,
                written,
                _scope: tracing::subscriber::set_default(subscriber),
                _idle: idle,
            }
        }

        /// Returns once a line says `message`.
        async fn wait_for(&self, message: &str) {
            loop {
                let written = self.written.notified();
                tokio::pin!(written);
                written.as_mut().enable();
                if !self.says(message).is_empty() {
                    return;
                }
                written.await;
            }
        }

        /// The level and the `name=value` words of each line that says `message`.
        fn says(&self, message: &str) -> Vec<String> {
            let text = String::from_utf8(self.text.lock().unwrap().clone()).unwrap();
            let words = |line: &str| {
                let words = line.split_whitespace();
                let words = words.filter(|w| w.contains('=') || w.chars().all(char::is_uppercase));
                words.collect::<Vec<_>>().join(" ")
            };
            text.lines()
                .filter(|line| line.contains(message))
                .map(words)
                .collect()
        }
    }

    /// A database that an earlier version filled under `KEY`: two accounts with
    /// the app password above, which only the first one's address opens, and a
    /// data key for each of `tenants`, wrapped under `KEY`. Returns its URL.
    async fn filled(dir: &tempfile::TempDir, tenants: &[&str]) -> String {
        let url = format!("sqlite://{}", dir.path().join("pass.db").display());
        let old = Store::connect(&url, &key(KEY)).await.unwrap();
        for tenant in tenants {
            old.for_tenant(tenant).data_key().await.unwrap();
        }
        for (id, email) in [("acct-1", "a@icloud.com"), ("acct-2", "b@icloud.com")] {
            let insert = "INSERT INTO accounts (id, email, password_ciphertext, created_at, \
                          updated_at) VALUES ($1, $2, $3, 1, 1)";
            let query = sqlx::query(insert).bind(id).bind(email).bind(PASSWORD);
            query.execute(old.pool()).await.unwrap();
        }
        old.close().await;
        url
    }

    async fn password(store: &Store, id: &str) -> String {
        sqlx::query_scalar("SELECT password_ciphertext FROM accounts WHERE id = $1")
            .bind(id)
            .fetch_one(store.pool())
            .await
            .unwrap()
    }

    /// Starts the background job on `store` with `gate` as its hook, waits for
    /// `until` and ends the job. Shutdown stops a pass under way, so `until` has
    /// to be something that the pass leaves behind when it is done.
    async fn run_job(store: &Store, gate: &Arc<Gate>, until: impl Future<Output = ()>) {
        let cancel = CancellationToken::new();
        let (store, hook): (_, Arc<dyn WatchOwnership>) = (store.clone(), gate.clone());
        let job = tokio::spawn(reencrypt_on_schedule(store, Some(hook), cancel.clone()));
        let waited = tokio::time::timeout(Duration::from_secs(30), until).await;
        assert!(waited.is_ok(), "the job did not do what the test waits for");
        cancel.cancel();
        job.await.unwrap();
    }

    /// A pass that counts how often it runs.
    fn counting() -> (
        Arc<AtomicUsize>,
        impl FnMut() -> std::future::Ready<()> + Send,
    ) {
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let pass = move || {
            counted.fetch_add(1, Ordering::SeqCst);
            std::future::ready(())
        };
        (runs, pass)
    }

    /// Runs `pass` on the schedule of the background job, on the paused clock.
    fn scheduled<Done: Future<Output = ()> + Send>(
        gate: Option<&Arc<Gate>>,
        pass: impl FnMut() -> Done + Send + 'static,
    ) -> (tokio::task::JoinHandle<()>, CancellationToken) {
        let (gate, cancel) = (gate.cloned(), CancellationToken::new());
        let stop = cancel.clone();
        let job = tokio::spawn(async move {
            let hook = gate.as_deref().map(|gate| gate as &dyn WatchOwnership);
            on_schedule(SharedJob::Reencrypt, HOUR, hook, &stop, pass).await;
        });
        (job, cancel)
    }

    /// Moves the paused clock on and lets the tasks that are ready run.
    async fn advance(by: Duration) {
        tokio::time::advance(by).await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    /// Ends `job`. One that honours shutdown ends at once; the clock runs on
    /// while it is waited for, so one that goes on fails the wait.
    async fn shut_down(job: tokio::task::JoinHandle<()>, cancel: &CancellationToken) {
        cancel.cancel();
        let ended = tokio::time::timeout(Duration::from_secs(60), job).await;
        assert!(ended.is_ok(), "the job did not end");
    }

    #[tokio::test(start_paused = true)]
    async fn the_schedule_runs_a_pass_at_start_and_each_period_the_hook_gives_to_this_process() {
        let (runs, pass) = counting();
        let gate = Arc::new(Gate::default());
        gate.turn.store(true, Ordering::SeqCst);
        let (job, cancel) = scheduled(Some(&gate), pass);
        let state = || (runs.load(Ordering::SeqCst), gate.asked().len());

        advance(Duration::ZERO).await;
        assert_eq!(state(), (1, 1), "at start");
        advance(HOUR.saturating_sub(Duration::from_millis(1))).await;
        assert_eq!(state(), (1, 1), "before a period is over");
        advance(Duration::from_millis(1)).await;
        assert_eq!(state(), (2, 2), "after a period");
        gate.turn.store(false, Ordering::SeqCst);
        advance(HOUR).await;
        assert_eq!(state(), (2, 3), "left to another process");
        gate.turn.store(true, Ordering::SeqCst);
        advance(HOUR).await;
        assert_eq!(state(), (3, 4), "given back");
        assert!(gate.asked().iter().all(|job| *job == SharedJob::Reencrypt));
        shut_down(job, &cancel).await;
    }

    #[tokio::test(start_paused = true)]
    async fn the_schedule_runs_every_pass_when_there_is_no_hook() {
        let (runs, pass) = counting();
        let (job, cancel) = scheduled(None, pass);

        advance(Duration::ZERO).await;
        assert_eq!(runs.load(Ordering::SeqCst), 1, "at start");
        advance(HOUR).await;
        assert_eq!(runs.load(Ordering::SeqCst), 2, "after a period");
        shut_down(job, &cancel).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_pass_that_outlasts_the_period_is_not_made_up_for() {
        // The first pass takes two and a half periods, the others no time.
        let runs = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&runs);
        let pass = move || {
            let first = counted.fetch_add(1, Ordering::SeqCst) == 0;
            async move {
                if first {
                    tokio::time::sleep(HOUR * 5 / 2).await;
                }
            }
        };
        let (job, cancel) = scheduled(None, pass);
        let started = || runs.load(Ordering::SeqCst);

        advance(Duration::ZERO).await;
        assert_eq!(started(), 1, "the long pass is under way");
        advance(HOUR * 5 / 2).await;
        // The ticks it missed are due at once. With `Burst` each of the two would
        // start a pass now; with `Delay` they make one.
        assert_eq!(started(), 2, "one pass for the missed ticks");
        advance(HOUR * 9 / 10).await;
        assert_eq!(started(), 2, "the next is a period after that one");
        advance(HOUR / 10).await;
        assert_eq!(started(), 3, "a period after that one");
        shut_down(job, &cancel).await;
    }

    /// The job as the server starts it, on the paused clock. The hook leaves every
    /// run to another process, so the job does not touch the database, and the
    /// questions it is asked say how often it would run.
    #[tokio::test]
    async fn the_job_asks_the_hook_at_start_and_every_hour() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("hourly.db").display());
        // Connecting waits on a thread of the database; that needs the real clock.
        let store = Store::connect(&url, &key(KEY)).await.unwrap();
        tokio::time::pause();
        let gate = Arc::new(Gate::default());
        let (hook, cancel): (Arc<dyn WatchOwnership>, _) = (gate.clone(), CancellationToken::new());
        let job = tokio::spawn(reencrypt_on_schedule(store, Some(hook), cancel.clone()));

        // The clock stopped between two of its milliseconds, so the tick that is
        // due at once falls due when the clock has moved on by a millisecond.
        let ms = Duration::from_millis(1);
        advance(Duration::ZERO).await;
        advance(ms).await;
        assert_eq!(gate.asked().len(), 1, "at start");
        advance(HOUR.saturating_sub(ms * 3)).await;
        assert_eq!(gate.asked().len(), 1, "before an hour is over");
        advance(ms * 4).await;
        assert_eq!(gate.asked().len(), 2, "after an hour");
        advance(HOUR).await;
        assert_eq!(gate.asked().len(), 3, "after two hours");
        shut_down(job, &cancel).await;
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_ends_a_pass_that_never_finishes() {
        let (job, cancel) = scheduled(None, std::future::pending::<()>);

        advance(Duration::ZERO).await;
        shut_down(job, &cancel).await;
    }

    #[tokio::test(start_paused = true)]
    async fn a_shutdown_that_fires_while_a_tick_is_due_beats_the_tick() {
        // Without `biased`, `select!` takes the due tick about half the time: 40
        // tries leave no doubt. The job is polled by hand, so that the shutdown
        // and the tick are both ready when it looks.
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        for _ in 0..40 {
            let (runs, pass) = counting();
            let cancel = CancellationToken::new();
            let job = on_schedule(SharedJob::Reencrypt, HOUR, None, &cancel, pass);
            let mut job = std::pin::pin!(job);
            assert!(job.as_mut().poll(&mut cx).is_pending(), "waits for a tick");
            assert_eq!(runs.load(Ordering::SeqCst), 1, "a pass at start");

            cancel.cancel();
            advance(HOUR).await;
            assert!(job.as_mut().poll(&mut cx).is_ready(), "ends");
            assert_eq!(
                runs.load(Ordering::SeqCst),
                1,
                "a pass after shutdown fired"
            );
        }
    }

    #[test]
    fn a_pass_is_logged_at_info_when_it_changed_something_or_keys_are_rotating() {
        let log = Captured::new();
        // converted, already_v2, unreadable, lost_races, rewrapped, unreadable_keys; rotating
        let cases = [
            ([0, 0, 0, 0, 0, 0], false, "DEBUG"),
            ([0, 2, 3, 0, 0, 6], false, "DEBUG"),
            ([1, 0, 0, 0, 0, 0], false, "INFO"),
            ([0, 0, 0, 4, 0, 0], false, "INFO"),
            ([0, 0, 0, 0, 5, 0], false, "INFO"),
            ([1, 2, 3, 4, 5, 6], false, "INFO"),
            ([0, 0, 0, 0, 0, 0], true, "INFO"),
            ([0, 2, 3, 0, 0, 6], true, "INFO"),
            ([1, 2, 3, 4, 5, 6], true, "INFO"),
        ];
        let mut expected = Vec::new();
        for (c, rotating, level) in cases {
            let (mut swept, mut wrapped) = (Reencrypted::default(), Rewrapped::default());
            (swept.updated, swept.already_v2, swept.unreadable) = (c[0], c[1], c[2]);
            (swept.lost_races, wrapped.rewrapped, wrapped.unreadable) = (c[3], c[4], c[5]);
            log_pass(&swept, &wrapped, rotating);
            expected.push(format!(
                "{level} converted={} already_v2={} unreadable={} lost_races={} rewrapped={} \
                 unreadable_keys={}",
                c[0], c[1], c[2], c[3], c[4], c[5]
            ));
        }
        assert_eq!(log.says("migrated stored values"), expected);
    }

    #[tokio::test]
    async fn a_pass_that_fails_is_tried_again_and_does_not_hold_back_the_re_wrap() {
        let dir = tempfile::tempdir().unwrap();
        let url = filled(&dir, &["default"]).await;
        let store = Store::connect_rotating(&url, &key(NEW_KEY), &[key(KEY)])
            .await
            .unwrap();
        // The sweep gets to its last column and fails there.
        let rename = "ALTER TABLE mail_events RENAME COLUMN payload_ciphertext TO gone";
        sqlx::query(rename).execute(store.pool()).await.unwrap();
        let log = Captured::new();

        migrate_stored_values(&store).await;

        let warned = log.says("could not move stored secrets to data keys");
        assert_eq!(warned.len(), 1);
        assert!(warned[0].starts_with("WARN"), "{warned:?}");
        assert_eq!(log.says("migrated stored values"), Vec::<String>::new());
        let kek: String = sqlx::query_scalar("SELECT kek_id FROM data_keys")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let new_key_id = LocalKeyWrapper::new(&key(NEW_KEY), &[]).current().id;
        assert_eq!(kek, new_key_id, "wrapped again all the same");

        // The next pass finds the column again and ends without an error.
        let restore = "ALTER TABLE mail_events RENAME COLUMN gone TO payload_ciphertext";
        sqlx::query(restore).execute(store.pool()).await.unwrap();
        migrate_stored_values(&store).await;
        // It moved nothing, and the store has previous keys: the line is at info.
        let line = "INFO converted=0 already_v2=1 unreadable=1 lost_races=0 rewrapped=0 \
                    unreadable_keys=0";
        assert_eq!(log.says("migrated stored values"), [line]);
    }

    /// A key service that wraps, and answers every unwrap with `KeyWrap`.
    struct Unreachable(LocalKeyWrapper);

    impl KeyWrapper for Unreachable {
        fn current(&self) -> Kek {
            self.0.current()
        }

        fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
            self.0.wrap(tenant, key)
        }

        fn unwrap<'a>(
            &'a self,
            _tenant: &'a str,
            _kek: &'a Kek,
            _wrapped: &'a [u8],
        ) -> WrapFuture<'a, DataKey> {
            let down = StoreError::KeyWrap("the key service does not answer".to_owned());
            Box::pin(std::future::ready(Err(down)))
        }
    }

    #[tokio::test]
    async fn a_re_wrap_that_fails_is_logged_and_the_sweep_is_not_blamed() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("rewrap.db").display());
        // A data key under the old master key and no value to move: the sweep has
        // nothing to ask the key service about, and the re-wrap has the key.
        let old = Store::connect(&url, &key(KEY)).await.unwrap();
        old.data_key().await.unwrap();
        old.close().await;
        let service = Unreachable(LocalKeyWrapper::new(&key(NEW_KEY), &[key(KEY)]));
        let store = Store::connect_rotating(&url, &key(NEW_KEY), &[key(KEY)])
            .await
            .unwrap()
            .with_key_wrapper(Arc::new(service));
        let log = Captured::new();

        migrate_stored_values(&store).await;

        let warned = log.says("could not re-wrap data keys");
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(warned[0].starts_with("WARN"), "{warned:?}");
        let sweep = log.says("could not move stored secrets to data keys");
        assert_eq!(sweep, Vec::<String>::new());
        assert_eq!(log.says("migrated stored values"), Vec::<String>::new());
    }

    #[tokio::test]
    async fn the_background_job_moves_the_values_of_a_server_without_previous_keys() {
        let dir = tempfile::tempdir().unwrap();
        let url = filled(&dir, &[]).await;
        let store = Store::connect(&url, &key(KEY)).await.unwrap();
        let log = Captured::new();
        let gate = Arc::new(Gate::default());

        run_job(&store, &gate, gate.heard.notified()).await;
        assert_eq!(password(&store, "acct-1").await, PASSWORD);
        assert_eq!(log.says("migrated stored values"), Vec::<String>::new());

        gate.turn.store(true, Ordering::SeqCst);
        run_job(&store, &gate, log.wait_for("migrated stored values")).await;
        assert_eq!(gate.asked(), [SharedJob::Reencrypt; 2]);
        assert!(password(&store, "acct-1").await.starts_with("v2.1."));
        let line = "INFO converted=1 already_v2=0 unreadable=1 lost_races=0 rewrapped=0 \
                    unreadable_keys=0";
        assert_eq!(log.says("migrated stored values"), [line]);
        // The value no key opens is named at debug level, not as a warning.
        let named = log.says("stored secret is unreadable with every configured key");
        assert_eq!(named.len(), 1);
        assert!(named[0].starts_with("DEBUG"), "{named:?}");
    }

    #[test]
    fn derives_allowed_hosts() {
        assert_eq!(
            allowed_hosts(
                "https://mail.example.com",
                &[" proxy.internal ".to_owned(), String::new()]
            ),
            ["mail.example.com", "proxy.internal"]
        );
        assert_eq!(
            allowed_hosts("http://localhost:8080", &[]),
            ["localhost", "localhost:8080"]
        );
    }

    #[test]
    fn derives_allowed_origins() {
        assert_eq!(
            allowed_origins(
                "https://mail.example.com",
                &[
                    " HTTP://LocalHost:6274/ ".to_owned(),
                    "not an origin".to_owned()
                ]
            ),
            ["https://mail.example.com", "http://localhost:6274"]
        );
    }

    #[test]
    fn origins_are_scheme_host_and_port() {
        for (value, expected) in [
            (
                "https://Mail.Example.com:443",
                Some("https://mail.example.com"),
            ),
            (
                "http://mail.example.com:443",
                Some("http://mail.example.com:443"),
            ),
            ("http://[::1]:8080", Some("http://[::1]:8080")),
            (
                "chrome-extension://abcdefghijklmnop",
                Some("chrome-extension://abcdefghijklmnop"),
            ),
            (
                "moz-extension://ABCD-1234",
                Some("moz-extension://abcd-1234"),
            ),
            ("https://mail.example.com/mcp", None),
            ("https://mail.example.com/?q=1", None),
            ("https://mail.example.com/#top", None),
            ("https://user@mail.example.com", None),
            ("https://*.example.com", None),
            ("mail.example.com", None),
            ("file:///index.html", None),
            ("null", None),
            ("", None),
        ] {
            assert_eq!(origin(value).as_deref(), expected, "{value:?}");
        }
    }
}
