//! Subcommand implementations.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use postkeep_auth::{AuthConfig, MailVerifier};
use postkeep_mail::ImapServers;
use postkeep_store::{MasterKey, Migrations, PurgePolicy, STORAGE_LEVEL_READS, Store, StoreError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer, Registry};

use crate::app::{self, AppConfig, Extensions, MCP_PATH, RequestLimits};
use crate::cli::{
    HealthcheckArgs, LevelAction, LogFormat, MigrateArgs, ServeArgs, StorageLevelArgs,
};
use crate::http::{self, ConnectionLimits};
use crate::metrics::Metrics;
use crate::pool::PoolConfig;
use crate::watch::{WatchConfig, Watchers};
use postkeep_webhook::Deliverer;

/// Error type for the binary: a message for the operator.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// How often expired OAuth records are removed.
const PURGE_PERIOD: Duration = Duration::from_mins(10);

/// How long watchers get to log out at shutdown.
const WATCHER_GRACE: Duration = Duration::from_secs(5);

/// Open connections on the metrics address: a scraper or two needs few, and
/// anyone who reaches that address can read it.
const METRICS_CONNECTIONS: usize = 16;

/// Applies pending database migrations and reports what it did. Running it
/// on an up-to-date database changes nothing and succeeds.
///
/// # Errors
///
/// Returns an error if the database cannot be reached or a migration fails.
pub async fn migrate(args: &MigrateArgs) -> Result<(), Error> {
    let applied = Store::migrate(args.url())
        .await
        .map_err(|err| format!("could not migrate the database: {err}"))?;
    let message = if applied.is_empty() {
        "the database is up to date".to_owned()
    } else {
        let versions: Vec<String> = applied
            .iter()
            .map(|version| format!("{version:04}"))
            .collect();
        format!("applied migrations {}", versions.join(", "))
    };
    writeln!(std::io::stdout().lock(), "{message}")?;
    Ok(())
}

/// Prints the database's storage level and the one this version reads. With
/// [`LevelAction::Raise`] it then raises the level to the latter, if lower.
///
/// # Errors
///
/// Returns an error if the level cannot be read, or on a raise if it cannot
/// be raised or the database is above what this version reads.
pub async fn storage_level(args: &StorageLevelArgs) -> Result<(), Error> {
    let url = args.database.url();
    // The raise reports the level it found: a separate read could see another raise's.
    let raised = match args.action {
        Some(LevelAction::Raise) => Some(
            Store::raise_storage_level(url)
                .await
                .map_err(|err| format!("could not raise the storage level: {err}"))?,
        ),
        None => None,
    };
    let found = match raised {
        Some((found, _)) => found,
        None => Store::read_storage_level(url)
            .await
            .map_err(|err| format!("could not read the storage level: {err}"))?,
    };
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "storage level {found} in the database; this version reads up to level {STORAGE_LEVEL_READS}"
    )?;
    if let Some((from, to)) = raised {
        if from == to {
            writeln!(out, "the storage level is already {to}")?;
        } else {
            writeln!(out, "raised the storage level from {from} to {to}")?;
        }
    }
    Ok(())
}

/// Runs the server until SIGINT or SIGTERM: [`ServerBuilder`] with no
/// extensions.
///
/// # Errors
///
/// Returns an error for invalid configuration, an unreachable database or
/// a port that cannot be bound.
pub async fn serve(args: ServeArgs) -> Result<(), Error> {
    ServerBuilder::new(args).serve().await
}

/// Builds the server from its command-line settings and the additions of an
/// embedding, then runs it.
///
/// ```no_run
/// # async fn run(args: postkeep::cli::ServeArgs) -> Result<(), postkeep::Error> {
/// use axum::{Router, routing::get};
///
/// postkeep::ServerBuilder::new(args)
///     .route(Router::new().route("/status", get(|| async { "ok" })))
///     .default_pages(false)
///     .serve()
///     .await
/// # }
/// ```
///
/// With nothing added, it serves exactly what [`serve`] serves.
#[derive(Debug)]
pub struct ServerBuilder {
    args: ServeArgs,
    extensions: Extensions,
    store: Option<Store>,
    listener: Option<std::net::TcpListener>,
}

impl ServerBuilder {
    /// A server with the given settings and no additions.
    #[must_use]
    pub fn new(args: ServeArgs) -> Self {
        Self {
            args,
            extensions: Extensions::default(),
            store: None,
            listener: None,
        }
    }

    /// Serves from `store` instead of opening the database, so the
    /// embedding's own code can use the same connection pool
    /// ([`Store::pool`]). Open it with [`open_store`] and the same settings.
    /// The server closes it when it stops.
    #[must_use]
    pub fn store(mut self, store: Store) -> Self {
        self.store = Some(store);
        self
    }

    /// Serves on `listener` instead of binding `--bind`, which is then
    /// unused, so an embedding can bind before the runtime starts, or on
    /// port 0 and read the port. `serve` sets it non-blocking itself, and
    /// the log shows its address. `--metrics-bind` is unaffected.
    #[must_use]
    pub fn listener(mut self, listener: std::net::TcpListener) -> Self {
        self.listener = Some(listener);
        self
    }

    /// Serves `routes` beside the built-in ones; see [`Extensions::route`].
    #[must_use]
    pub fn route(mut self, routes: axum::Router) -> Self {
        self.extensions = self.extensions.route(routes);
        self
    }

    /// Decides who a bearer token on the MCP endpoint belongs to; see
    /// [`Extensions::principal_resolver`].
    #[must_use]
    pub fn principal_resolver(
        mut self,
        resolver: std::sync::Arc<dyn postkeep_auth::PrincipalResolver>,
    ) -> Self {
        self.extensions = self.extensions.principal_resolver(resolver);
        self
    }

    /// Hands `/authorize` requests for the resources `hook` handles to it;
    /// see [`Extensions::sign_in_hook`].
    #[must_use]
    pub fn sign_in_hook(mut self, hook: std::sync::Arc<dyn postkeep_auth::SignInHook>) -> Self {
        self.extensions = self.extensions.sign_in_hook(hook);
        self
    }

    /// Finishes the Microsoft or Google sign-ins the embedding starts for
    /// its tenants; see [`Extensions::continuation_hook`].
    #[must_use]
    pub fn continuation_hook(
        mut self,
        hook: std::sync::Arc<dyn postkeep_auth::ContinuationHook>,
    ) -> Self {
        self.extensions = self.extensions.continuation_hook(hook);
        self
    }

    /// Shows `page` for the requests `/authorize` refuses and for the
    /// server's own pages at `/oauth/{provider}/callback`; see
    /// [`Extensions::invalid_request_page`].
    #[must_use]
    pub fn invalid_request_page(
        mut self,
        page: std::sync::Arc<dyn postkeep_auth::InvalidRequestPage>,
    ) -> Self {
        self.extensions = self.extensions.invalid_request_page(page);
        self
    }

    /// Adds an embedding's tools, instructions and checks to the MCP
    /// endpoint; see [`Extensions::tool_extension`].
    #[must_use]
    pub fn tool_extension(
        mut self,
        extension: std::sync::Arc<dyn crate::tools::ToolExtension>,
    ) -> Self {
        self.extensions = self.extensions.tool_extension(extension);
        self
    }

    /// Asks `hook` before a sign-in adds a mailbox, a tool call and a send,
    /// and tells it how each call it allowed ended; see
    /// [`Extensions::usage_hook`].
    #[must_use]
    pub fn usage_hook(mut self, hook: std::sync::Arc<dyn postkeep_auth::UsageHook>) -> Self {
        self.extensions = self.extensions.usage_hook(hook);
        self
    }

    /// Decides which mailboxes this process watches and which shared jobs
    /// it runs; see [`Extensions::watch_ownership`].
    #[must_use]
    pub fn watch_ownership(
        mut self,
        ownership: std::sync::Arc<dyn crate::watch::WatchOwnership>,
    ) -> Self {
        self.extensions = self.extensions.watch_ownership(ownership);
        self
    }

    /// Makes every allowed host its own protected resource; see
    /// [`Extensions::per_request_resources`].
    #[must_use]
    pub fn per_request_resources(mut self, enabled: bool) -> Self {
        self.extensions = self.extensions.per_request_resources(enabled);
        self
    }

    /// Makes every name under `prefix` its own protected resource; see
    /// [`Extensions::resource_prefix`].
    #[must_use]
    pub fn resource_prefix(mut self, prefix: postkeep_auth::ResourcePrefix) -> Self {
        self.extensions = self.extensions.resource_prefix(prefix);
        self
    }

    /// Serves or leaves out the landing and account pages; see
    /// [`Extensions::default_pages`].
    #[must_use]
    pub fn default_pages(mut self, enabled: bool) -> Self {
        self.extensions = self.extensions.default_pages(enabled);
        self
    }

    /// Makes `/readyz` also wait for `check`; see
    /// [`Extensions::readiness_check`].
    #[must_use]
    pub fn readiness_check(
        mut self,
        check: std::sync::Arc<dyn crate::readiness::ReadinessCheck>,
    ) -> Self {
        self.extensions = self.extensions.readiness_check(check);
        self
    }

    /// Runs the server until SIGINT or SIGTERM. From that signal on,
    /// `/readyz` answers `503`; the server keeps serving for
    /// `POSTKEEP_SHUTDOWN_DRAIN` seconds, or until a second signal, then
    /// stops accepting connections and lets open requests finish.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, an unreachable database,
    /// a port that cannot be bound or a [`listener`](Self::listener) that
    /// cannot be used.
    pub async fn serve(self) -> Result<(), Error> {
        let Self {
            args,
            extensions,
            store,
            listener,
        } = self;
        run_server(args, extensions, store, listener).await
    }
}

async fn run_server(
    args: ServeArgs,
    extensions: Extensions,
    store: Option<Store>,
    listener: Option<std::net::TcpListener>,
) -> Result<(), Error> {
    init_logging(&args.log, args.log_format)?;

    let key = load_master_key(&args)?;
    let auth = auth_config(&args)?;
    let origins = allowed_origins(&args)?;
    let purge_policy = PurgePolicy {
        unused_client_ttl: Duration::from_secs(args.unused_client_ttl),
        idle_client_ttl: Duration::from_secs(args.idle_client_ttl),
    };
    warn_about_public_url(auth.issuer());

    let store = server_store(store, &args, &key).await?;
    store.set_outbox_policy(
        args.outbox_policy()
            .map_err(|message| -> Error { message.into() })?,
    )?;
    store.set_event_hold(Duration::from_secs(args.webhook_outbox_hold));
    let servers = auth.imap_servers.clone();
    pin_legacy_imap_server(&store, &servers).await?;
    let cancel = CancellationToken::new();
    let watchers = args.webhooks.then(|| {
        Watchers::new(
            store.clone(),
            servers,
            Deliverer::new(concat!("postkeep/", env!("CARGO_PKG_VERSION"))),
            WatchConfig {
                max_watchers: args.webhook_max_watchers,
                allowed_emails: auth.allowed_emails.clone(),
                // The same interval caps the growing delay and the pause,
                // so a webhook that is not paused yet never waits longer
                // than one that is.
                webhook_retry_interval: Duration::from_secs(args.webhook_retry_interval),
                outbox_max_backoff: Duration::from_secs(args.webhook_retry_interval),
                max_filter_rules: args.webhook_filter_max_rules,
                ..WatchConfig::default()
            },
            cancel.child_token(),
        )
    });
    let upstream = upstream_client(&args, &auth)?;
    let google_push = google_push(&args, &auth, upstream.as_ref(), watchers.is_some())?;
    let config = AppConfig {
        upstream,
        google_push,
        auth,
        extra_allowed_hosts: args.allowed_hosts.clone(),
        extra_allowed_origins: origins,
        limits: request_limits(&args),
        pool: PoolConfig {
            idle_timeout: Duration::from_secs(args.imap_pool_idle),
            ..PoolConfig::default()
        },
        watchers: watchers.clone(),
    };
    let resource = config.auth.resource();
    let draining = CancellationToken::new();
    let ownership = extensions.ownership();
    let metrics = Metrics::default();
    let router = app::router_with(
        config,
        store.clone(),
        MailVerifier,
        cancel.clone(),
        extensions
            .drain_on(draining.clone())
            .count_into(metrics.clone()),
    );

    let listener = bind_server(listener, args.bind).await?;
    let metrics_at = bind_metrics(args.metrics_bind).await?;
    tracing::info!(bind = %local_addr(&listener)?, mcp = %resource, version = env!("CARGO_PKG_VERSION"), "postkeep is ready");

    if let Some(watchers) = &watchers {
        watchers.start_all().await;
    }
    let jobs = spawn_jobs(&store, purge_policy, ownership, &cancel);
    let shutdown = cancel.clone();
    let drain = Duration::from_secs(args.shutdown_drain);
    let mut signals = ShutdownSignals::listen();
    tokio::join!(
        http::serve(
            listener,
            router,
            ConnectionLimits {
                max_connections: args.max_connections.max(1),
                ..ConnectionLimits::default()
            },
            async move {
                drain_signal(&mut signals, &draining, drain).await;
                tracing::info!("shutting down");
                shutdown.cancel();
            },
        ),
        serve_metrics(metrics_at, metrics, &store, watchers.as_ref(), &cancel),
    );
    cancel.cancel();
    if let Some(watchers) = &watchers {
        watchers.shutdown(WATCHER_GRACE).await;
    }
    finish_jobs(jobs).await;
    store.close().await;
    Ok(())
}

/// Takes the listener an embedding handed over, else binds `addr`.
async fn bind_server(
    listener: Option<std::net::TcpListener>,
    addr: SocketAddr,
) -> Result<tokio::net::TcpListener, Error> {
    let Some(listener) = listener else {
        return tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|err| format!("could not listen on {addr}: {err}").into());
    };
    listener
        .set_nonblocking(true)
        .and_then(|()| tokio::net::TcpListener::from_std(listener))
        .map_err(|err| format!("could not listen on the given listener: {err}").into())
}

/// Binds the metrics address, when one is set.
async fn bind_metrics(addr: Option<SocketAddr>) -> Result<Option<tokio::net::TcpListener>, Error> {
    let Some(addr) = addr else {
        return Ok(None);
    };
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|err| format!("could not listen on {addr} for metrics: {err}"))?;
    tracing::info!(bind = %local_addr(&listener)?, "serving metrics");
    Ok(Some(listener))
}

/// The address `listener` is bound to, which differs from the one asked for
/// when that one's port is 0.
fn local_addr(listener: &tokio::net::TcpListener) -> Result<SocketAddr, Error> {
    listener
        .local_addr()
        .map_err(|err| format!("could not read the address the server listens on: {err}").into())
}

/// Serves `GET /metrics` on `listener`, when there is one, with the gauges
/// of `store` and `watchers`, until `stop` is cancelled.
async fn serve_metrics(
    listener: Option<tokio::net::TcpListener>,
    metrics: Metrics,
    store: &Store,
    watchers: Option<&Watchers>,
    stop: &CancellationToken,
) {
    if let Some(listener) = listener {
        http::serve(
            listener,
            crate::metrics::router(metrics, store.clone(), watchers.cloned()),
            ConnectionLimits {
                max_connections: METRICS_CONNECTIONS,
                ..ConnectionLimits::default()
            },
            async move { stop.cancelled().await },
        )
        .await;
    }
}

/// Starts the jobs that run beside the server, for the whole database: the
/// purge, and the pass that moves stored values to data keys.
fn spawn_jobs(
    store: &Store,
    purge_policy: PurgePolicy,
    ownership: Option<std::sync::Arc<dyn crate::watch::WatchOwnership>>,
    cancel: &CancellationToken,
) -> [tokio::task::JoinHandle<()>; 2] {
    let purge = app::purge_on_schedule(
        store.clone(),
        purge_policy,
        PURGE_PERIOD,
        ownership.clone(),
        cancel.clone(),
    );
    let reencrypt = app::reencrypt_on_schedule(store.clone(), ownership, cancel.clone());
    [tokio::spawn(purge), tokio::spawn(reencrypt)]
}

/// Waits until both jobs have ended, which they do once the token they were
/// given has fired: the purge when its statement is done, the pass that moves
/// stored values at its next await.
async fn finish_jobs(jobs: [tokio::task::JoinHandle<()>; 2]) {
    for job in jobs {
        job.await.ok();
    }
}

/// The OAuth client for sign-in with Microsoft and Google, if either is
/// configured.
fn upstream_client(
    args: &ServeArgs,
    auth: &AuthConfig,
) -> Result<Option<postkeep_upstream::OAuthClient>, Error> {
    let (microsoft, google) = args.providers.apps()?;
    if microsoft.is_none() && google.is_none() {
        return Ok(None);
    }
    let public_url = url::Url::parse(auth.issuer())
        .map_err(|err| format!("POSTKEEP_PUBLIC_URL is not a valid URL: {err}"))?;
    let client = postkeep_upstream::OAuthClient::new(
        postkeep_upstream::Http::new(concat!("postkeep/", env!("CARGO_PKG_VERSION"))),
        postkeep_upstream::Endpoints::default(),
        public_url,
        microsoft,
        google,
    );
    for provider in client.configured() {
        tracing::info!(
            %provider,
            redirect_uri = %client.redirect_uri(provider),
            "sign-in with {} enabled",
            provider.display_name()
        );
    }
    Ok(Some(client))
}

/// Gmail push settings, if configured.
fn google_push(
    args: &ServeArgs,
    auth: &AuthConfig,
    upstream: Option<&postkeep_upstream::OAuthClient>,
    webhooks: bool,
) -> Result<Option<(String, postkeep_upstream::PushExpectations)>, Error> {
    let public_url = url::Url::parse(auth.issuer())
        .map_err(|err| format!("POSTKEEP_PUBLIC_URL is not a valid URL: {err}"))?;
    let Some(push) = args.providers.google_push(&public_url)? else {
        return Ok(None);
    };
    if !upstream
        .is_some_and(|client| client.is_configured(postkeep_upstream::UpstreamProvider::Google))
    {
        return Err("POSTKEEP_GOOGLE_PUBSUB_TOPIC needs POSTKEEP_GOOGLE_CLIENT_ID and POSTKEEP_GOOGLE_CLIENT_SECRET".to_owned().into());
    }
    if !webhooks {
        tracing::warn!(
            "POSTKEEP_GOOGLE_PUBSUB_TOPIC is set but webhooks are disabled; Gmail push stays off"
        );
    }
    tracing::info!(topic = %push.0, audience = %push.1.audience, "Gmail push through Pub/Sub enabled");
    Ok(Some(push))
}

/// The authorization server settings from the command line.
fn auth_config(args: &ServeArgs) -> Result<AuthConfig, Error> {
    let mut auth = AuthConfig::new(&args.public_url, MCP_PATH)?;
    auth.access_token_ttl = Duration::from_secs(args.access_token_ttl);
    auth.refresh_token_ttl = Duration::from_secs(args.refresh_token_ttl);
    let allowed: Vec<String> = args
        .allowed_emails
        .iter()
        .map(|email| email.trim().to_lowercase())
        .filter(|email| !email.is_empty())
        .collect();
    if !allowed.is_empty() {
        auth.allowed_emails = Some(allowed);
    }
    if let Some(name) = args
        .client_ip_header
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
    {
        auth.client_ip_header = Some(
            axum::http::HeaderName::try_from(name)
                .map_err(|_| format!("invalid client IP header name: {name:?}"))?,
        );
    }
    auth.registrations_per_ip = args.registration_limit;
    auth.registration_window = Duration::from_secs(args.registration_window.max(1));
    auth.max_clients = args.max_clients;
    auth.requests_per_minute = args.rate_limit.max(1);
    auth.account_backoff_max = Duration::from_secs(args.account_backoff_max);
    auth.ip_backoff_max = Duration::from_secs(args.ip_backoff_max);
    auth.imap_servers = args.mail.servers();
    if auth.imap_servers.is_empty() {
        return Err(
            "no mail provider is offered; set POSTKEEP_IMAP_PROVIDERS or POSTKEEP_IMAP_HOST".into(),
        );
    }
    Ok(auth)
}

/// The request limits from the command line, raised to their minimums.
fn request_limits(args: &ServeArgs) -> RequestLimits {
    RequestLimits {
        max_body_bytes: args.max_body_bytes.max(16 * 1024),
        request_timeout: Duration::from_secs(args.request_timeout.max(1)),
        max_concurrent_requests: args.max_concurrent_requests.max(1),
        account_concurrency: args.account_concurrency.max(1),
    }
}

/// The extra origins from `POSTKEEP_ALLOWED_ORIGINS`.
fn allowed_origins(args: &ServeArgs) -> Result<Vec<String>, Error> {
    args.allowed_origins
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| {
            app::origin(value).ok_or_else(|| -> Error {
                format!(
                    "POSTKEEP_ALLOWED_ORIGINS: {value:?} is not an origin such as https://app.example.com"
                )
                .into()
            })
        })
        .collect()
}

/// Records the current default server on accounts created before servers
/// were stored, so offering more servers later can't move them.
async fn pin_legacy_imap_server(store: &Store, servers: &ImapServers) -> Result<(), Error> {
    let Some(server) = servers.default_server() else {
        return Ok(());
    };
    let pinned = store
        .pin_imap_server(server.id.id())
        .await
        .map_err(|err| format!("could not update accounts: {err}"))?;
    if pinned > 0 {
        tracing::info!(
            accounts = pinned,
            server = server.id.id(),
            "recorded the mail server of existing accounts"
        );
    }
    Ok(())
}

/// Crates whose trace or debug logs include credentials or message bodies.
/// `(target prefix, highest level that stays enabled)`.
///
/// `async_imap` logs raw IMAP at trace, including `LOGIN` and `FETCH`
/// bodies. `imap_proto` is the parser beside it. `rmcp` logs MCP requests
/// and tool results at debug and whole JSON-RPC messages at trace.
/// `lettre` logs SMTP commands and message data at debug when its
/// `tracing` feature is compiled.
const SENSITIVE_LOG_CAPS: &[(&str, &str)] = &[
    ("async_imap", "warn"),
    ("imap_proto", "warn"),
    ("rmcp", "info"),
    ("lettre", "warn"),
];

/// Builds the process log filter from `user_filter`.
///
/// Directives that target [`SENSITIVE_LOG_CAPS`] are dropped and replaced
/// with those caps, so `POSTKEEP_LOG=trace` or `rmcp::service=debug` cannot
/// turn the leaks back on. Span directives such as `[serve_inner]=trace`
/// have no target and are kept; [`sensitive_log_cap`] still drops events
/// from a capped crate above its cap. Every other directive, including ones
/// for postkeep's own crates, is kept.
fn log_filter(user_filter: &str) -> String {
    let mut directives: Vec<&str> = user_filter
        .split(',')
        .map(str::trim)
        .filter(|directive| !directive.is_empty() && !directive_targets_sensitive(directive))
        .collect();
    let caps: Vec<String> = SENSITIVE_LOG_CAPS
        .iter()
        .map(|(target, level)| format!("{target}={level}"))
        .collect();
    directives.extend(caps.iter().map(String::as_str));
    directives.join(",")
}

/// Whether `directive` sets a level for one of [`SENSITIVE_LOG_CAPS`].
fn directive_targets_sensitive(directive: &str) -> bool {
    let target = directive
        .split(['=', '['])
        .next()
        .unwrap_or(directive)
        .trim();
    if target.is_empty() || is_bare_level(target) {
        return false;
    }
    SENSITIVE_LOG_CAPS.iter().any(|(name, _)| {
        target == *name
            || target
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with("::"))
    })
}

/// A directive with no target, such as `info` or `trace`.
fn is_bare_level(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "error" | "warn" | "warning" | "info" | "debug" | "trace" | "off"
    )
}

/// Drops events from [`SENSITIVE_LOG_CAPS`] above their cap.
///
/// `EnvFilter` span directives (`[serve_inner]=trace`) enable every target
/// inside a matching span, which overrides a static `async_imap=warn`
/// directive. This filter looks only at the event's own target and level.
/// It is a layer of its own beside the `EnvFilter` ([`log_subscriber`]), and
/// an event needs both to enable it, so a span directive cannot raise the cap.
fn sensitive_target_allowed(metadata: &tracing::Metadata<'_>) -> bool {
    let target = metadata.target();
    for (name, cap) in SENSITIVE_LOG_CAPS {
        let capped = target == *name
            || target
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with("::"));
        if capped {
            return metadata.level() <= &cap_level(cap);
        }
    }
    true
}

/// The most verbose level still emitted for a [`SENSITIVE_LOG_CAPS`] entry.
fn cap_level(cap: &str) -> tracing::Level {
    match cap {
        "info" => tracing::Level::INFO,
        "warn" => tracing::Level::WARN,
        _ => tracing::Level::ERROR,
    }
}

fn sensitive_log_cap() -> tracing_subscriber::filter::FilterFn<fn(&tracing::Metadata<'_>) -> bool> {
    tracing_subscriber::filter::filter_fn(sensitive_target_allowed)
}

/// The subscriber that writes to `output` what `env` allows, with the caps of
/// [`SENSITIVE_LOG_CAPS`] held.
///
/// `env` and the cap are layers of their own, not a per-layer filter
/// (`with_filter`) of `output`. A per-layer filter passes its answer for an
/// event to its layer in a thread-local, which the layer reads when the event
/// arrives. sqlx asks the `log` crate after each PostgreSQL statement whether
/// it would log it (`log::log_enabled!`); that reaches the subscriber through
/// `LogTracer` as `enabled` with no event after it, and the answer "no" then
/// sat in the thread-local until it dropped the next event of the thread whose
/// callsite is cached as enabled.
///
/// The cap has no level hint on purpose. The hints of layers combine by their
/// maximum, so one of `TRACE` would make the `log` crate ask the subscriber
/// about every record that `env` turns off.
fn log_subscriber(
    env: EnvFilter,
    output: impl Layer<Registry> + Send + Sync + 'static,
) -> impl tracing::Subscriber + Send + Sync + 'static {
    tracing_subscriber::registry()
        .with(output)
        .with(env)
        .with(sensitive_log_cap())
}

fn init_logging(filter: &str, format: LogFormat) -> Result<(), Error> {
    let spec = log_filter(filter);
    let env =
        EnvFilter::try_new(&spec).map_err(|err| format!("invalid log filter {spec:?}: {err}"))?;
    let output = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let result = match format {
        LogFormat::Text => log_subscriber(env, output).try_init(),
        LogFormat::Json => log_subscriber(env, output.json().flatten_event(true)).try_init(),
    };
    result.map_err(|err| format!("could not initialize logging: {err}").into())
}

fn load_master_key(args: &ServeArgs) -> Result<MasterKey, Error> {
    let text = match (&args.master_key, &args.master_key_file) {
        (Some(key), _) => key.clone(),
        (None, Some(path)) => std::fs::read_to_string(path).map_err(|err| {
            format!(
                "could not read the master key file {}: {err}",
                path.display()
            )
        })?,
        (None, None) => {
            return Err("set POSTKEEP_MASTER_KEY or POSTKEEP_MASTER_KEY_FILE".into());
        }
    };
    MasterKey::parse(text.trim()).map_err(|err| {
        format!("invalid master key ({err}); generate one with `postkeep generate-key`").into()
    })
}

/// Opens the database as [`ServerBuilder::serve`] does.
///
/// It uses the master key and any previous keys and the pool settings, and
/// applies or refuses pending migrations as
/// `POSTKEEP_DATABASE_MIGRATE_ON_START` says. An embedding opens it first to
/// share the connection pool ([`Store::pool`]) with its own code, then
/// passes it to [`ServerBuilder::store`]. When the server starts with previous
/// keys set, values still stored under the master key are moved to data keys
/// ([`Store::reencrypt`]), and data keys that a previous key wrapped are
/// wrapped again ([`Store::rewrap_data_keys`]), before it serves. It does both
/// again shortly after it starts and then every hour, with previous keys or not.
///
/// # Errors
///
/// Returns an error for a missing or invalid master key, an unreachable
/// database, a failed migration, or migrations pending while
/// `POSTKEEP_DATABASE_MIGRATE_ON_START` is false.
/// So is a database above the storage level this build reads.
pub async fn open_store(args: &ServeArgs) -> Result<Store, Error> {
    let key = load_master_key(args)?;
    connect_store(args, &key).await
}

async fn connect_store(args: &ServeArgs, key: &MasterKey) -> Result<Store, Error> {
    let previous = load_previous_keys(args)?;
    let migrations = if args.database_migrate_on_start {
        Migrations::Apply
    } else {
        Migrations::RequireCurrent
    };
    let store = Store::connect_with(
        &args.database_url,
        key,
        &previous,
        args.pool_settings(),
        migrations,
    )
    .await
    .map_err(|err| match err {
        StoreError::PendingMigrations(_) => format!(
            "{err}. POSTKEEP_DATABASE_MIGRATE_ON_START is false, so run `postkeep migrate` \
                 first (it uses POSTKEEP_DATABASE_MIGRATE_URL when set)"
        ),
        err => format!("could not open the database: {err}"),
    })?;
    Ok(store)
}

/// The store an embedding gave, or else the database the settings name.
/// During a key rotation (previous master keys set), values stored under the
/// master key are moved to data keys first, and then data keys are wrapped
/// again. Without previous keys nothing is moved here, whatever is stored: the
/// background pass does it after the start.
async fn server_store(
    given: Option<Store>,
    args: &ServeArgs,
    key: &MasterKey,
) -> Result<Store, Error> {
    let store = match given {
        Some(store) => store,
        None => connect_store(args, key).await?,
    };
    if store.rotating_keys() {
        let report = store
            .reencrypt()
            .await
            .map_err(|err| format!("could not move stored secrets to data keys: {err}"))?;
        tracing::info!(
            converted = report.updated,
            already_v2 = report.already_v2,
            unreadable = report.unreadable,
            lost_races = report.lost_races,
            "moved stored secrets to data keys"
        );
        let keys = store
            .rewrap_data_keys()
            .await
            .map_err(|err| format!("could not re-wrap data keys: {err}"))?;
        tracing::info!(
            rewrapped = keys.rewrapped,
            unreadable = keys.unreadable,
            "re-wrapped data keys; remove the previous keys only after a start on every instance \
             converts nothing (converted and lost_races are 0) and re-wraps nothing"
        );
    }
    Ok(store)
}

fn load_previous_keys(args: &ServeArgs) -> Result<Vec<MasterKey>, Error> {
    let mut texts: Vec<String> = args.previous_master_keys.clone();
    if let Some(path) = &args.previous_master_keys_file {
        let content = std::fs::read_to_string(path).map_err(|err| {
            format!(
                "could not read the previous master keys file {}: {err}",
                path.display()
            )
        })?;
        texts.extend(content.lines().map(str::to_owned));
    }
    texts
        .iter()
        .map(|text| text.trim())
        .filter(|text| !text.is_empty() && !text.starts_with('#'))
        .enumerate()
        .map(|(index, text)| {
            MasterKey::parse(text)
                .map_err(|err| format!("invalid previous master key #{} ({err})", index + 1).into())
        })
        .collect()
}

fn warn_about_public_url(issuer: &str) {
    let Ok(url) = url::Url::parse(issuer) else {
        return;
    };
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.scheme() == "http" && !local {
        tracing::warn!(
            public_url = issuer,
            "the public URL uses plain http; serve it through a TLS-terminating proxy and use https"
        );
    }
}

/// Waits for SIGINT or SIGTERM, cancels `draining`, then waits `drain`
/// longer or until a second signal.
async fn drain_signal(
    signals: &mut ShutdownSignals,
    draining: &CancellationToken,
    drain: Duration,
) {
    signals.recv().await;
    draining.cancel();
    if drain.is_zero() {
        return;
    }
    tracing::info!(
        seconds = drain.as_secs(),
        "draining: /readyz answers 503 while the server keeps serving; a second signal ends the wait"
    );
    tokio::select! {
        () = tokio::time::sleep(drain) => {}
        () = signals.recv() => {}
    }
}

/// SIGINT (Ctrl-C) and, on Unix, SIGTERM. A listener hears only signals
/// sent after it starts, so on Unix both are set up before the server
/// accepts connections and kept until it stops; a second signal right after
/// the first is not lost.
struct ShutdownSignals {
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
}

impl ShutdownSignals {
    fn listen() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let listen = |kind: SignalKind, name: &str| {
                signal(kind)
                    .inspect_err(|err| tracing::warn!(error = %err, "could not listen for {name}"))
                    .ok()
            };
            Self {
                interrupt: listen(SignalKind::interrupt(), "Ctrl-C"),
                terminate: listen(SignalKind::terminate(), "SIGTERM"),
            }
        }
        #[cfg(not(unix))]
        Self {}
    }

    /// Waits for the next signal.
    async fn recv(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            () = next_signal(self.interrupt.as_mut()) => {}
            () = next_signal(self.terminate.as_mut()) => {}
        }
        #[cfg(not(unix))]
        {
            if let Err(err) = tokio::signal::ctrl_c().await {
                tracing::warn!(error = %err, "could not listen for Ctrl-C");
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Waits for `signal`, or forever if it could not be listened for.
#[cfg(unix)]
async fn next_signal(signal: Option<&mut tokio::signal::unix::Signal>) {
    match signal {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// Prints a new master key to stdout.
///
/// # Errors
///
/// Returns an error if the system random number generator fails.
pub fn generate_key() -> Result<(), Error> {
    let key = MasterKey::generate_encoded()?;
    writeln!(std::io::stdout().lock(), "{key}")?;
    Ok(())
}

/// Requests `/healthz` from a local server and fails unless it answers 200.
///
/// # Errors
///
/// Returns an error if the server is unreachable or unhealthy.
pub async fn healthcheck(args: &HealthcheckArgs) -> Result<(), Error> {
    let mut addr = args.bind;
    if addr.ip().is_unspecified() {
        addr = match addr {
            SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port())),
            SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::LOCALHOST, addr.port())),
        };
    }
    let check = async {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::time::timeout(Duration::from_secs(5), check)
        .await
        .map_err(|_| format!("{addr}: timed out"))?
        .map_err(|err| format!("{addr}: {err}"))?;
    let status_line = response
        .split(|&byte| byte == b'\n')
        .next()
        .unwrap_or_default();
    let status_line = String::from_utf8_lossy(status_line);
    if status_line.split_whitespace().nth(1) == Some("200") {
        Ok(())
    } else {
        Err(format!("unhealthy: {}", status_line.trim()).into())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};

    use clap::Parser as _;
    use tracing::callsite::{DefaultCallsite, Identifier};
    use tracing::field::{FieldSet, Value};
    use tracing::level_filters::LevelFilter;
    use tracing::metadata::Kind;
    use tracing::{Event, Level, Metadata, Subscriber as _};
    use tracing_log::LogTracer;
    use tracing_log::log::{self, Log as _};
    use tracing_subscriber::EnvFilter;

    use postkeep_store::{
        DataKey, Kek, KeyWrapper, LocalKeyWrapper, MasterKey, PurgePolicy, Store, WrapFuture,
        Wrapped,
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        allowed_origins, finish_jobs, log_filter, log_subscriber, server_store, spawn_jobs,
    };
    use crate::cli::{Cli, Command};

    struct Shared(Arc<Mutex<Vec<u8>>>);

    impl Write for Shared {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Renders `emit` through the filter `POSTKEEP_LOG` would install.
    fn captured(user_filter: &str, emit: impl Fn()) -> String {
        static OTHERS: OnceLock<[tracing::Dispatch; 2]> = OnceLock::new();
        let buf = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&buf);
        let subscriber = log_subscriber(
            EnvFilter::try_new(log_filter(user_filter)).expect("filter parses"),
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .without_time()
                .with_writer(move || Shared(Arc::clone(&writer))),
        );
        // With one dispatcher alive, tracing takes a callsite's interest from the
        // default of the thread that first reaches it. A test on another thread that
        // gets there first with no subscriber would leave it at "never", and this
        // capture would see nothing. Two more dispatchers, alive for the whole
        // process, make tracing ask every one; one dropped mid-run would not.
        OTHERS.get_or_init(|| {
            [(); 2].map(|()| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()))
        });
        tracing::subscriber::with_default(subscriber, emit);
        let bytes = buf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        String::from_utf8(bytes).expect("log lines are utf-8")
    }

    #[test]
    fn sensitive_crates_stay_capped_whatever_the_user_filter_says() {
        let user = "trace,async_imap::imap_stream=trace,rmcp::service=debug,\
                    lettre::transport::smtp=debug,imap_proto=trace";
        let built = log_filter(user);
        assert!(built.split(',').any(|directive| directive == "trace"));
        assert!(
            built
                .split(',')
                .any(|directive| directive == "async_imap=warn")
        );
        assert!(
            built
                .split(',')
                .any(|directive| directive == "imap_proto=warn")
        );
        assert!(built.split(',').any(|directive| directive == "rmcp=info"));
        assert!(built.split(',').any(|directive| directive == "lettre=warn"));
        assert!(!built.contains("async_imap::imap_stream"));
        assert!(!built.contains("rmcp::service"));
        assert!(!built.contains("lettre::transport"));
        assert!(
            !built
                .split(',')
                .any(|directive| directive == "imap_proto=trace")
        );

        let output = captured(user, || {
            tracing::trace!(target: "postkeep::run", "postkeep-trace-marker");
            tracing::info!(target: "rmcp::service", "rmcp-info-marker");
            tracing::debug!(target: "rmcp::service", "mail-body-secret");
            tracing::trace!(target: "async_imap::imap_stream", "LOGIN secret-password");
            tracing::warn!(target: "async_imap::imap_stream", "async-imap-warn-marker");
            tracing::debug!(target: "lettre::transport::smtp", "AUTH smtp-secret");
            tracing::trace!(target: "imap_proto", "protocol-secret");
            tracing::info!(target: "other_crate", "other-info-marker");
        });
        assert!(output.contains("postkeep-trace-marker"), "{output}");
        assert!(output.contains("rmcp-info-marker"), "{output}");
        assert!(output.contains("async-imap-warn-marker"), "{output}");
        assert!(output.contains("other-info-marker"), "{output}");
        assert!(!output.contains("mail-body-secret"), "{output}");
        assert!(!output.contains("secret-password"), "{output}");
        assert!(!output.contains("smtp-secret"), "{output}");
        assert!(!output.contains("protocol-secret"), "{output}");
    }

    #[test]
    fn postkeep_directives_are_kept() {
        let built = log_filter("postkeep=debug,info");
        assert!(built.starts_with("postkeep=debug,info,"));
        assert!(built.contains("async_imap=warn"));
        let output = captured("postkeep=debug,info", || {
            tracing::debug!(target: "postkeep::run", "postkeep-debug-marker");
            tracing::trace!(target: "postkeep::run", "postkeep-trace-marker");
            tracing::debug!(target: "async_imap::imap_stream", "imap-debug-secret");
            tracing::info!(target: "other_crate", "other-info-marker");
        });
        assert!(output.contains("postkeep-debug-marker"), "{output}");
        assert!(!output.contains("postkeep-trace-marker"), "{output}");
        assert!(!output.contains("imap-debug-secret"), "{output}");
        assert!(output.contains("other-info-marker"), "{output}");
    }

    #[test]
    fn span_directives_cannot_raise_capped_crates() {
        let user = "info,[some_span]=trace";
        let built = log_filter(user);
        assert!(
            built
                .split(',')
                .any(|directive| directive == "[some_span]=trace"),
            "{built}"
        );
        assert!(
            built
                .split(',')
                .any(|directive| directive == "async_imap=warn")
        );

        let output = captured(user, || {
            let span = tracing::info_span!("some_span");
            let _entered = span.enter();
            tracing::trace!(target: "async_imap::imap_stream", "LOGIN secret-password");
            tracing::warn!(target: "async_imap::imap_stream", "async-imap-warn-marker");
            tracing::debug!(target: "rmcp::service", "mail-body-secret");
            tracing::info!(target: "rmcp::service", "rmcp-info-marker");
            tracing::debug!(target: "lettre::transport::smtp", "AUTH smtp-secret");
            tracing::trace!(target: "imap_proto", "protocol-secret");
            tracing::trace!(target: "postkeep::run", "postkeep-trace-in-span");
            tracing::info!(target: "postkeep::run", "postkeep-info-marker");
        });
        assert!(output.contains("async-imap-warn-marker"), "{output}");
        assert!(output.contains("rmcp-info-marker"), "{output}");
        assert!(output.contains("postkeep-trace-in-span"), "{output}");
        assert!(output.contains("postkeep-info-marker"), "{output}");
        assert!(!output.contains("secret-password"), "{output}");
        assert!(!output.contains("mail-body-secret"), "{output}");
        assert!(!output.contains("smtp-secret"), "{output}");
        assert!(!output.contains("protocol-secret"), "{output}");
    }

    /// Sends an `info` event as a `tracing` macro does once it has cached its
    /// callsite as enabled, which the server's callsites are: with no `enabled`
    /// call first. (`captured` keeps a second dispatcher alive, and then the
    /// macros ask `enabled` before every event.)
    fn send_cached_info(message: &str) {
        static CALLSITE: DefaultCallsite = DefaultCallsite::new(&META);
        static META: Metadata<'static> = Metadata::new(
            "send_cached_info",
            "postkeep::run",
            Level::INFO,
            None,
            None,
            None,
            FieldSet::new(&["message"], Identifier(&CALLSITE)),
            Kind::EVENT,
        );
        let field = META.fields().field("message").expect("the message field");
        let values = [(&field, Some(&message as &dyn Value))];
        Event::dispatch(&META, &META.fields().value_set(&values));
    }

    /// After each PostgreSQL statement sqlx asks the `log` crate whether it
    /// would log the statement (`log::log_enabled!`), and the subscriber
    /// answers as the `log` logger through `LogTracer`. For a level the
    /// filter turns off the answer is no, and it must not cost the thread its
    /// next line: the lines a start with previous keys logs were lost on
    /// PostgreSQL.
    #[test]
    fn a_log_check_for_a_level_that_is_off_does_not_swallow_the_next_line() {
        let tracer = LogTracer::new();
        // Its statements are at `debug`.
        let statement = log::Metadata::builder()
            .level(log::Level::Debug)
            .target("sqlx::query")
            .build();
        for (user_filter, on) in [
            ("info", false),
            ("info,other_crate=debug", false),
            ("info,sqlx::query=debug", true),
        ] {
            let answer = std::cell::Cell::new(None);
            let output = captured(user_filter, || {
                answer.set(Some(tracer.enabled(&statement)));
                send_cached_info("first-marker");
                send_cached_info("second-marker");
            });
            assert!(output.contains("first-marker"), "{user_filter}: {output}");
            assert!(output.contains("second-marker"), "{user_filter}: {output}");
            assert_eq!(answer.get(), Some(on), "{user_filter}");
        }
    }

    /// The request line turns off on its own, and the request span, at `ERROR`
    /// with a target of its own, keeps the ids on the other lines, also under a
    /// `warn` filter.
    #[test]
    fn the_request_log_turns_off_alone_and_the_ids_stay() {
        use axum::routing::get;
        use tower::ServiceExt as _;

        for (user_filter, line) in [
            ("info", true),
            ("info,postkeep::request_log=off", false),
            ("warn", false),
        ] {
            let output = captured(user_filter, || {
                let app = axum::Router::new()
                    .route("/", get(|| async { tracing::warn!("inside the request") }))
                    .layer(axum::middleware::from_fn_with_state(
                        crate::metrics::Metrics::default(),
                        crate::request_log::log,
                    ));
                let request = axum::http::Request::new(axum::body::Body::empty());
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("runtime");
                runtime.block_on(app.oneshot(request)).expect("answered");
            });
            let inside = output
                .lines()
                .find(|line| line.contains("inside the request"))
                .unwrap_or_else(|| panic!("{user_filter}: {output}"));
            assert!(
                inside.contains("request{request_id="),
                "{user_filter}: {output}"
            );
            assert_eq!(
                output.contains("answered a request"),
                line,
                "{user_filter}: {output}"
            );
        }
    }

    /// `try_init` hands the subscriber's most verbose level to the `log` crate,
    /// which then refuses what is above it before the subscriber is asked.
    /// With the default filter that is everything above `info`, as long as the
    /// cap names no level of its own (see `log_subscriber`).
    #[test]
    fn the_default_filter_lets_the_log_crate_refuse_what_is_above_info() {
        let subscriber = log_subscriber(
            EnvFilter::try_new(log_filter("info")).expect("filter parses"),
            tracing_subscriber::fmt::layer(),
        );
        assert_eq!(subscriber.max_level_hint(), Some(LevelFilter::INFO));
    }

    /// `async_imap` logs raw IMAP at trace through the `log` crate, and a
    /// `log` record reaches the subscriber through `LogTracer`: a span
    /// directive that enables `trace` must not raise the cap there either.
    #[test]
    fn log_records_of_capped_crates_stay_capped() {
        let tracer = LogTracer::new();
        let output = captured("info,[some_span]=trace", || {
            let span = tracing::info_span!("some_span");
            let _entered = span.enter();
            for (target, level, message) in [
                (
                    "async_imap::imap_stream",
                    log::Level::Trace,
                    "LOGIN secret-password",
                ),
                ("rmcp::service", log::Level::Debug, "mail-body-secret"),
                ("other_crate", log::Level::Trace, "other-trace-marker"),
            ] {
                tracer.log(
                    &log::Record::builder()
                        .level(level)
                        .target(target)
                        .args(format_args!("{message}"))
                        .build(),
                );
            }
        });
        assert!(output.contains("other-trace-marker"), "{output}");
        assert!(!output.contains("secret-password"), "{output}");
        assert!(!output.contains("mail-body-secret"), "{output}");
    }

    #[test]
    fn similar_crate_names_are_not_capped() {
        let built = log_filter("async_imap_other=trace,lettre_extra=debug");
        assert!(built.contains("async_imap_other=trace"));
        assert!(built.contains("lettre_extra=debug"));
        assert!(built.contains("async_imap=warn"));
    }

    #[test]
    fn allowed_origins_must_be_origins() {
        let origins = |value: &str| {
            let Command::Serve(args) = Cli::try_parse_from([
                "postkeep",
                "serve",
                "--public-url",
                "https://mail.example.com",
                "--master-key",
                "00",
                "--allowed-origins",
                value,
            ])
            .expect("command line parses")
            .command
            else {
                panic!("expected serve");
            };
            allowed_origins(&args)
        };
        assert_eq!(
            origins(" https://App.example.com ,, http://localhost:6274").expect("origins"),
            ["https://app.example.com", "http://localhost:6274"]
        );
        let err = origins("https://app.example.com,https://app.example.com/page")
            .expect_err("a path is refused")
            .to_string();
        assert!(err.starts_with("POSTKEEP_ALLOWED_ORIGINS: "), "{err}");
        assert!(err.contains("\"https://app.example.com/page\""), "{err}");
    }

    /// Starting with a previous master key wraps the data keys again under the
    /// current one, so that the previous key can go.
    #[tokio::test]
    async fn starting_with_a_previous_key_wraps_data_keys_again() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let url = format!("sqlite://{}", dir.path().join("test.db").display());
        let (old, new) = ("00".repeat(32), "11".repeat(32));
        let key = |text: &str| MasterKey::parse(text).expect("master key");
        let first = Store::connect(&url, &key(&old)).await.expect("connects");
        let tenant = first.for_tenant("tenant-a");
        let (_, made) = tenant.data_key().await.expect("makes a key");
        first.close().await;

        let line = format!(
            "postkeep serve --public-url https://mail.example.com --master-key {new} \
             --previous-master-keys {old} --database-url {url}"
        );
        let Command::Serve(args) = Cli::try_parse_from(line.split(' '))
            .expect("command line parses")
            .command
        else {
            panic!("expected serve");
        };
        let started = server_store(None, &args, &key(&new)).await;
        started.expect("starts").close().await;

        let alone = Store::connect(&url, &key(&new)).await.expect("connects");
        let (_, found) = alone
            .for_tenant("tenant-a")
            .data_key()
            .await
            .expect("unwraps");
        assert_eq!(found.expose(), made.expose());
    }

    /// The two lines of a start with previous keys give the counts that tell
    /// when the previous keys can go. A password from before data keys, sealed
    /// under the previous key, is moved and the tenant's key is wrapped again;
    /// the next start finds both done.
    #[test]
    fn a_start_with_previous_keys_logs_what_it_moved_and_wrapped_again() {
        // The key `[7; 32]` and a password under it for `a@icloud.com`, as
        // `v1_rows` of the store's upgrade test has them.
        const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
        const PASSWORD: &str = "v1.AAECAwQFBgcICQoLeeOKFHxrui0W0Ib4gzoPnpoIGEwd-_0hdUaq2rZR4IQ";
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let dir = tempfile::tempdir().expect("temporary directory");
        let url = format!("sqlite://{}", dir.path().join("test.db").display());
        let new = "11".repeat(32);
        let key = |text: &str| MasterKey::parse(text).expect("master key");
        runtime.block_on(async {
            let old = Store::connect(&url, &key(KEY)).await.expect("connects");
            old.data_key().await.expect("makes a key");
            sqlx::query(
                "INSERT INTO accounts (id, email, password_ciphertext, created_at, updated_at) \
                 VALUES ('acct-1', 'a@icloud.com', $1, 1, 1)",
            )
            .bind(PASSWORD)
            .execute(old.pool())
            .await
            .expect("inserts the account");
            old.close().await;
        });

        let line = format!(
            "postkeep serve --public-url https://mail.example.com --master-key {new} \
             --previous-master-keys {KEY} --database-url {url}"
        );
        let Command::Serve(args) = Cli::try_parse_from(line.split(' '))
            .expect("command line parses")
            .command
        else {
            panic!("expected serve");
        };
        // The log of one start, at the default level. `captured` takes a
        // closure that is not async, so the start runs on the runtime above.
        let start = || {
            captured(&args.log, || {
                runtime.block_on(async {
                    let started = server_store(None, &args, &key(&new)).await;
                    started.expect("starts").close().await;
                });
            })
        };
        // The `name=value` words of the one line that says `message`.
        let counts = |log: &str, message: &str| {
            let mut lines = log.lines().filter(|line| line.contains(message));
            let line = lines
                .next()
                .unwrap_or_else(|| panic!("no line says {message:?}: {log}"));
            assert!(lines.next().is_none(), "{message:?} twice: {log}");
            let words = line.split_whitespace().filter(|word| word.contains('='));
            words.collect::<Vec<_>>().join(" ")
        };
        let (moved, wrapped) = ("moved stored secrets to data keys", "re-wrapped data keys");

        let first = start();
        assert_eq!(
            counts(&first, moved),
            "converted=1 already_v2=0 unreadable=0 lost_races=0"
        );
        assert_eq!(counts(&first, wrapped), "rewrapped=1 unreadable=0");
        let second = start();
        assert_eq!(
            counts(&second, moved),
            "converted=0 already_v2=1 unreadable=0 lost_races=0"
        );
        assert_eq!(counts(&second, wrapped), "rewrapped=0 unreadable=0");
    }

    /// A key service that never answers an unwrap. `asked` is told when a call
    /// starts to wait, and `dropped` is set when that call is dropped.
    struct Silent {
        local: LocalKeyWrapper,
        asked: Arc<tokio::sync::Notify>,
        dropped: Arc<AtomicBool>,
    }

    struct SetOnDrop(Arc<AtomicBool>);

    impl Drop for SetOnDrop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    impl KeyWrapper for Silent {
        fn current(&self) -> Kek {
            self.local.current()
        }

        fn wrap<'a>(&'a self, tenant: &'a str, key: &'a DataKey) -> WrapFuture<'a, Wrapped> {
            self.local.wrap(tenant, key)
        }

        fn unwrap<'a>(
            &'a self,
            _tenant: &'a str,
            _kek: &'a Kek,
            _wrapped: &'a [u8],
        ) -> WrapFuture<'a, DataKey> {
            let (asked, guard) = (
                Arc::clone(&self.asked),
                SetOnDrop(Arc::clone(&self.dropped)),
            );
            Box::pin(async move {
                let _guard = guard;
                asked.notify_one();
                std::future::pending().await
            })
        }
    }

    /// The pass that moves stored values waits for a key service that never
    /// answers. Shutdown does not wait for it: the jobs end, and the pass is
    /// dropped before `finish_jobs` returns.
    #[tokio::test]
    async fn shutdown_ends_a_pass_that_waits_for_a_key_service_that_never_answers() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let url = format!("sqlite://{}", dir.path().join("silent.db").display());
        let (old, new) = ("00".repeat(32), "11".repeat(32));
        let key = |text: &str| MasterKey::parse(text).expect("master key");
        // A data key under the old master key: the re-wrap of the pass has to
        // ask the key service for it.
        let first = Store::connect(&url, &key(&old)).await.expect("connects");
        first.data_key().await.expect("makes a key");
        first.close().await;
        let (asked, dropped) = (
            Arc::new(tokio::sync::Notify::new()),
            Arc::new(AtomicBool::new(false)),
        );
        let service = Silent {
            local: LocalKeyWrapper::new(&key(&new), &[key(&old)]),
            asked: Arc::clone(&asked),
            dropped: Arc::clone(&dropped),
        };
        let store = Store::connect_rotating(&url, &key(&new), &[key(&old)])
            .await
            .expect("connects")
            .with_key_wrapper(Arc::new(service));
        let cancel = CancellationToken::new();
        let jobs = spawn_jobs(&store, PurgePolicy::default(), None, &cancel);

        asked.notified().await;
        cancel.cancel();
        let ended = tokio::time::timeout(std::time::Duration::from_secs(30), finish_jobs(jobs));
        assert!(
            ended.await.is_ok(),
            "shutdown waits for a pass that never ends"
        );
        assert!(
            dropped.load(Ordering::SeqCst),
            "the pass was still under way"
        );
    }
}
