//! Command-line and environment configuration.
//!
//! Every option can be set with a `POSTKEEP_*` environment variable, so the
//! container image needs no flags.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use secrecy::{ExposeSecret, SecretString};

/// Prefix of every environment variable.
pub const ENV_PREFIX: &str = "POSTKEEP_";

/// MCP server for email over Streamable HTTP.
#[derive(Debug, Parser)]
#[command(name = "postkeep", version, about, long_about = None)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the server.
    Serve(Box<ServeArgs>),
    /// Print a new random master key (32 random bytes, base64).
    GenerateKey,
    /// Check that a local server answers `/healthz` (for container health checks).
    Healthcheck(HealthcheckArgs),
    /// Apply pending database migrations and exit (for release commands).
    Migrate(MigrateArgs),
    /// Show the database's storage level, or raise it to the one this version reads.
    StorageLevel(StorageLevelArgs),
}

/// Options for `serve`.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Public origin of this server, as MCP clients and browsers reach it,
    /// for example `https://mail.example.com`.
    #[arg(long, env = "POSTKEEP_PUBLIC_URL")]
    pub public_url: String,

    /// Address and port to listen on.
    #[arg(long, env = "POSTKEEP_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,

    /// Address and port for Prometheus metrics at `GET /metrics`, for
    /// example `127.0.0.1:9091`; unset serves none. Anyone who reaches that
    /// address can read it: keep it off public networks.
    #[arg(long, env = "POSTKEEP_METRICS_BIND")]
    pub metrics_bind: Option<SocketAddr>,

    /// Seconds to keep serving after SIGINT or SIGTERM while `/readyz`
    /// answers 503, so load balancers stop sending requests first. A second
    /// signal ends the wait.
    #[arg(long, env = "POSTKEEP_SHUTDOWN_DRAIN", default_value_t = 0)]
    pub shutdown_drain: u64,

    /// Database URL: `sqlite://path/to/file.db` or `postgres://user:pass@host/db`.
    // Relative to the process working directory. The container image sets
    // that directory to `/data`, so the file is `/data/postkeep.db`.
    #[arg(
        long,
        env = "POSTKEEP_DATABASE_URL",
        default_value = "sqlite://postkeep.db",
        hide_env_values = true
    )]
    pub database_url: String,

    /// Most database connections this server opens at once.
    #[arg(
        long,
        env = "POSTKEEP_DATABASE_MAX_CONNECTIONS",
        default_value_t = 10,
        value_parser = clap::value_parser!(u32).range(1..)
    )]
    pub database_max_connections: u32,

    /// Seconds a request waits for a free database connection before it fails.
    #[arg(
        long,
        env = "POSTKEEP_DATABASE_ACQUIRE_TIMEOUT",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub database_acquire_timeout: u64,

    /// Apply pending database migrations at start. With `false`, the server
    /// refuses to start while any is pending; run `postkeep migrate` first.
    #[arg(
        long,
        env = "POSTKEEP_DATABASE_MIGRATE_ON_START",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub database_migrate_on_start: bool,

    /// Seconds an unused database connection stays open (0 keeps it open).
    #[arg(long, env = "POSTKEEP_DATABASE_IDLE_TIMEOUT", default_value_t = 600)]
    pub database_idle_timeout: u64,

    /// Seconds before a database connection is replaced (0 never replaces it).
    #[arg(long, env = "POSTKEEP_DATABASE_MAX_LIFETIME", default_value_t = 1800)]
    pub database_max_lifetime: u64,

    /// Master key that encrypts stored credentials: 32 bytes as hex or base64.
    #[arg(
        long,
        env = "POSTKEEP_MASTER_KEY",
        hide_env_values = true,
        conflicts_with = "master_key_file",
        required_unless_present = "master_key_file"
    )]
    pub master_key: Option<String>,

    /// File containing the master key (for Docker or Kubernetes secrets).
    #[arg(long, env = "POSTKEEP_MASTER_KEY_FILE")]
    pub master_key_file: Option<PathBuf>,

    /// Previous master keys, comma-separated, during a key rotation. Before
    /// the server serves, and then every hour, values that a master key
    /// encrypts directly are moved to data keys, and data keys that a previous
    /// key wrapped are wrapped again.
    #[arg(
        long,
        env = "POSTKEEP_PREVIOUS_MASTER_KEYS",
        hide_env_values = true,
        value_delimiter = ','
    )]
    pub previous_master_keys: Vec<String>,

    /// File with previous master keys, one per line.
    #[arg(long, env = "POSTKEEP_PREVIOUS_MASTER_KEYS_FILE")]
    pub previous_master_keys_file: Option<PathBuf>,

    /// Comma-separated addresses allowed to connect. Empty allows any.
    #[arg(long, env = "POSTKEEP_ALLOWED_EMAILS", value_delimiter = ',')]
    pub allowed_emails: Vec<String>,

    /// Extra `Host` header values to accept on the MCP endpoint, besides the
    /// public URL's host (comma-separated).
    #[arg(long, env = "POSTKEEP_ALLOWED_HOSTS", value_delimiter = ',')]
    pub allowed_hosts: Vec<String>,

    /// Extra `Origin` header values to accept on the MCP endpoint, besides
    /// the public URL's origin (comma-separated, such as
    /// `https://app.example.com`). Requests without an `Origin` pass.
    #[arg(long, env = "POSTKEEP_ALLOWED_ORIGINS", value_delimiter = ',')]
    pub allowed_origins: Vec<String>,

    /// Access token lifetime in seconds.
    #[arg(long, env = "POSTKEEP_ACCESS_TOKEN_TTL", default_value_t = 3600)]
    pub access_token_ttl: u64,

    /// Refresh token lifetime in seconds.
    #[arg(long, env = "POSTKEEP_REFRESH_TOKEN_TTL", default_value_t = 30 * 24 * 3600)]
    pub refresh_token_ttl: u64,

    /// Header with the real client IP, set by your reverse proxy (for example
    /// `Fly-Client-IP`, `CF-Connecting-IP` or `X-Forwarded-For`). Only set
    /// this behind a proxy that always overwrites the header; otherwise
    /// clients can forge it. Unset: the TCP peer address is used.
    #[arg(long, env = "POSTKEEP_CLIENT_IP_HEADER")]
    pub client_ip_header: Option<String>,

    /// OAuth client registrations allowed per client IP in each
    /// registration window.
    #[arg(long, env = "POSTKEEP_REGISTRATION_LIMIT", default_value_t = 20)]
    pub registration_limit: u32,

    /// Length of the registration window in seconds.
    #[arg(long, env = "POSTKEEP_REGISTRATION_WINDOW", default_value_t = 3600)]
    pub registration_window: u64,

    /// Maximum number of registered OAuth clients.
    #[arg(long, env = "POSTKEEP_MAX_CLIENTS", default_value_t = 10_000)]
    pub max_clients: u64,

    /// Requests per minute and client IP to the OAuth endpoints.
    #[arg(long, env = "POSTKEEP_RATE_LIMIT", default_value_t = 120)]
    pub rate_limit: u32,

    /// Seconds after which a registered client that never obtained a token is deleted.
    #[arg(long, env = "POSTKEEP_UNUSED_CLIENT_TTL", default_value_t = 24 * 3600)]
    pub unused_client_ttl: u64,

    /// Seconds after its last token request that a client without live
    /// grants is deleted.
    #[arg(long, env = "POSTKEEP_IDLE_CLIENT_TTL", default_value_t = 30 * 24 * 3600)]
    pub idle_client_ttl: u64,

    /// Longest sign-in backoff for one email address, in seconds. Keep it
    /// short: it is what someone guessing at your address can make you wait.
    #[arg(long, env = "POSTKEEP_ACCOUNT_BACKOFF_MAX", default_value_t = 60)]
    pub account_backoff_max: u64,

    /// Longest sign-in backoff for one client IP address, in seconds.
    #[arg(long, env = "POSTKEEP_IP_BACKOFF_MAX", default_value_t = 900)]
    pub ip_backoff_max: u64,

    /// Largest accepted request body, in bytes.
    #[arg(long, env = "POSTKEEP_MAX_BODY_BYTES", default_value_t = 1024 * 1024)]
    pub max_body_bytes: usize,

    /// Seconds a request may take before the server answers 503.
    #[arg(long, env = "POSTKEEP_REQUEST_TIMEOUT", default_value_t = 120)]
    pub request_timeout: u64,

    /// Requests handled at once; more are answered with 503.
    #[arg(long, env = "POSTKEEP_MAX_CONCURRENT_REQUESTS", default_value_t = 256)]
    pub max_concurrent_requests: usize,

    /// MCP requests handled at once per account.
    #[arg(long, env = "POSTKEEP_ACCOUNT_CONCURRENCY", default_value_t = 4)]
    pub account_concurrency: usize,

    /// Open HTTP connections; further connections are closed immediately.
    #[arg(long, env = "POSTKEEP_MAX_CONNECTIONS", default_value_t = 1024)]
    pub max_connections: usize,

    /// Seconds an idle IMAP session is kept for reuse; 0 disables pooling.
    #[arg(long, env = "POSTKEEP_IMAP_POOL_IDLE", default_value_t = 60)]
    pub imap_pool_idle: u64,

    /// Offer opt-in new-mail webhooks on the account page (`true` or
    /// `false`). An IMAP webhook keeps one IMAP connection open; Outlook
    /// and Gmail do not. A paused IMAP webhook still keeps its connection.
    #[arg(long, env = "POSTKEEP_WEBHOOKS", default_value_t = true, action = clap::ArgAction::Set)]
    pub webhooks: bool,

    /// Accounts whose Inbox is watched for webhooks at once. A paused
    /// webhook still uses one slot: IMAP keeps its connection, and Gmail
    /// and Graph keep renewing. Turning the webhook off frees the slot.
    #[arg(long, env = "POSTKEEP_WEBHOOK_MAX_WATCHERS", default_value_t = 100)]
    pub webhook_max_watchers: usize,

    /// Seconds between delivery attempts while a webhook is paused after
    /// repeated failures, and the longest wait before it is paused. From
    /// 1 to 86400.
    #[arg(
        long,
        env = "POSTKEEP_WEBHOOK_RETRY_INTERVAL",
        default_value_t = 3600,
        value_parser = parse_webhook_retry_interval
    )]
    pub webhook_retry_interval: u64,

    /// How long events are kept when an account has no override, in seconds.
    /// From 1 hour to 366 days, and not above
    /// [`Self::webhook_outbox_max_retention`].
    #[arg(
        long,
        env = "POSTKEEP_WEBHOOK_OUTBOX_RETENTION",
        default_value_t = 7 * 24 * 60 * 60,
        value_parser = parse_outbox_retention
    )]
    pub webhook_outbox_retention: u64,

    /// How many events are kept per account when it has no override.
    /// Delivered and undelivered events both count. From 1 to 100000, and
    /// not above [`Self::webhook_outbox_max_events_limit`].
    #[arg(
        long,
        env = "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS",
        default_value_t = 1000,
        value_parser = parse_outbox_max_events
    )]
    pub webhook_outbox_max_events: u64,

    /// Longest outbox retention an account may set, in seconds. From 1 hour
    /// to 366 days. One account cannot keep mail longer than this.
    #[arg(
        long,
        env = "POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION",
        default_value_t = 30 * 24 * 60 * 60,
        value_parser = parse_outbox_max_retention
    )]
    pub webhook_outbox_max_retention: u64,

    /// Most events one account may keep. From 1 to 100000. A stored event
    /// is about 1 KB of encrypted JSON, so the default of 10000 is about
    /// 10 MB for one account.
    #[arg(
        long,
        env = "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT",
        default_value_t = 10_000,
        value_parser = parse_outbox_max_events_limit
    )]
    pub webhook_outbox_max_events_limit: u64,

    /// Seconds an event that this server cannot open is held, with the events
    /// after it, before it is skipped, counted from when the event was
    /// stored. From 0 to 366 days; 0 skips at once.
    #[arg(
        long,
        env = "POSTKEEP_WEBHOOK_OUTBOX_HOLD",
        default_value_t = 60 * 60,
        value_parser = clap::value_parser!(u64).range(..=31_622_400)
    )]
    pub webhook_outbox_hold: u64,

    /// How many of a mailbox's webhook filter rules count, oldest first: the
    /// newer ones judge nothing and no rule can be added past it. From 0 to
    /// 2000; the usage hook of an embedding replaces it per mailbox.
    #[arg(
        long,
        env = "POSTKEEP_WEBHOOK_FILTER_MAX_RULES",
        default_value_t = crate::watch::DEFAULT_MAX_FILTER_RULES,
        value_parser = parse_filter_max_rules
    )]
    pub webhook_filter_max_rules: usize,

    /// Log filter, for example `info` or `postkeep=debug,info`.
    /// Crates that would log credentials or message bodies stay capped.
    #[arg(long, env = "POSTKEEP_LOG", default_value = "info")]
    pub log: String,

    /// Log format.
    #[arg(long, env = "POSTKEEP_LOG_FORMAT", value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,

    /// Mail server settings.
    #[command(flatten)]
    pub mail: MailArgs,

    /// Microsoft and Google sign-in.
    #[command(flatten)]
    pub providers: ProviderArgs,
}

impl ServeArgs {
    /// The database pool settings. `0` turns the idle timeout or the
    /// lifetime off.
    #[must_use]
    pub fn pool_settings(&self) -> postkeep_store::PoolSettings {
        let optional = |seconds: u64| (seconds > 0).then(|| Duration::from_secs(seconds));
        postkeep_store::PoolSettings {
            max_connections: self.database_max_connections,
            acquire_timeout: Duration::from_secs(self.database_acquire_timeout),
            idle_timeout: optional(self.database_idle_timeout),
            max_lifetime: optional(self.database_max_lifetime),
        }
    }

    /// Server outbox defaults and the ceilings an account cannot pass.
    ///
    /// # Errors
    ///
    /// Returns an error when a default is above its ceiling. Each value is
    /// already inside the absolute range.
    pub fn outbox_policy(&self) -> Result<postkeep_store::OutboxPolicy, String> {
        fn signed(name: &str, value: u64) -> Result<i64, String> {
            i64::try_from(value).map_err(|_| format!("{name} does not fit in a signed integer"))
        }
        postkeep_store::OutboxPolicy::try_new(
            signed(
                "POSTKEEP_WEBHOOK_OUTBOX_RETENTION",
                self.webhook_outbox_retention,
            )?,
            signed(
                "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS",
                self.webhook_outbox_max_events,
            )?,
            signed(
                "POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION",
                self.webhook_outbox_max_retention,
            )?,
            signed(
                "POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT",
                self.webhook_outbox_max_events_limit,
            )?,
        )
    }
}

/// OAuth app credentials for "Sign in with Microsoft" (Outlook) and "Sign
/// in with Google" (Gmail). A provider's button shows only when both its
/// client ID and secret are set. See docs/providers/.
#[derive(Debug, Args)]
#[command(next_help_heading = "Microsoft and Google sign-in")]
pub struct ProviderArgs {
    /// Application (client) ID of the Microsoft Entra app registration.
    #[arg(long, env = "POSTKEEP_MICROSOFT_CLIENT_ID")]
    pub microsoft_client_id: Option<String>,
    /// Client secret of the Microsoft Entra app registration.
    #[arg(long, env = "POSTKEEP_MICROSOFT_CLIENT_SECRET", hide_env_values = true)]
    pub microsoft_client_secret: Option<SecretString>,
    /// OAuth client ID of the Google Cloud web application client.
    #[arg(long, env = "POSTKEEP_GOOGLE_CLIENT_ID")]
    pub google_client_id: Option<String>,
    /// OAuth client secret of the Google Cloud web application client.
    #[arg(long, env = "POSTKEEP_GOOGLE_CLIENT_SECRET", hide_env_values = true)]
    pub google_client_secret: Option<SecretString>,
    /// Cloud Pub/Sub topic Gmail publishes new-mail notifications to,
    /// `projects/<project>/topics/<topic>`. Enables new-mail webhooks for
    /// Gmail accounts.
    #[arg(long, env = "POSTKEEP_GOOGLE_PUBSUB_TOPIC")]
    pub google_pubsub_topic: Option<String>,
    /// Service account the Pub/Sub push subscription authenticates as;
    /// push requests whose OIDC token names another account are refused.
    #[arg(long, env = "POSTKEEP_GOOGLE_PUBSUB_SERVICE_ACCOUNT")]
    pub google_pubsub_service_account: Option<String>,
    /// Audience configured on the push subscription. Defaults to the push
    /// endpoint URL, `{POSTKEEP_PUBLIC_URL}/push/google`.
    #[arg(long, env = "POSTKEEP_GOOGLE_PUBSUB_AUDIENCE")]
    pub google_pubsub_audience: Option<String>,
}

impl ProviderArgs {
    /// Gmail push settings: the topic and what push tokens must say.
    ///
    /// # Errors
    ///
    /// Returns an error when the settings are incomplete or malformed.
    pub fn google_push(
        &self,
        public_url: &url::Url,
    ) -> Result<Option<(String, postkeep_upstream::PushExpectations)>, String> {
        let clean = |value: Option<&String>| {
            value
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        };
        let topic = clean(self.google_pubsub_topic.as_ref());
        let account = clean(self.google_pubsub_service_account.as_ref());
        let audience = clean(self.google_pubsub_audience.as_ref());
        let Some(topic) = topic else {
            if account.is_some() || audience.is_some() {
                return Err("POSTKEEP_GOOGLE_PUBSUB_SERVICE_ACCOUNT and POSTKEEP_GOOGLE_PUBSUB_AUDIENCE need POSTKEEP_GOOGLE_PUBSUB_TOPIC".to_owned());
            }
            return Ok(None);
        };
        if !is_topic_name(&topic) {
            return Err(format!(
                "POSTKEEP_GOOGLE_PUBSUB_TOPIC must look like projects/<project>/topics/<topic>, not {topic:?}"
            ));
        }
        let Some(service_account) = account else {
            return Err("POSTKEEP_GOOGLE_PUBSUB_TOPIC needs POSTKEEP_GOOGLE_PUBSUB_SERVICE_ACCOUNT, the service account of the authenticated push subscription".to_owned());
        };
        if !service_account.contains('@') {
            return Err(
                "POSTKEEP_GOOGLE_PUBSUB_SERVICE_ACCOUNT must be a service account email".to_owned(),
            );
        }
        let audience = audience.unwrap_or_else(|| {
            let mut url = public_url.clone();
            url.set_path(crate::push::GOOGLE_PATH);
            url.to_string()
        });
        Ok(Some((
            topic,
            postkeep_upstream::PushExpectations {
                audience,
                service_account,
            },
        )))
    }

    /// The configured apps.
    ///
    /// # Errors
    ///
    /// Returns an error when only one of a provider's client ID and secret
    /// is set.
    pub fn apps(
        &self,
    ) -> Result<
        (
            Option<postkeep_upstream::AppCredentials>,
            Option<postkeep_upstream::AppCredentials>,
        ),
        String,
    > {
        fn pair(
            name: &str,
            id: Option<&String>,
            secret: Option<&SecretString>,
        ) -> Result<Option<postkeep_upstream::AppCredentials>, String> {
            let id = id.map(|id| id.trim()).filter(|id| !id.is_empty());
            let secret = secret.filter(|secret| !secret.expose_secret().trim().is_empty());
            match (id, secret) {
                (Some(id), Some(secret)) => Ok(Some(postkeep_upstream::AppCredentials {
                    client_id: id.to_owned(),
                    client_secret: SecretString::from(secret.expose_secret().trim().to_owned()),
                })),
                (None, None) => Ok(None),
                _ => Err(format!(
                    "set both POSTKEEP_{name}_CLIENT_ID and POSTKEEP_{name}_CLIENT_SECRET, or neither"
                )),
            }
        }
        Ok((
            pair(
                "MICROSOFT",
                self.microsoft_client_id.as_ref(),
                self.microsoft_client_secret.as_ref(),
            )?,
            pair(
                "GOOGLE",
                self.google_client_id.as_ref(),
                self.google_client_secret.as_ref(),
            )?,
        ))
    }
}

/// Whether `topic` is a full Pub/Sub topic name.
fn is_topic_name(topic: &str) -> bool {
    let parts: Vec<&str> = topic.split('/').collect();
    matches!(parts.as_slice(), ["projects", project, "topics", name]
        if !project.is_empty() && !name.is_empty()
            && [project, name].iter().all(|part| part.chars().all(|c| c.is_ascii_alphanumeric() || "-_.~+%:".contains(c))))
}

/// Mail server settings: the provider presets offered at sign-in, or one
/// custom IMAP and SMTP server.
#[derive(Debug, Args)]
#[command(next_help_heading = "Mail servers")]
pub struct MailArgs {
    /// Mail providers users can pick when signing in with an app password,
    /// as a comma-separated list of `icloud`, `fastmail`, `yahoo` and `gmail`.
    /// Defaults to all of them, or to none when a custom server is set
    /// with `--imap-host`.
    #[arg(long, env = "POSTKEEP_IMAP_PROVIDERS", value_delimiter = ',', value_parser = parse_imap_preset)]
    pub imap_providers: Option<Vec<postkeep_mail::ImapPreset>>,
    /// IMAP host of a custom mail server. Users can't enter a server
    /// themselves; this is the only way to offer one outside the presets.
    #[arg(long, env = "POSTKEEP_IMAP_HOST")]
    pub imap_host: Option<String>,
    /// Name of the custom mail server, shown on the sign-in page.
    #[arg(
        long,
        env = "POSTKEEP_IMAP_NAME",
        default_value = "Custom mail server",
        requires = "imap_host"
    )]
    pub imap_name: String,
    /// IMAP port of the custom server.
    #[arg(long, env = "POSTKEEP_IMAP_PORT", default_value_t = postkeep_mail::ICLOUD_IMAP_PORT)]
    pub imap_port: u16,
    /// IMAP transport security of the custom server.
    #[arg(long, env = "POSTKEEP_IMAP_SECURITY", value_enum, default_value_t = ImapSecurityArg::Tls)]
    pub imap_security: ImapSecurityArg,
    /// SMTP host of the custom server (defaults to the IMAP host).
    #[arg(long, env = "POSTKEEP_SMTP_HOST", requires = "imap_host")]
    pub smtp_host: Option<String>,
    /// SMTP port of the custom server.
    #[arg(long, env = "POSTKEEP_SMTP_PORT", default_value_t = postkeep_mail::ICLOUD_SMTP_PORT)]
    pub smtp_port: u16,
    /// SMTP transport security of the custom server.
    #[arg(long, env = "POSTKEEP_SMTP_SECURITY", value_enum, default_value_t = SmtpSecurityArg::Starttls)]
    pub smtp_security: SmtpSecurityArg,
    /// Timeout for each mail server operation, in seconds.
    #[arg(long, env = "POSTKEEP_MAIL_TIMEOUT", default_value_t = 30)]
    pub mail_timeout: u64,
}

fn parse_outbox_seconds(name: &str, value: &str) -> Result<u64, String> {
    let seconds: u64 = value
        .parse()
        .map_err(|_| format!("{name} must be a whole number of seconds, not `{value}`"))?;
    let min = u64::try_from(postkeep_store::MIN_OUTBOX_RETENTION_SECS).unwrap_or(0);
    let max = u64::try_from(postkeep_store::ABSOLUTE_MAX_OUTBOX_RETENTION_SECS).unwrap_or(0);
    if (min..=max).contains(&seconds) {
        Ok(seconds)
    } else {
        Err(format!(
            "{name} must be from {min} to {max} seconds, not {seconds}"
        ))
    }
}

fn parse_outbox_retention(value: &str) -> Result<u64, String> {
    parse_outbox_seconds("POSTKEEP_WEBHOOK_OUTBOX_RETENTION", value)
}

fn parse_outbox_max_retention(value: &str) -> Result<u64, String> {
    parse_outbox_seconds("POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION", value)
}

fn parse_outbox_count(name: &str, value: &str) -> Result<u64, String> {
    let events: u64 = value
        .parse()
        .map_err(|_| format!("{name} must be a whole number of events, not `{value}`"))?;
    let min = u64::try_from(postkeep_store::MIN_OUTBOX_EVENTS).unwrap_or(0);
    let max = u64::try_from(postkeep_store::ABSOLUTE_MAX_OUTBOX_EVENTS).unwrap_or(0);
    if (min..=max).contains(&events) {
        Ok(events)
    } else {
        Err(format!("{name} must be from {min} to {max}, not {events}"))
    }
}

fn parse_outbox_max_events(value: &str) -> Result<u64, String> {
    parse_outbox_count("POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS", value)
}

fn parse_outbox_max_events_limit(value: &str) -> Result<u64, String> {
    parse_outbox_count("POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT", value)
}

fn parse_filter_max_rules(value: &str) -> Result<usize, String> {
    let max = postkeep_webhook::filter::MAX_RULES;
    let range = |shown: &str| {
        format!("POSTKEEP_WEBHOOK_FILTER_MAX_RULES must be from 0 to {max}, not {shown}")
    };
    let rules: usize = value.parse().map_err(|_| range(value))?;
    if rules <= max {
        Ok(rules)
    } else {
        Err(range(value))
    }
}

fn parse_webhook_retry_interval(value: &str) -> Result<u64, String> {
    let seconds: u64 = value.parse().map_err(|_| {
        format!("invalid webhook retry interval `{value}`; expected a number of seconds")
    })?;
    if (1..=86_400).contains(&seconds) {
        Ok(seconds)
    } else {
        Err(format!(
            "webhook retry interval must be from 1 to 86400 seconds, not {seconds}"
        ))
    }
}

fn parse_imap_preset(value: &str) -> Result<postkeep_mail::ImapPreset, String> {
    postkeep_mail::ImapPreset::parse(value.trim()).ok_or_else(|| {
        format!("unknown mail provider `{value}`; expected icloud, fastmail, yahoo or gmail")
    })
}

/// Options for `healthcheck`.
#[derive(Debug, Args)]
pub struct HealthcheckArgs {
    /// Address the server listens on; `0.0.0.0` is checked via `127.0.0.1`.
    #[arg(long, env = "POSTKEEP_BIND", default_value = "0.0.0.0:8080")]
    pub bind: SocketAddr,
}

/// Options for `migrate`.
#[derive(Debug, Args)]
pub struct MigrateArgs {
    /// Database URL for migrations, for example a direct connection that
    /// bypasses a pooler. Defaults to `POSTKEEP_DATABASE_URL`.
    #[arg(long, env = "POSTKEEP_DATABASE_MIGRATE_URL", hide_env_values = true)]
    pub migrate_url: Option<String>,

    /// Database URL the server uses.
    #[arg(
        long,
        env = "POSTKEEP_DATABASE_URL",
        default_value = "sqlite://postkeep.db",
        hide_env_values = true
    )]
    pub database_url: String,
}

impl MigrateArgs {
    /// The URL to migrate: the migration URL if set, else the server's.
    #[must_use]
    pub fn url(&self) -> &str {
        self.migrate_url
            .as_deref()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or(&self.database_url)
    }
}

/// What `storage-level` does besides showing the level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LevelAction {
    /// Raise the level to the one this version reads, if it is lower. Run it
    /// only once every instance runs this version or a newer one.
    Raise,
}

/// Options for `storage-level`.
#[derive(Debug, Args)]
pub struct StorageLevelArgs {
    /// What to do. Without one, the level is only shown.
    pub action: Option<LevelAction>,

    /// The database, as for `migrate`.
    #[command(flatten)]
    pub database: MigrateArgs,
}

/// Log output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Human-readable lines.
    Text,
    /// One JSON object per line.
    Json,
}

/// IMAP security modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImapSecurityArg {
    /// TLS from the first byte.
    Tls,
    /// No encryption (local test servers only).
    Plaintext,
}

/// SMTP security modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SmtpSecurityArg {
    /// TLS from the first byte.
    Tls,
    /// STARTTLS upgrade (iCloud).
    Starttls,
    /// No encryption (local test servers only).
    Plaintext,
}

impl MailArgs {
    /// The custom server's configuration, if `--imap-host` is set.
    #[must_use]
    pub fn custom_config(&self) -> Option<postkeep_mail::MailConfig> {
        let imap_host = self.imap_host.as_ref()?;
        let mut config = postkeep_mail::MailConfig::default();
        config.imap.host.clone_from(imap_host);
        config.imap.port = self.imap_port;
        config.imap.security = match self.imap_security {
            ImapSecurityArg::Tls => postkeep_mail::ImapSecurity::Tls,
            ImapSecurityArg::Plaintext => postkeep_mail::ImapSecurity::Plaintext,
        };
        config
            .smtp
            .host
            .clone_from(self.smtp_host.as_ref().unwrap_or(imap_host));
        config.smtp.port = self.smtp_port;
        config.smtp.security = match self.smtp_security {
            SmtpSecurityArg::Tls => postkeep_mail::SmtpSecurity::Tls,
            SmtpSecurityArg::Starttls => postkeep_mail::SmtpSecurity::StartTls,
            SmtpSecurityArg::Plaintext => postkeep_mail::SmtpSecurity::Plaintext,
        };
        config.timeout = self.timeout();
        Some(config)
    }

    /// The servers users can sign in to.
    #[must_use]
    pub fn servers(&self) -> postkeep_mail::ImapServers {
        let custom = self.custom_config();
        let presets = self.imap_providers.clone().unwrap_or_else(|| {
            if custom.is_some() {
                Vec::new()
            } else {
                postkeep_mail::ImapPreset::ALL.to_vec()
            }
        });
        postkeep_mail::ImapServers::new(
            presets,
            custom.map(|config| (self.imap_name.clone(), config)),
        )
        .with_timeout(self.timeout())
    }

    const fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.mail_timeout)
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_serve_flags() {
        let cli = Cli::try_parse_from([
            "postkeep",
            "serve",
            "--public-url",
            "https://mail.example.com",
            "--master-key",
            "00",
            "--allowed-emails",
            "a@icloud.com,b@icloud.com",
            "--imap-host",
            "mail.example.com",
            "--imap-security",
            "plaintext",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("expected serve");
        };
        assert_eq!(args.allowed_emails, ["a@icloud.com", "b@icloud.com"]);
        assert_eq!(args.bind.port(), 8080);
        assert_eq!(args.metrics_bind, None, "no metrics unless asked for");
        assert_eq!(args.shutdown_drain, 0, "no drain unless asked for");
        let mail = args.mail.custom_config().unwrap();
        assert_eq!(mail.imap.security, postkeep_mail::ImapSecurity::Plaintext);
        assert_eq!(mail.smtp.security, postkeep_mail::SmtpSecurity::StartTls);
        assert_eq!(mail.smtp.host, "mail.example.com");
        assert!(!mail.server_files_sent, "postkeep appends the Sent copy");
        assert!(mail.permanent_delete, "a permanent delete stays allowed");
        let servers = args.mail.servers();
        assert_eq!(
            servers.choices().len(),
            1,
            "a custom server replaces the presets"
        );
        assert_eq!(servers.default_server().unwrap().name, "Custom mail server");
        assert_eq!(args.webhook_retry_interval, 3600);
    }

    #[test]
    fn parses_metrics_bind() {
        let parse = |value: &str| {
            Cli::try_parse_from([
                "postkeep",
                "serve",
                "--public-url",
                "https://mail.example.com",
                "--master-key",
                "00",
                "--metrics-bind",
                value,
            ])
        };
        let Command::Serve(args) = parse("[::]:9091").unwrap().command else {
            panic!("expected serve");
        };
        assert_eq!(args.metrics_bind, Some("[::]:9091".parse().unwrap()));
        assert!(parse("9091").is_err(), "a port alone is not an address");
    }

    #[test]
    fn parses_webhook_retry_interval() {
        let cli = Cli::try_parse_from([
            "postkeep",
            "serve",
            "--public-url",
            "https://mail.example.com",
            "--master-key",
            "00",
            "--webhook-retry-interval",
            "120",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("expected serve");
        };
        assert_eq!(args.webhook_retry_interval, 120);

        for bad in ["0", "86401"] {
            let err = Cli::try_parse_from([
                "postkeep",
                "serve",
                "--public-url",
                "https://mail.example.com",
                "--master-key",
                "00",
                "--webhook-retry-interval",
                bad,
            ])
            .unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("86400") || message.contains("interval"),
                "{message}"
            );
        }
    }

    #[test]
    fn parses_webhook_filter_max_rules() {
        let parsed = |extra: &[&str]| {
            let base = [
                "postkeep",
                "serve",
                "--public-url",
                "https://mail.example.com",
            ];
            let args = base.iter().chain(&["--master-key", "00"]).chain(extra);
            Cli::try_parse_from(args).map(|cli| match cli.command {
                Command::Serve(args) => args.webhook_filter_max_rules,
                _ => panic!("expected serve"),
            })
        };
        assert_eq!(parsed(&[]).unwrap(), 1000);
        for ok in [0, 2000] {
            let value = ok.to_string();
            let flag = ["--webhook-filter-max-rules", value.as_str()];
            assert_eq!(parsed(&flag).unwrap(), ok);
        }
        for bad in ["2001", "x"] {
            let message = parsed(&["--webhook-filter-max-rules", bad])
                .unwrap_err()
                .to_string();
            let expected =
                format!("POSTKEEP_WEBHOOK_FILTER_MAX_RULES must be from 0 to 2000, not {bad}");
            assert!(message.contains(&expected), "{message}");
        }
    }

    /// Flags share the env parsers. `std::env::set_var` is unsafe on this
    /// toolchain and `unsafe_code` is forbidden, so the env names are
    /// covered by the parser messages and by [`ServeArgs::outbox_policy`].
    #[test]
    fn validates_outbox_limits() {
        let Command::Serve(args) = Cli::try_parse_from([
            "postkeep",
            "serve",
            "--public-url",
            "https://mail.example.com",
            "--master-key",
            "00",
        ])
        .unwrap()
        .command
        else {
            panic!("expected serve");
        };
        let policy = args.outbox_policy().unwrap();
        assert_eq!(
            policy.retention_secs,
            postkeep_store::DEFAULT_OUTBOX_RETENTION_SECS
        );
        assert_eq!(policy.max_events, postkeep_store::DEFAULT_OUTBOX_MAX_EVENTS);
        assert_eq!(
            policy.max_retention_secs,
            postkeep_store::DEFAULT_OUTBOX_MAX_RETENTION_SECS
        );
        assert_eq!(
            policy.max_events_limit,
            postkeep_store::DEFAULT_OUTBOX_MAX_EVENTS_LIMIT
        );

        let rejected = |flag: &str, value: &str| {
            Cli::try_parse_from([
                "postkeep",
                "serve",
                "--public-url",
                "https://mail.example.com",
                "--master-key",
                "00",
                flag,
                value,
            ])
            .unwrap_err()
            .to_string()
        };
        let low = rejected("--webhook-outbox-retention", "0");
        assert!(low.contains("3600") && low.contains("31622400"), "{low}");
        let hour = rejected("--webhook-outbox-max-retention", "3599");
        assert!(hour.contains("must be from 3600"), "{hour}");
        let year = rejected("--webhook-outbox-max-retention", "31708800");
        assert!(year.contains("31622400"), "{year}");
        let duration = rejected("--webhook-outbox-retention", "36h");
        assert!(duration.contains("whole number of seconds"), "{duration}");
        let zero_events = rejected("--webhook-outbox-max-events", "0");
        assert!(
            zero_events.contains("must be from 1 to 100000"),
            "{zero_events}"
        );
        let huge = rejected("--webhook-outbox-max-events-limit", "100001");
        assert!(huge.contains("100000"), "{huge}");
    }

    #[test]
    fn rejects_outbox_defaults_above_their_ceilings() {
        let Command::Serve(args) = Cli::try_parse_from([
            "postkeep",
            "serve",
            "--public-url",
            "https://mail.example.com",
            "--master-key",
            "00",
            "--webhook-outbox-retention",
            "2592000",
            "--webhook-outbox-max-retention",
            "86400",
        ])
        .unwrap()
        .command
        else {
            panic!("expected serve");
        };
        let message = args.outbox_policy().unwrap_err();
        assert!(
            message.contains("POSTKEEP_WEBHOOK_OUTBOX_RETENTION (2592000 seconds)")
                && message.contains("POSTKEEP_WEBHOOK_OUTBOX_MAX_RETENTION (86400 seconds)"),
            "{message}"
        );

        let Command::Serve(args) = Cli::try_parse_from([
            "postkeep",
            "serve",
            "--public-url",
            "https://mail.example.com",
            "--master-key",
            "00",
            "--webhook-outbox-max-events",
            "20000",
            "--webhook-outbox-max-events-limit",
            "10000",
        ])
        .unwrap()
        .command
        else {
            panic!("expected serve");
        };
        let message = args.outbox_policy().unwrap_err();
        assert!(
            message.contains("POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS (20000)")
                && message.contains("POSTKEEP_WEBHOOK_OUTBOX_MAX_EVENTS_LIMIT (10000)"),
            "{message}"
        );
    }

    #[test]
    fn the_event_hold_is_an_hour_unless_set_in_whole_seconds() {
        let parse = |hold: &[&str]| {
            let line = ["postkeep", "serve", "--public-url", "https://a.example"];
            let line = line.iter().chain(&["--master-key", "00"]).chain(hold);
            Cli::try_parse_from(line)
        };
        let Command::Serve(args) = parse(&[]).unwrap().command else {
            panic!("expected serve");
        };
        assert_eq!(args.webhook_outbox_hold, 3600);
        let accepts = |value: &str| parse(&["--webhook-outbox-hold", value]).is_ok();
        assert!(accepts("0") && accepts("31622400"));
        assert!(!accepts("31622401") && !accepts("1h"));
        assert!(serve_arg_help("webhook-outbox-hold").contains("0 skips at once"));
    }

    fn providers(extra: &[&str]) -> ProviderArgs {
        let mut command_line = vec![
            "postkeep",
            "serve",
            "--public-url",
            "https://m.example.com",
            "--master-key",
            "00",
        ];
        command_line.extend_from_slice(extra);
        let Command::Serve(args) = Cli::try_parse_from(command_line).unwrap().command else {
            panic!("expected serve");
        };
        args.providers
    }

    #[test]
    fn validates_gmail_push_settings() {
        let public = url::Url::parse("https://m.example.com").unwrap();
        assert_eq!(providers(&[]).google_push(&public), Ok(None));
        let (topic, expected) = providers(&[
            "--google-pubsub-topic",
            "projects/demo-1/topics/gmail",
            "--google-pubsub-service-account",
            "push@demo-1.iam.gserviceaccount.com",
        ])
        .google_push(&public)
        .unwrap()
        .unwrap();
        assert_eq!(topic, "projects/demo-1/topics/gmail");
        assert_eq!(expected.audience, "https://m.example.com/push/google");
        assert_eq!(
            expected.service_account,
            "push@demo-1.iam.gserviceaccount.com"
        );
        let custom = providers(&[
            "--google-pubsub-topic",
            "projects/demo-1/topics/gmail",
            "--google-pubsub-service-account",
            "push@demo-1.iam.gserviceaccount.com",
            "--google-pubsub-audience",
            "postkeep-push",
        ])
        .google_push(&public)
        .unwrap()
        .unwrap();
        assert_eq!(custom.1.audience, "postkeep-push");
        for bad in [
            &["--google-pubsub-topic", "gmail"][..],
            &["--google-pubsub-topic", "projects/demo-1/topics/gmail"][..],
            &[
                "--google-pubsub-service-account",
                "push@demo-1.iam.gserviceaccount.com",
            ][..],
            &[
                "--google-pubsub-topic",
                "projects/demo-1/topics/gmail",
                "--google-pubsub-service-account",
                "push",
            ][..],
        ] {
            assert!(providers(bad).google_push(&public).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn offers_every_preset_by_default() {
        let cli = Cli::try_parse_from([
            "postkeep",
            "serve",
            "--public-url",
            "https://m.example.com",
            "--master-key",
            "00",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("expected serve");
        };
        let servers = args.mail.servers();
        assert_eq!(
            servers.choices().len(),
            postkeep_mail::ImapPreset::ALL.len()
        );
        let ids: Vec<_> = servers.choices().iter().map(|s| s.id.id()).collect();
        assert!(ids.contains(&"gmail"), "offered by default: {ids:?}");
        assert_eq!(servers.default_server().unwrap().id.id(), "icloud");
    }

    #[test]
    fn parses_provider_lists() {
        let cli = Cli::try_parse_from([
            "postkeep",
            "serve",
            "--public-url",
            "https://m.example.com",
            "--master-key",
            "00",
            "--imap-providers",
            "fastmail,icloud,gmail",
            "--imap-host",
            "mx.example.com",
            "--imap-name",
            "Example",
        ])
        .unwrap();
        let Command::Serve(args) = cli.command else {
            panic!("expected serve");
        };
        let names: Vec<String> = args
            .mail
            .servers()
            .choices()
            .into_iter()
            .map(|server| server.name)
            .collect();
        assert_eq!(names, ["Fastmail", "iCloud Mail", "Gmail", "Example"]);
        // "gmail" used to be the example of a name that is no preset.
        assert!(
            Cli::try_parse_from([
                "postkeep",
                "serve",
                "--public-url",
                "https://m.example.com",
                "--master-key",
                "00",
                "--imap-providers",
                "hotmail",
            ])
            .is_err()
        );
    }

    #[test]
    fn every_option_uses_the_postkeep_prefix() {
        for subcommand in Cli::command().get_subcommands() {
            for arg in subcommand.get_arguments() {
                if let Some(env) = arg.get_env() {
                    assert!(
                        env.to_string_lossy().starts_with(ENV_PREFIX),
                        "{env:?} does not start with {ENV_PREFIX}"
                    );
                }
            }
        }
    }

    #[test]
    fn unset_pool_settings_are_the_store_defaults() {
        let base = [
            "postkeep",
            "serve",
            "--public-url",
            "https://a.example",
            "--master-key",
        ];
        let key = "00".repeat(32);
        let mut args: Vec<&str> = base.to_vec();
        args.push(&key);
        let Command::Serve(serve) = Cli::try_parse_from(&args).unwrap().command else {
            panic!("not serve");
        };
        assert_eq!(
            serve.pool_settings(),
            postkeep_store::PoolSettings::default()
        );

        args.extend([
            "--database-max-connections",
            "4",
            "--database-idle-timeout",
            "300",
            "--database-max-lifetime",
            "0",
        ]);
        let Command::Serve(serve) = Cli::try_parse_from(&args).unwrap().command else {
            panic!("not serve");
        };
        let pool = serve.pool_settings();
        assert_eq!(pool.max_connections, 4);
        assert_eq!(pool.idle_timeout, Some(Duration::from_secs(300)));
        assert_eq!(pool.max_lifetime, None);
        args.extend(["--database-max-connections", "0"]);
        assert!(Cli::try_parse_from(&args).is_err());
    }

    #[test]
    fn requires_a_master_key() {
        let result =
            Cli::try_parse_from(["postkeep", "serve", "--public-url", "https://a.example"]);
        assert!(result.is_err());
    }

    fn serve_arg_help(flag: &str) -> String {
        let command = Cli::command();
        let serve = command.find_subcommand("serve").unwrap();
        let argument = serve
            .get_arguments()
            .find(|argument| argument.get_long() == Some(flag))
            .unwrap();
        argument.get_help().unwrap().to_string()
    }

    #[test]
    fn help_names_addresses_and_which_webhooks_hold_an_imap_connection() {
        // Clap removes one trailing period from short help. The doc comments
        // keep it; this is the text `postkeep serve --help` shows.
        let emails = serve_arg_help("allowed-emails");
        assert_eq!(
            emails,
            "Comma-separated addresses allowed to connect. Empty allows any"
        );
        assert!(!emails.contains("iCloud"));

        let webhooks = serve_arg_help("webhooks");
        assert!(
            webhooks.contains(
                "An IMAP webhook keeps one IMAP connection open; Outlook and Gmail do not"
            ),
            "{webhooks}"
        );
        assert!(
            !webhooks.contains("Each enabled webhook keeps one IMAP connection open"),
            "{webhooks}"
        );
        assert!(
            webhooks.contains("A paused IMAP webhook still keeps its connection"),
            "{webhooks}"
        );
    }
}
