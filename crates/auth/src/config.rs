//! Authorization server configuration.

use std::time::Duration;

use axum::http::{HeaderMap, HeaderName};
use postkeep_store::SessionTtl;
use url::Url;

use crate::hosts::{AllowedHosts, RequestHost};

/// Where RFC 9728 documents live; a resource's path follows it.
pub const METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

/// Invalid authorization server configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// The public URL could not be parsed or is not usable as an issuer.
    #[error("invalid public URL: {0}")]
    PublicUrl(String),
    /// The MCP endpoint path is not an absolute path.
    #[error("invalid resource path: {0}")]
    ResourcePath(String),
    /// A resource prefix is not an absolute path made of names.
    #[error("invalid resource prefix: {0}")]
    ResourcePrefix(String),
}

/// A path such as `/w` under which each name is its own protected resource:
/// `<prefix>/<name><resource path>`. See [`AuthConfig::resource_prefix`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePrefix(String);

impl ResourcePrefix {
    /// Checks `prefix`: a `/` followed by one or more names separated by
    /// `/`, without a trailing slash. A name is 1 to 63 ASCII letters,
    /// digits, `-` or `_`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ResourcePrefix`] for anything else.
    pub fn new(prefix: &str) -> Result<Self, ConfigError> {
        let valid = prefix
            .strip_prefix('/')
            .is_some_and(|rest| rest.split('/').all(is_resource_name));
        if valid {
            Ok(Self(prefix.to_owned()))
        } else {
            Err(ConfigError::ResourcePrefix(prefix.to_owned()))
        }
    }

    /// The prefix, such as `/w`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `name` can be one segment of a resource path: 1 to 63 ASCII
/// letters, digits, `-` or `_`, so that the resource URL needs no
/// percent-encoding and has no dot segments.
fn is_resource_name(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

/// Settings for the authorization server.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AuthConfig {
    issuer: String,
    resource_path: String,
    /// Lifetime of access tokens.
    pub access_token_ttl: Duration,
    /// Lifetime of refresh tokens. Each refresh issues a new one.
    pub refresh_token_ttl: Duration,
    /// Window from first use in which a refresh token may rotate again.
    /// Defaults to 30 seconds; zero revokes on every reuse. Elapsed time is
    /// counted in whole seconds from the stored first use; a clock behind it
    /// revokes too. Longer grace gives a copied token more time to obtain an
    /// undetected independent token chain.
    pub refresh_reuse_grace: Duration,
    /// Lifetime of authorization codes.
    pub code_ttl: Duration,
    /// How long the sign-in page stays valid.
    pub sign_in_ttl: Duration,
    /// If set, only these addresses (lowercase) may sign in or use
    /// their existing tokens.
    pub allowed_emails: Option<Vec<String>>,
    /// Header carrying the client IP address, set by a trusted reverse
    /// proxy (for example `Fly-Client-IP` or `X-Forwarded-For`). When `None`,
    /// the TCP peer address is used.
    pub client_ip_header: Option<HeaderName>,
    /// Failed sign-ins allowed per address or client IP before backoff
    /// starts.
    pub free_sign_in_failures: u32,
    /// First backoff delay; each further failure doubles it.
    pub sign_in_backoff_base: Duration,
    /// Longest backoff for one iCloud address. Kept short so that someone
    /// guessing at another person's address cannot lock them out for long.
    pub account_backoff_max: Duration,
    /// Longest backoff for one client IP address (IPv6: per /64).
    pub ip_backoff_max: Duration,
    /// Client registrations allowed per IP address in
    /// [`AuthConfig::registration_window`].
    pub registrations_per_ip: u32,
    /// Window for [`AuthConfig::registrations_per_ip`].
    pub registration_window: Duration,
    /// Upper bound on registered clients; registration fails beyond it.
    pub max_clients: u64,
    /// Requests per minute and client IP to the authorization, token,
    /// revocation and registration endpoints.
    pub requests_per_minute: u32,
    /// How long account page sessions last.
    pub session_ttl: SessionTtl,
    /// IMAP servers users can sign in to with an app password.
    pub imap_servers: postkeep_mail::ImapServers,
    /// `Host` values the MCP endpoint answers to. The application sets the
    /// public host plus `POSTKEEP_ALLOWED_HOSTS`, which may hold
    /// `*.example.com` patterns.
    pub allowed_hosts: AllowedHosts,
    /// Whether each allowed host is its own protected resource,
    /// `https://<host><resource path>`, under the one issuer. Off by default:
    /// the public URL is the only resource. On, a token must name the exact
    /// resource of the host it is used at: `resource` is required at
    /// `/authorize` and `/token`, and the issuer no longer counts as one.
    pub per_request_resources: bool,
    /// With [`per_request_resources`](Self::per_request_resources), also
    /// makes `<prefix>/<name><resource path>` on every allowed host its own
    /// protected resource, for each name of 1 to 63 ASCII letters, digits,
    /// `-` or `_`. This gives every name its own audience on a host that
    /// cannot have a subdomain per name. The resource path itself stays a
    /// resource too. Ignored without per-request resources.
    pub resource_prefix: Option<ResourcePrefix>,
}

impl AuthConfig {
    /// Creates a configuration for a server reachable at `public_url`, with
    /// the MCP endpoint at `resource_path` (for example `/mcp`).
    ///
    /// The public URL must be an `http` or `https` origin without a path,
    /// query or fragment, such as `https://mail.example.com`.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the URL or path is unusable.
    pub fn new(public_url: &str, resource_path: &str) -> Result<Self, ConfigError> {
        let url = Url::parse(public_url).map_err(|err| ConfigError::PublicUrl(err.to_string()))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(ConfigError::PublicUrl(
                "the scheme must be http or https".to_owned(),
            ));
        }
        if url.host().is_none() {
            return Err(ConfigError::PublicUrl("a host is required".to_owned()));
        }
        if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            return Err(ConfigError::PublicUrl(
                "use the origin only, without a path, query or fragment".to_owned(),
            ));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConfigError::PublicUrl(
                "credentials are not allowed".to_owned(),
            ));
        }
        if !resource_path.starts_with('/')
            || resource_path.len() < 2
            || resource_path.ends_with('/')
        {
            return Err(ConfigError::ResourcePath(resource_path.to_owned()));
        }
        let issuer = url.as_str().trim_end_matches('/').to_owned();
        Ok(Self {
            issuer,
            resource_path: resource_path.to_owned(),
            access_token_ttl: Duration::from_hours(1),
            refresh_token_ttl: Duration::from_hours(30 * 24),
            refresh_reuse_grace: Duration::from_secs(30),
            code_ttl: Duration::from_mins(5),
            sign_in_ttl: Duration::from_mins(30),
            allowed_emails: None,
            client_ip_header: None,
            free_sign_in_failures: 5,
            sign_in_backoff_base: Duration::from_secs(1),
            account_backoff_max: Duration::from_mins(1),
            ip_backoff_max: Duration::from_mins(15),
            registrations_per_ip: 20,
            registration_window: Duration::from_hours(1),
            max_clients: 10_000,
            requests_per_minute: 120,
            session_ttl: SessionTtl {
                idle: Duration::from_hours(1),
                absolute: Duration::from_hours(12),
            },
            imap_servers: postkeep_mail::ImapServers::default(),
            allowed_hosts: AllowedHosts::new(url.host_str()),
            per_request_resources: false,
            resource_prefix: None,
        })
    }

    /// Whether the public URL uses `https`.
    #[must_use]
    pub fn is_https(&self) -> bool {
        self.issuer.starts_with("https://")
    }

    /// The issuer identifier: the public URL without a trailing slash.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Path of the protected MCP endpoint, such as `/mcp`.
    #[must_use]
    pub fn resource_path(&self) -> &str {
        &self.resource_path
    }

    /// The canonical URI of the MCP endpoint, used as the resource indicator.
    #[must_use]
    pub fn resource(&self) -> String {
        format!("{}{}", self.issuer, self.resource_path)
    }

    /// Path of the RFC 9728 metadata document for the MCP endpoint.
    #[must_use]
    pub fn resource_metadata_path(&self) -> String {
        format!("{METADATA_PATH}{}", self.resource_path)
    }

    /// Absolute URL of the RFC 9728 metadata document for the MCP endpoint.
    #[must_use]
    pub fn resource_metadata_url(&self) -> String {
        format!("{}{}", self.issuer, self.resource_metadata_path())
    }

    /// The route pattern, such as `/w/{name}/mcp`, of the resources under
    /// [`resource_prefix`](Self::resource_prefix), when there are any.
    #[must_use]
    pub fn prefixed_resource_route(&self) -> Option<String> {
        let prefix = self
            .resource_prefix
            .as_ref()
            .filter(|_| self.per_request_resources)?;
        Some(format!(
            "{}/{{name}}{}",
            prefix.as_str(),
            self.resource_path
        ))
    }

    /// Whether `path` is the path of one of this server's resources: the
    /// resource path, or with a [`resource_prefix`](Self::resource_prefix)
    /// `<prefix>/<name><resource path>`.
    fn is_resource_path(&self, path: &str) -> bool {
        if path == self.resource_path {
            return true;
        }
        self.resource_prefix
            .as_ref()
            .filter(|_| self.per_request_resources)
            .and_then(|prefix| path.strip_prefix(prefix.as_str()))
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.strip_suffix(self.resource_path.as_str()))
            .is_some_and(is_resource_name)
    }

    /// Absolute URL of an endpoint on this server.
    pub(crate) fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.issuer)
    }

    /// Whether a requested resource indicator names this server's MCP
    /// endpoint. The bare origin is accepted too, since some clients send it.
    ///
    /// With [`per_request_resources`](Self::per_request_resources), only the
    /// exact resource URL of an allowed host is accepted: no trailing slash,
    /// no bare origin, no issuer.
    pub(crate) fn accepts_resource(&self, resource: &str) -> bool {
        if self.per_request_resources {
            return self.serves_resource(resource);
        }
        let resource = resource.trim_end_matches('/');
        resource == self.resource() || resource == self.issuer
    }

    /// `http` or `https`, from the public URL.
    fn scheme(&self) -> &str {
        if self.is_https() { "https" } else { "http" }
    }

    /// The URL of `path` on `host`: `<scheme>://<host><path>`.
    fn url_on(&self, host: &RequestHost, path: &str) -> String {
        format!("{}://{}{path}", self.scheme(), host.authority())
    }

    /// Whether `resource` is exactly the URL of a resource path on an
    /// allowed host.
    fn serves_resource(&self, resource: &str) -> bool {
        let Ok(url) = url::Url::parse(resource) else {
            return false;
        };
        let Some(host) = url.host_str() else {
            return false;
        };
        let host = RequestHost {
            host: host.trim_matches(['[', ']']).to_ascii_lowercase(),
            port: url.port(),
        };
        self.allowed_hosts.allows(&host)
            && self.is_resource_path(url.path())
            && self.url_on(&host, url.path()) == resource
    }

    /// The allowed host of a request whose path is a resource path.
    fn served_host(&self, headers: &HeaderMap, path: &str) -> Option<RequestHost> {
        RequestHost::from_headers(headers)
            .filter(|host| self.allowed_hosts.allows(host) && self.is_resource_path(path))
    }

    /// The resource a request for `path` addresses. Without per-request
    /// resources it is always [`resource`](Self::resource). With them it is
    /// `<scheme>://<host><path>` for the request's `Host`, or `None` when
    /// that host is missing or not allowed, or `path` is not the resource
    /// path or a name under the [`resource_prefix`](Self::resource_prefix).
    #[must_use]
    pub fn resource_for(&self, headers: &HeaderMap, path: &str) -> Option<String> {
        if !self.per_request_resources {
            return Some(self.resource());
        }
        self.served_host(headers, path)
            .map(|host| self.url_on(&host, path))
    }

    /// The RFC 9728 metadata URL to advertise to a request for `path`: the
    /// resource's own document with per-request resources, otherwise (or
    /// when the request addresses no resource)
    /// [`resource_metadata_url`](Self::resource_metadata_url).
    #[must_use]
    pub fn resource_metadata_url_for(&self, headers: &HeaderMap, path: &str) -> String {
        if self.per_request_resources
            && let Some(host) = self.served_host(headers, path)
        {
            return self.url_on(&host, &format!("{METADATA_PATH}{path}"));
        }
        self.resource_metadata_url()
    }

    /// Whether `email` may sign in or use its tokens. Comparison is
    /// case-insensitive.
    #[must_use]
    pub fn email_allowed(&self, email: &str) -> bool {
        self.allowed_emails.as_ref().is_none_or(|allowed| {
            allowed
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(email.trim()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_urls_from_origin() {
        let config = AuthConfig::new("https://mail.example.com/", "/mcp").unwrap();
        assert_eq!(config.issuer(), "https://mail.example.com");
        assert_eq!(config.resource(), "https://mail.example.com/mcp");
        assert_eq!(
            config.resource_metadata_url(),
            "https://mail.example.com/.well-known/oauth-protected-resource/mcp"
        );
        assert!(config.accepts_resource("https://mail.example.com/mcp"));
        assert!(config.accepts_resource("https://mail.example.com/"));
        assert!(!config.accepts_resource("https://evil.example.com/mcp"));
    }

    #[test]
    fn keeps_non_default_ports() {
        let config = AuthConfig::new("http://localhost:8080", "/mcp").unwrap();
        assert_eq!(config.issuer(), "http://localhost:8080");
    }

    #[test]
    fn rejects_unusable_urls() {
        for url in [
            "mail.example.com",
            "ftp://mail.example.com",
            "https://mail.example.com/base",
            "https://mail.example.com/?x=1",
            "https://user:pw@mail.example.com",
        ] {
            assert!(AuthConfig::new(url, "/mcp").is_err(), "{url}");
        }
        for path in ["mcp", "/", "/mcp/"] {
            assert!(
                AuthConfig::new("https://a.example", path).is_err(),
                "{path}"
            );
        }
    }

    #[test]
    fn checks_resource_prefixes() {
        for prefix in ["/w", "/teams/v1", "/A-z_0"] {
            assert_eq!(ResourcePrefix::new(prefix).unwrap().as_str(), prefix);
        }
        for prefix in [
            "", "/", "w", "/w/", "//w", "/w//x", "/{w}", "/w.x", "/w/..", "/é",
        ] {
            assert!(ResourcePrefix::new(prefix).is_err(), "{prefix}");
        }
        assert!(ResourcePrefix::new(&format!("/{}", "a".repeat(64))).is_err());
    }

    #[test]
    fn a_prefix_makes_each_name_a_resource() {
        let mut config = AuthConfig::new("https://app.example.com", "/mcp").unwrap();
        config.resource_prefix = Some(ResourcePrefix::new("/w").unwrap());
        // Without per-request resources the prefix does nothing.
        assert_eq!(config.prefixed_resource_route(), None);
        assert!(!config.is_resource_path("/w/acme/mcp"));

        config.per_request_resources = true;
        assert_eq!(
            config.prefixed_resource_route().as_deref(),
            Some("/w/{name}/mcp")
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::HOST,
            axum::http::HeaderValue::from_static("app.example.com"),
        );
        assert_eq!(
            config.resource_for(&headers, "/w/acme-1_b/mcp").as_deref(),
            Some("https://app.example.com/w/acme-1_b/mcp")
        );
        assert_eq!(
            config.resource_for(&headers, "/mcp").as_deref(),
            Some("https://app.example.com/mcp")
        );
        assert_eq!(
            config.resource_metadata_url_for(&headers, "/w/acme/mcp"),
            "https://app.example.com/.well-known/oauth-protected-resource/w/acme/mcp"
        );
        for path in [
            "/w/mcp",
            "/w//mcp",
            "/w/a/b/mcp",
            "/w/a.b/mcp",
            "/w/acme",
            "/x/acme/mcp",
        ] {
            assert_eq!(config.resource_for(&headers, path), None, "{path}");
            assert_eq!(
                config.resource_metadata_url_for(&headers, path),
                config.resource_metadata_url(),
                "{path}"
            );
        }

        assert!(config.accepts_resource("https://app.example.com/w/acme/mcp"));
        assert!(config.accepts_resource("https://app.example.com/mcp"));
        for resource in [
            "https://app.example.com/w/acme/mcp/",
            "https://app.example.com/w/acme/mcp?x=1",
            "https://app.example.com/w/acme/mcp#x",
            "https://app.example.com/w/./mcp",
            "https://app.example.com/w/%61cme/mcp",
            "https://app.example.com/w/a/b/mcp",
            "https://app.example.com/w/acme",
            "http://app.example.com/w/acme/mcp",
            "https://other.example.com/w/acme/mcp",
        ] {
            assert!(!config.accepts_resource(resource), "{resource}");
        }
    }

    #[test]
    fn filters_allowed_emails() {
        let mut config = AuthConfig::new("https://a.example", "/mcp").unwrap();
        assert!(config.email_allowed("anyone@icloud.com"));
        config.allowed_emails = Some(vec!["me@icloud.com".to_owned()]);
        assert!(config.email_allowed("me@icloud.com"));
        assert!(config.email_allowed("Me@iCloud.com"));
        assert!(!config.email_allowed("other@icloud.com"));
    }
}
