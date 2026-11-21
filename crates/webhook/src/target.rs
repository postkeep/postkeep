//! Webhook URLs and custom auth headers, validated before they are stored.

use std::fmt;
use std::net::IpAddr;

use http::{HeaderName, HeaderValue};
use url::{Host, Url};

use crate::ip;

/// The longest URL accepted.
pub const MAX_URL_LEN: usize = 2048;
/// The longest custom header value accepted.
pub const MAX_HEADER_VALUE_LEN: usize = 4096;

/// Why a webhook URL or header was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TargetError {
    /// Not an absolute URL.
    #[error("enter a full URL, such as https://example.com/hooks/new-mail")]
    Invalid,
    /// Longer than [`MAX_URL_LEN`].
    #[error("the URL is too long")]
    TooLong,
    /// Not `https`.
    #[error("the URL must use https")]
    NotHttps,
    /// Contains a user name or password.
    #[error("the URL must not contain a user name or password")]
    Credentials,
    /// A literal IP address, or a name, that is not publicly routable.
    #[error("private, loopback, link-local and metadata addresses are blocked")]
    Blocked,
    /// The header name is not a valid token or is reserved.
    #[error("this header name can't be used")]
    HeaderName,
    /// The header value contains forbidden characters or is too long.
    #[error("the header value contains characters that aren't allowed or is too long")]
    HeaderValue,
}

/// An `https` URL that passed the static checks. Its host still has to
/// resolve to public addresses at delivery time.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookUrl {
    url: Url,
}

impl WebhookUrl {
    /// Validates a URL entered by a user.
    ///
    /// # Errors
    ///
    /// Returns a [`TargetError`] describing the first problem found.
    pub fn parse(text: &str) -> Result<Self, TargetError> {
        let text = text.trim();
        if text.len() > MAX_URL_LEN {
            return Err(TargetError::TooLong);
        }
        let mut url = Url::parse(text).map_err(|_| TargetError::Invalid)?;
        if url.scheme() != "https" {
            return Err(TargetError::NotHttps);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(TargetError::Credentials);
        }
        match url.host() {
            None => return Err(TargetError::Invalid),
            Some(Host::Ipv4(ip)) if !ip::is_public(IpAddr::V4(ip)) => {
                return Err(TargetError::Blocked);
            }
            Some(Host::Ipv6(ip)) if !ip::is_public(IpAddr::V6(ip)) => {
                return Err(TargetError::Blocked);
            }
            Some(Host::Domain(domain)) if is_local_name(domain) => {
                return Err(TargetError::Blocked);
            }
            Some(_) => {}
        }
        url.set_fragment(None);
        Ok(Self { url })
    }

    /// The full URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    /// The host as a DNS name, or `None` for a literal IP address.
    #[must_use]
    pub fn domain(&self) -> Option<&str> {
        self.url.domain()
    }

    /// The host as written in the URL (IPv6 without brackets).
    #[must_use]
    pub fn host(&self) -> String {
        match self.url.host() {
            Some(Host::Ipv6(ip)) => ip.to_string(),
            Some(host) => host.to_string(),
            None => String::new(),
        }
    }

    /// The literal IP address, if the host is one.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        match self.url.host() {
            Some(Host::Ipv4(ip)) => Some(IpAddr::V4(ip)),
            Some(Host::Ipv6(ip)) => Some(IpAddr::V6(ip)),
            _ => None,
        }
    }

    /// The port, 443 unless the URL names another.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.url.port_or_known_default().unwrap_or(443)
    }

    /// The value of the `Host` header: the host, plus the port if it is
    /// not 443.
    #[must_use]
    pub fn authority(&self) -> String {
        let host = match self.url.host() {
            Some(Host::Ipv6(ip)) => format!("[{ip}]"),
            Some(host) => host.to_string(),
            None => String::new(),
        };
        match self.url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }

    /// The path and query, as sent in the request line.
    #[must_use]
    pub fn path_and_query(&self) -> String {
        let path = self.url.path();
        self.url
            .query()
            .map_or_else(|| path.to_owned(), |query| format!("{path}?{query}"))
    }
}

impl fmt::Debug for WebhookUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Query strings often carry tokens: show only scheme, host and path.
        write!(f, "WebhookUrl({}{})", self.authority(), self.url.path())
    }
}

/// Names that always point inside the host or its private network.
fn is_local_name(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    domain == "localhost"
        || !domain.contains('.')
        || [".localhost", ".local", ".internal", ".home.arpa", ".lan"]
            .iter()
            .any(|suffix| domain.ends_with(suffix))
}

/// Headers that the delivery sets itself and a user can't override.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-length",
    "content-type",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-connection",
    "user-agent",
    "expect",
    "cookie",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "x-signature-256",
];

/// A custom header sent with every delivery, such as `Authorization`.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthHeader {
    /// The header name, lowercase.
    pub name: HeaderName,
    /// The header value, marked sensitive.
    pub value: HeaderValue,
}

impl AuthHeader {
    /// Validates a header name and value entered by a user.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::HeaderName`] or [`TargetError::HeaderValue`].
    pub fn new(name: &str, value: &str) -> Result<Self, TargetError> {
        let name = parse_header_name(name)?;
        if value.len() > MAX_HEADER_VALUE_LEN || value.is_empty() {
            return Err(TargetError::HeaderValue);
        }
        let mut value = HeaderValue::from_str(value).map_err(|_| TargetError::HeaderValue)?;
        value.set_sensitive(true);
        Ok(Self { name, value })
    }
}

impl fmt::Debug for AuthHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthHeader({}: <redacted>)", self.name)
    }
}

/// Validates a custom header name on its own (the value may be kept from
/// earlier).
///
/// # Errors
///
/// Returns [`TargetError::HeaderName`] if the name is not a valid token or
/// is set by the delivery itself.
pub fn parse_header_name(name: &str) -> Result<HeaderName, TargetError> {
    let name =
        HeaderName::from_bytes(name.trim().as_bytes()).map_err(|_| TargetError::HeaderName)?;
    let lower = name.as_str();
    if RESERVED_HEADERS.contains(&lower)
        || lower.starts_with("x-webhook-")
        || lower.starts_with("sec-")
    {
        return Err(TargetError::HeaderName);
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_public_https_urls() {
        let url = WebhookUrl::parse(" https://hooks.example.com/mail?token=abc#frag ")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(url.as_str(), "https://hooks.example.com/mail?token=abc");
        assert_eq!(url.domain(), Some("hooks.example.com"));
        assert_eq!(url.port(), 443);
        assert_eq!(url.authority(), "hooks.example.com");
        assert_eq!(url.path_and_query(), "/mail?token=abc");
        assert!(!format!("{url:?}").contains("token"));

        let url = WebhookUrl::parse("https://[2606:4700:4700::1111]:8443/x")
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(url.authority(), "[2606:4700:4700::1111]:8443");
        assert_eq!(url.host(), "2606:4700:4700::1111");
        assert_eq!(url.port(), 8443);
        assert!(url.ip().is_some());
    }

    #[test]
    fn refuses_unsafe_urls() {
        for (text, error) in [
            ("hooks.example.com", TargetError::Invalid),
            ("http://hooks.example.com/", TargetError::NotHttps),
            ("ftp://hooks.example.com/", TargetError::NotHttps),
            ("file:///etc/passwd", TargetError::NotHttps),
            (
                "https://user:pass@hooks.example.com/",
                TargetError::Credentials,
            ),
            ("https://user@hooks.example.com/", TargetError::Credentials),
            ("https://127.0.0.1/", TargetError::Blocked),
            ("https://2130706433/", TargetError::Blocked),
            ("https://0x7f.1/", TargetError::Blocked),
            (
                "https://169.254.169.254/latest/meta-data/",
                TargetError::Blocked,
            ),
            ("https://[::1]/", TargetError::Blocked),
            ("https://[::ffff:7f00:1]/", TargetError::Blocked),
            ("https://[fd00:ec2::254]/", TargetError::Blocked),
            ("https://localhost/", TargetError::Blocked),
            ("https://LOCALHOST./", TargetError::Blocked),
            ("https://app.localhost/", TargetError::Blocked),
            ("https://my-app.internal/", TargetError::Blocked),
            ("https://printer.local/", TargetError::Blocked),
            ("https://intranet/", TargetError::Blocked),
        ] {
            assert_eq!(WebhookUrl::parse(text), Err(error), "{text}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(WebhookUrl::parse(&long), Err(TargetError::TooLong));
    }

    #[test]
    fn validates_auth_headers() {
        let header =
            AuthHeader::new("Authorization", "Bearer abc").unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(header.name, "authorization");
        assert!(header.value.is_sensitive());
        assert!(!format!("{header:?}").contains("abc"));
        assert!(AuthHeader::new("X-Api-Key", "k").is_ok());

        for name in [
            "Host",
            "content-type",
            "X-Webhook-Signature",
            "X-Signature-256",
            "bad name",
            "",
            "Sec-Fetch-Site",
        ] {
            assert_eq!(
                AuthHeader::new(name, "v"),
                Err(TargetError::HeaderName),
                "{name}"
            );
        }
        for value in [
            "",
            "a\r\nX-Evil: 1",
            "a\nb",
            &"v".repeat(MAX_HEADER_VALUE_LEN + 1),
        ] {
            assert_eq!(
                AuthHeader::new("Authorization", value),
                Err(TargetError::HeaderValue)
            );
        }
    }
}
