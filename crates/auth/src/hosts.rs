//! `Host` header values the server answers to.

use axum::http::{HeaderMap, header};

/// Host names the MCP endpoint answers to.
///
/// Entries are exact names, with an optional port, and `*.example.com`
/// patterns that match exactly one more label (`a.example.com`, but not
/// `example.com` or `a.b.example.com`). A pattern or name without a port
/// matches any port, as rmcp's own check does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowedHosts {
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Entry {
    Exact { host: String, port: Option<u16> },
    OneLabel { suffix: String, port: Option<u16> },
}

/// A `Host` header value, lowercased, IPv6 brackets removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHost {
    /// The host name or address.
    pub host: String,
    /// The port, when the header names one.
    pub port: Option<u16>,
}

impl RequestHost {
    /// The request's `Host`, if it is present and well formed.
    #[must_use]
    pub fn from_headers(headers: &HeaderMap) -> Option<Self> {
        let value = headers.get(header::HOST)?.to_str().ok()?;
        let authority = axum::http::uri::Authority::try_from(value.trim()).ok()?;
        let host = authority
            .host()
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        (!host.is_empty()).then_some(Self {
            host,
            port: authority.port_u16(),
        })
    }

    /// `host[:port]` as it appears in a URL authority.
    #[must_use]
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        self.port
            .map_or_else(|| host.clone(), |port| format!("{host}:{port}"))
    }
}

fn split_port(value: &str) -> (String, Option<u16>) {
    if let Ok(authority) = axum::http::uri::Authority::try_from(value) {
        return (
            authority
                .host()
                .trim_matches(['[', ']'])
                .to_ascii_lowercase(),
            authority.port_u16(),
        );
    }
    (value.to_ascii_lowercase(), None)
}

impl AllowedHosts {
    /// Parses names and `*.` patterns; blank entries are skipped.
    #[must_use]
    pub fn new<'a>(values: impl IntoIterator<Item = &'a str>) -> Self {
        let entries = values
            .into_iter()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.strip_prefix("*.").map_or_else(
                    || {
                        let (host, port) = split_port(value);
                        Entry::Exact { host, port }
                    },
                    |rest| {
                        let (suffix, port) = split_port(rest);
                        Entry::OneLabel { suffix, port }
                    },
                )
            })
            .collect();
        Self { entries }
    }

    /// Whether a pattern is present.
    #[must_use]
    pub fn has_patterns(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry, Entry::OneLabel { .. }))
    }

    /// Whether `host` is allowed.
    #[must_use]
    pub fn allows(&self, host: &RequestHost) -> bool {
        let port_matches = |port: &Option<u16>| port.is_none_or(|port| host.port == Some(port));
        self.entries.iter().any(|entry| match entry {
            Entry::Exact { host: name, port } => *name == host.host && port_matches(port),
            Entry::OneLabel { suffix, port } => {
                port_matches(port)
                    && host
                        .host
                        .strip_suffix(suffix.as_str())
                        .and_then(|label| label.strip_suffix('.'))
                        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn host(value: &str) -> RequestHost {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::HOST,
            HeaderValue::from_str(value).unwrap_or_else(|err| unreachable!("{err}")),
        );
        RequestHost::from_headers(&headers).unwrap_or_else(|| unreachable!("{value}"))
    }

    #[test]
    fn a_pattern_matches_exactly_one_label() {
        let allowed = AllowedHosts::new(["mail.example.com", "*.mcp.example.com"]);
        assert!(allowed.has_patterns());
        assert!(allowed.allows(&host("mail.example.com")));
        assert!(allowed.allows(&host("MAIL.example.com:8443")));
        assert!(allowed.allows(&host("acme.mcp.example.com")));
        assert!(allowed.allows(&host("acme.mcp.example.com:443")));
        assert!(!allowed.allows(&host("mcp.example.com")));
        assert!(!allowed.allows(&host("a.b.mcp.example.com")));
        assert!(!allowed.allows(&host("acmemcp.example.com")));
        assert!(!allowed.allows(&host("acme.mcp.example.com.evil.test")));
        assert!(!allowed.allows(&host("other.example.com")));
    }

    #[test]
    fn ports_are_compared_when_the_entry_names_one() {
        let allowed = AllowedHosts::new(["localhost:8080", "*.dev.test:9000", "[::1]"]);
        assert!(allowed.allows(&host("localhost:8080")));
        assert!(!allowed.allows(&host("localhost:8081")));
        assert!(!allowed.allows(&host("localhost")));
        assert!(allowed.allows(&host("a.dev.test:9000")));
        assert!(!allowed.allows(&host("a.dev.test")));
        assert!(allowed.allows(&host("[::1]:3000")));
        assert_eq!(host("[::1]:3000").authority(), "[::1]:3000");
        assert_eq!(host("A.Dev.Test:9000").authority(), "a.dev.test:9000");
    }

    #[test]
    fn missing_or_malformed_hosts_are_none() {
        assert_eq!(RequestHost::from_headers(&HeaderMap::new()), None);
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("bad host"));
        assert_eq!(RequestHost::from_headers(&headers), None);
    }
}
