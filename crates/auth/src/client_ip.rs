//! Working out the client's IP address for per-client limits.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName};

use crate::state::AuthState;

/// The client's IP address, if known. Extracted from the header named in
/// [`AuthConfig::client_ip_header`](crate::AuthConfig::client_ip_header)
/// when one is configured (behind a reverse proxy), otherwise from the TCP
/// peer address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub Option<IpAddr>);

impl ClientIp {
    /// The key for per-client limits.
    pub fn key(self) -> String {
        self.0
            .map_or_else(|| "unknown".to_owned(), crate::limits::ip_key)
    }
}

impl FromRequestParts<AuthState> for ClientIp {
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        std::future::ready(Ok(Self(resolve(
            &parts.headers,
            state.config().client_ip_header.as_ref(),
            peer,
        ))))
    }
}

/// Picks the client address from `header` if configured and parseable,
/// falling back to the peer address.
///
/// For `X-Forwarded-For` the last entry is used: it was added by the
/// trusted proxy in front of this server, while earlier entries can be
/// forged by the client.
pub fn resolve(
    headers: &HeaderMap,
    header: Option<&HeaderName>,
    peer: Option<IpAddr>,
) -> Option<IpAddr> {
    header
        .and_then(|name| headers.get_all(name).iter().next_back())
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .and_then(parse_ip)
        .or(peer)
}

/// Parses an address, tolerating a port and IPv6 brackets.
fn parse_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim();
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .or_else(|| {
            value
                .strip_prefix('[')
                .and_then(|rest| rest.split_once(']'))
                .and_then(|(ip, _)| ip.parse().ok())
        })
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn uses_peer_without_configured_header() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.1"));
        let peer = Some("10.0.0.1".parse().unwrap());
        assert_eq!(resolve(&headers, None, peer), peer);
    }

    #[test]
    fn uses_last_forwarded_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 203.0.113.7"),
        );
        let name = HeaderName::from_static("x-forwarded-for");
        assert_eq!(
            resolve(&headers, Some(&name), None),
            Some("203.0.113.7".parse().unwrap())
        );
    }

    #[test]
    fn parses_single_value_headers_and_ports() {
        let name = HeaderName::from_static("fly-client-ip");
        for (value, expected) in [
            ("2001:db8::1", "2001:db8::1"),
            ("203.0.113.9:4711", "203.0.113.9"),
            ("[2001:db8::2]:443", "2001:db8::2"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(name.clone(), HeaderValue::from_static(value));
            assert_eq!(
                resolve(&headers, Some(&name), None),
                Some(expected.parse().unwrap()),
                "{value}"
            );
        }
    }

    #[test]
    fn falls_back_to_peer_on_garbage() {
        let name = HeaderName::from_static("fly-client-ip");
        let mut headers = HeaderMap::new();
        headers.insert(name.clone(), HeaderValue::from_static("not an ip"));
        let peer = Some("10.0.0.1".parse().unwrap());
        assert_eq!(resolve(&headers, Some(&name), peer), peer);
    }
}
