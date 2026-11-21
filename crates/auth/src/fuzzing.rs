//! Entry points for the `cargo-fuzz` targets in `fuzz/`.
//!
//! Only compiled with the `fuzzing` feature.

#![allow(clippy::missing_panics_doc, clippy::panic, clippy::expect_used)]

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

use crate::{client_ip, random, redirect, token};

/// Redirect URIs from client registration and authorization requests.
pub fn redirect_uri(registered: &str, requested: &str, state: &str) {
    if let Ok(url) = redirect::validate(registered) {
        assert!(url.fragment().is_none());
        // Registered URIs are stored one per line.
        assert_eq!(registered.lines().count(), 1, "{registered:?}");
        assert!(
            !redirect::scheme_forbidden(url.scheme()),
            "forbidden scheme accepted: {url}"
        );
        if url.scheme() != "http" && url.scheme() != "https" {
            let rest = registered
                .get(url.scheme().len().saturating_add(1)..)
                .unwrap_or("");
            let rest = rest.to_ascii_lowercase();
            assert!(
                !rest.contains("https:") && !rest.contains("http:"),
                "embedded URL accepted: {registered:?}"
            );
        }
        if url.scheme() == "http" {
            assert!(
                matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
                    || url.host_str().is_some_and(|host| host.starts_with("127.")),
                "{url}"
            );
        }
        let registered = vec![registered.to_owned()];
        if redirect::matches(&registered, requested) {
            // A match never moves the redirect to another host or scheme.
            let requested = url::Url::parse(requested).ok();
            if let Some(requested) = requested {
                assert_eq!(requested.scheme(), url.scheme());
                assert_eq!(requested.host_str(), url.host_str());
            }
        }
        // Parameters are appended without changing where the URI points.
        if let Some(back) = redirect::with_params(url.as_str(), &[("state", state), ("code", "c")])
        {
            let back = url::Url::parse(&back).expect("redirect stays a valid URL");
            assert_eq!(back.scheme(), url.scheme());
            assert_eq!(back.host_str(), url.host_str());
            assert_eq!(back.path(), url.path());
            assert!(back.query_pairs().any(|(k, v)| k == "state" && v == state));
        }
    }
}

/// Client IP headers set by a proxy (or forged by a client).
pub fn client_ip(value: &[u8]) {
    let Ok(value) = HeaderValue::from_bytes(value) else {
        return;
    };
    let name = HeaderName::from_static("x-forwarded-for");
    let mut headers = HeaderMap::new();
    headers.insert(name.clone(), value);
    let peer = Some(std::net::IpAddr::from([192, 0, 2, 1]));
    let resolved = client_ip::resolve(&headers, Some(&name), peer);
    assert!(resolved.is_some());
    let _ = resolved.map(crate::limits::ip_key);
}

/// `Authorization: Basic` client credentials and PKCE verifiers.
pub fn client_credentials(value: &[u8], verifier: &str, challenge: &str) {
    if let Ok(value) = HeaderValue::from_bytes(value) {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, value);
        let _ = token::basic_credentials(&headers);
    }
    if random::verify_pkce(verifier, challenge) {
        assert!(random::valid_challenge(challenge));
    }
}
