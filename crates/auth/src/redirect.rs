//! Redirect URI validation (RFC 6749 section 3.1.2, RFC 8252).

use url::Url;

/// Schemes that must never be used as redirect targets.
///
/// Browser and OS handlers are not native-app redirects. Some embed a URL
/// after the scheme (`microsoft-edge:https://...`, `intent:`). Others name
/// the browser in the scheme and put the target in the authority, and the
/// OS opens that host in a browser: Chrome for iOS uses `googlechromes://`
/// (the https form of `googlechrome`), and Safari on macOS and iOS uses
/// `x-safari-https://` and `x-safari-http://`. [`scheme_forbidden`] rejects
/// that whole family, not only the names in this list.
const FORBIDDEN_SCHEMES: &[&str] = &[
    "javascript",
    "data",
    "file",
    "vbscript",
    "blob",
    "about",
    "microsoft-edge",
    "microsoft-edge-holographic",
    "googlechrome",
    "firefox",
    "opera",
    "brave",
    "intent",
    "ftp",
    "ftps",
    "ws",
    "wss",
    "mailto",
    "tel",
    "sms",
    "news",
    "nntp",
    "gopher",
    "ldap",
    "smb",
    "ssh",
    "telnet",
    "irc",
    "market",
    "itms",
    "itms-apps",
    "shell",
];

/// Whether `scheme` is a browser, network, or OS handler rather than a
/// private-use app scheme.
///
/// `http` and `https` themselves are not forbidden; callers allow `https`
/// anywhere and `http` only on loopback. Any other scheme whose name
/// contains `http` is rejected (`x-safari-https`, `opera-http`), as are
/// `ms-*`, `microsoft-edge*`, `googlechrome*` (including `googlechromes`),
/// `firefox*`, `opera*`, `brave*` and `x-safari-*`.
pub fn scheme_forbidden(scheme: &str) -> bool {
    let scheme = scheme.to_ascii_lowercase();
    if scheme == "http" || scheme == "https" {
        return false;
    }
    FORBIDDEN_SCHEMES.contains(&scheme.as_str())
        || scheme.starts_with("ms-")
        || scheme.starts_with("microsoft-edge")
        || scheme.starts_with("googlechrome")
        || scheme.starts_with("firefox")
        || scheme.starts_with("opera")
        || scheme.starts_with("brave")
        || scheme.starts_with("x-safari-")
        || scheme.contains("http")
}

/// Whether the part after `scheme:` embeds another URL (`http:` or `https:`).
///
/// `microsoft-edge:https://evil.example/phish` has scheme `microsoft-edge`
/// and no host, but the OS still hands the embedded URL to a browser.
fn embeds_url(uri: &str, scheme: &str) -> bool {
    let Some(rest) = uri.get(scheme.len().saturating_add(1)..) else {
        return false;
    };
    let rest = rest.to_ascii_lowercase();
    rest.contains("https:") || rest.contains("http:")
}

/// Checks a redirect URI at registration time.
///
/// Accepts `https` URLs, `http` URLs on a loopback host (for native apps),
/// and private-use schemes such as `com.example.app:/callback`,
/// `cursor://...`, `vscode://...` and `claude://...`. Fragments are never
/// allowed.
///
/// Whitespace and control characters are refused outright: the URL parser
/// silently drops tabs and line breaks, so `https://a.example/cb\njavascript:x`
/// would otherwise validate as one URI, and registered URIs are stored one
/// per line, where it would come back as two, the second never checked.
pub fn validate(uri: &str) -> Result<Url, String> {
    if uri.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(format!(
            "{}: whitespace and control characters are not allowed",
            uri.escape_debug()
        ));
    }
    let url = Url::parse(uri).map_err(|err| format!("{uri}: {err}"))?;
    if url.fragment().is_some() {
        return Err(format!("{uri}: fragments are not allowed"));
    }
    match url.scheme() {
        "https" => {
            if url.host().is_none() {
                return Err(format!("{uri}: a host is required"));
            }
        }
        "http" => {
            if !is_loopback(&url) {
                return Err(format!(
                    "{uri}: http is only allowed for loopback addresses"
                ));
            }
        }
        scheme if scheme_forbidden(scheme) => {
            return Err(format!("{uri}: the {scheme} scheme is not allowed"));
        }
        scheme if embeds_url(uri, scheme) => {
            return Err(format!(
                "{uri}: a non-http redirect must not embed another URL"
            ));
        }
        _ => {}
    }
    Ok(url)
}

/// Whether `requested` matches one of the registered redirect URIs.
///
/// Matching is exact, except that the port of an `http` loopback URI may
/// differ, as RFC 8252 section 7.3 requires for native apps.
pub fn matches(registered: &[String], requested: &str) -> bool {
    if registered.iter().any(|uri| uri == requested) {
        return true;
    }
    let Ok(requested) = Url::parse(requested) else {
        return false;
    };
    if requested.scheme() != "http" || !is_loopback(&requested) {
        return false;
    }
    registered
        .iter()
        .filter_map(|uri| Url::parse(uri).ok())
        .any(|uri| {
            uri.scheme() == "http"
                && is_loopback(&uri)
                && uri.host() == requested.host()
                && uri.path() == requested.path()
                && uri.query() == requested.query()
        })
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Whether `uri` points at a web site: `https`, or `http` on a host that is
/// not loopback. Loopback and private-use scheme URIs reach a native app on
/// the user's own device instead.
///
/// Browser and OS handler schemes, including scheme-replacement forms such
/// as `googlechromes://` and `x-safari-https://`, are treated as web targets
/// so errors and codes are not redirected there, even for a client
/// registered before the scheme was rejected.
pub fn is_web(uri: &str) -> bool {
    let Ok(url) = Url::parse(uri) else {
        return true;
    };
    match url.scheme() {
        "https" => true,
        "http" => !is_loopback(&url),
        scheme if scheme_forbidden(scheme) || embeds_url(uri, scheme) => true,
        _ => false,
    }
}

/// Builds the redirect back to the client with the given query parameters.
pub fn with_params(redirect_uri: &str, params: &[(&str, &str)]) -> Option<String> {
    let mut url = Url::parse(redirect_uri).ok()?;
    {
        let mut query = url.query_pairs_mut();
        for (name, value) in params {
            query.append_pair(name, value);
        }
    }
    Some(url.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_registration() {
        for ok in [
            "https://client.example/cb",
            "http://127.0.0.1:3000/callback",
            "http://localhost/callback",
            "http://[::1]:8080/cb",
            "cursor://anysphere.cursor-retrieval/oauth/callback",
            "vscode://vscode.git/oauth/callback",
            "claude://anthropic.claude/oauth/callback",
            "com.example.app:/oauth",
        ] {
            assert!(validate(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://client.example/cb",
            "https://client.example/cb#frag",
            "javascript:alert(1)",
            "data:text/html,hi",
            "/relative",
            "https://client.example/cb\njavascript:alert(1)",
            "https://client.example/cb\r\nhttp://evil.example/cb",
            "https://client.example/c\tb",
            "https://client.example/cb ",
            "microsoft-edge:https://evil.example/phish",
            "microsoft-edge-holographic:https://evil.example/phish",
            "microsoft-edge-dev:https://evil.example/phish",
            "googlechrome:https://evil.example/phish",
            "googlechromes://evil.example/cb",
            "googlechrome-ios://evil.example/cb",
            "GoogleChromes://evil.example/cb",
            "firefox:https://evil.example/phish",
            "firefox-private://evil.example/cb",
            "opera:https://evil.example/phish",
            "opera-http://evil.example/cb",
            "brave:https://evil.example/phish",
            "brave-browser://evil.example/cb",
            "x-safari-https://evil.example/cb",
            "x-safari-http://evil.example/cb",
            "x-safari-custom://evil.example/cb",
            "myhttpapp://evil.example/cb",
            "intent:https://evil.example/phish#Intent;scheme=https;end",
            "ftp://files.example/cb",
            "ftps://files.example/cb",
            "ws://127.0.0.1/cb",
            "wss://client.example/cb",
            "mailto:user@example.com",
            "tel:+15555550100",
            "sms:+15555550100",
            "news:comp.lang.rust",
            "nntp://news.example/rust",
            "gopher://gopher.example/1",
            "ldap://ldap.example/dc=example",
            "smb://files.example/share",
            "ssh://shell.example/",
            "telnet://shell.example/",
            "irc://irc.example/room",
            "market://details?id=com.example.app",
            "itms://apps.example/app",
            "itms-apps://apps.example/app",
            "shell:startup",
            "ms-settings:network",
            "ms-word:ofe|u|https://evil.example/doc",
            // A private-use scheme that smuggles a browser URL.
            "com.example.app:https://evil.example/phish",
            "cursor://anysphere.cursor-retrieval/oauth/callback?next=https://evil.example",
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn matches_exactly_or_with_any_loopback_port() {
        let registered = vec![
            "https://client.example/cb".to_owned(),
            "http://127.0.0.1/callback".to_owned(),
        ];
        assert!(matches(&registered, "https://client.example/cb"));
        assert!(!matches(&registered, "https://client.example/cb2"));
        assert!(!matches(&registered, "https://client.example:8443/cb"));
        assert!(matches(&registered, "http://127.0.0.1:51234/callback"));
        assert!(!matches(&registered, "http://127.0.0.1:51234/other"));
        assert!(!matches(&registered, "http://localhost:51234/callback"));
    }

    #[test]
    fn tells_web_sites_from_native_apps() {
        assert!(is_web("https://client.example/cb"));
        assert!(is_web("http://client.example/cb"));
        assert!(is_web("not a url"));
        assert!(!is_web("http://127.0.0.1:3000/callback"));
        assert!(!is_web("http://[::1]/cb"));
        assert!(!is_web(
            "cursor://anysphere.cursor-retrieval/oauth/callback"
        ));
        assert!(!is_web("com.example.app:/oauth"));
        assert!(!is_web("vscode://vscode.git/oauth/callback"));
        assert!(!is_web("claude://anthropic.claude/oauth/callback"));
        // Handler schemes must not receive a 303 with the code or error.
        assert!(is_web("microsoft-edge:https://evil.example/phish"));
        assert!(is_web("googlechromes://evil.example/cb"));
        assert!(is_web("x-safari-https://evil.example/cb"));
        assert!(is_web("x-safari-http://evil.example/cb"));
        assert!(is_web("opera-http://evil.example/cb"));
        assert!(is_web("firefox-private://evil.example/cb"));
        assert!(is_web("ftp://files.example/cb"));
        assert!(is_web("ms-settings:network"));
        assert!(is_web("com.example.app:https://evil.example/phish"));
    }

    #[test]
    fn rejects_scheme_replacement_browser_handlers() {
        assert!(!scheme_forbidden("http"));
        assert!(!scheme_forbidden("https"));
        assert!(!scheme_forbidden("HTTPS"));
        for bad in [
            "googlechromes://evil.example/cb",
            "googlechrome-ios://evil.example/cb",
            "GoogleChromes://evil.example/cb",
            "firefox-private://evil.example/cb",
            "opera-http://evil.example/cb",
            "brave-browser://evil.example/cb",
            "x-safari-https://evil.example/cb",
            "x-safari-http://evil.example/cb",
            "x-safari-custom://evil.example/cb",
            "myhttpapp://evil.example/cb",
        ] {
            let err = validate(bad).map_or_else(|err| err, |url| format!("accepted {url}"));
            assert!(
                err.contains("not allowed"),
                "{bad} should fail the scheme guard, got {err}"
            );
            assert!(is_web(bad), "{bad}");
        }
        for ok in [
            "https://client.example/cb",
            "http://127.0.0.1:3000/callback",
            "http://localhost/callback",
            "http://[::1]/cb",
            "com.example.app:/cb",
            "cursor://anysphere.cursor-retrieval/oauth/callback",
            "vscode://vscode.git/oauth/callback",
            "claude://anthropic.claude/oauth/callback",
        ] {
            assert!(validate(ok).is_ok(), "{ok}");
        }
    }

    #[test]
    fn appends_query_parameters() {
        let url = with_params(
            "https://c.example/cb?x=1",
            &[("code", "a b"), ("state", "s")],
        )
        .unwrap();
        assert_eq!(url, "https://c.example/cb?x=1&code=a+b&state=s");
    }
}
