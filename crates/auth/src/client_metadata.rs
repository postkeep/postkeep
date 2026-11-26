//! OAuth Client ID Metadata Documents
//! (draft-ietf-oauth-client-id-metadata-document).
//!
//! A client whose `client_id` is an `https` URL publishes its metadata at
//! that URL instead of registering. The document is fetched with the
//! webhook crate's client: only public addresses, the address pinned after
//! the lookup, no redirects followed, at most 64 KiB, 5 seconds. It must
//! name the same `client_id`, list its redirect URIs and be a public client.
//! A valid document is stored as a client with that ID, so grants and codes
//! refer to it like any other, and is fetched again once its cache lifetime
//! (`Cache-Control: max-age`, clamped to 5 minutes to 24 hours) has passed.
//! Errors and invalid documents are never cached.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, StatusCode, header};
use postkeep_store::{Client, Store, StoreError};
use postkeep_webhook::{Deliverer, FetchError, WebhookUrl};
use serde::Deserialize;

use crate::redirect;
use crate::register::{MAX_REDIRECT_URIS, sanitize_client_name};

/// Time allowed for fetching a document.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest document read, in bytes.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// Shortest time a document is reused before it is fetched again.
pub const MIN_CACHE: Duration = Duration::from_mins(5);

/// Longest time a document is reused before it is fetched again.
pub const MAX_CACHE: Duration = Duration::from_hours(24);

/// Documents remembered as fresh before expired entries are dropped.
const MAX_CACHE_ENTRIES: usize = 10_000;

/// Whether `client_id` names a metadata document rather than a registered
/// client. Generated client IDs never start with `https://`.
#[must_use]
pub fn is_document_url(client_id: &str) -> bool {
    client_id.starts_with("https://")
}

/// Why a metadata document client could not be used. The messages are
/// shown on the sign-in error page and never repeat the document.
#[derive(Debug, thiserror::Error)]
pub enum MetadataError {
    /// The URL breaks the rules for a client ID URL.
    #[error("its client_id is not a valid metadata document address ({0})")]
    InvalidUrl(&'static str),
    /// The fetch failed before a response, or took too long.
    #[error("its metadata document could not be fetched: {0}")]
    Fetch(String),
    /// The address answered with a redirect, which is not followed.
    #[error("its metadata document address redirects, and redirects are not followed")]
    Redirect,
    /// The address answered with another status than 200.
    #[error("its metadata document address answered with HTTP {0}")]
    Status(u16),
    /// The document is larger than [`MAX_DOCUMENT_BYTES`].
    #[error("its metadata document is larger than 64 KiB")]
    TooLarge,
    /// The document is not a valid client metadata document.
    #[error("its metadata document is not valid: {0}")]
    Invalid(&'static str),
    /// The server's client limit is reached.
    #[error("this server is not accepting new apps right now")]
    Full,
    /// Too many new clients from this network, as for registration.
    #[error("too many new apps were added from your network; try again later")]
    TooManyNew,
    /// The database failed.
    #[error("the server could not store it")]
    Store(#[from] StoreError),
}

/// The fields of a document this server reads.
#[derive(Debug, Deserialize)]
struct Document {
    client_id: Option<String>,
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[expect(clippy::option_option, reason = "a null method is not a missing one")]
    #[serde(default, deserialize_with = "present")]
    token_endpoint_auth_method: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    client_secret: Option<serde_json::Value>,
    client_secret_expires_at: Option<serde_json::Value>,
}

/// Reads a present field as `Some`, so that `null` is not read as a missing
/// field: it is refused where `T` is a list and kept as `Some(None)` where
/// `T` is an `Option`.
fn present<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
}

/// Checks the client ID URL itself, before anything is fetched.
///
/// The URL must already be in normal form (no `.` or `..` segments, no
/// default port, lowercase scheme and host), because client IDs are
/// compared as plain strings and the document must name the exact URL
/// that was fetched.
fn parse_client_id(client_id: &str) -> Result<WebhookUrl, MetadataError> {
    let parsed = url::Url::parse(client_id).map_err(|_| MetadataError::InvalidUrl("not a URL"))?;
    if parsed.fragment().is_some() {
        return Err(MetadataError::InvalidUrl("it has a fragment"));
    }
    if parsed.as_str() != client_id {
        return Err(MetadataError::InvalidUrl("it is not in normal form"));
    }
    WebhookUrl::parse(client_id).map_err(|err| match err {
        postkeep_webhook::TargetError::Blocked => {
            MetadataError::InvalidUrl("private and local addresses are not fetched")
        }
        postkeep_webhook::TargetError::Credentials => {
            MetadataError::InvalidUrl("it contains a user name or password")
        }
        postkeep_webhook::TargetError::TooLong => MetadataError::InvalidUrl("it is too long"),
        _ => MetadataError::InvalidUrl("it must be an https URL"),
    })
}

/// How long a document stays fresh: `max-age` clamped to
/// [`MIN_CACHE`]..=[`MAX_CACHE`], and [`MIN_CACHE`] without one or with
/// `no-cache` or `no-store`.
fn cache_lifetime(headers: &HeaderMap) -> Duration {
    let mut max_age = None;
    for value in headers.get_all(header::CACHE_CONTROL) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for directive in value.split(',').map(str::trim) {
            let lower = directive.to_ascii_lowercase();
            if lower == "no-store" || lower == "no-cache" {
                return MIN_CACHE;
            }
            if let Some(seconds) = lower.strip_prefix("max-age=") {
                max_age = seconds.trim_matches('"').parse::<u64>().ok();
            }
        }
    }
    max_age.map_or(MIN_CACHE, |seconds| {
        Duration::from_secs(seconds).clamp(MIN_CACHE, MAX_CACHE)
    })
}

/// The name and redirect URIs of a valid document for `client_id`.
fn validate(
    document: Document,
    client_id: &str,
) -> Result<(Option<String>, Vec<String>), MetadataError> {
    if document.client_id.as_deref() != Some(client_id) {
        return Err(MetadataError::Invalid(
            "its client_id is not the address it was fetched from",
        ));
    }
    if document.client_secret.is_some() || document.client_secret_expires_at.is_some() {
        return Err(MetadataError::Invalid(
            "it must not contain a client_secret",
        ));
    }
    // A shared secret cannot be published, and private_key_jwt is not
    // supported, so only public clients (PKCE) are accepted. A client that
    // lists the methods it can use (draft-03 section 5) must list none, and
    // a single method it also gives, even null, must be one of them.
    let preferred = document
        .token_endpoint_auth_method
        .as_ref()
        .map(Option::as_deref);
    if let Some(methods) = &document.token_endpoint_auth_methods_supported {
        if let Some(preferred) = preferred
            && !methods
                .iter()
                .any(|method| Some(method.as_str()) == preferred)
        {
            return Err(MetadataError::Invalid(
                "token_endpoint_auth_method is not in token_endpoint_auth_methods_supported",
            ));
        }
        if methods
            .iter()
            .any(|method| method.starts_with("client_secret_"))
        {
            return Err(MetadataError::Invalid(
                "token_endpoint_auth_methods_supported must not list a client secret method",
            ));
        }
        if !methods.iter().any(|method| method == "none") {
            return Err(MetadataError::Invalid(
                "token_endpoint_auth_methods_supported must include none",
            ));
        }
    } else if !matches!(preferred, None | Some(None | Some("none"))) {
        return Err(MetadataError::Invalid(
            "token_endpoint_auth_method must be none",
        ));
    }
    if document
        .grant_types
        .is_some_and(|grants| !grants.iter().any(|grant| grant == "authorization_code"))
    {
        return Err(MetadataError::Invalid(
            "grant_types must include authorization_code",
        ));
    }
    if document
        .response_types
        .is_some_and(|types| !types.iter().any(|kind| kind == "code"))
    {
        return Err(MetadataError::Invalid("response_types must include code"));
    }
    if document.redirect_uris.is_empty() {
        return Err(MetadataError::Invalid("it has no redirect_uris"));
    }
    if document.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(MetadataError::Invalid("it has too many redirect_uris"));
    }
    if document
        .redirect_uris
        .iter()
        .any(|uri| redirect::validate(uri).is_err())
    {
        return Err(MetadataError::Invalid("a redirect_uri is not allowed"));
    }
    let name = document
        .client_name
        .as_deref()
        .map(sanitize_client_name)
        .filter(|name| !name.is_empty());
    Ok((name, document.redirect_uris))
}

/// When each document stored last stops being fresh.
#[derive(Debug, Default)]
struct Freshness {
    until: HashMap<String, Instant>,
}

impl Freshness {
    fn is_fresh(&self, client_id: &str, now: Instant) -> bool {
        self.until.get(client_id).is_some_and(|until| now < *until)
    }

    fn remember(&mut self, client_id: &str, now: Instant, lifetime: Duration) {
        if self.until.len() >= MAX_CACHE_ENTRIES {
            self.until.retain(|_, until| now < *until);
        }
        self.until.insert(client_id.to_owned(), now + lifetime);
    }
}

/// Fetches, checks, stores and caches metadata document clients.
pub struct MetadataClients {
    deliverer: RwLock<Deliverer>,
    freshness: Mutex<Freshness>,
}

impl std::fmt::Debug for MetadataClients {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetadataClients").finish_non_exhaustive()
    }
}

impl MetadataClients {
    /// Fetches documents with `deliverer`.
    pub fn new(deliverer: Deliverer) -> Self {
        Self {
            deliverer: RwLock::new(deliverer),
            freshness: Mutex::new(Freshness::default()),
        }
    }

    /// Replaces the HTTPS client.
    pub fn set_deliverer(&self, deliverer: Deliverer) {
        *self
            .deliverer
            .write()
            .unwrap_or_else(PoisonError::into_inner) = deliverer;
    }

    /// The client for `client_id`: the stored one while its document is
    /// fresh, otherwise the document is fetched, checked and stored again.
    /// `may_add` is asked only before a client that is not stored yet is
    /// added, so the per-network registration limit applies to new ones.
    ///
    /// # Errors
    ///
    /// Returns a [`MetadataError`] if the URL, the fetch or the document is
    /// refused, a limit is reached or the database fails.
    pub async fn resolve(
        &self,
        store: &Store,
        max_clients: u64,
        client_id: &str,
        may_add: impl FnOnce() -> bool,
    ) -> Result<Client, MetadataError> {
        let url = parse_client_id(client_id)?;
        let fresh = self
            .freshness
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_fresh(client_id, Instant::now());
        if fresh && let Some(client) = store.client(client_id).await? {
            return Ok(client);
        }
        let deliverer = self
            .deliverer
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let fetched = deliverer
            .fetch(&url, MAX_DOCUMENT_BYTES, FETCH_TIMEOUT)
            .await
            .map_err(|err| match err {
                FetchError::TooLarge { .. } => MetadataError::TooLarge,
                other => MetadataError::Fetch(other.to_string()),
            })?;
        if fetched.status.is_redirection() {
            return Err(MetadataError::Redirect);
        }
        if fetched.status != StatusCode::OK {
            return Err(MetadataError::Status(fetched.status.as_u16()));
        }
        let document: Document = serde_json::from_slice(&fetched.body).map_err(|_| {
            MetadataError::Invalid("it is not a JSON object with the expected fields")
        })?;
        let (name, redirect_uris) = validate(document, client_id)?;
        if store.client(client_id).await?.is_none() {
            if store.client_count().await? >= max_clients {
                return Err(MetadataError::Full);
            }
            if !may_add() {
                return Err(MetadataError::TooManyNew);
            }
        }
        let client = store
            .upsert_metadata_client(client_id, name.as_deref(), &redirect_uris)
            .await?;
        self.freshness
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remember(client_id, Instant::now(), cache_lifetime(&fetched.headers));
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn document(value: serde_json::Value) -> Document {
        serde_json::from_value(value).unwrap_or_else(|err| unreachable!("{err}"))
    }

    const ID: &str = "https://app.example.com/oauth/client.json";

    #[test]
    fn client_id_urls_must_be_https_public_and_in_normal_form() {
        assert!(parse_client_id(ID).is_ok());
        for bad in [
            "http://app.example.com/client.json",
            "https://app.example.com/client.json#x",
            "https://user:pw@app.example.com/client.json",
            "https://10.0.0.1/client.json",
            "https://169.254.169.254/latest",
            "https://[fdaa::3]/client.json",
            "https://localhost/client.json",
            "https://app.internal/client.json",
            "https://app.example.com/a/../client.json",
            "https://app.example.com/./client.json",
            "https://app.example.com:443/client.json",
            "https://APP.example.com/client.json",
            "not a url",
        ] {
            assert!(
                matches!(parse_client_id(bad), Err(MetadataError::InvalidUrl(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn cache_lifetime_follows_max_age_within_bounds() {
        let headers = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CACHE_CONTROL,
                HeaderValue::from_str(value).unwrap_or_else(|err| unreachable!("{err}")),
            );
            headers
        };
        assert_eq!(cache_lifetime(&HeaderMap::new()), MIN_CACHE);
        assert_eq!(cache_lifetime(&headers("max-age=0")), MIN_CACHE);
        assert_eq!(
            cache_lifetime(&headers("public, max-age=3600")),
            Duration::from_hours(1)
        );
        assert_eq!(cache_lifetime(&headers("max-age=31536000")), MAX_CACHE);
        assert_eq!(
            cache_lifetime(&headers("max-age=3600, no-store")),
            MIN_CACHE
        );
        assert_eq!(cache_lifetime(&headers("no-cache")), MIN_CACHE);
        assert_eq!(cache_lifetime(&headers("max-age=nonsense")), MIN_CACHE);
    }

    #[test]
    fn a_cached_document_expires_after_its_lifetime() {
        let mut freshness = Freshness::default();
        let start = Instant::now();
        assert!(!freshness.is_fresh(ID, start));
        freshness.remember(ID, start, MIN_CACHE);
        assert!(freshness.is_fresh(ID, start + Duration::from_secs(299)));
        assert!(!freshness.is_fresh(ID, start + MIN_CACHE));
        assert!(!freshness.is_fresh("https://other.example.com/c", start));
    }

    #[test]
    fn documents_must_match_and_be_public_clients() {
        let valid = serde_json::json!({
            "client_id": ID,
            "client_name": "Example \u{202E}App",
            "redirect_uris": ["https://app.example.com/callback", "http://127.0.0.1/cb"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"]
        });
        let (name, uris) =
            validate(document(valid.clone()), ID).unwrap_or_else(|err| unreachable!("{err}"));
        assert_eq!(name.as_deref(), Some("Example App"));
        assert_eq!(uris.len(), 2);

        let refused = |patch: serde_json::Value| {
            let mut value = valid.clone();
            for (key, field) in patch.as_object().into_iter().flatten() {
                value[key] = field.clone();
            }
            validate(document(value), ID).is_err()
        };
        assert!(refused(
            serde_json::json!({ "client_id": "https://evil.example.com/c.json" })
        ));
        assert!(refused(
            serde_json::json!({ "client_id": format!("{ID}/") })
        ));
        assert!(refused(serde_json::json!({ "client_id": null })));
        assert!(refused(serde_json::json!({ "client_secret": "s3cret" })));
        assert!(refused(
            serde_json::json!({ "token_endpoint_auth_method": "client_secret_basic" })
        ));
        assert!(refused(
            serde_json::json!({ "token_endpoint_auth_method": "private_key_jwt" })
        ));
        // Without a list, the single method must be none, null or missing.
        assert!(!refused(
            serde_json::json!({ "token_endpoint_auth_method": "none" })
        ));
        assert!(!refused(
            serde_json::json!({ "token_endpoint_auth_method": null })
        ));
        // With the list of methods a client can use (draft-03 section 5),
        // the single method is only its preference, as in ChatGPT's document.
        assert!(!refused(serde_json::json!({
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "token_endpoint_auth_method": "private_key_jwt"
        })));
        assert!(!refused(serde_json::json!({
            "token_endpoint_auth_methods_supported": ["private_key_jwt", "none"]
        })));
        for patch in [
            serde_json::json!({ "token_endpoint_auth_methods_supported": [] }),
            serde_json::json!({ "token_endpoint_auth_methods_supported": ["private_key_jwt"] }),
            serde_json::json!({
                "token_endpoint_auth_methods_supported": ["none"],
                "token_endpoint_auth_method": "private_key_jwt"
            }),
            serde_json::json!({
                "token_endpoint_auth_methods_supported": ["none"],
                "token_endpoint_auth_method": null
            }),
            serde_json::json!({
                "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"]
            }),
        ] {
            assert!(refused(patch.clone()), "{patch}");
        }
        // A list that is null or not a list is refused, never read as missing.
        for malformed in [
            serde_json::Value::Null,
            serde_json::json!("none"),
            serde_json::json!(["none", null]),
        ] {
            let field = serde_json::json!({ "token_endpoint_auth_methods_supported": malformed });
            assert!(
                serde_json::from_value::<Document>(field).is_err(),
                "{malformed}"
            );
        }
        assert!(refused(serde_json::json!({ "redirect_uris": [] })));
        assert!(refused(
            serde_json::json!({ "redirect_uris": ["javascript:alert(1)"] })
        ));
        assert!(refused(
            serde_json::json!({ "grant_types": ["client_credentials"] })
        ));
        assert!(refused(serde_json::json!({ "response_types": ["token"] })));
    }
}
