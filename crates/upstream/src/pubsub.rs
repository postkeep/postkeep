//! Verification of Google Cloud Pub/Sub push requests.
//!
//! A push subscription with authentication enabled sends
//! `Authorization: Bearer <JWT>`: an `OpenID` Connect ID token signed by
//! Google (RS256) for the subscription's service account. postkeep checks
//! the signature against Google's published keys, the issuer, the
//! audience it was configured with, the expiry, and that the token was
//! issued for the configured service account with a verified email.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Method;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::http::{self as transport, Endpoints, Http, JSON_LIMIT};

/// Leeway for clock differences, in seconds.
const LEEWAY: i64 = 60;
/// How long keys are cached when Google does not say.
const DEFAULT_KEY_TTL: Duration = Duration::from_hours(1);
/// How long to wait before another key fetch after a failure, and before
/// refetching a fresh cache for an unknown key id.
const REFETCH_INTERVAL: Duration = Duration::from_secs(60);
/// Returned while a failed fetch is inside [`REFETCH_INTERVAL`]. Callers
/// map [`PushTokenError::Keys`] to HTTP 503 so Pub/Sub retries later.
const KEYS_BACKOFF: &str = "Google's signing keys are temporarily unavailable";
/// Longest accepted token, in bytes.
const MAX_TOKEN_LEN: usize = 8 * 1024;

/// Why a push token was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PushTokenError {
    /// Not a well-formed RS256 JWT.
    #[error("the token is malformed: {0}")]
    Malformed(&'static str),
    /// No Google key with the token's key id.
    #[error("the token was signed with an unknown key")]
    UnknownKey,
    /// The signature does not verify.
    #[error("the token signature is invalid")]
    BadSignature,
    /// A claim does not match.
    #[error("the token claim {0} does not match")]
    Claim(&'static str),
    /// Google's keys could not be fetched.
    #[error("Google's signing keys are unavailable: {0}")]
    Keys(String),
}

/// The verified claims of a push token.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct PushClaims {
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Service account email.
    pub email: String,
    /// Whether Google verified the email.
    #[serde(default)]
    pub email_verified: bool,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// Issued at (Unix seconds).
    #[serde(default)]
    pub iat: i64,
}

/// What a push token must say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushExpectations {
    /// The audience configured on the push subscription.
    pub audience: String,
    /// The service account the subscription authenticates as.
    pub service_account: String,
}

#[derive(Debug, Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

/// An RSA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RsaKey {
    n: Vec<u8>,
    e: Vec<u8>,
}

#[derive(Debug, Default)]
struct KeyCache {
    keys: HashMap<String, RsaKey>,
    expires: Option<Instant>,
    fetched: Option<Instant>,
    /// A failed fetch is not repeated until this instant, even when the
    /// cache is empty or already expired.
    retry_after: Option<Instant>,
}

/// What [`PushVerifier::key`] should do before using the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FetchPlan {
    /// The cache is inside its TTL and holds this key id.
    Cached,
    /// Fetch, then serve the key or report an unknown id.
    Fetch,
    /// The cache is fresh, but this id was not in it and another fetch is
    /// not due yet.
    Unknown,
    /// A fetch failed recently and the cache is missing or expired. Do not
    /// serve expired keys and do not hit the network.
    Unavailable,
}

/// Decides whether to fetch. Expired keys are never [`FetchPlan::Cached`]:
/// `expires` has to be in the future, so a backoff after a failed refresh
/// fails the request instead of accepting a key past its TTL.
fn fetch_plan(cache: &KeyCache, kid: &str, now: Instant) -> FetchPlan {
    let fresh = cache.expires.is_some_and(|expires| expires > now);
    if fresh && cache.keys.contains_key(kid) {
        return FetchPlan::Cached;
    }
    let in_backoff = cache.retry_after.is_some_and(|until| until > now);
    let recently_fetched = cache
        .fetched
        .is_some_and(|fetched| now.saturating_duration_since(fetched) < REFETCH_INTERVAL);
    if fresh && (in_backoff || recently_fetched) {
        return FetchPlan::Unknown;
    }
    if in_backoff {
        return FetchPlan::Unavailable;
    }
    FetchPlan::Fetch
}

/// Verifies push tokens, caching Google's keys. Cheap to clone.
#[derive(Debug, Clone)]
pub struct PushVerifier {
    http: Http,
    endpoints: Endpoints,
    cache: Arc<Mutex<KeyCache>>,
}

impl PushVerifier {
    /// A verifier fetching keys from `endpoints.google_certs`.
    #[must_use]
    pub fn new(http: Http, endpoints: Endpoints) -> Self {
        Self {
            http,
            endpoints,
            cache: Arc::default(),
        }
    }

    /// Verifies `token` against `expected`.
    ///
    /// # Errors
    ///
    /// Returns why the token was refused.
    pub async fn verify(
        &self,
        token: &str,
        expected: &PushExpectations,
    ) -> Result<PushClaims, PushTokenError> {
        let parts = split(token)?;
        let key = self.key(parts.header.kid.as_deref()).await?;
        verify_with_key(&parts, &key, expected, chrono::Utc::now().timestamp())
    }

    async fn key(&self, kid: Option<&str>) -> Result<RsaKey, PushTokenError> {
        let kid = kid.ok_or(PushTokenError::Malformed("no key id"))?;
        let mut cache = self.cache.lock().await;
        match fetch_plan(&cache, kid, Instant::now()) {
            FetchPlan::Cached => cache
                .keys
                .get(kid)
                .cloned()
                .ok_or(PushTokenError::UnknownKey),
            FetchPlan::Unknown => Err(PushTokenError::UnknownKey),
            FetchPlan::Unavailable => Err(PushTokenError::Keys(KEYS_BACKOFF.to_owned())),
            FetchPlan::Fetch => {
                self.refresh(&mut cache).await?;
                cache
                    .keys
                    .get(kid)
                    .cloned()
                    .ok_or(PushTokenError::UnknownKey)
            }
        }
    }

    async fn refresh(&self, cache: &mut KeyCache) -> Result<(), PushTokenError> {
        let started = Instant::now();
        // Record the attempt first so a failure backs off even when the
        // request never returns a key set. The caller holds the cache
        // mutex, so this is not visible until `refresh` returns.
        cache.fetched = Some(started);
        match self.fetch_key_set().await {
            Ok((keys, ttl)) => {
                cache.keys = keys;
                cache.expires = Some(Instant::now() + ttl);
                cache.retry_after = None;
                Ok(())
            }
            Err(err) => {
                cache.retry_after = Some(started + REFETCH_INTERVAL);
                Err(err)
            }
        }
    }

    async fn fetch_key_set(&self) -> Result<(HashMap<String, RsaKey>, Duration), PushTokenError> {
        let request = transport::request(
            Method::GET,
            &self.endpoints.google_certs,
            &[],
            bytes::Bytes::new(),
        )
        .map_err(|err| PushTokenError::Keys(err.to_string()))?;
        let response = self
            .http
            .send(request, JSON_LIMIT)
            .await
            .map_err(|err| PushTokenError::Keys(err.to_string()))?;
        if !response.is_success() {
            return Err(PushTokenError::Keys(format!("HTTP {}", response.status)));
        }
        let jwks: Jwks = response
            .json()
            .map_err(|_| PushTokenError::Keys("unreadable key set".to_owned()))?;
        let ttl = max_age(&response.headers).unwrap_or(DEFAULT_KEY_TTL);
        Ok((parse_keys(jwks), ttl))
    }
}

fn parse_keys(jwks: Jwks) -> HashMap<String, RsaKey> {
    jwks.keys
        .into_iter()
        .filter(|key| key.kty == "RSA")
        .filter_map(|key| {
            let n = URL_SAFE_NO_PAD.decode(key.n?.trim_end_matches('=')).ok()?;
            let e = URL_SAFE_NO_PAD.decode(key.e?.trim_end_matches('=')).ok()?;
            Some((key.kid?, RsaKey { n, e }))
        })
        .collect()
}

/// `Cache-Control: max-age`, clamped to five minutes .. one day.
fn max_age(headers: &http::HeaderMap) -> Option<Duration> {
    let value = headers.get(http::header::CACHE_CONTROL)?.to_str().ok()?;
    let seconds: u64 = value
        .split(',')
        .find_map(|part| part.trim().strip_prefix("max-age="))?
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds.clamp(300, 86_400)))
}

/// A split, decoded JWT.
#[derive(Debug)]
struct Parts<'a> {
    header: Header,
    signed: &'a str,
    claims: Vec<u8>,
    signature: Vec<u8>,
}

fn split(token: &str) -> Result<Parts<'_>, PushTokenError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(PushTokenError::Malformed("too long"));
    }
    let mut pieces = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (pieces.next(), pieces.next(), pieces.next(), pieces.next())
    else {
        return Err(PushTokenError::Malformed("not a JWT"));
    };
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .map_err(|_| PushTokenError::Malformed("not base64url"))
    };
    let header: Header = serde_json::from_slice(&decode(header)?)
        .map_err(|_| PushTokenError::Malformed("unreadable header"))?;
    if header.alg != "RS256" {
        return Err(PushTokenError::Malformed("not RS256"));
    }
    let signed_len = token.len() - signature.len() - 1;
    Ok(Parts {
        header,
        signed: &token[..signed_len],
        claims: decode(claims)?,
        signature: decode(signature)?,
    })
}

fn verify_with_key(
    parts: &Parts<'_>,
    key: &RsaKey,
    expected: &PushExpectations,
    now: i64,
) -> Result<PushClaims, PushTokenError> {
    let public = ring::signature::RsaPublicKeyComponents {
        n: &key.n,
        e: &key.e,
    };
    public
        .verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            parts.signed.as_bytes(),
            &parts.signature,
        )
        .map_err(|_| PushTokenError::BadSignature)?;
    check_claims(&parts.claims, expected, now)
}

/// Checks verified claims against `expected` at `now`.
fn check_claims(
    claims: &[u8],
    expected: &PushExpectations,
    now: i64,
) -> Result<PushClaims, PushTokenError> {
    let claims: PushClaims = serde_json::from_slice(claims)
        .map_err(|_| PushTokenError::Malformed("unreadable claims"))?;
    if !matches!(
        claims.iss.as_str(),
        "https://accounts.google.com" | "accounts.google.com"
    ) {
        return Err(PushTokenError::Claim("iss"));
    }
    if claims.aud != expected.audience {
        return Err(PushTokenError::Claim("aud"));
    }
    if claims.exp.saturating_add(LEEWAY) < now {
        return Err(PushTokenError::Claim("exp"));
    }
    if claims.iat.saturating_sub(LEEWAY) > now {
        return Err(PushTokenError::Claim("iat"));
    }
    if !claims.email_verified || !claims.email.eq_ignore_ascii_case(&expected.service_account) {
        return Err(PushTokenError::Claim("email"));
    }
    Ok(claims)
}

/// Hooks for the fuzz targets.
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    use super::{PushExpectations, RsaKey, check_claims, split, verify_with_key};

    /// Runs `token` through parsing and verification against a key that
    /// signs nothing.
    ///
    /// # Panics
    ///
    /// If a forged token is ever accepted.
    pub fn check_token(token: &str, now: i64) {
        let expected = PushExpectations {
            audience: "https://mail.example.com/push/google".to_owned(),
            service_account: "push@demo.iam.gserviceaccount.com".to_owned(),
        };
        if let Ok(parts) = split(token) {
            let key = RsaKey {
                n: vec![0xc5; 256],
                e: vec![1, 0, 1],
            };
            assert!(
                verify_with_key(&parts, &key, &expected, now).is_err(),
                "accepted a token not signed by the key"
            );
        }
    }

    /// Checks arbitrary claims.
    ///
    /// # Panics
    ///
    /// If accepted claims do not match the expectations.
    pub fn check_claims_bytes(claims: &[u8], now: i64) {
        let expected = PushExpectations {
            audience: "https://mail.example.com/push/google".to_owned(),
            service_account: "push@demo.iam.gserviceaccount.com".to_owned(),
        };
        if let Ok(accepted) = check_claims(claims, &expected, now) {
            assert_eq!(accepted.aud, expected.audience);
            assert!(
                accepted
                    .email
                    .eq_ignore_ascii_case(&expected.service_account)
            );
            assert!(accepted.email_verified);
            assert!(accepted.exp.saturating_add(super::LEEWAY) >= now);
        }
    }
}

/// The Gmail notification inside a Pub/Sub push body.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailNotification {
    /// The mailbox that changed.
    pub email_address: String,
    /// The mailbox's history id after the change.
    pub history_id: u64,
}

/// Parses a Pub/Sub push body (`{"message": {"data": base64}, ...}`) into
/// the Gmail notification it carries.
///
/// # Errors
///
/// Returns a description for malformed bodies.
pub fn parse_push_body(body: &[u8]) -> Result<GmailNotification, &'static str> {
    #[derive(Deserialize)]
    struct Envelope {
        message: Message,
    }
    #[derive(Deserialize)]
    struct Message {
        data: Option<String>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Raw {
        email_address: String,
        history_id: serde_json::Value,
    }
    let envelope: Envelope = serde_json::from_slice(body).map_err(|_| "not a Pub/Sub push body")?;
    let data = envelope.message.data.ok_or("the message has no data")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data.trim())
        .or_else(|_| URL_SAFE_NO_PAD.decode(data.trim().trim_end_matches('=')))
        .map_err(|_| "the message data is not base64")?;
    let raw: Raw =
        serde_json::from_slice(&decoded).map_err(|_| "the message is not a Gmail notification")?;
    let history_id = match raw.history_id {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
    .ok_or("the notification has no history id")?;
    Ok(GmailNotification {
        email_address: raw.email_address,
        history_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gmail_push_bodies() {
        let data = base64::engine::general_purpose::STANDARD
            .encode(br#"{"emailAddress":"user@example.com","historyId":9876543210}"#);
        let body = format!(
            r#"{{"message":{{"data":"{data}","messageId":"1","publishTime":"2026-10-08T00:00:00Z"}},"subscription":"projects/p/subscriptions/s"}}"#
        );
        assert_eq!(
            parse_push_body(body.as_bytes()),
            Ok(GmailNotification {
                email_address: "user@example.com".to_owned(),
                history_id: 9_876_543_210
            })
        );
        assert!(parse_push_body(b"{}").is_err());
        assert!(parse_push_body(br#"{"message":{"data":"!!"}}"#).is_err());
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let expected = PushExpectations {
            audience: "a".to_owned(),
            service_account: "s@example.com".to_owned(),
        };
        let claims = |exp: i64, iat: i64| {
            format!(
                r#"{{"iss":"accounts.google.com","aud":"a","email":"s@example.com","email_verified":true,"exp":{exp},"iat":{iat}}}"#
            )
        };
        assert!(check_claims(claims(i64::MAX, i64::MIN).as_bytes(), &expected, 0).is_ok());
        assert_eq!(
            check_claims(claims(i64::MIN, 0).as_bytes(), &expected, 0).unwrap_err(),
            PushTokenError::Claim("exp")
        );
        assert_eq!(
            check_claims(claims(10, i64::MAX).as_bytes(), &expected, 0).unwrap_err(),
            PushTokenError::Claim("iat")
        );
    }

    #[test]
    fn reads_cache_control_max_age() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("public, max-age=22000, must-revalidate"),
        );
        assert_eq!(max_age(&headers), Some(Duration::from_secs(22_000)));
        headers.insert(
            http::header::CACHE_CONTROL,
            http::HeaderValue::from_static("max-age=1"),
        );
        assert_eq!(max_age(&headers), Some(Duration::from_secs(300)));
    }

    fn cache_holding(
        kid: Option<&str>,
        expires: Option<Instant>,
        fetched: Option<Instant>,
        retry_after: Option<Instant>,
    ) -> KeyCache {
        let mut keys = HashMap::new();
        if let Some(kid) = kid {
            keys.insert(
                kid.to_owned(),
                RsaKey {
                    n: vec![1],
                    e: vec![1, 0, 1],
                },
            );
        }
        KeyCache {
            keys,
            expires,
            fetched,
            retry_after,
        }
    }

    fn before(now: Instant, by: Duration) -> Instant {
        now.checked_sub(by).unwrap_or(now)
    }

    #[test]
    fn failed_fetches_back_off_without_serving_expired_keys() {
        let now = Instant::now();
        let earlier = before(now, Duration::from_secs(5));
        let later = now + Duration::from_secs(30);
        let expired = cache_holding(Some("k"), Some(earlier), Some(now), Some(later));
        assert_eq!(fetch_plan(&expired, "k", now), FetchPlan::Unavailable);
        assert_eq!(fetch_plan(&expired, "other", now), FetchPlan::Unavailable);

        let empty = cache_holding(None, None, Some(now), Some(later));
        assert_eq!(fetch_plan(&empty, "k", now), FetchPlan::Unavailable);

        let backoff_over = cache_holding(Some("k"), Some(earlier), Some(earlier), Some(earlier));
        assert_eq!(fetch_plan(&backoff_over, "k", now), FetchPlan::Fetch);
        assert_eq!(fetch_plan(&KeyCache::default(), "k", now), FetchPlan::Fetch);

        let fresh = cache_holding(
            Some("k"),
            Some(now + Duration::from_secs(3600)),
            Some(now),
            None,
        );
        assert_eq!(fetch_plan(&fresh, "k", now), FetchPlan::Cached);
        assert_eq!(fetch_plan(&fresh, "other", now), FetchPlan::Unknown);

        let refetch_due = cache_holding(
            Some("k"),
            Some(now + Duration::from_secs(3600)),
            Some(before(now, REFETCH_INTERVAL + Duration::from_secs(1))),
            None,
        );
        assert_eq!(fetch_plan(&refetch_due, "other", now), FetchPlan::Fetch);

        let ttl_over = cache_holding(
            Some("k"),
            Some(earlier),
            Some(before(now, Duration::from_secs(3600))),
            None,
        );
        assert_eq!(fetch_plan(&ttl_over, "k", now), FetchPlan::Fetch);
    }

    #[test]
    fn refuses_non_rs256_and_malformed_tokens() {
        let none_alg = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
            URL_SAFE_NO_PAD.encode(b"{}")
        );
        assert_eq!(
            split(&none_alg).err(),
            Some(PushTokenError::Malformed("not RS256"))
        );
        assert!(split("a.b").is_err());
        assert!(split(&"a".repeat(MAX_TOKEN_LEN + 1)).is_err());
    }
}
