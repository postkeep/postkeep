//! Authorized calls to Microsoft Graph and the Gmail API for one account.
//!
//! [`ApiClient`] adds the account's access token to authorized requests, refreshes
//! it once when the provider answers 401, and turns error responses into an
//! [`ApiError`] that carries the provider's error code but never a token.

use std::time::Instant;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, Method, StatusCode, header};
use postkeep_store::AccountId;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::http::{self as transport, HttpError, HttpResponse, JSON_LIMIT};
use crate::oauth::UpstreamProvider;
use crate::tokens::{GRAPH_REQUESTS_PER_MAILBOX, TokenError, TokenManager};

/// A failed API call.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// No access token could be obtained.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// The request did not complete.
    #[error(transparent)]
    Http(#[from] HttpError),
    /// The provider answered with an error status.
    #[error("{provider} answered {status}{}: {message}", code.as_deref().map(|code| format!(" ({code})")).unwrap_or_default())]
    Status {
        /// Provider.
        provider: UpstreamProvider,
        /// HTTP status.
        status: StatusCode,
        /// The provider's error code, for example `ErrorItemNotFound`.
        code: Option<String>,
        /// Google's reason, from the first entry of the body's `errors`
        /// list, for example `userRateLimitExceeded`.
        reason: Option<String>,
        /// Bounded numeric `Retry-After`, when the status or reason allows it.
        retry_after: Option<u64>,
        /// The provider's message, shortened.
        message: String,
    },
    /// The response did not have the expected shape.
    #[error("unexpected response from {provider}: {what}")]
    Malformed {
        /// Provider.
        provider: UpstreamProvider,
        /// What was wrong.
        what: String,
    },
}

impl ApiError {
    /// The HTTP status of a [`ApiError::Status`].
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        match self {
            Self::Status { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The provider error code of a [`ApiError::Status`].
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Status { code, .. } => code.as_deref(),
            _ => None,
        }
    }

    /// Whether the call's deadline left this request unsent, including a
    /// refresh that did not start after waiting for another token rotation.
    #[must_use]
    pub const fn is_deadline(&self) -> bool {
        matches!(
            self,
            Self::Http(HttpError::Deadline)
                | Self::Token(TokenError::OAuth(crate::oauth::OAuthError::Http(
                    HttpError::Deadline
                )))
        )
    }

    /// Whether the provider is limiting requests: a 429, or a Google error
    /// whose reason is `userRateLimitExceeded` or `rateLimitExceeded`, which
    /// Gmail sends with a 403.
    #[must_use]
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::Status { status, reason, .. }
            if is_per_account_rate_limit(*status, reason.as_deref()))
    }

    /// Whether Google reports that the daily request limit was reached.
    #[must_use]
    pub fn is_daily_limit_exceeded(&self) -> bool {
        matches!(self, Self::Status { reason, .. } if is_daily_limit_reason(reason.as_deref()))
    }

    /// Whether either a per-account rate limit or a daily limit was reached.
    #[must_use]
    pub fn is_any_rate_limit(&self) -> bool {
        self.is_rate_limited() || self.is_daily_limit_exceeded()
    }

    /// The bounded delay in seconds supplied with an eligible API status.
    #[must_use]
    pub const fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Status { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

fn is_per_account_rate_limit(status: StatusCode, reason: Option<&str>) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || matches!(reason, Some("userRateLimitExceeded" | "rateLimitExceeded"))
}

fn is_daily_limit_reason(reason: Option<&str>) -> bool {
    reason == Some("dailyLimitExceeded")
}

pub(crate) fn status_retry_after(
    status: StatusCode,
    reason: Option<&str>,
    headers: &HeaderMap,
) -> Option<u64> {
    if status == StatusCode::SERVICE_UNAVAILABLE
        || is_per_account_rate_limit(status, reason)
        || is_daily_limit_reason(reason)
    {
        transport::parse_retry_after(headers)
    } else {
        None
    }
}

/// Authorized requests for one account. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ApiClient {
    tokens: TokenManager,
    account: AccountId,
    provider: UpstreamProvider,
}

#[derive(Clone, Copy)]
struct Response<'a> {
    limit: Option<usize>,
    can_start: &'a (dyn Fn() -> bool + Sync),
}

impl Response<'_> {
    const fn body(limit: usize) -> Self {
        Self {
            limit: Some(limit),
            can_start: &|| true,
        }
    }
}

impl ApiClient {
    /// A client for `account` at `provider`.
    #[must_use]
    pub const fn new(tokens: TokenManager, account: AccountId, provider: UpstreamProvider) -> Self {
        Self {
            tokens,
            account,
            provider,
        }
    }

    /// The provider.
    #[must_use]
    pub const fn provider(&self) -> UpstreamProvider {
        self.provider
    }

    /// The account.
    #[must_use]
    pub const fn account(&self) -> &AccountId {
        &self.account
    }

    /// The provider endpoints.
    #[must_use]
    pub const fn endpoints(&self) -> &crate::Endpoints {
        self.tokens.oauth().endpoints()
    }

    /// A scoped clone that starts no provider or token request after `deadline`.
    /// Other clients and requests already in flight keep their own limits.
    #[must_use]
    pub fn until(&self, deadline: Instant) -> Self {
        let mut client = self.clone();
        client.tokens.set_deadline(deadline);
        client
    }

    /// Sends a request and returns the successful response.
    ///
    /// A Microsoft request first waits for one of the mailbox's
    /// [`GRAPH_REQUESTS_PER_MAILBOX`]
    /// slots and holds it until the response is read.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] for a missing token, a transport failure or
    /// a non-2xx status.
    pub async fn call(
        &self,
        method: Method,
        url: &Url,
        headers: &[(HeaderName, String)],
        body: Bytes,
        limit: usize,
    ) -> Result<HttpResponse, ApiError> {
        self.call_with(method, url, headers, body, Response::body(limit))
            .await
    }

    /// Makes a request whose success body is not used, checking `can_start` before transmission
    /// (including a retry after an authorization rejection). Once started it reads the status
    /// regardless of `can_start`. Refusal bodies are still read up to the JSON limit.
    ///
    /// # Errors
    ///
    /// As [`Self::call`], or [`HttpError::Deadline`] through [`ApiError::Http`] if `can_start`
    /// vetoes a request.
    pub async fn call_status(
        &self,
        method: Method,
        url: &Url,
        headers: &[(HeaderName, String)],
        body: Bytes,
        can_start: impl Fn() -> bool + Sync,
    ) -> Result<(), ApiError> {
        self.call_with(
            method,
            url,
            headers,
            body,
            Response {
                limit: None,
                can_start: &can_start,
            },
        )
        .await
        .map(drop)
    }

    /// Uploads one range to a checked Outlook upload URL, using a Graph slot but no bearer.
    ///
    /// # Errors
    ///
    /// Returns an [`ApiError`] for a disallowed URL, transport failure, vetoed request
    /// or non-2xx status.
    /// Provider error bodies are discarded because they might echo the URL's token.
    pub async fn put_range(
        &self,
        url: &Url,
        content_range: String,
        body: Bytes,
        can_start: impl Fn() -> bool + Sync,
    ) -> Result<(StatusCode, Bytes), ApiError> {
        if url.origin() != self.endpoints().outlook_uploads.origin()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            let host = url.host_str().unwrap_or("unknown host");
            return Err(HttpError::Request(format!("refused Outlook upload URL at {host}")).into());
        }
        let http = self.tokens.oauth().http();
        let _slot = http.wait(self.tokens.graph_slot(&self.account, 1)).await?;
        if !can_start() {
            return Err(HttpError::Deadline.into());
        }
        let headers = [
            (header::CONTENT_RANGE, content_range),
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
        ];
        let request = transport::request(Method::PUT, url, &headers, body)?;
        let response = http.send(request, JSON_LIMIT).await?;
        if response.is_success() {
            Ok((response.status, response.body))
        } else {
            Err(ApiError::Status {
                provider: self.provider,
                status: response.status,
                code: None,
                reason: None,
                retry_after: status_retry_after(response.status, None, &response.headers),
                message: "attachment range refused".to_owned(),
            })
        }
    }

    async fn call_with(
        &self,
        method: Method,
        url: &Url,
        headers: &[(HeaderName, String)],
        body: Bytes,
        response: Response<'_>,
    ) -> Result<HttpResponse, ApiError> {
        let token = self
            .tokens
            .access_token(&self.account, self.provider)
            .await?;
        let _slot = match self.provider {
            UpstreamProvider::Microsoft => {
                self.tokens
                    .oauth()
                    .http()
                    .wait(self.tokens.graph_slot(&self.account, 1))
                    .await?
            }
            UpstreamProvider::Google => None,
        };
        self.authorized(method, url, headers, body, response, &token)
            .await
    }

    /// Sends a JSON batch while holding every Graph request slot of this mailbox.
    /// Returns `None` without sending if slot or token setup uses the deadline.
    ///
    /// # Errors
    ///
    /// As [`ApiClient::call`].
    pub async fn call_batch(
        &self,
        url: &Url,
        headers: &[(HeaderName, String)],
        body: Bytes,
        limit: usize,
        deadline: Instant,
    ) -> Result<Option<HttpResponse>, ApiError> {
        let api = self.until(deadline);
        let result: Result<HttpResponse, ApiError> = async {
            let _slots = api
                .tokens
                .oauth()
                .http()
                .wait(
                    api.tokens
                        .graph_slot(&api.account, GRAPH_REQUESTS_PER_MAILBOX),
                )
                .await?;
            let token = api.tokens.access_token(&api.account, api.provider).await?;
            api.authorized(
                Method::POST,
                url,
                headers,
                body,
                Response::body(limit),
                &token,
            )
            .await
        }
        .await;
        match result {
            Err(err) if err.is_deadline() => Ok(None),
            result => result.map(Some),
        }
    }

    async fn authorized(
        &self,
        method: Method,
        url: &Url,
        headers: &[(HeaderName, String)],
        body: Bytes,
        policy: Response<'_>,
        token: &SecretString,
    ) -> Result<HttpResponse, ApiError> {
        let response = self
            .send_once(&method, url, headers, body.clone(), policy, token)
            .await?;
        let response = if response.status == StatusCode::UNAUTHORIZED {
            let token = self
                .tokens
                .refresh_after_rejection(&self.account, self.provider, token)
                .await?;
            self.send_once(&method, url, headers, body, policy, &token)
                .await?
        } else {
            response
        };
        if response.is_success() {
            Ok(response)
        } else {
            Err(self.status_error(&response))
        }
    }

    /// `GET` returning JSON.
    ///
    /// # Errors
    ///
    /// As [`ApiClient::call`], or [`ApiError::Malformed`] for an
    /// unexpected body.
    pub async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &Url,
        headers: &[(HeaderName, String)],
    ) -> Result<T, ApiError> {
        let response = self
            .call(Method::GET, url, headers, Bytes::new(), JSON_LIMIT)
            .await?;
        self.parse(&response)
    }

    /// Sends a JSON body and returns the response.
    ///
    /// # Errors
    ///
    /// As [`ApiClient::call`].
    pub async fn send_json(
        &self,
        method: Method,
        url: &Url,
        headers: &[(HeaderName, String)],
        body: &serde_json::Value,
    ) -> Result<HttpResponse, ApiError> {
        let mut all = headers.to_vec();
        all.push((header::CONTENT_TYPE, "application/json".to_owned()));
        self.call(method, url, &all, Bytes::from(body.to_string()), JSON_LIMIT)
            .await
    }

    /// Parses a response body as JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Malformed`].
    pub fn parse<T: serde::de::DeserializeOwned>(
        &self,
        response: &HttpResponse,
    ) -> Result<T, ApiError> {
        response.json().map_err(|err| ApiError::Malformed {
            provider: self.provider,
            what: err.to_string(),
        })
    }

    async fn send_once(
        &self,
        method: &Method,
        url: &Url,
        headers: &[(HeaderName, String)],
        body: Bytes,
        policy: Response<'_>,
        token: &SecretString,
    ) -> Result<HttpResponse, ApiError> {
        let mut all = headers.to_vec();
        all.push((
            header::AUTHORIZATION,
            format!("Bearer {}", token.expose_secret()),
        ));
        let request = transport::request(method.clone(), url, &all, body)?;
        if !(policy.can_start)() {
            return Err(HttpError::Deadline.into());
        }
        Ok(self
            .tokens
            .oauth()
            .http()
            .send_response(request, policy.limit)
            .await?)
    }

    fn status_error(&self, response: &HttpResponse) -> ApiError {
        let (code, message) = error_details(&response.body);
        let reason = error_reason(&response.body);
        ApiError::Status {
            provider: self.provider,
            status: response.status,
            code,
            retry_after: status_retry_after(response.status, reason.as_deref(), &response.headers),
            reason,
            message,
        }
    }
}

/// Extracts the error code and message from a Graph or Google error body
/// (`{"error": {"code": ..., "message": ...}}`; Google also has `status`).
#[must_use]
pub fn error_details(body: &[u8]) -> (Option<String>, String) {
    #[derive(serde::Deserialize)]
    struct Envelope {
        error: Detail,
    }
    #[derive(serde::Deserialize)]
    struct Detail {
        code: Option<serde_json::Value>,
        status: Option<String>,
        message: Option<String>,
    }
    let Ok(Envelope { error }) = serde_json::from_slice::<Envelope>(body) else {
        return (None, "no details".to_owned());
    };
    let code = error
        .status
        .or_else(|| {
            error.code.map(|code| match code {
                serde_json::Value::String(code) => code,
                other => other.to_string(),
            })
        })
        .map(|code| code.chars().take(100).collect::<String>());
    let message = error
        .message
        .unwrap_or_default()
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(300)
        .collect::<String>();
    (code, message)
}

/// The `reason` of the first entry in a Google error body's `errors` list
/// (`{"error": {"errors": [{"reason": ...}]}}`). Graph bodies have none.
fn error_reason(body: &[u8]) -> Option<String> {
    let body: serde_json::Value = serde_json::from_slice(body).ok()?;
    body.pointer("/error/errors/0/reason")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn api_status_and_upload_range_capture_retry_after() {
        use postkeep_store::{MasterKey, Store};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let base = Url::parse(&server.uri()).unwrap();
        let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let db = format!("sqlite://{}", dir.path().join("test.db").display());
        let store = Store::connect(&db, &key).await.unwrap();
        let oauth = crate::OAuthClient::new(
            crate::Http::for_tests(),
            crate::Endpoints::all_at(&base),
            base.clone(),
            None,
            None,
        );
        let client = ApiClient::new(
            TokenManager::new(store, oauth),
            AccountId("test".into()),
            UpstreamProvider::Google,
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::RETRY_AFTER,
            http::HeaderValue::from_static("18446744073709551616"),
        );
        for (status, reason, expected) in [
            (
                StatusCode::TOO_MANY_REQUESTS,
                "",
                Some(transport::MAX_RETRY_AFTER_SECS),
            ),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "",
                Some(transport::MAX_RETRY_AFTER_SECS),
            ),
            (
                StatusCode::FORBIDDEN,
                "userRateLimitExceeded",
                Some(transport::MAX_RETRY_AFTER_SECS),
            ),
            (
                StatusCode::FORBIDDEN,
                "dailyLimitExceeded",
                Some(transport::MAX_RETRY_AFTER_SECS),
            ),
            (StatusCode::PAYLOAD_TOO_LARGE, "", None),
        ] {
            let body = serde_json::json!({"error":{"errors":[{"reason":reason}]}});
            let err = client.status_error(&HttpResponse {
                status,
                headers: headers.clone(),
                body: Bytes::from(body.to_string()),
            });
            assert_eq!(err.retry_after(), expected);
            assert_eq!(
                err.is_daily_limit_exceeded(),
                reason == "dailyLimitExceeded"
            );
            if err.is_daily_limit_exceeded() {
                assert!(err.is_any_rate_limit() && !err.is_rate_limited());
            }
        }
        Mock::given(method("PUT"))
            .and(path("/range"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "9")
                    .set_body_string("discarded body"),
            )
            .expect(1)
            .mount(&server)
            .await;
        let err = client
            .put_range(
                &base.join("range").unwrap(),
                "bytes 0-0/1".into(),
                Bytes::from_static(b"a"),
                || true,
            )
            .await
            .unwrap_err();
        assert_eq!(err.retry_after(), Some(9));
        assert!(!err.to_string().contains("discarded body"));
    }

    #[test]
    fn reads_graph_and_google_error_bodies() {
        let graph = br#"{"error":{"code":"ErrorItemNotFound","message":"The specified object was not found in the store.\nmore"}}"#;
        assert_eq!(
            error_details(graph),
            (
                Some("ErrorItemNotFound".to_owned()),
                "The specified object was not found in the store.".to_owned()
            )
        );
        let google = br#"{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND"}}"#;
        assert_eq!(error_details(google).0.as_deref(), Some("NOT_FOUND"));
        assert_eq!(error_details(b"<html>").0, None);
    }

    /// The 403 samples in Google's Gmail guide "Resolve errors": only the
    /// reason in the first entry of `error.errors` tells a rate limit from a
    /// refusal. A 429 is a rate limit whatever its body says.
    #[test]
    fn google_rate_limit_reasons_and_429s_are_rate_limits() {
        let user = br#"{"error":{"errors":[{"domain":"usageLimits","reason":"userRateLimitExceeded","message":"User Rate Limit Exceeded"}],"code":403,"message":"User Rate Limit Exceeded"}}"#;
        let rate = br#"{"error":{"errors":[{"domain":"usageLimits","message":"Rate Limit Exceeded","reason":"rateLimitExceeded"}],"code":403,"message":"Rate Limit Exceeded","status":"PERMISSION_DENIED"}}"#;
        let policy = br#"{"error":{"errors":[{"domain":"global","reason":"domainPolicy","message":"The domain administrators have disabled Gmail apps."}],"code":403,"message":"The domain administrators have disabled Gmail apps."}}"#;
        let graph = br#"{"error":{"code":"ErrorAccessDenied","message":"Access is denied."}}"#;
        assert_eq!(error_reason(user).as_deref(), Some("userRateLimitExceeded"));
        assert_eq!(error_reason(rate).as_deref(), Some("rateLimitExceeded"));
        assert_eq!(error_reason(policy).as_deref(), Some("domainPolicy"));
        assert_eq!(error_reason(graph), None);
        assert_eq!(error_reason(b"<html>"), None);

        let answer = |status: StatusCode, body: &[u8]| ApiError::Status {
            provider: UpstreamProvider::Google,
            status,
            code: None,
            reason: error_reason(body),
            retry_after: None,
            message: String::new(),
        };
        assert!(answer(StatusCode::FORBIDDEN, user).is_rate_limited());
        assert!(answer(StatusCode::FORBIDDEN, rate).is_rate_limited());
        assert!(!answer(StatusCode::FORBIDDEN, policy).is_rate_limited());
        assert!(!answer(StatusCode::FORBIDDEN, b"{}").is_rate_limited());
        assert!(answer(StatusCode::TOO_MANY_REQUESTS, b"{}").is_rate_limited());
        let malformed = ApiError::Malformed {
            provider: UpstreamProvider::Google,
            what: String::new(),
        };
        assert!(!malformed.is_rate_limited());
    }
}
