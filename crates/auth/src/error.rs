//! OAuth error responses (RFC 6749 section 5.2).

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use postkeep_store::StoreError;
use serde::Serialize;

/// An error returned as a JSON OAuth error response.
#[derive(Debug)]
pub struct OAuthError {
    status: StatusCode,
    code: &'static str,
    description: String,
    basic_challenge: bool,
}

#[derive(Serialize)]
struct Body<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    error_description: &'a str,
}

impl OAuthError {
    fn new(status: StatusCode, code: &'static str, description: impl Into<String>) -> Self {
        Self {
            status,
            code,
            description: description.into(),
            basic_challenge: false,
        }
    }

    /// `invalid_request`: a missing or malformed parameter.
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_request", description)
    }

    /// `invalid_client`: unknown client or failed client authentication.
    pub fn invalid_client(basic_challenge: bool) -> Self {
        Self {
            basic_challenge,
            ..Self::new(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "client authentication failed",
            )
        }
    }

    /// `invalid_grant`: the code or refresh token is invalid or expired.
    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", description)
    }

    /// `unsupported_grant_type`.
    pub fn unsupported_grant_type() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code and refresh_token are supported",
        )
    }

    /// `invalid_target`: the resource indicator is not this server (RFC 8707).
    pub fn invalid_target() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "the resource parameter does not name this server",
        )
    }

    /// `invalid_redirect_uri` (RFC 7591).
    pub fn invalid_redirect_uri(description: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_redirect_uri", description)
    }

    /// `invalid_client_metadata` (RFC 7591).
    pub fn invalid_client_metadata(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            description,
        )
    }

    /// `429 Too Many Requests` with `invalid_request`; OAuth defines no
    /// rate-limit error code for these endpoints.
    pub fn too_many_requests() -> Self {
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            "invalid_request",
            "too many requests; slow down and retry later",
        )
    }

    /// `temporarily_unavailable`-style `503` for registration limits.
    pub fn registration_unavailable(description: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            description,
        )
    }

    /// `server_error`. The cause should be logged by the caller.
    pub fn server_error() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "server_error", "")
    }
}

impl From<StoreError> for OAuthError {
    fn from(err: StoreError) -> Self {
        tracing::error!(error = %err, "storage error");
        Self::server_error()
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = Body {
            error: self.code,
            error_description: &self.description,
        };
        let mut response = (self.status, no_store(), Json(body)).into_response();
        if self.basic_challenge {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Basic realm=\"postkeep\""),
            );
        }
        response
    }
}

/// `Cache-Control: no-store` and `Pragma: no-cache`, required on token
/// responses and useful on every OAuth response.
pub const fn no_store() -> [(header::HeaderName, HeaderValue); 2] {
    [
        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        (header::PRAGMA, HeaderValue::from_static("no-cache")),
    ]
}
