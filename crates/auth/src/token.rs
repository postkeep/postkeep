//! The token (RFC 6749 section 3.2) and revocation (RFC 7009) endpoints.

use axum::Form;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::FormRejection;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use postkeep_store::{Client, Redemption, RefreshRotation};
use serde::{Deserialize, Serialize};

use crate::error::{OAuthError, no_store};
use crate::state::AuthState;
use crate::{random, redirect};

#[derive(Debug, Default, Deserialize)]
pub struct TokenRequest {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    refresh_token: Option<String>,
    resource: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
struct TokenResponse<'a> {
    access_token: &'a str,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: &'a str,
    scope: &'a str,
}

/// `POST /token`
pub async fn token(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<TokenRequest>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(request) = form.map_err(|err| OAuthError::invalid_request(err.body_text()))?;
    let client = authenticate_client(
        &state,
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )
    .await?;
    match request.resource.as_deref() {
        None if state.config().per_request_resources => {
            return Err(OAuthError::invalid_request("resource is required"));
        }
        Some(resource) if !state.config().accepts_resource(resource) => {
            return Err(OAuthError::invalid_target());
        }
        _ => {}
    }
    match request.grant_type.as_deref() {
        Some("authorization_code") => authorization_code(&state, &client, &request).await,
        Some("refresh_token") => refresh(&state, &client, &request).await,
        Some(_) => Err(OAuthError::unsupported_grant_type()),
        None => Err(OAuthError::invalid_request("grant_type is required")),
    }
}

async fn authorization_code(
    state: &AuthState,
    client: &Client,
    request: &TokenRequest,
) -> Result<Response, OAuthError> {
    let code = request
        .code
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("code is required"))?;
    let verifier = request
        .code_verifier
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("code_verifier is required"))?;
    // Taking the code consumes it, so a failed attempt cannot be retried.
    let grant = match state.store().take_code(code).await? {
        Redemption::Valid(grant) => grant,
        Redemption::Replayed => {
            tracing::warn!(client_id = %client.id, "authorization code reused; revoked its grant");
            return Err(OAuthError::invalid_grant(
                "the authorization code was already used",
            ));
        }
        Redemption::Invalid => {
            return Err(OAuthError::invalid_grant(
                "the authorization code is invalid or expired",
            ));
        }
    };
    if grant.client_id != client.id {
        return Err(OAuthError::invalid_grant(
            "the code was issued to another client",
        ));
    }
    // redirect_uri must repeat the one used at /authorize. OAuth 2.1 drops
    // the requirement when PKCE is used, so it may also be omitted.
    if let Some(uri) = request.redirect_uri.as_deref()
        && uri != grant.redirect_uri
        && !redirect::matches(std::slice::from_ref(&grant.redirect_uri), uri)
    {
        return Err(OAuthError::invalid_grant("redirect_uri does not match"));
    }
    if !random::verify_pkce(verifier, &grant.code_challenge) {
        return Err(OAuthError::invalid_grant(
            "code_verifier does not match the code_challenge",
        ));
    }
    if state.config().per_request_resources {
        // Both are required and must be the same exact URL.
        if request.resource.is_none() || request.resource != grant.resource {
            return Err(OAuthError::invalid_target());
        }
    } else if let (Some(requested), Some(granted)) =
        (request.resource.as_deref(), grant.resource.as_deref())
        && requested.trim_end_matches('/') != granted.trim_end_matches('/')
    {
        return Err(OAuthError::invalid_target());
    }
    // The grant, the code link and the first token pair commit together.
    // A purge deletes a grant that has no token row, so this path cannot
    // commit the grant first. Refresh rotation marks the old refresh token
    // used and stores the replacement pair in that same transaction.
    let config = state.config();
    let access = random::token()?;
    let refresh = random::token()?;
    if state
        .store()
        .create_grant_for_code(
            code,
            &grant,
            &access,
            config.access_token_ttl,
            &refresh,
            config.refresh_token_ttl,
        )
        .await?
        .is_none()
    {
        return Err(OAuthError::invalid_grant(
            "the authorization code was already used",
        ));
    }
    // Activity is not part of issuing the tokens. A failure here must not
    // hide the tokens that were already committed: the client would retry
    // the authorization code and that replay would revoke the grant.
    if let Err(error) = state.store().touch_client(&client.id).await {
        tracing::warn!(
            error = %error,
            client_id = %client.id,
            "could not record client activity"
        );
    }
    Ok(token_response(
        &access,
        config.access_token_ttl.as_secs(),
        &refresh,
        &grant.scope,
    ))
}

async fn refresh(
    state: &AuthState,
    client: &Client,
    request: &TokenRequest,
) -> Result<Response, OAuthError> {
    let token = request
        .refresh_token
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("refresh_token is required"))?;
    let store = state.store().clone();
    let config = state.config();
    let access = random::token()?;
    let refresh_token = random::token()?;
    // The claim and new pair commit together. A failure leaves a first-use
    // token unused; grace reuse keeps the original first-use timestamp.
    let grant = match store
        .rotate_refresh_token(
            token,
            &client.id,
            &access,
            config.access_token_ttl,
            &refresh_token,
            config.refresh_token_ttl,
            config.refresh_reuse_grace,
            |email| config.email_allowed(email),
        )
        .await?
    {
        RefreshRotation::Rotated(grant) => grant,
        RefreshRotation::Refused(_) => {
            return Err(OAuthError::invalid_grant(
                "this account is not allowed on this server",
            ));
        }
        RefreshRotation::Replayed => {
            tracing::warn!(client_id = %client.id, "refresh token reused; revoked its grant");
            return Err(OAuthError::invalid_grant(
                "the refresh token was already used; sign in again",
            ));
        }
        RefreshRotation::Invalid => {
            return Err(OAuthError::invalid_grant(
                "the refresh token is invalid or expired",
            ));
        }
    };
    // With per-request resources the refresh must name the grant's exact
    // resource. A mismatch leaves the already-stored new pair undisclosed;
    // correcting the resource and retrying can succeed within the original grace.
    // A token is still limited to its own resource (see the bearer check).
    if config.per_request_resources && request.resource != grant.resource {
        return Err(OAuthError::invalid_target());
    }
    // Activity is not part of the rotation. A failure here must not hide
    // the tokens that were already committed: the client would retry the
    // old refresh token and a replay after the grace would revoke the grant.
    if let Err(error) = state.store().touch_client(&client.id).await {
        tracing::warn!(
            error = %error,
            client_id = %client.id,
            "could not record client activity"
        );
    }
    Ok(token_response(
        &access,
        config.access_token_ttl.as_secs(),
        &refresh_token,
        &grant.scope,
    ))
}

fn token_response(access: &str, expires_in: u64, refresh: &str, scope: &str) -> Response {
    let body = TokenResponse {
        access_token: access,
        token_type: "Bearer",
        expires_in,
        refresh_token: refresh,
        scope,
    };
    (StatusCode::OK, no_store(), Json(body)).into_response()
}

#[derive(Debug, Default, Deserialize)]
pub struct RevokeRequest {
    token: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

/// `POST /revoke`. Revoking either token of a grant revokes the grant,
/// but only when the token was issued to the authenticated client
/// (RFC 7009 section 2.1). The response is 200 either way.
pub async fn revoke(
    State(state): State<AuthState>,
    headers: HeaderMap,
    form: Result<Form<RevokeRequest>, FormRejection>,
) -> Result<Response, OAuthError> {
    let Form(request) = form.map_err(|err| OAuthError::invalid_request(err.body_text()))?;
    let client = authenticate_client(
        &state,
        &headers,
        request.client_id.as_deref(),
        request.client_secret.as_deref(),
    )
    .await?;
    let token = request
        .token
        .as_deref()
        .ok_or_else(|| OAuthError::invalid_request("token is required"))?;
    if state.store().revoke_token(token, &client.id).await? {
        tracing::info!(client_id = %client.id, "revoked a grant");
    }
    // RFC 7009: respond 200 whether or not the token was valid, including
    // when it belongs to a different client.
    Ok((StatusCode::OK, no_store()).into_response())
}

/// Identifies the client from HTTP Basic credentials or form fields and
/// checks its secret if it is confidential.
async fn authenticate_client(
    state: &AuthState,
    headers: &HeaderMap,
    form_id: Option<&str>,
    form_secret: Option<&str>,
) -> Result<Client, OAuthError> {
    let basic = basic_credentials(headers)?;
    let used_basic = basic.is_some();
    let (client_id, secret) = match basic {
        Some((id, secret)) => {
            if form_id.is_some_and(|form_id| form_id != id) {
                return Err(OAuthError::invalid_request(
                    "client_id does not match the credentials",
                ));
            }
            (id, Some(secret))
        }
        None => (
            form_id
                .ok_or_else(|| OAuthError::invalid_request("client_id is required"))?
                .to_owned(),
            form_secret.map(str::to_owned),
        ),
    };
    let client = state
        .store()
        .client(&client_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_client(used_basic))?;
    if client.confidential {
        let secret = secret.ok_or_else(|| OAuthError::invalid_client(used_basic))?;
        if !state
            .store()
            .verify_client_secret(&client.id, &secret)
            .await?
        {
            return Err(OAuthError::invalid_client(used_basic));
        }
    }
    Ok(client)
}

/// Parses `Authorization: Basic` client credentials (RFC 6749 section 2.3.1).
pub fn basic_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| OAuthError::invalid_client(true))?;
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return Ok(None);
    }
    let decoded = STANDARD
        .decode(encoded.trim())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| OAuthError::invalid_client(true))?;
    let (id, secret) = decoded
        .split_once(':')
        .ok_or_else(|| OAuthError::invalid_client(true))?;
    let decode = |part: &str| {
        url::form_urlencoded::parse(format!("x={part}").as_bytes())
            .next()
            .map(|(_, value)| value.into_owned())
    };
    match (decode(id), decode(secret)) {
        (Some(id), Some(secret)) => Ok(Some((id, secret))),
        _ => Err(OAuthError::invalid_client(true)),
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn parses_basic_credentials_with_form_encoding() {
        let mut headers = HeaderMap::new();
        let encoded = STANDARD.encode("my%20client:s%3Acret");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        assert_eq!(
            basic_credentials(&headers).unwrap(),
            Some(("my client".to_owned(), "s:cret".to_owned()))
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(basic_credentials(&headers).unwrap(), None);
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic !!!"));
        assert!(basic_credentials(&headers).is_err());
    }
}
