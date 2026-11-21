//! Discovery documents: RFC 8414 and RFC 9728.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, Uri};
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::SCOPE;
use crate::config::METADATA_PATH;
use crate::state::AuthState;

/// Client authentication methods accepted at the token and revocation
/// endpoints.
pub const AUTH_METHODS: [&str; 3] = ["none", "client_secret_post", "client_secret_basic"];

/// `GET /.well-known/oauth-authorization-server`
pub async fn authorization_server(State(state): State<AuthState>) -> impl IntoResponse {
    let config = state.config();
    Json(json!({
        "issuer": config.issuer(),
        "authorization_endpoint": config.endpoint("/authorize"),
        "token_endpoint": config.endpoint("/token"),
        "registration_endpoint": config.endpoint("/register"),
        "revocation_endpoint": config.endpoint("/revoke"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": AUTH_METHODS,
        "revocation_endpoint_auth_methods_supported": AUTH_METHODS,
        // Refresh tokens are always issued, so offline_access needs no
        // separate grant. Resources should not list it (MCP 2026-07-28),
        // so only this document does.
        "scopes_supported": [SCOPE, "offline_access"],
        "authorization_response_iss_parameter_supported": true,
        "client_id_metadata_document_supported": true,
        "service_documentation": env!("CARGO_PKG_REPOSITORY"),
    }))
}

/// `GET /.well-known/oauth-protected-resource[/<path>]`
///
/// With per-request resources, the resource is `<path>` (the resource path
/// when there is none) on the request's host; an unknown host or path gets
/// the public URL's.
pub async fn protected_resource(
    State(state): State<AuthState>,
    uri: Uri,
    headers: HeaderMap,
) -> impl IntoResponse {
    let config = state.config();
    let path = uri
        .path()
        .strip_prefix(METADATA_PATH)
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| config.resource_path());
    let resource = config
        .resource_for(&headers, path)
        .unwrap_or_else(|| config.resource());
    let document: Value = json!({
        "resource": resource,
        "authorization_servers": [config.issuer()],
        "scopes_supported": [SCOPE],
        "bearer_methods_supported": ["header"],
        "resource_name": "postkeep",
        "resource_documentation": env!("CARGO_PKG_REPOSITORY"),
    });
    Json(document)
}
