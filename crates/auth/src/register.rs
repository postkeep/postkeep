//! Dynamic client registration (RFC 7591).

use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use postkeep_mail::invisible::hidden;
use postkeep_store::NewClient;
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;

use crate::client_ip::ClientIp;
use crate::error::{OAuthError, no_store};
use crate::metadata::AUTH_METHODS;
use crate::state::AuthState;
use crate::{random, redirect};

pub const MAX_REDIRECT_URIS: usize = 10;
const MAX_NAME_CHARS: usize = 100;

/// Trims `name`, drops control characters and those of [`hidden`], which a
/// browser draws as nothing or which reorder the text around them, and keeps
/// at most 100 characters.
///
/// Applied at registration and again when a stored name is shown, so a
/// name saved by an older version cannot spoof the consent screen.
#[must_use]
pub fn sanitize_client_name(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .filter(|&c| !c.is_control() && !hidden(c))
        .take(MAX_NAME_CHARS)
        .collect();
    cleaned.trim().to_owned()
}

/// The name to show for a client, or `fallback` when none remains after
/// [`sanitize_client_name`].
#[must_use]
pub fn client_name_for_display(name: Option<&str>, fallback: &str) -> String {
    name.map(sanitize_client_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| fallback.to_owned())
}

#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    #[serde(default)]
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

/// `POST /register`
pub async fn register(
    State(state): State<AuthState>,
    ip: ClientIp,
    body: Result<Json<RegistrationRequest>, JsonRejection>,
) -> Result<Response, OAuthError> {
    let Json(request) = body.map_err(|err| OAuthError::invalid_client_metadata(err.body_text()))?;
    if state.limits().registrations.check(&ip.key()).is_err() {
        tracing::warn!("client registration limit reached");
        return Err(OAuthError::too_many_requests());
    }
    if state.store().client_count().await? >= state.config().max_clients {
        tracing::warn!("the registered client limit is reached");
        return Err(OAuthError::registration_unavailable(
            "this server is not accepting new client registrations right now",
        ));
    }

    if request.redirect_uris.is_empty() {
        return Err(OAuthError::invalid_redirect_uri(
            "at least one redirect_uri is required",
        ));
    }
    if request.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(OAuthError::invalid_redirect_uri("too many redirect_uris"));
    }
    for uri in &request.redirect_uris {
        redirect::validate(uri).map_err(OAuthError::invalid_redirect_uri)?;
    }

    // RFC 7591 defaults to client_secret_basic; MCP clients normally ask
    // for "none" (public client with PKCE).
    let method = request
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    if !AUTH_METHODS.contains(&method) {
        return Err(OAuthError::invalid_client_metadata(format!(
            "unsupported token_endpoint_auth_method: {method}"
        )));
    }
    let grant_types = request
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".to_owned(), "refresh_token".to_owned()]);
    if grant_types
        .iter()
        .any(|grant| !matches!(grant.as_str(), "authorization_code" | "refresh_token"))
    {
        return Err(OAuthError::invalid_client_metadata(
            "only authorization_code and refresh_token grants are supported",
        ));
    }
    let response_types = request
        .response_types
        .unwrap_or_else(|| vec!["code".to_owned()]);
    if response_types.iter().any(|kind| kind != "code") {
        return Err(OAuthError::invalid_client_metadata(
            "only the code response type is supported",
        ));
    }
    let name = request
        .client_name
        .as_deref()
        .map(sanitize_client_name)
        .filter(|name| !name.is_empty());

    let secret = if method == "none" {
        None
    } else {
        Some(random::token()?)
    };
    let client = state
        .store()
        .create_client(&NewClient {
            name: name.clone(),
            redirect_uris: request.redirect_uris.clone(),
            secret: secret.clone().map(SecretString::from),
        })
        .await?;
    tracing::info!(client_id = %client.id, public = secret.is_none(), "registered OAuth client");

    let mut body = json!({
        "client_id": client.id,
        "client_id_issued_at": client.created_at,
        "redirect_uris": client.redirect_uris,
        "token_endpoint_auth_method": method,
        "grant_types": grant_types,
        "response_types": response_types,
    });
    if let Some(name) = name {
        body["client_name"] = json!(name);
    }
    if let Some(secret) = secret {
        body["client_secret"] = json!(secret);
        body["client_secret_expires_at"] = json!(0);
    }
    Ok((StatusCode::CREATED, no_store(), Json(body)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every character the consent-screen filter must remove.
    const SPOOF: &str = "\
        \u{200B}\u{200C}\u{200D}\u{200E}\u{200F}\
        \u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\
        \u{2028}\u{2029}\
        \u{2060}\u{2061}\u{2062}\u{2063}\u{2064}\
        \u{2066}\u{2067}\u{2068}\u{2069}\
        \u{FEFF}";

    #[test]
    fn client_names_drop_bidi_format_and_line_separators() {
        assert_eq!(sanitize_client_name(&format!("A{SPOOF}B")), "AB");
        assert_eq!(sanitize_client_name("Acme\u{202E}evil\u{202C}"), "Acmeevil");
        assert_eq!(
            sanitize_client_name("line\u{2028}break\u{2029}here"),
            "linebreakhere"
        );
        assert_eq!(sanitize_client_name("a\nb\tc\u{0000}d\u{007F}"), "abcd");
        assert_eq!(sanitize_client_name("  Café メール  "), "Café メール");
        assert_eq!(sanitize_client_name("  \u{202E}\n  "), "");
        assert_eq!(sanitize_client_name(&"n".repeat(150)).chars().count(), 100);
        assert_eq!(
            client_name_for_display(Some("\u{202E}"), "An unnamed app"),
            "An unnamed app"
        );
        assert_eq!(
            client_name_for_display(Some("  Acme\u{200F}  "), "An unnamed app"),
            "Acme"
        );
        assert_eq!(client_name_for_display(None, "Unnamed app"), "Unnamed app");
    }

    #[test]
    fn client_names_drop_every_hidden_character() {
        assert_eq!(
            sanitize_client_name("A\u{061C}B\u{00AD}C\u{034F}D\u{180E}E"),
            "ABCDE"
        );
        assert_eq!(
            sanitize_client_name(
                "A\u{2065}\u{206A}\u{206F}B\u{FE00}\u{FE0F}C\u{FFF9}\u{FFFB}D\u{1D173}E"
            ),
            "ABCDE"
        );
        assert_eq!(
            sanitize_client_name("Acme\u{E0001}\u{E0065}\u{E006E}"),
            "Acme"
        );
        assert_eq!(
            client_name_for_display(Some("\u{3164}\u{FFA0}\u{115F}"), "An unnamed app"),
            "An unnamed app"
        );
        // An emoji stays, without its presentation selector.
        assert_eq!(
            sanitize_client_name("\u{2764}\u{FE0F} Mail \u{1F4EC}"),
            "\u{2764} Mail \u{1F4EC}"
        );
    }
}
