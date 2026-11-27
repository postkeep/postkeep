//! The upstream OAuth client: postkeep signs users in with Microsoft or
//! Google (authorization code flow with PKCE and `state`) and keeps their
//! refresh token to call Microsoft Graph or the Gmail API.
//!
//! This is the *client* side. postkeep stays the OAuth authorization
//! server for MCP clients; the two legs never share tokens.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, Method, StatusCode};
use postkeep_store::Provider;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

use crate::http::{Endpoints, Http, HttpError, JSON_LIMIT, join_segments, request};

/// Microsoft Graph scopes: read and change mail, send mail, refresh tokens,
/// read the signed-in user's id and address, and translate search hits to
/// immutable message ids (`User.Read`).
pub const MICROSOFT_SCOPES: &[&str] =
    &["offline_access", "User.Read", "Mail.ReadWrite", "Mail.Send"];

/// Gmail scopes. `openid` gives a stable account id (`sub`); the address
/// comes from the Gmail profile, so the `email` scope is not needed.
pub const GOOGLE_SCOPES: &[&str] = &[
    "openid",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.send",
];

/// Scopes the account can't work without. Google's granular consent lets
/// users untick scopes, so the granted list is checked after sign-in.
/// `gmail.modify` already allows sending, so `gmail.send` is not required.
const MICROSOFT_REQUIRED: &[&str] = &["Mail.ReadWrite", "Mail.Send"];
const GOOGLE_REQUIRED: &[&str] = &["openid", "https://www.googleapis.com/auth/gmail.modify"];

/// The Microsoft tenant: `common` accepts work, school and personal
/// accounts.
const MICROSOFT_TENANT: &str = "common";

/// Longest error description kept from a provider response.
const MAX_DESCRIPTION: usize = 300;

/// An upstream identity provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpstreamProvider {
    /// Microsoft Entra ID / Microsoft account, for Outlook via Graph.
    Microsoft,
    /// Google, for Gmail.
    Google,
}

impl UpstreamProvider {
    /// Both providers.
    pub const ALL: [Self; 2] = [Self::Microsoft, Self::Google];

    /// The URL slug: `microsoft` or `google`.
    #[must_use]
    pub const fn slug(self) -> &'static str {
        match self {
            Self::Microsoft => "microsoft",
            Self::Google => "google",
        }
    }

    /// Parses a slug.
    #[must_use]
    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.slug() == slug)
    }

    /// The mail provider of accounts signed in this way.
    #[must_use]
    pub const fn mail_provider(self) -> Provider {
        match self {
            Self::Microsoft => Provider::Graph,
            Self::Google => Provider::Gmail,
        }
    }

    /// The upstream provider of a mail provider, if it uses OAuth.
    #[must_use]
    pub const fn for_mail_provider(provider: Provider) -> Option<Self> {
        match provider {
            Provider::Graph => Some(Self::Microsoft),
            Provider::Gmail => Some(Self::Google),
            Provider::Imap => None,
        }
    }

    /// The redirect URI path on postkeep.
    #[must_use]
    pub const fn callback_path(self) -> &'static str {
        match self {
            Self::Microsoft => "/oauth/microsoft/callback",
            Self::Google => "/oauth/google/callback",
        }
    }

    /// The scopes requested.
    #[must_use]
    pub const fn scopes(self) -> &'static [&'static str] {
        match self {
            Self::Microsoft => MICROSOFT_SCOPES,
            Self::Google => GOOGLE_SCOPES,
        }
    }

    /// A display name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Microsoft => "Microsoft",
            Self::Google => "Google",
        }
    }
}

impl fmt::Display for UpstreamProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

/// A registered OAuth app: client ID and secret.
#[derive(Clone)]
pub struct AppCredentials {
    /// Client (application) ID.
    pub client_id: String,
    /// Client secret.
    pub client_secret: SecretString,
}

impl fmt::Debug for AppCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Why an OAuth request failed.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    /// The provider is not configured on this server.
    #[error("{0} sign-in is not configured on this server")]
    NotConfigured(UpstreamProvider),
    /// The grant was rejected for good (revoked, expired, password changed,
    /// consent withdrawn): the user must sign in again.
    #[error("the {provider} sign-in is no longer valid ({code}); sign in again")]
    NeedsReauth {
        /// Provider.
        provider: UpstreamProvider,
        /// The OAuth error code, such as `invalid_grant`.
        code: String,
    },
    /// The provider refused the request.
    #[error("{provider} refused the request: {code}{}", .description.as_deref().map(|d| format!(" ({d})")).unwrap_or_default())]
    Rejected {
        /// Provider.
        provider: UpstreamProvider,
        /// HTTP status of the response.
        status: StatusCode,
        /// Bounded numeric `Retry-After`, when applicable.
        retry_after: Option<u64>,
        /// OAuth error code, or the HTTP status.
        code: String,
        /// Shortened description from the provider.
        description: Option<String>,
    },
    /// The user did not grant every required permission.
    #[error("not every required permission was granted: {}", .0.join(", "))]
    MissingScopes(Vec<String>),
    /// The provider's answer did not have the expected shape.
    #[error("unexpected answer from {provider}: {what}")]
    Malformed {
        /// Provider.
        provider: UpstreamProvider,
        /// What was wrong.
        what: &'static str,
    },
    /// The account has no mailbox the provider's mail API can reach (for
    /// example a Microsoft work account without an Exchange Online
    /// license).
    #[error("this {0} account has no mailbox that postkeep can use")]
    NoMailbox(UpstreamProvider),
    /// A transport error.
    #[error(transparent)]
    Http(#[from] HttpError),
}

impl OAuthError {
    /// The bounded delay in seconds supplied with an eligible provider status.
    #[must_use]
    pub const fn retry_after(&self) -> Option<u64> {
        match self {
            Self::Rejected { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// Whether the provider's HTTP status indicated rate limiting.
    #[must_use]
    pub fn is_rate_limited(&self) -> bool {
        matches!(
            self,
            Self::Rejected {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            }
        )
    }

    /// Whether the provider reported a server failure or temporary outage.
    #[must_use]
    pub fn is_server_unavailable(&self) -> bool {
        matches!(self, Self::Rejected { status, code, .. }
            if status.is_server_error() || matches!(code.as_str(), "temporarily_unavailable" | "server_error"))
    }

    /// Whether retrying later could help.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Http(_)) || self.is_rate_limited() || self.is_server_unavailable()
    }
}

/// A token endpoint response.
#[derive(Clone)]
pub struct TokenResponse {
    /// Access token for the provider's API.
    pub access_token: SecretString,
    /// Refresh token. Microsoft rotates it; Google returns one only on
    /// the first consent (forced with `prompt=consent`).
    pub refresh_token: Option<SecretString>,
    /// Access token lifetime in seconds.
    pub expires_in: Option<i64>,
    /// Granted scopes, space-separated.
    pub scope: Option<String>,
    /// Google's ID token (only with the `openid` scope).
    pub id_token: Option<SecretString>,
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct RawToken {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
}

#[derive(Deserialize)]
struct RawError {
    error: Option<serde_json::Value>,
    #[serde(default)]
    error_description: Option<String>,
}

/// The signed-in user at the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Stable account id at the provider: the Graph user id, or Google's
    /// `sub`.
    pub subject: String,
    /// The mailbox address.
    pub email: String,
}

/// The OAuth client for both providers.
#[derive(Clone)]
pub struct OAuthClient {
    http: Http,
    endpoints: Endpoints,
    public_url: Url,
    microsoft: Option<AppCredentials>,
    google: Option<AppCredentials>,
}

impl fmt::Debug for OAuthClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OAuthClient")
            .field("public_url", &self.public_url.as_str())
            .field("microsoft", &self.microsoft.is_some())
            .field("google", &self.google.is_some())
            .finish_non_exhaustive()
    }
}

impl OAuthClient {
    /// Creates the client. `public_url` is postkeep's own public base URL;
    /// redirect URIs are built from it.
    #[must_use]
    pub const fn new(
        http: Http,
        endpoints: Endpoints,
        public_url: Url,
        microsoft: Option<AppCredentials>,
        google: Option<AppCredentials>,
    ) -> Self {
        Self {
            http,
            endpoints,
            public_url,
            microsoft,
            google,
        }
    }

    pub(crate) const fn set_deadline(&mut self, deadline: std::time::Instant) {
        self.http.set_deadline(deadline);
    }

    /// The HTTP client.
    #[must_use]
    pub const fn http(&self) -> &Http {
        &self.http
    }

    /// The provider endpoints.
    #[must_use]
    pub const fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// Whether `provider` is configured.
    #[must_use]
    pub const fn is_configured(&self, provider: UpstreamProvider) -> bool {
        self.app(provider).is_some()
    }

    /// The configured providers.
    #[must_use]
    pub fn configured(&self) -> Vec<UpstreamProvider> {
        UpstreamProvider::ALL
            .into_iter()
            .filter(|provider| self.is_configured(*provider))
            .collect()
    }

    const fn app(&self, provider: UpstreamProvider) -> Option<&AppCredentials> {
        match provider {
            UpstreamProvider::Microsoft => self.microsoft.as_ref(),
            UpstreamProvider::Google => self.google.as_ref(),
        }
    }

    fn require(&self, provider: UpstreamProvider) -> Result<&AppCredentials, OAuthError> {
        self.app(provider)
            .ok_or(OAuthError::NotConfigured(provider))
    }

    /// The redirect URI registered with the provider.
    #[must_use]
    pub fn redirect_uri(&self, provider: UpstreamProvider) -> Url {
        let mut url = self.public_url.clone();
        url.set_path(provider.callback_path());
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    fn authorize_endpoint(&self, provider: UpstreamProvider) -> Url {
        match provider {
            UpstreamProvider::Microsoft => join_segments(
                &self.endpoints.microsoft_login,
                &[MICROSOFT_TENANT, "oauth2", "v2.0", "authorize"],
            ),
            UpstreamProvider::Google => join_segments(
                &self.endpoints.google_accounts,
                &["o", "oauth2", "v2", "auth"],
            ),
        }
    }

    fn token_endpoint(&self, provider: UpstreamProvider) -> Url {
        match provider {
            UpstreamProvider::Microsoft => join_segments(
                &self.endpoints.microsoft_login,
                &[MICROSOFT_TENANT, "oauth2", "v2.0", "token"],
            ),
            UpstreamProvider::Google => join_segments(&self.endpoints.google_oauth, &["token"]),
        }
    }

    /// The URL that starts sign-in at the provider. `state` and the PKCE
    /// `code_challenge` (S256) come from [`crate::pkce`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::NotConfigured`] if the provider is not set up.
    pub fn authorize_url(
        &self,
        provider: UpstreamProvider,
        state: &str,
        code_challenge: &str,
        login_hint: Option<&str>,
    ) -> Result<Url, OAuthError> {
        let app = self.require(provider)?;
        let mut url = self.authorize_endpoint(provider);
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("client_id", &app.client_id)
                .append_pair("response_type", "code")
                .append_pair("redirect_uri", self.redirect_uri(provider).as_str())
                .append_pair("scope", &provider.scopes().join(" "))
                .append_pair("state", state)
                .append_pair("code_challenge", code_challenge)
                .append_pair("code_challenge_method", "S256");
            match provider {
                UpstreamProvider::Microsoft => {
                    query
                        .append_pair("response_mode", "query")
                        .append_pair("prompt", "select_account");
                }
                UpstreamProvider::Google => {
                    // A refresh token is only issued with offline access,
                    // and again on later sign-ins only with forced consent.
                    query
                        .append_pair("access_type", "offline")
                        .append_pair("prompt", "consent");
                }
            }
            if let Some(hint) = login_hint.filter(|hint| !hint.is_empty()) {
                query.append_pair("login_hint", hint);
            }
        }
        Ok(url)
    }

    /// Exchanges an authorization code for tokens and checks the granted
    /// scopes.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError`] if the provider rejects the code, a
    /// required scope is missing or the request fails.
    pub async fn exchange_code(
        &self,
        provider: UpstreamProvider,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, OAuthError> {
        let app = self.require(provider)?;
        let redirect_uri = self.redirect_uri(provider);
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.expose_secret()),
            ("code_verifier", code_verifier),
        ];
        let scope = provider.scopes().join(" ");
        if provider == UpstreamProvider::Microsoft {
            form.push(("scope", scope.as_str()));
        }
        let token = self.token_request(provider, &form).await?;
        if token.refresh_token.is_none() {
            return Err(OAuthError::Malformed {
                provider,
                what: "no refresh token was issued",
            });
        }
        if let Err(err) = check_scopes(provider, token.scope.as_deref()) {
            // Don't leave behind a grant that will never be used.
            if let Some(refresh) = token.refresh_token.as_ref()
                && let Err(revoke) = self.revoke(provider, refresh).await
            {
                tracing::warn!(%provider, error = %revoke, "could not revoke an incomplete grant");
            }
            return Err(err);
        }
        Ok(token)
    }

    /// Gets a new access token with a refresh token.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthError::NeedsReauth`] when the refresh token is no
    /// longer valid, or another [`OAuthError`].
    pub async fn refresh(
        &self,
        provider: UpstreamProvider,
        refresh_token: &SecretString,
    ) -> Result<TokenResponse, OAuthError> {
        let app = self.require(provider)?;
        let scope = provider.scopes().join(" ");
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose_secret()),
            ("client_id", app.client_id.as_str()),
            ("client_secret", app.client_secret.expose_secret()),
        ];
        if provider == UpstreamProvider::Microsoft {
            form.push(("scope", scope.as_str()));
        }
        self.token_request(provider, &form).await
    }

    async fn token_request(
        &self,
        provider: UpstreamProvider,
        form: &[(&str, &str)],
    ) -> Result<TokenResponse, OAuthError> {
        let body = form_body(form);
        let request = request(
            Method::POST,
            &self.token_endpoint(provider),
            &[
                (CONTENT_TYPE, "application/x-www-form-urlencoded".to_owned()),
                (ACCEPT, "application/json".to_owned()),
            ],
            Bytes::from(body),
        )?;
        let response = self.http.send(request, JSON_LIMIT).await?;
        if !response.is_success() {
            return Err(provider_error(
                provider,
                response.status,
                &response.headers,
                &response.body,
            ));
        }
        let raw: RawToken = response.json().map_err(|_| OAuthError::Malformed {
            provider,
            what: "the token response is not valid JSON",
        })?;
        if raw.access_token.is_empty() {
            return Err(OAuthError::Malformed {
                provider,
                what: "the token response has no access token",
            });
        }
        Ok(TokenResponse {
            access_token: SecretString::from(raw.access_token),
            refresh_token: raw
                .refresh_token
                .filter(|token| !token.is_empty())
                .map(SecretString::from),
            expires_in: raw.expires_in,
            scope: raw.scope,
            id_token: raw.id_token.map(SecretString::from),
        })
    }

    /// Revokes a token at the provider, so the grant disappears from the
    /// user's account. Only Google offers this; Microsoft has no endpoint
    /// for an app to revoke its own delegated grant, so this does nothing
    /// for Microsoft (the user removes the app at
    /// <https://account.live.com/consent/Manage> or
    /// <https://myapps.microsoft.com>).
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError`] if Google refuses the request or it fails.
    /// A token Google no longer knows counts as revoked.
    pub async fn revoke(
        &self,
        provider: UpstreamProvider,
        token: &SecretString,
    ) -> Result<(), OAuthError> {
        if provider != UpstreamProvider::Google {
            return Ok(());
        }
        self.require(provider)?;
        let request = request(
            Method::POST,
            &join_segments(&self.endpoints.google_oauth, &["revoke"]),
            &[(CONTENT_TYPE, "application/x-www-form-urlencoded".to_owned())],
            Bytes::from(form_body(&[("token", token.expose_secret())])),
        )?;
        let response = self.http.send(request, JSON_LIMIT).await?;
        if response.is_success() {
            return Ok(());
        }
        match provider_error(provider, response.status, &response.headers, &response.body) {
            // Already revoked or expired.
            OAuthError::NeedsReauth { .. } => Ok(()),
            OAuthError::Rejected { code, .. } if code == "invalid_token" => Ok(()),
            other => Err(other),
        }
    }

    /// Looks up the signed-in user with a fresh token response.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthError`] if the profile can't be read or lacks an
    /// id or address.
    pub async fn identity(
        &self,
        provider: UpstreamProvider,
        token: &TokenResponse,
    ) -> Result<Identity, OAuthError> {
        match provider {
            UpstreamProvider::Microsoft => self.microsoft_identity(&token.access_token).await,
            UpstreamProvider::Google => {
                let app = self.require(provider)?;
                let id_token = token.id_token.as_ref().ok_or(OAuthError::Malformed {
                    provider,
                    what: "no ID token was issued",
                })?;
                let subject = google_subject(id_token.expose_secret(), &app.client_id)?;
                let email = self.gmail_address(&token.access_token).await?;
                Ok(Identity { subject, email })
            }
        }
    }

    async fn microsoft_identity(
        &self,
        access_token: &SecretString,
    ) -> Result<Identity, OAuthError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Me {
            id: Option<String>,
            mail: Option<String>,
            user_principal_name: Option<String>,
        }
        let provider = UpstreamProvider::Microsoft;
        let mut url = join_segments(&self.endpoints.graph, &["me"]);
        url.query_pairs_mut()
            .append_pair("$select", "id,mail,userPrincipalName");
        let me: Me = self.get_json(provider, &url, access_token).await?;
        let subject = me
            .id
            .filter(|id| !id.is_empty())
            .ok_or(OAuthError::Malformed {
                provider,
                what: "the profile has no id",
            })?;
        let email = me
            .mail
            .filter(|mail| mail.contains('@'))
            .or_else(|| me.user_principal_name.filter(|upn| upn.contains('@')))
            .ok_or(OAuthError::Malformed {
                provider,
                what: "the profile has no email address",
            })?;
        // The address is only trusted for a real mailbox: Exchange Online
        // keeps `mail` equal to the mailbox's primary address, which must be
        // in a domain the tenant has verified. A directory user without a
        // mailbox can carry any `mail` value its tenant admin typed in, so
        // it must not pass the allow-list under someone else's address.
        let mut inbox = join_segments(&self.endpoints.graph, &["me", "mailFolders", "inbox"]);
        inbox.query_pairs_mut().append_pair("$select", "id");
        match self
            .get_json::<serde_json::Value>(provider, &inbox, access_token)
            .await
        {
            Ok(_) => {}
            Err(OAuthError::Rejected { .. } | OAuthError::NeedsReauth { .. }) => {
                return Err(OAuthError::NoMailbox(provider));
            }
            Err(err) => return Err(err),
        }
        Ok(Identity {
            subject,
            email: email.trim().to_ascii_lowercase(),
        })
    }

    async fn gmail_address(&self, access_token: &SecretString) -> Result<String, OAuthError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Profile {
            email_address: Option<String>,
        }
        let provider = UpstreamProvider::Google;
        let url = join_segments(
            &self.endpoints.gmail,
            &["gmail", "v1", "users", "me", "profile"],
        );
        let profile: Profile = self.get_json(provider, &url, access_token).await?;
        profile
            .email_address
            .filter(|email| email.contains('@'))
            .map(|email| email.trim().to_ascii_lowercase())
            .ok_or(OAuthError::Malformed {
                provider,
                what: "the Gmail profile has no address",
            })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        provider: UpstreamProvider,
        url: &Url,
        access_token: &SecretString,
    ) -> Result<T, OAuthError> {
        let request = request(
            Method::GET,
            url,
            &[
                (
                    AUTHORIZATION,
                    format!("Bearer {}", access_token.expose_secret()),
                ),
                (ACCEPT, "application/json".to_owned()),
            ],
            Bytes::new(),
        )?;
        let response = self.http.send(request, JSON_LIMIT).await?;
        if !response.is_success() {
            return Err(provider_error(
                provider,
                response.status,
                &response.headers,
                &response.body,
            ));
        }
        response.json().map_err(|_| OAuthError::Malformed {
            provider,
            what: "the profile is not valid JSON",
        })
    }
}

/// URL-encodes a form body.
fn form_body(pairs: &[(&str, &str)]) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
}

/// Turns an error response into an [`OAuthError`]. Token endpoint errors
/// carry an OAuth `error` code; API errors (Graph, Gmail) carry an object.
pub(crate) fn provider_error(
    provider: UpstreamProvider,
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> OAuthError {
    let retry_after = crate::api::status_retry_after(status, None, headers);
    let parsed: Option<RawError> = serde_json::from_slice(body).ok();
    let (code, description) = match parsed {
        Some(RawError {
            error: Some(serde_json::Value::String(code)),
            error_description,
        }) => (code, error_description),
        Some(RawError {
            error: Some(serde_json::Value::Object(object)),
            ..
        }) => (
            object
                .get("code")
                .and_then(|code| {
                    code.as_str()
                        .map(str::to_owned)
                        .or_else(|| code.as_u64().map(|n| n.to_string()))
                })
                .unwrap_or_else(|| status.as_u16().to_string()),
            object
                .get("message")
                .and_then(|message| message.as_str())
                .map(str::to_owned),
        ),
        _ => (status.as_u16().to_string(), None),
    };
    if matches!(
        code.as_str(),
        "invalid_grant" | "interaction_required" | "consent_required"
    ) {
        return OAuthError::NeedsReauth { provider, code };
    }
    OAuthError::Rejected {
        provider,
        status,
        retry_after,
        code: if code.is_empty() {
            status.as_u16().to_string()
        } else {
            code
        },
        description: description.map(|text| shorten(&text)),
    }
}

/// Keeps the first line of a description, at most [`MAX_DESCRIPTION`]
/// characters.
fn shorten(text: &str) -> String {
    let line = text.lines().next().unwrap_or_default().trim();
    line.chars().take(MAX_DESCRIPTION).collect()
}

/// Checks that every required scope was granted.
///
/// # Errors
///
/// Returns [`OAuthError::MissingScopes`] with the missing scopes.
pub fn check_scopes(provider: UpstreamProvider, granted: Option<&str>) -> Result<(), OAuthError> {
    let required = match provider {
        UpstreamProvider::Microsoft => MICROSOFT_REQUIRED,
        UpstreamProvider::Google => GOOGLE_REQUIRED,
    };
    // A token response without `scope` means the requested scopes were
    // granted as asked (RFC 6749, section 5.1).
    let Some(granted) = granted else {
        return Ok(());
    };
    let granted: Vec<&str> = granted.split_whitespace().collect();
    let missing: Vec<String> = required
        .iter()
        .filter(|scope| {
            !granted
                .iter()
                .any(|have| scope_matches(provider, have, scope))
        })
        .map(|scope| (*scope).to_owned())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(OAuthError::MissingScopes(missing))
    }
}

fn scope_matches(provider: UpstreamProvider, granted: &str, required: &str) -> bool {
    match provider {
        // Graph may answer with fully qualified scopes and any case.
        UpstreamProvider::Microsoft => {
            let short = granted
                .strip_prefix("https://graph.microsoft.com/")
                .unwrap_or(granted);
            short.eq_ignore_ascii_case(required)
        }
        UpstreamProvider::Google => granted == required,
    }
}

/// Reads `sub` from a Google ID token.
///
/// The token must come straight from Google's token endpoint over TLS:
/// `OpenID` Connect Core, section 3.1.3.7, lets TLS server authentication
/// replace the signature check in that case. The audience, issuer and
/// expiry are still checked.
///
/// # Errors
///
/// Returns [`OAuthError::Malformed`] for anything unexpected.
pub fn google_subject(id_token: &str, client_id: &str) -> Result<String, OAuthError> {
    #[derive(Deserialize)]
    struct Claims {
        iss: String,
        aud: String,
        sub: String,
        exp: i64,
    }
    let malformed = |what| OAuthError::Malformed {
        provider: UpstreamProvider::Google,
        what,
    };
    let mut parts = id_token.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(malformed("the ID token is not a JWT"));
    };
    let payload = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .map_err(|_| malformed("the ID token is not a JWT"))?;
    let claims: Claims =
        serde_json::from_slice(&payload).map_err(|_| malformed("the ID token lacks claims"))?;
    if !matches!(
        claims.iss.as_str(),
        "https://accounts.google.com" | "accounts.google.com"
    ) {
        return Err(malformed("the ID token has the wrong issuer"));
    }
    if claims.aud != client_id {
        return Err(malformed("the ID token is for another client"));
    }
    if claims.exp.saturating_add(300) < chrono::Utc::now().timestamp() {
        return Err(malformed("the ID token has expired"));
    }
    if claims.sub.is_empty() || claims.sub.len() > 255 {
        return Err(malformed("the ID token has no subject"));
    }
    Ok(claims.sub)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(public: &str) -> OAuthClient {
        let app = |id: &str| AppCredentials {
            client_id: id.to_owned(),
            client_secret: SecretString::from("s3cret".to_owned()),
        };
        OAuthClient::new(
            Http::for_tests(),
            Endpoints::default(),
            Url::parse(public).unwrap_or_else(|_| unreachable!()),
            Some(app("ms-client")),
            Some(app("google-client")),
        )
    }

    fn query(url: &Url) -> std::collections::HashMap<String, String> {
        url.query_pairs().into_owned().collect()
    }

    #[test]
    fn builds_microsoft_authorize_urls() {
        let client = client("https://mail.example.com/");
        let url = client
            .authorize_url(UpstreamProvider::Microsoft, "st", "ch", None)
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert_eq!(
            url.as_str().split('?').next(),
            Some("https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
        );
        let q = query(&url);
        assert_eq!(q["client_id"], "ms-client");
        assert_eq!(
            q["redirect_uri"],
            "https://mail.example.com/oauth/microsoft/callback"
        );
        assert_eq!(
            q["scope"],
            "offline_access User.Read Mail.ReadWrite Mail.Send"
        );
        assert_eq!(q["state"], "st");
        assert_eq!(q["code_challenge"], "ch");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(q["response_type"], "code");
        assert!(!q.contains_key("client_secret"));
    }

    #[test]
    fn builds_google_authorize_urls() {
        let client = client("https://mail.example.com/base/?x=1");
        let url = client
            .authorize_url(UpstreamProvider::Google, "st", "ch", Some("a@example.com"))
            .unwrap_or_else(|e| unreachable!("{e}"));
        assert!(
            url.as_str()
                .starts_with("https://accounts.google.com/o/oauth2/v2/auth?")
        );
        let q = query(&url);
        assert_eq!(
            q["redirect_uri"],
            "https://mail.example.com/oauth/google/callback"
        );
        assert_eq!(q["access_type"], "offline");
        assert_eq!(q["prompt"], "consent");
        assert_eq!(q["login_hint"], "a@example.com");
        assert_eq!(
            q["scope"],
            "openid https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/gmail.send"
        );
        assert!(!q.contains_key("include_granted_scopes"));
    }

    #[test]
    fn unconfigured_providers_are_refused() {
        let client = OAuthClient::new(
            Http::for_tests(),
            Endpoints::default(),
            Url::parse("https://mail.example.com").unwrap_or_else(|_| unreachable!()),
            None,
            None,
        );
        assert_eq!(client.configured(), Vec::<UpstreamProvider>::new());
        assert!(matches!(
            client.authorize_url(UpstreamProvider::Google, "s", "c", None),
            Err(OAuthError::NotConfigured(UpstreamProvider::Google))
        ));
    }

    #[test]
    fn checks_granted_scopes() {
        let ms = UpstreamProvider::Microsoft;
        assert!(check_scopes(ms, Some("https://graph.microsoft.com/Mail.ReadWrite https://graph.microsoft.com/Mail.Send User.Read")).is_ok());
        assert!(check_scopes(ms, Some("mail.readwrite mail.send")).is_ok());
        assert!(matches!(
            check_scopes(ms, Some("User.Read Mail.ReadWrite")),
            Err(OAuthError::MissingScopes(missing)) if missing == ["Mail.Send"]
        ));
        let google = UpstreamProvider::Google;
        assert!(
            check_scopes(
                google,
                Some("openid https://www.googleapis.com/auth/gmail.modify")
            )
            .is_ok()
        );
        assert!(
            check_scopes(
                google,
                Some("openid https://www.googleapis.com/auth/gmail.send")
            )
            .is_err()
        );
        assert!(check_scopes(google, None).is_ok());
    }

    #[test]
    fn classifies_provider_errors() {
        let status = http::StatusCode::BAD_REQUEST;
        let reauth = provider_error(
            UpstreamProvider::Microsoft,
            status,
            &HeaderMap::new(),
            br#"{"error":"invalid_grant","error_description":"AADSTS70008: expired"}"#,
        );
        assert!(
            matches!(reauth, OAuthError::NeedsReauth { ref code, .. } if code == "invalid_grant")
        );
        assert!(!reauth.is_transient());
        let graph = provider_error(
            UpstreamProvider::Microsoft,
            http::StatusCode::FORBIDDEN,
            &HeaderMap::new(),
            br#"{"error":{"code":"ErrorAccessDenied","message":"Access is denied.\nmore"}}"#,
        );
        assert!(matches!(
            graph,
            OAuthError::Rejected { ref code, description: Some(ref d), .. }
                if code == "ErrorAccessDenied" && d == "Access is denied."
        ));
        let gmail = provider_error(
            UpstreamProvider::Google,
            http::StatusCode::NOT_FOUND,
            &HeaderMap::new(),
            br#"{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND"}}"#,
        );
        assert!(matches!(gmail, OAuthError::Rejected { ref code, .. } if code == "404"));
        let opaque = provider_error(
            UpstreamProvider::Google,
            http::StatusCode::BAD_GATEWAY,
            &HeaderMap::new(),
            b"<html>",
        );
        assert!(opaque.is_transient());
    }

    #[test]
    fn symbolic_oauth_errors_preserve_response_status_and_delay() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::RETRY_AFTER,
            http::HeaderValue::from_static("12"),
        );
        for code in [
            "temporarily_unavailable",
            "server_error",
            "slow_down",
            "invalid_grant",
        ] {
            let (status, limited, unavailable) = match code {
                "slow_down" => (StatusCode::TOO_MANY_REQUESTS, true, false),
                "invalid_grant" => (StatusCode::BAD_REQUEST, false, false),
                _ => (StatusCode::SERVICE_UNAVAILABLE, false, true),
            };
            let body = serde_json::json!({"error": code}).to_string();
            let err = provider_error(
                UpstreamProvider::Microsoft,
                status,
                &headers,
                body.as_bytes(),
            );
            assert_eq!(err.is_rate_limited(), limited);
            assert_eq!(err.is_server_unavailable(), unavailable);
            assert_eq!(err.is_transient(), limited || unavailable);
            assert_eq!(err.retry_after(), (limited || unavailable).then_some(12));
        }
    }

    fn jwt(claims: &serde_json::Value) -> String {
        let encode = |value: &[u8]| URL_SAFE_NO_PAD.encode(value);
        format!(
            "{}.{}.sig",
            encode(br#"{"alg":"RS256"}"#),
            encode(claims.to_string().as_bytes())
        )
    }

    #[test]
    fn reads_google_subjects() {
        let now = chrono::Utc::now().timestamp();
        let good = serde_json::json!({"iss":"https://accounts.google.com","aud":"cid","sub":"1234","exp":now + 600});
        assert_eq!(
            google_subject(&jwt(&good), "cid").ok().as_deref(),
            Some("1234")
        );
        for bad in [
            serde_json::json!({"iss":"https://evil.example","aud":"cid","sub":"1","exp":now + 600}),
            serde_json::json!({"iss":"accounts.google.com","aud":"other","sub":"1","exp":now + 600}),
            serde_json::json!({"iss":"accounts.google.com","aud":"cid","sub":"","exp":now + 600}),
            serde_json::json!({"iss":"accounts.google.com","aud":"cid","sub":"1","exp":now - 3600}),
        ] {
            assert!(google_subject(&jwt(&bad), "cid").is_err(), "{bad}");
        }
        assert!(google_subject("not-a-jwt", "cid").is_err());
    }

    #[test]
    fn debug_output_hides_secrets() {
        let client = client("https://mail.example.com");
        assert!(!format!("{client:?}").contains("s3cret"));
        let token = TokenResponse {
            access_token: SecretString::from("at-secret".to_owned()),
            refresh_token: Some(SecretString::from("rt-secret".to_owned())),
            expires_in: Some(3600),
            scope: None,
            id_token: None,
        };
        let debug = format!("{token:?}");
        assert!(!debug.contains("at-secret") && !debug.contains("rt-secret"));
    }
}
