//! Upstream OAuth for postkeep's Microsoft and Google accounts.
//!
//! postkeep is an OAuth authorization server for MCP clients. For Outlook
//! and Gmail accounts it is also an OAuth *client* of Microsoft or Google:
//! the user signs in there, postkeep stores the refresh token encrypted, and
//! exchanges it for short-lived access tokens to call Microsoft Graph or the
//! Gmail API.
//!
//! * [`api`]: authorized Graph and Gmail calls with one refresh on 401.
//! * [`http`]: a size- and time-limited HTTPS client for the fixed provider
//!   endpoints.
//! * [`oauth`]: authorization URLs, code exchange with PKCE, refresh,
//!   revocation and the signed-in identity.
//! * [`tokens`]: cached access tokens with serialized refresh and
//!   `invalid_grant` handling.
//! * [`pkce`]: PKCE and `state` values.
//! * [`pubsub`]: verification of Google Pub/Sub push requests (OIDC JWT).

pub mod api;
pub mod http;
pub mod oauth;
pub mod pkce;
pub mod pubsub;
pub mod tokens;

pub use api::{ApiClient, ApiError};
pub use http::{Endpoints, Http, HttpError, HttpResponse};
pub use oauth::{
    AppCredentials, Identity, OAuthClient, OAuthError, TokenResponse, UpstreamProvider,
};
pub use pubsub::{GmailNotification, PushClaims, PushExpectations, PushTokenError, PushVerifier};
pub use tokens::{TokenError, TokenManager};
