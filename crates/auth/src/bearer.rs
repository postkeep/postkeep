//! Bearer token middleware for the protected MCP endpoint (RFC 6750), and
//! the [`PrincipalResolver`] it asks who a token belongs to.

use std::future::Future;
use std::pin::Pin;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use postkeep_store::{AccountId, GrantSubject, StoreError, TokenGrant};

use crate::state::AuthState;

/// Tenant of every principal the default resolver returns.
pub const DEFAULT_TENANT: &str = "default";

/// The authenticated caller, inserted into the request extensions by
/// [`require_bearer`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Authenticated {
    /// The connected mailbox account.
    pub account_id: AccountId,
    /// The OAuth client that holds the token.
    pub client_id: String,
    /// The granted scope.
    pub scope: String,
    /// The tenant the principal belongs to; [`DEFAULT_TENANT`] unless a
    /// [`PrincipalResolver`] says otherwise. The request log writes it, so
    /// it must hold no address or secret.
    pub tenant: String,
    /// Who is calling, as an opaque string. The default resolver uses the
    /// account ID. The request log writes it, so it must hold no address or
    /// secret.
    pub principal: String,
    /// Every mailbox the caller may use, `account_id` first. With a
    /// resolver whose [`PrincipalResolver::selects_mailboxes`] is true, a
    /// tool call picks one of them by ID or address; otherwise only
    /// `account_id` is used.
    pub mailboxes: Vec<AccountId>,
}

impl Authenticated {
    /// A caller acting for `account_id` in the default tenant, with the
    /// account ID as principal and no other mailbox.
    #[must_use]
    pub fn for_account(account_id: AccountId, client_id: String, scope: String) -> Self {
        let principal = account_id.0.clone();
        let mailboxes = vec![account_id.clone()];
        Self {
            account_id,
            client_id,
            scope,
            tenant: DEFAULT_TENANT.to_owned(),
            principal,
            mailboxes,
        }
    }

    /// The same caller, also allowed to use `mailboxes`. `account_id` stays
    /// the default and stays allowed.
    #[must_use]
    pub fn with_mailboxes(mut self, mailboxes: impl IntoIterator<Item = AccountId>) -> Self {
        let mut allowed = vec![self.account_id.clone()];
        for mailbox in mailboxes {
            if !allowed.contains(&mailbox) {
                allowed.push(mailbox);
            }
        }
        self.mailboxes = allowed;
        self
    }

    /// Whether the caller may use `mailbox`.
    #[must_use]
    pub fn may_use(&self, mailbox: &AccountId) -> bool {
        *mailbox == self.account_id || self.mailboxes.contains(mailbox)
    }

    /// The same caller in `tenant`.
    #[must_use]
    pub fn with_tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant = tenant.into();
        self
    }

    /// The same caller as `principal`.
    #[must_use]
    pub fn with_principal(mut self, principal: impl Into<String>) -> Self {
        self.principal = principal.into();
        self
    }
}

/// What a [`PrincipalResolver`] decided about a bearer token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// The token is valid.
    Authenticated(Authenticated),
    /// The token is refused. The text becomes the `error_description` of
    /// the `401` challenge, so it must not repeat the token.
    Refused(&'static str),
}

/// The future a [`PrincipalResolver`] returns.
pub type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Resolution, StoreError>> + Send + 'a>>;

/// The request a [`PrincipalResolver`] decides about.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct BearerRequest<'a> {
    /// The request's headers, for example its `Host`.
    pub headers: &'a HeaderMap,
    /// The protected resource the request addresses, from
    /// [`AuthConfig::resource_for`](crate::AuthConfig::resource_for).
    /// `None` when per-request resources are on and the request's host or
    /// path is not one of this server's resources.
    pub resource: Option<&'a str>,
}

impl<'a> BearerRequest<'a> {
    /// A request with `headers` that addresses `resource`.
    #[must_use]
    pub const fn new(headers: &'a HeaderMap, resource: Option<&'a str>) -> Self {
        Self { headers, resource }
    }
}

/// Decides who a bearer token on the MCP endpoint belongs to.
///
/// The default, [`TokenResolver`], looks the token up among the access
/// tokens this server issued. An embedding can replace it, for example to
/// accept its own API keys or to put callers in tenants, with
/// [`AuthState::set_principal_resolver`]. A resolver that also takes this
/// server's access tokens, including those for principals, looks them up
/// with [`AuthState::access_grant`]. A storage error answers `500`.
pub trait PrincipalResolver: Send + Sync + 'static {
    /// Resolves `token`, the credential after `Bearer `, presented in
    /// `request`.
    fn resolve<'a>(
        &'a self,
        state: &'a AuthState,
        token: &'a str,
        request: BearerRequest<'a>,
    ) -> ResolveFuture<'a>;

    /// Whether a principal may hold several mailboxes
    /// ([`Authenticated::mailboxes`]). When true, every MCP tool takes an
    /// optional `mailbox` argument, an ID or address among the caller's
    /// mailboxes; anything else fails as an unknown mailbox. The server
    /// reads this once, when it builds its router. Default: false, and the
    /// tools act on [`Authenticated::account_id`] only.
    fn selects_mailboxes(&self) -> bool {
        false
    }
}

/// The default resolver: an access token issued by this server, whose
/// grant is for a mailbox account with an allowed address and names this
/// server's resource.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokenResolver;

impl PrincipalResolver for TokenResolver {
    fn resolve<'a>(
        &'a self,
        state: &'a AuthState,
        token: &'a str,
        request: BearerRequest<'a>,
    ) -> ResolveFuture<'a> {
        Box::pin(async move {
            let grant = match state.access_grant(token, request).await? {
                Ok(grant) => grant,
                Err(refusal) => return Ok(Resolution::Refused(refusal)),
            };
            let (GrantSubject::Account(account_id), Some(email)) = (grant.subject, grant.email)
            else {
                return Ok(Resolution::Refused(
                    "the access token is not for a mailbox account",
                ));
            };
            if !state.config().email_allowed(&email) {
                return Ok(Resolution::Refused(
                    "this account is not allowed on this server",
                ));
            }
            Ok(Resolution::Authenticated(Authenticated::for_account(
                account_id,
                grant.client_id,
                grant.scope,
            )))
        })
    }
}

impl AuthState {
    /// The grant behind `token`, an access token this server issued, if it
    /// has not expired and is for the resource `request` addresses. With
    /// per-request resources the grant must name exactly that resource;
    /// otherwise any resource this server accepts, or none. If not, the
    /// reason, for [`Resolution::Refused`].
    ///
    /// The grant can be for a mailbox account or for a principal; the
    /// caller decides which it accepts. The address allow-list is not
    /// applied.
    ///
    /// # Errors
    ///
    /// Returns an error if the store fails.
    pub async fn access_grant(
        &self,
        token: &str,
        request: BearerRequest<'_>,
    ) -> Result<Result<TokenGrant, &'static str>, StoreError> {
        let Some(grant) = self.store().access_token(token).await? else {
            return Ok(Err("the access token is invalid or expired"));
        };
        let config = self.config();
        if config.per_request_resources {
            // Audience binding: the token must name exactly the resource the
            // request addresses.
            let Some(expected) = request.resource else {
                return Ok(Err("this URL is not served here"));
            };
            match grant.resource.as_deref() {
                None => return Ok(Err("the access token names no resource")),
                Some(resource) if resource != expected => {
                    return Ok(Err("the access token is for another resource"));
                }
                Some(_) => {}
            }
        } else if let Some(resource) = grant.resource.as_deref()
            && !config.accepts_resource(resource)
        {
            return Ok(Err("the access token is for another resource"));
        }
        Ok(Ok(grant))
    }
}

/// Middleware that requires a valid access token.
///
/// On success it inserts [`Authenticated`] into the request extensions. On
/// failure it answers `401` with a `WWW-Authenticate` header pointing at the
/// protected resource metadata, which is how MCP clients discover the
/// authorization server.
pub async fn require_bearer(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    let token = bearer_token(&request);
    let Some(token) = token else {
        return unauthorized(&state, &request, None);
    };
    let resolver = state.principal_resolver();
    let resource = state
        .config()
        .resource_for(request.headers(), request.uri().path());
    let presented = BearerRequest::new(request.headers(), resource.as_deref());
    match resolver.resolve(&state, &token, presented).await {
        Ok(Resolution::Authenticated(caller)) => {
            request.extensions_mut().insert(caller);
            next.run(request).await
        }
        Ok(Resolution::Refused(description)) => unauthorized(&state, &request, Some(description)),
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn bearer_token(request: &Request) -> Option<String> {
    let value = request
        .headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_owned())
}

fn unauthorized(state: &AuthState, request: &Request, error: Option<&str>) -> Response {
    let metadata = state
        .config()
        .resource_metadata_url_for(request.headers(), request.uri().path());
    let challenge = error.map_or_else(
        || format!("Bearer resource_metadata=\"{metadata}\""),
        |description| {
            format!(
                "Bearer resource_metadata=\"{metadata}\", error=\"invalid_token\", error_description=\"{description}\""
            )
        },
    );
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}
