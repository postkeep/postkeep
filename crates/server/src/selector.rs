//! The mailbox selector, for principal resolvers whose callers may use
//! several mailboxes ([`postkeep_auth::PrincipalResolver::selects_mailboxes`]).
//!
//! Every tool then takes an optional `mailbox` argument: the ID or address
//! of one of the caller's mailboxes. A resolver can also name a tenant
//! argument. Without an explicit tenant, the selector searches the caller's
//! tenancies for the mailbox, or uses the first tenancy if no mailbox is
//! named. A call always acts in one tenancy.
//! [`select_mailbox`] runs after the bearer check and before the per-account
//! limit. It takes the selector arguments out of a `tools/call` request,
//! narrows the caller and records the outcome as a [`Selection`], which
//! the tools and the limit read.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Extensions, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use postkeep_auth::Authenticated;
use postkeep_store::{AccountId, Store, StoreError};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::Tool;
use serde_json::{Map, Value, json};

use crate::request_log::Note;

/// Name of the tool argument.
pub const ARGUMENT: &str = "mailbox";

/// The tool error for a mailbox the caller cannot use, whatever the reason.
const UNKNOWN_MAILBOX: &str = "unknown mailbox: pass the id or address of a mailbox \
this connection can use, or leave mailbox out to use the default one";

const AMBIGUOUS_MAILBOX: &str =
    "several of this connection's mailboxes have this address: pass its id";

/// Added to the server instructions when selection is on.
pub const INSTRUCTIONS: &str = " This connection can use several mailboxes: every tool \
takes an optional mailbox argument, the id or address of one of them, and uses the default \
mailbox without it.";

const ARGUMENT_DESCRIPTION: &str =
    "Mailbox to use: its id or email address. Omit it to use the default mailbox.";

/// The mailbox a `tools/call` request named, as a request extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// One of the caller's mailboxes.
    Mailbox(AccountId),
    /// None: the call acts on the caller's default mailbox.
    Default,
    /// The selection failed, with a tool error explaining why.
    Refused(String),
}

/// The mailbox a tool call acts on.
pub fn account(extensions: &Extensions) -> Result<AccountId, String> {
    let auth = extensions
        .get::<Authenticated>()
        .ok_or_else(|| "not authenticated".to_owned())?;
    match extensions.get::<Selection>() {
        Some(Selection::Mailbox(account)) => Ok(account.clone()),
        Some(Selection::Refused(message)) => Err(message.clone()),
        Some(Selection::Default) | None => Ok(auth.account_id.clone()),
    }
}

/// The mailbox a request counts against for the per-account limit.
/// `None` before authentication.
pub fn limit_key(extensions: &Extensions) -> Option<AccountId> {
    let auth = extensions.get::<Authenticated>()?;
    Some(match extensions.get::<Selection>() {
        Some(Selection::Mailbox(account)) => account.clone(),
        Some(Selection::Default | Selection::Refused(_)) | None => auth.account_id.clone(),
    })
}

/// Adds the optional `mailbox` argument to every tool's input schema.
pub fn advertise<S>(router: &mut ToolRouter<S>) {
    for route in router.map.values_mut() {
        advertise_tool(&mut route.attr);
    }
}

/// Adds the optional `mailbox` argument to `tool`'s input schema unless it
/// has one.
pub fn advertise_tool(tool: &mut Tool) {
    let schema = Arc::make_mut(&mut tool.input_schema);
    let properties = schema
        .entry("properties")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Value::Object(properties) = properties {
        properties
            .entry(ARGUMENT)
            .or_insert_with(|| json!({ "description": ARGUMENT_DESCRIPTION, "type": "string" }));
    }
}

/// State of [`select_mailbox`].
#[derive(Debug, Clone)]
pub struct MailboxSelector {
    store: Store,
    max_body_bytes: usize,
    tenant_argument: Option<&'static str>,
}

impl MailboxSelector {
    pub const fn new(
        store: Store,
        max_body_bytes: usize,
        tenant_argument: Option<&'static str>,
    ) -> Self {
        Self {
            store,
            max_body_bytes,
            tenant_argument,
        }
    }

    async fn select<'a>(
        &self,
        auth: &'a Authenticated,
        tenant: Option<(&str, &Value)>,
        mailbox: Option<&Value>,
    ) -> Result<(Selection, Option<&'a Authenticated>), StoreError> {
        let refused = |message: &str| (Selection::Refused(message.to_owned()), None);
        let tenancies = auth.tenancies();
        let candidates = match tenant.map(|(name, value)| (name, argument(Some(value)))) {
            None | Some((_, Ok(None))) => tenancies,
            Some((name, requested)) => {
                let Some(tenancy) = requested
                    .ok()
                    .flatten()
                    .and_then(|id| tenancies.iter().find(|entry| entry.tenant == id))
                else {
                    return Ok((
                        Selection::Refused(format!(
                            "unknown {name}: pass the id of one this connection can use"
                        )),
                        None,
                    ));
                };
                std::slice::from_ref(tenancy)
            }
        };
        let name = match argument(mailbox) {
            Ok(Some(name)) => name,
            Ok(None) => return Ok((Selection::Default, candidates.first())),
            Err(()) => return Ok(refused(UNKNOWN_MAILBOX)),
        };
        let mut found = None;
        for tenancy in candidates {
            if let Some(account) = self
                .store
                .for_tenant(&tenancy.tenant)
                .find_account(name)
                .await?
                && tenancy.may_use(&account.id)
            {
                if found.is_some() {
                    return Ok(refused(AMBIGUOUS_MAILBOX));
                }
                found = Some((Selection::Mailbox(account.id), Some(tenancy)));
            }
        }
        Ok(found.unwrap_or_else(|| refused(UNKNOWN_MAILBOX)))
    }
}

fn argument(value: Option<&Value>) -> Result<Option<&str>, ()> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.trim()).filter(|value| !value.is_empty())),
        Some(_) => Err(()),
    }
}

/// Middleware that takes the tenant and mailbox arguments out of a
/// `tools/call` request and records the narrowed caller and [`Selection`].
///
/// Anything else, including a body that is not a JSON-RPC object, passes
/// unchanged; the MCP service answers it.
pub async fn select_mailbox(
    State(selector): State<MailboxSelector>,
    request: Request,
    next: Next,
) -> Response {
    if request.method() != Method::POST {
        return next.run(request).await;
    }
    let (mut parts, body) = request.into_parts();
    let Some(auth) = parts.extensions.get::<Authenticated>() else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    let bytes = match axum::body::to_bytes(body, selector.max_body_bytes).await {
        Ok(bytes) => bytes,
        Err(err) => return unreadable_body(&err),
    };
    let Ok(Value::Object(mut message)) = serde_json::from_slice::<Value>(&bytes) else {
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    };
    if message.get("method").and_then(Value::as_str) != Some("tools/call") {
        return next
            .run(Request::from_parts(parts, Body::from(bytes)))
            .await;
    }
    let (tenant, mailbox) = message
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .and_then(|params| params.get_mut("arguments"))
        .and_then(Value::as_object_mut)
        .map_or((None, None), |arguments| {
            let mailbox = arguments.remove(ARGUMENT);
            let tenant = selector
                .tenant_argument
                .and_then(|name| arguments.remove(name).map(|value| (name, value)));
            (tenant, mailbox)
        });
    let (selection, tenancy) = match selector
        .select(
            auth,
            tenant.as_ref().map(|(name, value)| (*name, value)),
            mailbox.as_ref(),
        )
        .await
    {
        Ok(result) => result,
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if matches!(selection, Selection::Refused(_)) {
        tracing::info!("refused a tool call for a tenant or mailbox the caller cannot use");
    }
    // A caller without a tenancy list is already its own selected tenancy.
    if let Some(tenancy) = tenancy
        && !std::ptr::eq(auth, tenancy)
        && let Some(caller) = auth.in_tenant(&tenancy.tenant)
    {
        if let Some(note) = parts.extensions.get::<Note>() {
            note.caller(&caller);
        }
        parts.extensions.insert(caller);
    }
    parts.extensions.insert(selection);
    let body = if tenant.is_some() || mailbox.is_some() {
        let bytes = Value::Object(message).to_string().into_bytes();
        parts.headers.remove(header::TRANSFER_ENCODING);
        parts
            .headers
            .insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
        Body::from(bytes)
    } else {
        Body::from(bytes)
    };
    next.run(Request::from_parts(parts, body)).await
}

fn unreadable_body(err: &axum::Error) -> Response {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(err) = source {
        if err.is::<http_body_util::LengthLimitError>() {
            return (StatusCode::PAYLOAD_TOO_LARGE, "length limit exceeded").into_response();
        }
        source = err.source();
    }
    StatusCode::BAD_REQUEST.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> Authenticated {
        Authenticated::for_account(
            AccountId("a".to_owned()),
            "client".to_owned(),
            "mail".to_owned(),
        )
    }

    #[test]
    fn tools_act_on_the_selection_or_the_token_account() {
        let mut extensions = Extensions::new();
        assert_eq!(account(&extensions), Err("not authenticated".to_owned()));
        assert_eq!(limit_key(&extensions), None);

        extensions.insert(caller());
        assert_eq!(account(&extensions), Ok(AccountId("a".to_owned())));
        assert_eq!(limit_key(&extensions), Some(AccountId("a".to_owned())));

        extensions.insert(Selection::Default);
        assert_eq!(account(&extensions), Ok(AccountId("a".to_owned())));
        assert_eq!(limit_key(&extensions), Some(AccountId("a".to_owned())));

        extensions.insert(Selection::Mailbox(AccountId("b".to_owned())));
        assert_eq!(account(&extensions), Ok(AccountId("b".to_owned())));
        assert_eq!(limit_key(&extensions), Some(AccountId("b".to_owned())));

        extensions.insert(Selection::Refused("refused selection".to_owned()));
        assert_eq!(account(&extensions), Err("refused selection".to_owned()));
        assert_eq!(limit_key(&extensions), Some(AccountId("a".to_owned())));
    }
}
