//! The mailbox selector, for principal resolvers whose callers may use
//! several mailboxes ([`postkeep_auth::PrincipalResolver::selects_mailboxes`]).
//!
//! Every tool then takes an optional `mailbox` argument: the ID or address
//! of one of the caller's mailboxes ([`Authenticated::mailboxes`]). The
//! [`select_mailbox`] middleware runs after the bearer check and before the
//! per-account limit. It takes the argument out of a `tools/call` request
//! and records the outcome as a [`Selection`], which the tools and the
//! limit read. A name that is not one of the caller's mailboxes, does not
//! exist, or belongs to another tenant gives the same [`UNKNOWN_MAILBOX`]
//! error. Without the argument the request acts on
//! [`Authenticated::account_id`], as it does when selection is off.

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

/// Name of the tool argument.
pub const ARGUMENT: &str = "mailbox";

/// The tool error for a mailbox the caller cannot use, whatever the reason.
pub const UNKNOWN_MAILBOX: &str = "unknown mailbox: pass the id or address of a mailbox \
this connection can use, or leave mailbox out to use the default one";

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
    /// A mailbox the caller cannot use.
    Unknown,
}

/// The mailbox a tool call acts on.
pub fn account(extensions: &Extensions) -> Result<AccountId, String> {
    let auth = extensions
        .get::<Authenticated>()
        .ok_or_else(|| "not authenticated".to_owned())?;
    match extensions.get::<Selection>() {
        Some(Selection::Mailbox(account)) => Ok(account.clone()),
        Some(Selection::Unknown) => Err(UNKNOWN_MAILBOX.to_owned()),
        Some(Selection::Default) | None => Ok(auth.account_id.clone()),
    }
}

/// The mailbox a request counts against for the per-account limit.
/// `None` before authentication.
pub fn limit_key(extensions: &Extensions) -> Option<AccountId> {
    let auth = extensions.get::<Authenticated>()?;
    Some(match extensions.get::<Selection>() {
        Some(Selection::Mailbox(account)) => account.clone(),
        Some(Selection::Default | Selection::Unknown) | None => auth.account_id.clone(),
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
}

impl MailboxSelector {
    pub const fn new(store: Store, max_body_bytes: usize) -> Self {
        Self {
            store,
            max_body_bytes,
        }
    }

    async fn select(
        &self,
        auth: &Authenticated,
        requested: Option<Value>,
    ) -> Result<Selection, StoreError> {
        let name = match requested {
            None | Some(Value::Null) => return Ok(Selection::Default),
            Some(Value::String(name)) => name,
            Some(_) => return Ok(Selection::Unknown),
        };
        if name.trim().is_empty() {
            return Ok(Selection::Default);
        }
        let found = self
            .store
            .for_tenant(&auth.tenant)
            .find_account(&name)
            .await?;
        Ok(match found {
            Some(account) if auth.may_use(&account.id) => Selection::Mailbox(account.id),
            _ => Selection::Unknown,
        })
    }
}

/// Middleware that resolves the `mailbox` argument of a `tools/call`
/// request into a [`Selection`] and removes it from the arguments, so the
/// tools never see it.
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
    let Some(auth) = request.extensions().get::<Authenticated>().cloned() else {
        return next.run(request).await;
    };
    let (mut parts, body) = request.into_parts();
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
    let requested = message
        .get_mut("params")
        .and_then(Value::as_object_mut)
        .and_then(|params| params.get_mut("arguments"))
        .and_then(Value::as_object_mut)
        .and_then(|arguments| arguments.remove(ARGUMENT));
    let rewrite = requested.is_some();
    let selection = match selector.select(&auth, requested).await {
        Ok(selection) => selection,
        Err(err) => {
            tracing::error!(error = %err, "storage error");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if selection == Selection::Unknown {
        tracing::info!("refused a tool call for a mailbox the caller cannot use");
    }
    parts.extensions.insert(selection);
    let body = if rewrite {
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

        extensions.insert(Selection::Unknown);
        assert_eq!(account(&extensions), Err(UNKNOWN_MAILBOX.to_owned()));
        assert_eq!(limit_key(&extensions), Some(AccountId("a".to_owned())));
    }
}
