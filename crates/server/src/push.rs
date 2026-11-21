//! Public endpoints that Microsoft Graph and Google Pub/Sub call when new
//! mail arrives.
//!
//! | Path | Caller | Verification |
//! | ---- | ------ | ------------ |
//! | `POST /push/microsoft` | Graph change notifications | `clientState` of the stored subscription, compared in constant time |
//! | `POST /push/microsoft/lifecycle` | Graph lifecycle notifications | the same |
//! | `POST /push/google` | Cloud Pub/Sub push (Gmail `users.watch`) | Google-signed OIDC token: signature, issuer, audience, expiry and service account |
//!
//! Both Graph endpoints also answer Graph's validation request
//! (`?validationToken=...`) by echoing the token as `text/plain`.
//!
//! A verified notification is only a signal for the subscription it names
//! (see [`crate::watch`]); nothing else in the request body is trusted.
//! Change notifications schedule a catch-up. Lifecycle notifications are
//! applied to that same subscription id, so a late event cannot act on a
//! subscription that has replaced it. Well-formed requests are always
//! acknowledged with `202` so a sender learns nothing about which
//! subscriptions exist.
//! Authenticated Pub/Sub pushes are acknowledged with `204` whether or not
//! they name a watched account, so Pub/Sub does not redeliver them.

use std::collections::HashSet;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use postkeep_store::{AccountId, Provider};
use serde::Deserialize;

use crate::watch::Watchers;

/// Graph change notifications.
pub const GRAPH_PATH: &str = "/push/microsoft";
/// Graph lifecycle notifications.
pub const GRAPH_LIFECYCLE_PATH: &str = "/push/microsoft/lifecycle";

/// Cloud Pub/Sub pushes for Gmail.
pub const GOOGLE_PATH: &str = "/push/google";

/// Notifications handled per request; Graph batches far fewer.
const MAX_NOTIFICATIONS: usize = 100;
/// Longest validation token echoed back.
const MAX_VALIDATION_TOKEN: usize = 1024;

/// The push routes.
pub fn router(watchers: Watchers) -> Router {
    Router::new()
        .route(GRAPH_PATH, post(graph_notifications))
        .route(GRAPH_LIFECYCLE_PATH, post(graph_lifecycle))
        .route(GOOGLE_PATH, post(google_push))
        .with_state(watchers)
}

#[derive(Debug, Deserialize)]
struct Validation {
    #[serde(rename = "validationToken")]
    validation_token: Option<String>,
}

/// One Graph notification; only the fields postkeep uses.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNotification {
    /// The subscription it belongs to.
    pub subscription_id: Option<String>,
    /// The secret set when subscribing.
    pub client_state: Option<String>,
    /// For lifecycle notifications: `reauthorizationRequired`,
    /// `subscriptionRemoved` or `missed`.
    pub lifecycle_event: Option<String>,
}

/// A batch of Graph notifications.
#[derive(Debug, Deserialize)]
pub struct GraphBatch {
    /// The notifications.
    pub value: Vec<GraphNotification>,
}

/// Parses a Graph notification body.
///
/// # Errors
///
/// Returns the parse error for malformed bodies.
pub fn parse_graph_batch(body: &[u8]) -> Result<GraphBatch, serde_json::Error> {
    serde_json::from_slice(body)
}

fn validation_response(token: String) -> Response {
    if token.len() > MAX_VALIDATION_TOKEN || token.chars().any(char::is_control) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        token,
    )
        .into_response()
}

/// One Graph notification whose subscription id and `clientState` match a
/// stored Graph subscription.
struct VerifiedNotification {
    account: AccountId,
    /// The id that matched. Later work must use this id, not whatever the
    /// account stores by the time a background task runs.
    subscription_id: String,
    lifecycle_event: Option<String>,
}

/// The verified notifications in `batch`.
///
/// The same account, subscription id and lifecycle event are returned
/// once. A different event or a different subscription is kept.
async fn verified(watchers: &Watchers, batch: &GraphBatch) -> Vec<VerifiedNotification> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut rejected = 0usize;
    for notification in batch.value.iter().take(MAX_NOTIFICATIONS) {
        let (Some(id), Some(state)) = (&notification.subscription_id, &notification.client_state)
        else {
            rejected += 1;
            continue;
        };
        match watchers.store().push_subscription_by_id(id).await {
            Ok(Some((account, subscription)))
                if subscription.provider == Provider::Graph
                    && subscription.client_state_matches(state) =>
            {
                let subscription_id = id.clone();
                let lifecycle_event = notification.lifecycle_event.clone();
                if seen.insert((
                    account.clone(),
                    subscription_id.clone(),
                    lifecycle_event.clone(),
                )) {
                    out.push(VerifiedNotification {
                        account,
                        subscription_id,
                        lifecycle_event,
                    });
                }
            }
            Ok(_) => rejected += 1,
            Err(err) => {
                tracing::error!(error = %err, "could not look up a Graph subscription");
            }
        }
    }
    if rejected > 0 {
        tracing::warn!(
            rejected,
            "ignored Graph notifications with an unknown subscription or a wrong clientState"
        );
    }
    out
}

async fn graph_notifications(
    State(watchers): State<Watchers>,
    Query(validation): Query<Validation>,
    body: Bytes,
) -> Response {
    if let Some(token) = validation.validation_token {
        return validation_response(token);
    }
    let Ok(batch) = parse_graph_batch(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    for notification in verified(&watchers, &batch).await {
        watchers.schedule_graph_catch_up(&notification.account);
    }
    StatusCode::ACCEPTED.into_response()
}

async fn graph_lifecycle(
    State(watchers): State<Watchers>,
    Query(validation): Query<Validation>,
    body: Bytes,
) -> Response {
    if let Some(token) = validation.validation_token {
        return validation_response(token);
    }
    let Ok(batch) = parse_graph_batch(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    for notification in verified(&watchers, &batch).await {
        if let Some(event) = notification.lifecycle_event {
            watchers.schedule_graph_lifecycle(
                &notification.account,
                notification.subscription_id,
                event,
            );
        }
    }
    StatusCode::ACCEPTED.into_response()
}

async fn google_push(
    State(watchers): State<Watchers>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let Some(google) = watchers.push().and_then(|push| push.google.clone()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
    else {
        tracing::warn!("refused a Pub/Sub push without a bearer token");
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if let Err(err) = google.verifier.verify(token.trim(), &google.expected).await {
        if matches!(err, postkeep_upstream::PushTokenError::Keys(_)) {
            tracing::error!(error = %err, "could not verify a Pub/Sub push");
            // Pub/Sub redelivers later.
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        tracing::warn!(error = %err, "refused a Pub/Sub push");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let notification = match postkeep_upstream::pubsub::parse_push_body(&body) {
        Ok(notification) => notification,
        Err(what) => {
            // Authentic but unusable: acknowledge so it is not redelivered.
            tracing::warn!(problem = what, "ignored an unreadable Pub/Sub push");
            return StatusCode::NO_CONTENT.into_response();
        }
    };
    match watchers
        .store()
        .account_by_email(&notification.email_address, Provider::Gmail)
        .await
    {
        Ok(Some(account)) => match watchers.store().push_subscription(&account.id).await {
            Ok(Some(subscription)) if subscription.provider == Provider::Gmail => {
                watchers.schedule_gmail_catch_up(&account.id);
            }
            Ok(_) => {
                tracing::debug!(account_id = %account.id, "ignored a Pub/Sub push for an unwatched account");
            }
            Err(err) => {
                tracing::error!(error = %err, "could not look up a Gmail watch");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        },
        Ok(None) => tracing::debug!("ignored a Pub/Sub push for an unknown mailbox"),
        Err(err) => {
            tracing::error!(error = %err, "could not look up a Gmail account");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_graph_batches() {
        let batch = parse_graph_batch(
            br#"{"value":[{"subscriptionId":"s","clientState":"c","changeType":"created",
            "resource":"Users/x/Messages/y","resourceData":{"id":"y"}}]}"#,
        )
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(batch.value[0].subscription_id.as_deref(), Some("s"));
        assert!(parse_graph_batch(b"{}").is_err());
    }

    #[test]
    fn validation_tokens_are_echoed_as_plain_text_only_when_sane() {
        let ok = validation_response("Validation: Testing client application!".to_owned());
        assert_eq!(ok.status(), StatusCode::OK);
        assert_eq!(
            ok.headers()[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            validation_response("a\r\nb".to_owned()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            validation_response("x".repeat(2000)).status(),
            StatusCode::BAD_REQUEST
        );
    }
}
