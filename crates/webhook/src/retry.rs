//! Retries with backoff.

use std::time::Duration;

use http::StatusCode;

use crate::client::{Deliverer, DeliveryError, Outgoing, Response};

/// Waits before each retry: 2 s, 10 s, then 60 s, so at most four attempts.
pub const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(2),
    Duration::from_secs(10),
    Duration::from_secs(60),
];

/// Whether a response status means the event was accepted.
#[must_use]
pub fn is_success(status: StatusCode) -> bool {
    status.is_success()
}

/// Whether a status is worth retrying: server errors, `408` and `429`.
/// Redirects and other client errors are final (redirects are never
/// followed).
#[must_use]
pub fn is_retryable(status: StatusCode) -> bool {
    status.is_server_error()
        || status == StatusCode::REQUEST_TIMEOUT
        || status == StatusCode::TOO_MANY_REQUESTS
}

/// The result of delivering one event, after any retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// How many attempts were made (at least 1).
    pub attempts: u32,
    /// The last attempt's result.
    pub result: Result<Response, DeliveryError>,
}

impl Delivery {
    /// Whether the event was accepted with a `2xx` status.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        matches!(&self.result, Ok(response) if is_success(response.status))
    }

    /// A one-line description for the account page, such as
    /// `HTTP 401 Unauthorized (after 1 attempt)`.
    #[must_use]
    pub fn summary(&self) -> String {
        let what = match &self.result {
            Ok(response) => format!(
                "HTTP {} {}",
                response.status.as_u16(),
                response.status.canonical_reason().unwrap_or("")
            )
            .trim_end()
            .to_owned(),
            Err(err) => err.to_string(),
        };
        let plural = if self.attempts == 1 { "" } else { "s" };
        format!("{what} (after {} attempt{plural})", self.attempts)
    }
}

/// Sends `request`, retrying transient failures after each of `delays`.
pub async fn deliver(deliverer: &Deliverer, request: &Outgoing, delays: &[Duration]) -> Delivery {
    let mut attempts = 0;
    let mut delays = delays.iter();
    loop {
        attempts += 1;
        let result = deliverer.send(request).await;
        let retry = match &result {
            Ok(response) => is_retryable(response.status),
            Err(err) => err.is_transient(),
        };
        match delays.next() {
            Some(delay) if retry => {
                tracing::debug!(
                    attempt = attempts,
                    ?delay,
                    "webhook delivery failed; retrying"
                );
                tokio::time::sleep(*delay).await;
            }
            _ => return Delivery { attempts, result },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_statuses() {
        for code in [500, 502, 503, 504, 408, 429] {
            assert!(
                is_retryable(StatusCode::from_u16(code).unwrap_or_default()),
                "{code}"
            );
        }
        for code in [200, 204, 301, 302, 307, 400, 401, 403, 404, 410, 413] {
            assert!(
                !is_retryable(StatusCode::from_u16(code).unwrap_or_default()),
                "{code}"
            );
        }
        assert!(!DeliveryError::Blocked("x".into()).is_transient());
        assert!(DeliveryError::Timeout("x".into()).is_transient());
    }

    #[test]
    fn summaries() {
        let delivery = Delivery {
            attempts: 1,
            result: Ok(Response {
                status: StatusCode::UNAUTHORIZED,
                elapsed: Duration::from_millis(5),
            }),
        };
        assert_eq!(
            delivery.summary(),
            "HTTP 401 Unauthorized (after 1 attempt)"
        );
        assert!(!delivery.succeeded());
        let delivery = Delivery {
            attempts: 4,
            result: Err(DeliveryError::Timeout("hooks.example.com".into())),
        };
        assert_eq!(
            delivery.summary(),
            "hooks.example.com did not answer within 10 seconds (after 4 attempts)"
        );
    }
}
