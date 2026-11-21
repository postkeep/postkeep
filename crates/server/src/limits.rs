//! Request-level limits: a global concurrency cap and a per-account cap on
//! concurrent MCP requests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use postkeep_store::AccountId;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How long an MCP request waits for a free per-account slot or room for a large forward.
pub(crate) const ACCOUNT_WAIT: Duration = Duration::from_secs(10);

const LARGE_MESSAGE_LIMIT: usize = postkeep_upstream::http::MESSAGE_LIMIT;
static LARGE_MESSAGES: Semaphore = Semaphore::const_new(LARGE_MESSAGE_LIMIT);

pub(crate) async fn large_message(
    size: usize,
) -> Result<tokio::sync::SemaphorePermit<'static>, String> {
    large_message_in(&LARGE_MESSAGES, size).await
}

async fn large_message_in(
    budget: &Semaphore,
    size: usize,
) -> Result<tokio::sync::SemaphorePermit<'_>, String> {
    const BUSY: &str =
        "Not sent: postkeep is busy with other large messages; try again in a minute.";
    let permits = u32::try_from(size.clamp(1, LARGE_MESSAGE_LIMIT)).map_err(|_| BUSY)?;
    tokio::time::timeout(ACCOUNT_WAIT, budget.acquire_many(permits))
        .await
        .map_err(|_| BUSY)?
        .map_err(|_| BUSY.to_owned())
}

/// Rejects requests with `503` once `max` are in flight.
#[derive(Debug, Clone)]
pub struct GlobalLimit(Arc<Semaphore>);

impl GlobalLimit {
    /// Allows `max` concurrent requests.
    #[must_use]
    pub fn new(max: usize) -> Self {
        Self(Arc::new(Semaphore::new(max.max(1))))
    }
}

/// Middleware for [`GlobalLimit`].
pub async fn limit_global(
    State(limit): State<GlobalLimit>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = limit.0.clone().try_acquire_owned() else {
        tracing::warn!("too many concurrent requests");
        return busy("the server is busy; retry shortly");
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

/// Limits concurrent MCP requests per account, so one client (or a stolen
/// token) cannot open dozens of iCloud connections at once. iCloud itself
/// limits simultaneous connections per account.
#[derive(Debug, Clone)]
pub struct AccountLimit {
    per_account: usize,
    wait: Duration,
    accounts: Arc<Mutex<HashMap<AccountId, Arc<Semaphore>>>>,
}

impl AccountLimit {
    /// Allows `per_account` concurrent requests per account; a request
    /// beyond that waits up to `wait` for a slot.
    #[must_use]
    pub fn new(per_account: usize, wait: Duration) -> Self {
        Self {
            per_account: per_account.max(1),
            wait,
            accounts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn acquire(&self, account: &AccountId) -> Option<OwnedSemaphorePermit> {
        let semaphore = {
            let mut accounts = self.accounts.lock().unwrap_or_else(PoisonError::into_inner);
            // Forget accounts with no request in flight.
            if accounts.len() > 1024 {
                accounts.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);
            }
            accounts
                .entry(account.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(self.per_account)))
                .clone()
        };
        tokio::time::timeout(self.wait, semaphore.acquire_owned())
            .await
            .ok()?
            .ok()
    }
}

/// Middleware for [`AccountLimit`]; runs after bearer authentication and
/// the mailbox selector, and counts a request against the mailbox it acts
/// on.
pub async fn limit_account(
    State(limit): State<AccountLimit>,
    request: Request,
    next: Next,
) -> Response {
    let Some(account) = crate::selector::limit_key(request.extensions()) else {
        return next.run(request).await;
    };
    let Some(permit) = limit.acquire(&account).await else {
        tracing::warn!(account_id = %account, "too many concurrent requests for one account");
        return busy("too many concurrent requests for this account; retry shortly");
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

fn busy(message: &'static str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, HeaderValue::from_static("1"))],
        message,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn large_forwards_wait_for_room_then_refuse_when_busy() {
        let budget = Semaphore::new(LARGE_MESSAGE_LIMIT);
        let size = LARGE_MESSAGE_LIMIT / 2 + 1;
        let first = large_message_in(&budget, size).await.unwrap();
        let (second, ()) = tokio::join!(large_message_in(&budget, size), async {
            tokio::time::sleep(ACCOUNT_WAIT / 2).await;
            drop(first);
        });
        let second = second.unwrap();
        let start = tokio::time::Instant::now();
        let busy = large_message_in(&budget, size).await.unwrap_err();
        assert!(busy.contains("busy with other large messages"));
        assert_eq!(start.elapsed(), ACCOUNT_WAIT);
        drop(second);
        let whole = large_message_in(&budget, LARGE_MESSAGE_LIMIT + 1)
            .await
            .unwrap();
        assert_eq!(whole.num_permits(), LARGE_MESSAGE_LIMIT);
    }

    #[tokio::test]
    async fn account_limit_is_per_account() {
        let limit = AccountLimit::new(1, Duration::from_millis(20));
        let a = AccountId("a".to_owned());
        let b = AccountId("b".to_owned());
        let first = limit.acquire(&a).await.unwrap();
        assert!(
            limit.acquire(&a).await.is_none(),
            "second request waits, then gives up"
        );
        assert!(limit.acquire(&b).await.is_some());
        drop(first);
        assert!(limit.acquire(&a).await.is_some());
    }

    #[tokio::test]
    async fn account_limit_counts_the_selected_mailbox() {
        use axum::Router;
        use axum::body::Body;
        use axum::routing::post;
        use postkeep_auth::Authenticated;
        use tower::ServiceExt;

        use crate::selector::Selection;

        let limit = AccountLimit::new(1, Duration::from_millis(20));
        let app = Router::new()
            .route("/", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                limit.clone(),
                limit_account,
            ));
        let send = |selection: Option<Selection>| {
            let app = app.clone();
            async move {
                let mut request = Request::post("/").body(Body::empty()).unwrap();
                request.extensions_mut().insert(Authenticated::for_account(
                    AccountId("a".to_owned()),
                    "client".to_owned(),
                    "mail".to_owned(),
                ));
                if let Some(selection) = selection {
                    request.extensions_mut().insert(selection);
                }
                app.oneshot(request).await.unwrap().status()
            }
        };
        let b = AccountId("b".to_owned());
        let busy_b = limit.acquire(&b).await.unwrap();
        assert_eq!(
            send(Some(Selection::Mailbox(b.clone()))).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(send(None).await, StatusCode::OK);
        assert_eq!(send(Some(Selection::Unknown)).await, StatusCode::OK);
        drop(busy_b);
        let busy_a = limit.acquire(&AccountId("a".to_owned())).await.unwrap();
        assert_eq!(
            send(Some(Selection::Mailbox(b))).await,
            StatusCode::OK,
            "a call for mailbox b does not wait for the token's mailbox"
        );
        assert_eq!(send(None).await, StatusCode::SERVICE_UNAVAILABLE);
        drop(busy_a);
    }
}
