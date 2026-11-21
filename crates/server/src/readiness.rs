//! `GET /readyz`: whether this process should be sent requests.
//!
//! `/healthz` says the process is alive. `/readyz` also fails while
//! migrations are pending, while an embedding's [`ReadinessCheck`] fails,
//! and from the first SIGINT or SIGTERM on, so a load balancer stops
//! routing to a process that is about to stop.

use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use postkeep_store::Store;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// The future a [`ReadinessCheck`] returns: `Ok(())` when ready, otherwise
/// the reason `/readyz` answers with.
pub type ReadinessFuture<'a> = Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

/// A condition `/readyz` waits for besides the database, for example an
/// embedding's warm-up; see [`crate::app::Extensions::readiness_check`].
pub trait ReadinessCheck: Send + Sync + 'static {
    /// Whether this process may be sent requests. The reason in `Err` is
    /// the body of the `503`, which anyone can request, so keep it short
    /// and free of secrets.
    fn check(&self) -> ReadinessFuture<'_>;
}

/// How long one answer is reused. Rounds of checks also run one at a time,
/// so a flood of requests holds at most one database connection.
const FRESH_FOR: Duration = Duration::from_secs(1);

/// Longest one round of checks may take before `/readyz` answers `503`.
const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

const DRAINING: &str = "draining";
const DATABASE_UNAVAILABLE: &str = "database unavailable";
const MIGRATIONS_PENDING: &str = "migrations pending";
const TIMED_OUT: &str = "readiness checks timed out";

/// What `/readyz` looks at.
pub(crate) struct Readiness {
    store: Store,
    checks: Vec<Arc<dyn ReadinessCheck>>,
    draining: CancellationToken,
    /// The last answer and when it was worked out. Held while a round of
    /// checks runs, so concurrent requests wait for that round; a request
    /// that goes away mid-round releases it to the next one.
    last: Mutex<Option<(Instant, Result<(), String>)>>,
}

impl Readiness {
    pub(crate) fn new(
        store: Store,
        checks: Vec<Arc<dyn ReadinessCheck>>,
        draining: CancellationToken,
    ) -> Self {
        Self {
            store,
            checks,
            draining,
            last: Mutex::new(None),
        }
    }

    /// `Ok(())` when ready, otherwise the reason.
    async fn answer(&self) -> Result<(), String> {
        if !self.draining.is_cancelled() {
            let answer = self.recent().await;
            if !self.draining.is_cancelled() {
                return answer;
            }
        }
        Err(DRAINING.to_owned())
    }

    /// The last answer if it is under [`FRESH_FOR`] old, otherwise a new
    /// one.
    async fn recent(&self) -> Result<(), String> {
        let mut last = self.last.lock().await;
        if let Some((at, answer)) = last.as_ref()
            && at.elapsed() < FRESH_FOR
        {
            return answer.clone();
        }
        let answer = tokio::time::timeout(CHECK_TIMEOUT, self.evaluate())
            .await
            .unwrap_or_else(|_| {
                tracing::warn!(timeout = ?CHECK_TIMEOUT, "readiness checks timed out");
                Err(TIMED_OUT.to_owned())
            });
        *last = Some((Instant::now(), answer.clone()));
        drop(last);
        answer
    }

    /// One round of checks: the database, its migrations, then each
    /// embedding check in the order it was added.
    async fn evaluate(&self) -> Result<(), String> {
        if let Err(err) = self.store.ping().await {
            tracing::error!(error = %err, "readiness check failed: the database does not answer");
            return Err(DATABASE_UNAVAILABLE.to_owned());
        }
        match self.store.pending_migrations().await {
            Ok(pending) if pending.is_empty() => {}
            Ok(pending) => {
                tracing::warn!(
                    ?pending,
                    "not ready: the database is missing migrations; run `postkeep migrate`"
                );
                return Err(MIGRATIONS_PENDING.to_owned());
            }
            Err(err) => {
                tracing::error!(error = %err, "readiness check failed: could not read the applied migrations");
                return Err(DATABASE_UNAVAILABLE.to_owned());
            }
        }
        for check in &self.checks {
            if let Err(reason) = check.check().await {
                tracing::debug!(%reason, "not ready");
                return Err(reason);
            }
        }
        Ok(())
    }
}

/// `200 ready`, or `503` with the reason.
pub(crate) async fn readyz(State(readiness): State<Arc<Readiness>>) -> Response {
    match readiness.answer().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(reason) => (StatusCode::SERVICE_UNAVAILABLE, reason).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use postkeep_store::MasterKey;

    use super::*;

    struct Counting(Arc<AtomicUsize>);

    impl ReadinessCheck for Counting {
        fn check(&self) -> ReadinessFuture<'_> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    async fn store(dir: &tempfile::TempDir) -> Store {
        let url = format!("sqlite://{}", dir.path().join("server.db").display());
        let key = MasterKey::parse(&MasterKey::generate_encoded().unwrap()).unwrap();
        Store::connect(&url, &key).await.unwrap()
    }

    #[tokio::test]
    async fn draining_wins_without_asking_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(&dir).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let draining = CancellationToken::new();
        let readiness = Readiness::new(
            store.clone(),
            vec![Arc::new(Counting(calls.clone()))],
            draining.clone(),
        );
        assert_eq!(readiness.answer().await, Ok(()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        draining.cancel();
        store.close().await;
        assert_eq!(readiness.answer().await, Err(DRAINING.to_owned()));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no round of checks ran");
    }

    #[tokio::test]
    async fn an_answer_is_reused_for_a_second() {
        let dir = tempfile::tempdir().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let readiness = Arc::new(Readiness::new(
            store(&dir).await,
            vec![Arc::new(Counting(calls.clone()))],
            CancellationToken::new(),
        ));
        let probes: Vec<_> = (0..50)
            .map(|_| {
                let readiness = readiness.clone();
                tokio::spawn(async move { readiness.answer().await })
            })
            .collect();
        for probe in probes {
            assert_eq!(probe.await.unwrap(), Ok(()));
        }
        assert!(
            calls.load(Ordering::SeqCst) <= 2,
            "{} rounds of checks for 50 probes",
            calls.load(Ordering::SeqCst)
        );

        tokio::time::sleep(FRESH_FOR + Duration::from_millis(100)).await;
        let before = calls.load(Ordering::SeqCst);
        assert_eq!(readiness.answer().await, Ok(()));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            before + 1,
            "a stale answer is redone"
        );
    }

    /// How long [`Gated`] keeps a round once released, so that rounds which
    /// are not kept apart overlap in it.
    const HOLD: Duration = Duration::from_millis(100);

    /// Holds each round until `release` is cancelled and then for [`HOLD`],
    /// and records how many rounds were in it at once.
    #[derive(Default)]
    struct Gated {
        release: CancellationToken,
        started: AtomicUsize,
        running: AtomicUsize,
        most: AtomicUsize,
    }

    /// Ends a round of [`Gated`], also when the request running it goes away.
    struct Running<'a>(&'a AtomicUsize);

    impl Drop for Running<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl ReadinessCheck for Gated {
        fn check(&self) -> ReadinessFuture<'_> {
            Box::pin(async move {
                self.started.fetch_add(1, Ordering::SeqCst);
                let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
                let _running = Running(&self.running);
                self.most.fetch_max(running, Ordering::SeqCst);
                self.release.cancelled().await;
                tokio::time::sleep(HOLD).await;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn rounds_never_overlap_even_when_a_request_goes_away() {
        let dir = tempfile::tempdir().unwrap();
        let gated = Arc::new(Gated::default());
        let readiness = Arc::new(Readiness::new(
            store(&dir).await,
            vec![gated.clone()],
            CancellationToken::new(),
        ));
        let probe = || {
            let readiness = readiness.clone();
            tokio::spawn(async move { readiness.answer().await })
        };

        let first = probe();
        tokio::time::timeout(Duration::from_secs(5), async {
            while gated.running.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let waiting: Vec<_> = (0..20).map(|_| probe()).collect();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            gated.started.load(Ordering::SeqCst),
            1,
            "the other requests wait for the round in progress"
        );

        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        gated.release.cancel();
        for probe in waiting {
            let answer = tokio::time::timeout(Duration::from_secs(5), probe).await;
            assert_eq!(answer.unwrap().unwrap(), Ok(()));
        }
        assert_eq!(gated.most.load(Ordering::SeqCst), 1, "rounds overlapped");
        assert!(
            gated.started.load(Ordering::SeqCst) >= 2,
            "the round that went away is redone"
        );
    }
}
