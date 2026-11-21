//! A small per-account pool of idle IMAP sessions.
//!
//! Opening an IMAP session costs a TCP connect, a TLS handshake and a login
//! (around a second against iCloud), and many short-lived logins can look
//! suspicious to the provider. Tool calls that arrive close together reuse a
//! session instead.
//!
//! Safety rules:
//!
//! * Sessions are keyed by account **and** a fingerprint of the credentials,
//!   so a session is never handed to another account, and a changed
//!   password never reuses a session logged in with the old one.
//! * A session is returned to the pool only after an operation succeeded or
//!   was refused cleanly (see `Error::leaves_session_usable`); after a
//!   timeout or I/O error it is dropped.
//! * Before reuse, a session must answer `NOOP`; every operation selects its
//!   folder again, so no state leaks between calls.
//! * Idle sessions are closed after the idle timeout and at shutdown, and
//!   the pool holds at most a few per account and a bounded total.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use postkeep_mail::ImapSession;
use postkeep_store::AccountId;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

/// Identifies the credentials a session was opened with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Fingerprints a server identifier, address and password. Kept only in
    /// memory.
    #[must_use]
    pub fn new(server: &str, email: &str, password: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"postkeep/imap-pool/v2\0");
        hasher.update(server.as_bytes());
        hasher.update(b"\0");
        hasher.update(email.as_bytes());
        hasher.update(b"\0");
        hasher.update(password.as_bytes());
        Self(hasher.finalize().into())
    }
}

/// Pool settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolConfig {
    /// How long an idle session is kept; zero disables pooling.
    pub idle_timeout: Duration,
    /// Idle sessions kept per account.
    pub per_account: usize,
    /// Idle sessions kept in total.
    pub total: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            per_account: 2,
            total: 256,
        }
    }
}

struct Idle {
    session: ImapSession,
    fingerprint: Fingerprint,
    since: Instant,
}

/// The pool. Cheap to clone.
#[derive(Clone)]
pub struct ImapPool {
    config: PoolConfig,
    idle: Arc<Mutex<HashMap<AccountId, Vec<Idle>>>>,
}

impl std::fmt::Debug for ImapPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImapPool")
            .field("config", &self.config)
            .field("idle", &self.idle_count())
            .finish()
    }
}

impl ImapPool {
    /// Creates an empty pool.
    #[must_use]
    pub fn new(config: PoolConfig) -> Self {
        Self {
            config,
            idle: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<AccountId, Vec<Idle>>> {
        self.idle.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of idle sessions.
    #[must_use]
    pub fn idle_count(&self) -> usize {
        self.lock().values().map(Vec::len).sum()
    }

    /// Takes a live idle session for `account` opened with `fingerprint`,
    /// or `None` if there is none.
    pub async fn take(&self, account: &AccountId, fingerprint: Fingerprint) -> Option<ImapSession> {
        self.take_until(account, fingerprint, None).await
    }

    /// The action path also bounds validation before the next NOOP starts.
    pub(crate) async fn take_until(
        &self,
        account: &AccountId,
        fingerprint: Fingerprint,
        deadline: Option<Instant>,
    ) -> Option<ImapSession> {
        loop {
            if postkeep_upstream::http::check_deadline(deadline).is_err() {
                return None;
            }

            let candidate = {
                let mut idle = self.lock();
                let sessions = idle.get_mut(account)?;
                // Sessions for other credentials are stale: drop them.
                let stale: Vec<Idle> = sessions
                    .extract_if(.., |entry| entry.fingerprint != fingerprint)
                    .collect();
                let candidate = sessions.pop();
                if sessions.is_empty() {
                    idle.remove(account);
                }
                drop(idle);
                close_all(stale.into_iter().map(|entry| entry.session));
                candidate?
            };
            if candidate.since.elapsed() >= self.config.idle_timeout {
                close_all([candidate.session]);
                continue;
            }
            let mut session = candidate.session;
            let alive = tokio::time::timeout(Duration::from_secs(5), session.noop()).await;
            if matches!(alive, Ok(Ok(()))) {
                return Some(session);
            }
            tracing::debug!("dropping a pooled IMAP session that failed NOOP");
        }
    }

    /// Returns a session after use. It is kept only if `usable` and there
    /// is room; otherwise it is logged out.
    pub fn give_back(
        &self,
        account: &AccountId,
        fingerprint: Fingerprint,
        session: ImapSession,
        usable: bool,
    ) {
        if !usable || self.config.idle_timeout.is_zero() {
            close_all([session]);
            return;
        }
        let mut idle = self.lock();
        let total: usize = idle.values().map(Vec::len).sum();
        let sessions = idle.entry(account.clone()).or_default();
        if sessions.len() >= self.config.per_account || total >= self.config.total {
            drop(idle);
            close_all([session]);
            return;
        }
        sessions.push(Idle {
            session,
            fingerprint,
            since: Instant::now(),
        });
    }

    /// Closes every idle session of `account`, for example after its
    /// password changed or it was deleted.
    pub fn evict(&self, account: &AccountId) {
        let sessions = self.lock().remove(account).unwrap_or_default();
        close_all(sessions.into_iter().map(|entry| entry.session));
    }

    /// Closes sessions idle for longer than the timeout.
    pub fn reap(&self) {
        let timeout = self.config.idle_timeout;
        let mut expired = Vec::new();
        {
            let mut idle = self.lock();
            for sessions in idle.values_mut() {
                expired.extend(
                    sessions
                        .extract_if(.., |entry| entry.since.elapsed() >= timeout)
                        .map(|entry| entry.session),
                );
            }
            idle.retain(|_, sessions| !sessions.is_empty());
        }
        close_all(expired);
    }

    /// Reaps expired sessions periodically; logs out every idle session
    /// when `cancel` fires.
    pub async fn run_reaper(self, cancel: CancellationToken) {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                _ = interval.tick() => self.reap(),
            }
        }
        let sessions: Vec<ImapSession> = self
            .lock()
            .drain()
            .flat_map(|(_, sessions)| sessions.into_iter().map(|entry| entry.session))
            .collect();
        let mut set = tokio::task::JoinSet::new();
        for session in sessions {
            set.spawn(async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), session.logout()).await;
            });
        }
        while set.join_next().await.is_some() {}
    }
}

/// Logs sessions out in the background.
fn close_all(sessions: impl IntoIterator<Item = ImapSession>) {
    for session in sessions {
        tokio::spawn(async move {
            if let Err(err) = session.logout().await {
                tracing::debug!(error = %err, "IMAP logout failed");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_depend_on_both_parts() {
        let a = Fingerprint::new("icloud", "a@icloud.com", "pw");
        assert_eq!(a, Fingerprint::new("icloud", "a@icloud.com", "pw"));
        assert_ne!(a, Fingerprint::new("icloud", "a@icloud.com", "pw2"));
        assert_ne!(a, Fingerprint::new("icloud", "b@icloud.com", "pw"));
        assert_ne!(a, Fingerprint::new("custom", "a@icloud.com", "pw"));
        // The separator prevents ambiguity between the two fields.
        assert_ne!(
            Fingerprint::new("s", "ab", "c"),
            Fingerprint::new("s", "a", "bc")
        );
    }
}
