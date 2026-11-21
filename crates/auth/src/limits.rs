//! In-memory abuse limits: exponential sign-in backoff and fixed-window
//! rate limits, keyed by client IP address or account.
//!
//! The limits live in process memory, so they reset on restart and are per
//! replica. That is enough to slow down guessing and flooding; it is not an
//! accounting system.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

// Std's clock, except in a paused test runtime, which follows that runtime's clock.
use tokio::time::Instant;

/// Entries kept before stale ones are pruned.
const PRUNE_THRESHOLD: usize = 10_000;

/// Exponential backoff after failed attempts.
///
/// The first `free` failures cost nothing. After that, each failure doubles
/// the wait before the next attempt, starting at `base` and capped at `max`.
/// A key is forgotten `forget_after` its last failure.
#[derive(Debug)]
pub struct Backoff {
    free: u32,
    base: Duration,
    max: Duration,
    forget_after: Duration,
    entries: Mutex<HashMap<String, BackoffEntry>>,
}

#[derive(Debug, Clone, Copy)]
struct BackoffEntry {
    failures: u32,
    last: Instant,
}

impl Backoff {
    pub fn new(free: u32, base: Duration, max: Duration, forget_after: Duration) -> Self {
        Self {
            free,
            base,
            max,
            forget_after,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// The wait imposed after `failures` failures.
    fn delay(&self, failures: u32) -> Duration {
        if failures <= self.free {
            return Duration::ZERO;
        }
        let exponent = (failures - self.free - 1).min(30);
        self.base.saturating_mul(1_u32 << exponent).min(self.max)
    }

    /// Returns how long `key` must wait, or `None` if it may try now.
    pub fn retry_after(&self, key: &str) -> Option<Duration> {
        let entry = *lock(&self.entries).get(key)?;
        let remaining = self
            .delay(entry.failures)
            .saturating_sub(entry.last.elapsed());
        (!remaining.is_zero()).then_some(remaining)
    }

    /// Records a failed attempt for `key`.
    pub fn record_failure(&self, key: &str) {
        let forget_after = self.forget_after;
        let now = Instant::now();
        let mut entries = lock(&self.entries);
        if entries.len() >= PRUNE_THRESHOLD {
            entries.retain(|_, entry| entry.last.elapsed() < forget_after);
        }
        let entry = entries.entry(key.to_owned()).or_insert(BackoffEntry {
            failures: 0,
            last: now,
        });
        if entry.last.elapsed() >= forget_after {
            entry.failures = 0;
        }
        entry.failures = entry.failures.saturating_add(1);
        entry.last = now;
        drop(entries);
    }

    /// Clears the record for `key`.
    pub fn record_success(&self, key: &str) {
        lock(&self.entries).remove(key);
    }
}

/// Allows `limit` events per key in each fixed window.
#[derive(Debug)]
pub struct RateLimit {
    limit: u32,
    window: Duration,
    entries: Mutex<HashMap<String, WindowEntry>>,
}

#[derive(Debug, Clone, Copy)]
struct WindowEntry {
    count: u32,
    started: Instant,
}

impl RateLimit {
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Counts an event for `key`. Returns how long to wait if the limit is
    /// already used up; a rejected event is not counted.
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        let window = self.window;
        let now = Instant::now();
        let mut entries = lock(&self.entries);
        if entries.len() >= PRUNE_THRESHOLD {
            entries.retain(|_, entry| entry.started.elapsed() < window);
        }
        let entry = entries.entry(key.to_owned()).or_insert(WindowEntry {
            count: 0,
            started: now,
        });
        if entry.started.elapsed() >= window {
            *entry = WindowEntry {
                count: 0,
                started: now,
            };
        }
        if entry.count >= self.limit {
            let wait = window.saturating_sub(entry.started.elapsed());
            drop(entries);
            return Err(wait.max(Duration::from_secs(1)));
        }
        entry.count += 1;
        drop(entries);
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The key used for per-client limits: the IPv4 address, or the /64 prefix
/// of an IPv6 address (one subscriber usually controls a whole /64).
#[must_use]
pub fn ip_key(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || {
                let segments = ip.segments();
                format!(
                    "{:x}:{:x}:{:x}:{:x}::/64",
                    segments[0], segments[1], segments[2], segments[3]
                )
            },
            |ip| ip.to_string(),
        ),
    }
}

/// Formats a wait for people: "45 seconds", "1 minute", "15 minutes".
#[must_use]
pub fn describe_wait(wait: Duration) -> String {
    let seconds = wait.as_secs().max(1);
    if seconds < 90 {
        let plural = if seconds == 1 { "" } else { "s" };
        format!("{seconds} second{plural}")
    } else {
        let minutes = seconds.div_ceil(60);
        format!("{minutes} minutes")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        let backoff = Backoff::new(
            2,
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::from_hours(1),
        );
        let delays: Vec<u64> = (0..8).map(|n| backoff.delay(n).as_secs()).collect();
        assert_eq!(delays, [0, 0, 0, 1, 2, 4, 8, 10]);
        assert_eq!(backoff.delay(u32::MAX), Duration::from_secs(10));
    }

    #[test]
    fn backoff_blocks_until_success() {
        let backoff = Backoff::new(
            1,
            Duration::from_mins(1),
            Duration::from_mins(5),
            Duration::from_hours(1),
        );
        backoff.record_failure("a");
        assert!(backoff.retry_after("a").is_none());
        backoff.record_failure("a");
        let wait = backoff.retry_after("a").unwrap();
        assert!(wait > Duration::from_secs(55) && wait <= Duration::from_mins(1));
        assert!(backoff.retry_after("b").is_none());
        backoff.record_success("a");
        assert!(backoff.retry_after("a").is_none());
    }

    #[test]
    fn backoff_forgets_old_failures() {
        let backoff = Backoff::new(
            0,
            Duration::from_mins(1),
            Duration::from_mins(1),
            Duration::ZERO,
        );
        backoff.record_failure("a");
        backoff.record_failure("a");
        // forget_after is zero, so every failure starts a fresh count of 1.
        assert_eq!(lock(&backoff.entries)["a"].failures, 1);
    }

    #[test]
    fn rate_limit_counts_per_key() {
        let limit = RateLimit::new(2, Duration::from_mins(1));
        assert!(limit.check("a").is_ok());
        assert!(limit.check("a").is_ok());
        let wait = limit.check("a").unwrap_err();
        assert!(wait <= Duration::from_mins(1));
        assert!(limit.check("b").is_ok());
    }

    #[test]
    fn rate_limit_window_resets() {
        let limit = RateLimit::new(1, Duration::ZERO);
        assert!(limit.check("a").is_ok());
        assert!(limit.check("a").is_ok());
    }

    #[test]
    fn groups_ipv6_by_prefix() {
        assert_eq!(ip_key("203.0.113.9".parse().unwrap()), "203.0.113.9");
        assert_eq!(
            ip_key("2001:db8:1:2:3:4:5:6".parse().unwrap()),
            "2001:db8:1:2::/64"
        );
        assert_eq!(
            ip_key("::ffff:198.51.100.7".parse().unwrap()),
            "198.51.100.7"
        );
    }

    #[test]
    fn describes_waits() {
        assert_eq!(describe_wait(Duration::ZERO), "1 second");
        assert_eq!(describe_wait(Duration::from_secs(45)), "45 seconds");
        assert_eq!(describe_wait(Duration::from_secs(61)), "61 seconds");
        assert_eq!(describe_wait(Duration::from_mins(15)), "15 minutes");
    }
}
