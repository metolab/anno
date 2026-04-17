//! Lightweight in-memory IP-based rate limiter for the login endpoint.
//!
//! Design tradeoffs:
//! - Sliding window is approximated with "first failure at" + "count". When
//!   the window has expired on the next attempt the counter resets. This is
//!   cheap and good-enough for brute-force protection; it is not intended as
//!   a general purpose QoS limiter.
//! - Successful login clears the counter so a legitimate user is never
//!   penalised by earlier typos once they finally get the password right.
//! - Storage is `DashMap<IpAddr, Entry>`; pruned opportunistically during
//!   `check`. The total key space is bounded by unique source IPs, which in
//!   practice is small for a management plane.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Maximum allowed failures within `window` before we reject with 429.
const MAX_FAILURES: u32 = 10;
/// Rolling window for failure counting.
const WINDOW: Duration = Duration::from_secs(60);
/// Opportunistic prune threshold: once the map exceeds this size we sweep
/// expired entries on the next write. Keeps memory bounded under slow
/// distributed scans that otherwise never collide with `record_success`.
const PRUNE_THRESHOLD: usize = 1024;

/// Per-IP state.
struct Entry {
    first_failure_at: Instant,
    failures: u32,
}

#[derive(Clone, Default)]
pub struct LoginRateLimiter {
    inner: Arc<DashMap<IpAddr, Entry>>,
}

/// Decision returned by [`LoginRateLimiter::check`].
#[derive(Debug, Clone, Copy)]
pub enum LoginDecision {
    /// Proceed with password verification.
    Allow,
    /// Too many failures — reject immediately with HTTP 429.
    Deny { retry_after_secs: u64 },
}

impl LoginRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `ip` is permitted to attempt a login right now.
    pub fn check(&self, ip: IpAddr) -> LoginDecision {
        let now = Instant::now();
        let mut drop_stale = false;
        if let Some(entry) = self.inner.get(&ip) {
            let elapsed = now.saturating_duration_since(entry.first_failure_at);
            if elapsed < WINDOW && entry.failures >= MAX_FAILURES {
                let remaining = WINDOW.saturating_sub(elapsed).as_secs();
                return LoginDecision::Deny {
                    retry_after_secs: remaining.max(1),
                };
            }
            if elapsed >= WINDOW {
                drop_stale = true;
            }
        }
        if drop_stale {
            // Expired entry is just noise from here on; drop it so the map
            // does not grow unbounded under a slow scan of distinct IPs.
            self.inner.remove(&ip);
        }
        LoginDecision::Allow
    }

    /// Record a failed login attempt from `ip`.
    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        {
            let mut entry = self.inner.entry(ip).or_insert(Entry {
                first_failure_at: now,
                failures: 0,
            });
            if now.saturating_duration_since(entry.first_failure_at) >= WINDOW {
                entry.first_failure_at = now;
                entry.failures = 1;
            } else {
                entry.failures = entry.failures.saturating_add(1);
            }
        }
        if self.inner.len() > PRUNE_THRESHOLD {
            self.prune_expired(now);
        }
    }

    /// Clear the counter for `ip` on a successful login.
    pub fn record_success(&self, ip: IpAddr) {
        self.inner.remove(&ip);
    }

    /// Remove any entries whose window has already elapsed at `now`.
    /// Runs in O(n) and is only triggered opportunistically on the write
    /// path once the map has grown past [`PRUNE_THRESHOLD`].
    fn prune_expired(&self, now: Instant) {
        let mut stale: Vec<IpAddr> = Vec::new();
        for entry in self.inner.iter() {
            if now.saturating_duration_since(entry.value().first_failure_at) >= WINDOW {
                stale.push(*entry.key());
            }
        }
        for ip in stale {
            self.inner.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn denies_after_max_failures() {
        let rl = LoginRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        for _ in 0..MAX_FAILURES {
            assert!(matches!(rl.check(ip), LoginDecision::Allow));
            rl.record_failure(ip);
        }
        assert!(matches!(rl.check(ip), LoginDecision::Deny { .. }));
    }

    #[test]
    fn success_clears_counter() {
        let rl = LoginRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        for _ in 0..MAX_FAILURES {
            rl.record_failure(ip);
        }
        assert!(matches!(rl.check(ip), LoginDecision::Deny { .. }));
        rl.record_success(ip);
        assert!(matches!(rl.check(ip), LoginDecision::Allow));
    }

    #[test]
    fn check_drops_expired_entry() {
        let rl = LoginRateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // Pretend the entry is older than WINDOW.
        let past = Instant::now()
            .checked_sub(WINDOW + Duration::from_secs(1))
            .expect("clock far enough in the future");
        rl.inner.insert(
            ip,
            Entry {
                first_failure_at: past,
                failures: 3,
            },
        );
        assert!(matches!(rl.check(ip), LoginDecision::Allow));
        assert!(rl.inner.get(&ip).is_none(), "expired entry should be pruned");
    }
}
