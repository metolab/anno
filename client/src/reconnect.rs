//! Exponential backoff and session error types for the reconnect loop.

use std::fmt;
use std::io;
use std::time::Duration;

use anno_common::ProtocolError;

/// Exponential backoff with **full jitter**.
///
/// Each `next()` returns a duration uniformly distributed in `[min, current]`
/// before doubling `current` (capped at `max`). Full jitter spreads
/// reconnect attempts across the entire interval, which dramatically
/// reduces synchronized retry storms across many clients compared to the
/// previous additive `current + 0..1s` approach (which still left the
/// `current` floor for everyone to land on simultaneously).
///
/// See AWS Architecture Blog — "Exponential Backoff and Jitter".
pub struct Backoff {
    min: Duration,
    max: Duration,
    current: Duration,
}

impl Backoff {
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max,
            current: min,
        }
    }

    /// Return the next sleep duration and advance the internal state.
    /// The returned value is uniformly chosen from `[min, current]`,
    /// then `current` is doubled (clamped to `max`).
    pub fn next(&mut self) -> Duration {
        let cur_ms = self.current.as_millis().max(self.min.as_millis()) as u64;
        let min_ms = self.min.as_millis() as u64;
        // Full-jitter draw in [min_ms, cur_ms]. Falls back to `cur_ms`
        // when the window is degenerate (cur_ms <= min_ms) so the
        // first reconnect after a successful session still respects
        // the configured floor.
        let span = cur_ms.saturating_sub(min_ms).saturating_add(1);
        let pick_ms = min_ms + rand::random::<u64>() % span;
        let d = Duration::from_millis(pick_ms);
        self.current = (self.current * 2).min(self.max);
        d
    }

    /// Reset to the minimum delay (call on a clean session end).
    pub fn reset(&mut self) {
        self.current = self.min;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_jitter_stays_within_bounds() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));
        // First call: window is [100ms, 100ms].
        let d0 = b.next();
        assert!(d0 >= Duration::from_millis(100));
        assert!(d0 <= Duration::from_millis(100));
        // After many doublings, draws still respect the cap.
        for _ in 0..20 {
            let d = b.next();
            assert!(d >= Duration::from_millis(100));
            assert!(d <= Duration::from_secs(30));
        }
    }

    #[test]
    fn reset_returns_to_min_window() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(30));
        for _ in 0..5 {
            let _ = b.next();
        }
        b.reset();
        // Immediately after reset, window collapses to [min, min].
        let d = b.next();
        assert_eq!(d, Duration::from_millis(100));
    }
}

/// Errors that can terminate a single `run_session` attempt.
#[derive(Debug)]
pub enum SessionError {
    /// Server rejected the client key — do NOT retry.
    AuthFailed,
    /// DNS resolution or TCP connect failed.
    Connect(io::Error),
    /// Protocol framing error (bad magic / version / etc.).
    Protocol(ProtocolError),
    /// No frame received from server for too long.
    IdleTimeout,
    /// Generic I/O error on the control stream.
    Io(io::Error),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthFailed => write!(f, "authentication failed (invalid key)"),
            Self::Connect(e) => write!(f, "connect error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::IdleTimeout => write!(f, "control connection idle timeout"),
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl From<io::Error> for SessionError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
