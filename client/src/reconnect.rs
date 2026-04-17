//! Exponential backoff and session error types for the reconnect loop.

use std::fmt;
use std::io;
use std::time::Duration;

use anno_common::ProtocolError;

/// Exponential backoff with jitter for reconnect delays.
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

    /// Return the next sleep duration (with ±0-1s jitter) and advance the internal state.
    pub fn next(&mut self) -> Duration {
        let jitter_ms = rand::random::<u64>() % 1000;
        let d = self.current + Duration::from_millis(jitter_ms);
        self.current = (self.current * 2).min(self.max);
        d
    }

    /// Reset to the minimum delay (call on a clean session end).
    pub fn reset(&mut self) {
        self.current = self.min;
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
