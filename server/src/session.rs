//! Unified session management for TCP/UDP tunneled connections.
//!
//! This module provides:
//! - Bounded channel for backpressure control (prevents OOM under heavy load)
//! - Automatic session cleanup with configurable timeout
//! - Connection statistics tracking
//! - Thread-safe session registry

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

/// Configuration for session management.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Capacity of the bounded channel for tunnel data.
    /// When full, data will be dropped with a warning.
    pub tunnel_queue_capacity: usize,

    /// Timeout for UDP sessions (no activity).
    pub udp_session_timeout: Duration,

    /// Interval for session cleanup task.
    pub cleanup_interval: Duration,

    /// Timeout for waiting ConnReady response.
    pub conn_ready_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            tunnel_queue_capacity: 256,
            udp_session_timeout: Duration::from_secs(300), // 5 minutes
            cleanup_interval: Duration::from_secs(30),
            conn_ready_timeout: Duration::from_secs(60),
        }
    }
}

/// Statistics for a single session.
#[derive(Debug, Default)]
pub struct SessionStats {
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub packets_up: AtomicU64,
    pub packets_down: AtomicU64,
    pub queue_drops: AtomicU64,
}

impl SessionStats {
    pub fn record_up(&self, bytes: usize) {
        self.bytes_up.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_up.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("tunnel_bytes_total", "direction" => "up").increment(bytes as u64);
    }

    pub fn record_down(&self, bytes: usize) {
        self.bytes_down.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_down.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("tunnel_bytes_total", "direction" => "down").increment(bytes as u64);
    }

    pub fn record_drop(&self) {
        self.queue_drops.fetch_add(1, Ordering::Relaxed);
        metrics::counter!("tunnel_queue_drops_total").increment(1);
    }
}

/// Protocol type for the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProtocol {
    Tcp,
    Udp,
}

/// A single tunneled session.
pub struct Session {
    pub conn_id: u64,
    pub protocol: SessionProtocol,
    pub server_port: u16,
    pub client_id: u64,
    pub created_at: Instant,
    pub last_active: std::sync::atomic::AtomicU64, // ms since created_at
    pub stats: SessionStats,
    /// Bounded sender to the public-facing socket writer.
    tx: mpsc::Sender<Bytes>,
}

impl Session {
    /// Create a new session with a bounded channel.
    pub fn new(
        conn_id: u64,
        protocol: SessionProtocol,
        server_port: u16,
        client_id: u64,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<Bytes>) {
        let (tx, rx) = mpsc::channel(capacity);
        let session = Self {
            conn_id,
            protocol,
            server_port,
            client_id,
            created_at: Instant::now(),
            last_active: AtomicU64::new(0),
            stats: SessionStats::default(),
            tx,
        };
        (session, rx)
    }

    /// Update last active timestamp.
    pub fn touch(&self) {
        let elapsed = self.created_at.elapsed().as_millis() as u64;
        self.last_active.store(elapsed, Ordering::Relaxed);
    }

    /// Get duration since last activity.
    pub fn idle_duration(&self) -> Duration {
        let last_ms = self.last_active.load(Ordering::Relaxed);
        let elapsed_ms = self.created_at.elapsed().as_millis() as u64;
        Duration::from_millis(elapsed_ms.saturating_sub(last_ms))
    }

    /// Try to send data through the bounded channel.
    /// Returns true if sent successfully, false if queue is full (data dropped).
    pub fn try_send(&self, data: Bytes) -> bool {
        match self.tx.try_send(data) {
            Ok(_) => {
                self.touch();
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_drop();
                tracing::warn!(conn_id = self.conn_id, "tunnel queue full, dropping packet");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Check if the channel is closed.
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Manages all active sessions.
pub struct SessionManager {
    config: SessionConfig,
    sessions: DashMap<u64, Arc<Session>>,
    /// conn_id -> sender for ConnReady notification
    conn_ready_waiters: DashMap<u64, oneshot::Sender<()>>,
    /// port -> active session count (O(1) lookup index)
    port_counts: DashMap<u16, AtomicUsize>,
    /// Statistics
    total_created: AtomicU64,
    total_closed: AtomicU64,
}

impl SessionManager {
    /// Create a new session manager with default config.
    pub fn new() -> Self {
        Self::with_config(SessionConfig::default())
    }

    /// Create a new session manager with custom config.
    pub fn with_config(config: SessionConfig) -> Self {
        Self {
            config,
            sessions: DashMap::new(),
            conn_ready_waiters: DashMap::new(),
            port_counts: DashMap::new(),
            total_created: AtomicU64::new(0),
            total_closed: AtomicU64::new(0),
        }
    }

    /// Get the session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Create a new session and register it.
    pub fn create_session(
        &self,
        conn_id: u64,
        protocol: SessionProtocol,
        server_port: u16,
        client_id: u64,
    ) -> (Arc<Session>, mpsc::Receiver<Bytes>) {
        let (session, rx) = Session::new(
            conn_id,
            protocol,
            server_port,
            client_id,
            self.config.tunnel_queue_capacity,
        );
        let session = Arc::new(session);
        self.sessions.insert(conn_id, Arc::clone(&session));
        self.total_created.fetch_add(1, Ordering::Relaxed);
        // Update port count index (O(1))
        self.port_counts
            .entry(server_port)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("sessions_created_total").increment(1);
        metrics::gauge!("sessions_active").increment(1.0);
        (session, rx)
    }

    /// Get a session by conn_id.
    pub fn get(&self, conn_id: u64) -> Option<Arc<Session>> {
        self.sessions.get(&conn_id).map(|r| Arc::clone(&r))
    }

    /// Remove a session.
    pub fn remove(&self, conn_id: u64) -> Option<Arc<Session>> {
        if let Some((_, session)) = self.sessions.remove(&conn_id) {
            self.total_closed.fetch_add(1, Ordering::Relaxed);
            // Decrement port count index
            if let Some(cnt) = self.port_counts.get(&session.server_port) {
                cnt.fetch_sub(1, Ordering::Relaxed);
            }
            metrics::counter!("sessions_closed_total").increment(1);
            metrics::gauge!("sessions_active").decrement(1.0);
            Some(session)
        } else {
            None
        }
    }

    /// Count sessions by server port (O(1) via port index).
    pub fn count_by_port(&self, port: u16) -> usize {
        self.port_counts
            .get(&port)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Count sessions by client.
    #[allow(dead_code)]
    pub fn count_by_client(&self, client_id: u64) -> usize {
        self.sessions
            .iter()
            .filter(|r| r.client_id == client_id)
            .count()
    }

    /// Get total active session count.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    /// Iterate over all sessions.
    pub fn iter_sessions(&self) -> dashmap::iter::Iter<'_, u64, Arc<Session>> {
        self.sessions.iter()
    }

    /// Register a waiter for ConnReady.
    pub fn register_conn_ready_waiter(&self, conn_id: u64) -> oneshot::Receiver<()> {
        let (tx, rx) = oneshot::channel();
        self.conn_ready_waiters.insert(conn_id, tx);
        rx
    }

    /// Notify that a connection is ready.
    pub fn notify_conn_ready(&self, conn_id: u64) -> bool {
        if let Some((_, tx)) = self.conn_ready_waiters.remove(&conn_id) {
            let _ = tx.send(());
            true
        } else {
            false
        }
    }

    /// Cancel a ConnReady waiter.
    pub fn cancel_conn_ready_waiter(&self, conn_id: u64) {
        self.conn_ready_waiters.remove(&conn_id);
    }

    /// Clean up timed-out UDP sessions.
    /// Returns the number of sessions cleaned up.
    pub fn cleanup_timed_out_sessions(&self) -> usize {
        let timeout = self.config.udp_session_timeout;
        let mut cleaned = 0;

        // Collect conn_ids to remove (to avoid holding the lock)
        let to_remove: Vec<u64> = self
            .sessions
            .iter()
            .filter(|r| r.protocol == SessionProtocol::Udp && r.idle_duration() > timeout)
            .map(|r| r.conn_id)
            .collect();

        for conn_id in to_remove {
            if self.remove(conn_id).is_some() {
                tracing::debug!(conn_id, "cleaned up timed-out UDP session");
                cleaned += 1;
            }
        }

        cleaned
    }

    /// Remove all sessions for a client.
    /// Uses the main sessions map (O(n) scan required, but only on disconnect).
    pub fn remove_client_sessions(&self, client_id: u64) -> usize {
        let to_remove: Vec<u64> = self
            .sessions
            .iter()
            .filter(|r| r.client_id == client_id)
            .map(|r| r.conn_id)
            .collect();

        let count = to_remove.len();
        for conn_id in to_remove {
            self.remove(conn_id);
        }
        count
    }

    /// Get statistics summary.
    #[allow(dead_code)]
    pub fn stats(&self) -> SessionManagerStats {
        SessionManagerStats {
            active_sessions: self.sessions.len(),
            total_created: self.total_created.load(Ordering::Relaxed),
            total_closed: self.total_closed.load(Ordering::Relaxed),
            pending_conn_ready: self.conn_ready_waiters.len(),
        }
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for the session manager.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SessionManagerStats {
    pub active_sessions: usize,
    pub total_created: u64,
    pub total_closed: u64,
    pub pending_conn_ready: usize,
}

/// Spawn the background cleanup task.
pub fn spawn_cleanup_task(manager: Arc<SessionManager>) -> tokio::task::JoinHandle<()> {
    let interval = manager.config.cleanup_interval;
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let cleaned = manager.cleanup_timed_out_sessions();
            if cleaned > 0 {
                tracing::info!(cleaned, "session cleanup completed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let manager = SessionManager::new();
        let (session, _rx) = manager.create_session(1, SessionProtocol::Tcp, 8080, 100);
        assert_eq!(session.conn_id, 1);
        assert_eq!(session.server_port, 8080);
        assert_eq!(session.client_id, 100);
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_session_removal() {
        let manager = SessionManager::new();
        manager.create_session(1, SessionProtocol::Tcp, 8080, 100);
        assert_eq!(manager.active_count(), 1);

        let removed = manager.remove(1);
        assert!(removed.is_some());
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn test_count_by_port() {
        let manager = SessionManager::new();
        manager.create_session(1, SessionProtocol::Tcp, 8080, 100);
        manager.create_session(2, SessionProtocol::Tcp, 8080, 100);
        manager.create_session(3, SessionProtocol::Tcp, 9090, 100);

        assert_eq!(manager.count_by_port(8080), 2);
        assert_eq!(manager.count_by_port(9090), 1);
        assert_eq!(manager.count_by_port(7070), 0);
    }

    #[test]
    fn test_session_try_send() {
        let config = SessionConfig {
            tunnel_queue_capacity: 2,
            ..Default::default()
        };
        let manager = SessionManager::with_config(config);
        let (session, mut rx) = manager.create_session(1, SessionProtocol::Tcp, 8080, 100);

        // Should succeed twice (capacity = 2)
        assert!(session.try_send(Bytes::from_static(b"1")));
        assert!(session.try_send(Bytes::from_static(b"2")));

        // Should fail (queue full)
        assert!(!session.try_send(Bytes::from_static(b"3")));
        assert_eq!(session.stats.queue_drops.load(Ordering::Relaxed), 1);

        // Consume one, then can send again
        let _ = rx.try_recv();
        assert!(session.try_send(Bytes::from_static(b"4")));
    }

    #[test]
    fn test_conn_ready_notification() {
        let manager = SessionManager::new();
        let mut rx = manager.register_conn_ready_waiter(42);

        assert!(manager.notify_conn_ready(42));
        assert!(rx.try_recv().is_ok());

        // Second notify should fail (already consumed)
        assert!(!manager.notify_conn_ready(42));
    }

    #[test]
    fn test_remove_client_sessions() {
        let manager = SessionManager::new();
        manager.create_session(1, SessionProtocol::Tcp, 8080, 100);
        manager.create_session(2, SessionProtocol::Tcp, 8081, 100);
        manager.create_session(3, SessionProtocol::Tcp, 8082, 200);

        let removed = manager.remove_client_sessions(100);
        assert_eq!(removed, 2);
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_session_idle_duration() {
        let (session, _rx) = Session::new(1, SessionProtocol::Udp, 8080, 100, 16);

        // Initially, idle duration should be very small
        let idle = session.idle_duration();
        assert!(idle < Duration::from_millis(100));

        // After touch, idle should reset
        std::thread::sleep(Duration::from_millis(10));
        session.touch();
        let idle_after_touch = session.idle_duration();
        assert!(idle_after_touch < Duration::from_millis(5));
    }
}
