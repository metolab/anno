//! Unified session management for TCP/UDP tunneled connections.
//!
//! This module provides:
//! - Bounded channel for backpressure control (prevents OOM under heavy load)
//! - Automatic session cleanup with configurable timeout
//! - Connection statistics tracking
//! - Thread-safe session registry
//! - O(1) per-port and per-client session counters (secondary indexes)
//! - ConnReady waiters that are actively woken with an error when a session
//!   is removed, so public-side tasks don't hang waiting for a handshake
//!   that will never complete.

/// Default maximum time to wait when forwarding a TCP frame into the session
/// channel. If the receiver is not consuming data within this window the
/// session is considered stuck and should be terminated. Overridable via
/// [`SessionConfig::tcp_send_timeout`] — the constant is kept as the
/// default only.
const DEFAULT_TCP_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Outcome of a `Session::send_tcp` call.
#[derive(Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Data was queued successfully.
    Ok,
    /// The receiving end of the channel has been dropped.
    Closed,
    /// The channel was full for longer than `TCP_SEND_TIMEOUT`.
    Timeout,
}

/// Reason a ConnReady waiter was resolved with an error instead of success.
#[derive(Debug, Clone)]
pub enum ConnReadyError {
    /// Session was removed before ConnReady arrived (cleanup, cancel,
    /// client-side Fault, etc.).
    Aborted,
    /// Client reported a specific Fault while the public side was waiting.
    ClientFault {
        code: u16,
        message: String,
    },
}

use anno_common::ErrorCode;
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

    /// Timeout for backpressure-safe TCP tunnel sends. If the client cannot
    /// drain within this window the session is considered stuck and closed.
    pub tcp_send_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            tunnel_queue_capacity: 256,
            udp_session_timeout: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(30),
            conn_ready_timeout: Duration::from_secs(60),
            tcp_send_timeout: DEFAULT_TCP_SEND_TIMEOUT,
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

/// Helper that recovers from a poisoned `RwLock`. Poisoning only happens on
/// a panic while a writer was active; we'd still rather unpoison and keep the
/// system functional than silently drop cleanup work.
fn rw_read<'a, T>(lock: &'a std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'a, T> {
    lock.read().unwrap_or_else(|e| e.into_inner())
}

fn rw_write<'a, T>(lock: &'a std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'a, T> {
    lock.write().unwrap_or_else(|e| e.into_inner())
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
    ///
    /// Wrapped in a `RwLock<Option<_>>` so that `close()` can drop the sender
    /// explicitly; the downstream task's `tun_rx.recv()` then returns `None`
    /// and the task exits — breaking the Arc cycle that would otherwise keep
    /// the `Session` alive forever.
    tx: std::sync::RwLock<Option<mpsc::Sender<Bytes>>>,
    /// Per-session TCP send timeout — snapshot of `SessionConfig::tcp_send_timeout`
    /// taken when the session was created.
    tcp_send_timeout: Duration,
}

impl Session {
    /// Create a new session with a bounded channel.
    pub fn new(
        conn_id: u64,
        protocol: SessionProtocol,
        server_port: u16,
        client_id: u64,
        capacity: usize,
        tcp_send_timeout: Duration,
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
            tx: std::sync::RwLock::new(Some(tx)),
            tcp_send_timeout,
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

    /// Try to send data through the bounded channel (non-blocking, drop on full).
    /// Suitable for UDP sessions where packet loss is acceptable.
    pub fn try_send(&self, data: Bytes) -> bool {
        let guard = rw_read(&self.tx);
        let tx = match guard.as_ref() {
            Some(tx) => tx,
            None => return false,
        };
        match tx.try_send(data) {
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

    /// Backpressure-safe send for TCP sessions.
    /// Waits up to the configured `tcp_send_timeout` before declaring a
    /// timeout. Returns a `SendOutcome` that the caller should act upon.
    pub async fn send_tcp(&self, data: Bytes) -> SendOutcome {
        // Clone the sender out of the lock so we don't hold the lock across
        // the await point.
        let tx = rw_read(&self.tx).as_ref().cloned();
        let Some(tx) = tx else {
            return SendOutcome::Closed;
        };
        match tokio::time::timeout(self.tcp_send_timeout, tx.send(data)).await {
            Ok(Ok(())) => {
                self.touch();
                SendOutcome::Ok
            }
            Ok(Err(_)) => SendOutcome::Closed,
            Err(_) => SendOutcome::Timeout,
        }
    }

    /// Explicitly close the session's tunnel channel.
    pub fn close(&self) {
        rw_write(&self.tx).take();
    }

    /// Check if the channel has been closed.
    #[allow(dead_code)]
    pub fn is_closed(&self) -> bool {
        match rw_read(&self.tx).as_ref() {
            Some(tx) => tx.is_closed(),
            None => true,
        }
    }
}

/// Manages all active sessions.
pub struct SessionManager {
    config: SessionConfig,
    sessions: DashMap<u64, Arc<Session>>,
    /// conn_id -> sender for ConnReady notification.
    conn_ready_waiters: DashMap<u64, oneshot::Sender<Result<(), ConnReadyError>>>,
    /// port -> active session count (O(1) lookup index)
    port_counts: DashMap<u16, AtomicUsize>,
    /// client_id -> active session count (O(1) lookup index).
    client_counts: DashMap<u64, AtomicUsize>,
    /// Statistics
    total_created: AtomicU64,
    total_closed: AtomicU64,
    /// Cumulative byte counters folded-in at `remove()` time. These let
    /// `aggregate_tunnel_stats` return a monotonic total that does not
    /// "forget" bytes when short-lived sessions (e.g. HTTP requests) close
    /// between two `/api/stats` polls. Matching semantics with the
    /// Prometheus `tunnel_bytes_total` counter.
    lifetime_bytes_up: AtomicU64,
    lifetime_bytes_down: AtomicU64,
    /// Cumulative `queue_drops` from closed sessions (same rationale as
    /// `lifetime_bytes_up`).
    lifetime_queue_drops: AtomicU64,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::with_config(SessionConfig::default())
    }

    pub fn with_config(config: SessionConfig) -> Self {
        Self {
            config,
            sessions: DashMap::new(),
            conn_ready_waiters: DashMap::new(),
            port_counts: DashMap::new(),
            client_counts: DashMap::new(),
            total_created: AtomicU64::new(0),
            total_closed: AtomicU64::new(0),
            lifetime_bytes_up: AtomicU64::new(0),
            lifetime_bytes_down: AtomicU64::new(0),
            lifetime_queue_drops: AtomicU64::new(0),
        }
    }

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
            self.config.tcp_send_timeout,
        );
        let session = Arc::new(session);
        self.sessions.insert(conn_id, Arc::clone(&session));
        self.total_created.fetch_add(1, Ordering::Relaxed);
        self.port_counts
            .entry(server_port)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
        self.client_counts
            .entry(client_id)
            .or_insert_with(|| AtomicUsize::new(0))
            .fetch_add(1, Ordering::Relaxed);
        metrics::counter!("sessions_created_total").increment(1);
        metrics::gauge!("sessions_active").increment(1.0);
        (session, rx)
    }

    pub fn get(&self, conn_id: u64) -> Option<Arc<Session>> {
        self.sessions.get(&conn_id).map(|r| Arc::clone(&r))
    }

    /// Remove a session. Wakes any pending ConnReady waiter with
    /// `ConnReadyError::Aborted` so public-side tasks don't hang.
    pub fn remove(&self, conn_id: u64) -> Option<Arc<Session>> {
        // Wake any pending ConnReady waiter first so handshake tasks can
        // abort without waiting for the configured timeout.
        if let Some((_, tx)) = self.conn_ready_waiters.remove(&conn_id) {
            let _ = tx.send(Err(ConnReadyError::Aborted));
        }

        if let Some((_, session)) = self.sessions.remove(&conn_id) {
            session.close();
            self.total_closed.fetch_add(1, Ordering::Relaxed);
            // Fold the closed session's counters into the lifetime totals so
            // `aggregate_tunnel_stats` keeps reporting a monotonic cumulative
            // number even after the session is gone.
            self.lifetime_bytes_up.fetch_add(
                session.stats.bytes_up.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.lifetime_bytes_down.fetch_add(
                session.stats.bytes_down.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.lifetime_queue_drops.fetch_add(
                session.stats.queue_drops.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            if let Some(cnt) = self.port_counts.get(&session.server_port) {
                cnt.fetch_sub(1, Ordering::Relaxed);
            }
            if let Some(cnt) = self.client_counts.get(&session.client_id) {
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

    /// Count sessions by client (O(1) via client index).
    pub fn count_by_client(&self, client_id: u64) -> usize {
        self.client_counts
            .get(&client_id)
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn iter_sessions(&self) -> dashmap::iter::Iter<'_, u64, Arc<Session>> {
        self.sessions.iter()
    }

    /// Register a waiter for ConnReady.
    pub fn register_conn_ready_waiter(
        &self,
        conn_id: u64,
    ) -> oneshot::Receiver<Result<(), ConnReadyError>> {
        let (tx, rx) = oneshot::channel();
        self.conn_ready_waiters.insert(conn_id, tx);
        rx
    }

    /// Notify that a connection is ready.
    pub fn notify_conn_ready(&self, conn_id: u64) -> bool {
        if let Some((_, tx)) = self.conn_ready_waiters.remove(&conn_id) {
            let _ = tx.send(Ok(()));
            true
        } else {
            false
        }
    }

    /// Notify that the client-side reported a Fault while we were waiting
    /// for ConnReady. Returns true if a waiter was woken.
    pub fn notify_conn_ready_err(
        &self,
        conn_id: u64,
        code: ErrorCode,
        message: String,
    ) -> bool {
        if let Some((_, tx)) = self.conn_ready_waiters.remove(&conn_id) {
            let _ = tx.send(Err(ConnReadyError::ClientFault {
                code: u16::from(code),
                message,
            }));
            true
        } else {
            false
        }
    }

    /// Cancel a ConnReady waiter (explicit cancellation without delivering
    /// a notification — the receiver will observe the sender being dropped).
    pub fn cancel_conn_ready_waiter(&self, conn_id: u64) {
        self.conn_ready_waiters.remove(&conn_id);
    }

    /// Clean up timed-out UDP sessions.
    /// Returns the number of sessions cleaned up.
    pub fn cleanup_timed_out_sessions(&self) -> usize {
        let timeout = self.config.udp_session_timeout;
        let mut cleaned = 0;

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

    /// Single pass over active tunnel sessions for HTTP `/api/stats`.
    ///
    /// The byte / queue-drop totals combine the counters of still-active
    /// sessions with the cumulative `lifetime_*` counters (folded-in at
    /// `remove()` time). The resulting numbers are monotonic and match the
    /// Prometheus `tunnel_bytes_total` counter, so short-lived traffic like
    /// HTTP requests no longer "disappears" from the Dashboard between
    /// polls.
    pub fn aggregate_tunnel_stats(&self) -> TunnelStatsAggregate {
        let mut out = TunnelStatsAggregate::default();
        let ordering = Ordering::Relaxed;
        out.bytes_up_total = self.lifetime_bytes_up.load(ordering);
        out.bytes_down_total = self.lifetime_bytes_down.load(ordering);
        out.queue_drops_total = self.lifetime_queue_drops.load(ordering);
        for entry in self.iter_sessions() {
            let s = entry.value();
            match s.protocol {
                SessionProtocol::Tcp => out.sessions_tcp += 1,
                SessionProtocol::Udp => out.sessions_udp += 1,
            }
            out.queue_drops_total += s.stats.queue_drops.load(ordering);
            out.bytes_up_total += s.stats.bytes_up.load(ordering);
            out.bytes_down_total += s.stats.bytes_down.load(ordering);
        }
        out.sessions_active = self.active_count();
        debug_assert_eq!(out.sessions_tcp + out.sessions_udp, out.sessions_active);
        out
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated tunnel counters derived from active sessions only.
#[derive(Debug, Clone, Copy, Default)]
pub struct TunnelStatsAggregate {
    pub sessions_active: usize,
    pub sessions_tcp: usize,
    pub sessions_udp: usize,
    pub bytes_up_total: u64,
    pub bytes_down_total: u64,
    pub queue_drops_total: u64,
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
        assert_eq!(manager.count_by_client(100), 1);
    }

    #[test]
    fn test_session_removal() {
        let manager = SessionManager::new();
        manager.create_session(1, SessionProtocol::Tcp, 8080, 100);
        assert_eq!(manager.active_count(), 1);

        let removed = manager.remove(1);
        assert!(removed.is_some());
        assert_eq!(manager.active_count(), 0);
        assert_eq!(manager.count_by_client(100), 0);
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
    fn test_count_by_client_is_indexed() {
        let manager = SessionManager::new();
        manager.create_session(1, SessionProtocol::Tcp, 8080, 100);
        manager.create_session(2, SessionProtocol::Udp, 8081, 100);
        manager.create_session(3, SessionProtocol::Tcp, 8082, 200);

        assert_eq!(manager.count_by_client(100), 2);
        assert_eq!(manager.count_by_client(200), 1);
        assert_eq!(manager.count_by_client(999), 0);

        manager.remove(1);
        assert_eq!(manager.count_by_client(100), 1);
    }

    #[test]
    fn test_session_try_send() {
        let config = SessionConfig {
            tunnel_queue_capacity: 2,
            ..Default::default()
        };
        let manager = SessionManager::with_config(config);
        let (session, mut rx) = manager.create_session(1, SessionProtocol::Tcp, 8080, 100);

        assert!(session.try_send(Bytes::from_static(b"1")));
        assert!(session.try_send(Bytes::from_static(b"2")));

        assert!(!session.try_send(Bytes::from_static(b"3")));
        assert_eq!(session.stats.queue_drops.load(Ordering::Relaxed), 1);

        let _ = rx.try_recv();
        assert!(session.try_send(Bytes::from_static(b"4")));
    }

    #[tokio::test]
    async fn test_conn_ready_notification_ok() {
        let manager = SessionManager::new();
        let rx = manager.register_conn_ready_waiter(42);

        assert!(manager.notify_conn_ready(42));
        let result = rx.await.unwrap();
        assert!(result.is_ok());

        // Second notify should fail (already consumed).
        assert!(!manager.notify_conn_ready(42));
    }

    #[tokio::test]
    async fn test_remove_wakes_waiter_with_aborted() {
        let manager = SessionManager::new();
        manager.create_session(77, SessionProtocol::Tcp, 8080, 100);
        let rx = manager.register_conn_ready_waiter(77);

        manager.remove(77);
        let err = rx.await.unwrap().unwrap_err();
        assert!(matches!(err, ConnReadyError::Aborted));
    }

    #[tokio::test]
    async fn test_notify_conn_ready_err_client_fault() {
        let manager = SessionManager::new();
        manager.create_session(88, SessionProtocol::Tcp, 8080, 100);
        let rx = manager.register_conn_ready_waiter(88);

        manager.notify_conn_ready_err(88, ErrorCode::ConnectionRefused, "refused".into());
        let err = rx.await.unwrap().unwrap_err();
        assert!(matches!(err, ConnReadyError::ClientFault { .. }));
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
        assert_eq!(manager.count_by_client(100), 0);
    }

    #[test]
    fn test_session_idle_duration() {
        let (session, _rx) = Session::new(
            1,
            SessionProtocol::Udp,
            8080,
            100,
            16,
            DEFAULT_TCP_SEND_TIMEOUT,
        );

        let idle = session.idle_duration();
        assert!(idle < Duration::from_millis(100));

        std::thread::sleep(Duration::from_millis(10));
        session.touch();
        let idle_after_touch = session.idle_duration();
        assert!(idle_after_touch < Duration::from_millis(5));
    }
}
