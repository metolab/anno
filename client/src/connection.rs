//! Control connection to server and per-session forwarding.
//!
//! `run_session` establishes a single control connection, handles all
//! multiplexed frames, and returns a `SessionError` when the session ends
//! (for any reason). The caller is responsible for the reconnect loop.

use crate::forward;
use crate::reconnect::SessionError;
use anno_common::{
    ConfigAck, ConfigPush, ConnClose, ConnProtocol, ConnReady, DataTcp, DataUdp, ErrorCode, Fault,
    Frame, FrameCodec, Message, MessageType, NewConn, Ping, Pong, Register, RegisterAck,
    TargetAddress,
};
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use socket2::{SockRef, TcpKeepalive};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

/// Default Ping interval; overridable via `ClientConfig::ping_interval`.
pub(crate) const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(15);
/// Default idle timeout; overridable via `ClientConfig::idle_timeout`.
pub(crate) const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Default TCP tunnel-send timeout; overridable via `ClientConfig::tcp_send_timeout`.
pub(crate) const DEFAULT_TCP_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for client sessions.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub tunnel_queue_capacity: usize,
    pub control_channel_capacity: usize,
    pub http_proxy_port: Option<u16>,
    /// Interval between client-originated Pings.
    pub ping_interval: Duration,
    /// Reconnect if no frame is received from the server within this window.
    pub idle_timeout: Duration,
    /// Maximum wait when forwarding a TCP frame into the tunnel queue; on
    /// timeout the session is closed instead of blocking the control loop.
    pub tcp_send_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            tunnel_queue_capacity: 256,
            control_channel_capacity: 1024,
            http_proxy_port: None,
            ping_interval: DEFAULT_PING_INTERVAL,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            tcp_send_timeout: DEFAULT_TCP_SEND_TIMEOUT,
        }
    }
}

/// Session entry with bounded sender and drop statistics.
///
/// `tx` is stored inside `RwLock<Option<_>>` so that `close()` can drop the
/// sender explicitly — the paired receiver held by the downstream forwarding
/// task then sees the channel as closed and the task exits instead of
/// leaking. We use `unwrap_or_else(|e| e.into_inner())` when locking so that
/// a panicked writer never blocks cleanup.
struct SessionEntry {
    tx: std::sync::RwLock<Option<mpsc::Sender<Bytes>>>,
    drops: AtomicU64,
    tcp_send_timeout: Duration,
}

fn rw_read<'a, T>(l: &'a std::sync::RwLock<T>) -> std::sync::RwLockReadGuard<'a, T> {
    l.read().unwrap_or_else(|e| e.into_inner())
}

fn rw_write<'a, T>(l: &'a std::sync::RwLock<T>) -> std::sync::RwLockWriteGuard<'a, T> {
    l.write().unwrap_or_else(|e| e.into_inner())
}

impl SessionEntry {
    fn new(tx: mpsc::Sender<Bytes>, tcp_send_timeout: Duration) -> Self {
        Self {
            tx: std::sync::RwLock::new(Some(tx)),
            drops: AtomicU64::new(0),
            tcp_send_timeout,
        }
    }

    fn try_send(&self, data: Bytes) -> bool {
        let guard = rw_read(&self.tx);
        let tx = match guard.as_ref() {
            Some(tx) => tx,
            None => return false,
        };
        match tx.try_send(data) {
            Ok(_) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.drops.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("tunnel queue full, dropping UDP packet");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    /// Backpressure-safe send for TCP: waits up to `tcp_send_timeout`.
    async fn send_tcp(&self, data: Bytes) -> bool {
        let tx = rw_read(&self.tx).as_ref().cloned();
        let Some(tx) = tx else { return false };
        match timeout(self.tcp_send_timeout, tx.send(data)).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => false,
            Err(_) => {
                tracing::warn!("TCP tunnel send timeout — closing session");
                false
            }
        }
    }

    /// Explicitly close the tunnel sender so the downstream forwarding task
    /// can exit instead of blocking indefinitely on `tun_rx.recv()`.
    fn close(&self) {
        rw_write(&self.tx).take();
    }
}

pub async fn run_session(
    server: &str,
    key: &str,
    config: &ClientConfig,
) -> Result<(), SessionError> {
    // Top-level cancellation token: when this session is torn down (any
    // way — IO error, idle timeout, auth failure, clean server close) we
    // `cancel()` the token in the scope guard below, which immediately
    // wakes up every task spawned for this session (handle_new_conn, its
    // up/down workers, the write_task). Without this, those tasks used
    // to linger until their next `.await` on a channel unblocked — for
    // the reconnect path that could mean they keep running against the
    // NEW session's server until the OS eventually kicked the old TCP
    // socket.
    let session_cancel = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop(session_cancel.clone());

    let mut addrs = tokio::net::lookup_host(server)
        .await
        .map_err(SessionError::Connect)?;
    let addr = addrs
        .next()
        .ok_or_else(|| SessionError::Connect(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("DNS returned no addresses for {server}"),
        )))?;

    let stream = TcpStream::connect(addr)
        .await
        .map_err(SessionError::Connect)?;

    stream.set_nodelay(true).map_err(SessionError::Io)?;
    {
        let ka = TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10))
            .with_retries(3);
        SockRef::from(&stream)
            .set_tcp_keepalive(&ka)
            .map_err(SessionError::Io)?;
    }

    let (rh, wh) = stream.into_split();
    let mut read_half = FramedRead::new(rh, FrameCodec);
    let mut write_half = FramedWrite::new(wh, FrameCodec);

    let reg = Register::new(key, config.http_proxy_port).to_frame(0);
    write_half.send(reg).await.map_err(SessionError::Io)?;

    let (out_tx, mut out_rx) = mpsc::channel::<Frame>(config.control_channel_capacity);

    let writer_cancel = session_cancel.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = writer_cancel.cancelled() => break,
                f = out_rx.recv() => match f {
                    Some(f) => {
                        if write_half.send(f).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
        let _ = write_half.close().await;
    });

    let tcp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>> = Arc::new(DashMap::new());
    let udp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>> = Arc::new(DashMap::new());
    let config = Arc::new(config.clone());

    let mut ping_ticker = tokio::time::interval(config.ping_interval);
    ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_ticker.tick().await;

    let mut idle_ticker = tokio::time::interval(Duration::from_secs(5));
    idle_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_ticker.tick().await;

    let mut last_rx = Instant::now();

    loop {
        tokio::select! {
            biased;

            frame_res = read_half.next() => {
                let frame = match frame_res {
                    None => {
                        tracing::info!("server closed control connection");
                        return Ok(());
                    }
                    Some(Err(e)) => {
                        return Err(SessionError::Io(e));
                    }
                    Some(Ok(f)) => f,
                };

                last_rx = Instant::now();

                match frame.msg_type {
                    MessageType::RegisterAck => {
                        let ack = RegisterAck::from_frame(&frame)
                            .map_err(SessionError::Protocol)?;
                        tracing::info!(client_id = ack.client_id, "registered with server");
                    }
                    MessageType::ConfigPush => {
                        let _cfg = ConfigPush::from_frame(&frame)
                            .map_err(SessionError::Protocol)?;
                        let _ = out_tx.send(ConfigAck.to_frame(0)).await;
                    }
                    MessageType::Ping => {
                        let _ = out_tx.send(Pong.to_frame(0)).await;
                    }
                    MessageType::Pong => {}
                    MessageType::NewConn => {
                        let nc = NewConn::from_frame(&frame)
                            .map_err(SessionError::Protocol)?;
                        let out = out_tx.clone();
                        let tcp_m = Arc::clone(&tcp_sessions);
                        let udp_m = Arc::clone(&udp_sessions);
                        let cfg = Arc::clone(&config);
                        let conn_id = frame.conn_id;
                        let child_cancel = session_cancel.child_token();
                        tokio::spawn(async move {
                            if let Err(e) = handle_new_conn(
                                conn_id,
                                nc.protocol,
                                nc.target,
                                out,
                                tcp_m,
                                udp_m,
                                &cfg,
                                child_cancel,
                            )
                            .await
                            {
                                tracing::warn!("new_conn {} failed: {}", conn_id, e);
                            }
                        });
                    }
                    MessageType::DataTcp => {
                        // IMPORTANT: do NOT spawn per frame — spawning breaks
                        // TCP byte ordering because independent tasks may run
                        // out of order. Send inline; `send_tcp` has its own
                        // bounded timeout so a single misbehaving session
                        // cannot stall the control loop forever.
                        let conn_id = frame.conn_id;
                        let payload = match DataTcp::from_frame(&frame) {
                            Ok(d) => d.data,
                            Err(_) => continue,
                        };
                        let entry_opt = tcp_sessions.get(&conn_id).map(|e| Arc::clone(&e));
                        if let Some(entry) = entry_opt {
                            if !entry.send_tcp(payload).await {
                                // Close the tunnel sender: the downstream task
                                // will exit and it will eventually remove the
                                // session from the map via its cleanup branch.
                                // Avoid double-remove here to keep cleanup
                                // responsibility in one place (the down task).
                                entry.close();
                                let _ = out_tx.send(ConnClose.to_frame(conn_id)).await;
                            }
                        } else {
                            tracing::debug!(conn_id, "DataTcp for unknown session");
                        }
                    }
                    MessageType::DataUdp => {
                        let payload = match DataUdp::from_frame(&frame) {
                            Ok(d) => d.data,
                            Err(_) => continue,
                        };
                        let entry_opt = udp_sessions
                            .get(&frame.conn_id)
                            .map(|e| Arc::clone(&e));
                        if let Some(entry) = entry_opt {
                            entry.try_send(payload);
                        }
                    }
                    MessageType::ConnClose => {
                        if let Some((_, e)) = tcp_sessions.remove(&frame.conn_id) {
                            e.close();
                        }
                        if let Some((_, e)) = udp_sessions.remove(&frame.conn_id) {
                            e.close();
                        }
                    }
                    MessageType::Fault => {
                        if let Ok(f) = Fault::from_frame(&frame) {
                            tracing::warn!(code = u16::from(f.code), message = %f.message, "received Fault from server");
                            let invalid_key = f.code == ErrorCode::UnknownClient
                                || (f.code == ErrorCode::ConnectionRefused
                                    && f.message.contains("invalid client key"));
                            if invalid_key {
                                return Err(SessionError::AuthFailed);
                            }
                        }
                    }
                    _ => {}
                }
            }

            _ = ping_ticker.tick() => {
                if out_tx.send(Ping.to_frame(0)).await.is_err() {
                    return Err(SessionError::Io(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "control write channel closed",
                    )));
                }
            }

            _ = idle_ticker.tick() => {
                if last_rx.elapsed() >= config.idle_timeout {
                    tracing::warn!("control connection idle for {:?}, reconnecting", last_rx.elapsed());
                    return Err(SessionError::IdleTimeout);
                }
            }
        }
    }
}

/// RAII guard that cancels a `CancellationToken` on drop. Used so every
/// exit path from `run_session` (including panics and early `?` returns)
/// tears down the fleet of per-session tasks immediately.
struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_new_conn(
    conn_id: u64,
    proto: ConnProtocol,
    target: TargetAddress,
    out_tx: mpsc::Sender<Frame>,
    tcp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>>,
    udp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>>,
    config: &ClientConfig,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match proto {
        ConnProtocol::Tcp => {
            let (tun_tx, mut tun_rx) = mpsc::channel::<Bytes>(config.tunnel_queue_capacity);
            let entry = Arc::new(SessionEntry::new(tun_tx, config.tcp_send_timeout));
            tcp_sessions.insert(conn_id, Arc::clone(&entry));

            let stream = match forward::tcp_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    if let Some((_, e2)) = tcp_sessions.remove(&conn_id) {
                        e2.close();
                    }
                    let fault =
                        Fault::new(ErrorCode::ConnectionRefused, e.to_string()).to_frame(conn_id);
                    let _ = out_tx.send(fault).await;
                    return Err(e.into());
                }
            };
            out_tx.send(ConnReady.to_frame(conn_id)).await?;

            let (mut rh, mut wh) = stream.into_split();

            let out_u = out_tx.clone();
            let tcp_sessions_up = Arc::clone(&tcp_sessions);
            let cancel_up = cancel.clone();
            let up = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let n = tokio::select! {
                        biased;
                        _ = cancel_up.cancelled() => break,
                        r = rh.read(&mut buf) => match r {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        },
                    };
                    let fr = DataTcp::new(Bytes::copy_from_slice(&buf[..n])).to_frame(conn_id);
                    if out_u.send(fr).await.is_err() {
                        break;
                    }
                }
                let _ = out_u.send(ConnClose.to_frame(conn_id)).await;
                if let Some((_, e)) = tcp_sessions_up.remove(&conn_id) {
                    e.close();
                }
            });

            let out_d = out_tx.clone();
            let tcp_sessions_dn = Arc::clone(&tcp_sessions);
            let cancel_dn = cancel.clone();
            let down = tokio::spawn(async move {
                loop {
                    let chunk = tokio::select! {
                        biased;
                        _ = cancel_dn.cancelled() => break,
                        r = tun_rx.recv() => match r {
                            Some(c) => c,
                            None => break,
                        },
                    };
                    if wh.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = wh.shutdown().await;
                if let Some((_, e)) = tcp_sessions_dn.remove(&conn_id) {
                    e.close();
                }
                let _ = out_d.send(ConnClose.to_frame(conn_id)).await;
            });

            let _ = tokio::join!(up, down);
        }

        ConnProtocol::Udp => {
            let (tun_tx, mut tun_rx) = mpsc::channel::<Bytes>(config.tunnel_queue_capacity);
            let entry = Arc::new(SessionEntry::new(tun_tx, config.tcp_send_timeout));
            udp_sessions.insert(conn_id, Arc::clone(&entry));

            let sock = match forward::udp_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    if let Some((_, e2)) = udp_sessions.remove(&conn_id) {
                        e2.close();
                    }
                    let fault =
                        Fault::new(ErrorCode::ConnectionRefused, e.to_string()).to_frame(conn_id);
                    let _ = out_tx.send(fault).await;
                    return Err(e.into());
                }
            };
            out_tx.send(ConnReady.to_frame(conn_id)).await?;

            let sock = Arc::new(sock);
            let out_u = out_tx.clone();
            let udp_sessions_up = Arc::clone(&udp_sessions);
            let s2 = Arc::clone(&sock);
            let cancel_up = cancel.clone();
            let up = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let n = tokio::select! {
                        biased;
                        _ = cancel_up.cancelled() => break,
                        r = s2.recv(&mut buf) => match r {
                            Ok(n) => n,
                            Err(_) => break,
                        },
                    };
                    let fr = DataUdp::new(Bytes::copy_from_slice(&buf[..n])).to_frame(conn_id);
                    if out_u.send(fr).await.is_err() {
                        break;
                    }
                }
                let _ = out_u.send(ConnClose.to_frame(conn_id)).await;
                if let Some((_, e)) = udp_sessions_up.remove(&conn_id) {
                    e.close();
                }
            });

            let out_d = out_tx.clone();
            let udp_sessions_dn = Arc::clone(&udp_sessions);
            let s3 = Arc::clone(&sock);
            let cancel_dn = cancel.clone();
            let down = tokio::spawn(async move {
                loop {
                    let chunk = tokio::select! {
                        biased;
                        _ = cancel_dn.cancelled() => break,
                        r = tun_rx.recv() => match r {
                            Some(c) => c,
                            None => break,
                        },
                    };
                    if s3.send(&chunk).await.is_err() {
                        break;
                    }
                }
                if let Some((_, e)) = udp_sessions_dn.remove(&conn_id) {
                    e.close();
                }
                let _ = out_d.send(ConnClose.to_frame(conn_id)).await;
            });

            let _ = tokio::join!(up, down);
        }
    }
    Ok(())
}
