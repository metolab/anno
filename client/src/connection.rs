//! Control connection to server and per-session forwarding.
//!
//! `run_session` establishes a single control connection, handles all
//! multiplexed frames, and returns a `SessionError` when the session ends
//! (for any reason). The caller is responsible for the reconnect loop.

use crate::forward;
use crate::reconnect::SessionError;
use anno_common::mux::{
    next_scheduled_frame, CreditMap, FrameShard, MuxSender, ReassemblyOutcome, Reassembler,
    Scheduler,
};
use anno_common::{
    ConfigAck, ConfigPush, ConnClose, ConnProtocol, ConnReady, DataUdp, ErrorCode, Fault, Frame,
    FrameCodec, GoAway, LaneHello, Message, MessageType, NewConn, Ping, Pong, Register,
    RegisterAck, TargetAddress, WindowUpdate, DEFAULT_INITIAL_WINDOW, DEFAULT_LANES,
    DEFAULT_MAX_FRAME_SIZE,
};
use bytes::Bytes;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use socket2::{SockRef, TcpKeepalive};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

/// Cap on the bytes a single TCP `DataTcp` reassembly is allowed to
/// occupy on the receive side before the stream is forcibly closed.
/// Slightly above the largest `max_frame_size` we'd ever negotiate so
/// adversarial peers cannot pin memory.
const MAX_REASSEMBLY_BYTES: usize = 1024 * 1024;
/// Wall-clock deadline for a single in-flight reassembly. Streams that
/// trickle shards beyond this window get swept.
const REASSEMBLY_DEADLINE: Duration = Duration::from_secs(5);

/// Default Ping interval; overridable via `ClientConfig::ping_interval`.
pub(crate) const DEFAULT_PING_INTERVAL: Duration = Duration::from_secs(15);
/// Default idle timeout; overridable via `ClientConfig::idle_timeout`.
pub(crate) const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Default TCP tunnel-send timeout; overridable via `ClientConfig::tcp_send_timeout`.
pub(crate) const DEFAULT_TCP_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard cap on how long the client will wait for in-flight streams to
/// finish after `GoAway`. Mirrors the server's `MuxDefaults::goaway_grace`.
const GOAWAY_GRACE: Duration = Duration::from_secs(5);
/// How long lane writers keep draining after the session is cancelled
/// so already-emitted Fault/ConnClose frames flush onto the wire
/// before the FIN. Mirrors the server's `WRITER_DRAIN_GRACE`.
const WRITER_DRAIN_GRACE: Duration = Duration::from_millis(500);

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
    /// Number of physical TCP lanes the client wants for this session.
    /// Server may grant fewer. 0 means "use protocol default".
    pub requested_lanes: u8,
    /// Largest single shard the client is willing to send/accept on the
    /// wire. 0 means "use protocol default".
    pub max_frame_size: u16,
    /// Initial per-stream credit window (bytes). 0 means default.
    pub initial_window: u32,
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
            requested_lanes: DEFAULT_LANES,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            initial_window: DEFAULT_INITIAL_WINDOW,
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

    // Try every address the resolver returns (capped) so a server
    // exposing both IPv6 and IPv4 keeps working when one family is
    // unreachable. Cap mirrors `forward::DNS_FALLBACK_MAX_ATTEMPTS`.
    const SERVER_DNS_MAX_ATTEMPTS: usize = 8;
    let candidate_addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(server)
        .await
        .map_err(SessionError::Connect)?
        .take(SERVER_DNS_MAX_ATTEMPTS)
        .collect();
    if candidate_addrs.is_empty() {
        return Err(SessionError::Connect(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("DNS returned no addresses for {server}"),
        )));
    }

    // -- Open primary lane (lane 0) and complete registration ------------
    let mut last_err: Option<SessionError> = None;
    let mut chosen_addr: Option<std::net::SocketAddr> = None;
    let mut lane0_opt: Option<TcpStream> = None;
    for addr in &candidate_addrs {
        match open_tcp_lane(*addr).await {
            Ok(s) => {
                chosen_addr = Some(*addr);
                lane0_opt = Some(s);
                break;
            }
            Err(e) => {
                tracing::debug!(server = %server, %addr, "lane 0 connect failed: {e}");
                last_err = Some(e);
            }
        }
    }
    let (addr, lane0) = match (chosen_addr, lane0_opt) {
        (Some(a), Some(s)) => (a, s),
        _ => {
            return Err(last_err.unwrap_or_else(|| {
                SessionError::Connect(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("no reachable address for {server}"),
                ))
            }));
        }
    };
    let (rh0, wh0) = lane0.into_split();
    let mut read_half0 = FramedRead::new(rh0, FrameCodec);
    let mut write_half0 = FramedWrite::new(wh0, FrameCodec);

    let reg = Register {
        key: key.to_string(),
        http_proxy_port: config.http_proxy_port,
        requested_lanes: config.requested_lanes,
        max_frame_size: config.max_frame_size,
        initial_window: config.initial_window,
    }
    .to_frame(0);
    write_half0.send(reg).await.map_err(SessionError::Io)?;

    // Synchronously wait for RegisterAck so we know how many extra lanes
    // the server has granted before we start opening them.
    let ack_frame = match tokio::time::timeout(
        Duration::from_secs(15),
        read_half0.next(),
    )
    .await
    {
        Ok(Some(Ok(f))) => f,
        Ok(Some(Err(e))) => return Err(SessionError::Io(e)),
        Ok(None) => return Err(SessionError::Connect(std::io::Error::other("server closed before RegisterAck"))),
        Err(_) => return Err(SessionError::Connect(std::io::Error::other("RegisterAck timeout"))),
    };
    if ack_frame.msg_type != MessageType::RegisterAck {
        return Err(SessionError::Protocol(
            anno_common::ProtocolError::BadMessageType(ack_frame.msg_type as u8),
        ));
    }
    let ack = RegisterAck::from_frame(&ack_frame).map_err(SessionError::Protocol)?;
    let agreed_frame = if ack.max_frame_size == 0 {
        DEFAULT_MAX_FRAME_SIZE
    } else {
        ack.max_frame_size
    };
    let agreed_window = if ack.initial_window == 0 {
        DEFAULT_INITIAL_WINDOW
    } else {
        ack.initial_window
    };
    tracing::info!(
        client_id = ack.client_id,
        session_token = ack.session_token,
        granted_lanes = ack.granted_lanes,
        max_frame_size = agreed_frame,
        initial_window = agreed_window,
        "registered with server"
    );

    // -- Spawn lane 0 writer task -----------------------------------------
    let (lane0_tx, lane0_rx) = mpsc::channel::<Frame>(config.control_channel_capacity);
    // Pre-allocate slots for every lane the server granted so that
    // routing during the brief lane-attach window falls back to lane 0
    // instead of a phantom slot. `granted_lanes` is computed below; we
    // size up after it's known.
    let granted_lanes_usize = ack.granted_lanes.max(1) as usize;
    let mux_tx = MuxSender::with_capacity(lane0_tx, granted_lanes_usize);

    // dispatch channel: every lane's reader task funnels frames here so
    // the main loop has a single point of demultiplexing. Bounded —
    // an unbounded channel would let a slow control loop balloon
    // memory if every lane keeps stuffing frames in. Capacity scales
    // with the number of lanes so steady-state throughput is
    // unaffected; transient backpressure parks lane readers, which
    // in turn naturally throttles the upstream peer via TCP's window.
    let dispatch_capacity = config
        .control_channel_capacity
        .saturating_mul(granted_lanes_usize)
        .max(config.control_channel_capacity);
    let (dispatch_tx, mut dispatch_rx) =
        mpsc::channel::<Result<Frame, std::io::Error>>(dispatch_capacity);

    spawn_lane_writer(session_cancel.clone(), mux_tx.clone(), 0, write_half0, lane0_rx);
    spawn_lane_reader(
        0,
        session_cancel.clone(),
        mux_tx.clone(),
        read_half0,
        dispatch_tx.clone(),
    );

    // -- Open extra lanes [1..granted_lanes] in parallel -----------------
    //
    // Establishing them serially used to make the worst-case attach
    // latency `(granted_lanes - 1) * LANE_CONNECT_TIMEOUT`. Doing it
    // concurrently turns it into `≈ LANE_CONNECT_TIMEOUT`. We also
    // *tolerate* per-lane failures here: as long as lane 0 is up, the
    // session is functional (lane 0 is the routing fallback target);
    // failed extra lanes are simply skipped, with `mux_lanes_active`
    // reflecting the real number attached.
    let granted_lanes = granted_lanes_usize;
    metrics::counter!("mux_lanes_attached_total", "side" => "client")
        .increment(granted_lanes as u64);

    if granted_lanes > 1 {
        let mut attach_futures = Vec::with_capacity(granted_lanes - 1);
        for lane_idx in 1..granted_lanes {
            let session_token = ack.session_token;
            let granted_u8 = granted_lanes as u8;
            attach_futures.push(async move {
                let lane = open_tcp_lane(addr).await?;
                let (rh, wh) = lane.into_split();
                let rh = FramedRead::new(rh, FrameCodec);
                let mut wh = FramedWrite::new(wh, FrameCodec);
                let hello =
                    LaneHello::new(session_token, lane_idx as u8, granted_u8).to_frame(0);
                wh.send(hello).await.map_err(SessionError::Io)?;
                Ok::<_, SessionError>((lane_idx, rh, wh))
            });
        }
        let results = futures::future::join_all(attach_futures).await;
        let mut attached = 0usize;
        for r in results {
            match r {
                Ok((lane_idx, rh, wh)) => {
                    let (lane_tx, lane_rx) =
                        mpsc::channel::<Frame>(config.control_channel_capacity);
                    mux_tx.set_lane(lane_idx, lane_tx).await;
                    spawn_lane_writer(
                        session_cancel.clone(),
                        mux_tx.clone(),
                        lane_idx,
                        wh,
                        lane_rx,
                    );
                    spawn_lane_reader(
                        lane_idx as u8,
                        session_cancel.clone(),
                        mux_tx.clone(),
                        rh,
                        dispatch_tx.clone(),
                    );
                    attached += 1;
                }
                Err(e) => {
                    // Tolerate: log, count, keep going. Lane 0 is
                    // still up so the session is fully functional.
                    metrics::counter!(
                        "mux_lane_failures_total",
                        "side" => "client",
                        "role" => "attach"
                    )
                    .increment(1);
                    tracing::warn!(
                        "extra lane attach failed (continuing on lane 0): {e}"
                    );
                }
            }
        }
        metrics::gauge!("mux_lanes_active", "side" => "client")
            .set((attached + 1) as f64);
    } else {
        metrics::gauge!("mux_lanes_active", "side" => "client").set(1.0);
    }
    drop(dispatch_tx); // ownership held only by per-lane reader tasks now.

    let out_tx = mux_tx;

    let tcp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>> = Arc::new(DashMap::new());
    let udp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>> = Arc::new(DashMap::new());
    let config = Arc::new(config.clone());

    // Negotiated `max_frame_size` defaults to the client's request until the
    // server's RegisterAck tells us the agreed value. This is what the
    // outbound DataTcp sharder uses, so it must be in scope for every
    // spawned per-conn task.
    let negotiated_max_frame_size: Arc<AtomicU64> = Arc::new(AtomicU64::new(agreed_frame as u64));

    // Receive-side reassembler for `MORE`-fragmented `DataTcp` frames.
    // Single global instance — keyed by `conn_id` so concurrent sessions
    // can share it without contention beyond the brief mutex hold.
    let reassembler: Arc<StdMutex<Reassembler>> = Arc::new(StdMutex::new(Reassembler::new(
        MAX_REASSEMBLY_BYTES,
        REASSEMBLY_DEADLINE,
    )));

    // Per-stream credit windows, sized at the server-granted initial
    // window. Created lazily per stream and dropped on ConnClose.
    let credit_map: Arc<CreditMap> = Arc::new(CreditMap::new(agreed_window));

    // Set to true when the server sends `GoAway`. While draining we
    // refuse fresh `NewConn` frames (defensive — the server should
    // already have stopped emitting them) and a watchdog task triggers
    // session cancellation once existing streams complete or the
    // grace timer expires, whichever comes first.
    let draining = Arc::new(AtomicBool::new(false));

    let mut ping_ticker = tokio::time::interval(config.ping_interval);
    ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_ticker.tick().await;

    let mut idle_ticker = tokio::time::interval(Duration::from_secs(5));
    idle_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_ticker.tick().await;

    // Sweep stale reassembly buffers periodically so a peer that dribbles
    // shards forever can't pin client memory.
    let mut reassembly_sweep_ticker = tokio::time::interval(Duration::from_secs(2));
    reassembly_sweep_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reassembly_sweep_ticker.tick().await;

    let mut last_rx = Instant::now();

    loop {
        tokio::select! {
            biased;

            frame_res = dispatch_rx.recv() => {
                let frame = match frame_res {
                    None => {
                        tracing::info!("all lanes closed");
                        return Ok(());
                    }
                    Some(Err(e)) => {
                        return Err(SessionError::Io(e));
                    }
                    Some(Ok(f)) => f,
                };

                last_rx = Instant::now();

                match frame.msg_type {
                    MessageType::ConfigPush => {
                        let _cfg = ConfigPush::from_frame(&frame)
                            .map_err(SessionError::Protocol)?;
                        // ConfigAck failure means lane 0's writer
                        // channel is gone (i.e. the session is
                        // already dying). Surface immediately so the
                        // reconnect loop kicks in instead of looping
                        // on a corpse.
                        if out_tx.send(ConfigAck.to_frame(0)).await.is_err() {
                            return Err(SessionError::Io(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "control write channel closed (ConfigAck)",
                            )));
                        }
                    }
                    MessageType::Ping => {
                        if out_tx.send(Pong.to_frame(0)).await.is_err() {
                            return Err(SessionError::Io(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "control write channel closed (Pong)",
                            )));
                        }
                    }
                    MessageType::Pong => {}
                    MessageType::NewConn => {
                        let nc = NewConn::from_frame(&frame)
                            .map_err(SessionError::Protocol)?;
                        if draining.load(Ordering::Relaxed) {
                            // Server has issued GoAway; politely refuse
                            // any latecomer NewConn so the public side
                            // tears down cleanly.
                            let fault = Fault::new(
                                ErrorCode::ConnectionRefused,
                                "client draining (GoAway)",
                            )
                            .to_frame(frame.conn_id);
                            let _ = out_tx.send(fault).await;
                            continue;
                        }
                        let out = out_tx.clone();
                        let tcp_m = Arc::clone(&tcp_sessions);
                        let udp_m = Arc::clone(&udp_sessions);
                        let cfg = Arc::clone(&config);
                        let conn_id = frame.conn_id;
                        let child_cancel = session_cancel.child_token();
                        let frame_size_handle = Arc::clone(&negotiated_max_frame_size);
                        let credit_map_handle = Arc::clone(&credit_map);
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
                                frame_size_handle,
                                credit_map_handle,
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
                        // Feed the shard into the reassembler; if it's not the
                        // last shard we just stash it and wait for more.
                        let outcome = {
                            let mut r = reassembler.lock().unwrap_or_else(|e| e.into_inner());
                            r.feed(frame)
                        };
                        let payload = match outcome {
                            ReassemblyOutcome::Pending => continue,
                            ReassemblyOutcome::Complete(b) => b,
                            ReassemblyOutcome::Overflow => {
                                metrics::counter!(
                                    "mux_reassembly_overflow_total",
                                    "side" => "client"
                                )
                                .increment(1);
                                tracing::warn!(
                                    conn_id,
                                    "TCP reassembly overflow; closing stream"
                                );
                                if let Some((_, e)) = tcp_sessions.remove(&conn_id) {
                                    e.close();
                                }
                                let _ = out_tx.send(ConnClose.to_frame(conn_id)).await;
                                continue;
                            }
                        };
                        let entry_opt = tcp_sessions.get(&conn_id).map(|e| Arc::clone(&e));
                        if let Some(entry) = entry_opt {
                            let payload_len = payload.len();
                            if !entry.send_tcp(payload).await {
                                // Close the tunnel sender: the downstream task
                                // will exit and it will eventually remove the
                                // session from the map via its cleanup branch.
                                // Avoid double-remove here to keep cleanup
                                // responsibility in one place (the down task).
                                entry.close();
                                {
                                    let mut r =
                                        reassembler.lock().unwrap_or_else(|e| e.into_inner());
                                    r.discard(conn_id);
                                }
                                credit_map.remove(conn_id);
                                let _ = out_tx.send(ConnClose.to_frame(conn_id)).await;
                            } else {
                                // Bytes have landed in the local TCP socket
                                // buffer — replenish the server's send credit
                                // if the per-stream threshold has been
                                // crossed.
                                let credit = credit_map.get_or_create(conn_id);
                                if let Some(inc) = credit.record_received(payload_len) {
                                    let _ = out_tx
                                        .send(WindowUpdate::new(inc).to_frame(conn_id))
                                        .await;
                                    metrics::counter!(
                                        "mux_window_updates_total",
                                        "side" => "client",
                                        "dir" => "tx"
                                    )
                                    .increment(1);
                                }
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
                        let mut r = reassembler.lock().unwrap_or_else(|e| e.into_inner());
                        r.discard(frame.conn_id);
                        credit_map.remove(frame.conn_id);
                    }
                    MessageType::WindowUpdate => match WindowUpdate::from_frame(&frame) {
                        Ok(wu) => {
                            metrics::counter!(
                                "mux_window_updates_total",
                                "side" => "client",
                                "dir" => "rx"
                            )
                            .increment(1);
                            if let Some(c) = credit_map.get(frame.conn_id) {
                                c.add_send_credit(wu.increment);
                            }
                        }
                        Err(e) => tracing::warn!("invalid WindowUpdate from server: {}", e),
                    },
                    MessageType::Fault => {
                        if let Ok(f) = Fault::from_frame(&frame) {
                            tracing::warn!(code = u16::from(f.code), message = %f.message, "received Fault from server");
                            // Treat the new explicit `AuthFailed` and the
                            // legacy `UnknownClient`/text-matched
                            // `ConnectionRefused` as terminal auth
                            // failures so the reconnect loop stops
                            // hammering the server.
                            let invalid_key = f.code == ErrorCode::AuthFailed
                                || f.code == ErrorCode::UnknownClient
                                || (f.code == ErrorCode::ConnectionRefused
                                    && f.message.contains("invalid client key"));
                            if invalid_key {
                                return Err(SessionError::AuthFailed);
                            }
                        }
                    }
                    MessageType::GoAway => {
                        let ga = GoAway::from_frame(&frame).map_err(SessionError::Protocol)?;
                        // Count every GoAway frame received, including
                        // duplicates, so the metric reflects what's on
                        // the wire rather than the de-dup'd state.
                        metrics::counter!("mux_goaway_total", "dir" => "rx").increment(1);
                        if draining.swap(true, Ordering::SeqCst) {
                            continue; // already draining, no-op
                        }
                        tracing::info!(
                            last_accepted_conn_id = ga.last_accepted_conn_id,
                            code = u16::from(ga.code),
                            reason = %ga.reason,
                            "received GoAway from server, draining"
                        );
                        // Watchdog: cancel the session as soon as
                        // active streams drop to zero, or after the
                        // grace timeout — whichever first. Cancellation
                        // closes every lane reader, drains
                        // dispatch_rx, and the loop exits with Ok(()).
                        let cancel_after = session_cancel.clone();
                        let tcp_m = Arc::clone(&tcp_sessions);
                        let udp_m = Arc::clone(&udp_sessions);
                        tokio::spawn(async move {
                            let deadline = Instant::now() + GOAWAY_GRACE;
                            loop {
                                if tcp_m.is_empty() && udp_m.is_empty() {
                                    tracing::info!("all streams drained after GoAway");
                                    break;
                                }
                                if Instant::now() >= deadline {
                                    tracing::warn!(
                                        remaining_tcp = tcp_m.len(),
                                        remaining_udp = udp_m.len(),
                                        "GoAway grace expired, force-closing"
                                    );
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            cancel_after.cancel();
                        });
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

            _ = reassembly_sweep_ticker.tick() => {
                let expired = {
                    let mut r = reassembler.lock().unwrap_or_else(|e| e.into_inner());
                    r.sweep_expired(Instant::now())
                };
                for conn_id in expired {
                    tracing::warn!(conn_id, "reassembly deadline exceeded; closing stream");
                    if let Some((_, e)) = tcp_sessions.remove(&conn_id) {
                        e.close();
                    }
                    credit_map.remove(conn_id);
                    let _ = out_tx.send(ConnClose.to_frame(conn_id)).await;
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

/// Cap on how long a single lane's TCP connect is allowed to sit
/// before we give up. Prevents a half-dead server from pinning the
/// session in the lane-attach loop.
const LANE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Open a single mux lane: a TCP connection to the server with the
/// usual nodelay+keepalive tuning. Used both for lane 0 and for the
/// extra LaneHello-attached lanes.
async fn open_tcp_lane(addr: std::net::SocketAddr) -> Result<TcpStream, SessionError> {
    let stream = match tokio::time::timeout(LANE_CONNECT_TIMEOUT, TcpStream::connect(addr)).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(SessionError::Connect(e)),
        Err(_) => {
            return Err(SessionError::Connect(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "lane connect to {} timed out after {:?}",
                    addr, LANE_CONNECT_TIMEOUT
                ),
            )))
        }
    };
    stream.set_nodelay(true).map_err(SessionError::Io)?;
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    SockRef::from(&stream)
        .set_tcp_keepalive(&ka)
        .map_err(SessionError::Io)?;
    Ok(stream)
}

/// Spawn the per-lane writer task: drains `lane_rx` (via the shared
/// scheduler) into the underlying socket. Exits cleanly when the
/// session is cancelled or the socket dies. On exit it clears its
/// slot in `mux_tx` so subsequent outbound frames don't try to route
/// to a dead lane (they'll fall back to lane 0).
fn spawn_lane_writer(
    cancel: CancellationToken,
    mux_tx: MuxSender,
    lane_idx: usize,
    mut wh: FramedWrite<tokio::net::tcp::OwnedWriteHalf, FrameCodec>,
    mut lane_rx: mpsc::Receiver<Frame>,
) {
    tokio::spawn(async move {
        let mut sched = Scheduler::new();
        loop {
            tokio::select! {
                biased;
                // On cancel, briefly drain enqueued frames so an
                // already-emitted Fault/ConnClose makes it on the
                // wire before the FIN. Mirrors the server-side
                // `drain_writer_on_cancel` helper.
                _ = cancel.cancelled() => {
                    let drain_deadline = tokio::time::sleep(WRITER_DRAIN_GRACE);
                    tokio::pin!(drain_deadline);
                    loop {
                        tokio::select! {
                            biased;
                            _ = &mut drain_deadline => break,
                            f = next_scheduled_frame(&mut sched, &mut lane_rx) => match f {
                                Some(frame) => {
                                    if wh.send(frame).await.is_err() {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                    }
                    break;
                }
                f = next_scheduled_frame(&mut sched, &mut lane_rx) => match f {
                    Some(f) => {
                        if wh.send(f).await.is_err() {
                            metrics::counter!(
                                "mux_lane_failures_total",
                                "side" => "client",
                                "role" => "writer"
                            )
                            .increment(1);
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
        let _ = wh.flush().await;
        let _ = wh.close().await;
        // Lane 0 stays in the slot — the session will tear down via
        // the reader's escalation path. For non-zero lanes, vacate
        // the slot so future frames fall back to lane 0.
        if lane_idx > 0 {
            mux_tx.clear_lane(lane_idx).await;
        }
    });
}

/// Spawn the per-lane reader task: every inbound frame is forwarded to
/// the shared dispatch channel. Lane 0's failure is escalated as a
/// session-level IO error (lane 0 carries the control plane and is
/// also the routing fallback target). Failures on lanes 1..N just
/// degrade routing — the lane is removed from `mux_tx` and the
/// session keeps running on the remaining lanes (with lane-0
/// fallback).
fn spawn_lane_reader(
    lane_idx: u8,
    cancel: CancellationToken,
    mux_tx: MuxSender,
    mut rh: FramedRead<tokio::net::tcp::OwnedReadHalf, FrameCodec>,
    dispatch_tx: mpsc::Sender<Result<Frame, std::io::Error>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                item = rh.next() => match item {
                    None => {
                        tracing::info!(lane_idx, "lane closed by server");
                        if lane_idx == 0 {
                            let _ = dispatch_tx.send(Err(std::io::Error::new(
                                std::io::ErrorKind::ConnectionReset,
                                "lane 0 closed by server",
                            ))).await;
                        } else {
                            metrics::counter!(
                                "mux_lane_failures_total",
                                "side" => "client",
                                "role" => "reader"
                            )
                            .increment(1);
                        }
                        break;
                    }
                    Some(Err(e)) => {
                        if lane_idx == 0 {
                            let _ = dispatch_tx.send(Err(e)).await;
                        } else {
                            tracing::warn!(
                                lane_idx,
                                "non-zero lane read error (degrading, not killing session): {e}"
                            );
                            metrics::counter!(
                                "mux_lane_failures_total",
                                "side" => "client",
                                "role" => "reader"
                            )
                            .increment(1);
                        }
                        break;
                    }
                    Some(Ok(f)) => {
                        // Bounded send: cancel-aware so a stuck control
                        // loop unparks us during teardown instead of
                        // pinning the lane forever.
                        let send = tokio::select! {
                            biased;
                            _ = cancel.cancelled() => break,
                            r = dispatch_tx.send(Ok(f)) => r,
                        };
                        if send.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        if lane_idx > 0 {
            mux_tx.clear_lane(lane_idx as usize).await;
            metrics::gauge!("mux_lanes_active", "side" => "client").decrement(1.0);
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn handle_new_conn(
    conn_id: u64,
    proto: ConnProtocol,
    target: TargetAddress,
    out_tx: MuxSender,
    tcp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>>,
    udp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>>,
    config: &ClientConfig,
    cancel: CancellationToken,
    max_frame_size: Arc<AtomicU64>,
    credit_map: Arc<CreditMap>,
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
            let max_frame_up = Arc::clone(&max_frame_size);
            let credit_map_up = Arc::clone(&credit_map);
            let up = tokio::spawn(async move {
                // Read at the negotiated `max_frame_size` so each TCP read
                // typically becomes exactly one shard. The sharder still
                // wraps the result for safety in case a future code path
                // produces a larger payload.
                let frame_cap =
                    (max_frame_up.load(Ordering::Relaxed) as usize).max(1024);
                let mut buf = vec![0u8; frame_cap];
                loop {
                    let n = tokio::select! {
                        biased;
                        _ = cancel_up.cancelled() => break,
                        r = rh.read(&mut buf) => match r {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        },
                    };
                    let payload = Bytes::copy_from_slice(&buf[..n]);
                    let mut sender_failed = false;
                    for shard in FrameShard::new(
                        MessageType::DataTcp,
                        conn_id,
                        payload,
                        frame_cap,
                    ) {
                        let shard_len = shard.payload.len();
                        metrics::counter!(
                            "mux_shards_total",
                            "side" => "client",
                            "dir" => "tx"
                        )
                        .increment(1);
                        // Block until the server has granted us enough credit
                        // for this shard. Returns Err only if the stream
                        // (or whole session) is being torn down.
                        let credit = credit_map_up.get_or_create(conn_id);
                        let t0 = std::time::Instant::now();
                        let acquired = tokio::select! {
                            biased;
                            _ = cancel_up.cancelled() => {
                                sender_failed = true;
                                break;
                            }
                            r = credit.acquire_send(shard_len) => r,
                        };
                        if acquired.is_err() {
                            sender_failed = true;
                            break;
                        }
                        let waited = t0.elapsed().as_secs_f64();
                        if waited > 0.001 {
                            metrics::histogram!(
                                "mux_credit_wait_seconds",
                                "side" => "client"
                            )
                            .record(waited);
                        }
                        let send_res = tokio::select! {
                            biased;
                            _ = cancel_up.cancelled() => {
                                sender_failed = true;
                                break;
                            }
                            r = out_u.send(shard) => r,
                        };
                        if send_res.is_err() {
                            sender_failed = true;
                            break;
                        }
                    }
                    if sender_failed {
                        break;
                    }
                }
                let _ = out_u.send(ConnClose.to_frame(conn_id)).await;
                if let Some((_, e)) = tcp_sessions_up.remove(&conn_id) {
                    e.close();
                }
                credit_map_up.remove(conn_id);
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
                    let send_res = tokio::select! {
                        biased;
                        _ = cancel_up.cancelled() => break,
                        r = out_u.send(fr) => r,
                    };
                    if send_res.is_err() {
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
