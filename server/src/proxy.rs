//! Public TCP/UDP listeners and bridging to connected clients.
//!
//! This module contains only the network workers — the reconciliation logic
//! (which mapping gets bound / torn down when) lives in
//! [`crate::listener`]. `spawn_tcp_listener` / `spawn_udp_listener` are the
//! worker-spawn primitives invoked by the listener actor; they return a
//! [`BindResult`] that the actor uses to decide whether to record the
//! listener as `Active` or to drop the reservation.
//!
//! Invariants (preserved from the original design):
//! - TCP/UDP sockets bound with SO_REUSEADDR (via socket2) to survive TIME_WAIT.
//! - UDP new-peer handshake is non-blocking: the recv_from loop is never
//!   stalled waiting for ConnReady. Incoming packets during the handshake
//!   window are buffered in a `Pending` entry (bounded).
//! - per-client session limit enforced before creating a new session.
//! - A ConnReady waiter resolved with `ConnReadyError` (client Fault or
//!   session removed) unwinds the public side immediately instead of
//!   waiting for `conn_ready_timeout`.

use crate::session::{ConnReadyError, SessionManager, SessionProtocol};
use crate::state::{next_conn_id, AppState, StoredMapping};
use anno_common::mux::{CreditMap, FrameShard};
use anno_common::{
    ConnClose, ConnProtocol, DataUdp, Host, Message, MessageType, NewConn, Protocol, TargetAddress,
    DEFAULT_MAX_FRAME_SIZE,
};
use bytes::Bytes;
use dashmap::DashMap;
use socket2::{Domain, Protocol as S2Proto, Socket, Type};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

/// Maximum number of UDP packets buffered for a peer during handshake.
const UDP_PENDING_PACKET_LIMIT: usize = 32;
/// Maximum total bytes buffered per pending UDP peer.
const UDP_PENDING_BYTE_LIMIT: usize = 256 * 1024;

// ---------------------------------------------------------------------------
// Public entry points used by the listener actor
// ---------------------------------------------------------------------------

/// Result of attempting to spawn a listener worker task.
pub enum BindResult {
    /// Bind succeeded and the long-running accept/recv_from task is running.
    Ok(tokio::task::JoinHandle<()>),
    /// Bind failed before the worker task could start.
    Err(std::io::Error),
}

/// Spawn a TCP listener worker for `mapping.server_port` targeting
/// `mapping.target`. Returns once the socket is bound (or has failed).
pub async fn spawn_tcp_listener(
    state: AppState,
    client_id: u64,
    mapping: StoredMapping,
) -> BindResult {
    let (bind_tx, bind_rx) = oneshot::channel::<std::io::Result<()>>();
    let handle = tokio::spawn(run_tcp(state, client_id, mapping, bind_tx));
    match bind_rx.await {
        Ok(Ok(())) => BindResult::Ok(handle),
        Ok(Err(e)) => {
            // Worker reported its own bind failure and will exit on its own.
            BindResult::Err(e)
        }
        Err(_) => {
            handle.abort();
            BindResult::Err(std::io::Error::other(
                "tcp listener task aborted before reporting bind status",
            ))
        }
    }
}

/// Spawn a UDP listener worker for `mapping.server_port`.
pub async fn spawn_udp_listener(
    state: AppState,
    client_id: u64,
    mapping: StoredMapping,
) -> BindResult {
    let (bind_tx, bind_rx) = oneshot::channel::<std::io::Result<()>>();
    let handle = tokio::spawn(run_udp(state, client_id, mapping, bind_tx));
    match bind_rx.await {
        Ok(Ok(())) => BindResult::Ok(handle),
        Ok(Err(e)) => BindResult::Err(e),
        Err(_) => {
            handle.abort();
            BindResult::Err(std::io::Error::other(
                "udp listener task aborted before reporting bind status",
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Socket helpers with SO_REUSEADDR
// ---------------------------------------------------------------------------

fn bind_tcp_reuse(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = Domain::for_address(addr);
    let sock = Socket::new(domain, Type::STREAM, Some(S2Proto::TCP))?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    TcpListener::from_std(sock.into())
}

fn bind_udp_reuse(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let domain = Domain::for_address(addr);
    let sock = Socket::new(domain, Type::DGRAM, None)?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    UdpSocket::from_std(sock.into())
}

// ---------------------------------------------------------------------------
// TCP public listener
// ---------------------------------------------------------------------------

async fn run_tcp(
    state: AppState,
    client_id: u64,
    m: StoredMapping,
    bind_ready: oneshot::Sender<std::io::Result<()>>,
) {
    let addr: SocketAddr = SocketAddr::new(state.config().public_bind, m.server_port);
    let listener = match bind_tcp_reuse(addr) {
        Ok(l) => {
            let _ = bind_ready.send(Ok(()));
            l
        }
        Err(e) => {
            tracing::error!("tcp bind {}: {}", addr, e);
            let _ = bind_ready.send(Err(e));
            return;
        }
    };
    tracing::info!("listening tcp {}", addr);
    let mut accept_backoff_ms: u64 = 1;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => {
                accept_backoff_ms = 1;
                x
            }
            Err(e) => {
                tracing::error!("tcp accept: {}", e);
                tokio::time::sleep(std::time::Duration::from_millis(accept_backoff_ms)).await;
                accept_backoff_ms = (accept_backoff_ms * 2).min(1000);
                continue;
            }
        };
        let st = state.clone();
        let mm = m.clone();
        tokio::spawn(async move {
            handle_tcp_incoming(st, client_id, mm, stream, peer).await;
        });
    }
}

async fn handle_tcp_incoming(
    state: AppState,
    client_id: u64,
    m: StoredMapping,
    mut ext: TcpStream,
    peer: SocketAddr,
) {
    let conn_id = next_conn_id();
    let session_manager = state.session_manager();
    let timeout = session_manager.config().conn_ready_timeout;

    let limit = state.config().max_sessions_per_client;
    if limit > 0 && session_manager.count_by_client(client_id) >= limit {
        tracing::warn!(
            client_id,
            limit,
            peer = %peer,
            "per-client session limit reached, rejecting TCP"
        );
        let _ = ext.shutdown().await;
        return;
    }

    let (session, mut tun_rx) =
        session_manager.create_session(conn_id, SessionProtocol::Tcp, m.server_port, client_id);

    let ready_rx = session_manager.register_conn_ready_waiter(conn_id);

    let (client_tx, cancel) = match state.client_tx_and_cancel(client_id) {
        Some(v) => v,
        None => {
            tracing::warn!("client {} offline, drop tcp {}", client_id, peer);
            cleanup_session(session_manager, conn_id);
            return;
        }
    };

    // HttpProxy mappings resolve the target dynamically to the client's
    // currently-registered local HTTP proxy port, so a client that
    // restarts with a new random port keeps serving existing mappings
    // without the admin editing anything.
    let target = if m.protocol == Protocol::HttpProxy {
        match state
            .clients()
            .get(&client_id)
            .and_then(|c| c.http_proxy_port)
        {
            Some(port) if port != 0 => TargetAddress {
                host: Host::V4(Ipv4Addr::LOCALHOST),
                port,
            },
            _ => {
                tracing::warn!(
                    client_id,
                    port = m.server_port,
                    peer = %peer,
                    "http_proxy mapping has no active client proxy port; dropping connection"
                );
                let _ = ext.shutdown().await;
                cleanup_session(session_manager, conn_id);
                return;
            }
        }
    } else {
        m.target.clone()
    };

    let new_conn = NewConn::new(m.server_port, ConnProtocol::Tcp, target).to_frame(conn_id);
    if client_tx.send(new_conn).await.is_err() {
        cleanup_session(session_manager, conn_id);
        return;
    }

    // `ready_rx` now returns `Result<Result<(), ConnReadyError>, Elapsed>`:
    //   Ok(Ok(())) — ConnReady delivered, tunnel is up.
    //   Ok(Err(ConnReadyError::Aborted)) — session removed before we heard back.
    //   Ok(Err(ClientFault{..})) — client reported a specific Fault.
    //   Err(Elapsed) — plain timeout.
    let ready_outcome = tokio::select! {
        biased;
        _ = cancel.cancelled() => {
            tracing::debug!(conn_id, peer = %peer, "tcp session canceled before ready");
            let _ = ext.shutdown().await;
            cleanup_session(session_manager, conn_id);
            return;
        }
        r = tokio::time::timeout(timeout, ready_rx) => r,
    };
    match ready_outcome {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(ConnReadyError::Aborted))) => {
            tracing::debug!(conn_id, peer = %peer, "tcp session aborted before ready");
            let _ = ext.shutdown().await;
            cleanup_session(session_manager, conn_id);
            return;
        }
        Ok(Ok(Err(ConnReadyError::ClientFault { code, message }))) => {
            tracing::warn!(
                conn_id, peer = %peer, code, %message,
                "tcp session ready failed: client fault"
            );
            let _ = ext.shutdown().await;
            cleanup_session(session_manager, conn_id);
            return;
        }
        Ok(Err(_recv)) => {
            tracing::warn!(conn_id, peer = %peer, "tcp ready_rx dropped");
            let _ = ext.shutdown().await;
            cleanup_session(session_manager, conn_id);
            return;
        }
        Err(_) => {
            tracing::warn!("tcp session {} ready timeout peer={}", conn_id, peer);
            let _ = ext.shutdown().await;
            cleanup_session(session_manager, conn_id);
            return;
        }
    }

    let (mut rh, mut wh) = ext.into_split();

    let to_client = client_tx.clone();
    let sm_up = Arc::clone(session_manager);
    let session_up = Arc::clone(&session);
    let cancel_up = cancel.clone();
    // Use the negotiated `max_frame_size` (per-client) when sharding
    // outbound DataTcp; falling back to the protocol default if the
    // client is somehow no longer in the directory by the time we
    // start the up task.
    let frame_cap = state
        .client_mux_params(client_id)
        .map(|p| p.max_frame_size as usize)
        .unwrap_or(DEFAULT_MAX_FRAME_SIZE as usize);
    // Per-stream send credit. The server is the *sender* here so it
    // must respect the window the client granted us via WindowUpdates.
    let credit_map_up: Option<Arc<CreditMap>> = state.client_credit_map(client_id);
    let up = tokio::spawn(async move {
        // Read at most one frame's worth at a time so each TCP read
        // typically becomes exactly one shard. The sharder still wraps
        // the result for safety in case a future code path produces a
        // larger payload. `frame_cap` is bounded by `MIN_MAX_FRAME_SIZE`
        // (1 KiB) on negotiation so this is always a sane size.
        let buf_size = frame_cap.max(1024);
        let mut buf = vec![0u8; buf_size];
        loop {
            let n = tokio::select! {
                biased;
                _ = cancel_up.cancelled() => break,
                r = rh.read(&mut buf) => match r {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                },
            };
            session_up.stats.record_up(n);
            let chunk = Bytes::copy_from_slice(&buf[..n]);
            let mut sender_failed = false;
            for shard in
                FrameShard::new(MessageType::DataTcp, conn_id, chunk, frame_cap)
            {
                let shard_len = shard.payload.len();
                metrics::counter!("mux_shards_total", "side" => "server", "dir" => "tx")
                    .increment(1);
                if let Some(cm) = credit_map_up.as_ref() {
                    let credit = cm.get_or_create(conn_id);
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
                        metrics::histogram!("mux_credit_wait_seconds", "side" => "server")
                            .record(waited);
                    }
                }
                let send_res = tokio::select! {
                    biased;
                    _ = cancel_up.cancelled() => {
                        sender_failed = true;
                        break;
                    }
                    r = to_client.send(shard) => r,
                };
                if send_res.is_err() {
                    tracing::warn!(
                        conn_id,
                        "to_client send failed (client control channel closed)"
                    );
                    sender_failed = true;
                    break;
                }
            }
            if sender_failed {
                break;
            }
        }
        let _ = to_client.send(ConnClose.to_frame(conn_id)).await;
        sm_up.remove(conn_id);
    });

    let sm_down = Arc::clone(session_manager);
    let session_down = Arc::clone(&session);
    let cancel_down = cancel.clone();
    let down = tokio::spawn(async move {
        loop {
            let chunk = tokio::select! {
                biased;
                _ = cancel_down.cancelled() => break,
                r = tun_rx.recv() => match r {
                    Some(c) => c,
                    None => break,
                },
            };
            session_down.stats.record_down(chunk.len());
            if wh.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = wh.shutdown().await;
        sm_down.remove(conn_id);
    });

    let _ = tokio::join!(up, down);
}

fn cleanup_session(session_manager: &Arc<SessionManager>, conn_id: u64) {
    session_manager.cancel_conn_ready_waiter(conn_id);
    session_manager.remove(conn_id);
}

// ---------------------------------------------------------------------------
// UDP public listener — non-blocking handshake
// ---------------------------------------------------------------------------

enum PeerState {
    Pending {
        conn_id: u64,
        buf: VecDeque<Bytes>,
        buf_bytes: usize,
        /// When the handshake started. The recv loop sweeps any
        /// entry whose age exceeds `2 * conn_ready_timeout` so a
        /// crashed handshake task or a peer that stopped sending
        /// after the first packet cannot pin a `Pending` slot
        /// (and its buffered packets) forever.
        created_at: Instant,
    },
    Active {
        conn_id: u64,
    },
}

async fn run_udp(
    state: AppState,
    client_id: u64,
    m: StoredMapping,
    bind_ready: oneshot::Sender<std::io::Result<()>>,
) {
    let addr: SocketAddr = SocketAddr::new(state.config().public_bind, m.server_port);
    let sock = match bind_udp_reuse(addr) {
        Ok(s) => {
            let _ = bind_ready.send(Ok(()));
            s
        }
        Err(e) => {
            tracing::error!("udp bind {}: {}", addr, e);
            let _ = bind_ready.send(Err(e));
            return;
        }
    };
    let sock = Arc::new(sock);
    tracing::info!("listening udp {}", addr);

    let session_manager = state.session_manager();
    let conn_ready_timeout = session_manager.config().conn_ready_timeout;

    let peer_sessions: Arc<DashMap<SocketAddr, PeerState>> = Arc::new(DashMap::new());
    let mut buf = vec![0u8; 64 * 1024];
    let mut recv_backoff_ms: u64 = 1;
    // Sweep stale `Pending` entries (peers whose handshake never
    // finished) so they don't pin memory forever. The cap is
    // generous — `conn_ready_timeout * 2` — because the per-handshake
    // task already has its own timeout; this is a defense against
    // panics or future code paths that bypass it.
    let pending_max_age = conn_ready_timeout.saturating_mul(2);
    let mut sweep_ticker = tokio::time::interval(std::time::Duration::from_secs(2));
    sweep_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    sweep_ticker.tick().await;

    loop {
        let (n, peer) = tokio::select! {
            biased;
            _ = sweep_ticker.tick() => {
                let now = Instant::now();
                peer_sessions.retain(|peer, st| match st {
                    PeerState::Pending { created_at, conn_id, .. } => {
                        if now.duration_since(*created_at) > pending_max_age {
                            tracing::debug!(
                                %peer,
                                conn_id = *conn_id,
                                age_secs = now.duration_since(*created_at).as_secs(),
                                "evicting stale UDP Pending entry"
                            );
                            // Best-effort: also drop any session row
                            // the handshake task may have left
                            // behind so we don't leak it either.
                            session_manager.remove(*conn_id);
                            metrics::counter!(
                                "udp_pending_evicted_total",
                                "side" => "server"
                            )
                            .increment(1);
                            false
                        } else {
                            true
                        }
                    }
                    PeerState::Active { .. } => true,
                });
                continue;
            }
            r = sock.recv_from(&mut buf) => match r {
                Ok(x) => {
                    recv_backoff_ms = 1;
                    x
                }
                Err(e) => {
                    tracing::error!("udp recv: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(recv_backoff_ms)).await;
                    recv_backoff_ms = (recv_backoff_ms * 2).min(1000);
                    continue;
                }
            },
        };
        let payload = Bytes::copy_from_slice(&buf[..n]);

        if let Some(entry) = peer_sessions.get(&peer) {
            match &*entry {
                PeerState::Active { conn_id } => {
                    let conn_id = *conn_id;
                    drop(entry);
                    // If the session has already been torn down (idle sweep,
                    // client Fault, etc.), the Active entry is stale. Clear
                    // it and fall through to the "new peer" branch so the
                    // next packet re-handshakes. Without this, packets from
                    // that peer would be silently black-holed forever.
                    if session_manager.get(conn_id).is_none() {
                        peer_sessions.remove(&peer);
                        session_manager.remove(conn_id);
                        // Re-insert as a new peer to trigger fresh handshake.
                        if let Err(()) = start_udp_peer_handshake(
                            &state,
                            client_id,
                            &m,
                            &sock,
                            &peer_sessions,
                            peer,
                            payload.clone(),
                            n,
                            conn_ready_timeout,
                        )
                        .await
                        {
                            continue;
                        }
                        continue;
                    }
                    if let Some(session) = session_manager.get(conn_id) {
                        session.touch();
                        session.stats.record_up(n);
                    }
                    let client_tx = match state.client_tx(client_id) {
                        Some(tx) => tx,
                        None => {
                            peer_sessions.remove(&peer);
                            session_manager.remove(conn_id);
                            continue;
                        }
                    };
                    let fr = DataUdp::new(payload).to_frame(conn_id);
                    let _ = client_tx.send(fr).await;
                    continue;
                }
                PeerState::Pending {
                    buf: pbuf,
                    buf_bytes,
                    ..
                } => {
                    let over_limit = pbuf.len() + 1 > UDP_PENDING_PACKET_LIMIT
                        || *buf_bytes + n > UDP_PENDING_BYTE_LIMIT;
                    drop(entry);
                    if !over_limit {
                        if let Some(mut e) = peer_sessions.get_mut(&peer) {
                            if let PeerState::Pending {
                                buf: pbuf,
                                buf_bytes,
                                ..
                            } = &mut *e
                            {
                                pbuf.push_back(payload);
                                *buf_bytes += n;
                            }
                        }
                    }
                    continue;
                }
            }
        }

        let _ = start_udp_peer_handshake(
            &state,
            client_id,
            &m,
            &sock,
            &peer_sessions,
            peer,
            payload,
            n,
            conn_ready_timeout,
        )
        .await;
    }
}

/// Kick off a new-peer UDP handshake: create session, send NewConn, buffer the
/// initial packet, and spawn a task that waits for ConnReady and promotes the
/// peer to Active. Returns `Err(())` if the request was rejected (e.g. per-
/// client limit, client offline) so the caller can skip early.
#[allow(clippy::too_many_arguments)]
async fn start_udp_peer_handshake(
    state: &AppState,
    client_id: u64,
    m: &StoredMapping,
    sock: &Arc<UdpSocket>,
    peer_sessions: &Arc<DashMap<SocketAddr, PeerState>>,
    peer: SocketAddr,
    payload: Bytes,
    n: usize,
    conn_ready_timeout: std::time::Duration,
) -> Result<(), ()> {
    let session_manager = state.session_manager();

    let limit = state.config().max_sessions_per_client;
    if limit > 0 && session_manager.count_by_client(client_id) >= limit {
        tracing::warn!(
            client_id,
            limit,
            peer = %peer,
            "per-client session limit reached, dropping UDP"
        );
        return Err(());
    }

    let conn_id = next_conn_id();
    let (session, mut tun_rx) =
        session_manager.create_session(conn_id, SessionProtocol::Udp, m.server_port, client_id);

    let ready_rx = session_manager.register_conn_ready_waiter(conn_id);

    let (client_tx, cancel): (_, CancellationToken) = match state.client_tx_and_cancel(client_id) {
        Some(v) => v,
        None => {
            cleanup_session(session_manager, conn_id);
            return Err(());
        }
    };

    let new_conn_frame =
        NewConn::new(m.server_port, ConnProtocol::Udp, m.target.clone()).to_frame(conn_id);
    if client_tx.send(new_conn_frame).await.is_err() {
        cleanup_session(session_manager, conn_id);
        return Err(());
    }

    let mut initial_buf = VecDeque::new();
    initial_buf.push_back(payload);
    peer_sessions.insert(
        peer,
        PeerState::Pending {
            conn_id,
            buf: initial_buf,
            buf_bytes: n,
            created_at: Instant::now(),
        },
    );

    let peer_sessions_c = Arc::clone(peer_sessions);
    let sm_c = Arc::clone(session_manager);
    let client_tx_c = client_tx.clone();
    let sock_c = Arc::clone(sock);
    let session_c = Arc::clone(&session);
    let cancel_c = cancel.clone();
    tokio::spawn(async move {
        let ready_outcome = tokio::select! {
            biased;
            _ = cancel_c.cancelled() => {
                peer_sessions_c.remove(&peer);
                sm_c.cancel_conn_ready_waiter(conn_id);
                sm_c.remove(conn_id);
                return;
            }
            r = tokio::time::timeout(conn_ready_timeout, ready_rx) => r,
        };
        match ready_outcome {
            Ok(Ok(Ok(()))) => {
                let buffered = if let Some(mut e) = peer_sessions_c.get_mut(&peer) {
                    if let PeerState::Pending {
                        conn_id: cid, buf, ..
                    } = &mut *e
                    {
                        if *cid == conn_id {
                            let pkts: Vec<Bytes> = buf.drain(..).collect();
                            *e = PeerState::Active { conn_id };
                            pkts
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };
                for pkt in buffered {
                    session_c.stats.record_up(pkt.len());
                    let fr = DataUdp::new(pkt).to_frame(conn_id);
                    if client_tx_c.send(fr).await.is_err() {
                        break;
                    }
                }
                let sm_down = Arc::clone(&sm_c);
                let session_d = Arc::clone(&session_c);
                let peer_sessions_d = Arc::clone(&peer_sessions_c);
                let cancel_d = cancel_c.clone();
                tokio::spawn(async move {
                    loop {
                        let chunk = tokio::select! {
                            biased;
                            _ = cancel_d.cancelled() => break,
                            r = tun_rx.recv() => match r {
                                Some(c) => c,
                                None => break,
                            },
                        };
                        session_d.stats.record_down(chunk.len());
                        session_d.touch();
                        if sock_c.send_to(&chunk, peer).await.is_err() {
                            break;
                        }
                    }
                    sm_down.remove(conn_id);
                    peer_sessions_d.remove(&peer);
                });
            }
            // ConnReady resolved with a negative result (Aborted / ClientFault).
            Ok(Ok(Err(err))) => {
                tracing::warn!(
                    conn_id,
                    peer = %peer,
                    reason = ?err,
                    "UDP session aborted before ready"
                );
                peer_sessions_c.remove(&peer);
                sm_c.cancel_conn_ready_waiter(conn_id);
                sm_c.remove(conn_id);
            }
            // Sender dropped (shouldn't normally happen).
            Ok(Err(_)) => {
                tracing::warn!(conn_id, peer = %peer, "UDP ready_rx dropped");
                peer_sessions_c.remove(&peer);
                sm_c.cancel_conn_ready_waiter(conn_id);
                sm_c.remove(conn_id);
            }
            Err(_) => {
                tracing::warn!(conn_id, peer = %peer, "UDP session ConnReady timeout");
                peer_sessions_c.remove(&peer);
                sm_c.cancel_conn_ready_waiter(conn_id);
                sm_c.remove(conn_id);
            }
        }
    });

    Ok(())
}
