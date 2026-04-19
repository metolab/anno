//! Client control connection (single multiplexed TCP connection).
//!
//! Key invariants maintained by this module:
//! - Each live control connection holds a unique `session_token`.
//! - On disconnect, only `clear_online_if_owner` is called, so a dying old
//!   connection cannot evict a freshly registered new connection.
//! - The server sends a Ping every 20 s and drops the connection if no frame
//!   arrives within 60 s.
//! - A `CancellationToken` is installed in `OnlineSession`; any code path
//!   that wants to tear the connection down (admin disconnect, registry
//!   delete, etc.) simply cancels it — explicit, synchronous, no reliance
//!   on implicit Sender-drop propagation.

use crate::directory::SessionMuxParams;
use crate::state::{AppState, ClientRecord, OnlineSession, StoredMapping};
use anno_common::mux::{
    next_scheduled_frame, CreditMap, MuxParams, MuxSender, ReassemblyOutcome, Reassembler,
    Scheduler,
};
use anno_common::{
    ConfigPush, ConnClose, ErrorCode, Fault, Frame, FrameCodec, GoAway, LaneHello, Message,
    MessageType, Ping, Pong, Register, RegisterAck, WindowUpdate,
};
use futures::{SinkExt, StreamExt};
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

/// How long the lane writer keeps draining after `cancel()` so that
/// already-enqueued diagnostic frames (Fault, GoAway, final
/// ConnClose) flush onto the wire before the FIN.
const WRITER_DRAIN_GRACE: Duration = Duration::from_millis(500);
/// Hard cap on how long the control task waits for the writer to
/// finish after cancelling. Slightly larger than `WRITER_DRAIN_GRACE`
/// to absorb the final `flush`/`close` syscalls.
const WRITER_JOIN_GRACE: Duration = Duration::from_secs(1);

/// Best-effort drain: after cancellation, keep flushing
/// already-enqueued frames for up to [`WRITER_DRAIN_GRACE`] so the
/// peer actually sees a Fault/GoAway/ConnClose before the FIN. Stops
/// early on send error or once the channel is empty.
async fn drain_writer_on_cancel(
    sched: &mut Scheduler,
    rx: &mut mpsc::Receiver<Frame>,
    write_half: &mut FramedWrite<tokio::net::tcp::OwnedWriteHalf, FrameCodec>,
) {
    let deadline = tokio::time::sleep(WRITER_DRAIN_GRACE);
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            biased;
            _ = &mut deadline => break,
            // `next_scheduled_frame` returns `None` once `rx` is
            // closed *and* the scheduler is empty — at which point
            // we have nothing left to send and can stop draining.
            f = next_scheduled_frame(sched, rx) => match f {
                Some(frame) => {
                    if write_half.send(frame).await.is_err() {
                        break;
                    }
                }
                None => break,
            }
        }
    }
}

pub async fn handle_control_connection(state: AppState, stream: TcpStream, peer: SocketAddr) {
    metrics::counter!("control_connections_total").increment(1);
    metrics::gauge!("control_connections_active").increment(1.0);
    handle_control_connection_inner(state, stream, peer).await;
    metrics::gauge!("control_connections_active").decrement(1.0);
}

async fn handle_control_connection_inner(state: AppState, stream: TcpStream, peer: SocketAddr) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(peer = %peer, "set_nodelay failed: {e}");
    }
    {
        let ka = TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10))
            .with_retries(3);
        if let Err(e) = SockRef::from(&stream).set_tcp_keepalive(&ka) {
            tracing::warn!(peer = %peer, "set_tcp_keepalive failed: {e}");
        }
    }

    let (rh, wh) = stream.into_split();
    let mut read_half = FramedRead::new(rh, FrameCodec);
    let mut write_half = FramedWrite::new(wh, FrameCodec);

    // Bound the time allowed between accept and the first Register frame so
    // a slow/silent client cannot pin a control slot indefinitely.
    let register_timeout = state.config().register_timeout;
    let first = match tokio::time::timeout(register_timeout, read_half.next()).await {
        Ok(Some(Ok(f))) => f,
        Ok(_) => return,
        Err(_) => {
            tracing::warn!(peer = %peer, ?register_timeout, "Register read timed out");
            let fault = Fault::new(ErrorCode::Timeout, "register timeout").to_frame(0);
            let _ = write_half.send(fault).await;
            return;
        }
    };

    // Branch on first frame type: Register opens a brand-new mux
    // session (lane 0). LaneHello attaches an additional lane to an
    // existing session identified by `session_token`.
    if first.msg_type == MessageType::LaneHello {
        handle_lane_hello(state, peer, read_half, write_half, first).await;
        return;
    }
    if first.msg_type != MessageType::Register {
        tracing::warn!("first frame not Register from {}", peer);
        let fault = Fault::new(ErrorCode::ProtocolError, "expected Register as first frame")
            .to_frame(0);
        let _ = write_half.send(fault).await;
        return;
    }

    let register = match Register::from_frame(&first) {
        Ok(x) => x,
        Err(e) => {
            tracing::warn!("bad register from {}: {}", peer, e);
            return;
        }
    };
    let http_proxy_port = register.http_proxy_port;
    let client_key = register.key;

    // Negotiate mux parameters: take the conservative side of every
    // value the client requested vs. the server's defaults.
    let mux_defaults = state.config().mux;
    let negotiated = MuxParams::negotiate(
        register.requested_lanes,
        register.max_frame_size,
        register.initial_window,
        mux_defaults.max_lanes,
        mux_defaults.max_frame_size,
        mux_defaults.initial_window,
    );
    let session_mux = SessionMuxParams {
        lanes: negotiated.lanes,
        max_frame_size: negotiated.max_frame_size,
        initial_window: negotiated.initial_window,
    };
    let reassembler = Arc::new(StdMutex::new(Reassembler::with_budget(
        mux_defaults.reassembly_inflight_cap,
        mux_defaults.reassembly_deadline,
        state.reassembly_budget().clone(),
    )));
    let credit_map = Arc::new(CreditMap::new(session_mux.initial_window));

    let Some(entry) = state.registry().lookup_by_key(&client_key) else {
        tracing::warn!(peer = %peer, "client authentication failed: unknown key");
        metrics::counter!("control_auth_failed_total", "reason" => "unknown_key").increment(1);
        let fault =
            Fault::new(ErrorCode::AuthFailed, "invalid client key").to_frame(0);
        let _ = write_half.send(fault).await;
        return;
    };
    let name = entry.name;

    let my_token = state.alloc_session_token();
    let cancel = CancellationToken::new();

    let channel_capacity = state.control_channel_capacity();
    let (tx, mut rx) = mpsc::channel::<Frame>(channel_capacity);

    // Wrap the lane-0 sender in a `MuxSender` pre-sized to the
    // negotiated lane count so additional lanes can be attached later
    // when the client sends `LaneHello`. Slots `1..lanes` start empty
    // and routing falls back to lane 0 until they're filled — this
    // closes the brief race where a `LaneHello` for a higher slot
    // arrives before lower ones, which previously could land DataTcp
    // frames on a closed sender.
    let mux_tx = MuxSender::with_capacity(tx.clone(), session_mux.lanes as usize);
    let new_online = OnlineSession {
        addr: peer,
        connected_at: SystemTime::now(),
        tx: mux_tx.clone(),
        session_token: my_token,
        cancel: cancel.clone(),
        mux: session_mux,
        reassembler: Arc::clone(&reassembler),
        credit: Arc::clone(&credit_map),
    };

    // Serialise the registration phase (and *only* the registration phase)
    // against a concurrent `registry_delete(name)`. Once the record is
    // installed and marked online we drop the guard so a subsequent
    // `registry_delete` is free to proceed via the normal cascade path.
    let client_id = {
        let _register_guard = state.lock_register_name(&name).await;

        // Re-check the entry is still present after we obtained the lock.
        // If registry_delete ran first it already removed both the entry
        // and any preloaded ClientRecord; we must not recreate them.
        if state.registry().lookup_by_key(&client_key).is_none() {
            tracing::warn!(
                peer = %peer,
                %name,
                "client entry deleted while we were waiting to register"
            );
            metrics::counter!("control_auth_failed_total", "reason" => "deleted").increment(1);
            let fault =
                Fault::new(ErrorCode::AuthFailed, "invalid client key").to_frame(0);
            let _ = write_half.send(fault).await;
            return;
        }

        let client_id = if let Some(id) = state.name_to_id().get(&name) {
            *id
        } else {
            let id = state.alloc_client_id();
            state.name_to_id().insert(name.clone(), id);
            id
        };

        // The preloaded ClientRecord (from registry on startup) may already
        // have persisted mappings — preserve them. `or_insert` only runs
        // when no record exists at all.
        state.clients().entry(client_id).or_insert(ClientRecord {
            name: name.clone(),
            http_proxy_port,
            mappings: vec![],
            online: None,
        });
        if let Some(mut rec) = state.clients().get_mut(&client_id) {
            rec.name = name.clone();
            rec.http_proxy_port = http_proxy_port;
        }
        // `replace_online` itself cancels the old session, closes
        // every per-stream credit semaphore (waking parked senders)
        // and drops in-flight reassembly buffers — see
        // `directory::teardown_online`. Just discard the returned
        // handle.
        let _ = state.replace_online(client_id, new_online);

        client_id
    };

    let ack = RegisterAck {
        client_id,
        session_token: my_token,
        granted_lanes: session_mux.lanes,
        max_frame_size: session_mux.max_frame_size,
        initial_window: session_mux.initial_window,
    }
    .to_frame(0);
    if write_half.send(ack).await.is_err() {
        state.clear_online_if_owner(client_id, my_token);
        return;
    }

    let mappings: Vec<StoredMapping> = state
        .clients()
        .get(&client_id)
        .map(|c| c.mappings.clone())
        .unwrap_or_default();
    let pm: Vec<anno_common::PortMapping> = mappings
        .iter()
        .map(crate::state::stored_to_port_mapping)
        .collect();
    let cfg = ConfigPush::new(pm).to_frame(0);
    if write_half.send(cfg).await.is_err() {
        state.clear_online_if_owner(client_id, my_token);
        return;
    }

    state.listeners_handle().sync_client(client_id).await;

    tracing::info!(
        peer = %peer,
        client_id,
        name = %name,
        session_token = my_token,
        "client connected"
    );

    // Lane 0 writer task. Lane 0 also serves as the fallback target
    // for non-zero lanes that have died — see `MuxSender::pick`. We
    // never `clear_lane(0)` here because losing lane 0 means the
    // entire session is gone; the reader loop's exit path handles
    // that via `cancel.cancel()`.
    //
    // On cancellation we don't bail immediately — instead we drain
    // already-enqueued frames for up to `WRITER_DRAIN_GRACE` so a
    // freshly emitted `Fault`/`GoAway` actually makes it on the wire
    // before the FIN. Without this drain, an early teardown could
    // race the writer and the peer would observe a bare RST/FIN with
    // no diagnostic frame.
    let cancel_writer = cancel.clone();
    let write_task = tokio::spawn(async move {
        let mut sched = Scheduler::new();
        loop {
            tokio::select! {
                biased;
                _ = cancel_writer.cancelled() => {
                    drain_writer_on_cancel(&mut sched, &mut rx, &mut write_half).await;
                    break;
                }
                frame = next_scheduled_frame(&mut sched, &mut rx) => match frame {
                    Some(frame) => {
                        if write_half.send(frame).await.is_err() {
                            metrics::counter!(
                                "mux_lane_failures_total",
                                "side" => "server",
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
        let _ = write_half.flush().await;
        let _ = write_half.close().await;
    });

    let st_read = state.clone();
    let ping_interval = state.config().control_ping_interval;
    let idle_timeout = state.config().control_idle_timeout;
    let mut ping_ticker = tokio::time::interval(ping_interval);
    ping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ping_ticker.tick().await;

    let mut idle_ticker = tokio::time::interval(Duration::from_secs(5));
    idle_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    idle_ticker.tick().await;

    // Sweep stale per-stream reassembly buffers periodically so a peer
    // that dribbles `MORE`-flagged shards forever cannot pin server
    // memory.
    let mut reassembly_sweep_ticker = tokio::time::interval(Duration::from_secs(2));
    reassembly_sweep_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    reassembly_sweep_ticker.tick().await;

    let mut last_rx = Instant::now();

    loop {
        tokio::select! {
            biased;

            _ = cancel.cancelled() => {
                tracing::info!(peer = %peer, client_id, "cancellation requested, closing control");
                break;
            }

            item = read_half.next() => {
                match item {
                    None => {
                        tracing::info!(peer = %peer, client_id, "client closed connection");
                        break;
                    }
                    Some(Err(e)) => {
                        tracing::warn!(peer = %peer, client_id, "read error: {e}");
                        break;
                    }
                    Some(Ok(frame)) => {
                        last_rx = Instant::now();
                        if dispatch_incoming(&st_read, client_id, &reassembler, &credit_map, frame).await.is_err() {
                            break;
                        }
                    }
                }
            }

            _ = ping_ticker.tick() => {
                if tx.send(Ping.to_frame(0)).await.is_err() {
                    break;
                }
            }

            _ = idle_ticker.tick() => {
                if last_rx.elapsed() >= idle_timeout {
                    tracing::warn!(
                        peer = %peer,
                        client_id,
                        idle_secs = last_rx.elapsed().as_secs(),
                        "control connection idle timeout, dropping"
                    );
                    metrics::counter!("control_idle_timeouts_total").increment(1);
                    break;
                }
            }

            _ = reassembly_sweep_ticker.tick() => {
                let expired = {
                    let mut r = reassembler.lock().unwrap_or_else(|e| e.into_inner());
                    r.sweep_expired(Instant::now())
                };
                for conn_id in expired {
                    tracing::warn!(client_id, conn_id, "reassembly deadline exceeded; closing stream");
                    state.session_manager().remove(conn_id);
                    credit_map.remove(conn_id);
                    let _ = tx.send(ConnClose.to_frame(conn_id)).await;
                }
            }
        }
    }

    // Cancel first, then wait for the writer to finish draining
    // already-enqueued frames (Fault/GoAway, in particular). The
    // writer's cancel-aware loop drains for up to
    // `WRITER_DRAIN_GRACE`; we additionally cap the join here so a
    // pathological writer that's stuck inside `send` doesn't pin the
    // control task.
    cancel.cancel();
    if tokio::time::timeout(WRITER_JOIN_GRACE, write_task)
        .await
        .is_err()
    {
        tracing::warn!(client_id, "writer task did not exit within grace");
        metrics::counter!("control_writer_drain_timeout_total", "scope" => "control")
            .increment(1);
    }

    let was_owner = state.clear_online_if_owner(client_id, my_token);
    if was_owner {
        let removed = state.session_manager().remove_client_sessions(client_id);
        if removed > 0 {
            tracing::info!(client_id, removed, "cleaned up sessions on disconnect");
        }
        state.listeners_handle().stop_client(client_id).await;
    }

    tracing::info!(
        peer = %peer,
        client_id,
        session_token = my_token,
        was_owner,
        "control connection closed"
    );
}

async fn dispatch_incoming(
    state: &AppState,
    client_id: u64,
    reassembler: &Arc<StdMutex<Reassembler>>,
    credit_map: &Arc<CreditMap>,
    frame: Frame,
) -> Result<(), ()> {
    let session_manager = state.session_manager();

    match frame.msg_type {
        MessageType::Ping => {
            if let Some(tx) = state.client_tx(client_id) {
                let _ = tx.send(Pong.to_frame(0)).await;
            }
        }
        MessageType::Pong | MessageType::ConfigAck => {}
        MessageType::ConnReady => {
            if session_manager.notify_conn_ready(frame.conn_id) {
                tracing::debug!(conn_id = frame.conn_id, "session ready (ConnReady)");
            } else {
                tracing::warn!(conn_id = frame.conn_id, "ConnReady for unknown conn_id");
            }
        }
        MessageType::DataTcp => {
            let conn_id = frame.conn_id;
            // Reassemble shards before handing the payload to the
            // session. Single shard frames go through the same code path
            // (Reassembler returns Complete immediately when MORE is clear).
            let outcome = {
                let mut r = reassembler.lock().unwrap_or_else(|e| e.into_inner());
                r.feed(frame)
            };
            let payload = match outcome {
                ReassemblyOutcome::Pending => return Ok(()),
                ReassemblyOutcome::Complete(b) => b,
                ReassemblyOutcome::Overflow => {
                    metrics::counter!("mux_reassembly_overflow_total", "side" => "server")
                        .increment(1);
                    tracing::warn!(
                        client_id,
                        conn_id,
                        "TCP reassembly overflow from client; closing stream"
                    );
                    session_manager.remove(conn_id);
                    if let Some(tx) = state.client_tx(client_id) {
                        let _ = tx.send(ConnClose.to_frame(conn_id)).await;
                    }
                    return Ok(());
                }
            };
            if let Some(session) = session_manager.get(conn_id) {
                session.touch();
                // Snapshot the lane-0 sender once — `client_tx` does
                // a DashMap lookup + clone, so caching here avoids
                // redoing it for the credit-replenish and timeout
                // paths below.
                let client_tx = state.client_tx(client_id);
                let payload_len = payload.len();
                match session.send_tcp(payload).await {
                    crate::session::SendOutcome::Ok => {
                        // Now that the bytes have been delivered to the
                        // upstream socket buffer, replenish the peer's
                        // send credit if we've crossed the per-stream
                        // threshold.
                        let credit = credit_map.get_or_create(conn_id);
                        if let Some(inc) = credit.record_received(payload_len) {
                            if let Some(tx) = &client_tx {
                                let _ = tx
                                    .send(WindowUpdate::new(inc).to_frame(conn_id))
                                    .await;
                                metrics::counter!(
                                    "mux_window_updates_total",
                                    "side" => "server",
                                    "dir" => "tx"
                                )
                                .increment(1);
                            }
                        }
                    }
                    crate::session::SendOutcome::Closed => {
                        session_manager.remove(conn_id);
                        credit_map.remove(conn_id);
                    }
                    crate::session::SendOutcome::Timeout => {
                        tracing::warn!(conn_id, "TCP tunnel send timeout — closing session");
                        session_manager.remove(conn_id);
                        credit_map.remove(conn_id);
                        if let Some(tx) = client_tx {
                            let _ = tx.send(ConnClose.to_frame(conn_id)).await;
                        }
                    }
                }
            } else {
                tracing::debug!(
                    conn_id,
                    msg_type = ?MessageType::DataTcp,
                    "data for unknown session"
                );
            }
        }
        MessageType::DataUdp => {
            if let Some(session) = session_manager.get(frame.conn_id) {
                session.touch();
                if !session.try_send(frame.payload) {
                    tracing::debug!(
                        conn_id = frame.conn_id,
                        "UDP tunnel queue full or closed, data dropped"
                    );
                }
            } else {
                tracing::debug!(
                    conn_id = frame.conn_id,
                    msg_type = ?frame.msg_type,
                    "data for unknown session"
                );
            }
        }
        MessageType::ConnClose => {
            if session_manager.remove(frame.conn_id).is_some() {
                tracing::debug!(conn_id = frame.conn_id, "session closed by client");
            }
            let mut r = reassembler.lock().unwrap_or_else(|e| e.into_inner());
            r.discard(frame.conn_id);
            credit_map.remove(frame.conn_id);
        }
                MessageType::WindowUpdate => match WindowUpdate::from_frame(&frame) {
            Ok(wu) => {
                metrics::counter!("mux_window_updates_total", "side" => "server", "dir" => "rx")
                    .increment(1);
                if let Some(c) = credit_map.get(frame.conn_id) {
                    c.add_send_credit(wu.increment);
                }
            }
            Err(e) => {
                tracing::warn!(client_id, "invalid WindowUpdate payload: {}", e);
            }
        },
        MessageType::GoAway => match GoAway::from_frame(&frame) {
            Ok(ga) => {
                tracing::info!(
                    client_id,
                    last_accepted_conn_id = ga.last_accepted_conn_id,
                    code = u16::from(ga.code),
                    reason = %ga.reason,
                    "received GoAway from client; stopping listeners and draining"
                );
                metrics::counter!("mux_goaway_total", "dir" => "rx").increment(1);
                // 1. Immediately stop accepting new public
                //    connections for this client so we don't queue
                //    fresh `NewConn` frames against a peer that's
                //    already shutting down.
                let st_stop = state.clone();
                tokio::spawn(async move {
                    st_stop.listeners_handle().stop_client(client_id).await;
                });
                // 2. Watchdog: cancel the session once existing
                //    sessions drain or the grace expires. We snapshot
                //    the cancel token now so the watchdog still works
                //    if the directory entry is later cleared.
                if let Some((_tx, cancel)) = state.client_tx_and_cancel(client_id) {
                    let grace = state.config().mux.goaway_grace;
                    let st_watch = state.clone();
                    tokio::spawn(async move {
                        let deadline = Instant::now() + grace;
                        let mut tick = tokio::time::interval(Duration::from_millis(100));
                        tick.set_missed_tick_behavior(
                            tokio::time::MissedTickBehavior::Skip,
                        );
                        loop {
                            if st_watch.session_manager().count_by_client(client_id) == 0 {
                                tracing::info!(
                                    client_id,
                                    "all sessions drained after client GoAway"
                                );
                                break;
                            }
                            if Instant::now() >= deadline {
                                tracing::warn!(
                                    client_id,
                                    grace_secs = grace.as_secs(),
                                    "client GoAway grace expired; force-cancelling"
                                );
                                break;
                            }
                            tokio::select! {
                                _ = cancel.cancelled() => return,
                                _ = tick.tick() => {}
                            }
                        }
                        cancel.cancel();
                    });
                }
            }
            Err(e) => {
                tracing::warn!(client_id, "invalid GoAway payload from client: {}", e);
            }
        },
        MessageType::Fault => match Fault::from_frame(&frame) {
            Ok(f) => {
                tracing::warn!(
                    client_id,
                    conn_id = frame.conn_id,
                    code = u16::from(f.code),
                    message = %f.message,
                    "received fault from client"
                );
                // Wake any handshake waiter FIRST so the public side can
                // unwind immediately; then remove.
                session_manager.notify_conn_ready_err(
                    frame.conn_id,
                    f.code,
                    f.message.clone(),
                );
                session_manager.remove(frame.conn_id);
                credit_map.remove(frame.conn_id);
            }
            Err(e) => {
                tracing::warn!(client_id, "invalid fault payload: {}", e);
            }
        },
        _ => {
            tracing::debug!(
                client_id,
                msg_type = ?frame.msg_type,
                "unhandled message type"
            );
        }
    }
    Ok(())
}

/// Attach an additional physical TCP lane to an already-registered
/// mux session. The first frame on the new TCP connection is a
/// `LaneHello` carrying the parent `session_token`. We look the
/// session up, install a fresh per-lane writer task, and run a
/// reader loop that simply funnels inbound frames into the same
/// `dispatch_incoming` pipeline as the primary lane.
async fn handle_lane_hello(
    state: AppState,
    peer: SocketAddr,
    mut read_half: FramedRead<tokio::net::tcp::OwnedReadHalf, FrameCodec>,
    mut write_half: FramedWrite<tokio::net::tcp::OwnedWriteHalf, FrameCodec>,
    first: Frame,
) {
    let hello = match LaneHello::from_frame(&first) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(peer = %peer, "invalid LaneHello: {}", e);
            return;
        }
    };
    let Some((client_id, mux_tx, cancel, session_mux, reassembler, credit_map)) =
        state.lookup_by_session_token(hello.session_token)
    else {
        tracing::warn!(
            peer = %peer,
            session_token = hello.session_token,
            "LaneHello refers to unknown session_token; rejecting"
        );
        let fault =
            Fault::new(ErrorCode::ProtocolError, "unknown session_token").to_frame(0);
        let _ = write_half.send(fault).await;
        return;
    };
    if hello.lane_idx as u16 >= session_mux.lanes as u16 {
        tracing::warn!(
            peer = %peer,
            client_id,
            lane_idx = hello.lane_idx,
            granted = session_mux.lanes,
            "LaneHello lane_idx exceeds granted lanes"
        );
        let fault = Fault::new(ErrorCode::ProtocolError, "lane_idx out of range")
            .to_frame(0);
        let _ = write_half.send(fault).await;
        return;
    }

    let channel_capacity = state.control_channel_capacity();
    let (lane_tx, mut lane_rx) = mpsc::channel::<Frame>(channel_capacity);
    let lane_idx = hello.lane_idx as usize;
    mux_tx.set_lane(lane_idx, lane_tx).await;

    metrics::counter!("mux_lanes_attached_total").increment(1);
    metrics::gauge!("mux_lanes_active").increment(1.0);

    tracing::info!(
        peer = %peer,
        client_id,
        lane_idx = hello.lane_idx,
        lane_total = hello.lane_total,
        "lane attached"
    );

    // Non-zero lane writer: on TCP write failure we just degrade
    // (clear our slot in `mux_tx` so subsequent frames fall back to
    // lane 0). The whole session keeps running. Drains pending
    // frames for `WRITER_DRAIN_GRACE` on cancel so a freshly emitted
    // Fault/GoAway makes it on the wire before the FIN.
    let cancel_writer = cancel.clone();
    let mux_tx_w = mux_tx.clone();
    let write_task = tokio::spawn(async move {
        let mut sched = Scheduler::new();
        loop {
            tokio::select! {
                biased;
                _ = cancel_writer.cancelled() => {
                    drain_writer_on_cancel(&mut sched, &mut lane_rx, &mut write_half).await;
                    break;
                }
                frame = next_scheduled_frame(&mut sched, &mut lane_rx) => match frame {
                    Some(frame) => {
                        if write_half.send(frame).await.is_err() {
                            metrics::counter!(
                                "mux_lane_failures_total",
                                "side" => "server",
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
        let _ = write_half.flush().await;
        let _ = write_half.close().await;
        // lane_idx > 0 by construction (handle_lane_hello validates).
        mux_tx_w.clear_lane(lane_idx).await;
    });

    let st_read = state.clone();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            item = read_half.next() => {
                match item {
                    None => break,
                    Some(Err(e)) => {
                        tracing::warn!(
                            peer = %peer,
                            client_id,
                            lane = hello.lane_idx,
                            "non-zero lane read error (degrading): {e}"
                        );
                        metrics::counter!(
                            "mux_lane_failures_total",
                            "side" => "server",
                            "role" => "reader"
                        )
                        .increment(1);
                        break;
                    }
                    Some(Ok(frame)) => {
                        if dispatch_incoming(
                            &st_read,
                            client_id,
                            &reassembler,
                            &credit_map,
                            frame,
                        ).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }

    // Bound how long we wait for the lane writer to finish flushing
    // already-enqueued frames after the reader exits.
    if tokio::time::timeout(WRITER_JOIN_GRACE, write_task)
        .await
        .is_err()
    {
        tracing::warn!(client_id, lane = hello.lane_idx, "lane writer did not exit within grace");
        metrics::counter!("control_writer_drain_timeout_total", "scope" => "lane")
            .increment(1);
    }
    mux_tx.clear_lane(lane_idx).await;
    metrics::gauge!("mux_lanes_active").decrement(1.0);
    tracing::info!(peer = %peer, client_id, lane = hello.lane_idx, "lane closed");
}

/// Graceful disconnect: stop accepting new public connections for
/// `client_id`, send a `GoAway` to the client, then poll for
/// already-bridged sessions to drain on their own. After
/// `goaway_grace` we hard-cancel even if some sessions are still
/// alive.
///
/// `last_accepted_conn_id` is best-effort: we just take the current
/// max; the client uses it to know which inbound `NewConn` frames
/// were already in flight.
pub async fn goaway_then_disconnect(
    state: &AppState,
    client_id: u64,
    code: ErrorCode,
    reason: impl Into<String>,
) {
    // Snapshot the lane-0 sender + cancel token before we remove
    // anything; subsequent stop_client / replace_online would close
    // the channel.
    let Some((mux_tx, cancel)) = state.client_tx_and_cancel(client_id) else {
        // Already offline — fall back to the synchronous teardown
        // (no-op if there's nothing to clean).
        return;
    };

    // 1. Stop accepting new public connections so no fresh `NewConn`
    //    can be queued onto the mux while we're draining.
    state.listeners_handle().stop_client(client_id).await;

    // 2. Send `GoAway`. Send error means the control connection is
    //    already dead; either way we proceed to teardown.
    let last_id = state.session_manager().max_conn_id_for_client(client_id);
    let reason = reason.into();
    let _ = mux_tx
        .send(GoAway::new(last_id, code, reason.clone()).to_frame(0))
        .await;
    metrics::counter!("mux_goaway_total", "dir" => "tx").increment(1);
    tracing::info!(
        client_id,
        last_accepted_conn_id = last_id,
        ?code,
        %reason,
        "GoAway sent, draining sessions"
    );

    // 3. Poll session count until it reaches zero or grace expires.
    let grace = state.config().mux.goaway_grace;
    let deadline = Instant::now() + grace;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        if state.session_manager().count_by_client(client_id) == 0 {
            tracing::info!(client_id, "all sessions drained");
            break;
        }
        if Instant::now() >= deadline {
            let remaining = state.session_manager().count_by_client(client_id);
            tracing::warn!(
                client_id,
                remaining,
                grace_secs = grace.as_secs(),
                "goaway grace expired; force-closing"
            );
            break;
        }
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!(client_id, "session cancelled during goaway drain");
                return;
            }
            _ = tick.tick() => {}
        }
    }

    // 4. Hard cancel: tears down the control loop, lane writers, and
    //    any per-session task that still holds the token.
    cancel.cancel();
    state.session_manager().remove_client_sessions(client_id);
}
