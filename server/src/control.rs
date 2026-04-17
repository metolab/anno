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

use crate::state::{AppState, ClientRecord, OnlineSession, StoredMapping};
use anno_common::{
    ConfigPush, ConnClose, ErrorCode, Fault, Frame, FrameCodec, Message, MessageType, Ping, Pong,
    Register, RegisterAck,
};
use futures::{SinkExt, StreamExt};
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};
use tokio_util::sync::CancellationToken;

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

    let Some(entry) = state.registry().lookup_by_key(&client_key) else {
        tracing::warn!(peer = %peer, "client authentication failed: unknown key");
        let fault =
            Fault::new(ErrorCode::ConnectionRefused, "invalid client key").to_frame(0);
        let _ = write_half.send(fault).await;
        return;
    };
    let name = entry.name;

    let my_token = state.alloc_session_token();
    let cancel = CancellationToken::new();

    let channel_capacity = state.control_channel_capacity();
    let (tx, mut rx) = mpsc::channel::<Frame>(channel_capacity);

    let new_online = OnlineSession {
        addr: peer,
        connected_at: SystemTime::now(),
        tx: tx.clone(),
        session_token: my_token,
        cancel: cancel.clone(),
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
            let fault =
                Fault::new(ErrorCode::ConnectionRefused, "invalid client key").to_frame(0);
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
        // Replacing an older online session implicitly cancels it via
        // `replace_online` → the old OnlineSession is dropped; but we must
        // also explicitly cancel so any outstanding per-session tasks
        // running with the old token tear down immediately.
        if let Some(old) = state.replace_online(client_id, new_online) {
            old.cancel.cancel();
        }

        client_id
    };

    let ack = RegisterAck::new(client_id).to_frame(0);
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

    let cancel_writer = cancel.clone();
    let write_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = cancel_writer.cancelled() => break,
                frame = rx.recv() => match frame {
                    Some(frame) => {
                        if write_half.send(frame).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                },
            }
        }
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
                        if dispatch_incoming(&st_read, client_id, frame).await.is_err() {
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
        }
    }

    // Cancel first, then wait for writer to finish draining. This ensures
    // any per-session tasks that share the same token also begin winding
    // down before we try to stop listeners.
    cancel.cancel();
    write_task.abort();

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
        MessageType::DataTcp | MessageType::DataUdp => {
            if let Some(session) = session_manager.get(frame.conn_id) {
                session.touch();
                if frame.msg_type == MessageType::DataTcp {
                    let conn_id = frame.conn_id;
                    let sm = state.session_manager().clone();
                    let client_tx = state.client_tx(client_id);
                    match session.send_tcp(frame.payload).await {
                        crate::session::SendOutcome::Ok => {}
                        crate::session::SendOutcome::Closed => {
                            sm.remove(conn_id);
                        }
                        crate::session::SendOutcome::Timeout => {
                            tracing::warn!(conn_id, "TCP tunnel send timeout — closing session");
                            sm.remove(conn_id);
                            if let Some(tx) = client_tx {
                                let _ = tx.send(ConnClose.to_frame(conn_id)).await;
                            }
                        }
                    }
                } else if !session.try_send(frame.payload) {
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
        }
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
