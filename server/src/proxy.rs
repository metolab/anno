//! Public TCP/UDP listeners and bridging to connected clients.

use crate::session::{SessionManager, SessionProtocol};
use crate::state::{next_conn_id, AppState, StoredMapping};
use anno_common::{build_data_tcp, build_data_udp, build_new_conn, Protocol};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

pub async fn sync_client_listeners(state: &AppState, client_id: u64) {
    let mappings: Vec<StoredMapping> = match state.clients().get(&client_id) {
        Some(c) => c.mappings.clone(),
        None => return,
    };

    let is_online = state
        .clients()
        .get(&client_id)
        .map(|c| c.online.is_some())
        .unwrap_or(false);
    if !is_online {
        stop_client_listeners(state, client_id, &mappings);
        return;
    }

    let desired: std::collections::HashSet<u16> = mappings.iter().map(|m| m.server_port).collect();
    let owned: Vec<u16> = state
        .port_owner()
        .iter()
        .filter(|e| *e.value() == client_id)
        .map(|e| *e.key())
        .collect();
    for p in owned {
        if !desired.contains(&p) {
            stop_port(state, p);
        }
    }

    for m in mappings {
        if state.listener_by_port().contains_key(&m.server_port) {
            continue;
        }
        if let Some(owner) = state.port_owner().get(&m.server_port) {
            if *owner != client_id {
                tracing::error!(
                    "port {} owned by {}, cannot start for {}",
                    m.server_port,
                    *owner,
                    client_id
                );
                continue;
            }
        }

        state.port_owner().insert(m.server_port, client_id);

        let h = match m.protocol {
            Protocol::Tcp => tokio::spawn(run_tcp(state.clone(), client_id, m.clone())),
            Protocol::Udp => tokio::spawn(run_udp(state.clone(), client_id, m.clone())),
            Protocol::Both => {
                let st = state.clone();
                let mm = m.clone();
                tokio::spawn(async move {
                    let t = run_tcp(st.clone(), client_id, mm.clone());
                    let u = run_udp(st, client_id, mm);
                    let _ = tokio::join!(t, u);
                })
            }
        };
        state.listener_by_port().insert(m.server_port, h);
    }
}

/// Stop a specific port listener.
pub fn stop_port(state: &AppState, port: u16) {
    if let Some((_, h)) = state.listener_by_port().remove(&port) {
        h.abort();
        tracing::info!(port, "stopped listener");
    }
    state.port_owner().remove(&port);
}

pub fn stop_client_listeners(state: &AppState, client_id: u64, mappings: &[StoredMapping]) {
    let _ = mappings;
    stop_all_client_ports(state, client_id);
}

/// Stops every public listener owned by `client_id` (used before re-syncing mappings).
pub fn stop_all_client_ports(state: &AppState, client_id: u64) {
    let ports: Vec<u16> = state
        .port_owner()
        .iter()
        .filter(|e| *e.value() == client_id)
        .map(|e| *e.key())
        .collect();
    for p in ports {
        stop_port(state, p);
    }
}

async fn run_tcp(state: AppState, client_id: u64, m: StoredMapping) {
    let listen_addr = format!("0.0.0.0:{}", m.server_port);
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("tcp bind {}: {}", listen_addr, e);
            return;
        }
    };
    tracing::info!("listening tcp {}", listen_addr);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("tcp accept: {}", e);
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

    // Create session with bounded channel
    let (session, mut tun_rx) =
        session_manager.create_session(conn_id, SessionProtocol::Tcp, m.server_port, client_id);

    // Register waiter for ConnReady
    let ready_rx = session_manager.register_conn_ready_waiter(conn_id);

    let client_tx = match state
        .clients()
        .get(&client_id)
        .and_then(|c| c.online.as_ref().map(|o| o.tx.clone()))
    {
        Some(tx) => tx,
        None => {
            tracing::warn!("client {} offline, drop tcp {}", client_id, peer);
            cleanup_session(session_manager, conn_id);
            return;
        }
    };

    let new_conn = build_new_conn(conn_id, m.server_port, Protocol::Tcp, &m.target);
    if client_tx.send(new_conn).await.is_err() {
        cleanup_session(session_manager, conn_id);
        return;
    }

    // Wait for ConnReady with timeout
    let ready = tokio::time::timeout(timeout, ready_rx).await;
    if ready.is_err() || ready.unwrap().is_err() {
        tracing::warn!("tcp session {} ready timeout peer={}", conn_id, peer);
        let _ = ext.shutdown().await;
        cleanup_session(session_manager, conn_id);
        return;
    }

    let (mut rh, mut wh) = ext.into_split();

    let to_client = client_tx.clone();
    let sm_up = Arc::clone(session_manager);
    let session_up = Arc::clone(&session);
    let up = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(64 * 1024);
        while let Ok(n) = rh.read_buf(&mut buf).await {
            if n == 0 {
                break;
            }
            session_up.stats.record_up(n);
            tracing::debug!(conn_id, peer = %peer, n, "public side read -> DataTcp to client");
            let chunk = buf.split_to(n).freeze();
            let fr = build_data_tcp(conn_id, chunk);
            if to_client.send(fr).await.is_err() {
                tracing::warn!(
                    conn_id,
                    "to_client send failed (client control channel closed)"
                );
                break;
            }
        }
        let _ = to_client.send(anno_common::build_conn_close(conn_id)).await;
        sm_up.remove(conn_id);
    });

    let sm_down = Arc::clone(session_manager);
    let session_down = Arc::clone(&session);
    let down = tokio::spawn(async move {
        while let Some(chunk) = tun_rx.recv().await {
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

async fn run_udp(state: AppState, client_id: u64, m: StoredMapping) {
    let listen_addr = format!("0.0.0.0:{}", m.server_port);
    let sock = match UdpSocket::bind(&listen_addr).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("udp bind {}: {}", listen_addr, e);
            return;
        }
    };
    let sock = Arc::new(sock);
    tracing::info!("listening udp {}", listen_addr);

    let session_manager = state.session_manager();
    let timeout = session_manager.config().conn_ready_timeout;

    // Maps peer address to conn_id (for routing incoming packets to existing sessions)
    let mut peer_sessions: HashMap<SocketAddr, u64> = HashMap::new();
    let mut buf = vec![0u8; 64 * 1024];

    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::error!("udp recv: {}", e);
                continue;
            }
        };
        let payload = Bytes::copy_from_slice(&buf[..n]);

        // Check if we have an existing session for this peer
        if let Some(&conn_id) = peer_sessions.get(&peer) {
            // Check if session is still valid
            if let Some(session) = session_manager.get(conn_id) {
                session.touch();
                session.stats.record_up(n);

                let client_tx = match state
                    .clients()
                    .get(&client_id)
                    .and_then(|c| c.online.as_ref().map(|o| o.tx.clone()))
                {
                    Some(tx) => tx,
                    None => {
                        peer_sessions.remove(&peer);
                        session_manager.remove(conn_id);
                        continue;
                    }
                };
                let fr = build_data_udp(conn_id, payload);
                let _ = client_tx.send(fr).await;
                continue;
            } else {
                // Session was cleaned up (timeout), remove from local map
                peer_sessions.remove(&peer);
            }
        }

        // Create new session for this peer
        let conn_id = next_conn_id();
        let (session, mut tun_rx) =
            session_manager.create_session(conn_id, SessionProtocol::Udp, m.server_port, client_id);

        let ready_rx = session_manager.register_conn_ready_waiter(conn_id);

        let client_tx = match state
            .clients()
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| o.tx.clone()))
        {
            Some(tx) => tx,
            None => {
                cleanup_session(session_manager, conn_id);
                continue;
            }
        };

        let new_conn = build_new_conn(conn_id, m.server_port, Protocol::Udp, &m.target);
        if client_tx.send(new_conn).await.is_err() {
            cleanup_session(session_manager, conn_id);
            continue;
        }

        // Wait for ConnReady with timeout
        let ready = tokio::time::timeout(timeout, ready_rx).await;
        if ready.is_err() || ready.unwrap().is_err() {
            tracing::warn!("udp session {} ready timeout peer={}", conn_id, peer);
            cleanup_session(session_manager, conn_id);
            continue;
        }

        peer_sessions.insert(peer, conn_id);
        session.stats.record_up(n);

        // Send the initial packet
        let fr0 = build_data_udp(conn_id, payload);
        if client_tx.send(fr0).await.is_err() {
            peer_sessions.remove(&peer);
            session_manager.remove(conn_id);
            continue;
        }

        // Spawn task to send data from tunnel to peer
        let sock_c = Arc::clone(&sock);
        let sm_c = Arc::clone(session_manager);
        let session_c = Arc::clone(&session);
        tokio::spawn(async move {
            while let Some(chunk) = tun_rx.recv().await {
                session_c.stats.record_down(chunk.len());
                session_c.touch();
                if sock_c.send_to(&chunk, peer).await.is_err() {
                    break;
                }
            }
            sm_c.remove(conn_id);
        });
    }
}
