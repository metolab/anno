//! Client control connection (single multiplexed TCP connection).

use crate::proxy;
use crate::state::{AppState, ClientRecord, OnlineSession, StoredMapping};
use anno_common::{build_config_push, build_register_ack, parse_error, MessageType};
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::SystemTime;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};

use anno_common::FrameCodec;

pub async fn handle_control_connection(state: AppState, stream: TcpStream, peer: SocketAddr) {
    metrics::counter!("control_connections_total").increment(1);
    metrics::gauge!("control_connections_active").increment(1.0);
    handle_control_connection_inner(state, stream, peer).await;
    metrics::gauge!("control_connections_active").decrement(1.0);
}

async fn handle_control_connection_inner(state: AppState, stream: TcpStream, peer: SocketAddr) {
    let (rh, wh) = stream.into_split();
    let mut read_half = FramedRead::new(rh, FrameCodec);
    let mut write_half = FramedWrite::new(wh, FrameCodec);

    let first = match read_half.next().await {
        Some(Ok(f)) => f,
        _ => return,
    };

    if first.msg_type != MessageType::Register {
        tracing::warn!("first frame not Register from {}", peer);
        return;
    }

    let (name, http_proxy_port, client_key): (String, Option<u16>, Option<String>) =
        match anno_common::parse_register(&first.payload) {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("bad register from {}: {}", peer, e);
                return;
            }
        };

    if !state.registry().verify_key(&name, client_key.as_deref()) {
        tracing::warn!(name = %name, peer = %peer, "client authentication failed: invalid key");
        let fault = anno_common::build_error(
            anno_common::ErrorCode::ConnectionRefused,
            "invalid client key",
        );
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

    let channel_capacity = state.control_channel_capacity();
    let (tx, mut rx) = mpsc::channel::<anno_common::Frame>(channel_capacity);

    {
        let mut entry = state.clients().entry(client_id).or_insert(ClientRecord {
            name: name.clone(),
            http_proxy_port,
            mappings: vec![],
            online: None,
        });
        entry.name = name.clone();
        entry.http_proxy_port = http_proxy_port;
        entry.online = Some(OnlineSession {
            addr: peer,
            connected_at: SystemTime::now(),
            tx: tx.clone(),
        });
    }

    let ack = build_register_ack(client_id);
    if write_half.send(ack).await.is_err() {
        clear_online(&state, client_id);
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
    let cfg = build_config_push(&pm);
    if write_half.send(cfg).await.is_err() {
        clear_online(&state, client_id);
        return;
    }

    proxy::sync_client_listeners(&state, client_id).await;

    let st_read = state.clone();
    let read_task = async move {
        while let Some(item) = read_half.next().await {
            match item {
                Err(e) => {
                    tracing::warn!("read error: {}", e);
                    break;
                }
                Ok(frame) => {
                    if dispatch_incoming(&st_read, client_id, frame).await.is_err() {
                        break;
                    }
                }
            }
        }
    };

    let write_task = async move {
        while let Some(frame) = rx.recv().await {
            if write_half.send(frame).await.is_err() {
                break;
            }
        }
        let _ = write_half.close().await;
    };

    tokio::join!(read_task, write_task);

    clear_online(&state, client_id);
    if let Some(c) = state.clients().get(&client_id) {
        proxy::stop_client_listeners(&state, client_id, &c.mappings);
    }
}

fn clear_online(state: &AppState, client_id: u64) {
    // Clean up all sessions for this client
    let removed = state.session_manager().remove_client_sessions(client_id);
    if removed > 0 {
        tracing::info!(
            client_id,
            removed,
            "cleaned up client sessions on disconnect"
        );
    }

    if let Some(mut c) = state.clients().get_mut(&client_id) {
        c.online = None;
    }
}

async fn dispatch_incoming(
    state: &AppState,
    client_id: u64,
    frame: anno_common::Frame,
) -> Result<(), ()> {
    let session_manager = state.session_manager();

    match frame.msg_type {
        MessageType::Ping => {
            let tx = state
                .clients()
                .get(&client_id)
                .and_then(|c| c.online.as_ref().map(|o| o.tx.clone()));
            if let Some(tx) = tx {
                let _ = tx.send(anno_common::build_pong()).await;
            }
        }
        MessageType::Pong | MessageType::ConfigAck => {}
        MessageType::ConnReady => {
            if session_manager.notify_conn_ready(frame.conn_id) {
                tracing::info!(conn_id = frame.conn_id, "session ready (ConnReady)");
            } else {
                tracing::warn!(conn_id = frame.conn_id, "ConnReady for unknown conn_id");
            }
        }
        MessageType::DataTcp | MessageType::DataUdp => {
            if let Some(session) = session_manager.get(frame.conn_id) {
                session.touch();
                if !session.try_send(frame.payload) {
                    tracing::debug!(
                        conn_id = frame.conn_id,
                        "tunnel queue full or closed, data dropped"
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
        MessageType::Fault => {
            // Handle fault messages from client
            match parse_error(&frame.payload) {
                Ok((code, msg)) => {
                    tracing::warn!(
                        client_id,
                        conn_id = frame.conn_id,
                        code,
                        message = %msg,
                        "received fault from client"
                    );
                    // Clean up the associated session if any
                    session_manager.remove(frame.conn_id);
                }
                Err(e) => {
                    tracing::warn!(client_id, "invalid fault payload: {}", e);
                }
            }
        }
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
