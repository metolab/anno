//! Control connection to server and per-session forwarding.

use crate::forward;
use anno_common::{
    build_config_ack, build_conn_close, build_conn_ready, build_data_tcp, build_data_udp,
    build_error, build_pong, parse_config_push, parse_new_conn, parse_register_ack, ErrorCode,
    MessageType, Protocol,
};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::{FramedRead, FramedWrite};

use anno_common::FrameCodec;

/// Configuration for client sessions.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Capacity of the bounded channel for tunnel data.
    pub tunnel_queue_capacity: usize,
    /// Control channel capacity.
    pub control_channel_capacity: usize,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            tunnel_queue_capacity: 256,
            control_channel_capacity: 1024,
        }
    }
}

/// Session entry with bounded sender and statistics.
struct SessionEntry {
    tx: mpsc::Sender<Bytes>,
    drops: AtomicU64,
}

impl SessionEntry {
    fn new(tx: mpsc::Sender<Bytes>) -> Self {
        Self {
            tx,
            drops: AtomicU64::new(0),
        }
    }

    fn try_send(&self, data: Bytes) -> bool {
        match self.tx.try_send(data) {
            Ok(_) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.drops.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("tunnel queue full, dropping packet");
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }
}

/// Run the client with custom configuration.
pub async fn run_client_with_config(
    server: SocketAddr,
    name: String,
    key: Option<String>,
    http_proxy_port: Option<u16>,
    config: ClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(server).await?;
    let (rh, wh) = stream.into_split();
    let mut read_half = FramedRead::new(rh, FrameCodec);
    let mut write_half = FramedWrite::new(wh, FrameCodec);

    let reg = anno_common::build_register(&name, key.as_deref(), http_proxy_port);
    write_half.send(reg).await?;

    let (out_tx, mut out_rx) = mpsc::channel::<anno_common::Frame>(config.control_channel_capacity);
    let out_tx2 = out_tx.clone();

    tokio::spawn(async move {
        while let Some(f) = out_rx.recv().await {
            if write_half.send(f).await.is_err() {
                break;
            }
        }
        let _ = write_half.close().await;
    });

    // Use bounded channels wrapped in SessionEntry for backpressure control
    let tcp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>> = Arc::new(DashMap::new());
    let udp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>> = Arc::new(DashMap::new());
    let config = Arc::new(config);

    while let Some(frame) = read_half.next().await {
        let frame = frame?;
        match frame.msg_type {
            MessageType::RegisterAck => {
                let _id = parse_register_ack(&frame.payload)?;
            }
            MessageType::ConfigPush => {
                let _cfg = parse_config_push(&frame.payload)?;
                out_tx2.send(build_config_ack()).await?;
            }
            MessageType::Ping => {
                out_tx2.send(build_pong()).await?;
            }
            MessageType::NewConn => {
                let conn_id = frame.conn_id;
                let (_sp, proto, target) = parse_new_conn(&frame.payload)?;
                let out = out_tx2.clone();
                let tcp_m = Arc::clone(&tcp_sessions);
                let udp_m = Arc::clone(&udp_sessions);
                let cfg = Arc::clone(&config);
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_new_conn(conn_id, proto, target, out, tcp_m, udp_m, &cfg).await
                    {
                        tracing::warn!("new_conn {} failed: {}", conn_id, e);
                    }
                });
            }
            MessageType::DataTcp => {
                if let Some(entry) = tcp_sessions.get(&frame.conn_id) {
                    tracing::debug!(
                        conn_id = frame.conn_id,
                        len = frame.payload.len(),
                        "recv DataTcp"
                    );
                    // Bounded forward with backpressure handling
                    entry.try_send(frame.payload);
                } else {
                    tracing::debug!(conn_id = frame.conn_id, "DataTcp for unknown session");
                }
            }
            MessageType::DataUdp => {
                if let Some(entry) = udp_sessions.get(&frame.conn_id) {
                    entry.try_send(frame.payload);
                }
            }
            MessageType::ConnClose => {
                tcp_sessions.remove(&frame.conn_id);
                udp_sessions.remove(&frame.conn_id);
            }
            _ => {}
        }
    }

    Ok(())
}

async fn handle_new_conn(
    conn_id: u64,
    proto: Protocol,
    target: anno_common::TargetAddress,
    out_tx: mpsc::Sender<anno_common::Frame>,
    tcp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>>,
    udp_sessions: Arc<DashMap<u64, Arc<SessionEntry>>>,
    config: &ClientConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match proto {
        Protocol::Tcp => {
            // Register tunnel before any await so the control read loop never drops early DataTcp
            // (server may send payload immediately after it observes ConnReady on the wire).
            let (tun_tx, mut tun_rx) = mpsc::channel::<Bytes>(config.tunnel_queue_capacity);
            let entry = Arc::new(SessionEntry::new(tun_tx));
            tcp_sessions.insert(conn_id, Arc::clone(&entry));

            let stream = match forward::tcp_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    tcp_sessions.remove(&conn_id);
                    let fault = build_error(ErrorCode::ConnectionRefused, &e.to_string());
                    let _ = out_tx.send(fault).await;
                    return Err(e.into());
                }
            };
            out_tx.send(build_conn_ready(conn_id)).await?;
            let (mut rh, mut wh) = stream.into_split();
            let out_u = out_tx.clone();
            let tcp_sessions_c = tcp_sessions.clone();
            let up = tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(64 * 1024);
                while let Ok(n) = rh.read_buf(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    let chunk = buf.split_to(n).freeze();
                    let fr = build_data_tcp(conn_id, chunk);
                    if out_u.send(fr).await.is_err() {
                        break;
                    }
                }
                let _ = out_u.send(build_conn_close(conn_id)).await;
                tcp_sessions_c.remove(&conn_id);
            });
            let out_d = out_tx.clone();
            let tcp_sessions_d = tcp_sessions.clone();
            let down = tokio::spawn(async move {
                while let Some(chunk) = tun_rx.recv().await {
                    if wh.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                let _ = wh.shutdown().await;
                tcp_sessions_d.remove(&conn_id);
                let _ = out_d.send(build_conn_close(conn_id)).await;
            });
            let _ = tokio::join!(up, down);
        }
        Protocol::Udp => {
            let (tun_tx, mut tun_rx) = mpsc::channel::<Bytes>(config.tunnel_queue_capacity);
            let entry = Arc::new(SessionEntry::new(tun_tx));
            udp_sessions.insert(conn_id, Arc::clone(&entry));

            let sock = match forward::udp_connect(&target).await {
                Ok(s) => s,
                Err(e) => {
                    udp_sessions.remove(&conn_id);
                    let fault = build_error(ErrorCode::ConnectionRefused, &e.to_string());
                    let _ = out_tx.send(fault).await;
                    return Err(e.into());
                }
            };
            out_tx.send(build_conn_ready(conn_id)).await?;
            let sock = Arc::new(sock);
            let out_u = out_tx.clone();
            let udp_sessions_c = udp_sessions.clone();
            let s2 = sock.clone();
            let up = tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match s2.recv(&mut buf).await {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    let fr = build_data_udp(conn_id, Bytes::copy_from_slice(&buf[..n]));
                    if out_u.send(fr).await.is_err() {
                        break;
                    }
                }
                let _ = out_u.send(build_conn_close(conn_id)).await;
                udp_sessions_c.remove(&conn_id);
            });
            let out_d = out_tx.clone();
            let udp_sessions_d = udp_sessions.clone();
            let s3 = sock.clone();
            let down = tokio::spawn(async move {
                while let Some(chunk) = tun_rx.recv().await {
                    if s3.send(&chunk).await.is_err() {
                        break;
                    }
                }
                udp_sessions_d.remove(&conn_id);
                let _ = out_d.send(build_conn_close(conn_id)).await;
            });
            let _ = tokio::join!(up, down);
        }
        Protocol::Both => {
            tracing::warn!("unexpected Protocol::Both in NewConn");
        }
    }
    Ok(())
}
