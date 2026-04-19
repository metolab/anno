//! In-process echo / discard servers for end-to-end benchmarks.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::error;

/// TCP echo: read data and write it back until EOF.
pub async fn run_tcp_echo(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind tcp echo {addr}"))?;
    tracing::info!("tcp echo listening on {}", addr);
    loop {
        let (mut stream, peer) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Err(e) = stream.write_all(&buf[..n]).await {
                            error!(?peer, "tcp echo write: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        error!(?peer, "tcp echo read: {e}");
                        break;
                    }
                }
            }
        });
    }
}

/// UDP echo: recv_from and send_to same payload.
pub async fn run_udp_echo(addr: SocketAddr) -> Result<()> {
    let socket = UdpSocket::bind(addr)
        .await
        .with_context(|| format!("bind udp echo {addr}"))?;
    tracing::info!("udp echo listening on {}", addr);
    let mut buf = vec![0u8; 65535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, peer)) => {
                if let Err(e) = socket.send_to(&buf[..n], peer).await {
                    error!(?peer, "udp echo send: {e}");
                }
            }
            Err(e) => {
                error!("udp echo recv: {e}");
            }
        }
    }
}

/// TCP discard: read until EOF, never write (one-way receive throughput).
#[allow(dead_code)]
pub async fn run_tcp_discard(addr: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind tcp discard {addr}"))?;
    tracing::info!("tcp discard listening on {}", addr);
    loop {
        let mut stream = listener.accept().await?.0;
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }
}

/// TCP "slow drain": for every accepted connection, do NOT read the
/// socket for `pause` and then drain at full speed. Used by the
/// window-saturation bench to confirm the sender's credit window
/// stalls forwarding when the receiver isn't consuming.
pub async fn run_tcp_slow_drain(addr: SocketAddr, pause: std::time::Duration) -> Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind tcp slow-drain {addr}"))?;
    tracing::info!("tcp slow-drain listening on {} (pause={:?})", addr, pause);
    loop {
        let mut stream = listener.accept().await?.0;
        tokio::spawn(async move {
            tokio::time::sleep(pause).await;
            let mut buf = vec![0u8; 65536];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });
    }
}
