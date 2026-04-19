//! Window-saturation benchmark.
//!
//! Verifies that the PR4 credit windowing makes a slow consumer
//! actually slow the sender down rather than letting the in-tunnel
//! queue grow unboundedly. We do this without touching internal
//! state: we instrument from the outside.
//!
//! Setup:
//!   1. spin up a "slow drain" TCP backend that doesn't read its
//!      socket for `pause` seconds, then drains at full speed.
//!   2. open a tunnelled TCP connection to it and write
//!      `total_bytes` of data, recording at what wall-clock time each
//!      `chunk_size`-sized write actually returned.
//!
//! Because the sender's `acquire_send` blocks once the per-stream
//! credit is exhausted, the per-write timings should plateau (the
//! writes start blocking) and resume only after the pause expires.
//! We report the max + average inter-write delay and the total
//! transfer time.

use crate::echo_server::run_tcp_slow_drain;
use crate::harness::TestHarness;
use anyhow::Result;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Run the window saturation scenario.
///
/// `total_bytes` should comfortably exceed the negotiated initial
/// window so we genuinely cross the credit boundary; the default
/// `initial_window` is 256 KiB, so 4 MiB is a safe choice.
pub async fn run(
    harness: &TestHarness,
    total_bytes: usize,
    chunk_size: usize,
    pause_ms: u64,
) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;

    // Spawn a dedicated slow-drain backend on a fresh port so we don't
    // interfere with the normal echo server and other concurrent
    // benches.
    let backend_port = 17_780u16;
    let backend_addr: std::net::SocketAddr =
        format!("127.0.0.1:{backend_port}").parse().expect("backend addr");
    let pause = Duration::from_millis(pause_ms);
    let backend = tokio::spawn(async move {
        let _ = run_tcp_slow_drain(backend_addr, pause).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let server_port = 22_900u16;
    harness
        .create_mapping(client_id, server_port, "tcp", "127.0.0.1", backend_port)
        .await?;

    let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .expect("window-sat target");

    let mut stream = TcpStream::connect(target).await?;
    stream.set_nodelay(true)?;
    let chunk = vec![0xE7u8; chunk_size];

    let total_start = Instant::now();
    let mut max_chunk_us: u128 = 0;
    let mut chunks_written = 0usize;
    let mut written = 0usize;
    while written < total_bytes {
        let n = chunk_size.min(total_bytes - written);
        let t0 = Instant::now();
        stream.write_all(&chunk[..n]).await?;
        let dt = t0.elapsed().as_micros();
        if dt > max_chunk_us {
            max_chunk_us = dt;
        }
        written += n;
        chunks_written += 1;
    }
    let total_us = total_start.elapsed().as_micros();
    let avg_chunk_us = if chunks_written > 0 {
        total_us / chunks_written as u128
    } else {
        0
    };

    drop(stream);
    harness.delete_mapping(client_id, server_port).await.ok();
    backend.abort();

    Ok(json!({
        "window_saturation": {
            "total_bytes": total_bytes,
            "chunk_size": chunk_size,
            "pause_ms": pause_ms,
            "chunks_written": chunks_written,
            "total_us": total_us,
            "max_chunk_us": max_chunk_us,
            "avg_chunk_us": avg_chunk_us,
        }
    }))
}
