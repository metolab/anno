//! End-to-end large-packet TCP test.
//!
//! Pushes a payload that is several times larger than the negotiated
//! mux `max_frame_size` through the tunnel and expects an exact echo
//! back. With PR2's `FrameShard` + `Reassembler` plumbing this exercises
//! the shard/MORE/reassembly path on both client and server.

use crate::harness::TestHarness;
use anyhow::Result;
use serde_json::{json, Value};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Run the large-packet scenario.
///
/// `payload_size` should be > the server's negotiated `max_frame_size`
/// (defaults to 16 KiB) so the data is guaranteed to span multiple
/// shards. Returns the round-trip duration and verifies byte-equality.
pub async fn run(harness: &TestHarness, payload_size: usize) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_tcp_addr.ip().to_string();
    let echo_port = harness.echo_tcp_addr.port();
    let server_port = 22_500u16;

    harness
        .create_mapping(client_id, server_port, "tcp", &echo_ip, echo_port)
        .await?;

    let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .expect("large-packet target");

    let mut stream = TcpStream::connect(target).await?;
    let payload: Vec<u8> = (0..payload_size).map(|i| (i % 251) as u8).collect();
    let mut read_buf = vec![0u8; payload.len()];

    let t0 = Instant::now();
    stream.write_all(&payload).await?;
    stream.read_exact(&mut read_buf).await?;
    let elapsed_us = t0.elapsed().as_micros() as u64;

    harness.delete_mapping(client_id, server_port).await.ok();

    if read_buf != payload {
        anyhow::bail!(
            "large-packet echo mismatch: sent {} bytes, got {} matching",
            payload.len(),
            read_buf.iter().zip(payload.iter()).take_while(|(a, b)| a == b).count()
        );
    }

    Ok(json!({
        "large_packet": {
            "payload_size": payload.len(),
            "rtt_us": elapsed_us,
            "echo_ok": true,
        }
    }))
}
