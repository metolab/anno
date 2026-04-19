//! Fairness benchmark: two concurrent streams compete for the same
//! tunnel.
//!
//! Each stream sends a fixed-size payload and reads the echo back, in
//! parallel. We measure per-stream throughput and report the ratio
//! between the slow and fast stream — under the PR3 weighted RR
//! scheduler + PR4 credit windowing this ratio should be close to 1.0
//! (i.e. neither stream starves the other).

use crate::harness::TestHarness;
use anyhow::Result;
use serde_json::{json, Value};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn drive_stream(
    target: std::net::SocketAddr,
    payload_size: usize,
    rounds: usize,
) -> Result<(usize, u128)> {
    let mut s = TcpStream::connect(target).await?;
    let payload: Vec<u8> = (0..payload_size).map(|i| (i % 251) as u8).collect();
    let mut read_buf = vec![0u8; payload.len()];
    let t0 = Instant::now();
    let mut bytes = 0usize;
    for _ in 0..rounds {
        s.write_all(&payload).await?;
        s.read_exact(&mut read_buf).await?;
        if read_buf != payload {
            anyhow::bail!("fairness echo mismatch");
        }
        bytes += payload.len();
    }
    Ok((bytes, t0.elapsed().as_micros()))
}

/// Run the fairness scenario.
///
/// Spawns two concurrent TCP echo loops through the tunnel and returns
/// per-stream throughput along with the slow/fast ratio so a CI gate
/// can assert it never drops below, say, 0.5.
pub async fn run(harness: &TestHarness, payload_size: usize, rounds: usize) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_tcp_addr.ip().to_string();
    let echo_port = harness.echo_tcp_addr.port();
    let server_port = 22_700u16;

    harness
        .create_mapping(client_id, server_port, "tcp", &echo_ip, echo_port)
        .await?;

    let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .expect("fairness target");

    // Run both streams concurrently. We pick identical payloads so any
    // imbalance is purely scheduling, not workload skew.
    let s1 = tokio::spawn(drive_stream(target, payload_size, rounds));
    let s2 = tokio::spawn(drive_stream(target, payload_size, rounds));
    let (r1, r2) = tokio::join!(s1, s2);
    let (b1, e1) = r1??;
    let (b2, e2) = r2??;

    harness.delete_mapping(client_id, server_port).await.ok();

    let mbps1 = (b1 as f64 * 8.0) / e1 as f64; // bits / us == Mb/s
    let mbps2 = (b2 as f64 * 8.0) / e2 as f64;
    let (lo, hi) = if mbps1 < mbps2 {
        (mbps1, mbps2)
    } else {
        (mbps2, mbps1)
    };
    let ratio = if hi > 0.0 { lo / hi } else { 1.0 };

    Ok(json!({
        "fairness": {
            "payload_size": payload_size,
            "rounds": rounds,
            "stream_a_mbps": mbps1,
            "stream_b_mbps": mbps2,
            "slow_fast_ratio": ratio,
        }
    }))
}
