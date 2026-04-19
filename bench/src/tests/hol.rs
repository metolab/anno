//! Head-of-line (HOL) repro benchmark.
//!
//! Hypothesis: a single fat stream consuming the wire shouldn't make
//! short, latency-sensitive streams suffer disproportionately. With
//! the PR3 weighted-RR scheduler + PR4 per-stream credit windowing +
//! PR5 multi-lane connection pool, the round-trip time of small
//! probes should stay close to baseline even while a hammer thread
//! pushes large echoed buffers in the background.
//!
//! The bench runs in two phases:
//!   1. baseline: send `probe_count` 64 B requests sequentially with no
//!      hammer running. Record the median + p99 RTT.
//!   2. under load: spawn a hammer that writes `payload_size` chunks in
//!      a tight loop, then run the same probe sequence. Record again.
//!
//! It returns both phases plus the p99 inflation ratio so a CI gate can
//! assert it stays under, say, 4x.
//!
//! NOTE: this does not assert anything by itself — it's a JSON-emitting
//! micro-benchmark intended for human / CI inspection.

use crate::harness::TestHarness;
use anyhow::Result;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const PROBE_BYTES: usize = 64;

async fn run_probes(
    target: std::net::SocketAddr,
    count: usize,
) -> Result<(u128, u128, u128)> {
    let mut stream = TcpStream::connect(target).await?;
    stream.set_nodelay(true)?;
    let probe = vec![0xA5u8; PROBE_BYTES];
    let mut buf = vec![0u8; PROBE_BYTES];
    let mut samples = Vec::with_capacity(count);
    for _ in 0..count {
        let t0 = Instant::now();
        stream.write_all(&probe).await?;
        stream.read_exact(&mut buf).await?;
        samples.push(t0.elapsed().as_micros());
    }
    samples.sort_unstable();
    let median = samples[samples.len() / 2];
    let p99 = samples[(samples.len() * 99) / 100];
    let max = *samples.last().unwrap_or(&0);
    Ok((median, p99, max))
}

/// Run the HOL scenario. `payload_size` controls how fat the hammer's
/// per-iteration writes are; `probe_count` controls how many small
/// round-trips we time.
pub async fn run(
    harness: &TestHarness,
    payload_size: usize,
    probe_count: usize,
    hammer_secs: u64,
) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_tcp_addr.ip().to_string();
    let echo_port = harness.echo_tcp_addr.port();
    let server_port = 22_800u16;

    harness
        .create_mapping(client_id, server_port, "tcp", &echo_ip, echo_port)
        .await?;

    let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .expect("hol target");

    // Phase 1: baseline RTTs without contention.
    let (base_med, base_p99, base_max) = run_probes(target, probe_count).await?;

    // Phase 2: spawn hammer thread, run probes in parallel, stop hammer
    // after `hammer_secs` (the probe loop might finish earlier; that's
    // fine — we only care that the hammer was running while we probed).
    let hammer_target = target;
    let hammer = tokio::spawn(async move {
        let mut s = match TcpStream::connect(hammer_target).await {
            Ok(s) => s,
            Err(_) => return Ok::<(), std::io::Error>(()),
        };
        s.set_nodelay(true)?;
        let payload = vec![0xC3u8; payload_size];
        let mut sink = vec![0u8; payload_size];
        let deadline = Instant::now() + Duration::from_secs(hammer_secs);
        while Instant::now() < deadline {
            s.write_all(&payload).await?;
            s.read_exact(&mut sink).await?;
        }
        Ok(())
    });

    // Give the hammer a moment to ramp up before sampling.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (load_med, load_p99, load_max) = run_probes(target, probe_count).await?;

    let _ = hammer.await;
    harness.delete_mapping(client_id, server_port).await.ok();

    let p99_inflation = if base_p99 > 0 {
        load_p99 as f64 / base_p99 as f64
    } else {
        f64::NAN
    };

    Ok(json!({
        "hol": {
            "probe_count": probe_count,
            "hammer_payload": payload_size,
            "hammer_secs": hammer_secs,
            "baseline_us":   { "median": base_med, "p99": base_p99, "max": base_max },
            "under_load_us": { "median": load_med, "p99": load_p99, "max": load_max },
            "p99_inflation": p99_inflation,
        }
    }))
}
