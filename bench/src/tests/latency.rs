use crate::harness::TestHarness;
use crate::metrics::{jitter_approx_us, summarize_histogram};
use anyhow::Result;
use serde_json::{json, Value};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn run(harness: &TestHarness, samples: u64, payload_size: usize) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_tcp_addr.ip().to_string();
    let echo_port = harness.echo_tcp_addr.port();
    let server_port = 22_000u16;

    harness
        .create_mapping(client_id, server_port, "tcp", &echo_ip, echo_port)
        .await?;

    let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .expect("latency target");

    let mut stream = TcpStream::connect(target).await?;
    let payload: Vec<u8> = (0..payload_size.max(1)).map(|i| (i % 256) as u8).collect();
    let mut read_buf = vec![0u8; payload.len()];

    let mut hist = hdrhistogram::Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;

    let warmup = 50u64;
    for i in 0..warmup + samples {
        let t0 = Instant::now();
        stream.write_all(&payload).await?;
        stream.read_exact(&mut read_buf).await?;
        let us = t0.elapsed().as_micros() as u64;
        if i >= warmup {
            let _ = hist.record(us);
        }
    }

    harness.delete_mapping(client_id, server_port).await.ok();

    let s = summarize_histogram(&hist);
    let jitter = jitter_approx_us(&hist);

    Ok(json!({
        "latency": {
            "samples": samples,
            "payload_size": payload.len(),
            "p50_us": s.p50_us,
            "p95_us": s.p95_us,
            "p99_us": s.p99_us,
            "p999_us": s.p999_us,
            "max_us": s.max_us,
            "jitter_us": jitter,
        }
    }))
}
