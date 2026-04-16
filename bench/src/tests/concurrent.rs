use crate::harness::TestHarness;
use crate::metrics::{rss_to_mb, summarize_histogram};
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio::time::timeout;

pub async fn run(
    harness: &TestHarness,
    max_connections: usize,
    payload_size: usize,
    dial_timeout: Duration,
) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_tcp_addr.ip().to_string();
    let echo_port = harness.echo_tcp_addr.port();
    let server_port = 23_000u16;

    harness
        .create_mapping(client_id, server_port, "tcp", &echo_ip, echo_port)
        .await?;

    let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .expect("concurrent target");

    let barrier = Arc::new(Barrier::new(max_connections + 1));
    let mut handles = Vec::new();
    let ps = payload_size.max(1);

    for _ in 0..max_connections {
        let barrier = barrier.clone();
        let addr = target;
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            let t0 = Instant::now();
            let stream = match timeout(dial_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(s)) => s,
                _ => return None,
            };
            let us = t0.elapsed().as_micros() as u64;
            let mut stream = stream;
            let payload: Vec<u8> = (0..ps).map(|i| (i % 256) as u8).collect();
            let mut r = vec![0u8; ps];
            if stream.write_all(&payload).await.is_err() {
                return Some((us, false));
            }
            if stream.read_exact(&mut r).await.is_err() {
                return Some((us, false));
            }
            Some((us, true))
        }));
    }

    barrier.wait().await;

    let mut dial_lat = hdrhistogram::Histogram::<u64>::new_with_bounds(1, 60_000_000, 3)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let mut established = 0usize;

    for h in handles {
        if let Ok(Some((us, ok))) = h.await {
            let _ = dial_lat.record(us);
            if ok {
                established += 1;
            }
        }
    }

    let dial_summary = summarize_histogram(&dial_lat);

    harness.delete_mapping(client_id, server_port).await.ok();

    let server_rss = crate::metrics::read_process_memory(harness.server_pid())
        .map(|m| rss_to_mb(m.rss_kb))
        .unwrap_or(f64::NAN);
    let client_rss = crate::metrics::read_process_memory(harness.client_pid())
        .map(|m| rss_to_mb(m.rss_kb))
        .unwrap_or(f64::NAN);

    Ok(json!({
        "concurrent": {
            "requested": max_connections,
            "established": established,
            "dial_latency_us": {
                "p50": dial_summary.p50_us,
                "p95": dial_summary.p95_us,
                "p99": dial_summary.p99_us,
                "max": dial_summary.max_us,
            },
            "server_rss_mb": server_rss,
            "client_rss_mb": client_rss,
        }
    }))
}
