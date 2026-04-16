use crate::harness::TestHarness;
use crate::metrics::{rss_to_mb, summarize_histogram};
use crate::traffic_gen::generate_udp_traffic;
use anyhow::Result;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

static PORT_SEQ: AtomicU16 = AtomicU16::new(21_000);

fn next_server_port() -> u16 {
    PORT_SEQ.fetch_add(1, Ordering::SeqCst)
}

pub async fn run(
    harness: &TestHarness,
    duration: Duration,
    packet_sizes: &[usize],
    pps_cap: Option<u64>,
) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_udp_addr.ip().to_string();
    let echo_port = harness.echo_udp_addr.port();

    let mut rows = Vec::new();

    for &pkt in packet_sizes {
        let body = pkt.max(8);
        let server_port = next_server_port();
        harness
            .create_mapping(client_id, server_port, "udp", &echo_ip, echo_port)
            .await?;

        let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
            .parse()
            .expect("parse mapped udp addr");

        let res = generate_udp_traffic(target, body, duration, pps_cap).await?;
        let lat = summarize_histogram(&res.latency_us);

        harness.delete_mapping(client_id, server_port).await.ok();

        rows.push(json!({
            "packet_size": pkt,
            "duration_secs": duration.as_secs_f64(),
            "pps": res.pps,
            "throughput_mbps": res.throughput_mbps,
            "packets_sent": res.packets_sent,
            "packets_ok": res.packets_ok,
            "packets_lost": res.packets_lost,
            "loss_rate": res.loss_rate,
            "latency_us": {
                "p50": lat.p50_us,
                "p95": lat.p95_us,
                "p99": lat.p99_us,
                "p999": lat.p999_us,
                "max": lat.max_us,
            }
        }));
    }

    let server_rss = crate::metrics::read_process_memory(harness.server_pid())
        .map(|m| rss_to_mb(m.rss_kb))
        .unwrap_or(f64::NAN);
    let client_rss = crate::metrics::read_process_memory(harness.client_pid())
        .map(|m| rss_to_mb(m.rss_kb))
        .unwrap_or(f64::NAN);

    Ok(json!({
        "udp_throughput": rows,
        "server_rss_mb": server_rss,
        "client_rss_mb": client_rss,
    }))
}
