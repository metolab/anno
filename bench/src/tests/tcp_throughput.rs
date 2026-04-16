use crate::harness::TestHarness;
use crate::metrics::{
    avg_cpu_fraction_of_machine, cpu_seconds_from_jiffies, logical_cpu_count,
    read_process_cpu_jiffies, read_process_memory, rss_to_mb, summarize_histogram,
};
use crate::traffic_gen::{generate_tcp_traffic, TrafficConfig};
use anyhow::Result;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

static PORT_SEQ: AtomicU16 = AtomicU16::new(20_000);

fn next_server_port() -> u16 {
    PORT_SEQ.fetch_add(1, Ordering::SeqCst)
}

#[derive(Debug, Clone)]
pub struct TcpThroughputOpts {
    /// Cap aggregate TCP payload throughput (decimal megabits per second, e.g. 100 = 100 Mbit/s).
    pub target_mbps: Option<f64>,
    /// Collect RSS timeline + CPU jiffies around each case.
    pub collect_resources: bool,
    pub resource_sample_interval: Duration,
}

impl Default for TcpThroughputOpts {
    fn default() -> Self {
        Self {
            target_mbps: None,
            collect_resources: false,
            resource_sample_interval: Duration::from_secs(2),
        }
    }
}

fn mbps_to_bytes_per_sec(mbps: f64) -> u64 {
    (mbps * 1_000_000.0 / 8.0).max(1.0) as u64
}

async fn rss_timeline(
    server_pid: u32,
    client_pid: u32,
    duration: Duration,
    interval: Duration,
) -> Vec<Value> {
    let start = Instant::now();
    let mut out = Vec::new();
    while start.elapsed() < duration {
        let t = start.elapsed().as_secs_f64();
        out.push(json!({
            "t_secs": t,
            "server_rss_mb": read_process_memory(server_pid).map(|m| rss_to_mb(m.rss_kb)).ok(),
            "client_rss_mb": read_process_memory(client_pid).map(|m| rss_to_mb(m.rss_kb)).ok(),
        }));
        tokio::time::sleep(interval).await;
    }
    out
}

pub async fn run_with_opts(
    harness: &TestHarness,
    duration: Duration,
    connections_list: &[usize],
    payload_sizes: &[usize],
    opts: &TcpThroughputOpts,
) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_tcp_addr.ip().to_string();
    let echo_port = harness.echo_tcp_addr.port();

    let rate_limit_bytes_per_sec = opts.target_mbps.map(mbps_to_bytes_per_sec);

    let mut rows = Vec::new();

    for &payload_size in payload_sizes {
        for &connections in connections_list {
            let server_port = next_server_port();
            harness
                .create_mapping(client_id, server_port, "tcp", &echo_ip, echo_port)
                .await?;

            let target: SocketAddr = format!("127.0.0.1:{server_port}")
                .parse()
                .expect("parse mapped addr");

            let cfg = TrafficConfig {
                target,
                connections,
                payload_size,
                duration,
                rate_limit_bytes_per_sec,
            };

            let server_pid = harness.server_pid();
            let client_pid = harness.client_pid();

            let wall = Instant::now();
            let ju_s0 = read_process_cpu_jiffies(server_pid).ok();
            let ju_c0 = read_process_cpu_jiffies(client_pid).ok();

            let (res, rss_samples): (_, Vec<Value>) =
                if opts.collect_resources && opts.resource_sample_interval > Duration::ZERO {
                    let iv = opts.resource_sample_interval;
                    let (r, s) = tokio::join!(
                        generate_tcp_traffic(cfg),
                        rss_timeline(server_pid, client_pid, duration, iv)
                    );
                    (r?, s)
                } else {
                    (generate_tcp_traffic(cfg).await?, Vec::new())
                };

            let elapsed = wall.elapsed();
            let wall_s = elapsed.as_secs_f64().max(1e-9);

            let ju_s1 = read_process_cpu_jiffies(server_pid).ok();
            let ju_c1 = read_process_cpu_jiffies(client_pid).ok();

            let lat = summarize_histogram(&res.latency_us);

            let mut row = json!({
                "payload_size": payload_size,
                "connections": connections,
                "duration_secs": duration.as_secs_f64(),
                "target_mbps": opts.target_mbps,
                "rate_limit_bytes_per_sec": rate_limit_bytes_per_sec,
                "throughput_mbps": res.throughput_mbps,
                "rps": res.rps,
                "total_bytes": res.total_bytes,
                "errors": res.errors,
                "latency_us": {
                    "p50": lat.p50_us,
                    "p95": lat.p95_us,
                    "p99": lat.p99_us,
                    "p999": lat.p999_us,
                    "max": lat.max_us,
                }
            });

            if opts.collect_resources {
                let srv_rss_after = read_process_memory(server_pid)
                    .map(|m| rss_to_mb(m.rss_kb))
                    .ok();
                let cli_rss_after = read_process_memory(client_pid)
                    .map(|m| rss_to_mb(m.rss_kb))
                    .ok();

                let cpu_s = match (ju_s0, ju_s1) {
                    (Some(a), Some(b)) => {
                        let sec = cpu_seconds_from_jiffies(a, b);
                        json!({
                            "user_sys_seconds": sec,
                            "avg_percent_of_machine": avg_cpu_fraction_of_machine(sec, wall_s) * 100.0,
                            "avg_core_usage_estimate": sec / wall_s,
                            "logical_cpus": logical_cpu_count(),
                        })
                    }
                    _ => json!(null),
                };
                let cpu_c = match (ju_c0, ju_c1) {
                    (Some(a), Some(b)) => {
                        let sec = cpu_seconds_from_jiffies(a, b);
                        json!({
                            "user_sys_seconds": sec,
                            "avg_percent_of_machine": avg_cpu_fraction_of_machine(sec, wall_s) * 100.0,
                            "avg_core_usage_estimate": sec / wall_s,
                            "logical_cpus": logical_cpu_count(),
                        })
                    }
                    _ => json!(null),
                };

                if let Some(obj) = row.as_object_mut() {
                    obj.insert(
                        "rss_mb_after_case".to_string(),
                        json!({ "server": srv_rss_after, "client": cli_rss_after }),
                    );
                    obj.insert(
                        "cpu".to_string(),
                        json!({ "server": cpu_s, "client": cpu_c }),
                    );
                    if !rss_samples.is_empty() {
                        let srv_vals: Vec<f64> = rss_samples
                            .iter()
                            .filter_map(|v| v.get("server_rss_mb").and_then(|x| x.as_f64()))
                            .collect();
                        let cli_vals: Vec<f64> = rss_samples
                            .iter()
                            .filter_map(|v| v.get("client_rss_mb").and_then(|x| x.as_f64()))
                            .collect();
                        obj.insert(
                            "rss_timeline_summary".to_string(),
                            json!({
                                "samples": rss_samples,
                                "server_rss_mb_max": srv_vals.iter().copied().max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)),
                                "client_rss_mb_max": cli_vals.iter().copied().max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal)),
                                "server_rss_mb_avg": avg_opt(&srv_vals),
                                "client_rss_mb_avg": avg_opt(&cli_vals),
                            }),
                        );
                    }
                }
            }

            harness.delete_mapping(client_id, server_port).await.ok();

            rows.push(row);
        }
    }

    let server_rss = read_process_memory(harness.server_pid())
        .map(|m| rss_to_mb(m.rss_kb))
        .unwrap_or(f64::NAN);
    let client_rss = read_process_memory(harness.client_pid())
        .map(|m| rss_to_mb(m.rss_kb))
        .unwrap_or(f64::NAN);

    Ok(json!({
        "tcp_throughput": rows,
        "suite_meta": {
            "target_mbps": opts.target_mbps,
            "collect_resources": opts.collect_resources,
            "resource_sample_interval_secs": opts.resource_sample_interval.as_secs(),
            "logical_cpus": logical_cpu_count(),
        },
        "server_rss_mb": server_rss,
        "client_rss_mb": client_rss,
    }))
}

fn avg_opt(v: &[f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    let sum: f64 = v.iter().sum();
    Some(sum / v.len() as f64)
}

/// Backwards-compatible wrapper (no resource sampling, no rate limit).
pub async fn run(
    harness: &TestHarness,
    duration: Duration,
    connections_list: &[usize],
    payload_sizes: &[usize],
) -> Result<Value> {
    run_with_opts(
        harness,
        duration,
        connections_list,
        payload_sizes,
        &TcpThroughputOpts::default(),
    )
    .await
}
