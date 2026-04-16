use crate::harness::TestHarness;
use crate::metrics::{read_process_memory, rss_to_mb};
use anyhow::Result;
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::sleep;

pub async fn run(
    harness: &TestHarness,
    duration: Duration,
    churn_every: Duration,
) -> Result<Value> {
    let client_id = harness.wait_client_id().await?;
    let echo_ip = harness.echo_tcp_addr.ip().to_string();
    let echo_port = harness.echo_tcp_addr.port();
    let server_port = 24_000u16;

    harness
        .create_mapping(client_id, server_port, "tcp", &echo_ip, echo_port)
        .await?;

    let target: std::net::SocketAddr = format!("127.0.0.1:{server_port}")
        .parse()
        .expect("memory test target");

    let server_pid = harness.server_pid();
    let client_pid = harness.client_pid();

    let initial_srv_kb = read_process_memory(server_pid).ok().map(|m| m.rss_kb);
    let initial_cli_kb = read_process_memory(client_pid).ok().map(|m| m.rss_kb);

    let start = Instant::now();
    let mut peak_srv = initial_srv_kb.unwrap_or(0);
    let mut peak_cli = initial_cli_kb.unwrap_or(0);
    let mut samples: Vec<Value> = Vec::new();

    while start.elapsed() < duration {
        // Churn: open a short-lived connection and exchange one echo.
        if let Ok(mut s) = TcpStream::connect(target).await {
            let buf = vec![0xabu8; 1024];
            let mut r = vec![0u8; 1024];
            let _ = s.write_all(&buf).await;
            let _ = s.read_exact(&mut r).await;
        }

        if let Ok(m) = read_process_memory(server_pid) {
            peak_srv = peak_srv.max(m.rss_kb);
        }
        if let Ok(m) = read_process_memory(client_pid) {
            peak_cli = peak_cli.max(m.rss_kb);
        }

        samples.push(json!({
            "t_secs": start.elapsed().as_secs_f64(),
            "server_rss_mb": read_process_memory(server_pid).map(|m| rss_to_mb(m.rss_kb)).unwrap_or(f64::NAN),
            "client_rss_mb": read_process_memory(client_pid).map(|m| rss_to_mb(m.rss_kb)).unwrap_or(f64::NAN),
        }));

        sleep(churn_every).await;
    }

    let final_srv_kb = read_process_memory(server_pid).ok().map(|m| m.rss_kb);
    let final_cli_kb = read_process_memory(client_pid).ok().map(|m| m.rss_kb);

    harness.delete_mapping(client_id, server_port).await.ok();

    let growth_srv = match (initial_srv_kb, final_srv_kb) {
        (Some(a), Some(b)) => rss_to_mb(b.saturating_sub(a)),
        _ => f64::NAN,
    };
    let growth_cli = match (initial_cli_kb, final_cli_kb) {
        (Some(a), Some(b)) => rss_to_mb(b.saturating_sub(a)),
        _ => f64::NAN,
    };

    let leak_srv = growth_srv.is_finite() && growth_srv > 64.0;
    let leak_cli = growth_cli.is_finite() && growth_cli > 64.0;

    Ok(json!({
        "memory": {
            "duration_secs": duration.as_secs_f64(),
            "server": {
                "initial_mb": initial_srv_kb.map(rss_to_mb),
                "peak_mb": rss_to_mb(peak_srv),
                "final_mb": final_srv_kb.map(rss_to_mb),
                "growth_mb": growth_srv,
                "leak_detected": leak_srv,
            },
            "client": {
                "initial_mb": initial_cli_kb.map(rss_to_mb),
                "peak_mb": rss_to_mb(peak_cli),
                "final_mb": final_cli_kb.map(rss_to_mb),
                "growth_mb": growth_cli,
                "leak_detected": leak_cli,
            },
            "samples": samples,
        }
    }))
}
