//! TCP/UDP traffic generators for measuring throughput and latency.

use anyhow::Result;
use hdrhistogram::Histogram;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Barrier;
use tokio::time::timeout;

fn new_latency_histogram() -> Result<Histogram<u64>> {
    Histogram::<u64>::new_with_bounds(1, 60_000_000, 3).map_err(|e| anyhow::anyhow!("{e:?}"))
}

#[derive(Debug, Clone)]
pub struct TrafficConfig {
    pub target: SocketAddr,
    pub connections: usize,
    pub payload_size: usize,
    pub duration: Duration,
    pub rate_limit_bytes_per_sec: Option<u64>,
}

#[derive(Debug)]
pub struct TrafficResult {
    pub total_bytes: u64,
    #[allow(dead_code)]
    pub total_ops: u64,
    pub throughput_mbps: f64,
    pub rps: f64,
    pub latency_us: Histogram<u64>,
    pub errors: u64,
}

/// Bidirectional TCP echo workload: each op sends `payload_size` bytes and reads the same back.
pub async fn generate_tcp_traffic(config: TrafficConfig) -> Result<TrafficResult> {
    let connections = config.connections.max(1);
    let payload_size = config.payload_size.max(1);
    let duration = config.duration;
    let rate_limit = config.rate_limit_bytes_per_sec;

    let barrier = Arc::new(Barrier::new(connections + 1));
    let start_at = Arc::new(tokio::sync::Mutex::new(None::<Instant>));

    let mut handles = Vec::new();
    for _ in 0..connections {
        let target = config.target;
        let barrier = Arc::clone(&barrier);
        let start_at = Arc::clone(&start_at);

        handles.push(tokio::spawn(async move {
            let mut stream = match TcpStream::connect(target).await {
                Ok(s) => s,
                Err(_) => {
                    return Ok::<_, anyhow::Error>((0u64, 0u64, 1u64, new_latency_histogram()?));
                }
            };

            let payload: Vec<u8> = (0..payload_size).map(|i| (i % 256) as u8).collect();
            let mut read_buf = vec![0u8; payload_size];

            barrier.wait().await;
            {
                let mut g = start_at.lock().await;
                if g.is_none() {
                    *g = Some(Instant::now());
                }
            }

            let deadline = {
                let g = start_at.lock().await;
                g.unwrap() + duration
            };

            let mut local_hist = new_latency_histogram()?;
            let mut bytes = 0u64;
            let mut ops = 0u64;
            let mut errs = 0u64;

            loop {
                if Instant::now() >= deadline {
                    break;
                }
                let t0 = Instant::now();
                if stream.write_all(&payload).await.is_err() {
                    errs += 1;
                    break;
                }
                if stream.read_exact(&mut read_buf).await.is_err() {
                    errs += 1;
                    break;
                }
                let us = t0.elapsed().as_micros() as u64;
                let _ = local_hist.record(us);
                ops += 1;
                bytes += (payload_size * 2) as u64;

                if let Some(limit) = rate_limit {
                    let share = (limit / connections as u64).max(1);
                    let elapsed = t0.elapsed().as_secs_f64();
                    let want_interval = (payload_size as f64 * 2.0) / share as f64;
                    if want_interval > elapsed {
                        tokio::time::sleep(Duration::from_secs_f64(want_interval - elapsed)).await;
                    }
                } else if ops.is_multiple_of(4096) {
                    tokio::task::yield_now().await;
                }
            }

            Ok((bytes, ops, errs, local_hist))
        }));
    }

    barrier.wait().await;

    let mut total_bytes = 0u64;
    let mut total_ops = 0u64;
    let mut errors = 0u64;
    let mut merged = new_latency_histogram()?;

    for h in handles {
        match h.await {
            Ok(Ok((b, o, e, part))) => {
                total_bytes += b;
                total_ops += o;
                errors += e;
                merged.add(&part)?;
            }
            Ok(Err(_)) | Err(_) => errors += 1,
        }
    }

    let elapsed = {
        let g = start_at.lock().await;
        g.map(|s| s.elapsed()).unwrap_or(duration)
    };
    let secs = elapsed.as_secs_f64().max(1e-9);

    let throughput_mbps = (total_bytes as f64 * 8.0) / (secs * 1_000_000.0);
    let rps = total_ops as f64 / secs;

    Ok(TrafficResult {
        total_bytes,
        total_ops,
        throughput_mbps,
        rps,
        latency_us: merged,
        errors,
    })
}

#[derive(Debug)]
pub struct UdpTrafficResult {
    pub packets_sent: u64,
    pub packets_ok: u64,
    pub packets_lost: u64,
    pub throughput_mbps: f64,
    pub pps: f64,
    pub latency_us: Histogram<u64>,
    pub loss_rate: f64,
}

/// UDP echo workload: each datagram is prefixed with u64 big-endian sequence (included in echo).
pub async fn generate_udp_traffic(
    target: SocketAddr,
    payload_body: usize,
    duration: Duration,
    pps_target: Option<u64>,
) -> Result<UdpTrafficResult> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(target).await?;

    let mut hist = new_latency_histogram()?;
    let body = payload_body.saturating_sub(8);
    let total_size = 8 + body;

    let deadline = Instant::now() + duration;
    let mut seq: u64 = 0;
    let mut sent = 0u64;
    let mut ok = 0u64;
    let mut buf = vec![0u8; 65535];

    let interval = pps_target.map(|pps| Duration::from_secs_f64(1.0 / pps.max(1) as f64));

    while Instant::now() < deadline {
        seq = seq.wrapping_add(1);
        let t0 = Instant::now();
        buf[..8].copy_from_slice(&seq.to_be_bytes());
        for i in 0..body {
            buf[8 + i] = (i % 256) as u8;
        }
        if sock.send(&buf[..total_size]).await.is_err() {
            break;
        }
        sent += 1;

        match timeout(Duration::from_secs(2), sock.recv(&mut buf)).await {
            Ok(Ok(n)) if n >= 8 => {
                let got = u64::from_be_bytes(buf[..8].try_into().unwrap());
                if got == seq {
                    ok += 1;
                    let _ = hist.record(t0.elapsed().as_micros() as u64);
                }
            }
            _ => {}
        }

        if let Some(iv) = interval {
            tokio::time::sleep(iv).await;
        }
    }

    let lost = sent.saturating_sub(ok);
    let secs = duration.as_secs_f64().max(1e-9);
    let bytes = (total_size as u64).saturating_mul(ok);
    let throughput_mbps = (bytes as f64 * 8.0) / (secs * 1_000_000.0);
    let pps = ok as f64 / secs;
    let loss_rate = if sent > 0 {
        lost as f64 / sent as f64
    } else {
        0.0
    };

    Ok(UdpTrafficResult {
        packets_sent: sent,
        packets_ok: ok,
        packets_lost: lost,
        throughput_mbps,
        pps,
        latency_us: hist,
        loss_rate,
    })
}
