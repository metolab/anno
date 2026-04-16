mod api_client;
mod echo_server;
mod harness;
mod metrics;
mod tests;
mod traffic_gen;

use anyhow::Result;
use clap::{Parser, Subcommand};
use harness::{HarnessArgs, TestHarness};
use std::path::PathBuf;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "anno-bench", about = "End-to-end NAT traversal benchmarks")]
struct Cli {
    /// Path to anno-server binary
    #[arg(long)]
    server_bin: Option<PathBuf>,

    /// Path to anno-client binary
    #[arg(long)]
    client_bin: Option<PathBuf>,

    /// Control plane address (must match server --control)
    #[arg(long, default_value = "127.0.0.1:19100")]
    control: String,

    /// Management API address (must match server --api)
    #[arg(long, default_value = "127.0.0.1:18080")]
    api: String,

    /// TCP echo bind address (backend target)
    #[arg(long, default_value = "127.0.0.1:17777")]
    echo_tcp: String,

    /// UDP echo bind address (backend target)
    #[arg(long, default_value = "127.0.0.1:17778")]
    echo_udp: String,

    /// anno-client registration name
    #[arg(long, default_value = "anno-bench-client")]
    client_name: String,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutFmt::Text)]
    output: OutFmt,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum OutFmt {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run all benchmark scenarios
    All {
        #[arg(long, default_value_t = 8)]
        tcp_duration: u64,
        #[arg(long, default_value = "1,10")]
        tcp_connections: String,
        #[arg(long, default_value = "64,1024,4096")]
        tcp_payloads: String,
        #[arg(long, default_value_t = 8)]
        udp_duration: u64,
        #[arg(long, default_value = "64,1024")]
        udp_packets: String,
        #[arg(long, default_value_t = 3000)]
        latency_samples: u64,
        #[arg(long, default_value_t = 256)]
        latency_payload: usize,
        #[arg(long, default_value_t = 200)]
        concurrent_max: usize,
        #[arg(long, default_value_t = 45)]
        memory_duration: u64,
        #[arg(long, default_value_t = 1)]
        memory_sample_interval_secs: u64,
    },
    /// TCP throughput (echo workload)
    Tcp {
        #[arg(long, default_value_t = 12)]
        duration: u64,
        #[arg(long, default_value = "1,5,10")]
        connections: String,
        #[arg(long, default_value = "64,1024,4096")]
        payload_sizes: String,
        /// Cap aggregate throughput near this bitrate (decimal Mbit/s), e.g. 100 for ~100 Mbps.
        #[arg(long)]
        target_mbps: Option<f64>,
        /// Record RSS timeline + CPU jiffies for each matrix case (on by default if --target-mbps is set).
        #[arg(long, default_value_t = false)]
        resources: bool,
        /// Seconds between RSS samples while load runs (0 = pick 2 when resources enabled).
        #[arg(long, default_value_t = 0)]
        resource_sample_interval_secs: u64,
    },
    /// UDP throughput (echo workload)
    Udp {
        #[arg(long, default_value_t = 30)]
        duration: u64,
        #[arg(long, default_value = "64,1024")]
        packet_size: String,
        #[arg(long)]
        pps: Option<u64>,
    },
    /// End-to-end RTT (TCP echo)
    Latency {
        #[arg(long, default_value_t = 10_000)]
        samples: u64,
        #[arg(long, default_value_t = 256)]
        payload: usize,
    },
    /// Concurrent TCP connections
    Concurrent {
        #[arg(long, default_value_t = 500)]
        max_connections: usize,
        #[arg(long, default_value_t = 1024)]
        payload: usize,
        #[arg(long, default_value_t = 5)]
        dial_timeout_secs: u64,
    },
    /// Memory sampling under light churn
    Memory {
        #[arg(long, default_value_t = 300)]
        duration: u64,
        #[arg(long, default_value_t = 1)]
        sample_interval_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let mut args = HarnessArgs::default();
    if let Some(p) = cli.server_bin {
        args.server_bin = p;
    }
    if let Some(p) = cli.client_bin {
        args.client_bin = p;
    }
    args.control = cli.control;
    args.api = cli.api;
    args.echo_tcp = cli.echo_tcp;
    args.echo_udp = cli.echo_udp;
    args.client_name = cli.client_name;

    let harness = TestHarness::setup(&args).await?;
    let out = match cli.command {
        Commands::All {
            tcp_duration,
            tcp_connections,
            tcp_payloads,
            udp_duration,
            udp_packets,
            latency_samples,
            latency_payload,
            concurrent_max,
            memory_duration,
            memory_sample_interval_secs,
        } => {
            let conns = parse_usize_list(&tcp_connections)?;
            let tcp_ps = parse_usize_list(&tcp_payloads)?;
            let udp_ps = parse_usize_list(&udp_packets)?;

            serde_json::json!({
                "tcp_throughput_suite": tests::tcp_throughput::run(
                    &harness,
                    Duration::from_secs(tcp_duration),
                    &conns,
                    &tcp_ps,
                ).await?,
                "udp_throughput_suite": tests::udp_throughput::run(
                    &harness,
                    Duration::from_secs(udp_duration),
                    &udp_ps,
                    None,
                ).await?,
                "latency": tests::latency::run(&harness, latency_samples, latency_payload).await?,
                "concurrent": tests::concurrent::run(
                    &harness,
                    concurrent_max,
                    1024,
                    Duration::from_secs(5),
                ).await?,
                "memory": tests::memory::run(
                    &harness,
                    Duration::from_secs(memory_duration),
                    Duration::from_secs(memory_sample_interval_secs.max(1)),
                ).await?,
            })
        }
        Commands::Tcp {
            duration,
            connections,
            payload_sizes,
            target_mbps,
            resources,
            resource_sample_interval_secs,
        } => {
            let conns = parse_usize_list(&connections)?;
            let ps = parse_usize_list(&payload_sizes)?;
            let collect = resources || target_mbps.is_some();
            let mut iv_secs = resource_sample_interval_secs;
            if collect && iv_secs == 0 {
                iv_secs = 2;
            }
            let opts = tests::tcp_throughput::TcpThroughputOpts {
                target_mbps,
                collect_resources: collect,
                resource_sample_interval: Duration::from_secs(iv_secs),
            };
            tests::tcp_throughput::run_with_opts(
                &harness,
                Duration::from_secs(duration),
                &conns,
                &ps,
                &opts,
            )
            .await?
        }
        Commands::Udp {
            duration,
            packet_size,
            pps,
        } => {
            let ps = parse_usize_list(&packet_size)?;
            tests::udp_throughput::run(&harness, Duration::from_secs(duration), &ps, pps).await?
        }
        Commands::Latency { samples, payload } => {
            tests::latency::run(&harness, samples, payload).await?
        }
        Commands::Concurrent {
            max_connections,
            payload,
            dial_timeout_secs,
        } => {
            tests::concurrent::run(
                &harness,
                max_connections,
                payload,
                Duration::from_secs(dial_timeout_secs),
            )
            .await?
        }
        Commands::Memory {
            duration,
            sample_interval_secs,
        } => {
            tests::memory::run(
                &harness,
                Duration::from_secs(duration),
                Duration::from_secs(sample_interval_secs),
            )
            .await?
        }
    };

    harness.teardown();

    match cli.output {
        OutFmt::Json => {
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        OutFmt::Text => {
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
    }

    Ok(())
}

fn parse_usize_list(s: &str) -> Result<Vec<usize>> {
    s.split(',')
        .map(|x| x.trim().parse::<usize>().map_err(|e| anyhow::anyhow!(e)))
        .collect()
}
