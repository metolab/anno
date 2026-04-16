mod connection;
mod forward;
mod http_proxy;

use clap::Parser;
use connection::ClientConfig;
use std::net::SocketAddr;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "anno-client", about = "NAT traversal client")]
struct Args {
    /// Server control address.
    #[arg(long)]
    server: SocketAddr,

    /// Client name (stable mapping on server).
    #[arg(long)]
    name: String,

    /// Authentication key for server-side client registry (required).
    #[arg(long)]
    key: String,

    /// Optional local HTTP proxy port.
    #[arg(long)]
    http_proxy: Option<u16>,

    /// Bounded channel capacity for tunnel data per session.
    #[arg(long, default_value_t = 256)]
    tunnel_queue_capacity: usize,

    /// Control channel capacity (outbound frames).
    #[arg(long, default_value_t = 1024)]
    control_channel_capacity: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let config = ClientConfig {
        tunnel_queue_capacity: args.tunnel_queue_capacity,
        control_channel_capacity: args.control_channel_capacity,
    };

    tracing::info!(
        server = %args.server,
        name = %args.name,
        tunnel_queue_capacity = config.tunnel_queue_capacity,
        control_channel_capacity = config.control_channel_capacity,
        "starting anno-client"
    );

    if let Some(p) = args.http_proxy {
        tokio::spawn(async move {
            if let Err(e) = http_proxy::run_http_proxy(p).await {
                tracing::error!("http proxy exited: {}", e);
            }
        });
    }

    if let Err(e) = connection::run_client_with_config(
        args.server,
        args.name,
        Some(args.key),
        args.http_proxy,
        config,
    )
    .await
    {
        tracing::error!("client exited: {}", e);
        std::process::exit(1);
    }
}
