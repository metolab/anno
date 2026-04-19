mod connection;
mod forward;
mod http_proxy;
mod reconnect;

use anno_common::{DEFAULT_INITIAL_WINDOW, DEFAULT_LANES, DEFAULT_MAX_FRAME_SIZE};
use clap::Parser;
use connection::ClientConfig;
use reconnect::{Backoff, SessionError};
use std::time::Duration;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "anno-client", about = "NAT traversal client")]
struct Args {
    /// Server control address (host:port, DNS re-resolved on each reconnect).
    #[arg(long)]
    server: String,

    /// Authentication key for server-side client registry (required).
    #[arg(long)]
    key: String,

    /// Local HTTP proxy port. Omitted or `0` means bind a random
    /// ephemeral port; the actual port is reported to the server in the
    /// `Register` frame so server-side `http_proxy` mappings can forward
    /// to it automatically across restarts. Use `--no-http-proxy` to
    /// disable the proxy entirely.
    #[arg(long)]
    http_proxy: Option<u16>,

    /// Disable the local HTTP proxy (overrides `--http-proxy`). Without
    /// this flag the client binds a random port by default.
    #[arg(long, default_value_t = false)]
    no_http_proxy: bool,

    /// Bounded channel capacity for tunnel data per session.
    #[arg(long, default_value_t = 256)]
    tunnel_queue_capacity: usize,

    /// Control channel capacity (outbound frames).
    #[arg(long, default_value_t = 1024)]
    control_channel_capacity: usize,

    /// Interval (seconds) between client-originated Pings on the control
    /// connection.
    #[arg(long, default_value_t = 15)]
    ping_interval_secs: u64,

    /// Reconnect if no frame is received from the server within this window
    /// (seconds).
    #[arg(long, default_value_t = 45)]
    idle_timeout_secs: u64,

    /// Timeout (seconds) waiting for space in a per-session tunnel mpsc when
    /// forwarding a TCP frame. On timeout the session is torn down.
    #[arg(long, default_value_t = 5)]
    tcp_send_timeout_secs: u64,

    /// Number of physical TCP lanes the client wants for this mux session.
    /// The server may grant fewer. Default matches `anno_common::DEFAULT_LANES`.
    #[arg(long, default_value_t = DEFAULT_LANES)]
    lanes: u8,

    /// Largest single shard the client is willing to send/accept on the
    /// wire. Default matches `anno_common::DEFAULT_MAX_FRAME_SIZE` (16 KiB).
    #[arg(long, default_value_t = DEFAULT_MAX_FRAME_SIZE)]
    max_frame_size: u16,

    /// Initial per-stream credit window (bytes) requested in `Register`.
    /// Default matches `anno_common::DEFAULT_INITIAL_WINDOW`.
    #[arg(long, default_value_t = DEFAULT_INITIAL_WINDOW)]
    initial_window: u32,
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let args = Args::parse();

    // Bind the local HTTP proxy *before* building the client config so the
    // Register frame carries the real bound port. The default is to bind a
    // random ephemeral port (requested = 0) so restarts transparently pick
    // up a new port and server-side `http_proxy` mappings keep working.
    // `--no-http-proxy` opts out entirely.
    let http_proxy_port = if args.no_http_proxy {
        None
    } else {
        let requested = args.http_proxy.unwrap_or(0);
        match http_proxy::bind_http_proxy(requested).await {
            Ok((listener, actual)) => {
                tokio::spawn(async move {
                    if let Err(e) = http_proxy::serve_http_proxy(listener).await {
                        tracing::error!("http proxy exited: {}", e);
                    }
                });
                Some(actual)
            }
            Err(e) => {
                tracing::error!(
                    requested,
                    "failed to bind local HTTP proxy; continuing without it: {}",
                    e
                );
                None
            }
        }
    };

    let config = ClientConfig {
        tunnel_queue_capacity: args.tunnel_queue_capacity,
        control_channel_capacity: args.control_channel_capacity,
        http_proxy_port,
        ping_interval: Duration::from_secs(args.ping_interval_secs),
        idle_timeout: Duration::from_secs(args.idle_timeout_secs),
        tcp_send_timeout: Duration::from_secs(args.tcp_send_timeout_secs),
        requested_lanes: args.lanes,
        max_frame_size: args.max_frame_size,
        initial_window: args.initial_window,
    };

    tracing::info!(
        server = %args.server,
        tunnel_queue_capacity = config.tunnel_queue_capacity,
        control_channel_capacity = config.control_channel_capacity,
        http_proxy_port = ?config.http_proxy_port,
        "starting anno-client"
    );

    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));

    loop {
        tokio::select! {
            result = connection::run_session(&args.server, &args.key, &config) => {
                match result {
                    Ok(()) => {
                        tracing::info!("session ended cleanly, reconnecting");
                        backoff.reset();
                        metrics::counter!("control_reconnects_total").increment(1);
                    }
                    Err(SessionError::AuthFailed) => {
                        tracing::error!("server rejected our key — exiting (check --key)");
                        std::process::exit(2);
                    }
                    Err(SessionError::IdleTimeout) => {
                        tracing::warn!("control connection idle timeout, reconnecting");
                        metrics::counter!("control_idle_timeouts_total").increment(1);
                        metrics::counter!("control_reconnects_total").increment(1);
                    }
                    Err(e) => {
                        tracing::warn!("session error: {}, reconnecting", e);
                        metrics::counter!("control_reconnects_total").increment(1);
                    }
                }
                let delay = backoff.next();
                tracing::info!("reconnecting in {:?}", delay);
                tokio::time::sleep(delay).await;
            }

            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C, shutting down");
                break;
            }
        }
    }
}
