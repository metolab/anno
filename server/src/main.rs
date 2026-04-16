mod api;
mod control;
mod proxy;
mod registry;
mod session;
mod state;

use crate::registry::ClientRegistry;
use crate::session::{spawn_cleanup_task, SessionConfig};
use crate::state::{AppConfig, AppState};
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "anno-server", about = "NAT traversal server")]
struct Args {
    /// Control plane listen address (clients connect here).
    #[arg(long, default_value = "0.0.0.0:9000")]
    control: SocketAddr,

    /// Management API listen address.
    #[arg(long, default_value = "0.0.0.0:8080")]
    api: SocketAddr,

    /// Bounded channel capacity for tunnel data per session.
    /// When full, excess packets are dropped.
    #[arg(long, default_value_t = 256)]
    tunnel_queue_capacity: usize,

    /// Control channel capacity (frames queued to client).
    #[arg(long, default_value_t = 1024)]
    control_channel_capacity: usize,

    /// UDP session idle timeout in seconds.
    #[arg(long, default_value_t = 300)]
    udp_session_timeout_secs: u64,

    /// Session cleanup interval in seconds.
    #[arg(long, default_value_t = 30)]
    cleanup_interval_secs: u64,

    /// Timeout waiting for ConnReady from client in seconds.
    #[arg(long, default_value_t = 60)]
    conn_ready_timeout_secs: u64,

    /// Maximum concurrent control connections (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    max_control_connections: usize,

    /// Optional API token for management API authentication (empty = no auth).
    #[arg(long, default_value = "")]
    api_token: String,

    /// Path to the client registry JSON file.
    #[arg(long, default_value = "clients.json")]
    registry_file: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Load .env file if present (ignore error if missing)
    let _ = dotenvy::dotenv();

    let args = Args::parse();

    let admin_password_hash = std::env::var("ADMIN_PASSWORD_HASH").ok();
    if admin_password_hash.is_some() {
        tracing::info!("admin password authentication enabled");
    }

    let config = AppConfig {
        session: SessionConfig {
            tunnel_queue_capacity: args.tunnel_queue_capacity,
            udp_session_timeout: Duration::from_secs(args.udp_session_timeout_secs),
            cleanup_interval: Duration::from_secs(args.cleanup_interval_secs),
            conn_ready_timeout: Duration::from_secs(args.conn_ready_timeout_secs),
        },
        control_channel_capacity: args.control_channel_capacity,
        max_control_connections: args.max_control_connections,
        api_token: if args.api_token.is_empty() {
            None
        } else {
            Some(args.api_token)
        },
        admin_password_hash,
    };

    let registry = ClientRegistry::load(&args.registry_file);
    tracing::info!(file = %args.registry_file, count = registry.list().len(), "client registry loaded");

    tracing::info!(
        tunnel_queue_capacity = config.session.tunnel_queue_capacity,
        control_channel_capacity = config.control_channel_capacity,
        udp_session_timeout_secs = args.udp_session_timeout_secs,
        conn_ready_timeout_secs = args.conn_ready_timeout_secs,
        max_control_connections = config.max_control_connections,
        "starting anno-server"
    );

    let state = AppState::with_config_and_registry(config, registry);

    // Start session cleanup task
    let session_manager = Arc::clone(state.session_manager());
    let _cleanup_handle = spawn_cleanup_task(session_manager);
    tracing::info!("session cleanup task started");

    // Install Prometheus metrics recorder
    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    let app = api::router(state.clone(), metrics_handle);
    let listener = tokio::net::TcpListener::bind(args.api)
        .await
        .expect("bind api");
    tracing::info!("management API listening on {}", args.api);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("api server error: {}", e);
        }
    });

    let ctl = TcpListener::bind(args.control).await.expect("bind control");
    tracing::info!("control plane listening on {}", args.control);

    let max_conn = state.config().max_control_connections;
    let active_connections = if max_conn > 0 {
        Some(Arc::new(std::sync::atomic::AtomicUsize::new(0)))
    } else {
        None
    };

    loop {
        let Ok((stream, peer)) = ctl.accept().await else {
            continue;
        };

        if let Some(ref counter) = active_connections {
            let current = counter.load(std::sync::atomic::Ordering::Relaxed);
            if current >= max_conn {
                tracing::warn!(
                    peer = %peer,
                    current,
                    max_conn,
                    "max control connections reached, rejecting"
                );
                continue;
            }
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let counter_c = Arc::clone(counter);
            let st = state.clone();
            tokio::spawn(async move {
                control::handle_control_connection(st, stream, peer).await;
                counter_c.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        } else {
            let st = state.clone();
            tokio::spawn(async move {
                control::handle_control_connection(st, stream, peer).await;
            });
        }
    }
}
