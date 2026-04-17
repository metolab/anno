mod api;
mod auth;
mod control;
mod directory;
mod frontend;
mod listener;
mod proxy;
mod ratelimit;
mod registry;
mod session;
mod state;

use crate::listener::{make_handle, spawn_listener_actor};
use crate::registry::ClientRegistry;
use crate::session::{spawn_cleanup_task, SessionConfig};
use crate::state::{stored_mapping_from_json, AppConfig, AppState, ClientRecord};
use clap::Parser;
use metrics_exporter_prometheus::PrometheusBuilder;
use socket2::{SockRef, TcpKeepalive};
use std::net::{IpAddr, SocketAddr};
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

    /// Dedicated Prometheus /metrics listen address. When set, /metrics is
    /// served only on this listener (typically a loopback address) and is
    /// *removed* from the main API router, eliminating the risk of public
    /// metrics exposure. When unset, /metrics stays on the main API but is
    /// gated by `METRICS_TOKEN` if that env is set.
    #[arg(long)]
    metrics_listen: Option<SocketAddr>,

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

    /// Maximum concurrent tunnel sessions per client (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    max_sessions_per_client: usize,

    /// Path to the client registry JSON file.
    #[arg(long, default_value = "clients.json")]
    registry_file: String,

    /// Public bind address used by every port mapping's TCP/UDP listener.
    /// Defaults to 0.0.0.0; set to a specific interface to limit exposure.
    #[arg(long, default_value = "0.0.0.0")]
    public_bind: IpAddr,

    /// Interval (seconds) between server-originated Pings on an idle
    /// control connection.
    #[arg(long, default_value_t = 20)]
    control_ping_interval_secs: u64,

    /// Drop a control connection if no frame is received within this window
    /// (seconds).
    #[arg(long, default_value_t = 60)]
    control_idle_timeout_secs: u64,

    /// Maximum time (seconds) allowed between accept and the client's first
    /// Register frame. Short values protect the control plane from slow-
    /// loris-style DoS.
    #[arg(long, default_value_t = 10)]
    register_timeout_secs: u64,

    /// Timeout (seconds) the server waits when enqueueing an outgoing TCP
    /// frame to a session mpsc. Slow consumers are forcefully closed.
    #[arg(long, default_value_t = 5)]
    tcp_send_timeout_secs: u64,
}

/// Materialise one offline [`ClientRecord`] per registry entry so the
/// management UI can show persisted mappings before the client reconnects,
/// and so the first reconnect does not need to re-read mappings from disk.
/// Listeners are *not* started here: the listener actor only binds ports
/// for clients whose `online` field is set, and `sync_client` is invoked
/// lazily from `control::handle_control_connection`.
fn preload_registry_records(state: &AppState) {
    let entries = state.registry().list();
    for entry in entries {
        let mappings = state
            .registry()
            .get_mappings(&entry.name)
            .iter()
            .filter_map(stored_mapping_from_json)
            .collect();

        let id = state.alloc_client_id();
        state.name_to_id().insert(entry.name.clone(), id);
        state.clients().insert(
            id,
            ClientRecord {
                name: entry.name,
                http_proxy_port: None,
                mappings,
                online: None,
            },
        );
    }
    tracing::info!(
        preloaded = state.clients().len(),
        "preloaded client records from registry"
    );
}

/// RAII guard that decrements an atomic counter on drop.
struct ConnectionCounterGuard {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for ConnectionCounterGuard {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[tokio::main]
async fn main() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    let _ = dotenvy::dotenv();

    let args = Args::parse();

    let admin_password_hash = std::env::var("ADMIN_PASSWORD_HASH").ok();
    if admin_password_hash.is_some() {
        tracing::info!("admin password authentication enabled");
    }

    let metrics_token = std::env::var("METRICS_TOKEN").ok().filter(|s| !s.is_empty());
    if metrics_token.is_some() && args.metrics_listen.is_none() {
        tracing::info!("METRICS_TOKEN set — /metrics on main API requires Bearer auth");
    }

    let config = AppConfig {
        session: SessionConfig {
            tunnel_queue_capacity: args.tunnel_queue_capacity,
            udp_session_timeout: Duration::from_secs(args.udp_session_timeout_secs),
            cleanup_interval: Duration::from_secs(args.cleanup_interval_secs),
            conn_ready_timeout: Duration::from_secs(args.conn_ready_timeout_secs),
            tcp_send_timeout: Duration::from_secs(args.tcp_send_timeout_secs),
        },
        control_channel_capacity: args.control_channel_capacity,
        max_control_connections: args.max_control_connections,
        admin_password_hash,
        max_sessions_per_client: args.max_sessions_per_client,
        metrics_token: metrics_token.clone(),
        control_ping_interval: Duration::from_secs(args.control_ping_interval_secs),
        control_idle_timeout: Duration::from_secs(args.control_idle_timeout_secs),
        register_timeout: Duration::from_secs(args.register_timeout_secs),
        public_bind: args.public_bind,
        control_addr: args.control,
    };

    let registry = ClientRegistry::load(&args.registry_file);
    tracing::info!(
        file = %args.registry_file,
        count = registry.list().len(),
        "client registry loaded"
    );
    let _persistor_handle = registry.start_persistor();

    tracing::info!(
        tunnel_queue_capacity = config.session.tunnel_queue_capacity,
        control_channel_capacity = config.control_channel_capacity,
        udp_session_timeout_secs = args.udp_session_timeout_secs,
        conn_ready_timeout_secs = args.conn_ready_timeout_secs,
        max_control_connections = config.max_control_connections,
        max_sessions_per_client = config.max_sessions_per_client,
        metrics_listen = ?args.metrics_listen,
        "starting anno-server"
    );

    // Construct the listener handle before the state so state can hold it.
    // The actor itself is spawned after state is built, since it needs a
    // state clone to look up mappings during reconciliation.
    let (listener_handle, listener_rx) = make_handle();

    let state = AppState::with_config_and_registry(config, registry, listener_handle);

    preload_registry_records(&state);

    let _listener_actor = spawn_listener_actor(state.clone(), listener_rx);
    tracing::info!("listener reconciliation actor started");

    let session_manager = Arc::clone(state.session_manager());
    let _cleanup_handle = spawn_cleanup_task(session_manager);
    tracing::info!("session cleanup task started");

    let metrics_handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("failed to install Prometheus recorder");

    let expose_metrics_on_main = args.metrics_listen.is_none();

    let app = api::router(state.clone(), metrics_handle.clone(), expose_metrics_on_main);
    let listener = tokio::net::TcpListener::bind(args.api)
        .await
        .expect("bind api");
    tracing::info!("management API listening on {}", args.api);
    tokio::spawn(async move {
        if let Err(e) =
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
        {
            tracing::error!("api server error: {}", e);
        }
    });

    // Dedicated /metrics listener.
    if let Some(addr) = args.metrics_listen {
        let router = api::metrics_only_router(metrics_handle);
        let bind = tokio::net::TcpListener::bind(addr).await.expect("bind metrics");
        tracing::info!("metrics listening on {}", addr);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(bind, router).await {
                tracing::error!("metrics server error: {}", e);
            }
        });
    }

    let ctl = TcpListener::bind(args.control).await.expect("bind control");
    tracing::info!("control plane listening on {}", args.control);

    let max_conn = state.config().max_control_connections;
    let active_connections = if max_conn > 0 {
        Some(Arc::new(std::sync::atomic::AtomicUsize::new(0)))
    } else {
        None
    };

    let mut accept_backoff_ms: u64 = 1;

    #[cfg(unix)]
    let mut sigterm = {
        use tokio::signal::unix::{signal, SignalKind};
        signal(SignalKind::terminate()).expect("failed to install SIGTERM handler")
    };

    loop {
        #[cfg(unix)]
        let accept_result = tokio::select! {
            r = ctl.accept() => r,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C, shutting down control plane");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, shutting down control plane");
                break;
            }
        };
        #[cfg(not(unix))]
        let accept_result = tokio::select! {
            r = ctl.accept() => r,
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C, shutting down control plane");
                break;
            }
        };

        let (stream, peer) = match accept_result {
            Ok(pair) => {
                accept_backoff_ms = 1;
                pair
            }
            Err(e) => {
                tracing::error!("control accept error: {e}");
                tokio::time::sleep(Duration::from_millis(accept_backoff_ms)).await;
                accept_backoff_ms = (accept_backoff_ms * 2).min(1000);
                continue;
            }
        };

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(peer = %peer, "accepted socket set_nodelay failed: {e}");
        }
        {
            let ka = TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10))
                .with_retries(3);
            if let Err(e) = SockRef::from(&stream).set_tcp_keepalive(&ka) {
                tracing::warn!(peer = %peer, "set_tcp_keepalive failed: {e}");
            }
        }

        if let Some(ref counter) = active_connections {
            // Atomic compare-and-increment so two concurrent accepts can't
            // both pass a load-then-add check and blow past `max_conn`.
            let reservation = counter.fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |current| {
                    if current >= max_conn {
                        None
                    } else {
                        Some(current + 1)
                    }
                },
            );
            if reservation.is_err() {
                let current = counter.load(std::sync::atomic::Ordering::Relaxed);
                tracing::warn!(
                    peer = %peer,
                    current,
                    max_conn,
                    "max control connections reached, rejecting"
                );
                let _ = {
                    use anno_common::{Fault, FrameCodec, Message};
                    use futures::SinkExt;
                    use tokio_util::codec::FramedWrite;
                    let frame = Fault::new(
                        anno_common::ErrorCode::PortUnavailable,
                        "server busy: max connections reached",
                    )
                    .to_frame(0);
                    let (_, wh) = stream.into_split();
                    let mut fw = FramedWrite::new(wh, FrameCodec);
                    fw.send(frame).await
                };
                continue;
            }
            let guard = ConnectionCounterGuard {
                counter: Arc::clone(counter),
            };
            let st = state.clone();
            tokio::spawn(async move {
                control::handle_control_connection(st, stream, peer).await;
                drop(guard);
            });
        } else {
            let st = state.clone();
            tokio::spawn(async move {
                control::handle_control_connection(st, stream, peer).await;
            });
        }
    }

    tracing::info!("stopping public listeners...");
    state.listeners_handle().stop_all().await;
    tracing::info!("flushing registry...");
    state.registry().flush_sync();
    tracing::info!("anno-server shut down cleanly");
}
