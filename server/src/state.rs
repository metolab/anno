//! Shared application state.
//!
//! After the Phase 5 refactor `AppState` is a thin aggregator that owns:
//!
//! - `config` — startup configuration (immutable at runtime).
//! - `directory` — `ClientRecord` by id/name, allocators,
//!   `client_tx` / `client_tx_and_cancel` helpers.
//! - `listeners` + `listeners_handle` — the public-listener registry and
//!   the serial reconciliation actor that owns it.
//! - `sessions` — unified TCP/UDP tunnel session manager.
//! - `auth` — admin-plane password/session token service.
//! - `registry` — persisted name → key registry.
//! - `client_write_locks` — per-client Mutex to serialise mapping edits.
//! - `login_rate_limiter` — IP+window counter for `/api/login`.
//!
//! Pre-existing public accessors (`clients()`, `set_token()`, etc.) are
//! preserved via delegation so callers don't need to change import paths
//! all at once.

use crate::auth::AuthService;
use crate::directory::ClientDirectory;
use crate::listener::ListenerHandle;
use crate::ratelimit::LoginRateLimiter;
use crate::registry::{ClientRegistry, StoredMappingJson};
use crate::session::{SessionConfig, SessionManager};
use anno_common::{Frame, Host, Protocol, TargetAddress};
use dashmap::DashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, OwnedMutexGuard};
use tokio_util::sync::CancellationToken;

pub use crate::directory::{stored_to_port_mapping, ClientRecord, OnlineSession, StoredMapping};

/// Global monotonic connection id for multiplexed sessions.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::SeqCst)
}

/// Convert a runtime [`StoredMapping`] into its persisted JSON form.
pub fn stored_mapping_to_json(m: &StoredMapping) -> StoredMappingJson {
    let target_host = match &m.target.host {
        Host::V4(ip) => ip.to_string(),
        Host::V6(ip) => ip.to_string(),
        Host::Domain(s) => s.clone(),
    };
    let protocol = match m.protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Both => "both",
        Protocol::HttpProxy => "http_proxy",
    }
    .to_string();
    StoredMappingJson {
        server_port: m.server_port,
        protocol,
        target_host,
        target_port: m.target.port,
    }
}

/// Convert a persisted [`StoredMappingJson`] back to a runtime `StoredMapping`.
/// Returns `None` when the JSON is malformed (unknown protocol, bad host,
/// or zero port); malformed entries are skipped on load rather than
/// aborting startup.
pub fn stored_mapping_from_json(j: &StoredMappingJson) -> Option<StoredMapping> {
    let protocol = match j.protocol.to_ascii_lowercase().as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "both" => Protocol::Both,
        "http_proxy" => Protocol::HttpProxy,
        _ => return None,
    };
    // HttpProxy mappings have no meaningful persisted target — the server
    // substitutes `127.0.0.1:<client.http_proxy_port>` at NewConn time.
    // Allow a sentinel zero target here rather than rejecting the entry.
    if protocol != Protocol::HttpProxy && j.target_port == 0 {
        return None;
    }
    let host = if protocol == Protocol::HttpProxy {
        Host::V4(std::net::Ipv4Addr::LOCALHOST)
    } else if let Ok(ip) = std::net::Ipv4Addr::from_str(&j.target_host) {
        Host::V4(ip)
    } else if let Ok(ip) = std::net::Ipv6Addr::from_str(&j.target_host) {
        Host::V6(ip)
    } else if !j.target_host.is_empty() && j.target_host.len() <= 255 {
        Host::Domain(j.target_host.clone())
    } else {
        return None;
    };
    Some(StoredMapping {
        server_port: j.server_port,
        protocol,
        target: TargetAddress {
            host,
            port: j.target_port,
        },
    })
}

/// Startup configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub session: SessionConfig,
    pub control_channel_capacity: usize,
    pub max_control_connections: usize,
    /// bcrypt hash of the admin password (from `ADMIN_PASSWORD_HASH`).
    pub admin_password_hash: Option<String>,
    /// Maximum sessions per client (0 = unlimited).
    pub max_sessions_per_client: usize,
    /// Optional Bearer token gating `/metrics` on the main API listener.
    pub metrics_token: Option<String>,
    /// How often the server sends Ping on control connections.
    pub control_ping_interval: Duration,
    /// Drop a control connection if no frame is received within this window.
    pub control_idle_timeout: Duration,
    /// Maximum time allowed between accept and the first `Register` frame.
    /// Short-circuits a trivial slow-client DoS against the control plane.
    pub register_timeout: Duration,
    /// Public listener bind address (shared by all port mappings).
    pub public_bind: IpAddr,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            control_channel_capacity: 1024,
            max_control_connections: 0,
            admin_password_hash: None,
            max_sessions_per_client: 0,
            metrics_token: None,
            control_ping_interval: Duration::from_secs(20),
            control_idle_timeout: Duration::from_secs(60),
            register_timeout: Duration::from_secs(10),
            public_bind: IpAddr::from_str("0.0.0.0").unwrap(),
        }
    }
}

/// Entry in the public-listener registry. `Binding` is a short-lived
/// reservation inserted by the listener actor before the async bind
/// completes; `Active` carries the `JoinHandle` of the long-running
/// accept/recv_from task.
pub enum ListenerRecord {
    Binding {
        client_id: u64,
    },
    Active {
        client_id: u64,
        handle: tokio::task::JoinHandle<()>,
    },
}

impl ListenerRecord {
    pub fn client_id(&self) -> u64 {
        match self {
            Self::Binding { client_id } | Self::Active { client_id, .. } => *client_id,
        }
    }
}

impl Drop for ListenerRecord {
    fn drop(&mut self) {
        if let Self::Active { handle, .. } = self {
            handle.abort();
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: AppConfig,
    directory: ClientDirectory,
    listeners: DashMap<u16, ListenerRecord>,
    listeners_handle: ListenerHandle,
    session_manager: Arc<SessionManager>,
    auth: AuthService,
    registry: ClientRegistry,
    client_write_locks: DashMap<u64, Arc<Mutex<()>>>,
    /// Per-client-name mutex: acquired by both the control-plane register
    /// handshake and by `registry_delete` so those two flows are serialised
    /// on the same `name`. Prevents the race where a client finishes its
    /// registration (inserting a `ClientRecord`) just after `registry_delete`
    /// has already deleted its registry entry, which would strand the
    /// runtime record with no way for the admin to authenticate it later.
    register_locks: DashMap<String, Arc<Mutex<()>>>,
    login_rate_limiter: LoginRateLimiter,
}

impl AppState {
    pub fn with_config_and_registry(
        config: AppConfig,
        registry: ClientRegistry,
        listeners_handle: ListenerHandle,
    ) -> Self {
        let session_manager = Arc::new(SessionManager::with_config(config.session.clone()));
        let auth = AuthService::new(config.admin_password_hash.clone());
        Self {
            inner: Arc::new(AppStateInner {
                config,
                directory: ClientDirectory::new(),
                listeners: DashMap::new(),
                listeners_handle,
                session_manager,
                auth,
                registry,
                client_write_locks: DashMap::new(),
                register_locks: DashMap::new(),
                login_rate_limiter: LoginRateLimiter::new(),
            }),
        }
    }

    // ------------------------------------------------------------------
    // Direct sub-service accessors
    // ------------------------------------------------------------------

    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    #[allow(dead_code)]
    pub fn directory(&self) -> &ClientDirectory {
        &self.inner.directory
    }

    pub fn auth(&self) -> &AuthService {
        &self.inner.auth
    }

    pub fn listeners(&self) -> &DashMap<u16, ListenerRecord> {
        &self.inner.listeners
    }

    pub fn listeners_handle(&self) -> &ListenerHandle {
        &self.inner.listeners_handle
    }

    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.inner.session_manager
    }

    pub fn registry(&self) -> &ClientRegistry {
        &self.inner.registry
    }

    pub fn login_rate_limiter(&self) -> &LoginRateLimiter {
        &self.inner.login_rate_limiter
    }

    pub fn control_channel_capacity(&self) -> usize {
        self.inner.config.control_channel_capacity
    }

    /// Per-client write lock: serialises mutations of `ClientRecord.mappings`
    /// and the subsequent listener reconciliation.
    pub async fn lock_client(&self, client_id: u64) -> OwnedMutexGuard<()> {
        let mutex = self
            .inner
            .client_write_locks
            .entry(client_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        mutex.lock_owned().await
    }

    /// Per-client-name mutex guarding the "register vs delete" race between
    /// `control::handle_control_connection` and `api::registry_delete`.
    pub async fn lock_register_name(&self, name: &str) -> OwnedMutexGuard<()> {
        let mutex = self
            .inner
            .register_locks
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        mutex.lock_owned().await
    }

    // ------------------------------------------------------------------
    // Directory delegations (kept for source-compatibility)
    // ------------------------------------------------------------------

    pub fn clients(&self) -> &DashMap<u64, ClientRecord> {
        self.inner.directory.clients()
    }

    pub fn name_to_id(&self) -> &DashMap<String, u64> {
        self.inner.directory.name_to_id()
    }

    pub fn alloc_client_id(&self) -> u64 {
        self.inner.directory.alloc_client_id()
    }

    pub fn alloc_session_token(&self) -> u64 {
        self.inner.directory.alloc_session_token()
    }

    pub fn replace_online(&self, client_id: u64, online: OnlineSession) -> Option<OnlineSession> {
        self.inner.directory.replace_online(client_id, online)
    }

    pub fn clear_online_if_owner(&self, client_id: u64, expected_token: u64) -> bool {
        self.inner
            .directory
            .clear_online_if_owner(client_id, expected_token)
    }

    pub fn client_tx(&self, client_id: u64) -> Option<mpsc::Sender<Frame>> {
        self.inner.directory.client_tx(client_id)
    }

    pub fn client_tx_and_cancel(
        &self,
        client_id: u64,
    ) -> Option<(mpsc::Sender<Frame>, CancellationToken)> {
        self.inner.directory.client_tx_and_cancel(client_id)
    }

    // ------------------------------------------------------------------
    // Auth delegations
    // ------------------------------------------------------------------

    pub fn set_token(&self, token: String) {
        self.inner.auth.set_token(token)
    }

    pub fn verify_token(&self, token: &str) -> bool {
        self.inner.auth.verify_token(token)
    }
}
