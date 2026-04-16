use crate::registry::ClientRegistry;
use crate::session::{SessionConfig, SessionManager};
use anno_common::{PortMapping, Protocol, TargetAddress};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use tokio::sync::mpsc;

/// Global monotonic connection id for multiplexed sessions.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::SeqCst)
}

/// Application state configuration.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Session management configuration.
    pub session: SessionConfig,
    /// Control channel capacity (frames queued to client).
    pub control_channel_capacity: usize,
    /// Maximum concurrent control connections (0 = unlimited).
    pub max_control_connections: usize,
    /// Optional API bearer token for management API auth (legacy static token).
    pub api_token: Option<String>,
    /// bcrypt hash of the admin password (from .env ADMIN_PASSWORD_HASH).
    pub admin_password_hash: Option<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            session: SessionConfig::default(),
            control_channel_capacity: 1024,
            max_control_connections: 0,
            api_token: None,
            admin_password_hash: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    pub config: AppConfig,
    pub clients: DashMap<u64, ClientRecord>,
    pub name_to_id: DashMap<String, u64>,
    pub port_owner: DashMap<u16, u64>,
    pub listener_by_port: DashMap<u16, tokio::task::JoinHandle<()>>,
    pub next_client_id: AtomicU64,
    /// Unified session manager for TCP/UDP connections.
    pub session_manager: Arc<SessionManager>,
    /// Single active session token (new login replaces old).
    pub current_token: RwLock<Option<String>>,
    /// Client registry for key-based authentication.
    pub registry: ClientRegistry,
}

pub struct ClientRecord {
    pub name: String,
    pub http_proxy_port: Option<u16>,
    pub mappings: Vec<StoredMapping>,
    pub online: Option<OnlineSession>,
}

pub struct OnlineSession {
    pub addr: SocketAddr,
    pub connected_at: SystemTime,
    pub tx: mpsc::Sender<anno_common::Frame>,
}

#[derive(Clone, Debug)]
pub struct StoredMapping {
    pub server_port: u16,
    pub protocol: Protocol,
    pub target: TargetAddress,
}

impl AppState {
    /// Create a new application state with default configuration.
    pub fn new() -> Self {
        Self::with_config(AppConfig::default())
    }

    /// Create a new application state with custom configuration.
    pub fn with_config(config: AppConfig) -> Self {
        Self::with_config_and_registry(config, ClientRegistry::load("clients.json"))
    }

    /// Create a new application state with custom configuration and registry path.
    pub fn with_config_and_registry(config: AppConfig, registry: ClientRegistry) -> Self {
        let session_manager = Arc::new(SessionManager::with_config(config.session.clone()));
        Self {
            inner: Arc::new(AppStateInner {
                config,
                clients: DashMap::new(),
                name_to_id: DashMap::new(),
                port_owner: DashMap::new(),
                listener_by_port: DashMap::new(),
                next_client_id: AtomicU64::new(1),
                session_manager,
                current_token: RwLock::new(None),
                registry,
            }),
        }
    }

    /// Get the application configuration.
    pub fn config(&self) -> &AppConfig {
        &self.inner.config
    }

    /// Allocate a new client ID.
    pub fn alloc_client_id(&self) -> u64 {
        self.inner.next_client_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Get the clients map.
    pub fn clients(&self) -> &DashMap<u64, ClientRecord> {
        &self.inner.clients
    }

    /// Get the name-to-id map.
    pub fn name_to_id(&self) -> &DashMap<String, u64> {
        &self.inner.name_to_id
    }

    /// Get the port owner map.
    pub fn port_owner(&self) -> &DashMap<u16, u64> {
        &self.inner.port_owner
    }

    /// Get the listener handles map.
    pub fn listener_by_port(&self) -> &DashMap<u16, tokio::task::JoinHandle<()>> {
        &self.inner.listener_by_port
    }

    /// Get the session manager.
    pub fn session_manager(&self) -> &Arc<SessionManager> {
        &self.inner.session_manager
    }

    /// Get the control channel capacity.
    pub fn control_channel_capacity(&self) -> usize {
        self.inner.config.control_channel_capacity
    }

    /// Set a new session token, replacing any existing one.
    pub fn set_token(&self, token: String) {
        let mut guard = self.inner.current_token.write().unwrap();
        *guard = Some(token);
    }

    /// Check if the given token matches the current session token.
    pub fn verify_token(&self, token: &str) -> bool {
        let guard = self.inner.current_token.read().unwrap();
        guard.as_deref() == Some(token)
    }

    /// Get the client registry.
    pub fn registry(&self) -> &ClientRegistry {
        &self.inner.registry
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

pub fn stored_to_port_mapping(m: &StoredMapping) -> PortMapping {
    PortMapping {
        server_port: m.server_port,
        protocol: m.protocol,
        target: m.target.clone(),
    }
}
