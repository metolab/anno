//! Client directory: the "who is registered, who is online, how do I reach
//! them" subset of shared state. Extracted from the original monolithic
//! `AppState` so that each concern has its own home:
//!
//! - ID + session-token allocation.
//! - Mapping between stable `name → client_id` and the full `ClientRecord`
//!   (including its `OnlineSession` when present).
//! - Helpers that used to be duplicated all over the server
//!   (`client_tx` / `client_tx_and_cancel`) encapsulating the
//!   "don't hold a DashMap Ref across `.await`" contract in exactly one
//!   place.

use anno_common::{Frame, PortMapping, Protocol, TargetAddress};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// One registered client, whether currently connected or not.
pub struct ClientRecord {
    pub name: String,
    pub http_proxy_port: Option<u16>,
    pub mappings: Vec<StoredMapping>,
    /// `Some` iff a control connection is currently registered.
    pub online: Option<OnlineSession>,
}

/// Runtime info attached to a currently-connected client.
pub struct OnlineSession {
    pub addr: SocketAddr,
    pub connected_at: SystemTime,
    /// Bounded sender into the control connection's writer task.
    pub tx: mpsc::Sender<Frame>,
    /// Unique token binding this `OnlineSession` to one specific control
    /// connection task. Used to prevent a dying old connection from
    /// cleaning up a freshly registered new one.
    pub session_token: u64,
    /// Explicit cancellation signal. Cancelling it tears down the control
    /// loop and every per-session task spawned for this client —
    /// replacing the old "drop the Sender → rx.recv returns None → tasks
    /// unwind" implicit chain.
    pub cancel: CancellationToken,
}

/// A port-forwarding rule owned by a client.
#[derive(Clone, Debug)]
pub struct StoredMapping {
    pub server_port: u16,
    pub protocol: Protocol,
    pub target: TargetAddress,
}

pub fn stored_to_port_mapping(m: &StoredMapping) -> PortMapping {
    PortMapping {
        server_port: m.server_port,
        protocol: m.protocol,
        target: m.target.clone(),
    }
}

/// Client directory — holds `ClientRecord`s indexed by id and by name,
/// plus the monotonic allocators for `client_id` and `session_token`.
pub struct ClientDirectory {
    clients: DashMap<u64, ClientRecord>,
    name_to_id: DashMap<String, u64>,
    next_client_id: AtomicU64,
    next_session_token: AtomicU64,
}

impl ClientDirectory {
    pub fn new() -> Self {
        Self {
            clients: DashMap::new(),
            name_to_id: DashMap::new(),
            next_client_id: AtomicU64::new(1),
            next_session_token: AtomicU64::new(1),
        }
    }

    pub fn clients(&self) -> &DashMap<u64, ClientRecord> {
        &self.clients
    }

    pub fn name_to_id(&self) -> &DashMap<String, u64> {
        &self.name_to_id
    }

    pub fn alloc_client_id(&self) -> u64 {
        self.next_client_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn alloc_session_token(&self) -> u64 {
        self.next_session_token.fetch_add(1, Ordering::SeqCst)
    }

    /// Atomically replace the online session for `client_id`. Returns the
    /// previous online entry (if any), so the caller can cancel it.
    pub fn replace_online(
        &self,
        client_id: u64,
        new_online: OnlineSession,
    ) -> Option<OnlineSession> {
        self.clients
            .get_mut(&client_id)
            .and_then(|mut rec| rec.online.replace(new_online))
    }

    /// Clear the online entry only if the stored `session_token` matches
    /// `expected_token`. Returns `true` if the clear happened. The old
    /// `OnlineSession` is dropped, and its `cancel` token is triggered
    /// so any tasks holding clones stop immediately.
    pub fn clear_online_if_owner(&self, client_id: u64, expected_token: u64) -> bool {
        if let Some(mut rec) = self.clients.get_mut(&client_id) {
            if rec.online.as_ref().map(|o| o.session_token) == Some(expected_token) {
                if let Some(old) = rec.online.take() {
                    old.cancel.cancel();
                }
                return true;
            }
        }
        false
    }

    /// Clone the control-channel sender for a connected client, if any.
    /// Encapsulates the "don't hold a DashMap Ref across `.await`" rule.
    pub fn client_tx(&self, client_id: u64) -> Option<mpsc::Sender<Frame>> {
        self.clients
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| o.tx.clone()))
    }

    /// Clone both the control-channel sender and the cancellation token
    /// for a connected client.
    pub fn client_tx_and_cancel(
        &self,
        client_id: u64,
    ) -> Option<(mpsc::Sender<Frame>, CancellationToken)> {
        self.clients
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| (o.tx.clone(), o.cancel.clone())))
    }
}

impl Default for ClientDirectory {
    fn default() -> Self {
        Self::new()
    }
}
