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

use anno_common::mux::{CreditMap, MuxSender, Reassembler};
use anno_common::{PortMapping, Protocol, TargetAddress};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::SystemTime;
use tokio_util::sync::CancellationToken;

/// One registered client, whether currently connected or not.
pub struct ClientRecord {
    pub name: String,
    pub http_proxy_port: Option<u16>,
    pub mappings: Vec<StoredMapping>,
    /// `Some` iff a control connection is currently registered.
    pub online: Option<OnlineSession>,
}

/// Negotiated mux parameters for a live session.
#[derive(Debug, Clone, Copy)]
pub struct SessionMuxParams {
    pub lanes: u8,
    pub max_frame_size: u16,
    pub initial_window: u32,
}

impl Default for SessionMuxParams {
    fn default() -> Self {
        Self {
            lanes: 1,
            max_frame_size: anno_common::DEFAULT_MAX_FRAME_SIZE,
            initial_window: anno_common::DEFAULT_INITIAL_WINDOW,
        }
    }
}

/// Runtime info attached to a currently-connected client.
pub struct OnlineSession {
    pub addr: SocketAddr,
    pub connected_at: SystemTime,
    /// Multi-lane sender that fans frames out across the per-lane
    /// writer tasks. Cheaply cloneable; routes by `conn_id` for data
    /// frames and to lane 0 for control frames.
    pub tx: MuxSender,
    /// Unique token binding this `OnlineSession` to one specific control
    /// connection task. Used to prevent a dying old connection from
    /// cleaning up a freshly registered new one.
    pub session_token: u64,
    /// Explicit cancellation signal. Cancelling it tears down the control
    /// loop and every per-session task spawned for this client —
    /// replacing the old "drop the Sender → rx.recv returns None → tasks
    /// unwind" implicit chain.
    pub cancel: CancellationToken,
    /// Negotiated mux parameters (lanes, frame size, window).
    pub mux: SessionMuxParams,
    /// Per-stream reassembly buffer for `MORE`-fragmented `DataTcp`
    /// frames. Shared between the control reader task (which feeds it)
    /// and the periodic sweeper. Stored here so accessors like
    /// `client_reassembler` can hand it out, even though the live task
    /// usually keeps its own clone for fast access.
    #[allow(dead_code)]
    pub reassembler: Arc<StdMutex<Reassembler>>,
    /// Per-stream send/recv credit windows. Sized at the negotiated
    /// `initial_window`; entries are created lazily on first DataTcp
    /// frame and dropped on `ConnClose`.
    pub credit: Arc<CreditMap>,
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
    /// previous online entry (if any) **after** explicitly tearing it
    /// down: cancel token fires, every per-stream credit semaphore is
    /// closed (waking any sender parked on `acquire_send`) and the
    /// per-stream reassembly buffers are dropped. Without this active
    /// teardown, tasks that still held an `Arc<StreamCredit>` clone
    /// could remain parked indefinitely after the session was replaced.
    pub fn replace_online(
        &self,
        client_id: u64,
        new_online: OnlineSession,
    ) -> Option<OnlineSession> {
        let old = self
            .clients
            .get_mut(&client_id)
            .and_then(|mut rec| rec.online.replace(new_online))?;
        teardown_online(&old);
        Some(old)
    }

    /// Clear the online entry only if the stored `session_token` matches
    /// `expected_token`. Returns `true` if the clear happened. The old
    /// `OnlineSession`'s `cancel` token is triggered, every per-stream
    /// credit semaphore is closed and the reassembler is drained so
    /// any task holding clones unparks immediately and any pinned
    /// memory is released.
    pub fn clear_online_if_owner(&self, client_id: u64, expected_token: u64) -> bool {
        let old = {
            let Some(mut rec) = self.clients.get_mut(&client_id) else {
                return false;
            };
            if rec.online.as_ref().map(|o| o.session_token) != Some(expected_token) {
                return false;
            }
            rec.online.take()
        };
        if let Some(old) = old {
            teardown_online(&old);
        }
        true
    }

    /// Clone the multi-lane sender for a connected client, if any.
    /// Encapsulates the "don't hold a DashMap Ref across `.await`" rule.
    pub fn client_tx(&self, client_id: u64) -> Option<MuxSender> {
        self.clients
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| o.tx.clone()))
    }

    /// Clone both the multi-lane sender and the cancellation token
    /// for a connected client.
    pub fn client_tx_and_cancel(
        &self,
        client_id: u64,
    ) -> Option<(MuxSender, CancellationToken)> {
        self.clients
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| (o.tx.clone(), o.cancel.clone())))
    }

    /// Cheap clone of the per-client reassembler handle. Returns `None`
    /// when the client is offline. Currently used by the control task
    /// directly via the locally-owned `Arc`; this accessor is kept so
    /// later modules (admin disconnect, GoAway path) can fetch the same
    /// state without reaching into `directory` internals.
    #[allow(dead_code)]
    pub fn client_reassembler(&self, client_id: u64) -> Option<Arc<StdMutex<Reassembler>>> {
        self.clients
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| Arc::clone(&o.reassembler)))
    }

    /// Snapshot of the negotiated mux parameters for this client.
    pub fn client_mux_params(&self, client_id: u64) -> Option<SessionMuxParams> {
        self.clients
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| o.mux))
    }

    /// Cheap clone of the per-client credit map handle.
    pub fn client_credit_map(&self, client_id: u64) -> Option<Arc<CreditMap>> {
        self.clients
            .get(&client_id)
            .and_then(|c| c.online.as_ref().map(|o| Arc::clone(&o.credit)))
    }

    /// Look up the online session whose `session_token` matches.
    /// Returns the parent `client_id` and a snapshot of the handles
    /// the LaneHello attach path needs (mux sender, cancel, mux
    /// params, reassembler, credit map). O(N) in the number of
    /// clients but only called on connection establishment.
    #[allow(clippy::type_complexity)]
    pub fn lookup_by_session_token(
        &self,
        session_token: u64,
    ) -> Option<(
        u64,
        MuxSender,
        CancellationToken,
        SessionMuxParams,
        Arc<StdMutex<Reassembler>>,
        Arc<CreditMap>,
    )> {
        for entry in self.clients.iter() {
            if let Some(o) = entry.value().online.as_ref() {
                if o.session_token == session_token {
                    return Some((
                        *entry.key(),
                        o.tx.clone(),
                        o.cancel.clone(),
                        o.mux,
                        Arc::clone(&o.reassembler),
                        Arc::clone(&o.credit),
                    ));
                }
            }
        }
        None
    }
}

impl Default for ClientDirectory {
    fn default() -> Self {
        Self::new()
    }
}

/// Synchronous teardown of an `OnlineSession`: fire the cancel token,
/// close every per-stream credit semaphore (waking parked senders) and
/// drop in-flight reassembly buffers. Idempotent — every operation is
/// safe to call on an already-torn-down session.
fn teardown_online(old: &OnlineSession) {
    old.cancel.cancel();
    old.credit.close_all();
    let mut r = old.reassembler.lock().unwrap_or_else(|e| e.into_inner());
    r.drain_all();
}
