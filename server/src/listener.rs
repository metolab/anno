//! Global listener reconciliation actor.
//!
//! All mutations of `state.listeners()` are funneled through a single tokio
//! task that consumes `ListenerCommand` messages. This guarantees:
//!
//! - Serial execution of bind / abort across the whole process, so two
//!   concurrent API handlers cannot race their "snapshot mappings → stop
//!   unwanted ports → bind desired ports" phases against each other.
//! - No TOCTOU between "port free" check and `insert`: the actor reserves a
//!   port atomically with `ListenerRecord::Binding` before starting the
//!   async bind. A failed bind removes the reservation; a successful bind
//!   upgrades it to `ListenerRecord::Active { handle }`.
//!
//! Callers interact via [`ListenerHandle`], which is a small wrapper over an
//! `mpsc::Sender<ListenerCommand>`. Each command carries a oneshot reply
//! channel; methods `.await` the reply so API handlers observe the reconcile
//! completing before returning to the HTTP client.

use crate::proxy::{spawn_tcp_listener, spawn_udp_listener, BindResult};
use crate::state::{AppState, ListenerRecord, StoredMapping};
use anno_common::Protocol;
use std::collections::HashSet;
use tokio::sync::{mpsc, oneshot};

/// Channel capacity for the listener command queue. In practice queue depth
/// is bounded by concurrent API handlers.
const COMMAND_CHANNEL_CAPACITY: usize = 256;

/// Report produced by `SyncClient`: lists the ports the actor could not
/// activate together with the reason. API callers use this to roll back
/// their in-memory / persisted mapping state and reply with an accurate
/// `409 Conflict` (or 500) to the HTTP caller.
#[derive(Debug, Default, Clone)]
pub struct SyncReport {
    pub rejected_ports: Vec<(u16, RejectReason)>,
}

#[derive(Debug, Clone)]
pub enum RejectReason {
    /// Another client currently owns this port in the listener registry.
    OwnedByOther(u64),
    /// The socket bind itself failed (EADDRINUSE from the OS, permission
    /// error binding below 1024, etc.).
    BindFailed(String),
}

/// Commands accepted by the listener actor.
pub enum ListenerCommand {
    /// Reconcile all listeners for one client to match the client's current
    /// `mappings` snapshot.
    SyncClient {
        client_id: u64,
        reply: oneshot::Sender<SyncReport>,
    },
    /// Stop every listener owned by `client_id`.
    StopClient {
        client_id: u64,
        reply: oneshot::Sender<()>,
    },
    /// Stop the listener for a specific port (regardless of owner).
    StopPort {
        port: u16,
        reply: oneshot::Sender<()>,
    },
    /// Stop every listener (used on graceful shutdown).
    StopAll { reply: oneshot::Sender<()> },
}

/// Cheap cloneable handle for sending commands to the listener actor.
#[derive(Clone)]
pub struct ListenerHandle {
    tx: mpsc::Sender<ListenerCommand>,
}

impl ListenerHandle {
    /// Synchronize listeners for a client and wait for the reconcile to
    /// complete. Returns the actor's [`SyncReport`] with any ports that
    /// could not be activated. Returns an empty report if the actor has
    /// already shut down (callers should treat that as "no new conflict
    /// information" — the shutdown path is already cleaning listeners up).
    pub async fn sync_client(&self, client_id: u64) -> SyncReport {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(ListenerCommand::SyncClient {
                client_id,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return SyncReport::default();
        }
        reply_rx.await.unwrap_or_default()
    }

    pub async fn stop_client(&self, client_id: u64) {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(ListenerCommand::StopClient {
                client_id,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return;
        }
        let _ = reply_rx.await;
    }

    pub async fn stop_port(&self, port: u16) {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(ListenerCommand::StopPort {
                port,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return;
        }
        let _ = reply_rx.await;
    }

    pub async fn stop_all(&self) {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(ListenerCommand::StopAll { reply: reply_tx })
            .await
            .is_err()
        {
            return;
        }
        let _ = reply_rx.await;
    }
}

/// Construct a listener actor channel without spawning yet. The caller must
/// call [`spawn_listener_actor`] once `AppState` is available so the actor
/// can be wired to read mappings from it.
pub fn make_handle() -> (ListenerHandle, mpsc::Receiver<ListenerCommand>) {
    let (tx, rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
    (ListenerHandle { tx }, rx)
}

/// Spawn the reconciliation actor. Must be called exactly once after
/// `AppState` is constructed.
pub fn spawn_listener_actor(
    state: AppState,
    rx: mpsc::Receiver<ListenerCommand>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(actor_loop(state, rx))
}

async fn actor_loop(state: AppState, mut rx: mpsc::Receiver<ListenerCommand>) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            ListenerCommand::SyncClient { client_id, reply } => {
                let report = sync_client_inner(&state, client_id).await;
                let _ = reply.send(report);
            }
            ListenerCommand::StopClient { client_id, reply } => {
                stop_client_inner(&state, client_id);
                let _ = reply.send(());
            }
            ListenerCommand::StopPort { port, reply } => {
                stop_port_inner(&state, port);
                let _ = reply.send(());
            }
            ListenerCommand::StopAll { reply } => {
                stop_all_inner(&state);
                let _ = reply.send(());
            }
        }
    }
    tracing::info!("listener actor exiting (channel closed)");
}

async fn sync_client_inner(state: &AppState, client_id: u64) -> SyncReport {
    let mut report = SyncReport::default();
    let mappings: Vec<StoredMapping> = match state.clients().get(&client_id) {
        Some(c) => c.mappings.clone(),
        None => return report,
    };

    let is_online = state
        .clients()
        .get(&client_id)
        .map(|c| c.online.is_some())
        .unwrap_or(false);

    if !is_online {
        stop_client_inner(state, client_id);
        return report;
    }

    let desired: HashSet<u16> = mappings.iter().map(|m| m.server_port).collect();

    // Stop any listener this client owns that no longer appears in mappings.
    let owned: Vec<u16> = state
        .listeners()
        .iter()
        .filter(|e| e.value().client_id() == client_id)
        .map(|e| *e.key())
        .collect();
    for p in owned {
        if !desired.contains(&p) {
            stop_port_inner(state, p);
        }
    }

    for m in mappings {
        // Ownership check — safe because actor is the sole writer.
        if let Some(existing) = state.listeners().get(&m.server_port) {
            let existing_owner = existing.client_id();
            drop(existing);
            if existing_owner != client_id {
                tracing::error!(
                    port = m.server_port,
                    other_client = existing_owner,
                    client_id,
                    "port owned by another client; skipping"
                );
                report
                    .rejected_ports
                    .push((m.server_port, RejectReason::OwnedByOther(existing_owner)));
                continue;
            }
            continue;
        }

        // Reserve the port atomically before the async bind so external
        // readers observe the port as "in use" immediately. Since the actor
        // is the only writer, this is simply `insert`.
        state.listeners().insert(
            m.server_port,
            ListenerRecord::Binding { client_id },
        );

        let bind_result = match m.protocol {
            // HttpProxy is transport-TCP; target is resolved dynamically
            // by the TCP listener to the client's current http_proxy_port.
            Protocol::Tcp | Protocol::HttpProxy => {
                spawn_tcp_listener(state.clone(), client_id, m.clone()).await
            }
            Protocol::Udp => spawn_udp_listener(state.clone(), client_id, m.clone()).await,
            Protocol::Both => {
                let tcp = spawn_tcp_listener(state.clone(), client_id, m.clone()).await;
                let udp = spawn_udp_listener(state.clone(), client_id, m.clone()).await;
                combine_bind_results(tcp, udp)
            }
        };

        match bind_result {
            BindResult::Ok(handle) => {
                state.listeners().insert(
                    m.server_port,
                    ListenerRecord::Active {
                        client_id,
                        handle,
                    },
                );
                tracing::debug!(port = m.server_port, client_id, "listener active");
            }
            BindResult::Err(e) => {
                tracing::error!(port = m.server_port, "bind failed: {}", e);
                state.listeners().remove(&m.server_port);
                report
                    .rejected_ports
                    .push((m.server_port, RejectReason::BindFailed(e.to_string())));
            }
        }
    }

    report
}

fn combine_bind_results(a: BindResult, b: BindResult) -> BindResult {
    match (a, b) {
        (BindResult::Ok(ha), BindResult::Ok(hb)) => {
            let joined = tokio::spawn(async move {
                let _ = tokio::join!(ha, hb);
            });
            BindResult::Ok(joined)
        }
        (BindResult::Ok(h), BindResult::Err(e)) | (BindResult::Err(e), BindResult::Ok(h)) => {
            h.abort();
            BindResult::Err(e)
        }
        (BindResult::Err(e), BindResult::Err(_)) => BindResult::Err(e),
    }
}

fn stop_client_inner(state: &AppState, client_id: u64) {
    let ports: Vec<u16> = state
        .listeners()
        .iter()
        .filter(|e| e.value().client_id() == client_id)
        .map(|e| *e.key())
        .collect();
    for p in ports {
        stop_port_inner(state, p);
    }
}

fn stop_port_inner(state: &AppState, port: u16) {
    if let Some((_, rec)) = state.listeners().remove(&port) {
        // `ListenerRecord::Drop` aborts the task for `Active`; for `Binding`
        // there is no handle to abort — the in-flight bind task will still
        // complete or fail on its own, but since we removed the reservation
        // it won't be re-inserted.
        drop(rec);
        tracing::info!(port, "stopped listener");
    }
}

fn stop_all_inner(state: &AppState) {
    let ports: Vec<u16> = state.listeners().iter().map(|e| *e.key()).collect();
    for p in ports {
        stop_port_inner(state, p);
    }
}
