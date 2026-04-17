//! Client registry: persisted client entries with authentication keys.
//!
//! Improvements over the original:
//! - O(1) `lookup_by_key` via a `key_to_name` secondary index.
//! - Non-blocking persist: changes are queued and written in a background
//!   `spawn_blocking` task with 200 ms debounce.  Writes are atomic
//!   (tmp-file + rename).
//! - `flush_sync` for graceful-shutdown use.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    pub name: String,
    pub key: String,
    pub description: Option<String>,
    pub created_at: u64,
    /// Persisted port mappings for this client. Empty for clients that have
    /// never had any mapping configured. `#[serde(default)]` makes old
    /// `clients.json` files (pre-mapping-persistence) upgrade silently.
    #[serde(default)]
    pub mappings: Vec<StoredMappingJson>,
}

/// JSON-friendly snapshot of a single port mapping. The in-memory
/// representation is [`crate::state::StoredMapping`]; this struct is the
/// wire/disk form — we keep them separate so the JSON schema does not leak
/// `anno_common` types (e.g. `Host::V4` variant names).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredMappingJson {
    pub server_port: u16,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
}

impl ClientEntry {
    fn new(name: impl Into<String>, description: Option<String>) -> Self {
        Self {
            name: name.into(),
            key: Uuid::new_v4().to_string(),
            description,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            mappings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RegistryFile {
    clients: Vec<ClientEntry>,
}

/// Shared inner state behind the registry clone handle.
struct RegistryInner {
    /// name → entry
    entries: DashMap<String, ClientEntry>,
    /// key → name  (secondary index for O(1) auth)
    key_to_name: DashMap<String, String>,
    file_path: PathBuf,
    /// Sending `true` on this channel triggers a debounced persist.
    dirty_tx: watch::Sender<bool>,
}

#[derive(Clone)]
pub struct ClientRegistry {
    inner: Arc<RegistryInner>,
}

impl ClientRegistry {
    /// Load registry from JSON file (creates empty if missing).
    ///
    /// This function is pure IO/in-memory setup and does NOT spawn any
    /// background task — so it is safe to call outside of a Tokio runtime
    /// (useful for unit tests and tooling). The caller must explicitly
    /// start the persistor with [`ClientRegistry::start_persistor`] inside
    /// a runtime to enable disk persistence.
    pub fn load(path: impl AsRef<Path>) -> Self {
        let file_path = path.as_ref().to_path_buf();
        let entries: DashMap<String, ClientEntry> = DashMap::new();
        let key_to_name: DashMap<String, String> = DashMap::new();

        if file_path.exists() {
            match std::fs::read_to_string(&file_path) {
                Ok(s) => match serde_json::from_str::<RegistryFile>(&s) {
                    Ok(rf) => {
                        for entry in rf.clients {
                            key_to_name.insert(entry.key.clone(), entry.name.clone());
                            entries.insert(entry.name.clone(), entry);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("failed to parse registry file: {}", e);
                    }
                },
                Err(e) => {
                    tracing::warn!("failed to read registry file: {}", e);
                }
            }
        }

        let (dirty_tx, _dirty_rx) = watch::channel(false);

        Self {
            inner: Arc::new(RegistryInner {
                entries,
                key_to_name,
                file_path,
                dirty_tx,
            }),
        }
    }

    /// Spawn the debounced background persistor task. Must be called inside a
    /// Tokio runtime. Returns the JoinHandle so callers can await shutdown.
    pub fn start_persistor(&self) -> tokio::task::JoinHandle<()> {
        let registry = self.clone();
        let dirty_rx = registry.inner.dirty_tx.subscribe();
        tokio::spawn(async move {
            persist_loop(registry, dirty_rx).await;
        })
    }

    /// Mark the registry as dirty; the background task will persist it soon.
    fn mark_dirty(&self) {
        let _ = self.inner.dirty_tx.send(true);
    }

    /// Block the current thread to flush pending changes synchronously.
    /// Intended for graceful-shutdown paths only.
    pub fn flush_sync(&self) {
        do_persist_sync(&self.inner);
    }

    /// List all entries sorted by name.
    pub fn list(&self) -> Vec<ClientEntry> {
        let mut v: Vec<ClientEntry> =
            self.inner.entries.iter().map(|e| e.value().clone()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Create a new entry with auto-generated key.
    pub fn create(
        &self,
        name: impl Into<String>,
        description: Option<String>,
    ) -> Result<ClientEntry, &'static str> {
        let name = name.into();
        if self.inner.entries.contains_key(&name) {
            return Err("client name already exists");
        }
        let entry = ClientEntry::new(name.clone(), description);
        self.inner
            .key_to_name
            .insert(entry.key.clone(), name.clone());
        self.inner.entries.insert(name, entry.clone());
        self.mark_dirty();
        Ok(entry)
    }

    /// Update description for an existing entry.
    pub fn update_description(
        &self,
        name: &str,
        description: Option<String>,
    ) -> Option<ClientEntry> {
        let mut entry = self.inner.entries.get_mut(name)?;
        entry.description = description;
        let updated = entry.clone();
        drop(entry);
        self.mark_dirty();
        Some(updated)
    }

    /// Regenerate key for an existing entry.
    pub fn regenerate_key(&self, name: &str) -> Option<ClientEntry> {
        let mut entry = self.inner.entries.get_mut(name)?;
        // Remove old key from secondary index.
        self.inner.key_to_name.remove(&entry.key);
        entry.key = Uuid::new_v4().to_string();
        let updated = entry.clone();
        drop(entry);
        // Insert new key into secondary index.
        self.inner
            .key_to_name
            .insert(updated.key.clone(), name.to_string());
        self.mark_dirty();
        Some(updated)
    }

    /// Delete an entry by name.
    pub fn delete(&self, name: &str) -> bool {
        if let Some((_, entry)) = self.inner.entries.remove(name) {
            self.inner.key_to_name.remove(&entry.key);
            self.mark_dirty();
            true
        } else {
            false
        }
    }

    /// Find registry entry by authentication key — O(1) via secondary index.
    pub fn lookup_by_key(&self, key: &str) -> Option<ClientEntry> {
        let name = self.inner.key_to_name.get(key)?;
        self.inner.entries.get(name.as_str()).map(|e| e.value().clone())
    }

    /// Get a single entry by name.
    pub fn get(&self, name: &str) -> Option<ClientEntry> {
        self.inner.entries.get(name).map(|e| e.value().clone())
    }

    /// Read the persisted mappings for `name`. Returns an empty vec if the
    /// entry is absent or has no mappings yet.
    pub fn get_mappings(&self, name: &str) -> Vec<StoredMappingJson> {
        self.inner
            .entries
            .get(name)
            .map(|e| e.value().mappings.clone())
            .unwrap_or_default()
    }

    /// Replace the mappings for `name` and schedule an async disk flush.
    /// Returns `false` if no entry exists with that name (caller can treat
    /// this as a no-op; no write is scheduled).
    pub fn set_mappings(&self, name: &str, mappings: Vec<StoredMappingJson>) -> bool {
        let Some(mut entry) = self.inner.entries.get_mut(name) else {
            return false;
        };
        entry.mappings = mappings;
        drop(entry);
        self.mark_dirty();
        true
    }
}

// ---------------------------------------------------------------------------
// Background persistor
// ---------------------------------------------------------------------------

async fn persist_loop(registry: ClientRegistry, mut dirty_rx: watch::Receiver<bool>) {
    loop {
        // Wait until the channel is marked dirty.
        if dirty_rx.changed().await.is_err() {
            break; // Sender dropped → shutdown.
        }

        // Debounce: wait up to 200 ms for any additional changes to accumulate.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Drain pending notifications before writing.
        let _ = dirty_rx.has_changed();

        let inner = Arc::clone(&registry.inner);
        if let Err(e) =
            tokio::task::spawn_blocking(move || do_persist_sync(&inner)).await
        {
            tracing::error!("registry persist task panicked: {e}");
        }
    }
}

fn do_persist_sync(inner: &RegistryInner) {
    let clients: Vec<ClientEntry> = inner.entries.iter().map(|e| e.value().clone()).collect();
    let rf = RegistryFile { clients };
    let json = match serde_json::to_string_pretty(&rf) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("failed to serialize registry: {e}");
            return;
        }
    };
    // Atomic write: write to tmp then rename.
    let tmp_path = inner.file_path.with_extension("json.tmp");
    if let Err(e) = std::fs::write(&tmp_path, &json) {
        tracing::error!("failed to write registry tmp file: {e}");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp_path, &inner.file_path) {
        tracing::error!("failed to rename registry tmp file: {e}");
    }
}
