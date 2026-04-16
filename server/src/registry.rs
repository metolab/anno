//! Client registry: persisted client entries with authentication keys.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    pub name: String,
    pub key: String,
    pub description: Option<String>,
    pub created_at: u64,
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
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RegistryFile {
    clients: Vec<ClientEntry>,
}

#[derive(Clone)]
pub struct ClientRegistry {
    entries: Arc<DashMap<String, ClientEntry>>,
    file_path: PathBuf,
}

impl ClientRegistry {
    /// Load registry from JSON file (creates empty if missing).
    pub fn load(path: impl AsRef<Path>) -> Self {
        let file_path = path.as_ref().to_path_buf();
        let entries: DashMap<String, ClientEntry> = DashMap::new();

        if file_path.exists() {
            match std::fs::read_to_string(&file_path) {
                Ok(s) => match serde_json::from_str::<RegistryFile>(&s) {
                    Ok(rf) => {
                        for entry in rf.clients {
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

        Self {
            entries: Arc::new(entries),
            file_path,
        }
    }

    fn persist(&self) {
        let clients: Vec<ClientEntry> = self.entries.iter().map(|e| e.value().clone()).collect();
        let rf = RegistryFile { clients };
        match serde_json::to_string_pretty(&rf) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&self.file_path, s) {
                    tracing::error!("failed to write registry file: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("failed to serialize registry: {}", e);
            }
        }
    }

    /// List all entries sorted by name.
    pub fn list(&self) -> Vec<ClientEntry> {
        let mut v: Vec<ClientEntry> = self.entries.iter().map(|e| e.value().clone()).collect();
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
        if self.entries.contains_key(&name) {
            return Err("client name already exists");
        }
        let entry = ClientEntry::new(name.clone(), description);
        self.entries.insert(name, entry.clone());
        self.persist();
        Ok(entry)
    }

    /// Update description for an existing entry.
    pub fn update_description(
        &self,
        name: &str,
        description: Option<String>,
    ) -> Option<ClientEntry> {
        let mut entry = self.entries.get_mut(name)?;
        entry.description = description;
        let updated = entry.clone();
        drop(entry);
        self.persist();
        Some(updated)
    }

    /// Regenerate key for an existing entry.
    pub fn regenerate_key(&self, name: &str) -> Option<ClientEntry> {
        let mut entry = self.entries.get_mut(name)?;
        entry.key = Uuid::new_v4().to_string();
        let updated = entry.clone();
        drop(entry);
        self.persist();
        Some(updated)
    }

    /// Delete an entry by name.
    pub fn delete(&self, name: &str) -> bool {
        let removed = self.entries.remove(name).is_some();
        if removed {
            self.persist();
        }
        removed
    }

    /// Verify that the given key matches the registered key for the client name.
    /// Returns true only if the name exists in the registry AND the key matches exactly.
    /// Clients with no registry entry or with a wrong/missing key are rejected.
    pub fn verify_key(&self, name: &str, key: Option<&str>) -> bool {
        match self.entries.get(name) {
            None => false,
            Some(entry) => key.map(|k| k == entry.key.as_str()).unwrap_or(false),
        }
    }

    /// Get a single entry by name.
    pub fn get(&self, name: &str) -> Option<ClientEntry> {
        self.entries.get(name).map(|e| e.value().clone())
    }
}
