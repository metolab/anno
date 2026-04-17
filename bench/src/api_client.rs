//! HTTP management API client for anno-server.

use anyhow::{Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientDto {
    pub id: u64,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub connected_at: Option<String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
    #[serde(default)]
    pub http_proxy_port: Option<u16>,
    #[serde(default)]
    pub mappings: Vec<MappingDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingDto {
    pub server_port: u16,
    pub protocol: String,
    pub target: String,
    pub active_connections: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsDto {
    pub clients_online: u64,
    pub clients_total: usize,
    pub mappings_total: u64,
    pub sessions_active: usize,
    pub sessions_tcp: usize,
    pub sessions_udp: usize,
    #[serde(default)]
    pub queue_drops_total: u64,
    #[serde(default)]
    pub bytes_up_total: u64,
    #[serde(default)]
    pub bytes_down_total: u64,
}

#[derive(Debug, Serialize)]
pub struct AddMappingReq {
    pub server_port: u16,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
}

pub struct ApiClient {
    base: Url,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new(api_base: &str) -> Result<Self> {
        let base = Url::parse(api_base).context("parse api base url")?;
        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .context("build reqwest client")?;
        Ok(Self { base, http })
    }

    pub async fn list_clients(&self) -> Result<Vec<ClientDto>> {
        let url = self.base.join("api/clients")?;
        let v = self
            .http
            .get(url)
            .send()
            .await
            .context("GET /api/clients")?
            .error_for_status()
            .context("GET /api/clients status")?
            .json()
            .await
            .context("GET /api/clients json")?;
        Ok(v)
    }

    pub async fn stats(&self) -> Result<StatsDto> {
        let url = self.base.join("api/stats")?;
        let v = self
            .http
            .get(url)
            .send()
            .await
            .context("GET /api/stats")?
            .error_for_status()
            .context("GET /api/stats status")?
            .json()
            .await
            .context("GET /api/stats json")?;
        Ok(v)
    }

    pub async fn add_mapping(&self, client_id: u64, body: AddMappingReq) -> Result<MappingDto> {
        let url = self
            .base
            .join(&format!("api/clients/{client_id}/mappings"))?;
        let v = self
            .http
            .post(url)
            .json(&body)
            .send()
            .await
            .context("POST mapping")?
            .error_for_status()
            .context("POST mapping status")?
            .json()
            .await
            .context("POST mapping json")?;
        Ok(v)
    }

    pub async fn delete_mapping(&self, client_id: u64, server_port: u16) -> Result<()> {
        let url = self
            .base
            .join(&format!("api/clients/{client_id}/mappings/{server_port}"))?;
        self.http
            .delete(url)
            .send()
            .await
            .context("DELETE mapping")?
            .error_for_status()
            .context("DELETE mapping status")?;
        Ok(())
    }
}
