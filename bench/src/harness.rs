//! Spawn real anno-server / anno-client processes and local echo servers.

use crate::api_client::ApiClient;
use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Fixed key written to the bench registry file and passed to `anno-client --key`.
const BENCH_CLIENT_KEY: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

pub struct TestHarness {
    pub server: Child,
    pub client: Child,
    pub echo_tcp: tokio::task::JoinHandle<()>,
    pub echo_udp: tokio::task::JoinHandle<()>,
    pub api: ApiClient,
    #[allow(dead_code)]
    pub control_addr: SocketAddr,
    #[allow(dead_code)]
    pub api_addr: SocketAddr,
    pub client_name: String,
    pub echo_tcp_addr: SocketAddr,
    pub echo_udp_addr: SocketAddr,
}

impl TestHarness {
    pub async fn setup(args: &HarnessArgs) -> Result<Self> {
        let echo_tcp_addr: SocketAddr = args.echo_tcp.parse().context("parse echo_tcp")?;
        let echo_udp_addr: SocketAddr = args.echo_udp.parse().context("parse echo_udp")?;
        let control_addr: SocketAddr = args.control.parse().context("parse control")?;
        let api_addr: SocketAddr = args.api.parse().context("parse api")?;

        let echo_tcp = tokio::spawn({
            let a = echo_tcp_addr;
            async move {
                if let Err(e) = crate::echo_server::run_tcp_echo(a).await {
                    tracing::error!("tcp echo exited: {e}");
                }
            }
        });
        let echo_udp = tokio::spawn({
            let a = echo_udp_addr;
            async move {
                if let Err(e) = crate::echo_server::run_udp_echo(a).await {
                    tracing::error!("udp echo exited: {e}");
                }
            }
        });

        // Let listeners bind.
        sleep(Duration::from_millis(50)).await;

        let registry_path = std::env::temp_dir().join(format!(
            "anno-bench-registry-{}.json",
            std::process::id()
        ));
        let registry_body = json!({
            "clients": [{
                "name": args.client_name,
                "key": BENCH_CLIENT_KEY,
                "description": null,
                "created_at": 0u64
            }]
        });
        fs::write(
            &registry_path,
            serde_json::to_string_pretty(&registry_body).context("serialize bench registry")?,
        )
        .with_context(|| format!("write {}", registry_path.display()))?;

        let mut server_cmd = Command::new(&args.server_bin);
        server_cmd
            .arg("--control")
            .arg(control_addr.to_string())
            .arg("--api")
            .arg(api_addr.to_string())
            .arg("--registry-file")
            .arg(&registry_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let server = server_cmd
            .spawn()
            .with_context(|| format!("spawn anno-server (bin={})", args.server_bin.display()))?;

        let api_base = format!("http://{}/", api_addr);
        let api = ApiClient::new(&api_base)?;
        wait_api_ready(&api, Duration::from_secs(30)).await?;

        let mut client_cmd = Command::new(&args.client_bin);
        client_cmd
            .arg("--server")
            .arg(control_addr.to_string())
            .arg("--key")
            .arg(BENCH_CLIENT_KEY)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let client = client_cmd
            .spawn()
            .with_context(|| format!("spawn anno-client (bin={})", args.client_bin.display()))?;

        wait_client_online(&api, &args.client_name, Duration::from_secs(30)).await?;

        Ok(Self {
            server,
            client,
            echo_tcp,
            echo_udp,
            api,
            control_addr,
            api_addr,
            client_name: args.client_name.clone(),
            echo_tcp_addr,
            echo_udp_addr,
        })
    }

    pub fn server_pid(&self) -> u32 {
        self.server.id()
    }

    pub fn client_pid(&self) -> u32 {
        self.client.id()
    }

    pub async fn wait_client_id(&self) -> Result<u64> {
        resolve_client_id(&self.api, &self.client_name).await
    }

    pub async fn create_mapping(
        &self,
        client_id: u64,
        server_port: u16,
        protocol: &str,
        target_host: &str,
        target_port: u16,
    ) -> Result<()> {
        use crate::api_client::AddMappingReq;
        self.api
            .add_mapping(
                client_id,
                AddMappingReq {
                    server_port,
                    protocol: protocol.to_string(),
                    target_host: target_host.to_string(),
                    target_port,
                },
            )
            .await?;
        // Allow listener + control path to settle.
        sleep(Duration::from_millis(200)).await;
        Ok(())
    }

    pub async fn delete_mapping(&self, client_id: u64, server_port: u16) -> Result<()> {
        self.api.delete_mapping(client_id, server_port).await?;
        sleep(Duration::from_millis(100)).await;
        Ok(())
    }

    pub fn teardown(mut self) {
        let _ = self.client.kill();
        let _ = self.client.wait();
        let _ = self.server.kill();
        let _ = self.server.wait();
        self.echo_tcp.abort();
        self.echo_udp.abort();
    }
}

#[derive(Debug, Clone)]
pub struct HarnessArgs {
    pub server_bin: PathBuf,
    pub client_bin: PathBuf,
    pub control: String,
    pub api: String,
    pub echo_tcp: String,
    pub echo_udp: String,
    pub client_name: String,
}

impl Default for HarnessArgs {
    fn default() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
            .join("release");
        Self {
            server_bin: root.join("anno-server"),
            client_bin: root.join("anno-client"),
            control: "127.0.0.1:19100".to_string(),
            api: "127.0.0.1:18080".to_string(),
            echo_tcp: "127.0.0.1:17777".to_string(),
            echo_udp: "127.0.0.1:17778".to_string(),
            client_name: "anno-bench-client".to_string(),
        }
    }
}

async fn wait_api_ready(api: &ApiClient, max_wait: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < max_wait {
        if api.stats().await.is_ok() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("management API not ready within {:?}", max_wait);
}

async fn wait_client_online(api: &ApiClient, name: &str, max_wait: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < max_wait {
        if let Ok(clients) = api.list_clients().await {
            for c in clients {
                if c.name == name && c.status == "online" {
                    return Ok(());
                }
            }
        }
        sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("client {name} not online within {:?}", max_wait);
}

pub async fn resolve_client_id(api: &ApiClient, name: &str) -> Result<u64> {
    let clients = api.list_clients().await?;
    for c in clients {
        if c.name == name {
            return Ok(c.id);
        }
    }
    anyhow::bail!("client {name} not found")
}
