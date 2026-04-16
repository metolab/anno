//! HTTP management API with structured error handling and security middleware.

use crate::proxy;
use crate::registry::ClientEntry;
use crate::state::{stored_to_port_mapping, AppState, StoredMapping};
use anno_common::{build_config_push, Host, PortMapping, Protocol, TargetAddress};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::Duration;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

// ============================================================================
// Error Handling
// ============================================================================

/// API error codes.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotFound,
    BadRequest,
    Conflict,
    Unauthorized,
    InternalError,
}

/// Structured API error response.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ApiError {
    pub fn not_found(resource: &str) -> Self {
        Self {
            code: ErrorCode::NotFound,
            message: format!("{} not found", resource),
            details: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::BadRequest,
            message: message.into(),
            details: None,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::Conflict,
            message: message.into(),
            details: None,
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            code: ErrorCode::Unauthorized,
            message: "unauthorized".to_string(),
            details: None,
        }
    }

    #[allow(dead_code)]
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InternalError,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code {
            ErrorCode::NotFound => StatusCode::NOT_FOUND,
            ErrorCode::BadRequest => StatusCode::BAD_REQUEST,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

/// Result type for API handlers.
pub type ApiResult<T> = Result<T, ApiError>;

// ============================================================================
// Auth Middleware
// ============================================================================

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let cfg = state.config();
    let needs_auth = cfg.api_token.is_some() || cfg.admin_password_hash.is_some();

    if needs_auth {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));

        let authed = match provided {
            None => false,
            Some(tok) => {
                // Check session token first, then fall back to static api_token
                state.verify_token(tok) || cfg.api_token.as_deref() == Some(tok)
            }
        };

        if !authed {
            return ApiError::unauthorized().into_response();
        }
    }
    next.run(req).await
}

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Serialize)]
pub struct ClientDto {
    pub id: u64,
    pub name: String,
    pub status: &'static str,
    pub connected_at: Option<String>,
    pub remote_addr: Option<String>,
    pub http_proxy_port: Option<u16>,
    pub mappings: Vec<MappingDto>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MappingDto {
    pub server_port: u16,
    pub protocol: String,
    pub target: String,
    pub active_connections: u64,
}

#[derive(Debug, Serialize)]
pub struct StatsDto {
    pub clients_online: u64,
    pub clients_total: usize,
    pub mappings_total: u64,
    pub sessions_active: usize,
    pub sessions_tcp: usize,
    pub sessions_udp: usize,
    pub queue_drops_total: u64,
    pub bytes_up_total: u64,
    pub bytes_down_total: u64,
}

#[derive(Debug, Deserialize)]
pub struct AddMappingReq {
    pub server_port: u16,
    pub protocol: String,
    pub target_host: String,
    pub target_port: u16,
}

pub fn router(state: AppState, metrics_handle: PrometheusHandle) -> Router {
    // Public login route (no auth required)
    let login_route = Router::new()
        .route("/api/login", post(login))
        .layer(RequestBodyLimitLayer::new(64 * 1024));

    // Protected /api/* routes with optional bearer token auth
    let api_routes = Router::new()
        .route("/api/clients", get(list_clients))
        .route("/api/clients/:id", get(get_client).delete(delete_client))
        .route(
            "/api/clients/:id/mappings",
            get(list_mappings).post(add_mapping),
        )
        .route(
            "/api/clients/:id/mappings/:port",
            put(update_mapping).delete(delete_mapping),
        )
        .route("/api/stats", get(stats))
        .route("/api/registry", get(registry_list).post(registry_create))
        .route(
            "/api/registry/:name",
            get(registry_get)
                .put(registry_update)
                .delete(registry_delete),
        )
        .route(
            "/api/registry/:name/regenerate-key",
            post(registry_regen_key),
        )
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(64 * 1024));

    // Public /metrics endpoint (Prometheus scraper does not send auth headers)
    let metrics_route = Router::new().route(
        "/metrics",
        get(move || async move {
            let body = metrics_handle.render();
            (
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; version=0.0.4",
                )],
                body,
            )
        }),
    );

    Router::new()
        .merge(login_route)
        .merge(api_routes)
        .merge(metrics_route)
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

async fn list_clients(State(state): State<AppState>) -> impl IntoResponse {
    let mut out: Vec<ClientDto> = Vec::new();
    for c in state.clients().iter() {
        let id = *c.key();
        let v = c.value();
        out.push(client_to_dto(id, v, &state));
    }
    out.sort_by_key(|c| c.id);
    Json(out)
}

async fn get_client(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> ApiResult<Json<ClientDto>> {
    match state.clients().get(&id) {
        Some(c) => Ok(Json(client_to_dto(id, &c, &state))),
        None => Err(ApiError::not_found("client")),
    }
}

async fn delete_client(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> ApiResult<StatusCode> {
    if let Some((_, rec)) = state.clients().remove(&id) {
        state.name_to_id().remove(&rec.name);
        proxy::stop_all_client_ports(&state, id);
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("client"))
    }
}

async fn list_mappings(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> ApiResult<Json<Vec<MappingDto>>> {
    match state.clients().get(&id) {
        Some(c) => {
            let v: Vec<MappingDto> = c
                .mappings
                .iter()
                .map(|m| mapping_to_dto(m, &state))
                .collect();
            Ok(Json(v))
        }
        None => Err(ApiError::not_found("client")),
    }
}

async fn add_mapping(
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<AddMappingReq>,
) -> ApiResult<(StatusCode, Json<MappingDto>)> {
    let proto = parse_protocol(&body.protocol).ok_or_else(|| {
        ApiError::bad_request("invalid protocol").with_details("must be tcp, udp, or both")
    })?;

    let target = parse_target(&body.target_host, body.target_port)
        .map_err(|e| ApiError::bad_request("invalid target").with_details(e))?;

    if let Some(existing) = state.port_owner().get(&body.server_port) {
        if *existing != id {
            return Err(
                ApiError::conflict("port in use by another client").with_details(format!(
                    "port {} is owned by client {}",
                    body.server_port, *existing
                )),
            );
        }
    }

    state
        .clients()
        .entry(id)
        .or_insert(crate::state::ClientRecord {
            name: format!("client-{}", id),
            http_proxy_port: None,
            mappings: vec![],
            online: None,
        });

    let sm = StoredMapping {
        server_port: body.server_port,
        protocol: proto,
        target,
    };

    let needs_restart = state.clients().get(&id).is_some_and(|c| {
        c.mappings
            .iter()
            .find(|m| m.server_port == body.server_port)
            .is_some_and(|m| m.protocol != proto)
    });

    match state.clients().get_mut(&id) {
        Some(mut c) => {
            c.mappings.retain(|m| m.server_port != body.server_port);
            c.mappings.push(sm.clone());
        }
        None => return Err(ApiError::not_found("client")),
    }

    if needs_restart {
        proxy::stop_port(&state, body.server_port);
    }

    push_config_if_online(&state, id).await;
    proxy::sync_client_listeners(&state, id).await;
    Ok((StatusCode::CREATED, Json(mapping_to_dto(&sm, &state))))
}

async fn update_mapping(
    state: State<AppState>,
    Path((id, port)): Path<(u64, u16)>,
    Json(body): Json<AddMappingReq>,
) -> ApiResult<(StatusCode, Json<MappingDto>)> {
    if body.server_port != port {
        return Err(ApiError::bad_request("port mismatch").with_details(format!(
            "URL port {} != body port {}",
            port, body.server_port
        )));
    }
    add_mapping(state, Path(id), Json(body)).await
}

async fn delete_mapping(
    State(state): State<AppState>,
    Path((id, port)): Path<(u64, u16)>,
) -> ApiResult<StatusCode> {
    match state.clients().get_mut(&id) {
        Some(mut c) => {
            let existed = c.mappings.iter().any(|m| m.server_port == port);
            if !existed {
                return Err(ApiError::not_found("mapping"));
            }
            c.mappings.retain(|m| m.server_port != port);
        }
        None => return Err(ApiError::not_found("client")),
    }

    proxy::stop_port(&state, port);
    push_config_if_online(&state, id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn stats(State(state): State<AppState>) -> Json<StatsDto> {
    let mut online = 0u64;
    let mut mappings = 0u64;
    for c in state.clients().iter() {
        mappings += c.mappings.len() as u64;
        if c.online.is_some() {
            online += 1;
        }
    }

    let session_manager = state.session_manager();
    let sessions_active = session_manager.active_count();

    let mut tcp_count = 0usize;
    let mut udp_count = 0usize;
    let mut queue_drops_total = 0u64;
    let mut bytes_up_total = 0u64;
    let mut bytes_down_total = 0u64;

    for entry in session_manager.iter_sessions() {
        let s = entry.value();
        match s.protocol {
            crate::session::SessionProtocol::Tcp => tcp_count += 1,
            crate::session::SessionProtocol::Udp => udp_count += 1,
        }
        queue_drops_total += s
            .stats
            .queue_drops
            .load(std::sync::atomic::Ordering::Relaxed);
        bytes_up_total += s.stats.bytes_up.load(std::sync::atomic::Ordering::Relaxed);
        bytes_down_total += s
            .stats
            .bytes_down
            .load(std::sync::atomic::Ordering::Relaxed);
    }

    Json(StatsDto {
        clients_online: online,
        clients_total: state.clients().len(),
        mappings_total: mappings,
        sessions_active,
        sessions_tcp: tcp_count,
        sessions_udp: udp_count,
        queue_drops_total,
        bytes_up_total,
        bytes_down_total,
    })
}

fn client_to_dto(id: u64, c: &crate::state::ClientRecord, state: &AppState) -> ClientDto {
    let status = if c.online.is_some() {
        "online"
    } else {
        "offline"
    };
    let (connected_at, remote_addr) = if let Some(o) = &c.online {
        (
            Some(format!("{:?}", o.connected_at)),
            Some(o.addr.to_string()),
        )
    } else {
        (None, None)
    };
    ClientDto {
        id,
        name: c.name.clone(),
        status,
        connected_at,
        remote_addr,
        http_proxy_port: c.http_proxy_port,
        mappings: c
            .mappings
            .iter()
            .map(|m| mapping_to_dto(m, state))
            .collect(),
    }
}

fn mapping_to_dto(m: &StoredMapping, state: &AppState) -> MappingDto {
    let active_connections = state.session_manager().count_by_port(m.server_port) as u64;
    MappingDto {
        server_port: m.server_port,
        protocol: protocol_to_str(m.protocol).to_string(),
        target: format_target(&m.target),
        active_connections,
    }
}

fn format_target(t: &TargetAddress) -> String {
    match &t.host {
        Host::V4(ip) => format!("{}:{}", ip, t.port),
        Host::V6(ip) => format!("[{}]:{}", ip, t.port),
        Host::Domain(s) => format!("{}:{}", s, t.port),
    }
}

fn protocol_to_str(p: Protocol) -> &'static str {
    match p {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Both => "both",
    }
}

fn parse_protocol(s: &str) -> Option<Protocol> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "both" => Some(Protocol::Both),
        _ => None,
    }
}

fn parse_target(host: &str, port: u16) -> Result<TargetAddress, &'static str> {
    let host = if let Ok(ip) = Ipv4Addr::from_str(host) {
        Host::V4(ip)
    } else if let Ok(ip) = Ipv6Addr::from_str(host) {
        Host::V6(ip)
    } else {
        Host::Domain(host.to_string())
    };
    Ok(TargetAddress { host, port })
}

// ============================================================================
// Login
// ============================================================================

#[derive(Debug, Deserialize)]
struct LoginReq {
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginRes {
    token: String,
}

async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginReq>,
) -> ApiResult<Json<LoginRes>> {
    let hash = state
        .config()
        .admin_password_hash
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("password authentication not configured"))?;

    let valid =
        bcrypt::verify(&body.password, hash).map_err(|_| ApiError::internal("bcrypt error"))?;

    if !valid {
        return Err(ApiError::unauthorized());
    }

    let token = Uuid::new_v4().to_string();
    state.set_token(token.clone());
    Ok(Json(LoginRes { token }))
}

// ============================================================================
// Client Registry
// ============================================================================

#[derive(Debug, Serialize)]
struct RegistryEntryDto {
    pub name: String,
    pub key: String,
    pub description: Option<String>,
    pub created_at: u64,
}

impl From<ClientEntry> for RegistryEntryDto {
    fn from(e: ClientEntry) -> Self {
        Self {
            name: e.name,
            key: e.key,
            description: e.description,
            created_at: e.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
struct CreateRegistryReq {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateRegistryReq {
    pub description: Option<String>,
}

async fn registry_list(State(state): State<AppState>) -> Json<Vec<RegistryEntryDto>> {
    let entries = state
        .registry()
        .list()
        .into_iter()
        .map(Into::into)
        .collect();
    Json(entries)
}

async fn registry_get(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<RegistryEntryDto>> {
    state
        .registry()
        .get(&name)
        .map(|e| Json(e.into()))
        .ok_or_else(|| ApiError::not_found("registry entry"))
}

async fn registry_create(
    State(state): State<AppState>,
    Json(body): Json<CreateRegistryReq>,
) -> ApiResult<(StatusCode, Json<RegistryEntryDto>)> {
    match state.registry().create(body.name, body.description) {
        Ok(entry) => Ok((StatusCode::CREATED, Json(entry.into()))),
        Err(e) => Err(ApiError::conflict(e)),
    }
}

async fn registry_update(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateRegistryReq>,
) -> ApiResult<Json<RegistryEntryDto>> {
    state
        .registry()
        .update_description(&name, body.description)
        .map(|e| Json(e.into()))
        .ok_or_else(|| ApiError::not_found("registry entry"))
}

async fn registry_delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<StatusCode> {
    if state.registry().delete(&name) {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found("registry entry"))
    }
}

async fn registry_regen_key(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Json<RegistryEntryDto>> {
    state
        .registry()
        .regenerate_key(&name)
        .map(|e| Json(e.into()))
        .ok_or_else(|| ApiError::not_found("registry entry"))
}

async fn push_config_if_online(state: &AppState, client_id: u64) {
    let Some(c) = state.clients().get(&client_id) else {
        return;
    };
    let Some(online) = c.online.as_ref() else {
        return;
    };
    let pm: Vec<PortMapping> = c.mappings.iter().map(stored_to_port_mapping).collect();
    let frame = build_config_push(&pm);
    let _ = online.tx.send(frame).await;
}
