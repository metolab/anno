//! HTTP management API with structured error handling and security middleware.

use crate::frontend::static_handler;
use crate::listener::{RejectReason, SyncReport};
use crate::ratelimit::LoginDecision;
use crate::registry::ClientEntry;
use crate::state::{
    stored_mapping_to_json, stored_to_port_mapping, AppState, StoredMapping,
};
use anno_common::{ConfigPush, Host, Message, PortMapping, Protocol, TargetAddress};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    TooManyRequests,
    InternalError,
}

/// Structured API error response.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    #[serde(skip)]
    pub retry_after_secs: Option<u64>,
}

impl ApiError {
    pub fn not_found(resource: &str) -> Self {
        Self {
            code: ErrorCode::NotFound,
            message: format!("{} not found", resource),
            details: None,
            retry_after_secs: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::BadRequest,
            message: message.into(),
            details: None,
            retry_after_secs: None,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::Conflict,
            message: message.into(),
            details: None,
            retry_after_secs: None,
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            code: ErrorCode::Unauthorized,
            message: "unauthorized".to_string(),
            details: None,
            retry_after_secs: None,
        }
    }

    pub fn too_many_requests(retry_after_secs: u64) -> Self {
        Self {
            code: ErrorCode::TooManyRequests,
            message: "too many requests".to_string(),
            details: Some(format!("retry after {} seconds", retry_after_secs)),
            retry_after_secs: Some(retry_after_secs),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InternalError,
            message: message.into(),
            details: None,
            retry_after_secs: None,
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
            ErrorCode::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let retry_after = self.retry_after_secs;
        let mut resp = (status, Json(self)).into_response();
        if let Some(retry) = retry_after {
            if let Ok(val) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                resp.headers_mut().insert("retry-after", val);
            }
        }
        resp
    }
}

/// Result type for API handlers.
pub type ApiResult<T> = Result<T, ApiError>;

// ============================================================================
// Auth middleware
// ============================================================================

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    if state.auth().needs_auth() {
        let provided = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));

        let authed = match provided {
            None => false,
            Some(tok) => state.verify_token(tok),
        };

        if !authed {
            return ApiError::unauthorized().into_response();
        }
    }
    next.run(req).await
}

/// Bearer-token guard for `/metrics` when `metrics_token` is configured.
/// When no token is configured the endpoint stays open (useful when you
/// bind metrics on a separate loopback listener via `--metrics-listen`).
async fn metrics_auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.config().metrics_token.as_deref() else {
        return next.run(req).await;
    };

    let provided = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if provided == Some(expected) {
        next.run(req).await
    } else {
        ApiError::unauthorized().into_response()
    }
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
    /// Target host; required for `tcp` / `udp` / `both`, ignored (may be
    /// omitted) for `http_proxy` since the server resolves the target
    /// dynamically to the client's current local HTTP proxy port.
    #[serde(default)]
    pub target_host: Option<String>,
    /// Target port; same semantics as `target_host`.
    #[serde(default)]
    pub target_port: Option<u16>,
}

/// Main management router. When `include_metrics` is true the `/metrics`
/// endpoint is mounted on this router (optionally gated by
/// `AppConfig::metrics_token`); when false the caller should mount
/// [`metrics_only_router`] on a dedicated listener.
pub fn router(
    state: AppState,
    metrics_handle: PrometheusHandle,
    include_metrics: bool,
) -> Router {
    let login_route = Router::new()
        .route("/api/login", post(login))
        .layer(RequestBodyLimitLayer::new(64 * 1024));

    let api_routes = Router::new()
        .route("/api/clients", get(list_clients))
        .route("/api/clients/:id", get(get_client))
        .route(
            "/api/clients/:id/disconnect",
            post(disconnect_client),
        )
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

    let mut app = Router::new().merge(login_route).merge(api_routes);

    if include_metrics {
        let metrics_route = Router::new()
            .route(
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
            )
            .layer(middleware::from_fn_with_state(
                state.clone(),
                metrics_auth_middleware,
            ));
        app = app.merge(metrics_route);
    }

    app.fallback(static_handler)
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

/// Router that exposes `/metrics` only. Mount this on a dedicated loopback
/// listener to keep scraping off the public management port entirely.
pub fn metrics_only_router(metrics_handle: PrometheusHandle) -> Router {
    Router::new().route(
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
    )
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

async fn disconnect_client(
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> ApiResult<StatusCode> {
    // Serialise with other mapping mutations for this client so we don't
    // tear down state while an in-flight `add_mapping` is still writing.
    let _guard = state.lock_client(id).await;

    if !state.clients().contains_key(&id) {
        return Err(ApiError::not_found("client"));
    }

    // Stop all public listeners for this client (via the actor → serial).
    state.listeners_handle().stop_client(id).await;

    // Tear down tunnel sessions (wakes pending ConnReady waiters too).
    state.session_manager().remove_client_sessions(id);

    // Explicit cancel: signal the control loop and all per-session tasks
    // that share this token to stop, then clear the online entry. This is
    // the key fix vs. "just set online = None" — previously we'd rely on
    // the control's write_task detecting the Sender drop, which could
    // lag arbitrarily under load.
    if let Some(mut rec) = state.clients().get_mut(&id) {
        if let Some(online) = rec.online.take() {
            online.cancel.cancel();
        }
    }

    Ok(StatusCode::NO_CONTENT)
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
    if body.server_port == 0 {
        return Err(
            ApiError::bad_request("invalid server_port").with_details("must be 1..=65535")
        );
    }
    let proto = parse_protocol(&body.protocol).ok_or_else(|| {
        ApiError::bad_request("invalid protocol")
            .with_details("must be tcp, udp, both, or http_proxy")
    })?;

    let target = target_for_protocol(proto, body.target_host.as_deref(), body.target_port)?;

    // Quick pre-check against the listener registry to fail obvious port
    // conflicts without paying the actor round-trip. Not authoritative —
    // `sync_client` below is the single source of truth.
    if let Some(existing) = state.listeners().get(&body.server_port) {
        if existing.client_id() != id {
            return Err(
                ApiError::conflict("port in use by another client").with_details(format!(
                    "port {} is owned by client {}",
                    body.server_port,
                    existing.client_id()
                )),
            );
        }
    }

    if !state.clients().contains_key(&id) {
        return Err(ApiError::not_found("client"));
    }

    let _guard = state.lock_client(id).await;

    // Re-check after acquiring the lock: a concurrent `registry_delete`
    // may have evicted the client while we were waiting.
    if !state.clients().contains_key(&id) {
        return Err(ApiError::not_found("client"));
    }

    let sm = StoredMapping {
        server_port: body.server_port,
        protocol: proto,
        target,
    };

    // Snapshot the pre-mutation mappings so we can roll back if the
    // listener actor rejects the new port (e.g. cross-client race or OS
    // bind failure).
    let previous_mappings: Vec<StoredMapping> = state
        .clients()
        .get(&id)
        .map(|c| c.mappings.clone())
        .unwrap_or_default();
    let previous_entry = previous_mappings
        .iter()
        .find(|m| m.server_port == body.server_port)
        .cloned();
    let needs_restart = previous_entry
        .as_ref()
        .is_some_and(|m| m.protocol != proto);

    match state.clients().get_mut(&id) {
        Some(mut c) => {
            c.mappings.retain(|m| m.server_port != body.server_port);
            c.mappings.push(sm.clone());
        }
        None => return Err(ApiError::not_found("client")),
    }

    persist_client_mappings(&state, id);

    if needs_restart {
        state.listeners_handle().stop_port(body.server_port).await;
    }

    push_config_if_online(&state, id).await;
    let report = state.listeners_handle().sync_client(id).await;

    if let Some(reason) = rejected_reason_for(&report, body.server_port) {
        rollback_mapping(&state, id, body.server_port, previous_entry).await;
        return Err(reject_reason_to_error(body.server_port, reason));
    }

    Ok((StatusCode::CREATED, Json(mapping_to_dto(&sm, &state))))
}

async fn update_mapping(
    State(state): State<AppState>,
    Path((id, port)): Path<(u64, u16)>,
    Json(body): Json<AddMappingReq>,
) -> ApiResult<Json<MappingDto>> {
    if body.server_port != port {
        return Err(ApiError::bad_request("port mismatch").with_details(format!(
            "URL port {} != body port {}",
            port, body.server_port
        )));
    }
    if body.server_port == 0 {
        return Err(
            ApiError::bad_request("invalid server_port").with_details("must be 1..=65535")
        );
    }
    let proto = parse_protocol(&body.protocol).ok_or_else(|| {
        ApiError::bad_request("invalid protocol")
            .with_details("must be tcp, udp, both, or http_proxy")
    })?;
    let target = target_for_protocol(proto, body.target_host.as_deref(), body.target_port)?;

    if !state.clients().contains_key(&id) {
        return Err(ApiError::not_found("client"));
    }

    let _guard = state.lock_client(id).await;

    let existing_proto = match state.clients().get(&id) {
        Some(c) => c
            .mappings
            .iter()
            .find(|m| m.server_port == port)
            .map(|m| m.protocol),
        None => return Err(ApiError::not_found("client")),
    };
    let old_proto = match existing_proto {
        Some(p) => p,
        None => return Err(ApiError::not_found("mapping")),
    };

    let sm = StoredMapping {
        server_port: port,
        protocol: proto,
        target,
    };
    let needs_restart = old_proto != proto;

    let previous_entry = state
        .clients()
        .get(&id)
        .and_then(|c| c.mappings.iter().find(|m| m.server_port == port).cloned());

    {
        let mut c = match state.clients().get_mut(&id) {
            Some(c) => c,
            None => return Err(ApiError::not_found("client")),
        };
        c.mappings.retain(|m| m.server_port != port);
        c.mappings.push(sm.clone());
    }

    persist_client_mappings(&state, id);

    if needs_restart {
        state.listeners_handle().stop_port(port).await;
    }

    push_config_if_online(&state, id).await;
    let report = state.listeners_handle().sync_client(id).await;

    if let Some(reason) = rejected_reason_for(&report, port) {
        rollback_mapping(&state, id, port, previous_entry).await;
        return Err(reject_reason_to_error(port, reason));
    }

    Ok(Json(mapping_to_dto(&sm, &state)))
}

async fn delete_mapping(
    State(state): State<AppState>,
    Path((id, port)): Path<(u64, u16)>,
) -> ApiResult<StatusCode> {
    let _guard = state.lock_client(id).await;

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

    persist_client_mappings(&state, id);

    state.listeners_handle().stop_port(port).await;
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

    let tunnel = state.session_manager().aggregate_tunnel_stats();

    Json(StatsDto {
        clients_online: online,
        clients_total: state.clients().len(),
        mappings_total: mappings,
        sessions_active: tunnel.sessions_active,
        sessions_tcp: tunnel.sessions_tcp,
        sessions_udp: tunnel.sessions_udp,
        queue_drops_total: tunnel.queue_drops_total,
        bytes_up_total: tunnel.bytes_up_total,
        bytes_down_total: tunnel.bytes_down_total,
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
    let target = match m.protocol {
        Protocol::HttpProxy => "→ client http proxy".to_string(),
        _ => format_target(&m.target),
    };
    MappingDto {
        server_port: m.server_port,
        protocol: protocol_to_str(m.protocol).to_string(),
        target,
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
        Protocol::HttpProxy => "http_proxy",
    }
}

fn parse_protocol(s: &str) -> Option<Protocol> {
    match s.to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        "both" => Some(Protocol::Both),
        "http_proxy" => Some(Protocol::HttpProxy),
        _ => None,
    }
}

/// Compute the stored [`TargetAddress`] for a new/updated mapping.
///
/// For regular TCP/UDP/Both mappings this validates and parses the
/// user-supplied host/port. For `http_proxy` mappings the target is a
/// sentinel (`127.0.0.1:0`) — the server rewrites it to the client's
/// currently-registered `http_proxy_port` at `NewConn` time — so the
/// fields are ignored and we don't surface spurious validation errors.
fn target_for_protocol(
    proto: Protocol,
    host: Option<&str>,
    port: Option<u16>,
) -> ApiResult<TargetAddress> {
    if proto == Protocol::HttpProxy {
        return Ok(TargetAddress {
            host: Host::V4(Ipv4Addr::LOCALHOST),
            port: 0,
        });
    }
    let host = host.ok_or_else(|| {
        ApiError::bad_request("invalid target").with_details("target_host is required")
    })?;
    let port = port.ok_or_else(|| {
        ApiError::bad_request("invalid target").with_details("target_port is required")
    })?;
    parse_target(host, port)
        .map_err(|e| ApiError::bad_request("invalid target").with_details(e))
}

fn parse_target(host: &str, port: u16) -> Result<TargetAddress, &'static str> {
    if port == 0 {
        return Err("target port must be non-zero");
    }
    let host = host.trim();
    if host.is_empty() {
        return Err("target host must be non-empty");
    }
    let host = if let Ok(ip) = Ipv4Addr::from_str(host) {
        Host::V4(ip)
    } else if let Ok(ip) = Ipv6Addr::from_str(host) {
        Host::V6(ip)
    } else {
        if host.len() > 255 {
            return Err("target domain must be <= 255 bytes");
        }
        if host.contains(char::is_whitespace) {
            return Err("target domain must not contain whitespace");
        }
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

/// Derive the client IP. Honours `X-Forwarded-For`'s left-most entry when
/// the request came from a trusted reverse proxy; otherwise falls back to
/// the direct peer address from `ConnectInfo`.
fn extract_client_ip(headers: &HeaderMap, connect: Option<SocketAddr>) -> IpAddr {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = v.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    connect
        .map(|s| s.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

async fn login(
    State(state): State<AppState>,
    connect: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<LoginReq>,
) -> ApiResult<Json<LoginRes>> {
    let ip = extract_client_ip(&headers, connect.map(|ConnectInfo(s)| s));
    let rl = state.login_rate_limiter();
    if let LoginDecision::Deny { retry_after_secs } = rl.check(ip) {
        return Err(ApiError::too_many_requests(retry_after_secs));
    }

    let valid = match state.auth().verify_password(&body.password).await {
        Ok(v) => v,
        Err(crate::auth::AuthError::NotConfigured) => {
            return Err(ApiError::bad_request(
                "password authentication not configured",
            ))
        }
        Err(e) => {
            tracing::warn!(error = %e, "bcrypt verify failed");
            return Err(ApiError::internal("bcrypt error"));
        }
    };

    if !valid {
        rl.record_failure(ip);
        return Err(ApiError::unauthorized());
    }

    rl.record_success(ip);
    let token = Uuid::new_v4().to_string();
    state.set_token(token.clone());
    Ok(Json(LoginRes { token }))
}

// ============================================================================
// Client registry
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
    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(ApiError::bad_request("name must be non-empty"));
    }
    if name.len() > 255 {
        return Err(ApiError::bad_request("name too long").with_details("<= 255 bytes"));
    }
    if name.contains(|c: char| c == '/' || c == '\\' || c.is_control() || c.is_whitespace()) {
        return Err(ApiError::bad_request("name contains invalid characters"));
    }
    match state.registry().create(name, body.description) {
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
    // Serialise against a concurrent control-plane registration for the
    // same name. Without this, an in-flight registration could install a
    // ClientRecord after we cascade-remove it below.
    let _register_guard = state.lock_register_name(&name).await;

    if !state.registry().delete(&name) {
        return Err(ApiError::not_found("registry entry"));
    }

    // Cascade: stop listeners and sessions for any connected client with
    // this name, and remove its runtime records. The per-client guard
    // serialises us against a concurrent add_mapping / disconnect.
    let Some(client_id) = state.name_to_id().remove(&name).map(|(_, id)| id) else {
        return Ok(StatusCode::NO_CONTENT);
    };

    let _guard = state.lock_client(client_id).await;

    state.listeners_handle().stop_client(client_id).await;
    state.session_manager().remove_client_sessions(client_id);

    // Explicit cancel before removing the client record — any in-flight
    // per-session task sharing this cancel will unwind immediately.
    if let Some((_, mut rec)) = state.clients().remove(&client_id) {
        if let Some(online) = rec.online.take() {
            online.cancel.cancel();
        }
    }
    Ok(StatusCode::NO_CONTENT)
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

fn persist_client_mappings(state: &AppState, client_id: u64) {
    let Some(c) = state.clients().get(&client_id) else {
        return;
    };
    let name = c.name.clone();
    let jsons = c.mappings.iter().map(stored_mapping_to_json).collect();
    drop(c);
    state.registry().set_mappings(&name, jsons);
}

fn rejected_reason_for(report: &SyncReport, port: u16) -> Option<RejectReason> {
    report
        .rejected_ports
        .iter()
        .find(|(p, _)| *p == port)
        .map(|(_, r)| r.clone())
}

fn reject_reason_to_error(port: u16, reason: RejectReason) -> ApiError {
    match reason {
        RejectReason::OwnedByOther(owner) => ApiError::conflict("port in use by another client")
            .with_details(format!("port {} is owned by client {}", port, owner)),
        RejectReason::BindFailed(msg) => ApiError::conflict("failed to bind port")
            .with_details(format!("port {}: {}", port, msg)),
    }
}

async fn rollback_mapping(
    state: &AppState,
    client_id: u64,
    port: u16,
    previous: Option<StoredMapping>,
) {
    if let Some(mut c) = state.clients().get_mut(&client_id) {
        c.mappings.retain(|m| m.server_port != port);
        if let Some(prev) = previous {
            c.mappings.push(prev);
        }
    } else {
        return;
    }
    persist_client_mappings(state, client_id);
    push_config_if_online(state, client_id).await;
    let _ = state.listeners_handle().sync_client(client_id).await;
}

async fn push_config_if_online(state: &AppState, client_id: u64) {
    // IMPORTANT: Do NOT hold a DashMap Ref across `.await`.
    let (tx, pm) = {
        let Some(c) = state.clients().get(&client_id) else {
            return;
        };
        let Some(online) = c.online.as_ref() else {
            return;
        };
        let pm: Vec<PortMapping> = c.mappings.iter().map(stored_to_port_mapping).collect();
        (online.tx.clone(), pm)
    };
    let frame = ConfigPush::new(pm).to_frame(0);
    let _ = tx.send(frame).await;
}
