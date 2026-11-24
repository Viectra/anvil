//! Loopback-only HTTP IPC bridge exposing `DesktopCommandHost` to standalone local UI sessions.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::commands::DesktopCommandHost;

pub const BRIDGE_TOKEN_HEADER: &str = "x-anvil-bridge-token";
pub const BRIDGE_TOKEN_ENV: &str = "ANVIL_DESKTOP_BRIDGE_TOKEN";
pub const MIN_BRIDGE_TOKEN_LEN: usize = 32;
pub const MAX_IPC_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum HttpBridgeError {
    #[error("desktop http bridge only binds to loopback addresses, got {0}")]
    NonLoopbackAddress(SocketAddr),
    #[error("desktop bridge token must be at least {MIN_BRIDGE_TOKEN_LEN} characters")]
    WeakToken,
    #[error("http bridge I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
struct BridgeState {
    host: Arc<DesktopCommandHost>,
    token: Zeroizing<String>,
}

#[derive(Deserialize)]
struct IpcRequest {
    command: String,
    #[serde(default)]
    payload: serde_json::Value,
}

fn json_response(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body,
    )
        .into_response()
}

fn error_json(status: StatusCode, message: &str) -> Response {
    let encoded = serde_json::to_string(message).unwrap_or_else(|_| "\"error\"".to_owned());
    json_response(status, format!("{{\"ok\":false,\"error\":{encoded}}}"))
}

fn token_matches(headers: &HeaderMap, expected: &str) -> bool {
    let Some(raw) = headers.get(BRIDGE_TOKEN_HEADER) else {
        return false;
    };
    let Ok(provided) = raw.to_str() else {
        return false;
    };
    bool::from(provided.as_bytes().ct_eq(expected.as_bytes()))
}

async fn handle_health() -> Response {
    let version =
        serde_json::to_string(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| "\"1.0.0\"".to_owned());
    json_response(
        StatusCode::OK,
        format!("{{\"status\":\"ok\",\"version\":{version}}}"),
    )
}

async fn handle_ipc(
    State(state): State<BridgeState>,
    headers: HeaderMap,
    Json(req): Json<IpcRequest>,
) -> Response {
    if !token_matches(&headers, &state.token) {
        return error_json(StatusCode::UNAUTHORIZED, "unauthorized bridge token");
    }

    let payload_str = if req.payload.is_null() {
        "{}".to_owned()
    } else {
        match serde_json::to_string(&req.payload) {
            Ok(encoded) => encoded,
            Err(err) => {
                return error_json(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid IPC payload JSON: {err}"),
                );
            }
        }
    };

    match state.host.dispatch_ipc(&req.command, &payload_str).await {
        Ok(data) => json_response(StatusCode::OK, format!("{{\"ok\":true,\"data\":{data}}}")),
        Err(err) => error_json(StatusCode::BAD_REQUEST, &err.to_string()),
    }
}

/// Builds the authenticated loopback Axum router for local Desktop IPC.
pub fn build_bridge_router(
    host: Arc<DesktopCommandHost>,
    token: String,
) -> Result<Router, HttpBridgeError> {
    if token.len() < MIN_BRIDGE_TOKEN_LEN {
        return Err(HttpBridgeError::WeakToken);
    }

    let state = BridgeState {
        host,
        token: Zeroizing::new(token),
    };

    Ok(Router::new()
        .route("/api/desktop-health", get(handle_health))
        .route("/api/desktop-ipc", post(handle_ipc))
        .layer(DefaultBodyLimit::max(MAX_IPC_BODY_BYTES))
        .with_state(state))
}

/// Binds and serves the Desktop HTTP IPC bridge on a loopback `SocketAddr`, locking RAM on exit.
pub async fn serve_http_bridge(
    host: Arc<DesktopCommandHost>,
    bind_addr: SocketAddr,
    token: String,
) -> Result<(), HttpBridgeError> {
    if !bind_addr.ip().is_loopback() {
        return Err(HttpBridgeError::NonLoopbackAddress(bind_addr));
    }

    let router = build_bridge_router(Arc::clone(&host), token)?;
    let listener = TcpListener::bind(bind_addr).await?;

    let serve_result = axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;

    let _ = host.cmd_lock().await;
    serve_result?;
    Ok(())
}
