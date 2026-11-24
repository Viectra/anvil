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
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
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

/// Running handle for the embedded local Desktop UI HTTP bridge.
pub struct EmbeddedBridgeHandle {
    pub url: String,
    host: Arc<DesktopCommandHost>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl EmbeddedBridgeHandle {
    /// Gracefully stops the local UI HTTP bridge and locks volatile vault memory.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
        let _ = self.host.cmd_lock().await;
    }
}

fn escape_inline_script_json(raw_json: &str) -> String {
    raw_json
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('/', "\\u002f")
}

/// Builds a loopback Axum router serving both the embedded HTML UI and authenticated Desktop IPC.
pub fn build_embedded_ui_router(
    host: Arc<DesktopCommandHost>,
    token: String,
    default_server_url: String,
    ui_html: &'static str,
) -> Result<Router, HttpBridgeError> {
    let api_router = build_bridge_router(host, token.clone())?;

    let token_json = serde_json::to_string(&token).unwrap_or_else(|_| "\"\"".to_owned());
    let server_url_json =
        serde_json::to_string(&default_server_url).unwrap_or_else(|_| "\"\"".to_owned());

    let rendered = Arc::new(
        ui_html
            .replace(
                "__ANVIL_BOOTSTRAP_TOKEN__",
                &escape_inline_script_json(&token_json),
            )
            .replace(
                "__ANVIL_DEFAULT_SERVER_URL__",
                &escape_inline_script_json(&server_url_json),
            ),
    );

    let index_handler = {
        let html = Arc::clone(&rendered);
        move || {
            let body = (*html).clone();
            async move {
                (
                    StatusCode::OK,
                    [
                        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                        (header::CACHE_CONTROL, "no-store"),
                        (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                        (header::X_FRAME_OPTIONS, "DENY"),
                        (
                            header::CONTENT_SECURITY_POLICY,
                            "default-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
                        ),
                    ],
                    body,
                )
                    .into_response()
            }
        }
    };

    Ok(api_router.route("/", get(index_handler)))
}

/// Binds the embedded Desktop UI + IPC server to an ephemeral loopback port.
pub async fn spawn_embedded_ui_bridge(
    host: Arc<DesktopCommandHost>,
    token: String,
    default_server_url: String,
    ui_html: &'static str,
) -> Result<EmbeddedBridgeHandle, HttpBridgeError> {
    let router = build_embedded_ui_router(Arc::clone(&host), token, default_server_url, ui_html)?;
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    Ok(EmbeddedBridgeHandle {
        url: format!("http://127.0.0.1:{}", local_addr.port()),
        host,
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}
