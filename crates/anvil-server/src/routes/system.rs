//! System health and instance discovery endpoints (`/api/v1/health`, `/api/v1/meta`).

use anvil_core::crypto::KdfParams;
use axum::Json;
use axum::extract::State;
use serde::Serialize;

use crate::db::VaultRepository;
use crate::error::ApiError;
use crate::routes::vault::MAX_BLOB_BYTES;
use crate::state::AppState;

/// Health check payload returned by `GET /api/v1/health`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub db_ok: bool,
}

/// Public server metadata returned by `GET /api/v1/meta`.
#[derive(Debug, Serialize)]
pub struct MetaResponse {
    pub signups_enabled: bool,
    pub server_version: &'static str,
    pub default_kdf: KdfParams,
    pub favicon_proxy_enabled: bool,
    pub max_blob_bytes: usize,
}

/// Verifies database connectivity and returns `503 Service Unavailable` if the backend fails.
pub async fn health(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    if state.db.health_check().await.is_err() {
        return Err(ApiError::service_unavailable(
            "DATABASE_UNAVAILABLE",
            "Database connectivity check failed",
        ));
    }

    Ok(Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        db_ok: true,
    }))
}

/// Exposes non-sensitive server policy and default client KDF parameters.
pub async fn meta(State(state): State<AppState>) -> Json<MetaResponse> {
    Json(MetaResponse {
        signups_enabled: state.config.allow_signups,
        server_version: env!("CARGO_PKG_VERSION"),
        default_kdf: KdfParams::default(),
        favicon_proxy_enabled: state.config.enable_favicon_proxy && cfg!(feature = "favicon-proxy"),
        max_blob_bytes: MAX_BLOB_BYTES,
    })
}
