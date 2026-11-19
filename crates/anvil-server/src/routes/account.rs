//! Account management, session revocation, and atomic master password rotation (`/api/v1/account/*`).

use anvil_core::crypto::kdf::KDF_SALT_LEN;
use anvil_core::crypto::{KEY_LEN, KdfParams};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::db::{
    AuditLogInput, DevicePlatform, RotatePasswordInput, RotatePasswordOutcome, UserRole,
    VaultRepository,
};
use crate::error::{ApiError, ApiJson};
use crate::routes::auth::{decode_b64_envelope, decode_b64_fixed, user_to_kdf_params};
use crate::state::AppState;

const MAX_WRAPPED_VAULT_KEY_BYTES: usize = 512;

#[derive(Debug, Serialize)]
pub struct AccountMeResponse {
    pub user_id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub kdf_params: KdfParams,
    pub key_version: u32,
    pub sync_revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct RotatePasswordRequest {
    pub current_master_auth_hash_b64: String,
    pub new_master_auth_hash_b64: String,
    pub new_kdf_salt_b64: String,
    pub new_kdf_params: KdfParams,
    pub new_key_version: u32,
    pub new_encrypted_vault_key_b64: String,
    pub revoke_other_sessions: bool,
}

#[derive(Debug, Serialize)]
pub struct RotatePasswordResponse {
    pub key_version: u32,
    pub rotated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SessionSummary {
    pub id: Uuid,
    pub device_name: String,
    pub device_platform: DevicePlatform,
    pub last_ip: Option<String>,
    pub user_agent: Option<String>,
    pub last_used_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_current: bool,
}

#[derive(Debug, Deserialize)]
pub struct DeleteAccountRequest {
    pub current_master_auth_hash_b64: String,
}

/// Returns public account and KDF metadata for the authenticated user.
pub async fn get_me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<AccountMeResponse>, ApiError> {
    let user = state
        .db
        .find_user_by_id(auth.user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("ACCOUNT_NOT_FOUND", "Account no longer exists"))?;

    Ok(Json(AccountMeResponse {
        user_id: user.id,
        email: user.email.clone(),
        role: user.role,
        kdf_params: user_to_kdf_params(&user),
        key_version: user.key_version,
        sync_revision: user.sync_revision,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Verifies the current `MasterAuthHash` and atomically updates auth hash, KDF salt/params, and re-wrapped `VaultKey`.
pub async fn rotate_password(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<RotatePasswordRequest>,
) -> Result<Json<RotatePasswordResponse>, ApiError> {
    req.new_kdf_params
        .validate()
        .map_err(|e| ApiError::bad_request("INVALID_KDF_PARAMS", e.to_string()))?;

    let current_hash = decode_b64_fixed::<KEY_LEN>(
        "current_master_auth_hash_b64",
        &req.current_master_auth_hash_b64,
    )?;
    let new_hash =
        decode_b64_fixed::<KEY_LEN>("new_master_auth_hash_b64", &req.new_master_auth_hash_b64)?;
    let new_kdf_salt = decode_b64_fixed::<KDF_SALT_LEN>("new_kdf_salt_b64", &req.new_kdf_salt_b64)?;
    let new_encrypted_vault_key = decode_b64_envelope(
        "new_encrypted_vault_key_b64",
        &req.new_encrypted_vault_key_b64,
        MAX_WRAPPED_VAULT_KEY_BYTES,
    )?;

    let user = state
        .db
        .find_user_by_id(auth.user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("ACCOUNT_NOT_FOUND", "Account no longer exists"))?;

    let hasher_verify = state.hasher.clone();
    let cur_salt = user.server_auth_salt.clone();
    let cur_encoded = user.server_auth_hash.clone();
    let valid_current = tokio::task::spawn_blocking(move || {
        hasher_verify.verify_master_auth_hash(&current_hash, &cur_salt, &cur_encoded)
    })
    .await
    .map_err(|e| ApiError::internal(anyhow::anyhow!("password verification join error: {e}")))??;

    if !valid_current {
        return Err(ApiError::unauthorized(
            "INVALID_CREDENTIALS",
            "Current master password verification failed",
        ));
    }

    let hasher_rehash = state.hasher.clone();
    let (new_server_auth_salt, new_server_auth_hash) =
        tokio::task::spawn_blocking(move || hasher_rehash.hash_master_auth_hash(&new_hash))
            .await
            .map_err(|e| {
                ApiError::internal(anyhow::anyhow!("password hashing join error: {e}"))
            })??;

    let actor_ip = auth.client_ip.map(|ip| ip.to_string());
    match state
        .db
        .rotate_master_password(RotatePasswordInput {
            user_id: auth.user_id,
            current_session_id: auth.session_id,
            new_kdf_algorithm: "argon2id".to_owned(),
            new_kdf_memory_kib: req.new_kdf_params.memory_kib,
            new_kdf_iterations: req.new_kdf_params.iterations,
            new_kdf_parallelism: req.new_kdf_params.parallelism,
            new_kdf_salt: new_kdf_salt.to_vec(),
            new_server_auth_salt,
            new_server_auth_hash,
            new_key_version: req.new_key_version,
            new_encrypted_vault_key,
            revoke_other_sessions: req.revoke_other_sessions,
            actor_ip,
        })
        .await?
    {
        RotatePasswordOutcome::Updated {
            key_version,
            rotated_at,
        } => Ok(Json(RotatePasswordResponse {
            key_version,
            rotated_at,
        })),
        RotatePasswordOutcome::VersionMismatch => Err(ApiError::conflict(
            "KEY_VERSION_CONFLICT",
            "new_key_version must equal current key_version + 1",
        )),
        RotatePasswordOutcome::NotFound => Err(ApiError::not_found(
            "ACCOUNT_NOT_FOUND",
            "Account no longer exists",
        )),
    }
}

/// Lists active and recent sessions belonging strictly to the authenticated user.
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SessionSummary>>, ApiError> {
    let sessions = state.db.list_user_sessions(auth.user_id).await?;
    let out = sessions
        .into_iter()
        .map(|s| SessionSummary {
            id: s.id,
            device_name: s.device_name,
            device_platform: s.device_platform,
            last_ip: s.last_ip,
            user_agent: s.user_agent,
            last_used_at: s.last_used_at,
            expires_at: s.expires_at,
            revoked_at: s.revoked_at,
            created_at: s.created_at,
            is_current: s.id == auth.session_id,
        })
        .collect();
    Ok(Json(out))
}

/// Revokes a specific session owned by the authenticated user.
pub async fn revoke_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(session_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let revoked = state.db.revoke_session(auth.user_id, session_id).await?;
    if !revoked {
        return Err(ApiError::not_found(
            "SESSION_NOT_FOUND",
            "Session not found",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Permanently deletes the authenticated user's account and cascades all vault records after verifying `MasterAuthHash`.
pub async fn delete_me(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<DeleteAccountRequest>,
) -> Result<StatusCode, ApiError> {
    let current_hash = decode_b64_fixed::<KEY_LEN>(
        "current_master_auth_hash_b64",
        &req.current_master_auth_hash_b64,
    )?;

    let user = state
        .db
        .find_user_by_id(auth.user_id)
        .await?
        .ok_or_else(|| ApiError::not_found("ACCOUNT_NOT_FOUND", "Account no longer exists"))?;

    let hasher = state.hasher.clone();
    let salt = user.server_auth_salt.clone();
    let encoded = user.server_auth_hash.clone();
    let valid = tokio::task::spawn_blocking(move || {
        hasher.verify_master_auth_hash(&current_hash, &salt, &encoded)
    })
    .await
    .map_err(|e| ApiError::internal(anyhow::anyhow!("password verification join error: {e}")))??;

    if !valid {
        return Err(ApiError::unauthorized(
            "INVALID_CREDENTIALS",
            "Current master password verification failed",
        ));
    }

    let actor_ip = auth.client_ip.map(|ip| ip.to_string());
    let _ = state
        .db
        .insert_audit_log(AuditLogInput {
            user_id: None,
            event_type: "account_deleted",
            actor_ip: actor_ip.as_deref(),
            session_id: Some(auth.session_id),
            metadata_json: Some(format!(r#"{{"deleted_user_id":"{}"}}"#, auth.user_id)),
        })
        .await;

    state.db.delete_user_account(auth.user_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
