//! Account management, session revocation, and atomic master password rotation (`/api/v1/account/*`).

use anvil_core::crypto::kdf::KDF_SALT_LEN;
use anvil_core::crypto::{KEY_LEN, KdfParams};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::auth::password::normalize_email;
use crate::db::{
    AuditLogInput, BlobReencryptUpsert, DevicePlatform, FolderUpsertInput, ItemUpsertInput,
    RotatePasswordInput, RotatePasswordOutcome, RotateVaultKeyInput, RotateVaultKeyOutcome,
    UpdateEmailOutcome, UserRole, VaultRepository,
};
use crate::error::{ApiError, ApiJson};
use crate::routes::auth::{decode_b64_envelope, decode_b64_fixed, user_to_kdf_params};
use crate::routes::vault::MAX_BLOB_BYTES;
use crate::state::AppState;

const MAX_WRAPPED_VAULT_KEY_BYTES: usize = 512;
const MAX_REENCRYPT_ENVELOPE_BYTES: usize = 1_048_576;
const MAX_AVATAR_UPLOAD_B64_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct AccountMeResponse {
    pub user_id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub kdf_params: KdfParams,
    pub key_version: u32,
    pub sync_revision: i64,
    pub avatar_b64: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct ChangeEmailRequest {
    pub current_master_auth_hash_b64: String,
    pub new_email: String,
}

#[derive(Debug, Serialize)]
pub struct ChangeEmailResponse {
    pub email: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UploadAvatarRequest {
    pub image_b64: String,
}

#[derive(Debug, Serialize)]
pub struct AvatarResponse {
    pub avatar_b64: String,
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

#[derive(Debug, Deserialize)]
pub struct ReencryptRecordDto {
    pub id: Uuid,
    pub encrypted_data_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct ReencryptBlobDto {
    pub id: Uuid,
    pub item_id: Uuid,
    pub encrypted_blob_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct RotateVaultKeyRequest {
    pub current_master_auth_hash_b64: String,
    pub base_revision: i64,
    pub new_key_version: u32,
    pub new_encrypted_vault_key_b64: String,
    pub folders: Vec<ReencryptRecordDto>,
    pub items: Vec<ReencryptRecordDto>,
    pub blobs: Vec<ReencryptBlobDto>,
    pub revoke_other_sessions: bool,
}

#[derive(Debug, Serialize)]
pub struct RotateVaultKeyResponse {
    pub key_version: u32,
    pub new_revision: i64,
    pub rotated_at: DateTime<Utc>,
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
        avatar_b64: user.avatar_png.as_deref().map(|b| STANDARD.encode(b)),
        created_at: user.created_at,
        updated_at: user.updated_at,
    }))
}

/// Verifies current `MasterAuthHash` and updates the authenticated user's login email.
pub async fn change_email(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<ChangeEmailRequest>,
) -> Result<Json<ChangeEmailResponse>, ApiError> {
    let normalized = normalize_email(&req.new_email)?;
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

    let actor_ip = auth.client_ip.map(|ip| ip.to_string());
    if !valid {
        let _ = state
            .db
            .insert_audit_log(AuditLogInput {
                user_id: Some(auth.user_id),
                event_type: "email_change_failed",
                actor_ip: actor_ip.as_deref(),
                session_id: Some(auth.session_id),
                metadata_json: Some(r#"{"reason":"bad_password"}"#.to_owned()),
            })
            .await;
        return Err(ApiError::unauthorized(
            "INVALID_CREDENTIALS",
            "Current master password verification failed",
        ));
    }

    if normalized == user.email {
        return Ok(Json(ChangeEmailResponse {
            email: user.email,
            updated_at: user.updated_at,
        }));
    }

    match state
        .db
        .update_user_email(
            auth.user_id,
            &normalized,
            actor_ip.as_deref(),
            Some(auth.session_id),
        )
        .await?
    {
        UpdateEmailOutcome::Updated { email, updated_at } => {
            Ok(Json(ChangeEmailResponse { email, updated_at }))
        }
        UpdateEmailOutcome::EmailExists => Err(ApiError::conflict(
            "EMAIL_ALREADY_REGISTERED",
            "An account with this email already exists",
        )),
        UpdateEmailOutcome::NotFound => Err(ApiError::not_found(
            "ACCOUNT_NOT_FOUND",
            "Account no longer exists",
        )),
    }
}

/// Validates image magic bytes (PNG/JPEG/WebP), strips EXIF metadata, resizes <= 256x256, and stores PNG avatar.
pub async fn upload_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<UploadAvatarRequest>,
) -> Result<Json<AvatarResponse>, ApiError> {
    let trimmed = req.image_b64.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_AVATAR_UPLOAD_B64_BYTES {
        return Err(ApiError::bad_request(
            "INVALID_IMAGE",
            "Avatar image payload is empty or exceeds maximum upload size",
        ));
    }
    let raw_bytes = STANDARD
        .decode(trimmed)
        .map_err(|_| ApiError::bad_request("INVALID_BASE64", "Invalid image_b64 payload"))?;

    let processed =
        tokio::task::spawn_blocking(move || anvil_core::media::process_avatar_image(&raw_bytes))
            .await
            .map_err(|e| ApiError::internal(anyhow::anyhow!("image processing join error: {e}")))?
            .map_err(|e| ApiError::bad_request("INVALID_IMAGE", e.to_string()))?;

    let actor_ip = auth.client_ip.map(|ip| ip.to_string());
    let saved = state
        .db
        .update_user_avatar(
            auth.user_id,
            Some(&processed.bytes),
            actor_ip.as_deref(),
            Some(auth.session_id),
        )
        .await?;
    if !saved {
        return Err(ApiError::not_found(
            "ACCOUNT_NOT_FOUND",
            "Account no longer exists",
        ));
    }

    Ok(Json(AvatarResponse {
        avatar_b64: STANDARD.encode(&processed.bytes),
    }))
}

/// Removes the authenticated user's profile picture.
pub async fn delete_avatar(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<StatusCode, ApiError> {
    let actor_ip = auth.client_ip.map(|ip| ip.to_string());
    let updated = state
        .db
        .update_user_avatar(
            auth.user_id,
            None,
            actor_ip.as_deref(),
            Some(auth.session_id),
        )
        .await?;
    if !updated {
        return Err(ApiError::not_found(
            "ACCOUNT_NOT_FOUND",
            "Account no longer exists",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
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

/// Atomically rotates a compromised `VaultKey` across the user's wrapped key and all active vault ciphertexts.
pub async fn rotate_vault_key(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<RotateVaultKeyRequest>,
) -> Result<Json<RotateVaultKeyResponse>, ApiError> {
    let current_hash = decode_b64_fixed::<KEY_LEN>(
        "current_master_auth_hash_b64",
        &req.current_master_auth_hash_b64,
    )?;
    let new_encrypted_vault_key = decode_b64_envelope(
        "new_encrypted_vault_key_b64",
        &req.new_encrypted_vault_key_b64,
        MAX_WRAPPED_VAULT_KEY_BYTES,
    )?;

    let mut folders = Vec::with_capacity(req.folders.len());
    for folder in req.folders {
        folders.push(FolderUpsertInput {
            id: folder.id,
            encrypted_data: decode_b64_envelope(
                "folders.encrypted_data_b64",
                &folder.encrypted_data_b64,
                MAX_REENCRYPT_ENVELOPE_BYTES,
            )?,
        });
    }

    let mut items = Vec::with_capacity(req.items.len());
    for item in req.items {
        items.push(ItemUpsertInput {
            id: item.id,
            encrypted_data: decode_b64_envelope(
                "items.encrypted_data_b64",
                &item.encrypted_data_b64,
                MAX_REENCRYPT_ENVELOPE_BYTES,
            )?,
        });
    }

    let mut blobs = Vec::with_capacity(req.blobs.len());
    for blob in req.blobs {
        let raw_blob = STANDARD
            .decode(blob.encrypted_blob_b64.trim())
            .map_err(|_| ApiError::bad_request("INVALID_BASE64", "Invalid encrypted_blob_b64"))?;
        if raw_blob.is_empty() || raw_blob.len() > MAX_BLOB_BYTES {
            return Err(ApiError::bad_request(
                "BLOB_SIZE_INVALID",
                format!("Encrypted blob must be 1..={MAX_BLOB_BYTES} bytes"),
            ));
        }
        let sha = Sha256::digest(&raw_blob).to_vec();
        blobs.push(BlobReencryptUpsert {
            id: blob.id,
            item_id: blob.item_id,
            encrypted_blob: raw_blob,
            sha256_ciphertext: sha,
        });
    }

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
    match state
        .db
        .rotate_vault_key(RotateVaultKeyInput {
            user_id: auth.user_id,
            current_session_id: auth.session_id,
            base_revision: req.base_revision,
            new_key_version: req.new_key_version,
            new_encrypted_vault_key,
            folders,
            items,
            blobs,
            revoke_other_sessions: req.revoke_other_sessions,
            actor_ip,
        })
        .await?
    {
        RotateVaultKeyOutcome::Rotated {
            key_version,
            new_revision,
            rotated_at,
        } => Ok(Json(RotateVaultKeyResponse {
            key_version,
            new_revision,
            rotated_at,
        })),
        RotateVaultKeyOutcome::VersionMismatch => Err(ApiError::conflict(
            "KEY_VERSION_CONFLICT",
            "new_key_version must equal current key_version + 1",
        )),
        RotateVaultKeyOutcome::RevisionConflict(_) => Err(ApiError::conflict(
            "SYNC_REVISION_CONFLICT",
            "Vault revision changed concurrently; synchronize before rotating VaultKey",
        )),
        RotateVaultKeyOutcome::IncompleteBatch {
            missing_folders,
            missing_items,
            missing_blobs,
        } => Err(ApiError::conflict(
            "INCOMPLETE_REENCRYPT_BATCH",
            format!(
                "All active folders/items/blobs must be re-encrypted atomically (missing folders={missing_folders}, items={missing_items}, blobs={missing_blobs})"
            ),
        )),
        RotateVaultKeyOutcome::NotFound => Err(ApiError::not_found(
            "ACCOUNT_NOT_FOUND",
            "Account no longer exists",
        )),
    }
}
