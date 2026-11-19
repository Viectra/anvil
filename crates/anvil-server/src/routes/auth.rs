//! Zero-Knowledge authentication endpoints (`/api/v1/auth/*`).

use anvil_core::crypto::kdf::KDF_SALT_LEN;
use anvil_core::crypto::{ENVELOPE_VERSION_V1, KEY_LEN, KdfParams, MIN_ENVELOPE_LEN};
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::jwt::REFRESH_TOKEN_TTL_DAYS;
use crate::auth::middleware::{AuthUser, ClientIp};
use crate::auth::password::{
    compute_fake_prelogin_salt, generate_opaque_token, hash_opaque_token, normalize_email,
};
use crate::db::{
    AuditLogInput, CreateSessionInput, DevicePlatform, RegisterOutcome, RegisterUserInput,
    RotateRefreshOutcome, UserRecord, UserRole, VaultRepository,
};
use crate::error::{ApiError, ApiJson};
use crate::state::AppState;

const MAX_WRAPPED_VAULT_KEY_BYTES: usize = 512;
const MAX_DEVICE_NAME_LEN: usize = 128;
const MAX_USER_AGENT_LEN: usize = 512;

#[derive(Debug, Deserialize)]
pub struct PreloginRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct PreloginResponse {
    pub kdf_algorithm: anvil_core::crypto::KdfAlgorithm,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub kdf_salt_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub user_id: Uuid,
    pub email: String,
    pub kdf_params: KdfParams,
    pub kdf_salt_b64: String,
    pub master_auth_hash_b64: String,
    pub encrypted_vault_key_b64: String,
    pub invite_token: Option<String>,
    pub device_name: Option<String>,
    pub device_platform: Option<DevicePlatform>,
}

#[derive(Debug, Serialize)]
pub struct PublicUserProfile {
    pub user_id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub kdf_params: KdfParams,
    pub key_version: u32,
    pub sync_revision: i64,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    pub user: PublicUserProfile,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub master_auth_hash_b64: String,
    pub device_name: Option<String>,
    pub device_platform: Option<DevicePlatform>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
    pub user_id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub key_version: u32,
    pub encrypted_vault_key_b64: String,
    pub sync_revision: i64,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
pub struct RefreshResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub refresh_token: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct LogoutRequest {
    pub refresh_token: Option<String>,
}

/// Decodes a Base64 field with exact byte length validation.
pub fn decode_b64_fixed<const N: usize>(field: &str, raw: &str) -> Result<[u8; N], ApiError> {
    let bytes = STANDARD.decode(raw.trim()).map_err(|_| {
        ApiError::bad_request(
            "INVALID_BASE64",
            format!("Field `{field}` is not valid base64"),
        )
    })?;
    if bytes.len() != N {
        return Err(ApiError::bad_request(
            "INVALID_FIELD_LENGTH",
            format!("Field `{field}` must decode to {N} bytes"),
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Decodes and validates a versioned binary AEAD envelope (`0x01 || nonce(24) || ct || tag(16)`).
pub fn decode_b64_envelope(field: &str, raw: &str, max_bytes: usize) -> Result<Vec<u8>, ApiError> {
    let bytes = STANDARD.decode(raw.trim()).map_err(|_| {
        ApiError::bad_request(
            "INVALID_BASE64",
            format!("Field `{field}` is not valid base64"),
        )
    })?;
    validate_envelope_bytes(field, &bytes, max_bytes)?;
    Ok(bytes)
}

/// Validates version byte, minimum header+tag length, and upper size cap on a binary envelope.
pub fn validate_envelope_bytes(
    field: &str,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<(), ApiError> {
    if bytes.len() < MIN_ENVELOPE_LEN || bytes.len() > max_bytes {
        return Err(ApiError::bad_request(
            "INVALID_ENVELOPE",
            format!("Field `{field}` must be between {MIN_ENVELOPE_LEN} and {max_bytes} bytes"),
        ));
    }
    if bytes[0] != ENVELOPE_VERSION_V1 {
        return Err(ApiError::bad_request(
            "UNSUPPORTED_ENVELOPE_VERSION",
            format!("Field `{field}` must start with envelope version 0x01"),
        ));
    }
    Ok(())
}

pub fn user_to_kdf_params(user: &UserRecord) -> KdfParams {
    KdfParams {
        algorithm: anvil_core::crypto::KdfAlgorithm::Argon2id,
        memory_kib: user.kdf_memory_kib,
        iterations: user.kdf_iterations,
        parallelism: user.kdf_parallelism,
    }
}

fn sanitize_device_name(raw: Option<String>) -> String {
    let trimmed = raw
        .unwrap_or_else(|| "Anvil Client".to_owned())
        .trim()
        .to_owned();
    if trimmed.is_empty() {
        return "Anvil Client".to_owned();
    }
    trimmed.chars().take(MAX_DEVICE_NAME_LEN).collect()
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_USER_AGENT_LEN).collect())
}

/// Returns a user's KDF parameters or a deterministic fake salt to prevent email enumeration.
pub async fn prelogin(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<PreloginRequest>,
) -> Result<Json<PreloginResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    if let Some(user) = state.db.find_user_by_email(&email).await? {
        return Ok(Json(PreloginResponse {
            kdf_algorithm: anvil_core::crypto::KdfAlgorithm::Argon2id,
            kdf_memory_kib: user.kdf_memory_kib,
            kdf_iterations: user.kdf_iterations,
            kdf_parallelism: user.kdf_parallelism,
            kdf_salt_b64: STANDARD.encode(&user.kdf_salt),
        }));
    }

    let defaults = KdfParams::default();
    let fake_salt = compute_fake_prelogin_salt(&state.config.prelogin_secret, &email)?;
    Ok(Json(PreloginResponse {
        kdf_algorithm: defaults.algorithm,
        kdf_memory_kib: defaults.memory_kib,
        kdf_iterations: defaults.iterations,
        kdf_parallelism: defaults.parallelism,
        kdf_salt_b64: STANDARD.encode(fake_salt),
    }))
}

/// Registers a new user account, consuming a single/multi-use invite token when signups are closed.
pub async fn register(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let email = normalize_email(&req.email)?;
    req.kdf_params
        .validate()
        .map_err(|e| ApiError::bad_request("INVALID_KDF_PARAMS", e.to_string()))?;

    let kdf_salt = decode_b64_fixed::<KDF_SALT_LEN>("kdf_salt_b64", &req.kdf_salt_b64)?;
    let master_auth_hash =
        decode_b64_fixed::<KEY_LEN>("master_auth_hash_b64", &req.master_auth_hash_b64)?;
    let encrypted_vault_key = decode_b64_envelope(
        "encrypted_vault_key_b64",
        &req.encrypted_vault_key_b64,
        MAX_WRAPPED_VAULT_KEY_BYTES,
    )?;

    let invite_token_hash = req
        .invite_token
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|tok| hash_opaque_token(tok).to_vec());

    if !state.config.allow_signups && invite_token_hash.is_none() {
        return Err(ApiError::forbidden(
            "SIGNUPS_DISABLED",
            "Registration requires a valid invitation token",
        ));
    }

    let hasher = state.hasher.clone();
    let (server_auth_salt, server_auth_hash) =
        tokio::task::spawn_blocking(move || hasher.hash_master_auth_hash(&master_auth_hash))
            .await
            .map_err(|e| {
                ApiError::internal(anyhow::anyhow!("password hashing join error: {e}"))
            })??;

    let (refresh_token, refresh_hash) = generate_opaque_token()?;
    let session_id = Uuid::new_v4();
    let token_family_id = Uuid::new_v4();
    let last_ip = client_ip.map(|ip| ip.to_string());
    let user_agent = extract_user_agent(&headers);

    let outcome = state
        .db
        .register_user_with_session(RegisterUserInput {
            user_id: req.user_id,
            email: email.clone(),
            kdf_algorithm: "argon2id".to_owned(),
            kdf_memory_kib: req.kdf_params.memory_kib,
            kdf_iterations: req.kdf_params.iterations,
            kdf_parallelism: req.kdf_params.parallelism,
            kdf_salt: kdf_salt.to_vec(),
            server_auth_salt,
            server_auth_hash,
            encrypted_vault_key,
            invite_token_hash,
            require_invitation: !state.config.allow_signups,
            session: CreateSessionInput {
                session_id,
                token_family_id,
                refresh_token_hash: refresh_hash.to_vec(),
                device_name: sanitize_device_name(req.device_name),
                device_platform: req.device_platform.unwrap_or_default(),
                user_agent,
                last_ip,
                expires_at: Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS),
            },
        })
        .await?;

    let user = match outcome {
        RegisterOutcome::Created(user) => *user,
        RegisterOutcome::EmailExists => {
            return Err(ApiError::conflict(
                "EMAIL_ALREADY_REGISTERED",
                "An account with this email already exists",
            ));
        }
        RegisterOutcome::UserIdConflict => {
            return Err(ApiError::conflict(
                "USER_ID_CONFLICT",
                "Specified user_id is unavailable",
            ));
        }
        RegisterOutcome::InvalidInvitation => {
            return Err(ApiError::forbidden(
                "INVALID_INVITATION",
                "Invitation token is missing, expired, revoked, or exhausted",
            ));
        }
    };

    let (access_token, expires_in) = state
        .jwt
        .issue_access_token(user.id, user.role, session_id)?;

    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            access_token,
            token_type: "Bearer",
            expires_in,
            refresh_token: refresh_token.to_string(),
            user: PublicUserProfile {
                user_id: user.id,
                email: user.email.clone(),
                role: user.role,
                kdf_params: user_to_kdf_params(&user),
                key_version: user.key_version,
                sync_revision: user.sync_revision,
            },
        }),
    ))
}

/// Verifies `MasterAuthHash` against Argon2id(+pepper) and opens a rotating refresh session.
pub async fn login(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    headers: HeaderMap,
    ApiJson(req): ApiJson<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let email = normalize_email(&req.email)?;
    let master_auth_hash =
        decode_b64_fixed::<KEY_LEN>("master_auth_hash_b64", &req.master_auth_hash_b64)?;
    let last_ip = client_ip.map(|ip| ip.to_string());

    let maybe_user = state.db.find_user_by_email(&email).await?;
    let Some(user) = maybe_user else {
        let hasher = state.hasher.clone();
        let _ = tokio::task::spawn_blocking(move || hasher.dummy_verify()).await;
        let _ = state
            .db
            .insert_audit_log(AuditLogInput {
                user_id: None,
                event_type: "login_failed",
                actor_ip: last_ip.as_deref(),
                session_id: None,
                metadata_json: Some(r#"{"reason":"unknown_account"}"#.to_owned()),
            })
            .await;
        return Err(ApiError::unauthorized(
            "INVALID_CREDENTIALS",
            "Invalid email or master password",
        ));
    };

    if !user.is_active {
        let hasher = state.hasher.clone();
        let _ = tokio::task::spawn_blocking(move || hasher.dummy_verify()).await;
        let _ = state
            .db
            .insert_audit_log(AuditLogInput {
                user_id: Some(user.id),
                event_type: "login_failed",
                actor_ip: last_ip.as_deref(),
                session_id: None,
                metadata_json: Some(r#"{"reason":"account_disabled"}"#.to_owned()),
            })
            .await;
        return Err(ApiError::unauthorized(
            "INVALID_CREDENTIALS",
            "Invalid email or master password",
        ));
    }

    let hasher = state.hasher.clone();
    let salt = user.server_auth_salt.clone();
    let encoded_hash = user.server_auth_hash.clone();
    let verified = tokio::task::spawn_blocking(move || {
        hasher.verify_master_auth_hash(&master_auth_hash, &salt, &encoded_hash)
    })
    .await
    .map_err(|e| ApiError::internal(anyhow::anyhow!("password verification join error: {e}")))??;

    if !verified {
        let _ = state
            .db
            .insert_audit_log(AuditLogInput {
                user_id: Some(user.id),
                event_type: "login_failed",
                actor_ip: last_ip.as_deref(),
                session_id: None,
                metadata_json: Some(r#"{"reason":"bad_password"}"#.to_owned()),
            })
            .await;
        return Err(ApiError::unauthorized(
            "INVALID_CREDENTIALS",
            "Invalid email or master password",
        ));
    }

    let (refresh_token, refresh_hash) = generate_opaque_token()?;
    let session_id = Uuid::new_v4();
    let token_family_id = Uuid::new_v4();
    let user_agent = extract_user_agent(&headers);

    state
        .db
        .create_session(
            user.id,
            CreateSessionInput {
                session_id,
                token_family_id,
                refresh_token_hash: refresh_hash.to_vec(),
                device_name: sanitize_device_name(req.device_name),
                device_platform: req.device_platform.unwrap_or_default(),
                user_agent,
                last_ip: last_ip.clone(),
                expires_at: Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS),
            },
        )
        .await?;

    let _ = state
        .db
        .insert_audit_log(AuditLogInput {
            user_id: Some(user.id),
            event_type: "login_succeeded",
            actor_ip: last_ip.as_deref(),
            session_id: Some(session_id),
            metadata_json: None,
        })
        .await;

    let (access_token, expires_in) = state
        .jwt
        .issue_access_token(user.id, user.role, session_id)?;

    Ok(Json(LoginResponse {
        access_token,
        token_type: "Bearer",
        expires_in,
        refresh_token: refresh_token.to_string(),
        user_id: user.id,
        email: user.email,
        role: user.role,
        key_version: user.key_version,
        encrypted_vault_key_b64: STANDARD.encode(&user.encrypted_vault_key),
        sync_revision: user.sync_revision,
    }))
}

/// Performs single-use refresh token rotation, revoking the full session family on replay.
pub async fn refresh(
    State(state): State<AppState>,
    ClientIp(client_ip): ClientIp,
    ApiJson(req): ApiJson<RefreshRequest>,
) -> Result<Json<RefreshResponse>, ApiError> {
    let presented = req.refresh_token.trim();
    if presented.is_empty() {
        return Err(ApiError::unauthorized(
            "INVALID_REFRESH_TOKEN",
            "Missing refresh token",
        ));
    }

    let presented_hash = hash_opaque_token(presented);
    let (new_refresh_token, new_hash) = generate_opaque_token()?;
    let last_ip = client_ip.map(|ip| ip.to_string());
    let new_expires_at = Utc::now() + Duration::days(REFRESH_TOKEN_TTL_DAYS);

    match state
        .db
        .rotate_refresh_token(
            &presented_hash,
            &new_hash,
            new_expires_at,
            last_ip.as_deref(),
        )
        .await?
    {
        RotateRefreshOutcome::Rotated { session, user } => {
            let (access_token, expires_in) = state
                .jwt
                .issue_access_token(user.id, user.role, session.id)?;
            Ok(Json(RefreshResponse {
                access_token,
                token_type: "Bearer",
                expires_in,
                refresh_token: new_refresh_token.to_string(),
            }))
        }
        RotateRefreshOutcome::ReuseDetected { .. } => Err(ApiError::unauthorized(
            "TOKEN_REUSE_DETECTED",
            "Refresh token reuse detected; session family revoked",
        )),
        RotateRefreshOutcome::InvalidOrExpired => Err(ApiError::unauthorized(
            "INVALID_REFRESH_TOKEN",
            "Invalid, revoked, or expired refresh token",
        )),
    }
}

/// Revokes the active session associated with the authenticated access token.
pub async fn logout(
    State(state): State<AppState>,
    auth: AuthUser,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    if !body.is_empty() {
        let _: LogoutRequest = serde_json::from_slice(&body)
            .map_err(|e| ApiError::bad_request("INVALID_JSON", e.to_string()))?;
    }

    state
        .db
        .revoke_session(auth.user_id, auth.session_id)
        .await?;
    let actor_ip = auth.client_ip.map(|ip| ip.to_string());
    let _ = state
        .db
        .insert_audit_log(AuditLogInput {
            user_id: Some(auth.user_id),
            event_type: "session_logged_out",
            actor_ip: actor_ip.as_deref(),
            session_id: Some(auth.session_id),
            metadata_json: None,
        })
        .await;

    Ok(StatusCode::NO_CONTENT)
}
