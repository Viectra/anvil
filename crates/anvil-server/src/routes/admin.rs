//! Administrative user and invitation management endpoints (`/api/v1/admin/*`).

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AdminUser;
use crate::auth::password::{generate_opaque_token, normalize_email};
use crate::db::{
    AdminUserSummary, AuditLogInput, InvitationRecord, UpdateUserAdminInput,
    UpdateUserAdminOutcome, UserRole, VaultRepository,
};
use crate::error::{ApiError, ApiJson};
use crate::state::AppState;

const MAX_INVITE_USES: i32 = 1_000;
const MAX_INVITE_HOURS: i64 = 24 * 365;

#[derive(Debug, Deserialize)]
pub struct CreateInvitationRequest {
    pub invited_email: Option<String>,
    pub max_uses: Option<i32>,
    pub expires_in_hours: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct CreateInvitationResponse {
    pub id: Uuid,
    pub invite_token: String,
    pub invite_url: String,
    pub invited_email: Option<String>,
    pub max_uses: i32,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAdminUserRequest {
    pub is_active: Option<bool>,
    pub role: Option<UserRole>,
}

/// Creates a single- or multi-use signup invitation and reveals the raw token once.
pub async fn create_invitation(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    ApiJson(req): ApiJson<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<CreateInvitationResponse>), ApiError> {
    let max_uses = req.max_uses.unwrap_or(1);
    if !(1..=MAX_INVITE_USES).contains(&max_uses) {
        return Err(ApiError::bad_request(
            "INVALID_MAX_USES",
            format!("max_uses must be between 1 and {MAX_INVITE_USES}"),
        ));
    }

    let expires_in_hours = req.expires_in_hours.unwrap_or(72);
    if !(1..=MAX_INVITE_HOURS).contains(&expires_in_hours) {
        return Err(ApiError::bad_request(
            "INVALID_EXPIRATION",
            format!("expires_in_hours must be between 1 and {MAX_INVITE_HOURS}"),
        ));
    }

    let invited_email = match req
        .invited_email
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => Some(normalize_email(raw)?),
        None => None,
    };

    let (token, token_hash) = generate_opaque_token()?;
    let expires_at = Utc::now() + Duration::hours(expires_in_hours);

    let record = state
        .db
        .create_invitation(
            &token_hash,
            invited_email.as_deref(),
            Some(admin.user_id),
            max_uses,
            expires_at,
        )
        .await?;

    let actor_ip = admin.client_ip.map(|ip| ip.to_string());
    let _ = state
        .db
        .insert_audit_log(AuditLogInput {
            user_id: Some(admin.user_id),
            event_type: "invitation_created",
            actor_ip: actor_ip.as_deref(),
            session_id: Some(admin.session_id),
            metadata_json: Some(format!(r#"{{"invitation_id":"{}"}}"#, record.id)),
        })
        .await;

    let token_string = token.to_string();
    let invite_url = match &state.config.public_url {
        Some(base) => format!("{base}/register?invite={token_string}"),
        None => format!("/register?invite={token_string}"),
    };

    Ok((
        StatusCode::CREATED,
        Json(CreateInvitationResponse {
            id: record.id,
            invite_token: token_string,
            invite_url,
            invited_email: record.invited_email,
            max_uses: record.max_uses,
            expires_at: record.expires_at,
        }),
    ))
}

/// Lists all invitations without revealing hashed secrets.
pub async fn list_invitations(
    State(state): State<AppState>,
    AdminUser(_admin): AdminUser,
) -> Result<Json<Vec<InvitationRecord>>, ApiError> {
    let invitations = state.db.list_invitations().await?;
    Ok(Json(invitations))
}

/// Revokes an active invitation identifier.
pub async fn revoke_invitation(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(invitation_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let revoked = state.db.revoke_invitation(invitation_id).await?;
    if !revoked {
        return Err(ApiError::not_found(
            "INVITATION_NOT_FOUND",
            "Invitation not found",
        ));
    }

    let actor_ip = admin.client_ip.map(|ip| ip.to_string());
    let _ = state
        .db
        .insert_audit_log(AuditLogInput {
            user_id: Some(admin.user_id),
            event_type: "invitation_revoked",
            actor_ip: actor_ip.as_deref(),
            session_id: Some(admin.session_id),
            metadata_json: Some(format!(r#"{{"invitation_id":"{invitation_id}"}}"#)),
        })
        .await;

    Ok(StatusCode::NO_CONTENT)
}

/// Lists user accounts (no vault payloads, keys, or salts exposed).
pub async fn list_users(
    State(state): State<AppState>,
    AdminUser(_admin): AdminUser,
) -> Result<Json<Vec<AdminUserSummary>>, ApiError> {
    let users = state.db.list_users_admin().await?;
    Ok(Json(users))
}

/// Updates user active state or role while protecting the last active administrator.
pub async fn update_user(
    State(state): State<AppState>,
    AdminUser(admin): AdminUser,
    Path(target_user_id): Path<Uuid>,
    ApiJson(req): ApiJson<UpdateAdminUserRequest>,
) -> Result<Json<AdminUserSummary>, ApiError> {
    if req.is_active.is_none() && req.role.is_none() {
        return Err(ApiError::bad_request(
            "EMPTY_UPDATE",
            "Specify `is_active` and/or `role`",
        ));
    }

    match state
        .db
        .update_user_admin(UpdateUserAdminInput {
            target_user_id,
            is_active: req.is_active,
            role: req.role,
        })
        .await?
    {
        UpdateUserAdminOutcome::Updated(summary) => {
            let actor_ip = admin.client_ip.map(|ip| ip.to_string());
            let _ = state
                .db
                .insert_audit_log(AuditLogInput {
                    user_id: Some(admin.user_id),
                    event_type: "admin_user_updated",
                    actor_ip: actor_ip.as_deref(),
                    session_id: Some(admin.session_id),
                    metadata_json: Some(format!(r#"{{"target_user_id":"{target_user_id}"}}"#)),
                })
                .await;
            Ok(Json(summary))
        }
        UpdateUserAdminOutcome::NotFound => {
            Err(ApiError::not_found("USER_NOT_FOUND", "User not found"))
        }
        UpdateUserAdminOutcome::LastAdminProtected => Err(ApiError::conflict(
            "LAST_ADMIN_PROTECTED",
            "Cannot demote or disable the last active administrator",
        )),
    }
}
