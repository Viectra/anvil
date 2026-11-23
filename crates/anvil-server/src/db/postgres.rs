//! PostgreSQL implementation of `VaultRepository`.

use std::collections::HashSet;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use sqlx::Row;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::db::{
    ActiveSessionUser, AdminUserSummary, AuditLogInput, CreateItemOutcome, CreateSessionInput,
    DbError, DeleteRecordOutcome, DevicePlatform, InvitationRecord, PutBlobOutcome,
    RegisterOutcome, RegisterUserInput, RotatePasswordInput, RotatePasswordOutcome,
    RotateRefreshOutcome, RotateVaultKeyInput, RotateVaultKeyOutcome, SessionRecord,
    StoredBlobData, StoredBlobMeta, StoredFolderRecord, StoredItemRecord, SyncPushBatch,
    SyncPushOutcome, UpdateItemOutcome, UpdateUserAdminInput, UpdateUserAdminOutcome, UserRecord,
    UserRole, VaultSyncState,
};

fn is_unique_violation(err: &sqlx::Error) -> Option<String> {
    if let sqlx::Error::Database(db_err) = err
        && db_err.code().as_deref() == Some("23505")
    {
        return Some(db_err.constraint().unwrap_or_default().to_owned());
    }
    None
}

fn to_u32(val: i32, field: &str) -> Result<u32, DbError> {
    u32::try_from(val).map_err(|_| DbError::Integrity(format!("negative `{field}` in database")))
}

fn decode_user(row: &PgRow) -> Result<UserRecord, DbError> {
    let role_str: String = row.try_get("role")?;
    let role = UserRole::from_str(&role_str).map_err(DbError::Integrity)?;
    Ok(UserRecord {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        role,
        is_active: row.try_get("is_active")?,
        kdf_algorithm: row.try_get("kdf_algorithm")?,
        kdf_memory_kib: to_u32(row.try_get("kdf_memory_kib")?, "kdf_memory_kib")?,
        kdf_iterations: to_u32(row.try_get("kdf_iterations")?, "kdf_iterations")?,
        kdf_parallelism: to_u32(row.try_get("kdf_parallelism")?, "kdf_parallelism")?,
        kdf_salt: row.try_get("kdf_salt")?,
        server_auth_salt: row.try_get("server_auth_salt")?,
        server_auth_hash: row.try_get("server_auth_hash")?,
        key_version: to_u32(row.try_get("key_version")?, "key_version")?,
        encrypted_vault_key: row.try_get("encrypted_vault_key")?,
        sync_revision: row.try_get("sync_revision")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn decode_admin_user(row: &PgRow) -> Result<AdminUserSummary, DbError> {
    let role_str: String = row.try_get("role")?;
    let role = UserRole::from_str(&role_str).map_err(DbError::Integrity)?;
    Ok(AdminUserSummary {
        id: row.try_get("id")?,
        email: row.try_get("email")?,
        role,
        is_active: row.try_get("is_active")?,
        sync_revision: row.try_get("sync_revision")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn decode_session(row: &PgRow) -> Result<SessionRecord, DbError> {
    let platform_str: String = row.try_get("device_platform")?;
    let device_platform = DevicePlatform::from_str(&platform_str).map_err(DbError::Integrity)?;
    Ok(SessionRecord {
        id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        token_family_id: row.try_get("token_family_id")?,
        refresh_token_hash: row.try_get("refresh_token_hash")?,
        device_name: row.try_get("device_name")?,
        device_platform,
        user_agent: row.try_get("user_agent")?,
        last_ip: row.try_get("last_ip")?,
        expires_at: row.try_get("expires_at")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn decode_invitation(row: &PgRow) -> Result<InvitationRecord, DbError> {
    Ok(InvitationRecord {
        id: row.try_get("id")?,
        invited_email: row.try_get("invited_email")?,
        created_by_user_id: row.try_get("created_by_user_id")?,
        max_uses: row.try_get("max_uses")?,
        used_count: row.try_get("used_count")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
        created_at: row.try_get("created_at")?,
    })
}

fn decode_folder(row: &PgRow) -> Result<StoredFolderRecord, DbError> {
    Ok(StoredFolderRecord {
        id: row.try_get("id")?,
        encrypted_data: row.try_get("encrypted_data")?,
        revision: row.try_get("revision")?,
        deleted: row.try_get("deleted")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn decode_item(row: &PgRow) -> Result<StoredItemRecord, DbError> {
    Ok(StoredItemRecord {
        id: row.try_get("id")?,
        encrypted_data: row.try_get("encrypted_data")?,
        revision: row.try_get("revision")?,
        deleted: row.try_get("deleted")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn decode_blob_meta(row: &PgRow) -> Result<StoredBlobMeta, DbError> {
    Ok(StoredBlobMeta {
        id: row.try_get("id")?,
        item_id: row.try_get("item_id")?,
        byte_size: row.try_get("byte_size")?,
        sha256_ciphertext: row.try_get("sha256_ciphertext")?,
        revision: row.try_get("revision")?,
        deleted: row.try_get("deleted")?,
        updated_at: row.try_get("updated_at")?,
    })
}

pub async fn health_check(pool: &sqlx::PgPool) -> Result<(), DbError> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}

pub async fn find_user_by_email(
    pool: &sqlx::PgPool,
    normalized_email: &str,
) -> Result<Option<UserRecord>, DbError> {
    let row = sqlx::query(
        "SELECT id, email, role, is_active, kdf_algorithm, kdf_memory_kib, kdf_iterations,
                kdf_parallelism, kdf_salt, server_auth_salt, server_auth_hash, key_version,
                encrypted_vault_key, sync_revision, created_at, updated_at
         FROM users
         WHERE email = $1",
    )
    .bind(normalized_email)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(decode_user).transpose()
}

pub async fn find_user_by_id(
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<Option<UserRecord>, DbError> {
    let row = sqlx::query(
        "SELECT id, email, role, is_active, kdf_algorithm, kdf_memory_kib, kdf_iterations,
                kdf_parallelism, kdf_salt, server_auth_salt, server_auth_hash, key_version,
                encrypted_vault_key, sync_revision, created_at, updated_at
         FROM users
         WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(decode_user).transpose()
}

pub async fn find_user_by_identifier(
    pool: &sqlx::PgPool,
    identifier: &str,
) -> Result<Option<UserRecord>, DbError> {
    if let Ok(id) = Uuid::parse_str(identifier.trim()) {
        return find_user_by_id(pool, id).await;
    }
    find_user_by_email(pool, &identifier.trim().to_ascii_lowercase()).await
}

pub async fn register_user_with_session(
    pool: &sqlx::PgPool,
    input: RegisterUserInput,
) -> Result<RegisterOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    if input.require_invitation && input.invite_token_hash.is_none() {
        return Ok(RegisterOutcome::InvalidInvitation);
    }

    if let Some(token_hash) = input.invite_token_hash.as_deref() {
        let consumed = sqlx::query(
            "UPDATE invitations
             SET used_count = used_count + 1
             WHERE token_hash = $1
               AND revoked_at IS NULL
               AND expires_at > $2
               AND used_count < max_uses
               AND (invited_email IS NULL OR invited_email = $3)
             RETURNING id",
        )
        .bind(token_hash)
        .bind(now)
        .bind(&input.email)
        .fetch_optional(&mut *tx)
        .await?;

        if consumed.is_none() {
            return Ok(RegisterOutcome::InvalidInvitation);
        }
    }

    let kdf_mem = i32::try_from(input.kdf_memory_kib)
        .map_err(|_| DbError::Integrity("kdf_memory_kib overflow".to_owned()))?;
    let kdf_iter = i32::try_from(input.kdf_iterations)
        .map_err(|_| DbError::Integrity("kdf_iterations overflow".to_owned()))?;
    let kdf_par = i32::try_from(input.kdf_parallelism)
        .map_err(|_| DbError::Integrity("kdf_parallelism overflow".to_owned()))?;

    let insert_res = sqlx::query(
        "INSERT INTO users (
            id, email, role, is_active, kdf_algorithm, kdf_memory_kib, kdf_iterations,
            kdf_parallelism, kdf_salt, server_auth_salt, server_auth_hash, key_version,
            encrypted_vault_key, sync_revision, created_at, updated_at
         ) VALUES ($1, $2, 'user', TRUE, $3, $4, $5, $6, $7, $8, $9, 1, $10, 0, $11, $11)
         RETURNING id, email, role, is_active, kdf_algorithm, kdf_memory_kib, kdf_iterations,
                   kdf_parallelism, kdf_salt, server_auth_salt, server_auth_hash, key_version,
                   encrypted_vault_key, sync_revision, created_at, updated_at",
    )
    .bind(input.user_id)
    .bind(&input.email)
    .bind(&input.kdf_algorithm)
    .bind(kdf_mem)
    .bind(kdf_iter)
    .bind(kdf_par)
    .bind(&input.kdf_salt)
    .bind(&input.server_auth_salt)
    .bind(&input.server_auth_hash)
    .bind(&input.encrypted_vault_key)
    .bind(now)
    .fetch_one(&mut *tx)
    .await;

    let user_row = match insert_res {
        Ok(row) => row,
        Err(err) => {
            if let Some(constraint) = is_unique_violation(&err) {
                if constraint.contains("email") {
                    return Ok(RegisterOutcome::EmailExists);
                }
                return Ok(RegisterOutcome::UserIdConflict);
            }
            return Err(err.into());
        }
    };
    let user = decode_user(&user_row)?;

    sqlx::query(
        "INSERT INTO sessions (
            id, user_id, token_family_id, refresh_token_hash, previous_token_hash,
            device_name, device_platform, user_agent, last_ip, expires_at, last_used_at, created_at
         ) VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $10)",
    )
    .bind(input.session.session_id)
    .bind(user.id)
    .bind(input.session.token_family_id)
    .bind(&input.session.refresh_token_hash)
    .bind(&input.session.device_name)
    .bind(input.session.device_platform.as_str())
    .bind(&input.session.user_agent)
    .bind(&input.session.last_ip)
    .bind(input.session.expires_at)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    insert_audit_log_tx(
        &mut tx,
        AuditLogInput {
            user_id: Some(user.id),
            event_type: "user_registered",
            actor_ip: input.session.last_ip.as_deref(),
            session_id: Some(input.session.session_id),
            metadata_json: None,
        },
        now,
    )
    .await?;

    tx.commit().await?;
    Ok(RegisterOutcome::Created(Box::new(user)))
}

pub async fn create_session(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    input: CreateSessionInput,
) -> Result<SessionRecord, DbError> {
    let now = Utc::now();
    let row = sqlx::query(
        "INSERT INTO sessions (
            id, user_id, token_family_id, refresh_token_hash, previous_token_hash,
            device_name, device_platform, user_agent, last_ip, expires_at, last_used_at, created_at
         ) VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $10)
         RETURNING id, user_id, token_family_id, refresh_token_hash, device_name, device_platform,
                   user_agent, last_ip, expires_at, last_used_at, revoked_at, created_at",
    )
    .bind(input.session_id)
    .bind(user_id)
    .bind(input.token_family_id)
    .bind(&input.refresh_token_hash)
    .bind(&input.device_name)
    .bind(input.device_platform.as_str())
    .bind(&input.user_agent)
    .bind(&input.last_ip)
    .bind(input.expires_at)
    .bind(now)
    .fetch_one(pool)
    .await?;

    decode_session(&row)
}

pub async fn verify_active_session(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    session_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<ActiveSessionUser>, DbError> {
    let row = sqlx::query(
        "SELECT u.id AS user_id, u.role, u.is_active
         FROM sessions s
         INNER JOIN users u ON u.id = s.user_id
         WHERE s.id = $1
           AND s.user_id = $2
           AND s.revoked_at IS NULL
           AND s.expires_at > $3",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    row.map(|r| {
        let role_str: String = r.try_get("role")?;
        let role = UserRole::from_str(&role_str).map_err(DbError::Integrity)?;
        Ok(ActiveSessionUser {
            user_id: r.try_get("user_id")?,
            role,
            is_active: r.try_get("is_active")?,
        })
    })
    .transpose()
}

pub async fn rotate_refresh_token(
    pool: &sqlx::PgPool,
    presented_hash: &[u8],
    new_hash: &[u8],
    new_expires_at: DateTime<Utc>,
    last_ip: Option<&str>,
) -> Result<RotateRefreshOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let current_row = sqlx::query(
        "SELECT id, user_id, token_family_id, refresh_token_hash, device_name, device_platform,
                user_agent, last_ip, expires_at, last_used_at, revoked_at, created_at
         FROM sessions
         WHERE refresh_token_hash = $1
         FOR UPDATE",
    )
    .bind(presented_hash)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(row) = current_row {
        let session = decode_session(&row)?;
        if session.revoked_at.is_some() || session.expires_at <= now {
            return Ok(RotateRefreshOutcome::InvalidOrExpired);
        }

        let Some(user) = find_user_by_id_tx(&mut tx, session.user_id).await? else {
            return Ok(RotateRefreshOutcome::InvalidOrExpired);
        };
        if !user.is_active {
            sqlx::query(
                "UPDATE sessions SET revoked_at = COALESCE(revoked_at, $1) WHERE id = $2 AND user_id = $3",
            )
            .bind(now)
            .bind(session.id)
            .bind(session.user_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(RotateRefreshOutcome::InvalidOrExpired);
        }

        sqlx::query(
            "INSERT INTO used_refresh_tokens (token_hash, user_id, token_family_id, expires_at, created_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (token_hash) DO NOTHING",
        )
        .bind(presented_hash)
        .bind(session.user_id)
        .bind(session.token_family_id)
        .bind(session.expires_at)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        let updated_row = sqlx::query(
            "UPDATE sessions
             SET previous_token_hash = $1,
                 refresh_token_hash = $2,
                 last_used_at = $3,
                 expires_at = $4,
                 last_ip = COALESCE($5, last_ip)
             WHERE id = $6
               AND user_id = $7
               AND refresh_token_hash = $1
               AND revoked_at IS NULL
             RETURNING id, user_id, token_family_id, refresh_token_hash, device_name,
                       device_platform, user_agent, last_ip, expires_at, last_used_at,
                       revoked_at, created_at",
        )
        .bind(presented_hash)
        .bind(new_hash)
        .bind(now)
        .bind(new_expires_at)
        .bind(last_ip)
        .bind(session.id)
        .bind(session.user_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(updated) = updated_row {
            let updated_session = decode_session(&updated)?;
            tx.commit().await?;
            return Ok(RotateRefreshOutcome::Rotated {
                session: Box::new(updated_session),
                user: Box::new(user),
            });
        }

        revoke_family_tx(
            &mut tx,
            session.user_id,
            session.token_family_id,
            last_ip,
            now,
        )
        .await?;
        tx.commit().await?;
        return Ok(RotateRefreshOutcome::ReuseDetected {
            user_id: session.user_id,
            token_family_id: session.token_family_id,
        });
    }

    let reused_row = sqlx::query(
        "SELECT user_id, token_family_id FROM sessions WHERE previous_token_hash = $1
         UNION ALL
         SELECT user_id, token_family_id FROM used_refresh_tokens WHERE token_hash = $1
         LIMIT 1",
    )
    .bind(presented_hash)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(row) = reused_row {
        let user_id: Uuid = row.try_get("user_id")?;
        let token_family_id: Uuid = row.try_get("token_family_id")?;
        revoke_family_tx(&mut tx, user_id, token_family_id, last_ip, now).await?;
        tx.commit().await?;
        return Ok(RotateRefreshOutcome::ReuseDetected {
            user_id,
            token_family_id,
        });
    }

    Ok(RotateRefreshOutcome::InvalidOrExpired)
}

async fn revoke_family_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    token_family_id: Uuid,
    actor_ip: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(), DbError> {
    sqlx::query(
        "UPDATE sessions
         SET revoked_at = COALESCE(revoked_at, $1)
         WHERE user_id = $2 AND token_family_id = $3",
    )
    .bind(now)
    .bind(user_id)
    .bind(token_family_id)
    .execute(&mut **tx)
    .await?;

    insert_audit_log_tx(
        tx,
        AuditLogInput {
            user_id: Some(user_id),
            event_type: "refresh_token_reuse_detected",
            actor_ip,
            session_id: None,
            metadata_json: Some(format!(r#"{{"token_family_id":"{token_family_id}"}}"#)),
        },
        now,
    )
    .await
}

pub async fn revoke_session(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE sessions
         SET revoked_at = COALESCE(revoked_at, $1)
         WHERE id = $2 AND user_id = $3",
    )
    .bind(Utc::now())
    .bind(session_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn list_user_sessions(
    pool: &sqlx::PgPool,
    user_id: Uuid,
) -> Result<Vec<SessionRecord>, DbError> {
    let rows = sqlx::query(
        "SELECT id, user_id, token_family_id, refresh_token_hash, device_name, device_platform,
                user_agent, last_ip, expires_at, last_used_at, revoked_at, created_at
         FROM sessions
         WHERE user_id = $1
         ORDER BY last_used_at DESC, created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    rows.iter().map(decode_session).collect()
}

pub async fn rotate_master_password(
    pool: &sqlx::PgPool,
    input: RotatePasswordInput,
) -> Result<RotatePasswordOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let row = sqlx::query("SELECT key_version FROM users WHERE id = $1 FOR UPDATE")
        .bind(input.user_id)
        .fetch_optional(&mut *tx)
        .await?;

    let Some(row) = row else {
        return Ok(RotatePasswordOutcome::NotFound);
    };
    let current_version = to_u32(row.try_get("key_version")?, "key_version")?;
    if input.new_key_version != current_version.saturating_add(1) {
        return Ok(RotatePasswordOutcome::VersionMismatch);
    }

    let kdf_mem = i32::try_from(input.new_kdf_memory_kib)
        .map_err(|_| DbError::Integrity("kdf_memory_kib overflow".to_owned()))?;
    let kdf_iter = i32::try_from(input.new_kdf_iterations)
        .map_err(|_| DbError::Integrity("kdf_iterations overflow".to_owned()))?;
    let kdf_par = i32::try_from(input.new_kdf_parallelism)
        .map_err(|_| DbError::Integrity("kdf_parallelism overflow".to_owned()))?;
    let new_ver = i32::try_from(input.new_key_version)
        .map_err(|_| DbError::Integrity("key_version overflow".to_owned()))?;

    sqlx::query(
        "UPDATE users
         SET kdf_algorithm = $1,
             kdf_memory_kib = $2,
             kdf_iterations = $3,
             kdf_parallelism = $4,
             kdf_salt = $5,
             server_auth_salt = $6,
             server_auth_hash = $7,
             key_version = $8,
             encrypted_vault_key = $9,
             updated_at = $10
         WHERE id = $11",
    )
    .bind(&input.new_kdf_algorithm)
    .bind(kdf_mem)
    .bind(kdf_iter)
    .bind(kdf_par)
    .bind(&input.new_kdf_salt)
    .bind(&input.new_server_auth_salt)
    .bind(&input.new_server_auth_hash)
    .bind(new_ver)
    .bind(&input.new_encrypted_vault_key)
    .bind(now)
    .bind(input.user_id)
    .execute(&mut *tx)
    .await?;

    if input.revoke_other_sessions {
        sqlx::query(
            "UPDATE sessions
             SET revoked_at = COALESCE(revoked_at, $1)
             WHERE user_id = $2 AND id <> $3",
        )
        .bind(now)
        .bind(input.user_id)
        .bind(input.current_session_id)
        .execute(&mut *tx)
        .await?;
    }

    insert_audit_log_tx(
        &mut tx,
        AuditLogInput {
            user_id: Some(input.user_id),
            event_type: "master_password_rotated",
            actor_ip: input.actor_ip.as_deref(),
            session_id: Some(input.current_session_id),
            metadata_json: Some(format!(r#"{{"key_version":{}}}"#, input.new_key_version)),
        },
        now,
    )
    .await?;

    tx.commit().await?;
    Ok(RotatePasswordOutcome::Updated {
        key_version: input.new_key_version,
        rotated_at: now,
    })
}

pub async fn rotate_vault_key(
    pool: &sqlx::PgPool,
    input: RotateVaultKeyInput,
) -> Result<RotateVaultKeyOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let row = sqlx::query("SELECT key_version, sync_revision FROM users WHERE id = $1 FOR UPDATE")
        .bind(input.user_id)
        .fetch_optional(&mut *tx)
        .await?;

    let Some(row) = row else {
        return Ok(RotateVaultKeyOutcome::NotFound);
    };
    let current_version = to_u32(row.try_get("key_version")?, "key_version")?;
    if input.new_key_version != current_version.saturating_add(1) {
        return Ok(RotateVaultKeyOutcome::VersionMismatch);
    }

    let current_revision: i64 = row.try_get("sync_revision")?;
    if input.base_revision != current_revision {
        let delta_since = input.base_revision.clamp(0, current_revision);
        let state = pull_vault_sync_tx(&mut tx, input.user_id, delta_since)
            .await?
            .ok_or_else(|| DbError::Integrity("user vanished inside tx".to_owned()))?;
        return Ok(RotateVaultKeyOutcome::RevisionConflict(state));
    }

    let provided_folders: HashSet<Uuid> = input.folders.iter().map(|f| f.id).collect();
    let provided_items: HashSet<Uuid> = input.items.iter().map(|i| i.id).collect();
    let provided_blobs: HashSet<Uuid> = input.blobs.iter().map(|b| b.id).collect();

    let missing_folders = sqlx::query(
        "SELECT id FROM vault_folders WHERE user_id = $1 AND deleted = FALSE FOR UPDATE",
    )
    .bind(input.user_id)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .filter_map(|r| r.try_get::<Uuid, _>("id").ok())
    .filter(|id| !provided_folders.contains(id))
    .count();

    let missing_items =
        sqlx::query("SELECT id FROM vault_items WHERE user_id = $1 AND deleted = FALSE FOR UPDATE")
            .bind(input.user_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .filter_map(|r| r.try_get::<Uuid, _>("id").ok())
            .filter(|id| !provided_items.contains(id))
            .count();

    let missing_blobs =
        sqlx::query("SELECT id FROM vault_blobs WHERE user_id = $1 AND deleted = FALSE FOR UPDATE")
            .bind(input.user_id)
            .fetch_all(&mut *tx)
            .await?
            .into_iter()
            .filter_map(|r| r.try_get::<Uuid, _>("id").ok())
            .filter(|id| !provided_blobs.contains(id))
            .count();

    if missing_folders > 0 || missing_items > 0 || missing_blobs > 0 {
        return Ok(RotateVaultKeyOutcome::IncompleteBatch {
            missing_folders,
            missing_items,
            missing_blobs,
        });
    }

    let new_ver = i32::try_from(input.new_key_version)
        .map_err(|_| DbError::Integrity("key_version overflow".to_owned()))?;
    let new_revision = current_revision + 1;

    sqlx::query(
        "UPDATE users
         SET key_version = $1,
             encrypted_vault_key = $2,
             sync_revision = $3,
             updated_at = $4
         WHERE id = $5",
    )
    .bind(new_ver)
    .bind(&input.new_encrypted_vault_key)
    .bind(new_revision)
    .bind(now)
    .bind(input.user_id)
    .execute(&mut *tx)
    .await?;

    for folder in &input.folders {
        sqlx::query(
            "INSERT INTO vault_folders (id, user_id, encrypted_data, revision, deleted, updated_at)
             VALUES ($1, $2, $3, $4, FALSE, $5)
             ON CONFLICT (user_id, id) DO UPDATE
             SET encrypted_data = EXCLUDED.encrypted_data,
                 revision = EXCLUDED.revision,
                 deleted = FALSE,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(folder.id)
        .bind(input.user_id)
        .bind(&folder.encrypted_data)
        .bind(new_revision)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    for item in &input.items {
        sqlx::query(
            "INSERT INTO vault_items (id, user_id, encrypted_data, revision, deleted, updated_at)
             VALUES ($1, $2, $3, $4, FALSE, $5)
             ON CONFLICT (user_id, id) DO UPDATE
             SET encrypted_data = EXCLUDED.encrypted_data,
                 revision = EXCLUDED.revision,
                 deleted = FALSE,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(item.id)
        .bind(input.user_id)
        .bind(&item.encrypted_data)
        .bind(new_revision)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    for blob in &input.blobs {
        let byte_size = i32::try_from(blob.encrypted_blob.len())
            .map_err(|_| DbError::Integrity("blob byte_size overflow".to_owned()))?;
        sqlx::query(
            "INSERT INTO vault_blobs (
                id, user_id, item_id, encrypted_blob, byte_size, sha256_ciphertext,
                revision, deleted, created_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8, $8)
             ON CONFLICT (user_id, id) DO UPDATE
             SET item_id = EXCLUDED.item_id,
                 encrypted_blob = EXCLUDED.encrypted_blob,
                 byte_size = EXCLUDED.byte_size,
                 sha256_ciphertext = EXCLUDED.sha256_ciphertext,
                 revision = EXCLUDED.revision,
                 deleted = FALSE,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(blob.id)
        .bind(input.user_id)
        .bind(blob.item_id)
        .bind(&blob.encrypted_blob)
        .bind(byte_size)
        .bind(&blob.sha256_ciphertext)
        .bind(new_revision)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    if input.revoke_other_sessions {
        sqlx::query(
            "UPDATE sessions
             SET revoked_at = COALESCE(revoked_at, $1)
             WHERE user_id = $2 AND id <> $3",
        )
        .bind(now)
        .bind(input.user_id)
        .bind(input.current_session_id)
        .execute(&mut *tx)
        .await?;
    }

    insert_audit_log_tx(
        &mut tx,
        AuditLogInput {
            user_id: Some(input.user_id),
            event_type: "vault_key_emergency_rotated",
            actor_ip: input.actor_ip.as_deref(),
            session_id: Some(input.current_session_id),
            metadata_json: Some(format!(
                r#"{{"key_version":{},"new_revision":{}}}"#,
                input.new_key_version, new_revision
            )),
        },
        now,
    )
    .await?;

    tx.commit().await?;
    Ok(RotateVaultKeyOutcome::Rotated {
        key_version: input.new_key_version,
        new_revision,
        rotated_at: now,
    })
}

pub async fn delete_user_account(pool: &sqlx::PgPool, user_id: Uuid) -> Result<bool, DbError> {
    let res = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn pull_vault_sync(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    since_revision: i64,
) -> Result<Option<VaultSyncState>, DbError> {
    let mut tx = pool.begin().await?;
    let state = pull_vault_sync_tx(&mut tx, user_id, since_revision).await?;
    tx.commit().await?;
    Ok(state)
}

async fn pull_vault_sync_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
    since_revision: i64,
) -> Result<Option<VaultSyncState>, DbError> {
    let since = since_revision.max(0);
    let user_row = sqlx::query(
        "SELECT sync_revision, key_version, encrypted_vault_key
         FROM users
         WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;

    let Some(user_row) = user_row else {
        return Ok(None);
    };

    let folder_rows = sqlx::query(
        "SELECT id, encrypted_data, revision, deleted, updated_at
         FROM vault_folders
         WHERE user_id = $1 AND revision > $2 AND ($2 > 0 OR deleted = FALSE)
         ORDER BY revision ASC, id ASC",
    )
    .bind(user_id)
    .bind(since)
    .fetch_all(&mut **tx)
    .await?;

    let item_rows = sqlx::query(
        "SELECT id, encrypted_data, revision, deleted, updated_at
         FROM vault_items
         WHERE user_id = $1 AND revision > $2 AND ($2 > 0 OR deleted = FALSE)
         ORDER BY revision ASC, id ASC",
    )
    .bind(user_id)
    .bind(since)
    .fetch_all(&mut **tx)
    .await?;

    let blob_rows = sqlx::query(
        "SELECT id, item_id, byte_size, sha256_ciphertext, revision, deleted, updated_at
         FROM vault_blobs
         WHERE user_id = $1 AND revision > $2 AND ($2 > 0 OR deleted = FALSE)
         ORDER BY revision ASC, id ASC",
    )
    .bind(user_id)
    .bind(since)
    .fetch_all(&mut **tx)
    .await?;

    let folders = folder_rows
        .iter()
        .map(decode_folder)
        .collect::<Result<Vec<_>, _>>()?;
    let items = item_rows
        .iter()
        .map(decode_item)
        .collect::<Result<Vec<_>, _>>()?;
    let blobs_meta = blob_rows
        .iter()
        .map(decode_blob_meta)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Some(VaultSyncState {
        current_revision: user_row.try_get("sync_revision")?,
        key_version: to_u32(user_row.try_get("key_version")?, "key_version")?,
        encrypted_vault_key: user_row.try_get("encrypted_vault_key")?,
        folders,
        items,
        blobs_meta,
    }))
}

pub async fn push_sync_batch(
    pool: &sqlx::PgPool,
    batch: SyncPushBatch,
) -> Result<SyncPushOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let user_row =
        sqlx::query("SELECT sync_revision, updated_at FROM users WHERE id = $1 FOR UPDATE")
            .bind(batch.user_id)
            .fetch_optional(&mut *tx)
            .await?;

    let Some(user_row) = user_row else {
        return Err(DbError::Integrity("authenticated user missing".to_owned()));
    };
    let current_revision: i64 = user_row.try_get("sync_revision")?;
    let last_updated_at: DateTime<Utc> = user_row.try_get("updated_at")?;

    if batch.base_revision != current_revision {
        let delta_since = batch.base_revision.clamp(0, current_revision);
        let state = pull_vault_sync_tx(&mut tx, batch.user_id, delta_since)
            .await?
            .ok_or_else(|| DbError::Integrity("authenticated user missing".to_owned()))?;
        return Ok(SyncPushOutcome::Conflict(state));
    }

    let has_mutations = !batch.folders_upsert.is_empty()
        || !batch.folders_delete_ids.is_empty()
        || !batch.items_upsert.is_empty()
        || !batch.items_delete_ids.is_empty();

    if !has_mutations {
        tx.commit().await?;
        return Ok(SyncPushOutcome::Committed {
            new_revision: current_revision,
            updated_at: last_updated_at,
        });
    }

    let new_revision = current_revision + 1;
    sqlx::query("UPDATE users SET sync_revision = $1, updated_at = $2 WHERE id = $3")
        .bind(new_revision)
        .bind(now)
        .bind(batch.user_id)
        .execute(&mut *tx)
        .await?;

    for folder in batch.folders_upsert {
        sqlx::query(
            "INSERT INTO vault_folders (id, user_id, encrypted_data, revision, deleted, updated_at)
             VALUES ($1, $2, $3, $4, FALSE, $5)
             ON CONFLICT (user_id, id) DO UPDATE
             SET encrypted_data = EXCLUDED.encrypted_data,
                 revision = EXCLUDED.revision,
                 deleted = FALSE,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(folder.id)
        .bind(batch.user_id)
        .bind(&folder.encrypted_data)
        .bind(new_revision)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    for folder_id in batch.folders_delete_ids {
        sqlx::query(
            "UPDATE vault_folders
             SET deleted = TRUE, revision = $1, updated_at = $2
             WHERE user_id = $3 AND id = $4 AND deleted = FALSE",
        )
        .bind(new_revision)
        .bind(now)
        .bind(batch.user_id)
        .bind(folder_id)
        .execute(&mut *tx)
        .await?;
    }

    for item in batch.items_upsert {
        sqlx::query(
            "INSERT INTO vault_items (id, user_id, encrypted_data, revision, deleted, updated_at)
             VALUES ($1, $2, $3, $4, FALSE, $5)
             ON CONFLICT (user_id, id) DO UPDATE
             SET encrypted_data = EXCLUDED.encrypted_data,
                 revision = EXCLUDED.revision,
                 deleted = FALSE,
                 updated_at = EXCLUDED.updated_at",
        )
        .bind(item.id)
        .bind(batch.user_id)
        .bind(&item.encrypted_data)
        .bind(new_revision)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    }

    for item_id in batch.items_delete_ids {
        sqlx::query(
            "UPDATE vault_items
             SET deleted = TRUE, revision = $1, updated_at = $2
             WHERE user_id = $3 AND id = $4 AND deleted = FALSE",
        )
        .bind(new_revision)
        .bind(now)
        .bind(batch.user_id)
        .bind(item_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE vault_blobs
             SET deleted = TRUE, revision = $1, updated_at = $2
             WHERE user_id = $3 AND item_id = $4 AND deleted = FALSE",
        )
        .bind(new_revision)
        .bind(now)
        .bind(batch.user_id)
        .bind(item_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(SyncPushOutcome::Committed {
        new_revision,
        updated_at: now,
    })
}

pub async fn create_item(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    item_id: Uuid,
    encrypted_data: &[u8],
) -> Result<CreateItemOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let exists = sqlx::query("SELECT 1 FROM vault_items WHERE user_id = $1 AND id = $2")
        .bind(user_id)
        .bind(item_id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_some() {
        return Ok(CreateItemOutcome::AlreadyExists);
    }

    let rev_row = sqlx::query(
        "UPDATE users
         SET sync_revision = sync_revision + 1, updated_at = $1
         WHERE id = $2
         RETURNING sync_revision",
    )
    .bind(now)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let new_rev: i64 = rev_row.try_get("sync_revision")?;

    let insert_res = sqlx::query(
        "INSERT INTO vault_items (id, user_id, encrypted_data, revision, deleted, updated_at)
         VALUES ($1, $2, $3, $4, FALSE, $5)",
    )
    .bind(item_id)
    .bind(user_id)
    .bind(encrypted_data)
    .bind(new_rev)
    .bind(now)
    .execute(&mut *tx)
    .await;

    if let Err(err) = insert_res {
        if is_unique_violation(&err).is_some() {
            return Ok(CreateItemOutcome::AlreadyExists);
        }
        return Err(err.into());
    }

    tx.commit().await?;
    Ok(CreateItemOutcome::Created {
        id: item_id,
        revision: new_rev,
        updated_at: now,
    })
}

pub async fn update_item(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    item_id: Uuid,
    expected_revision: i64,
    encrypted_data: &[u8],
) -> Result<UpdateItemOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let row = sqlx::query(
        "SELECT id, encrypted_data, revision, deleted, updated_at
         FROM vault_items
         WHERE user_id = $1 AND id = $2
         FOR UPDATE",
    )
    .bind(user_id)
    .bind(item_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        return Ok(UpdateItemOutcome::NotFound);
    };
    let current = decode_item(&row)?;
    if current.revision != expected_revision {
        return Ok(UpdateItemOutcome::Conflict(current));
    }

    let rev_row = sqlx::query(
        "UPDATE users
         SET sync_revision = sync_revision + 1, updated_at = $1
         WHERE id = $2
         RETURNING sync_revision",
    )
    .bind(now)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let new_rev: i64 = rev_row.try_get("sync_revision")?;

    sqlx::query(
        "UPDATE vault_items
         SET encrypted_data = $1, revision = $2, deleted = FALSE, updated_at = $3
         WHERE user_id = $4 AND id = $5",
    )
    .bind(encrypted_data)
    .bind(new_rev)
    .bind(now)
    .bind(user_id)
    .bind(item_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(UpdateItemOutcome::Updated {
        id: item_id,
        revision: new_rev,
        updated_at: now,
    })
}

pub async fn delete_item(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    item_id: Uuid,
) -> Result<DeleteRecordOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let existing = sqlx::query(
        "SELECT revision, deleted FROM vault_items WHERE user_id = $1 AND id = $2 FOR UPDATE",
    )
    .bind(user_id)
    .bind(item_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(existing) = existing else {
        return Ok(DeleteRecordOutcome::NotFound);
    };
    let already_deleted: bool = existing.try_get("deleted")?;
    if already_deleted {
        return Ok(DeleteRecordOutcome::NotFound);
    }

    let rev_row = sqlx::query(
        "UPDATE users
         SET sync_revision = sync_revision + 1, updated_at = $1
         WHERE id = $2
         RETURNING sync_revision",
    )
    .bind(now)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let new_rev: i64 = rev_row.try_get("sync_revision")?;

    sqlx::query(
        "UPDATE vault_items
         SET deleted = TRUE, revision = $1, updated_at = $2
         WHERE user_id = $3 AND id = $4",
    )
    .bind(new_rev)
    .bind(now)
    .bind(user_id)
    .bind(item_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE vault_blobs
         SET deleted = TRUE, revision = $1, updated_at = $2
         WHERE user_id = $3 AND item_id = $4 AND deleted = FALSE",
    )
    .bind(new_rev)
    .bind(now)
    .bind(user_id)
    .bind(item_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(DeleteRecordOutcome::Deleted {
        revision: new_rev,
        updated_at: now,
    })
}

pub async fn put_blob(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    item_id: Uuid,
    blob_id: Uuid,
    encrypted_blob: &[u8],
    sha256_ciphertext: &[u8],
) -> Result<PutBlobOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let item_exists =
        sqlx::query("SELECT 1 FROM vault_items WHERE user_id = $1 AND id = $2 AND deleted = FALSE")
            .bind(user_id)
            .bind(item_id)
            .fetch_optional(&mut *tx)
            .await?;
    if item_exists.is_none() {
        return Ok(PutBlobOutcome::ItemNotFound);
    }

    let byte_size = i32::try_from(encrypted_blob.len())
        .map_err(|_| DbError::Integrity("blob byte_size overflow".to_owned()))?;

    let rev_row = sqlx::query(
        "UPDATE users
         SET sync_revision = sync_revision + 1, updated_at = $1
         WHERE id = $2
         RETURNING sync_revision",
    )
    .bind(now)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let new_rev: i64 = rev_row.try_get("sync_revision")?;

    sqlx::query(
        "INSERT INTO vault_blobs (
            id, user_id, item_id, encrypted_blob, byte_size, sha256_ciphertext,
            revision, deleted, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, FALSE, $8, $8)
         ON CONFLICT (user_id, id) DO UPDATE
         SET item_id = EXCLUDED.item_id,
             encrypted_blob = EXCLUDED.encrypted_blob,
             byte_size = EXCLUDED.byte_size,
             sha256_ciphertext = EXCLUDED.sha256_ciphertext,
             revision = EXCLUDED.revision,
             deleted = FALSE,
             updated_at = EXCLUDED.updated_at",
    )
    .bind(blob_id)
    .bind(user_id)
    .bind(item_id)
    .bind(encrypted_blob)
    .bind(byte_size)
    .bind(sha256_ciphertext)
    .bind(new_rev)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(PutBlobOutcome::Saved {
        blob_id,
        revision: new_rev,
        byte_size,
        updated_at: now,
    })
}

pub async fn get_blob(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    blob_id: Uuid,
) -> Result<Option<StoredBlobData>, DbError> {
    let row = sqlx::query(
        "SELECT id, item_id, encrypted_blob, byte_size, sha256_ciphertext, revision, updated_at
         FROM vault_blobs
         WHERE user_id = $1 AND id = $2 AND deleted = FALSE",
    )
    .bind(user_id)
    .bind(blob_id)
    .fetch_optional(pool)
    .await?;

    row.map(|r| {
        Ok(StoredBlobData {
            id: r.try_get("id")?,
            item_id: r.try_get("item_id")?,
            encrypted_blob: r.try_get("encrypted_blob")?,
            byte_size: r.try_get("byte_size")?,
            sha256_ciphertext: r.try_get("sha256_ciphertext")?,
            revision: r.try_get("revision")?,
            updated_at: r.try_get("updated_at")?,
        })
    })
    .transpose()
}

pub async fn delete_blob(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    blob_id: Uuid,
) -> Result<DeleteRecordOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let existing =
        sqlx::query("SELECT deleted FROM vault_blobs WHERE user_id = $1 AND id = $2 FOR UPDATE")
            .bind(user_id)
            .bind(blob_id)
            .fetch_optional(&mut *tx)
            .await?;

    let Some(existing) = existing else {
        return Ok(DeleteRecordOutcome::NotFound);
    };
    let already_deleted: bool = existing.try_get("deleted")?;
    if already_deleted {
        return Ok(DeleteRecordOutcome::NotFound);
    }

    let rev_row = sqlx::query(
        "UPDATE users
         SET sync_revision = sync_revision + 1, updated_at = $1
         WHERE id = $2
         RETURNING sync_revision",
    )
    .bind(now)
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await?;
    let new_rev: i64 = rev_row.try_get("sync_revision")?;

    sqlx::query(
        "UPDATE vault_blobs
         SET deleted = TRUE, revision = $1, updated_at = $2
         WHERE user_id = $3 AND id = $4",
    )
    .bind(new_rev)
    .bind(now)
    .bind(user_id)
    .bind(blob_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(DeleteRecordOutcome::Deleted {
        revision: new_rev,
        updated_at: now,
    })
}

pub async fn create_invitation(
    pool: &sqlx::PgPool,
    token_hash: &[u8],
    invited_email: Option<&str>,
    created_by_user_id: Option<Uuid>,
    max_uses: i32,
    expires_at: DateTime<Utc>,
) -> Result<InvitationRecord, DbError> {
    let now = Utc::now();
    let id = Uuid::new_v4();
    let row = sqlx::query(
        "INSERT INTO invitations (
            id, token_hash, invited_email, created_by_user_id, max_uses, used_count,
            expires_at, revoked_at, created_at
         ) VALUES ($1, $2, $3, $4, $5, 0, $6, NULL, $7)
         RETURNING id, invited_email, created_by_user_id, max_uses, used_count,
                   expires_at, revoked_at, created_at",
    )
    .bind(id)
    .bind(token_hash)
    .bind(invited_email)
    .bind(created_by_user_id)
    .bind(max_uses)
    .bind(expires_at)
    .bind(now)
    .fetch_one(pool)
    .await?;

    decode_invitation(&row)
}

pub async fn list_invitations(pool: &sqlx::PgPool) -> Result<Vec<InvitationRecord>, DbError> {
    let rows = sqlx::query(
        "SELECT id, invited_email, created_by_user_id, max_uses, used_count,
                expires_at, revoked_at, created_at
         FROM invitations
         ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(decode_invitation).collect()
}

pub async fn revoke_invitation(pool: &sqlx::PgPool, invitation_id: Uuid) -> Result<bool, DbError> {
    let res = sqlx::query(
        "UPDATE invitations
         SET revoked_at = COALESCE(revoked_at, $1)
         WHERE id = $2",
    )
    .bind(Utc::now())
    .bind(invitation_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn list_users_admin(pool: &sqlx::PgPool) -> Result<Vec<AdminUserSummary>, DbError> {
    let rows = sqlx::query(
        "SELECT id, email, role, is_active, sync_revision, created_at, updated_at
         FROM users
         ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await?;
    rows.iter().map(decode_admin_user).collect()
}

pub async fn update_user_admin(
    pool: &sqlx::PgPool,
    input: UpdateUserAdminInput,
) -> Result<UpdateUserAdminOutcome, DbError> {
    let mut tx = pool.begin().await?;
    let now = Utc::now();

    let target_row = sqlx::query(
        "SELECT id, email, role, is_active, sync_revision, created_at, updated_at
         FROM users
         WHERE id = $1
         FOR UPDATE",
    )
    .bind(input.target_user_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(target_row) = target_row else {
        return Ok(UpdateUserAdminOutcome::NotFound);
    };
    let current = decode_admin_user(&target_row)?;
    let new_role = input.role.unwrap_or(current.role);
    let new_active = input.is_active.unwrap_or(current.is_active);

    let was_active_admin = current.role == UserRole::Admin && current.is_active;
    let stays_active_admin = new_role == UserRole::Admin && new_active;
    if was_active_admin && !stays_active_admin {
        let count_row = sqlx::query(
            "SELECT COUNT(*) AS cnt FROM users WHERE role = 'admin' AND is_active = TRUE",
        )
        .fetch_one(&mut *tx)
        .await?;
        let active_admins: i64 = count_row.try_get("cnt")?;
        if active_admins <= 1 {
            return Ok(UpdateUserAdminOutcome::LastAdminProtected);
        }
    }

    let updated_row = sqlx::query(
        "UPDATE users
         SET role = $1, is_active = $2, updated_at = $3
         WHERE id = $4
         RETURNING id, email, role, is_active, sync_revision, created_at, updated_at",
    )
    .bind(new_role.as_str())
    .bind(new_active)
    .bind(now)
    .bind(input.target_user_id)
    .fetch_one(&mut *tx)
    .await?;

    if !new_active {
        sqlx::query(
            "UPDATE sessions
             SET revoked_at = COALESCE(revoked_at, $1)
             WHERE user_id = $2",
        )
        .bind(now)
        .bind(input.target_user_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(UpdateUserAdminOutcome::Updated(decode_admin_user(
        &updated_row,
    )?))
}

pub async fn insert_audit_log(
    pool: &sqlx::PgPool,
    entry: AuditLogInput<'_>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO audit_logs (user_id, event_type, actor_ip, session_id, metadata_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(entry.user_id)
    .bind(entry.event_type)
    .bind(entry.actor_ip)
    .bind(entry.session_id)
    .bind(entry.metadata_json)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

async fn find_user_by_id_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user_id: Uuid,
) -> Result<Option<UserRecord>, DbError> {
    let row = sqlx::query(
        "SELECT id, email, role, is_active, kdf_algorithm, kdf_memory_kib, kdf_iterations,
                kdf_parallelism, kdf_salt, server_auth_salt, server_auth_hash, key_version,
                encrypted_vault_key, sync_revision, created_at, updated_at
         FROM users
         WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await?;
    row.as_ref().map(decode_user).transpose()
}

async fn insert_audit_log_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entry: AuditLogInput<'_>,
    now: DateTime<Utc>,
) -> Result<(), DbError> {
    sqlx::query(
        "INSERT INTO audit_logs (user_id, event_type, actor_ip, session_id, metadata_json, created_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(entry.user_id)
    .bind(entry.event_type)
    .bind(entry.actor_ip)
    .bind(entry.session_id)
    .bind(entry.metadata_json)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
