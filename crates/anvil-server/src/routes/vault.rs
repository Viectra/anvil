//! Encrypted vault synchronization, item CRUD, and encrypted blob endpoints (`/api/v1/vault/*`).

use axum::Json;
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthUser;
use crate::db::{
    CreateItemOutcome, DeleteRecordOutcome, FolderUpsertInput, ItemUpsertInput, PutBlobOutcome,
    StoredBlobMeta, StoredFolderRecord, StoredItemRecord, SyncPushBatch, SyncPushOutcome,
    UpdateItemOutcome, VaultRepository, VaultSyncState,
};
use crate::error::{ApiError, ApiJson};
use crate::routes::auth::decode_b64_envelope;
use crate::routes::auth::validate_envelope_bytes;
use crate::state::AppState;

/// Maximum permitted encrypted blob size in bytes (`256 KiB`).
pub const MAX_BLOB_BYTES: usize = 262_144;
/// Upper bound on an encrypted item or folder envelope (`1 MiB`).
const MAX_ITEM_ENVELOPE_BYTES: usize = 1_048_576;
const MAX_BATCH_MUTATIONS: usize = 2_000;

#[derive(Debug, Deserialize)]
pub struct SyncPullQuery {
    #[serde(default)]
    pub since_revision: i64,
}

#[derive(Debug, Serialize)]
pub struct WireFolderRecord {
    pub id: Uuid,
    pub encrypted_data_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WireItemRecord {
    pub id: Uuid,
    pub encrypted_data_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WireBlobMetaRecord {
    pub id: Uuid,
    pub item_id: Uuid,
    pub byte_size: i32,
    pub sha256_ciphertext_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct SyncResponse {
    pub current_revision: i64,
    pub key_version: u32,
    pub encrypted_vault_key_b64: String,
    pub folders: Vec<WireFolderRecord>,
    pub items: Vec<WireItemRecord>,
    pub blobs_meta: Vec<WireBlobMetaRecord>,
}

#[derive(Debug, Deserialize)]
pub struct FolderUpsertPayload {
    pub id: Uuid,
    pub encrypted_data_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct ItemUpsertPayload {
    pub id: Uuid,
    pub encrypted_data_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct SyncPushRequest {
    pub base_revision: i64,
    #[serde(default)]
    pub folders_upsert: Vec<FolderUpsertPayload>,
    #[serde(default)]
    pub folders_delete_ids: Vec<Uuid>,
    #[serde(default)]
    pub items_upsert: Vec<ItemUpsertPayload>,
    #[serde(default)]
    pub items_delete_ids: Vec<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct SyncPushResponse {
    pub new_revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateItemRequest {
    pub id: Uuid,
    pub encrypted_data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct ItemMutationResponse {
    pub id: Uuid,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateItemRequest {
    pub expected_revision: i64,
    pub encrypted_data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
pub struct PutBlobQuery {
    pub item_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct PutBlobResponse {
    pub blob_id: Uuid,
    pub revision: i64,
    pub byte_size: i32,
}

impl From<StoredFolderRecord> for WireFolderRecord {
    fn from(r: StoredFolderRecord) -> Self {
        Self {
            id: r.id,
            encrypted_data_b64: STANDARD.encode(r.encrypted_data),
            revision: r.revision,
            deleted: r.deleted,
            updated_at: r.updated_at,
        }
    }
}

impl From<StoredItemRecord> for WireItemRecord {
    fn from(r: StoredItemRecord) -> Self {
        Self {
            id: r.id,
            encrypted_data_b64: STANDARD.encode(r.encrypted_data),
            revision: r.revision,
            deleted: r.deleted,
            updated_at: r.updated_at,
        }
    }
}

impl From<StoredBlobMeta> for WireBlobMetaRecord {
    fn from(r: StoredBlobMeta) -> Self {
        Self {
            id: r.id,
            item_id: r.item_id,
            byte_size: r.byte_size,
            sha256_ciphertext_b64: STANDARD.encode(r.sha256_ciphertext),
            revision: r.revision,
            deleted: r.deleted,
            updated_at: r.updated_at,
        }
    }
}

impl From<VaultSyncState> for SyncResponse {
    fn from(state: VaultSyncState) -> Self {
        Self {
            current_revision: state.current_revision,
            key_version: state.key_version,
            encrypted_vault_key_b64: STANDARD.encode(state.encrypted_vault_key),
            folders: state.folders.into_iter().map(Into::into).collect(),
            items: state.items.into_iter().map(Into::into).collect(),
            blobs_meta: state.blobs_meta.into_iter().map(Into::into).collect(),
        }
    }
}

/// Returns incremental (`since_revision > 0`) or full (`since_revision = 0`) encrypted records for the authenticated user.
pub async fn pull_sync(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<SyncPullQuery>,
) -> Result<Json<SyncResponse>, ApiError> {
    if query.since_revision < 0 {
        return Err(ApiError::bad_request(
            "INVALID_REVISION",
            "since_revision must be non-negative",
        ));
    }

    let sync_state = state
        .db
        .pull_vault_sync(auth.user_id, query.since_revision)
        .await?
        .ok_or_else(|| ApiError::not_found("ACCOUNT_NOT_FOUND", "Account no longer exists"))?;

    Ok(Json(SyncResponse::from(sync_state)))
}

/// Commits an optimistic-concurrency batch of encrypted folder/item mutations.
pub async fn push_sync(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<SyncPushRequest>,
) -> Result<Json<SyncPushResponse>, ApiError> {
    if req.base_revision < 0 {
        return Err(ApiError::bad_request(
            "INVALID_REVISION",
            "base_revision must be non-negative",
        ));
    }

    let mutation_count = req.folders_upsert.len()
        + req.folders_delete_ids.len()
        + req.items_upsert.len()
        + req.items_delete_ids.len();
    if mutation_count > MAX_BATCH_MUTATIONS {
        return Err(ApiError::bad_request(
            "BATCH_TOO_LARGE",
            format!("Sync batch exceeds maximum of {MAX_BATCH_MUTATIONS} operations"),
        ));
    }

    let mut folders_upsert = Vec::with_capacity(req.folders_upsert.len());
    for folder in req.folders_upsert {
        let encrypted_data = decode_b64_envelope(
            "folders_upsert.encrypted_data_b64",
            &folder.encrypted_data_b64,
            MAX_ITEM_ENVELOPE_BYTES,
        )?;
        folders_upsert.push(FolderUpsertInput {
            id: folder.id,
            encrypted_data,
        });
    }

    let mut items_upsert = Vec::with_capacity(req.items_upsert.len());
    for item in req.items_upsert {
        let encrypted_data = decode_b64_envelope(
            "items_upsert.encrypted_data_b64",
            &item.encrypted_data_b64,
            MAX_ITEM_ENVELOPE_BYTES,
        )?;
        items_upsert.push(ItemUpsertInput {
            id: item.id,
            encrypted_data,
        });
    }

    let outcome = state
        .db
        .push_sync_batch(SyncPushBatch {
            user_id: auth.user_id,
            base_revision: req.base_revision,
            folders_upsert,
            folders_delete_ids: req.folders_delete_ids,
            items_upsert,
            items_delete_ids: req.items_delete_ids,
        })
        .await?;

    match outcome {
        SyncPushOutcome::Committed {
            new_revision,
            updated_at,
        } => Ok(Json(SyncPushResponse {
            new_revision,
            updated_at,
        })),
        SyncPushOutcome::Conflict(server_state) => {
            let sync_json = serde_json::to_value(SyncResponse::from(server_state))
                .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
            Err(ApiError::SyncConflict {
                message: "Server revision is ahead of base_revision".to_owned(),
                sync: sync_json,
            })
        }
    }
}

/// Creates a single encrypted item atomically for the authenticated user.
pub async fn create_item(
    State(state): State<AppState>,
    auth: AuthUser,
    ApiJson(req): ApiJson<CreateItemRequest>,
) -> Result<(StatusCode, Json<ItemMutationResponse>), ApiError> {
    let encrypted_data = decode_b64_envelope(
        "encrypted_data_b64",
        &req.encrypted_data_b64,
        MAX_ITEM_ENVELOPE_BYTES,
    )?;

    match state
        .db
        .create_item(auth.user_id, req.id, &encrypted_data)
        .await?
    {
        CreateItemOutcome::Created {
            id,
            revision,
            updated_at,
        } => Ok((
            StatusCode::CREATED,
            Json(ItemMutationResponse {
                id,
                revision,
                updated_at,
            }),
        )),
        CreateItemOutcome::AlreadyExists => Err(ApiError::conflict(
            "ITEM_ALREADY_EXISTS",
            "An item with this identifier already exists",
        )),
    }
}

/// Updates an existing encrypted item scoped strictly to `auth.user_id` if `expected_revision` matches.
pub async fn update_item(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(item_id): Path<Uuid>,
    ApiJson(req): ApiJson<UpdateItemRequest>,
) -> Result<Json<ItemMutationResponse>, ApiError> {
    if req.expected_revision < 1 {
        return Err(ApiError::bad_request(
            "INVALID_REVISION",
            "expected_revision must be at least 1",
        ));
    }

    let encrypted_data = decode_b64_envelope(
        "encrypted_data_b64",
        &req.encrypted_data_b64,
        MAX_ITEM_ENVELOPE_BYTES,
    )?;

    match state
        .db
        .update_item(
            auth.user_id,
            item_id,
            req.expected_revision,
            &encrypted_data,
        )
        .await?
    {
        UpdateItemOutcome::Updated {
            id,
            revision,
            updated_at,
        } => Ok(Json(ItemMutationResponse {
            id,
            revision,
            updated_at,
        })),
        UpdateItemOutcome::NotFound => Err(ApiError::not_found(
            "ITEM_NOT_FOUND",
            "Vault item not found",
        )),
        UpdateItemOutcome::Conflict(current) => {
            let current_item = serde_json::to_value(WireItemRecord::from(current))
                .map_err(|e| ApiError::internal(anyhow::Error::from(e)))?;
            Err(ApiError::ItemConflict {
                message: "Item revision does not match expected_revision".to_owned(),
                current_item,
            })
        }
    }
}

/// Writes a deletion tombstone on an item owned by `auth.user_id` and its child blobs.
pub async fn delete_item(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(item_id): Path<Uuid>,
) -> Result<Json<DeleteResponse>, ApiError> {
    match state.db.delete_item(auth.user_id, item_id).await? {
        DeleteRecordOutcome::Deleted {
            revision,
            updated_at,
        } => Ok(Json(DeleteResponse {
            revision,
            updated_at,
        })),
        DeleteRecordOutcome::NotFound => Err(ApiError::not_found(
            "ITEM_NOT_FOUND",
            "Vault item not found",
        )),
    }
}

/// Uploads or replaces an encrypted binary blob (`<= 256 KiB`) attached to an active item owned by `auth.user_id`.
pub async fn put_blob(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<Uuid>,
    Query(query): Query<PutBlobQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<PutBlobResponse>, ApiError> {
    let item_id = match query.item_id {
        Some(id) => id,
        None => {
            let raw = headers
                .get("x-anvil-item-id")
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    ApiError::bad_request(
                        "MISSING_ITEM_ID",
                        "Specify parent item via `?item_id=<uuid>` query or `X-Anvil-Item-Id` header",
                    )
                })?;
            Uuid::parse_str(raw.trim())
                .map_err(|_| ApiError::bad_request("INVALID_ITEM_ID", "Invalid parent item UUID"))?
        }
    };

    if body.len() > MAX_BLOB_BYTES {
        return Err(ApiError::payload_too_large(
            "BLOB_TOO_LARGE",
            format!("Encrypted blob exceeds maximum size of {MAX_BLOB_BYTES} bytes"),
        ));
    }

    validate_envelope_bytes("encrypted_blob", &body, MAX_BLOB_BYTES)?;
    let sha256_ciphertext = Sha256::digest(&body);

    match state
        .db
        .put_blob(
            auth.user_id,
            item_id,
            blob_id,
            &body,
            sha256_ciphertext.as_slice(),
        )
        .await?
    {
        PutBlobOutcome::Saved {
            blob_id,
            revision,
            byte_size,
            ..
        } => Ok(Json(PutBlobResponse {
            blob_id,
            revision,
            byte_size,
        })),
        PutBlobOutcome::ItemNotFound => Err(ApiError::not_found(
            "ITEM_NOT_FOUND",
            "Target vault item not found",
        )),
    }
}

/// Streams an encrypted binary blob owned strictly by `auth.user_id`.
pub async fn get_blob(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let blob = state
        .db
        .get_blob(auth.user_id, blob_id)
        .await?
        .ok_or_else(|| ApiError::not_found("BLOB_NOT_FOUND", "Encrypted blob not found"))?;

    let etag_value = format!("\"{}\"", encode_lower_hex(&blob.sha256_ciphertext));
    let mut response = (StatusCode::OK, blob.encrypted_blob).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(etag) = HeaderValue::from_str(&etag_value) {
        headers.insert(header::ETAG, etag);
    }
    if let Ok(item_header) = HeaderValue::from_str(&blob.item_id.hyphenated().to_string()) {
        headers.insert("x-anvil-item-id", item_header);
    }
    if let Ok(rev_header) = HeaderValue::from_str(&blob.revision.to_string()) {
        headers.insert("x-anvil-revision", rev_header);
    }
    Ok(response)
}

/// Tombstones an encrypted binary blob owned by `auth.user_id`.
pub async fn delete_blob(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(blob_id): Path<Uuid>,
) -> Result<Json<DeleteResponse>, ApiError> {
    match state.db.delete_blob(auth.user_id, blob_id).await? {
        DeleteRecordOutcome::Deleted {
            revision,
            updated_at,
        } => Ok(Json(DeleteResponse {
            revision,
            updated_at,
        })),
        DeleteRecordOutcome::NotFound => Err(ApiError::not_found(
            "BLOB_NOT_FOUND",
            "Encrypted blob not found",
        )),
    }
}

fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
