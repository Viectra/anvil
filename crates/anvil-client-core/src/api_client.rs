//! HTTP REST client for `anvil-server` with automatic single-flight JWT refresh.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::crypto::KdfParams;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, ETAG, HeaderMap};
use reqwest::{Client, Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::ClientError;

#[derive(Debug, Clone, Deserialize)]
struct ServerErrorWrapper {
    error: ServerErrorDetail,
    #[serde(default)]
    sync: Option<SyncResponseDto>,
}

#[derive(Debug, Clone, Deserialize)]
struct ServerErrorDetail {
    code: String,
    message: String,
    #[serde(default)]
    request_id: String,
}

/// Public server health response.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthResponseDto {
    pub status: String,
    pub version: String,
    pub db_ok: bool,
}

/// Public instance discovery metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct MetaResponseDto {
    pub signups_enabled: bool,
    pub server_version: String,
    pub default_kdf: KdfParams,
    pub favicon_proxy_enabled: bool,
    pub max_blob_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PreloginResponseDto {
    pub kdf_algorithm: anvil_core::crypto::KdfAlgorithm,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub kdf_salt_b64: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterRequestDto {
    pub user_id: Uuid,
    pub email: String,
    pub kdf_params: KdfParams,
    pub kdf_salt_b64: String,
    pub master_auth_hash_b64: String,
    pub encrypted_vault_key_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    pub device_name: String,
    pub device_platform: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicUserProfileDto {
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub kdf_params: KdfParams,
    pub key_version: u32,
    pub sync_revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterResponseDto {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub user: PublicUserProfileDto,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginResponseDto {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub user_id: Uuid,
    pub email: String,
    pub role: String,
    pub key_version: u32,
    pub encrypted_vault_key_b64: String,
    pub sync_revision: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshResponseDto {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireFolderDto {
    pub id: Uuid,
    pub encrypted_data_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireItemDto {
    pub id: Uuid,
    pub encrypted_data_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WireBlobMetaDto {
    pub id: Uuid,
    pub item_id: Uuid,
    pub byte_size: i32,
    pub sha256_ciphertext_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncResponseDto {
    pub current_revision: i64,
    pub key_version: u32,
    pub encrypted_vault_key_b64: String,
    pub folders: Vec<WireFolderDto>,
    pub items: Vec<WireItemDto>,
    pub blobs_meta: Vec<WireBlobMetaDto>,
}

#[derive(Debug, Serialize)]
pub struct FolderUpsertDto {
    pub id: Uuid,
    pub encrypted_data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct ItemUpsertDto {
    pub id: Uuid,
    pub encrypted_data_b64: String,
}

#[derive(Debug, Serialize)]
pub struct SyncPushRequestDto {
    pub base_revision: i64,
    pub folders_upsert: Vec<FolderUpsertDto>,
    pub folders_delete_ids: Vec<Uuid>,
    pub items_upsert: Vec<ItemUpsertDto>,
    pub items_delete_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncPushResponseDto {
    pub new_revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub enum PushSyncOutcome {
    Committed(SyncPushResponseDto),
    Conflict(SyncResponseDto),
}

#[derive(Debug, Clone, Deserialize)]
pub struct PutBlobResponseDto {
    pub blob_id: Uuid,
    pub revision: i64,
    pub byte_size: i32,
}

#[derive(Debug, Clone)]
pub struct DownloadedBlob {
    pub item_id: Option<Uuid>,
    pub revision: i64,
    pub etag_hex: Option<String>,
    pub encrypted_bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct RotatePasswordRequestDto {
    pub current_master_auth_hash_b64: String,
    pub new_master_auth_hash_b64: String,
    pub new_kdf_salt_b64: String,
    pub new_kdf_params: KdfParams,
    pub new_key_version: u32,
    pub new_encrypted_vault_key_b64: String,
    pub revoke_other_sessions: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RotatePasswordResponseDto {
    pub key_version: u32,
    pub rotated_at: DateTime<Utc>,
}

/// Active bearer and refresh tokens kept purely in volatile RAM.
#[derive(Clone)]
pub struct SessionTokens {
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
}

impl fmt::Debug for SessionTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionTokens([REDACTED])")
    }
}

/// Async REST client targeting one `anvil-server` base URL.
#[derive(Clone)]
pub struct AnvilApiClient {
    base_url: String,
    http: Client,
    tokens: Arc<RwLock<Option<SessionTokens>>>,
    refresh_lock: Arc<Mutex<()>>,
}

impl fmt::Debug for AnvilApiClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnvilApiClient")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl AnvilApiClient {
    pub fn new(server_url: &str) -> Result<Self, ClientError> {
        let parsed = Url::parse(server_url.trim())
            .map_err(|e| ClientError::InvalidServerUrl(e.to_string()))?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
            return Err(ClientError::InvalidServerUrl(
                "server URL must use http or https with a valid host".to_owned(),
            ));
        }

        let normalized = server_url.trim().trim_end_matches('/').to_owned();
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("Anvil-Client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ClientError::Network(e.to_string()))?;

        Ok(Self {
            base_url: normalized,
            http,
            tokens: Arc::new(RwLock::new(None)),
            refresh_lock: Arc::new(Mutex::new(())),
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn set_tokens(&self, access_token: String, refresh_token: String) {
        let mut guard = self.tokens.write().await;
        *guard = Some(SessionTokens {
            access_token: Zeroizing::new(access_token),
            refresh_token: Zeroizing::new(refresh_token),
        });
    }

    pub async fn clear_tokens(&self) {
        let mut guard = self.tokens.write().await;
        *guard = None;
    }

    pub async fn has_session(&self) -> bool {
        self.tokens.read().await.is_some()
    }

    pub async fn current_tokens(&self) -> Option<(String, String)> {
        self.tokens
            .read()
            .await
            .as_ref()
            .map(|t| (t.access_token.to_string(), t.refresh_token.to_string()))
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }

    pub async fn health(&self) -> Result<HealthResponseDto, ClientError> {
        let (status, _, bytes) = self
            .send_raw(Method::GET, "/api/v1/health", None, None, None)
            .await?;
        decode_ok_or_error(status, &bytes)
    }

    pub async fn meta(&self) -> Result<MetaResponseDto, ClientError> {
        let (status, _, bytes) = self
            .send_raw(Method::GET, "/api/v1/meta", None, None, None)
            .await?;
        decode_ok_or_error(status, &bytes)
    }

    pub async fn prelogin(&self, email: &str) -> Result<PreloginResponseDto, ClientError> {
        #[derive(Serialize)]
        struct PreloginBody<'a> {
            email: &'a str,
        }
        let body = serde_json::to_vec(&PreloginBody { email })
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
        let (status, _, bytes) = self
            .send_raw(
                Method::POST,
                "/api/v1/auth/prelogin",
                None,
                Some("application/json"),
                Some(body),
            )
            .await?;
        decode_ok_or_error(status, &bytes)
    }

    pub async fn register(
        &self,
        req: &RegisterRequestDto,
    ) -> Result<RegisterResponseDto, ClientError> {
        let body =
            serde_json::to_vec(req).map_err(|e| ClientError::Serialization(e.to_string()))?;
        let (status, _, bytes) = self
            .send_raw(
                Method::POST,
                "/api/v1/auth/register",
                None,
                Some("application/json"),
                Some(body),
            )
            .await?;
        let dto: RegisterResponseDto = decode_ok_or_error(status, &bytes)?;
        self.set_tokens(dto.access_token.clone(), dto.refresh_token.clone())
            .await;
        Ok(dto)
    }

    pub async fn login(
        &self,
        email: &str,
        master_auth_hash: &[u8; 32],
        device_name: &str,
        device_platform: &str,
    ) -> Result<LoginResponseDto, ClientError> {
        #[derive(Serialize)]
        struct LoginBody<'a> {
            email: &'a str,
            master_auth_hash_b64: String,
            device_name: &'a str,
            device_platform: &'a str,
        }
        let body = serde_json::to_vec(&LoginBody {
            email,
            master_auth_hash_b64: STANDARD.encode(master_auth_hash),
            device_name,
            device_platform,
        })
        .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let (status, _, bytes) = self
            .send_raw(
                Method::POST,
                "/api/v1/auth/login",
                None,
                Some("application/json"),
                Some(body),
            )
            .await?;
        let dto: LoginResponseDto = decode_ok_or_error(status, &bytes)?;
        self.set_tokens(dto.access_token.clone(), dto.refresh_token.clone())
            .await;
        Ok(dto)
    }

    pub async fn logout(&self) -> Result<(), ClientError> {
        if let Some((access, refresh)) = self.current_tokens().await {
            #[derive(Serialize)]
            struct LogoutBody {
                refresh_token: String,
            }
            let body = serde_json::to_vec(&LogoutBody {
                refresh_token: refresh,
            })
            .map_err(|e| ClientError::Serialization(e.to_string()))?;
            let _ = self
                .send_raw(
                    Method::POST,
                    "/api/v1/auth/logout",
                    Some(&access),
                    Some("application/json"),
                    Some(body),
                )
                .await;
        }
        self.clear_tokens().await;
        Ok(())
    }

    pub async fn pull_sync(&self, since_revision: i64) -> Result<SyncResponseDto, ClientError> {
        let path = format!("/api/v1/vault/sync?since_revision={since_revision}");
        let (status, _, bytes) = self
            .send_authenticated(Method::GET, &path, None, None)
            .await?;
        decode_ok_or_error(status, &bytes)
    }

    pub async fn push_sync(
        &self,
        req: &SyncPushRequestDto,
    ) -> Result<PushSyncOutcome, ClientError> {
        let body =
            serde_json::to_vec(req).map_err(|e| ClientError::Serialization(e.to_string()))?;
        let (status, _, bytes) = self
            .send_authenticated(
                Method::POST,
                "/api/v1/vault/sync",
                Some("application/json"),
                Some(body),
            )
            .await?;

        if status == StatusCode::CONFLICT {
            let parsed: ServerErrorWrapper = serde_json::from_slice(&bytes)
                .map_err(|e| ClientError::Serialization(e.to_string()))?;
            let sync = parsed.sync.ok_or_else(|| {
                ClientError::Serialization("missing sync delta in 409 conflict payload".to_owned())
            })?;
            return Ok(PushSyncOutcome::Conflict(sync));
        }

        let committed: SyncPushResponseDto = decode_ok_or_error(status, &bytes)?;
        Ok(PushSyncOutcome::Committed(committed))
    }

    pub async fn put_blob(
        &self,
        item_id: Uuid,
        blob_id: Uuid,
        encrypted_blob: Vec<u8>,
    ) -> Result<PutBlobResponseDto, ClientError> {
        let path = format!(
            "/api/v1/vault/blobs/{}?item_id={}",
            blob_id.hyphenated(),
            item_id.hyphenated()
        );
        let (status, _, bytes) = self
            .send_authenticated(
                Method::PUT,
                &path,
                Some("application/octet-stream"),
                Some(encrypted_blob),
            )
            .await?;
        decode_ok_or_error(status, &bytes)
    }

    pub async fn get_blob(&self, blob_id: Uuid) -> Result<DownloadedBlob, ClientError> {
        let path = format!("/api/v1/vault/blobs/{}", blob_id.hyphenated());
        let (status, headers, bytes) = self
            .send_authenticated(Method::GET, &path, None, None)
            .await?;
        if !status.is_success() {
            return Err(parse_server_error(status, &bytes));
        }

        let item_id = headers
            .get("x-anvil-item-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| Uuid::parse_str(s).ok());
        let revision = headers
            .get("x-anvil-revision")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(1);
        let etag_hex = headers
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim_matches('"').to_owned());

        Ok(DownloadedBlob {
            item_id,
            revision,
            etag_hex,
            encrypted_bytes: bytes,
        })
    }

    pub async fn delete_blob(&self, blob_id: Uuid) -> Result<i64, ClientError> {
        #[derive(Deserialize)]
        struct DelResp {
            revision: i64,
        }
        let path = format!("/api/v1/vault/blobs/{}", blob_id.hyphenated());
        let (status, _, bytes) = self
            .send_authenticated(Method::DELETE, &path, None, None)
            .await?;
        let resp: DelResp = decode_ok_or_error(status, &bytes)?;
        Ok(resp.revision)
    }

    pub async fn rotate_password(
        &self,
        req: &RotatePasswordRequestDto,
    ) -> Result<RotatePasswordResponseDto, ClientError> {
        let body =
            serde_json::to_vec(req).map_err(|e| ClientError::Serialization(e.to_string()))?;
        let (status, _, bytes) = self
            .send_authenticated(
                Method::POST,
                "/api/v1/account/rotate-password",
                Some("application/json"),
                Some(body),
            )
            .await?;
        decode_ok_or_error(status, &bytes)
    }

    async fn send_authenticated(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
        let current = self.tokens.read().await.clone();
        let Some(tokens) = current else {
            return Err(ClientError::NotAuthenticated);
        };

        let failed_access = tokens.access_token.to_string();
        let (status, headers, bytes) = self
            .send_raw(
                method.clone(),
                path,
                Some(&failed_access),
                content_type,
                body.clone(),
            )
            .await?;

        if status != StatusCode::UNAUTHORIZED {
            return Ok((status, headers, bytes));
        }

        if self.refresh_single_flight(&failed_access).await?
            && let Some(fresh) = self.tokens.read().await.clone()
        {
            return self
                .send_raw(method, path, Some(&fresh.access_token), content_type, body)
                .await;
        }

        Ok((status, headers, bytes))
    }

    async fn refresh_single_flight(&self, failed_access_token: &str) -> Result<bool, ClientError> {
        #[derive(Serialize)]
        struct RefreshBody {
            refresh_token: String,
        }

        let _guard = self.refresh_lock.lock().await;
        let current = self.tokens.read().await.clone();
        let Some(tokens) = current else {
            return Ok(false);
        };
        if tokens.access_token.as_str() != failed_access_token {
            return Ok(true);
        }

        let body = serde_json::to_vec(&RefreshBody {
            refresh_token: tokens.refresh_token.to_string(),
        })
        .map_err(|e| ClientError::Serialization(e.to_string()))?;

        let (status, _, bytes) = self
            .send_raw(
                Method::POST,
                "/api/v1/auth/refresh",
                None,
                Some("application/json"),
                Some(body),
            )
            .await?;

        if !status.is_success() {
            if status == StatusCode::UNAUTHORIZED {
                self.clear_tokens().await;
            }
            return Err(parse_server_error(status, &bytes));
        }

        let refreshed: RefreshResponseDto = decode_ok_or_error(status, &bytes)?;
        self.set_tokens(refreshed.access_token, refreshed.refresh_token)
            .await;
        Ok(true)
    }

    async fn send_raw(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        content_type: Option<&str>,
        body: Option<Vec<u8>>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
        let mut req = self.http.request(method, self.endpoint(path));
        if let Some(tok) = bearer {
            req = req.header(AUTHORIZATION, format!("Bearer {tok}"));
        }
        if let Some(ct) = content_type {
            req = req.header(CONTENT_TYPE, ct);
        }
        if let Some(payload) = body {
            req = req.body(payload);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Network(e.to_string()))?
            .to_vec();
        Ok((status, headers, bytes))
    }
}

fn decode_ok_or_error<T: DeserializeOwned>(
    status: StatusCode,
    bytes: &[u8],
) -> Result<T, ClientError> {
    if !status.is_success() {
        return Err(parse_server_error(status, bytes));
    }
    serde_json::from_slice(bytes).map_err(|e| ClientError::Serialization(e.to_string()))
}

fn parse_server_error(status: StatusCode, bytes: &[u8]) -> ClientError {
    if let Ok(parsed) = serde_json::from_slice::<ServerErrorWrapper>(bytes) {
        return ClientError::ServerError {
            status: status.as_u16(),
            code: parsed.error.code,
            message: parsed.error.message,
            request_id: parsed.error.request_id,
        };
    }
    let fallback_msg = std::str::from_utf8(bytes)
        .ok()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unexpected server response")
        .to_owned();
    ClientError::ServerError {
        status: status.as_u16(),
        code: "HTTP_ERROR".to_owned(),
        message: fallback_msg,
        request_id: String::new(),
    }
}
