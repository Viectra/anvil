//! Encrypted-only SQLite offline cache and mutation queue (zero plaintext persisted on disk).

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use anvil_core::crypto::KdfParams;
use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::Row;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteRow,
    SqliteSynchronous,
};
use uuid::Uuid;

use crate::error::ClientError;

const CACHE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS local_account (
    id                          INTEGER PRIMARY KEY CHECK (id = 1),
    user_id                     TEXT NOT NULL UNIQUE,
    server_url                  TEXT NOT NULL,
    email                       TEXT NOT NULL,
    role                        TEXT NOT NULL,
    kdf_memory_kib              INTEGER NOT NULL,
    kdf_iterations              INTEGER NOT NULL,
    kdf_parallelism             INTEGER NOT NULL,
    kdf_salt                    BLOB NOT NULL,
    key_version                 INTEGER NOT NULL,
    encrypted_vault_key         BLOB NOT NULL,
    last_synced_revision        INTEGER NOT NULL DEFAULT 0,
    biometric_sealed_vault_key  BLOB NULL,
    avatar_png                  BLOB NULL,
    encrypted_refresh_token     BLOB NULL,
    updated_at                  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cached_folders (
    user_id         TEXT NOT NULL,
    id              TEXT NOT NULL,
    encrypted_data  BLOB NOT NULL,
    revision        INTEGER NOT NULL,
    deleted         INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
);

CREATE TABLE IF NOT EXISTS cached_items (
    user_id         TEXT NOT NULL,
    id              TEXT NOT NULL,
    encrypted_data  BLOB NOT NULL,
    revision        INTEGER NOT NULL,
    deleted         INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
);

CREATE TABLE IF NOT EXISTS cached_blobs (
    user_id             TEXT NOT NULL,
    id                  TEXT NOT NULL,
    item_id             TEXT NOT NULL,
    encrypted_blob      BLOB NOT NULL,
    byte_size           INTEGER NOT NULL,
    sha256_ciphertext   BLOB NOT NULL,
    revision            INTEGER NOT NULL,
    deleted             INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    updated_at          TEXT NOT NULL,
    PRIMARY KEY (user_id, id)
);

CREATE TABLE IF NOT EXISTS offline_mutation_queue (
    seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             TEXT NOT NULL,
    entity_kind         TEXT NOT NULL CHECK (entity_kind IN ('folder', 'item', 'blob')),
    entity_id           TEXT NOT NULL,
    op_kind             TEXT NOT NULL CHECK (op_kind IN ('upsert', 'delete')),
    item_id             TEXT NULL,
    encrypted_payload   BLOB NULL,
    queued_at           TEXT NOT NULL,
    UNIQUE (user_id, entity_kind, entity_id)
);

CREATE TABLE IF NOT EXISTS sync_conflicts (
    id                      TEXT PRIMARY KEY,
    user_id                 TEXT NOT NULL,
    entity_kind             TEXT NOT NULL CHECK (entity_kind IN ('folder', 'item')),
    entity_id               TEXT NOT NULL,
    local_encrypted_data    BLOB NOT NULL,
    server_encrypted_data   BLOB NULL,
    server_deleted          INTEGER NOT NULL DEFAULT 0 CHECK (server_deleted IN (0, 1)),
    server_revision         INTEGER NOT NULL,
    detected_at             TEXT NOT NULL
);
"#;

/// Entity class tracked in the offline mutation queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationEntityKind {
    Folder,
    Item,
    Blob,
}

impl MutationEntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::Item => "item",
            Self::Blob => "blob",
        }
    }
}

impl FromStr for MutationEntityKind {
    type Err = ClientError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "folder" => Ok(Self::Folder),
            "item" => Ok(Self::Item),
            "blob" => Ok(Self::Blob),
            _ => Err(ClientError::CacheIntegrity(format!(
                "unknown mutation entity kind `{raw}`"
            ))),
        }
    }
}

/// Operation kind queued offline prior to server push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationOpKind {
    Upsert,
    Delete,
}

impl MutationOpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

impl FromStr for MutationOpKind {
    type Err = ClientError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "upsert" => Ok(Self::Upsert),
            "delete" => Ok(Self::Delete),
            _ => Err(ClientError::CacheIntegrity(format!(
                "unknown mutation op `{raw}`"
            ))),
        }
    }
}

/// Entity class eligible for 3-way conflict resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictEntityKind {
    Folder,
    Item,
}

impl ConflictEntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Folder => "folder",
            Self::Item => "item",
        }
    }
}

impl FromStr for ConflictEntityKind {
    type Err = ClientError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "folder" => Ok(Self::Folder),
            "item" => Ok(Self::Item),
            _ => Err(ClientError::CacheIntegrity(format!(
                "unknown conflict entity kind `{raw}`"
            ))),
        }
    }
}

/// Cached local account header containing only public KDF metadata and the client-wrapped `VaultKey`.
#[derive(Clone)]
pub struct CachedAccount {
    pub user_id: Uuid,
    pub server_url: String,
    pub email: String,
    pub role: String,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub kdf_salt: Vec<u8>,
    pub key_version: u32,
    pub encrypted_vault_key: Vec<u8>,
    pub last_synced_revision: i64,
    pub biometric_sealed_vault_key: Option<Vec<u8>>,
    pub avatar_png: Option<Vec<u8>>,
    pub encrypted_refresh_token: Option<Vec<u8>>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for CachedAccount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedAccount")
            .field("user_id", &self.user_id)
            .field("server_url", &self.server_url)
            .field("email", &self.email)
            .field("key_version", &self.key_version)
            .field("last_synced_revision", &self.last_synced_revision)
            .field(
                "has_biometric_seal",
                &self.biometric_sealed_vault_key.is_some(),
            )
            .finish()
    }
}

/// Cached encrypted folder row.
#[derive(Debug, Clone)]
pub struct CachedEncryptedFolder {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Cached encrypted item row.
#[derive(Debug, Clone)]
pub struct CachedEncryptedItem {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Cached encrypted binary blob row.
#[derive(Debug, Clone)]
pub struct CachedEncryptedBlob {
    pub id: Uuid,
    pub item_id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub byte_size: i32,
    pub sha256_ciphertext: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Coalesced offline mutation queued for transmission on the next sync pass.
#[derive(Debug, Clone)]
pub struct QueuedMutation {
    pub seq: i64,
    pub user_id: Uuid,
    pub entity_kind: MutationEntityKind,
    pub entity_id: Uuid,
    pub op_kind: MutationOpKind,
    pub item_id: Option<Uuid>,
    pub encrypted_payload: Option<Vec<u8>>,
    pub queued_at: DateTime<Utc>,
}

/// Persisted encrypted sync conflict awaiting interactive resolution.
#[derive(Debug, Clone)]
pub struct StoredSyncConflict {
    pub id: Uuid,
    pub user_id: Uuid,
    pub entity_kind: ConflictEntityKind,
    pub entity_id: Uuid,
    pub local_encrypted_data: Vec<u8>,
    pub server_encrypted_data: Option<Vec<u8>>,
    pub server_deleted: bool,
    pub server_revision: i64,
    pub detected_at: DateTime<Utc>,
}

/// Encrypted-only SQLite local cache (`WAL` mode + `foreign_keys = ON`).
#[derive(Clone)]
pub struct EncryptedLocalCache {
    pool: SqlitePool,
}

impl fmt::Debug for EncryptedLocalCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedLocalCache(..)")
    }
}

impl EncryptedLocalCache {
    /// Opens or creates the SQLite cache file at `database_url` (e.g. `sqlite:///path/cache.db` or `sqlite::memory:`).
    pub async fn connect(database_url: &str) -> Result<Self, ClientError> {
        let is_memory = database_url == "sqlite::memory:" || database_url.contains("mode=memory");
        let opts = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(if is_memory { 1 } else { 4 })
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(opts)
            .await?;

        sqlx::raw_sql(CACHE_SCHEMA_SQL).execute(&pool).await?;

        // Seamlessly migrate existing on-disk SQLite caches lacking avatar_png / encrypted_refresh_token.
        let cols = sqlx::query("PRAGMA table_info(local_account)")
            .fetch_all(&pool)
            .await?;
        let col_names: HashSet<String> = cols
            .iter()
            .filter_map(|r| r.try_get::<String, _>("name").ok())
            .collect();
        if !col_names.contains("avatar_png") {
            sqlx::query("ALTER TABLE local_account ADD COLUMN avatar_png BLOB NULL")
                .execute(&pool)
                .await?;
        }
        if !col_names.contains("encrypted_refresh_token") {
            sqlx::query("ALTER TABLE local_account ADD COLUMN encrypted_refresh_token BLOB NULL")
                .execute(&pool)
                .await?;
        }

        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn save_account(&self, acct: &CachedAccount) -> Result<(), ClientError> {
        sqlx::query(
            "INSERT INTO local_account (
                id, user_id, server_url, email, role, kdf_memory_kib, kdf_iterations,
                kdf_parallelism, kdf_salt, key_version, encrypted_vault_key,
                last_synced_revision, biometric_sealed_vault_key, avatar_png,
                encrypted_refresh_token, updated_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT (id) DO UPDATE SET
                user_id = excluded.user_id,
                server_url = excluded.server_url,
                email = excluded.email,
                role = excluded.role,
                kdf_memory_kib = excluded.kdf_memory_kib,
                kdf_iterations = excluded.kdf_iterations,
                kdf_parallelism = excluded.kdf_parallelism,
                kdf_salt = excluded.kdf_salt,
                key_version = excluded.key_version,
                encrypted_vault_key = excluded.encrypted_vault_key,
                last_synced_revision = excluded.last_synced_revision,
                biometric_sealed_vault_key = CASE
                    WHEN local_account.user_id = excluded.user_id
                    THEN COALESCE(excluded.biometric_sealed_vault_key, local_account.biometric_sealed_vault_key)
                    ELSE excluded.biometric_sealed_vault_key
                END,
                avatar_png = excluded.avatar_png,
                encrypted_refresh_token = CASE
                    WHEN local_account.user_id = excluded.user_id
                    THEN COALESCE(excluded.encrypted_refresh_token, local_account.encrypted_refresh_token)
                    ELSE excluded.encrypted_refresh_token
                END,
                updated_at = excluded.updated_at",
        )
        .bind(fmt_uuid(acct.user_id))
        .bind(&acct.server_url)
        .bind(&acct.email)
        .bind(&acct.role)
        .bind(i64::from(acct.kdf_memory_kib))
        .bind(i64::from(acct.kdf_iterations))
        .bind(i64::from(acct.kdf_parallelism))
        .bind(&acct.kdf_salt)
        .bind(i64::from(acct.key_version))
        .bind(&acct.encrypted_vault_key)
        .bind(acct.last_synced_revision)
        .bind(&acct.biometric_sealed_vault_key)
        .bind(&acct.avatar_png)
        .bind(&acct.encrypted_refresh_token)
        .bind(fmt_ts(acct.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn load_account(&self) -> Result<Option<CachedAccount>, ClientError> {
        let row = sqlx::query(
            "SELECT user_id, server_url, email, role, kdf_memory_kib, kdf_iterations,
                    kdf_parallelism, kdf_salt, key_version, encrypted_vault_key,
                    last_synced_revision, biometric_sealed_vault_key, avatar_png,
                    encrypted_refresh_token, updated_at
             FROM local_account
             WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(decode_account).transpose()
    }

    pub async fn set_account_profile(
        &self,
        user_id: Uuid,
        email: &str,
        role: &str,
        avatar_png: Option<&[u8]>,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "UPDATE local_account
             SET email = ?1, role = ?2, avatar_png = ?3, updated_at = ?4
             WHERE user_id = ?5",
        )
        .bind(email)
        .bind(role)
        .bind(avatar_png)
        .bind(fmt_ts(Utc::now()))
        .bind(fmt_uuid(user_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_account_avatar(
        &self,
        user_id: Uuid,
        avatar_png: Option<&[u8]>,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "UPDATE local_account
             SET avatar_png = ?1, updated_at = ?2
             WHERE user_id = ?3",
        )
        .bind(avatar_png)
        .bind(fmt_ts(Utc::now()))
        .bind(fmt_uuid(user_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_encrypted_refresh_token(
        &self,
        user_id: Uuid,
        encrypted_refresh_token: Option<&[u8]>,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "UPDATE local_account
             SET encrypted_refresh_token = ?1, updated_at = ?2
             WHERE user_id = ?3",
        )
        .bind(encrypted_refresh_token)
        .bind(fmt_ts(Utc::now()))
        .bind(fmt_uuid(user_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_biometric_seal(
        &self,
        user_id: Uuid,
        sealed_vault_key: Option<&[u8]>,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "UPDATE local_account
             SET biometric_sealed_vault_key = ?1, updated_at = ?2
             WHERE user_id = ?3",
        )
        .bind(sealed_vault_key)
        .bind(fmt_ts(Utc::now()))
        .bind(fmt_uuid(user_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_synced_revision(
        &self,
        user_id: Uuid,
        revision: i64,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "UPDATE local_account
             SET last_synced_revision = ?1, updated_at = ?2
             WHERE user_id = ?3",
        )
        .bind(revision)
        .bind(fmt_ts(Utc::now()))
        .bind(fmt_uuid(user_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_key_material(
        &self,
        user_id: Uuid,
        kdf_params: KdfParams,
        kdf_salt: &[u8],
        key_version: u32,
        encrypted_vault_key: &[u8],
    ) -> Result<(), ClientError> {
        sqlx::query(
            "UPDATE local_account
             SET kdf_memory_kib = ?1,
                 kdf_iterations = ?2,
                 kdf_parallelism = ?3,
                 kdf_salt = ?4,
                 key_version = ?5,
                 encrypted_vault_key = ?6,
                 updated_at = ?7
             WHERE user_id = ?8",
        )
        .bind(i64::from(kdf_params.memory_kib))
        .bind(i64::from(kdf_params.iterations))
        .bind(i64::from(kdf_params.parallelism))
        .bind(kdf_salt)
        .bind(i64::from(key_version))
        .bind(encrypted_vault_key)
        .bind(fmt_ts(Utc::now()))
        .bind(fmt_uuid(user_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_cached_folder(
        &self,
        user_id: Uuid,
        folder: &CachedEncryptedFolder,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "INSERT INTO cached_folders (user_id, id, encrypted_data, revision, deleted, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (user_id, id) DO UPDATE SET
                encrypted_data = excluded.encrypted_data,
                revision = excluded.revision,
                deleted = excluded.deleted,
                updated_at = excluded.updated_at",
        )
        .bind(fmt_uuid(user_id))
        .bind(fmt_uuid(folder.id))
        .bind(&folder.encrypted_data)
        .bind(folder.revision)
        .bind(i64::from(folder.deleted))
        .bind(fmt_ts(folder.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_cached_item(
        &self,
        user_id: Uuid,
        item: &CachedEncryptedItem,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "INSERT INTO cached_items (user_id, id, encrypted_data, revision, deleted, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (user_id, id) DO UPDATE SET
                encrypted_data = excluded.encrypted_data,
                revision = excluded.revision,
                deleted = excluded.deleted,
                updated_at = excluded.updated_at",
        )
        .bind(fmt_uuid(user_id))
        .bind(fmt_uuid(item.id))
        .bind(&item.encrypted_data)
        .bind(item.revision)
        .bind(i64::from(item.deleted))
        .bind(fmt_ts(item.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_cached_blob(
        &self,
        user_id: Uuid,
        blob: &CachedEncryptedBlob,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "INSERT INTO cached_blobs (
                user_id, id, item_id, encrypted_blob, byte_size, sha256_ciphertext,
                revision, deleted, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (user_id, id) DO UPDATE SET
                item_id = excluded.item_id,
                encrypted_blob = excluded.encrypted_blob,
                byte_size = excluded.byte_size,
                sha256_ciphertext = excluded.sha256_ciphertext,
                revision = excluded.revision,
                deleted = excluded.deleted,
                updated_at = excluded.updated_at",
        )
        .bind(fmt_uuid(user_id))
        .bind(fmt_uuid(blob.id))
        .bind(fmt_uuid(blob.item_id))
        .bind(&blob.encrypted_blob)
        .bind(i64::from(blob.byte_size))
        .bind(&blob.sha256_ciphertext)
        .bind(blob.revision)
        .bind(i64::from(blob.deleted))
        .bind(fmt_ts(blob.updated_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_blob_deleted(&self, user_id: Uuid, blob_id: Uuid) -> Result<(), ClientError> {
        sqlx::query(
            "UPDATE cached_blobs SET deleted = 1, updated_at = ?1 WHERE user_id = ?2 AND id = ?3",
        )
        .bind(fmt_ts(Utc::now()))
        .bind(fmt_uuid(user_id))
        .bind(fmt_uuid(blob_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_active_folders(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<CachedEncryptedFolder>, ClientError> {
        let rows = sqlx::query(
            "SELECT id, encrypted_data, revision, deleted, updated_at
             FROM cached_folders
             WHERE user_id = ?1 AND deleted = 0",
        )
        .bind(fmt_uuid(user_id))
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(CachedEncryptedFolder {
                    id: get_uuid(r, "id")?,
                    encrypted_data: r.try_get("encrypted_data")?,
                    revision: r.try_get("revision")?,
                    deleted: get_bool(r, "deleted")?,
                    updated_at: get_ts(r, "updated_at")?,
                })
            })
            .collect()
    }

    pub async fn list_active_items(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<CachedEncryptedItem>, ClientError> {
        let rows = sqlx::query(
            "SELECT id, encrypted_data, revision, deleted, updated_at
             FROM cached_items
             WHERE user_id = ?1 AND deleted = 0",
        )
        .bind(fmt_uuid(user_id))
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                Ok(CachedEncryptedItem {
                    id: get_uuid(r, "id")?,
                    encrypted_data: r.try_get("encrypted_data")?,
                    revision: r.try_get("revision")?,
                    deleted: get_bool(r, "deleted")?,
                    updated_at: get_ts(r, "updated_at")?,
                })
            })
            .collect()
    }

    pub async fn get_cached_blob(
        &self,
        user_id: Uuid,
        blob_id: Uuid,
    ) -> Result<Option<CachedEncryptedBlob>, ClientError> {
        let row = sqlx::query(
            "SELECT id, item_id, encrypted_blob, byte_size, sha256_ciphertext, revision, deleted, updated_at
             FROM cached_blobs
             WHERE user_id = ?1 AND id = ?2 AND deleted = 0",
        )
        .bind(fmt_uuid(user_id))
        .bind(fmt_uuid(blob_id))
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref()
            .map(|r| {
                Ok(CachedEncryptedBlob {
                    id: get_uuid(r, "id")?,
                    item_id: get_uuid(r, "item_id")?,
                    encrypted_blob: r.try_get("encrypted_blob")?,
                    byte_size: to_i32(r.try_get("byte_size")?, "byte_size")?,
                    sha256_ciphertext: r.try_get("sha256_ciphertext")?,
                    revision: r.try_get("revision")?,
                    deleted: get_bool(r, "deleted")?,
                    updated_at: get_ts(r, "updated_at")?,
                })
            })
            .transpose()
    }

    /// Enqueues or coalesces an offline mutation inside `(user_id, entity_kind, entity_id)`.
    pub async fn queue_mutation(
        &self,
        user_id: Uuid,
        entity_kind: MutationEntityKind,
        entity_id: Uuid,
        op_kind: MutationOpKind,
        item_id: Option<Uuid>,
        encrypted_payload: Option<&[u8]>,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "INSERT INTO offline_mutation_queue (
                user_id, entity_kind, entity_id, op_kind, item_id, encrypted_payload, queued_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT (user_id, entity_kind, entity_id) DO UPDATE SET
                op_kind = excluded.op_kind,
                item_id = excluded.item_id,
                encrypted_payload = excluded.encrypted_payload,
                queued_at = excluded.queued_at",
        )
        .bind(fmt_uuid(user_id))
        .bind(entity_kind.as_str())
        .bind(fmt_uuid(entity_id))
        .bind(op_kind.as_str())
        .bind(item_id.map(fmt_uuid))
        .bind(encrypted_payload)
        .bind(fmt_ts(Utc::now()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_queued_mutations(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<QueuedMutation>, ClientError> {
        let rows = sqlx::query(
            "SELECT seq, user_id, entity_kind, entity_id, op_kind, item_id, encrypted_payload, queued_at
             FROM offline_mutation_queue
             WHERE user_id = ?1
             ORDER BY seq ASC",
        )
        .bind(fmt_uuid(user_id))
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let kind_str: String = r.try_get("entity_kind")?;
                let op_str: String = r.try_get("op_kind")?;
                Ok(QueuedMutation {
                    seq: r.try_get("seq")?,
                    user_id: get_uuid(r, "user_id")?,
                    entity_kind: MutationEntityKind::from_str(&kind_str)?,
                    entity_id: get_uuid(r, "entity_id")?,
                    op_kind: MutationOpKind::from_str(&op_str)?,
                    item_id: get_opt_uuid(r, "item_id")?,
                    encrypted_payload: r.try_get("encrypted_payload")?,
                    queued_at: get_ts(r, "queued_at")?,
                })
            })
            .collect()
    }

    pub async fn remove_queued_mutation(
        &self,
        user_id: Uuid,
        entity_kind: MutationEntityKind,
        entity_id: Uuid,
    ) -> Result<(), ClientError> {
        sqlx::query(
            "DELETE FROM offline_mutation_queue
             WHERE user_id = ?1 AND entity_kind = ?2 AND entity_id = ?3",
        )
        .bind(fmt_uuid(user_id))
        .bind(entity_kind.as_str())
        .bind(fmt_uuid(entity_id))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn save_conflict(&self, conflict: &StoredSyncConflict) -> Result<(), ClientError> {
        sqlx::query(
            "INSERT INTO sync_conflicts (
                id, user_id, entity_kind, entity_id, local_encrypted_data,
                server_encrypted_data, server_deleted, server_revision, detected_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT (id) DO UPDATE SET
                local_encrypted_data = excluded.local_encrypted_data,
                server_encrypted_data = excluded.server_encrypted_data,
                server_deleted = excluded.server_deleted,
                server_revision = excluded.server_revision,
                detected_at = excluded.detected_at",
        )
        .bind(fmt_uuid(conflict.id))
        .bind(fmt_uuid(conflict.user_id))
        .bind(conflict.entity_kind.as_str())
        .bind(fmt_uuid(conflict.entity_id))
        .bind(&conflict.local_encrypted_data)
        .bind(&conflict.server_encrypted_data)
        .bind(i64::from(conflict.server_deleted))
        .bind(conflict.server_revision)
        .bind(fmt_ts(conflict.detected_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_conflicts(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<StoredSyncConflict>, ClientError> {
        let rows = sqlx::query(
            "SELECT id, user_id, entity_kind, entity_id, local_encrypted_data,
                    server_encrypted_data, server_deleted, server_revision, detected_at
             FROM sync_conflicts
             WHERE user_id = ?1
             ORDER BY detected_at ASC",
        )
        .bind(fmt_uuid(user_id))
        .fetch_all(&self.pool)
        .await?;

        rows.iter()
            .map(|r| {
                let kind_str: String = r.try_get("entity_kind")?;
                Ok(StoredSyncConflict {
                    id: get_uuid(r, "id")?,
                    user_id: get_uuid(r, "user_id")?,
                    entity_kind: ConflictEntityKind::from_str(&kind_str)?,
                    entity_id: get_uuid(r, "entity_id")?,
                    local_encrypted_data: r.try_get("local_encrypted_data")?,
                    server_encrypted_data: r.try_get("server_encrypted_data")?,
                    server_deleted: get_bool(r, "server_deleted")?,
                    server_revision: r.try_get("server_revision")?,
                    detected_at: get_ts(r, "detected_at")?,
                })
            })
            .collect()
    }

    pub async fn delete_conflict(
        &self,
        user_id: Uuid,
        conflict_id: Uuid,
    ) -> Result<(), ClientError> {
        sqlx::query("DELETE FROM sync_conflicts WHERE user_id = ?1 AND id = ?2")
            .bind(fmt_uuid(user_id))
            .bind(fmt_uuid(conflict_id))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn clear_all(&self) -> Result<(), ClientError> {
        sqlx::raw_sql(
            "DELETE FROM sync_conflicts;
             DELETE FROM offline_mutation_queue;
             DELETE FROM cached_blobs;
             DELETE FROM cached_items;
             DELETE FROM cached_folders;
             DELETE FROM local_account;",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

fn fmt_uuid(id: Uuid) -> String {
    id.hyphenated().to_string()
}

fn fmt_ts(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn get_uuid(row: &SqliteRow, col: &str) -> Result<Uuid, ClientError> {
    let raw: String = row.try_get(col)?;
    Uuid::parse_str(&raw)
        .map_err(|e| ClientError::CacheIntegrity(format!("invalid UUID in `{col}`: {e}")))
}

fn get_opt_uuid(row: &SqliteRow, col: &str) -> Result<Option<Uuid>, ClientError> {
    let raw: Option<String> = row.try_get(col)?;
    raw.map(|s| {
        Uuid::parse_str(&s)
            .map_err(|e| ClientError::CacheIntegrity(format!("invalid UUID in `{col}`: {e}")))
    })
    .transpose()
}

fn get_ts(row: &SqliteRow, col: &str) -> Result<DateTime<Utc>, ClientError> {
    let raw: String = row.try_get(col)?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| ClientError::CacheIntegrity(format!("invalid timestamp in `{col}`: {e}")))
}

fn get_bool(row: &SqliteRow, col: &str) -> Result<bool, ClientError> {
    let raw: i64 = row.try_get(col)?;
    Ok(raw != 0)
}

fn to_u32(val: i64, field: &str) -> Result<u32, ClientError> {
    u32::try_from(val)
        .map_err(|_| ClientError::CacheIntegrity(format!("invalid `{field}` in local cache")))
}

fn to_i32(val: i64, field: &str) -> Result<i32, ClientError> {
    i32::try_from(val)
        .map_err(|_| ClientError::CacheIntegrity(format!("invalid `{field}` in local cache")))
}

fn decode_account(row: &SqliteRow) -> Result<CachedAccount, ClientError> {
    Ok(CachedAccount {
        user_id: get_uuid(row, "user_id")?,
        server_url: row.try_get("server_url")?,
        email: row.try_get("email")?,
        role: row.try_get("role")?,
        kdf_memory_kib: to_u32(row.try_get("kdf_memory_kib")?, "kdf_memory_kib")?,
        kdf_iterations: to_u32(row.try_get("kdf_iterations")?, "kdf_iterations")?,
        kdf_parallelism: to_u32(row.try_get("kdf_parallelism")?, "kdf_parallelism")?,
        kdf_salt: row.try_get("kdf_salt")?,
        key_version: to_u32(row.try_get("key_version")?, "key_version")?,
        encrypted_vault_key: row.try_get("encrypted_vault_key")?,
        last_synced_revision: row.try_get("last_synced_revision")?,
        biometric_sealed_vault_key: row.try_get("biometric_sealed_vault_key")?,
        avatar_png: row.try_get("avatar_png")?,
        encrypted_refresh_token: row.try_get("encrypted_refresh_token")?,
        updated_at: get_ts(row, "updated_at")?,
    })
}
