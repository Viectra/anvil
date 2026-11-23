//! Dual-backend SQL persistence abstraction supporting PostgreSQL and SQLite.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use thiserror::Error;
use uuid::Uuid;

pub mod postgres;
pub mod sqlite;

/// Database layer errors normalized across PostgreSQL and SQLite.
#[derive(Debug, Error)]
pub enum DbError {
    #[error("unsupported database URL scheme; expected `postgres://` or `sqlite:`")]
    UnsupportedScheme,
    #[error("database migration failed: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("database query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("database integrity violation: {0}")]
    Integrity(String),
}

/// Dual database connection pool avoiding untyped `sqlx::Any` compromises.
#[derive(Clone)]
pub enum DbPool {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

impl fmt::Debug for DbPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(_) => f.write_str("DbPool::Postgres(...)"),
            Self::Sqlite(_) => f.write_str("DbPool::Sqlite(...)"),
        }
    }
}

impl DbPool {
    /// Connects to PostgreSQL or SQLite based on `database_url`, applying SQLite WAL and FK pragmas.
    pub async fn connect(database_url: &str) -> Result<Self, DbError> {
        if database_url.starts_with("postgres://") || database_url.starts_with("postgresql://") {
            let pool = PgPoolOptions::new()
                .max_connections(20)
                .acquire_timeout(Duration::from_secs(10))
                .connect(database_url)
                .await?;
            return Ok(Self::Postgres(pool));
        }

        if database_url.starts_with("sqlite:") {
            let is_memory =
                database_url == "sqlite::memory:" || database_url.contains("mode=memory");
            let opts = SqliteConnectOptions::from_str(database_url)?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5));
            let pool = SqlitePoolOptions::new()
                .max_connections(if is_memory { 1 } else { 5 })
                .acquire_timeout(Duration::from_secs(10))
                .connect_with(opts)
                .await?;
            return Ok(Self::Sqlite(pool));
        }

        Err(DbError::UnsupportedScheme)
    }

    /// Runs embedded schema migrations for the active backend.
    pub async fn migrate(&self) -> Result<(), DbError> {
        const POSTGRES_MIGRATIONS: EmbeddedMigrations = EmbeddedMigrations(&[(
            1,
            "initial",
            include_str!("../../migrations/postgres/0001_initial.sql"),
        )]);
        const SQLITE_MIGRATIONS: EmbeddedMigrations = EmbeddedMigrations(&[(
            1,
            "initial",
            include_str!("../../migrations/sqlite/0001_initial.sql"),
        )]);

        match self {
            Self::Postgres(pool) => {
                let migrator = sqlx::migrate::Migrator::new(POSTGRES_MIGRATIONS).await?;
                migrator.run(pool).await?;
            }
            Self::Sqlite(pool) => {
                let migrator = sqlx::migrate::Migrator::new(SQLITE_MIGRATIONS).await?;
                migrator.run(pool).await?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct EmbeddedMigrations(&'static [(i64, &'static str, &'static str)]);

impl sqlx::migrate::MigrationSource<'static> for EmbeddedMigrations {
    fn resolve(
        self,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<sqlx::migrate::Migration>, sqlx::error::BoxDynError>,
                > + Send
                + 'static,
        >,
    > {
        let migrations = self
            .0
            .iter()
            .map(|&(version, description, sql)| {
                sqlx::migrate::Migration::new(
                    version,
                    std::borrow::Cow::Borrowed(description),
                    sqlx::migrate::MigrationType::Simple,
                    std::borrow::Cow::Borrowed(sql),
                    sql.starts_with("-- no-transaction"),
                )
            })
            .collect();
        Box::pin(async move { Ok(migrations) })
    }
}

/// Account privilege level stored in `users.role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
}

impl UserRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Admin => "admin",
        }
    }
}

impl FromStr for UserRole {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "user" => Ok(Self::User),
            "admin" => Ok(Self::Admin),
            _ => Err(format!("invalid user role `{raw}`")),
        }
    }
}

/// Client device classification recorded on each refresh session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DevicePlatform {
    Windows,
    MacOs,
    Linux,
    Android,
    Ios,
    Browser,
    Cli,
    #[default]
    Unknown,
}

impl DevicePlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::MacOs => "macos",
            Self::Linux => "linux",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Browser => "browser",
            Self::Cli => "cli",
            Self::Unknown => "unknown",
        }
    }
}

impl FromStr for DevicePlatform {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw {
            "windows" => Ok(Self::Windows),
            "macos" => Ok(Self::MacOs),
            "linux" => Ok(Self::Linux),
            "android" => Ok(Self::Android),
            "ios" => Ok(Self::Ios),
            "browser" => Ok(Self::Browser),
            "cli" => Ok(Self::Cli),
            "unknown" => Ok(Self::Unknown),
            _ => Err(format!("invalid device platform `{raw}`")),
        }
    }
}

/// Full persisted user row.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub is_active: bool,
    pub kdf_algorithm: String,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub kdf_salt: Vec<u8>,
    pub server_auth_salt: Vec<u8>,
    pub server_auth_hash: String,
    pub key_version: u32,
    pub encrypted_vault_key: Vec<u8>,
    pub sync_revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Public admin-facing summary containing no vault data.
#[derive(Debug, Clone, Serialize)]
pub struct AdminUserSummary {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub is_active: bool,
    pub sync_revision: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Result of checking whether a session and its owning user are currently active.
#[derive(Debug, Clone)]
pub struct ActiveSessionUser {
    pub user_id: Uuid,
    pub role: UserRole,
    pub is_active: bool,
}

/// Persisted authentication session row.
#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_family_id: Uuid,
    pub refresh_token_hash: Vec<u8>,
    pub device_name: String,
    pub device_platform: DevicePlatform,
    pub user_agent: Option<String>,
    pub last_ip: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Invitation metadata returned by repository queries.
#[derive(Debug, Clone, Serialize)]
pub struct InvitationRecord {
    pub id: Uuid,
    pub invited_email: Option<String>,
    pub created_by_user_id: Option<Uuid>,
    pub max_uses: i32,
    pub used_count: i32,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Persisted encrypted folder row.
#[derive(Debug, Clone)]
pub struct StoredFolderRecord {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Persisted encrypted item row.
#[derive(Debug, Clone)]
pub struct StoredItemRecord {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Encrypted blob metadata included in vault sync responses.
#[derive(Debug, Clone)]
pub struct StoredBlobMeta {
    pub id: Uuid,
    pub item_id: Uuid,
    pub byte_size: i32,
    pub sha256_ciphertext: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Encrypted blob payload returned on blob download.
#[derive(Debug, Clone)]
pub struct StoredBlobData {
    pub id: Uuid,
    pub item_id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub byte_size: i32,
    pub sha256_ciphertext: Vec<u8>,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

/// Full or incremental vault sync state returned to authenticated clients.
#[derive(Debug, Clone)]
pub struct VaultSyncState {
    pub current_revision: i64,
    pub key_version: u32,
    pub encrypted_vault_key: Vec<u8>,
    pub folders: Vec<StoredFolderRecord>,
    pub items: Vec<StoredItemRecord>,
    pub blobs_meta: Vec<StoredBlobMeta>,
}

/// Input parameters to create an account and its initial session atomically.
#[derive(Debug, Clone)]
pub struct RegisterUserInput {
    pub user_id: Uuid,
    pub email: String,
    pub kdf_algorithm: String,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    pub kdf_salt: Vec<u8>,
    pub server_auth_salt: Vec<u8>,
    pub server_auth_hash: String,
    pub encrypted_vault_key: Vec<u8>,
    pub invite_token_hash: Option<Vec<u8>>,
    pub require_invitation: bool,
    pub session: CreateSessionInput,
}

#[derive(Debug, Clone)]
pub enum RegisterOutcome {
    Created(Box<UserRecord>),
    EmailExists,
    UserIdConflict,
    InvalidInvitation,
}

/// Input parameters to open a refresh session.
#[derive(Debug, Clone)]
pub struct CreateSessionInput {
    pub session_id: Uuid,
    pub token_family_id: Uuid,
    pub refresh_token_hash: Vec<u8>,
    pub device_name: String,
    pub device_platform: DevicePlatform,
    pub user_agent: Option<String>,
    pub last_ip: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of single-use refresh token rotation.
#[derive(Debug, Clone)]
pub enum RotateRefreshOutcome {
    Rotated {
        session: Box<SessionRecord>,
        user: Box<UserRecord>,
    },
    InvalidOrExpired,
    ReuseDetected {
        user_id: Uuid,
        token_family_id: Uuid,
    },
}

/// Parameters for atomic master password rotation.
#[derive(Debug, Clone)]
pub struct RotatePasswordInput {
    pub user_id: Uuid,
    pub current_session_id: Uuid,
    pub new_kdf_algorithm: String,
    pub new_kdf_memory_kib: u32,
    pub new_kdf_iterations: u32,
    pub new_kdf_parallelism: u32,
    pub new_kdf_salt: Vec<u8>,
    pub new_server_auth_salt: Vec<u8>,
    pub new_server_auth_hash: String,
    pub new_key_version: u32,
    pub new_encrypted_vault_key: Vec<u8>,
    pub revoke_other_sessions: bool,
    pub actor_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RotatePasswordOutcome {
    Updated {
        key_version: u32,
        rotated_at: DateTime<Utc>,
    },
    VersionMismatch,
    NotFound,
}

/// Re-encrypted blob payload submitted during atomic emergency `VaultKey` rotation.
#[derive(Debug, Clone)]
pub struct BlobReencryptUpsert {
    pub id: Uuid,
    pub item_id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub sha256_ciphertext: Vec<u8>,
}

/// Atomic re-keying transaction replacing wrapped `VaultKey` and all active vault ciphertexts.
#[derive(Debug, Clone)]
pub struct RotateVaultKeyInput {
    pub user_id: Uuid,
    pub current_session_id: Uuid,
    pub base_revision: i64,
    pub new_key_version: u32,
    pub new_encrypted_vault_key: Vec<u8>,
    pub folders: Vec<FolderUpsertInput>,
    pub items: Vec<ItemUpsertInput>,
    pub blobs: Vec<BlobReencryptUpsert>,
    pub revoke_other_sessions: bool,
    pub actor_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RotateVaultKeyOutcome {
    Rotated {
        key_version: u32,
        new_revision: i64,
        rotated_at: DateTime<Utc>,
    },
    VersionMismatch,
    RevisionConflict(VaultSyncState),
    IncompleteBatch {
        missing_folders: usize,
        missing_items: usize,
        missing_blobs: usize,
    },
    NotFound,
}

/// Client upsert payload for an encrypted folder.
#[derive(Debug, Clone)]
pub struct FolderUpsertInput {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
}

/// Client upsert payload for an encrypted item.
#[derive(Debug, Clone)]
pub struct ItemUpsertInput {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
}

/// Batch synchronization mutation pushed by a client.
#[derive(Debug, Clone)]
pub struct SyncPushBatch {
    pub user_id: Uuid,
    pub base_revision: i64,
    pub folders_upsert: Vec<FolderUpsertInput>,
    pub folders_delete_ids: Vec<Uuid>,
    pub items_upsert: Vec<ItemUpsertInput>,
    pub items_delete_ids: Vec<Uuid>,
}

#[derive(Debug, Clone)]
pub enum SyncPushOutcome {
    Committed {
        new_revision: i64,
        updated_at: DateTime<Utc>,
    },
    Conflict(VaultSyncState),
}

#[derive(Debug, Clone)]
pub enum CreateItemOutcome {
    Created {
        id: Uuid,
        revision: i64,
        updated_at: DateTime<Utc>,
    },
    AlreadyExists,
}

#[derive(Debug, Clone)]
pub enum UpdateItemOutcome {
    Updated {
        id: Uuid,
        revision: i64,
        updated_at: DateTime<Utc>,
    },
    NotFound,
    Conflict(StoredItemRecord),
}

#[derive(Debug, Clone)]
pub enum DeleteRecordOutcome {
    Deleted {
        revision: i64,
        updated_at: DateTime<Utc>,
    },
    NotFound,
}

#[derive(Debug, Clone)]
pub enum PutBlobOutcome {
    Saved {
        blob_id: Uuid,
        revision: i64,
        byte_size: i32,
        updated_at: DateTime<Utc>,
    },
    ItemNotFound,
}

#[derive(Debug, Clone)]
pub struct UpdateUserAdminInput {
    pub target_user_id: Uuid,
    pub is_active: Option<bool>,
    pub role: Option<UserRole>,
}

#[derive(Debug, Clone)]
pub enum UpdateUserAdminOutcome {
    Updated(AdminUserSummary),
    NotFound,
    LastAdminProtected,
}

#[derive(Debug, Clone)]
pub struct AuditLogInput<'a> {
    pub user_id: Option<Uuid>,
    pub event_type: &'a str,
    pub actor_ip: Option<&'a str>,
    pub session_id: Option<Uuid>,
    pub metadata_json: Option<String>,
}

/// Storage abstraction implemented identically across PostgreSQL and SQLite.
#[async_trait]
pub trait VaultRepository: Send + Sync {
    async fn health_check(&self) -> Result<(), DbError>;

    async fn find_user_by_email(
        &self,
        normalized_email: &str,
    ) -> Result<Option<UserRecord>, DbError>;
    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, DbError>;
    async fn find_user_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserRecord>, DbError>;

    async fn register_user_with_session(
        &self,
        input: RegisterUserInput,
    ) -> Result<RegisterOutcome, DbError>;

    async fn create_session(
        &self,
        user_id: Uuid,
        input: CreateSessionInput,
    ) -> Result<SessionRecord, DbError>;

    async fn verify_active_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<ActiveSessionUser>, DbError>;

    async fn rotate_refresh_token(
        &self,
        presented_hash: &[u8],
        new_hash: &[u8],
        new_expires_at: DateTime<Utc>,
        last_ip: Option<&str>,
    ) -> Result<RotateRefreshOutcome, DbError>;

    async fn revoke_session(&self, user_id: Uuid, session_id: Uuid) -> Result<bool, DbError>;

    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, DbError>;

    async fn rotate_master_password(
        &self,
        input: RotatePasswordInput,
    ) -> Result<RotatePasswordOutcome, DbError>;

    async fn rotate_vault_key(
        &self,
        input: RotateVaultKeyInput,
    ) -> Result<RotateVaultKeyOutcome, DbError>;

    async fn delete_user_account(&self, user_id: Uuid) -> Result<bool, DbError>;

    async fn pull_vault_sync(
        &self,
        user_id: Uuid,
        since_revision: i64,
    ) -> Result<Option<VaultSyncState>, DbError>;

    async fn push_sync_batch(&self, batch: SyncPushBatch) -> Result<SyncPushOutcome, DbError>;

    async fn create_item(
        &self,
        user_id: Uuid,
        item_id: Uuid,
        encrypted_data: &[u8],
    ) -> Result<CreateItemOutcome, DbError>;

    async fn update_item(
        &self,
        user_id: Uuid,
        item_id: Uuid,
        expected_revision: i64,
        encrypted_data: &[u8],
    ) -> Result<UpdateItemOutcome, DbError>;

    async fn delete_item(
        &self,
        user_id: Uuid,
        item_id: Uuid,
    ) -> Result<DeleteRecordOutcome, DbError>;

    async fn put_blob(
        &self,
        user_id: Uuid,
        item_id: Uuid,
        blob_id: Uuid,
        encrypted_blob: &[u8],
        sha256_ciphertext: &[u8],
    ) -> Result<PutBlobOutcome, DbError>;

    async fn get_blob(
        &self,
        user_id: Uuid,
        blob_id: Uuid,
    ) -> Result<Option<StoredBlobData>, DbError>;

    async fn delete_blob(
        &self,
        user_id: Uuid,
        blob_id: Uuid,
    ) -> Result<DeleteRecordOutcome, DbError>;

    async fn create_invitation(
        &self,
        token_hash: &[u8],
        invited_email: Option<&str>,
        created_by_user_id: Option<Uuid>,
        max_uses: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<InvitationRecord, DbError>;

    async fn list_invitations(&self) -> Result<Vec<InvitationRecord>, DbError>;

    async fn revoke_invitation(&self, invitation_id: Uuid) -> Result<bool, DbError>;

    async fn list_users_admin(&self) -> Result<Vec<AdminUserSummary>, DbError>;

    async fn update_user_admin(
        &self,
        input: UpdateUserAdminInput,
    ) -> Result<UpdateUserAdminOutcome, DbError>;

    async fn insert_audit_log(&self, entry: AuditLogInput<'_>) -> Result<(), DbError>;
}

#[async_trait]
impl VaultRepository for DbPool {
    async fn health_check(&self) -> Result<(), DbError> {
        match self {
            Self::Postgres(pool) => postgres::health_check(pool).await,
            Self::Sqlite(pool) => sqlite::health_check(pool).await,
        }
    }

    async fn find_user_by_email(
        &self,
        normalized_email: &str,
    ) -> Result<Option<UserRecord>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::find_user_by_email(pool, normalized_email).await,
            Self::Sqlite(pool) => sqlite::find_user_by_email(pool, normalized_email).await,
        }
    }

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<UserRecord>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::find_user_by_id(pool, user_id).await,
            Self::Sqlite(pool) => sqlite::find_user_by_id(pool, user_id).await,
        }
    }

    async fn find_user_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserRecord>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::find_user_by_identifier(pool, identifier).await,
            Self::Sqlite(pool) => sqlite::find_user_by_identifier(pool, identifier).await,
        }
    }

    async fn register_user_with_session(
        &self,
        input: RegisterUserInput,
    ) -> Result<RegisterOutcome, DbError> {
        match self {
            Self::Postgres(pool) => postgres::register_user_with_session(pool, input).await,
            Self::Sqlite(pool) => sqlite::register_user_with_session(pool, input).await,
        }
    }

    async fn create_session(
        &self,
        user_id: Uuid,
        input: CreateSessionInput,
    ) -> Result<SessionRecord, DbError> {
        match self {
            Self::Postgres(pool) => postgres::create_session(pool, user_id, input).await,
            Self::Sqlite(pool) => sqlite::create_session(pool, user_id, input).await,
        }
    }

    async fn verify_active_session(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        now: DateTime<Utc>,
    ) -> Result<Option<ActiveSessionUser>, DbError> {
        match self {
            Self::Postgres(pool) => {
                postgres::verify_active_session(pool, user_id, session_id, now).await
            }
            Self::Sqlite(pool) => {
                sqlite::verify_active_session(pool, user_id, session_id, now).await
            }
        }
    }

    async fn rotate_refresh_token(
        &self,
        presented_hash: &[u8],
        new_hash: &[u8],
        new_expires_at: DateTime<Utc>,
        last_ip: Option<&str>,
    ) -> Result<RotateRefreshOutcome, DbError> {
        match self {
            Self::Postgres(pool) => {
                postgres::rotate_refresh_token(
                    pool,
                    presented_hash,
                    new_hash,
                    new_expires_at,
                    last_ip,
                )
                .await
            }
            Self::Sqlite(pool) => {
                sqlite::rotate_refresh_token(
                    pool,
                    presented_hash,
                    new_hash,
                    new_expires_at,
                    last_ip,
                )
                .await
            }
        }
    }

    async fn revoke_session(&self, user_id: Uuid, session_id: Uuid) -> Result<bool, DbError> {
        match self {
            Self::Postgres(pool) => postgres::revoke_session(pool, user_id, session_id).await,
            Self::Sqlite(pool) => sqlite::revoke_session(pool, user_id, session_id).await,
        }
    }

    async fn list_user_sessions(&self, user_id: Uuid) -> Result<Vec<SessionRecord>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::list_user_sessions(pool, user_id).await,
            Self::Sqlite(pool) => sqlite::list_user_sessions(pool, user_id).await,
        }
    }

    async fn rotate_master_password(
        &self,
        input: RotatePasswordInput,
    ) -> Result<RotatePasswordOutcome, DbError> {
        match self {
            Self::Postgres(pool) => postgres::rotate_master_password(pool, input).await,
            Self::Sqlite(pool) => sqlite::rotate_master_password(pool, input).await,
        }
    }

    async fn rotate_vault_key(
        &self,
        input: RotateVaultKeyInput,
    ) -> Result<RotateVaultKeyOutcome, DbError> {
        match self {
            Self::Postgres(pool) => postgres::rotate_vault_key(pool, input).await,
            Self::Sqlite(pool) => sqlite::rotate_vault_key(pool, input).await,
        }
    }

    async fn delete_user_account(&self, user_id: Uuid) -> Result<bool, DbError> {
        match self {
            Self::Postgres(pool) => postgres::delete_user_account(pool, user_id).await,
            Self::Sqlite(pool) => sqlite::delete_user_account(pool, user_id).await,
        }
    }

    async fn pull_vault_sync(
        &self,
        user_id: Uuid,
        since_revision: i64,
    ) -> Result<Option<VaultSyncState>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::pull_vault_sync(pool, user_id, since_revision).await,
            Self::Sqlite(pool) => sqlite::pull_vault_sync(pool, user_id, since_revision).await,
        }
    }

    async fn push_sync_batch(&self, batch: SyncPushBatch) -> Result<SyncPushOutcome, DbError> {
        match self {
            Self::Postgres(pool) => postgres::push_sync_batch(pool, batch).await,
            Self::Sqlite(pool) => sqlite::push_sync_batch(pool, batch).await,
        }
    }

    async fn create_item(
        &self,
        user_id: Uuid,
        item_id: Uuid,
        encrypted_data: &[u8],
    ) -> Result<CreateItemOutcome, DbError> {
        match self {
            Self::Postgres(pool) => {
                postgres::create_item(pool, user_id, item_id, encrypted_data).await
            }
            Self::Sqlite(pool) => sqlite::create_item(pool, user_id, item_id, encrypted_data).await,
        }
    }

    async fn update_item(
        &self,
        user_id: Uuid,
        item_id: Uuid,
        expected_revision: i64,
        encrypted_data: &[u8],
    ) -> Result<UpdateItemOutcome, DbError> {
        match self {
            Self::Postgres(pool) => {
                postgres::update_item(pool, user_id, item_id, expected_revision, encrypted_data)
                    .await
            }
            Self::Sqlite(pool) => {
                sqlite::update_item(pool, user_id, item_id, expected_revision, encrypted_data).await
            }
        }
    }

    async fn delete_item(
        &self,
        user_id: Uuid,
        item_id: Uuid,
    ) -> Result<DeleteRecordOutcome, DbError> {
        match self {
            Self::Postgres(pool) => postgres::delete_item(pool, user_id, item_id).await,
            Self::Sqlite(pool) => sqlite::delete_item(pool, user_id, item_id).await,
        }
    }

    async fn put_blob(
        &self,
        user_id: Uuid,
        item_id: Uuid,
        blob_id: Uuid,
        encrypted_blob: &[u8],
        sha256_ciphertext: &[u8],
    ) -> Result<PutBlobOutcome, DbError> {
        match self {
            Self::Postgres(pool) => {
                postgres::put_blob(
                    pool,
                    user_id,
                    item_id,
                    blob_id,
                    encrypted_blob,
                    sha256_ciphertext,
                )
                .await
            }
            Self::Sqlite(pool) => {
                sqlite::put_blob(
                    pool,
                    user_id,
                    item_id,
                    blob_id,
                    encrypted_blob,
                    sha256_ciphertext,
                )
                .await
            }
        }
    }

    async fn get_blob(
        &self,
        user_id: Uuid,
        blob_id: Uuid,
    ) -> Result<Option<StoredBlobData>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::get_blob(pool, user_id, blob_id).await,
            Self::Sqlite(pool) => sqlite::get_blob(pool, user_id, blob_id).await,
        }
    }

    async fn delete_blob(
        &self,
        user_id: Uuid,
        blob_id: Uuid,
    ) -> Result<DeleteRecordOutcome, DbError> {
        match self {
            Self::Postgres(pool) => postgres::delete_blob(pool, user_id, blob_id).await,
            Self::Sqlite(pool) => sqlite::delete_blob(pool, user_id, blob_id).await,
        }
    }

    async fn create_invitation(
        &self,
        token_hash: &[u8],
        invited_email: Option<&str>,
        created_by_user_id: Option<Uuid>,
        max_uses: i32,
        expires_at: DateTime<Utc>,
    ) -> Result<InvitationRecord, DbError> {
        match self {
            Self::Postgres(pool) => {
                postgres::create_invitation(
                    pool,
                    token_hash,
                    invited_email,
                    created_by_user_id,
                    max_uses,
                    expires_at,
                )
                .await
            }
            Self::Sqlite(pool) => {
                sqlite::create_invitation(
                    pool,
                    token_hash,
                    invited_email,
                    created_by_user_id,
                    max_uses,
                    expires_at,
                )
                .await
            }
        }
    }

    async fn list_invitations(&self) -> Result<Vec<InvitationRecord>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::list_invitations(pool).await,
            Self::Sqlite(pool) => sqlite::list_invitations(pool).await,
        }
    }

    async fn revoke_invitation(&self, invitation_id: Uuid) -> Result<bool, DbError> {
        match self {
            Self::Postgres(pool) => postgres::revoke_invitation(pool, invitation_id).await,
            Self::Sqlite(pool) => sqlite::revoke_invitation(pool, invitation_id).await,
        }
    }

    async fn list_users_admin(&self) -> Result<Vec<AdminUserSummary>, DbError> {
        match self {
            Self::Postgres(pool) => postgres::list_users_admin(pool).await,
            Self::Sqlite(pool) => sqlite::list_users_admin(pool).await,
        }
    }

    async fn update_user_admin(
        &self,
        input: UpdateUserAdminInput,
    ) -> Result<UpdateUserAdminOutcome, DbError> {
        match self {
            Self::Postgres(pool) => postgres::update_user_admin(pool, input).await,
            Self::Sqlite(pool) => sqlite::update_user_admin(pool, input).await,
        }
    }

    async fn insert_audit_log(&self, entry: AuditLogInput<'_>) -> Result<(), DbError> {
        match self {
            Self::Postgres(pool) => postgres::insert_audit_log(pool, entry).await,
            Self::Sqlite(pool) => sqlite::insert_audit_log(pool, entry).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[tokio::test]
    async fn sqlite_migrations_and_pragmas_apply() -> Result<(), Box<dyn std::error::Error>> {
        let pool = DbPool::connect("sqlite::memory:").await?;
        pool.migrate().await?;
        pool.health_check().await?;

        if let DbPool::Sqlite(sqlite_pool) = &pool {
            let fk: (i64,) = sqlx::query_as("PRAGMA foreign_keys")
                .fetch_one(sqlite_pool)
                .await?;
            assert_eq!(fk.0, 1);
        }

        let inv = pool
            .create_invitation(
                &[0x11u8; 32],
                Some("alice@example.com"),
                None,
                1,
                Utc::now() + Duration::hours(24),
            )
            .await?;
        assert_eq!(inv.used_count, 0);
        assert_eq!(pool.list_invitations().await?.len(), 1);
        Ok(())
    }
}
