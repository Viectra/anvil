//! Typed errors surfaced by `anvil-client-core` across cache, crypto, lock state, and sync.

use thiserror::Error;

/// Client-side domain and transport errors.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("vault is locked")]
    VaultLocked,
    #[error("no local account configured; register or login first")]
    NotConfigured,
    #[error("no active server session; login required")]
    NotAuthenticated,
    #[error("invalid master password")]
    InvalidMasterPassword,
    #[error("item or folder not found")]
    NotFound,
    #[error("sync conflict unresolved ({conflict_count} pending)")]
    UnresolvedConflicts { conflict_count: usize },
    #[error("conflict record not found")]
    ConflictNotFound,
    #[error("server URL is invalid: {0}")]
    InvalidServerUrl(String),
    #[error("server returned HTTP {status} ({code}): {message}")]
    ServerError {
        status: u16,
        code: String,
        message: String,
        request_id: String,
    },
    #[error("cryptographic failure: {0}")]
    Crypto(#[from] anvil_core::error::AnvilError),
    #[error("local cache failure: {0}")]
    Database(#[from] sqlx::Error),
    #[error("local cache integrity error: {0}")]
    CacheIntegrity(String),
    #[error("network request failed: {0}")]
    Network(String),
    #[error("serialization failure: {0}")]
    Serialization(String),
}
