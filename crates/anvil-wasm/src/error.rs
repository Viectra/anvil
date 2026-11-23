//! Typed domain errors surfaced across the WASM / browser extension boundary.

use thiserror::Error;

/// Errors raised by `anvil-wasm` operations and anti-phishing checks.
#[derive(Debug, Error)]
pub enum WasmError {
    #[error("vault is locked")]
    VaultLocked,
    #[error("local account metadata is not configured")]
    NotConfigured,
    #[error("ephemeral session has expired")]
    SessionExpired,
    #[error("invalid master password")]
    InvalidMasterPassword,
    #[error("item or folder not found")]
    NotFound,
    #[error("import preview session expired or was not found")]
    ImportPreviewNotFound,
    #[error("autofill blocked by security policy: {0}")]
    AutofillBlocked(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("cryptographic failure: {0}")]
    Crypto(#[from] anvil_core::error::AnvilError),
    #[error("serialization failure: {0}")]
    Serialization(String),
}
