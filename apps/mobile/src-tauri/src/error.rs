//! Typed error definitions for the Anvil Mobile backend and OS autofill bridges.

use anvil_client_core::error::ClientError;
use thiserror::Error;

/// Errors returned across mobile Tauri commands, QR parsing, enclave sealing, and OS autofill.
#[derive(Debug, Error)]
pub enum MobileError {
    #[error("{0}")]
    Client(#[from] ClientError),
    #[error("{0}")]
    Core(#[from] anvil_core::error::AnvilError),
    #[error("hardware biometric enclave is unavailable on this device")]
    BiometricUnavailable,
    #[error("biometric unlock is not enabled for the current account")]
    BiometricNotEnabled,
    #[error("failed to seal VaultKey into hardware enclave")]
    EnclaveSealFailed,
    #[error("failed to unseal VaultKey from hardware enclave")]
    EnclaveUnsealFailed,
    #[error("invalid QR code payload: {0}")]
    InvalidQrPayload(String),
    #[error("server URL rejected by TLS policy: {0}")]
    InsecureServerUrl(String),
    #[error("autofill request denied: {0}")]
    AutofillDenied(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unknown IPC command: {0}")]
    UnknownCommand(String),
    #[error("internal mobile host synchronization error")]
    InternalState,
}
