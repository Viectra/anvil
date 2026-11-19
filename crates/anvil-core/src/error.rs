//! Typed domain errors for `anvil-core`.

use thiserror::Error;

/// Unified error type returned by `anvil-core` operations.
#[derive(Debug, Error)]
pub enum AnvilError {
    #[error("KDF parameters are outside allowed security bounds: {0}")]
    KdfParamsOutOfBounds(String),

    #[error("key derivation failed: {0}")]
    KdfFailed(String),

    #[error("HKDF expansion failed")]
    HkdfFailed,

    #[error("authenticated encryption failed")]
    EncryptionFailed,

    #[error("authenticated decryption failed")]
    DecryptionFailed,

    #[error("malformed encrypted envelope")]
    InvalidEnvelope,

    #[error("unsupported encrypted envelope version: {0}")]
    UnsupportedEnvelopeVersion(u8),

    #[error("invalid Base32 secret")]
    InvalidBase32,

    #[error("invalid TOTP configuration or URI: {0}")]
    InvalidTotpUri(String),

    #[error("invalid password generator configuration: {0}")]
    InvalidPasswordConfig(String),

    #[error("import failed: {0}")]
    ImportError(String),

    #[error("export failed: {0}")]
    ExportError(String),

    #[error("unsupported or unrecognized import format")]
    UnsupportedImportFormat,

    #[error("wrong backup password or tampered encrypted backup")]
    WrongBackupPassword,

    #[error("archive safety limit exceeded: {0}")]
    ArchiveLimitExceeded(String),

    #[error("media processing failed: {0}")]
    MediaError(String),

    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("system CSPRNG failure")]
    RngFailed,
}
