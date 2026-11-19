//! Argon2id and HKDF-SHA256 key derivation with security bound enforcement.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::crypto::keys::{
    KEY_LEN, MasterAuthHash, MasterEncryptionKey, MasterKey, MasterPassword, VaultKey,
    VaultSubKeys, fill_random_bytes,
};
use crate::error::AnvilError;

/// Length in bytes of the client-generated KDF salt.
pub const KDF_SALT_LEN: usize = 32;

/// Minimum allowed Argon2id memory cost in KiB (19 MiB OWASP floor).
pub const MIN_KDF_MEMORY_KIB: u32 = 19_456;
/// Maximum allowed Argon2id memory cost in KiB (512 MiB anti-DoS cap).
pub const MAX_KDF_MEMORY_KIB: u32 = 524_288;
/// Minimum allowed Argon2id time cost.
pub const MIN_KDF_ITERATIONS: u32 = 2;
/// Maximum allowed Argon2id time cost.
pub const MAX_KDF_ITERATIONS: u32 = 20;
/// Minimum allowed Argon2id parallelism.
pub const MIN_KDF_PARALLELISM: u32 = 1;
/// Maximum allowed Argon2id parallelism.
pub const MAX_KDF_PARALLELISM: u32 = 8;

/// Default Argon2id memory cost in KiB (64 MiB).
pub const DEFAULT_KDF_MEMORY_KIB: u32 = 65_536;
/// Default Argon2id iterations.
pub const DEFAULT_KDF_ITERATIONS: u32 = 3;
/// Default Argon2id parallelism (`p = 1` ensures identical behavior on native and WASM).
pub const DEFAULT_KDF_PARALLELISM: u32 = 1;

const INFO_MASTER_ENC_KEY: &[u8] = b"anvil:v1:master-encryption-key";
const INFO_MASTER_AUTH_HASH: &[u8] = b"anvil:v1:master-auth-hash";
const INFO_VAULT_ITEM_ENC: &[u8] = b"anvil:v1:item-enc";
const INFO_VAULT_FOLDER_ENC: &[u8] = b"anvil:v1:folder-enc";
const INFO_VAULT_BLOB_ENC: &[u8] = b"anvil:v1:blob-enc";

/// Supported client KDF algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgorithm {
    #[default]
    Argon2id,
}

/// Public client KDF parameters stored per user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: KdfAlgorithm,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: DEFAULT_KDF_MEMORY_KIB,
            iterations: DEFAULT_KDF_ITERATIONS,
            parallelism: DEFAULT_KDF_PARALLELISM,
        }
    }
}

impl KdfParams {
    /// Validates that server-supplied KDF parameters are within safe security and DoS bounds.
    pub fn validate(&self) -> Result<(), AnvilError> {
        if !(MIN_KDF_MEMORY_KIB..=MAX_KDF_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(AnvilError::KdfParamsOutOfBounds(format!(
                "memory_kib {} must be between {MIN_KDF_MEMORY_KIB} and {MAX_KDF_MEMORY_KIB}",
                self.memory_kib
            )));
        }
        if !(MIN_KDF_ITERATIONS..=MAX_KDF_ITERATIONS).contains(&self.iterations) {
            return Err(AnvilError::KdfParamsOutOfBounds(format!(
                "iterations {} must be between {MIN_KDF_ITERATIONS} and {MAX_KDF_ITERATIONS}",
                self.iterations
            )));
        }
        if !(MIN_KDF_PARALLELISM..=MAX_KDF_PARALLELISM).contains(&self.parallelism) {
            return Err(AnvilError::KdfParamsOutOfBounds(format!(
                "parallelism {} must be between {MIN_KDF_PARALLELISM} and {MAX_KDF_PARALLELISM}",
                self.parallelism
            )));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn fast_for_tests() -> Self {
        Self {
            algorithm: KdfAlgorithm::Argon2id,
            memory_kib: 1_024,
            iterations: 1,
            parallelism: 1,
        }
    }
}

/// Generates a fresh 32-byte CSPRNG salt for client KDF derivation.
pub fn generate_kdf_salt() -> Result<[u8; KDF_SALT_LEN], AnvilError> {
    let mut salt = [0u8; KDF_SALT_LEN];
    fill_random_bytes(&mut salt)?;
    Ok(salt)
}

/// Derives the 256-bit `MasterKey` using Argon2id v0x13 after validating security bounds.
pub fn derive_master_key(
    password: &MasterPassword,
    salt: &[u8; KDF_SALT_LEN],
    params: &KdfParams,
) -> Result<MasterKey, AnvilError> {
    params.validate()?;
    derive_master_key_raw(password, salt, params)
}

pub(crate) fn derive_master_key_raw(
    password: &MasterPassword,
    salt: &[u8; KDF_SALT_LEN],
    params: &KdfParams,
) -> Result<MasterKey, AnvilError> {
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| AnvilError::KdfFailed(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password.as_bytes(), salt, &mut *out)
        .map_err(|e| AnvilError::KdfFailed(e.to_string()))?;

    Ok(MasterKey::from_bytes(*out))
}

/// Splits `MasterKey` via HKDF-SHA256 into `MasterEncryptionKey` and `MasterAuthHash`.
pub fn derive_master_subkeys(
    master_key: &MasterKey,
    kdf_salt: &[u8; KDF_SALT_LEN],
) -> Result<(MasterEncryptionKey, MasterAuthHash), AnvilError> {
    let hk = Hkdf::<Sha256>::new(Some(kdf_salt), master_key.as_bytes());

    let mut enc_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_MASTER_ENC_KEY, &mut *enc_key)
        .map_err(|_| AnvilError::HkdfFailed)?;

    let mut auth_hash = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_MASTER_AUTH_HASH, &mut *auth_hash)
        .map_err(|_| AnvilError::HkdfFailed)?;

    Ok((
        MasterEncryptionKey::from_bytes(*enc_key),
        MasterAuthHash::from_bytes(*auth_hash),
    ))
}

/// Derives domain-separated item, folder, and blob encryption subkeys from `VaultKey`.
pub fn derive_vault_subkeys(vault_key: &VaultKey) -> Result<VaultSubKeys, AnvilError> {
    let hk = Hkdf::<Sha256>::new(None, vault_key.as_bytes());

    let mut item_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_VAULT_ITEM_ENC, &mut *item_key)
        .map_err(|_| AnvilError::HkdfFailed)?;

    let mut folder_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_VAULT_FOLDER_ENC, &mut *folder_key)
        .map_err(|_| AnvilError::HkdfFailed)?;

    let mut blob_key = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(INFO_VAULT_BLOB_ENC, &mut *blob_key)
        .map_err(|_| AnvilError::HkdfFailed)?;

    Ok(VaultSubKeys {
        item_key,
        folder_key,
        blob_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_params_bounds_reject_weak_and_excessive_values() {
        assert!(KdfParams::default().validate().is_ok());

        let low_mem = KdfParams {
            memory_kib: 1024,
            ..Default::default()
        };
        assert!(matches!(
            low_mem.validate(),
            Err(AnvilError::KdfParamsOutOfBounds(_))
        ));

        let high_mem = KdfParams {
            memory_kib: 1_048_576,
            ..Default::default()
        };
        assert!(matches!(
            high_mem.validate(),
            Err(AnvilError::KdfParamsOutOfBounds(_))
        ));

        let low_iter = KdfParams {
            iterations: 1,
            ..Default::default()
        };
        assert!(matches!(
            low_iter.validate(),
            Err(AnvilError::KdfParamsOutOfBounds(_))
        ));

        let zero_par = KdfParams {
            parallelism: 0,
            ..Default::default()
        };
        assert!(matches!(
            zero_par.validate(),
            Err(AnvilError::KdfParamsOutOfBounds(_))
        ));
    }

    #[test]
    fn argon2id_default_owasp_parameters_derive_deterministic_subkeys() {
        let pw = MasterPassword::new("correct-horse-battery-staple-42");
        let salt = [0x42u8; KDF_SALT_LEN];
        let params = KdfParams::default();

        let mk1 = derive_master_key(&pw, &salt, &params).expect("kdf should succeed");
        let mk2 = derive_master_key(&pw, &salt, &params).expect("kdf should succeed");
        assert_eq!(mk1, mk2);

        let (mek, auth) = derive_master_subkeys(&mk1, &salt).expect("hkdf should succeed");
        assert_ne!(mek.as_bytes(), auth.as_bytes());
        assert_ne!(mek.as_bytes(), mk1.as_bytes());
    }

    #[test]
    fn vault_subkeys_are_domain_separated() {
        let vk = VaultKey::from_bytes([0x11u8; KEY_LEN]);
        let sub = derive_vault_subkeys(&vk).expect("hkdf should succeed");
        assert_ne!(sub.item_key, sub.folder_key);
        assert_ne!(sub.item_key, sub.blob_key);
        assert_ne!(sub.folder_key, sub.blob_key);
    }
}
