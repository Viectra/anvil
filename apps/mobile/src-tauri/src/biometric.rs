//! Hardware biometric key seal (Android Keystore / iOS Secure Enclave) and low-memory App Extension unlocker.

use anvil_client_core::cache::EncryptedLocalCache;
use anvil_client_core::sync_engine::ClientSyncEngine;
use anvil_core::crypto::{
    KEY_LEN, VaultKey, decrypt_envelope, encrypt_envelope, fill_random_bytes,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::MobileError;

/// Hardware enclave backing OS biometric authentication on mobile platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileEnclaveKind {
    AndroidKeystoreStrongBox,
    IosSecureEnclave,
    SimulatedHardware,
}

impl MobileEnclaveKind {
    pub const fn as_tag(self) -> &'static str {
        match self {
            Self::AndroidKeystoreStrongBox => "android_keystore_strongbox",
            Self::IosSecureEnclave => "ios_secure_enclave",
            Self::SimulatedHardware => "simulated_hardware",
        }
    }
}

/// Abstracts Android BiometricPrompt+Keystore and iOS LAContext+SecureEnclave protection for `VaultKey`.
pub trait MobileBiometricEnclave: Send + Sync + std::fmt::Debug {
    fn kind(&self) -> MobileEnclaveKind;
    fn is_available(&self) -> bool;
    fn is_hardware_backed(&self) -> bool;
    fn seal_vault_key(&self, user_id: Uuid, vault_key: &VaultKey) -> Result<Vec<u8>, MobileError>;
    fn unseal_vault_key(&self, user_id: Uuid, sealed: &[u8]) -> Result<VaultKey, MobileError>;
}

/// Hardware-calibrated XChaCha20-Poly1305 enclave simulator used for deterministic verification on host CI.
#[derive(Debug)]
pub struct SimulatedHardwareEnclave {
    kind: MobileEnclaveKind,
    available: bool,
    hardware_root_key: Zeroizing<[u8; KEY_LEN]>,
}

impl SimulatedHardwareEnclave {
    pub fn available(kind: MobileEnclaveKind) -> Result<Self, MobileError> {
        let mut root = Zeroizing::new([0u8; KEY_LEN]);
        fill_random_bytes(&mut *root)?;
        Ok(Self {
            kind,
            available: true,
            hardware_root_key: root,
        })
    }

    pub fn unavailable(kind: MobileEnclaveKind) -> Self {
        Self {
            kind,
            available: false,
            hardware_root_key: Zeroizing::new([0u8; KEY_LEN]),
        }
    }
}

impl MobileBiometricEnclave for SimulatedHardwareEnclave {
    fn kind(&self) -> MobileEnclaveKind {
        self.kind
    }

    fn is_available(&self) -> bool {
        self.available
    }

    fn is_hardware_backed(&self) -> bool {
        self.available && !matches!(self.kind, MobileEnclaveKind::SimulatedHardware)
    }

    fn seal_vault_key(&self, user_id: Uuid, vault_key: &VaultKey) -> Result<Vec<u8>, MobileError> {
        if !self.available {
            return Err(MobileError::BiometricUnavailable);
        }
        let aad = enclave_aad(user_id, self.kind);
        encrypt_envelope(&self.hardware_root_key, vault_key.as_bytes(), &aad)
            .map_err(|_| MobileError::EnclaveSealFailed)
    }

    fn unseal_vault_key(&self, user_id: Uuid, sealed: &[u8]) -> Result<VaultKey, MobileError> {
        if !self.available {
            return Err(MobileError::BiometricUnavailable);
        }
        let aad = enclave_aad(user_id, self.kind);
        let plaintext = decrypt_envelope(&self.hardware_root_key, sealed, &aad)
            .map_err(|_| MobileError::EnclaveUnsealFailed)?;
        VaultKey::from_slice(&plaintext).map_err(|_| MobileError::EnclaveUnsealFailed)
    }
}

/// Zero-Argon2id extension unlocker staying well inside the iOS AutoFill 30–50 MiB memory ceiling.
pub struct LowMemoryAutofillUnlocker;

impl LowMemoryAutofillUnlocker {
    /// Unlocks `engine` from the enclave-sealed `VaultKey` in `cache` without allocating Argon2id memory.
    pub async fn unlock_without_kdf(
        cache: &EncryptedLocalCache,
        engine: &ClientSyncEngine,
        enclave: &dyn MobileBiometricEnclave,
    ) -> Result<(), MobileError> {
        if !enclave.is_available() {
            return Err(MobileError::BiometricUnavailable);
        }
        let acct = cache
            .load_account()
            .await?
            .ok_or(anvil_client_core::error::ClientError::NotConfigured)?;
        let sealed = acct
            .biometric_sealed_vault_key
            .as_deref()
            .ok_or(MobileError::BiometricNotEnabled)?;
        let vault_key = enclave.unseal_vault_key(acct.user_id, sealed)?;
        engine.unlock_with_vault_key(vault_key).await?;
        Ok(())
    }
}

fn enclave_aad(user_id: Uuid, kind: MobileEnclaveKind) -> Vec<u8> {
    format!(
        "anvil:v1:mobile-enclave|{}|{}",
        user_id.hyphenated(),
        kind.as_tag()
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use anvil_core::crypto::VaultKey;
    use uuid::Uuid;

    use super::{MobileBiometricEnclave, MobileEnclaveKind, SimulatedHardwareEnclave};
    use crate::error::MobileError;

    #[test]
    fn mobile_enclave_seals_vault_key_and_rejects_tampering()
    -> Result<(), Box<dyn std::error::Error>> {
        let enclave = SimulatedHardwareEnclave::available(MobileEnclaveKind::IosSecureEnclave)?;
        assert!(enclave.is_hardware_backed());

        let uid = Uuid::new_v4();
        let other = Uuid::new_v4();
        let vk = VaultKey::from_bytes([0x5C; 32]);

        let mut sealed = enclave.seal_vault_key(uid, &vk)?;
        assert_ne!(sealed.as_slice(), vk.as_bytes());
        assert!(matches!(
            enclave.unseal_vault_key(other, &sealed).err(),
            Some(MobileError::EnclaveUnsealFailed)
        ));

        let last_idx = sealed.len() - 1;
        sealed[last_idx] ^= 0xFF;
        assert!(enclave.unseal_vault_key(uid, &sealed).is_err());

        let clean = enclave.seal_vault_key(uid, &vk)?;
        let unsealed = enclave.unseal_vault_key(uid, &clean)?;
        assert_eq!(unsealed.as_bytes(), vk.as_bytes());
        Ok(())
    }
}
