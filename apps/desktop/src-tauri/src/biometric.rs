//! OS keychain / DPAPI protection sealing `VaultKey` (never the Master Password).

use std::collections::HashMap;
use std::sync::Mutex;

use anvil_core::crypto::VaultKey;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Errors raised while sealing or unsealing a `VaultKey` through OS hardware/user protection.
#[derive(Debug, Error)]
pub enum BiometricError {
    #[error("biometric / OS key seal provider is unavailable")]
    Unavailable,
    #[error("failed to protect vault key with OS store")]
    SealFailed,
    #[error("failed to unseal vault key with OS store")]
    UnsealFailed,
    #[error("unsealed vault key has invalid length")]
    InvalidKeyMaterial,
}

/// Abstracts OS-backed protection of the volatile `VaultKey` (DPAPI on Windows).
pub trait BiometricProvider: Send + Sync + std::fmt::Debug {
    fn is_available(&self) -> bool;
    fn seal_vault_key(
        &self,
        user_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<Vec<u8>, BiometricError>;
    fn unseal_vault_key(&self, user_id: Uuid, sealed: &[u8]) -> Result<VaultKey, BiometricError>;
}

type SealedKeyMap = Mutex<HashMap<Vec<u8>, (Uuid, [u8; 32])>>;

/// Deterministic in-memory provider used on platforms without DPAPI and in offline test suites.
#[derive(Debug, Default)]
pub struct MemoryBiometricProvider {
    available: bool,
    records: SealedKeyMap,
}

impl MemoryBiometricProvider {
    pub fn available() -> Self {
        Self {
            available: true,
            records: Mutex::new(HashMap::new()),
        }
    }

    pub fn unavailable() -> Self {
        Self {
            available: false,
            records: Mutex::new(HashMap::new()),
        }
    }
}

impl BiometricProvider for MemoryBiometricProvider {
    fn is_available(&self) -> bool {
        self.available
    }

    fn seal_vault_key(
        &self,
        user_id: Uuid,
        vault_key: &VaultKey,
    ) -> Result<Vec<u8>, BiometricError> {
        if !self.available {
            return Err(BiometricError::Unavailable);
        }
        let token = Uuid::new_v4().as_bytes().to_vec();
        let mut guard = self
            .records
            .lock()
            .map_err(|_| BiometricError::SealFailed)?;
        guard.insert(token.clone(), (user_id, *vault_key.as_bytes()));
        Ok(token)
    }

    fn unseal_vault_key(&self, user_id: Uuid, sealed: &[u8]) -> Result<VaultKey, BiometricError> {
        if !self.available {
            return Err(BiometricError::Unavailable);
        }
        let guard = self
            .records
            .lock()
            .map_err(|_| BiometricError::UnsealFailed)?;
        let (owner, raw_key) = guard.get(sealed).ok_or(BiometricError::UnsealFailed)?;
        if *owner != user_id {
            return Err(BiometricError::UnsealFailed);
        }
        Ok(VaultKey::from_bytes(*raw_key))
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
mod native {
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    use anvil_core::crypto::VaultKey;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use super::{BiometricError, BiometricProvider, user_entropy};

    type Bool = i32;
    type Dword = u32;
    type Hlocal = *mut c_void;

    const CRYPTPROTECT_UI_FORBIDDEN: Dword = 0x0000_0001;

    #[repr(C)]
    struct DataBlob {
        cb_data: Dword,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    unsafe extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: Dword,
            p_data_out: *mut DataBlob,
        ) -> Bool;
        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: Dword,
            p_data_out: *mut DataBlob,
        ) -> Bool;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(h_mem: Hlocal) -> Hlocal;
    }

    /// Windows user-scoped DPAPI seal binding the `VaultKey` to current user credentials + `user_id` entropy.
    #[derive(Debug, Default)]
    pub struct WindowsDpapiBiometricProvider;

    impl WindowsDpapiBiometricProvider {
        pub fn new() -> Self {
            Self
        }
    }

    impl BiometricProvider for WindowsDpapiBiometricProvider {
        fn is_available(&self) -> bool {
            true
        }

        fn seal_vault_key(
            &self,
            user_id: Uuid,
            vault_key: &VaultKey,
        ) -> Result<Vec<u8>, BiometricError> {
            let mut key_buf = Zeroizing::new(*vault_key.as_bytes());
            let mut entropy = Zeroizing::new(user_entropy(user_id));

            let data_in = DataBlob {
                cb_data: key_buf.len() as Dword,
                pb_data: key_buf.as_mut_ptr(),
            };
            let entropy_blob = DataBlob {
                cb_data: entropy.len() as Dword,
                pb_data: entropy.as_mut_ptr(),
            };
            let mut data_out = DataBlob {
                cb_data: 0,
                pb_data: null_mut(),
            };

            let mut descr: Vec<u16> = "AnvilVaultKey".encode_utf16().collect();
            descr.push(0);

            // SAFETY: Input blobs reference pinned stack/heap slices for the synchronous call duration.
            let ok = unsafe {
                CryptProtectData(
                    &data_in,
                    descr.as_ptr(),
                    &entropy_blob,
                    null_mut(),
                    null_mut(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut data_out,
                )
            };
            if ok == 0 || data_out.pb_data.is_null() {
                return Err(BiometricError::SealFailed);
            }

            // SAFETY: DPAPI allocates `data_out.pb_data` with `cb_data` valid bytes until `LocalFree`.
            let sealed = unsafe {
                let slice = std::slice::from_raw_parts(data_out.pb_data, data_out.cb_data as usize);
                let vec = slice.to_vec();
                let _ = LocalFree(data_out.pb_data.cast::<c_void>());
                vec
            };

            Ok(sealed)
        }

        fn unseal_vault_key(
            &self,
            user_id: Uuid,
            sealed: &[u8],
        ) -> Result<VaultKey, BiometricError> {
            let mut sealed_copy = sealed.to_vec();
            let mut entropy = Zeroizing::new(user_entropy(user_id));

            let data_in = DataBlob {
                cb_data: sealed_copy.len() as Dword,
                pb_data: sealed_copy.as_mut_ptr(),
            };
            let entropy_blob = DataBlob {
                cb_data: entropy.len() as Dword,
                pb_data: entropy.as_mut_ptr(),
            };
            let mut data_out = DataBlob {
                cb_data: 0,
                pb_data: null_mut(),
            };

            // SAFETY: `data_in` and `entropy_blob` reference owned writable/readable slices during DPAPI call.
            let ok = unsafe {
                CryptUnprotectData(
                    &data_in,
                    null::<*mut u16>().cast_mut(),
                    &entropy_blob,
                    null_mut(),
                    null_mut(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &mut data_out,
                )
            };
            if ok == 0 || data_out.pb_data.is_null() {
                return Err(BiometricError::UnsealFailed);
            }

            let key_len = data_out.cb_data as usize;
            let mut out_bytes = Zeroizing::new([0u8; 32]);

            // SAFETY: Scrub native heap plaintext immediately after copying before releasing via `LocalFree`.
            unsafe {
                if key_len == 32 {
                    let slice = std::slice::from_raw_parts(data_out.pb_data, key_len);
                    out_bytes.copy_from_slice(slice);
                }
                std::ptr::write_bytes(data_out.pb_data, 0, key_len);
                let _ = LocalFree(data_out.pb_data.cast::<c_void>());
            }

            if key_len != 32 {
                return Err(BiometricError::InvalidKeyMaterial);
            }

            Ok(VaultKey::from_bytes(*out_bytes))
        }
    }
}

#[cfg(windows)]
pub use native::WindowsDpapiBiometricProvider;

/// Returns the platform default biometric/DPAPI key seal provider.
pub fn default_biometric_provider() -> std::sync::Arc<dyn BiometricProvider> {
    #[cfg(windows)]
    {
        std::sync::Arc::new(WindowsDpapiBiometricProvider::new())
    }
    #[cfg(not(windows))]
    {
        std::sync::Arc::new(MemoryBiometricProvider::unavailable())
    }
}

#[cfg_attr(not(windows), allow(dead_code))]
fn user_entropy(user_id: Uuid) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(format!("anvil:v1:os-vault-key-seal|{}", user_id.hyphenated()).into_bytes())
}

#[cfg(test)]
mod tests {
    use anvil_core::crypto::VaultKey;
    use uuid::Uuid;

    use super::{BiometricProvider, MemoryBiometricProvider};

    #[test]
    fn memory_provider_binds_sealed_key_to_user_id() {
        let provider = MemoryBiometricProvider::available();
        let uid = Uuid::new_v4();
        let other = Uuid::new_v4();
        let key = VaultKey::from_bytes([0x42; 32]);

        let sealed = provider.seal_vault_key(uid, &key).ok();
        assert!(sealed.is_some());
        if let Some(blob) = sealed {
            assert!(provider.unseal_vault_key(other, &blob).is_err());
            let unsealed = provider.unseal_vault_key(uid, &blob).ok();
            assert_eq!(unsealed.map(|k| *k.as_bytes()), Some([0x42; 32]));
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_seals_and_unseals_vault_key() {
        use super::WindowsDpapiBiometricProvider;

        let provider = WindowsDpapiBiometricProvider::new();
        let uid = Uuid::new_v4();
        let other = Uuid::new_v4();
        let key = VaultKey::from_bytes([0xA7; 32]);

        let sealed = provider.seal_vault_key(uid, &key).ok();
        assert!(sealed.is_some());
        if let Some(blob) = sealed {
            assert_ne!(blob, [0xA7; 32]);
            assert!(provider.unseal_vault_key(other, &blob).is_err());
            let unsealed = provider.unseal_vault_key(uid, &blob).ok();
            assert_eq!(unsealed.map(|k| *k.as_bytes()), Some([0xA7; 32]));
        }
    }
}
