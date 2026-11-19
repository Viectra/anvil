//! Zeroized key material wrappers with constant-time comparisons and redacted `Debug`.

use std::fmt;

use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::error::AnvilError;

/// Length in bytes of symmetric 256-bit keys and authentication hashes.
pub const KEY_LEN: usize = 32;

/// Fills `dest` with cryptographically secure random bytes from the OS/browser CSPRNG.
pub fn fill_random_bytes(dest: &mut [u8]) -> Result<(), AnvilError> {
    getrandom::getrandom(dest).map_err(|_| AnvilError::RngFailed)
}

/// User master password normalized to UTF-8 NFC and wiped from memory on drop.
#[derive(Clone)]
pub struct MasterPassword(Zeroizing<String>);

impl MasterPassword {
    /// Normalizes the password to UTF-8 NFC and stores it in a zeroized buffer.
    pub fn new(raw: impl AsRef<str>) -> Self {
        let normalized: String = raw.as_ref().nfc().collect();
        Self(Zeroizing::new(normalized))
    }

    /// Returns the normalized UTF-8 byte representation.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Returns the normalized string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if the password is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterPassword([REDACTED])")
    }
}

macro_rules! define_secret_key {
    ($name:ident, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name(Zeroizing<[u8; KEY_LEN]>);

        impl $name {
            /// Wraps a raw 32-byte key in a zeroized container.
            pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            /// Wraps a 32-byte slice into the key type, rejecting wrong lengths.
            pub fn from_slice(slice: &[u8]) -> Result<Self, AnvilError> {
                if slice.len() != KEY_LEN {
                    return Err(AnvilError::InvalidEnvelope);
                }
                let mut buf = [0u8; KEY_LEN];
                buf.copy_from_slice(slice);
                Ok(Self(Zeroizing::new(buf)))
            }

            /// Exposes the underlying 32-byte slice.
            pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0.ct_eq(&*other.0).into()
            }
        }

        impl Eq for $name {}

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

define_secret_key!(
    MasterKey,
    "256-bit key derived by Argon2id from the master password."
);
define_secret_key!(
    MasterEncryptionKey,
    "Client-only 256-bit key used exclusively to wrap and unwrap the VaultKey."
);
define_secret_key!(
    MasterAuthHash,
    "256-bit authentication hash sent over TLS and re-hashed server-side."
);
define_secret_key!(
    VaultKey,
    "Random 256-bit symmetric root key for all vault entries, folders, and blobs."
);

impl VaultKey {
    /// Generates a fresh 256-bit VaultKey from the system CSPRNG.
    pub fn generate() -> Result<Self, AnvilError> {
        let mut bytes = [0u8; KEY_LEN];
        fill_random_bytes(&mut bytes)?;
        Ok(Self::from_bytes(bytes))
    }
}

/// Domain-separated 256-bit encryption subkeys derived from a `VaultKey`.
#[derive(Clone)]
pub struct VaultSubKeys {
    pub item_key: Zeroizing<[u8; KEY_LEN]>,
    pub folder_key: Zeroizing<[u8; KEY_LEN]>,
    pub blob_key: Zeroizing<[u8; KEY_LEN]>,
}

impl fmt::Debug for VaultSubKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultSubKeys([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_password_normalizes_nfc_and_redacts_debug() {
        let decomposed = MasterPassword::new("cafe\u{0301}");
        let composed = MasterPassword::new("caf\u{00e9}");
        assert_eq!(decomposed.as_str(), composed.as_str());
        assert_eq!(format!("{composed:?}"), "MasterPassword([REDACTED])");
    }

    #[test]
    fn vault_key_generation_and_redaction() {
        let k1 = VaultKey::generate().expect("csprng should succeed");
        let k2 = VaultKey::generate().expect("csprng should succeed");
        assert_ne!(k1, k2);
        assert_eq!(format!("{k1:?}"), "VaultKey([REDACTED])");
    }
}
