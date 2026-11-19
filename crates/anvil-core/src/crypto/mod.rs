//! Zero-knowledge cryptographic primitives and key hygiene.

pub mod aead;
pub mod bitwarden_crypto;
pub mod kdf;
pub mod keys;

pub use aead::{
    ENVELOPE_VERSION_V1, MIN_ENVELOPE_LEN, NONCE_LEN, TAG_LEN, aad_blob, aad_folder, aad_item,
    aad_vault_key, decrypt_envelope, decrypt_json, encrypt_envelope, encrypt_json,
    unwrap_vault_key, wrap_vault_key,
};
pub use bitwarden_crypto::{BitwardenKdfParams, BitwardenKdfType, decrypt_bitwarden_cipher_string};
pub use kdf::{
    KdfAlgorithm, KdfParams, derive_master_key, derive_master_subkeys, derive_vault_subkeys,
    generate_kdf_salt,
};
pub use keys::{
    KEY_LEN, MasterAuthHash, MasterEncryptionKey, MasterKey, MasterPassword, VaultKey,
    VaultSubKeys, fill_random_bytes,
};
