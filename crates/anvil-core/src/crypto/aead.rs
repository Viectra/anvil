//! Versioned XChaCha20-Poly1305 binary envelopes with strict AAD context binding.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::keys::{KEY_LEN, MasterEncryptionKey, VaultKey, fill_random_bytes};
use crate::error::AnvilError;

/// Current binary envelope format version byte.
pub const ENVELOPE_VERSION_V1: u8 = 0x01;
/// Length in bytes of an XChaCha20-Poly1305 192-bit nonce.
pub const NONCE_LEN: usize = 24;
/// Length in bytes of a Poly1305 authentication tag.
pub const TAG_LEN: usize = 16;
/// Minimum byte length of a valid binary envelope (`version + nonce + tag`).
pub const MIN_ENVELOPE_LEN: usize = 1 + NONCE_LEN + TAG_LEN;

const AAD_VAULT_KEY_PREFIX: &[u8] = b"anvil:v1:vault-key|";
const AAD_ITEM_PREFIX: &[u8] = b"anvil:v1:item|";
const AAD_FOLDER_PREFIX: &[u8] = b"anvil:v1:folder|";
const AAD_BLOB_PREFIX: &[u8] = b"anvil:v1:blob|";

/// Builds AAD binding a wrapped `VaultKey` to its owning `user_id` and `key_version`.
pub fn aad_vault_key(user_id: Uuid, key_version: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_VAULT_KEY_PREFIX.len() + 16 + 4);
    aad.extend_from_slice(AAD_VAULT_KEY_PREFIX);
    aad.extend_from_slice(user_id.as_bytes());
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}

/// Builds AAD binding an encrypted vault item to its owning `user_id` and `item_id`.
pub fn aad_item(user_id: Uuid, item_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_ITEM_PREFIX.len() + 32);
    aad.extend_from_slice(AAD_ITEM_PREFIX);
    aad.extend_from_slice(user_id.as_bytes());
    aad.extend_from_slice(item_id.as_bytes());
    aad
}

/// Builds AAD binding an encrypted folder to its owning `user_id` and `folder_id`.
pub fn aad_folder(user_id: Uuid, folder_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_FOLDER_PREFIX.len() + 32);
    aad.extend_from_slice(AAD_FOLDER_PREFIX);
    aad.extend_from_slice(user_id.as_bytes());
    aad.extend_from_slice(folder_id.as_bytes());
    aad
}

/// Builds AAD binding an encrypted binary blob to its owning `user_id`, `item_id`, and `blob_id`.
pub fn aad_blob(user_id: Uuid, item_id: Uuid, blob_id: Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_BLOB_PREFIX.len() + 48);
    aad.extend_from_slice(AAD_BLOB_PREFIX);
    aad.extend_from_slice(user_id.as_bytes());
    aad.extend_from_slice(item_id.as_bytes());
    aad.extend_from_slice(blob_id.as_bytes());
    aad
}

/// Encrypts `plaintext` into `[0x01 | nonce_24 | ciphertext | tag_16]` using XChaCha20-Poly1305.
pub fn encrypt_envelope(
    key: &[u8; KEY_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AnvilError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random_bytes(&mut nonce_bytes)?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AnvilError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(1 + NONCE_LEN + ciphertext.len());
    out.push(ENVELOPE_VERSION_V1);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Verifies envelope version, nonce, and Poly1305 tag against `aad`, returning zeroized plaintext.
pub fn decrypt_envelope(
    key: &[u8; KEY_LEN],
    envelope: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AnvilError> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(AnvilError::InvalidEnvelope);
    }
    let version = envelope[0];
    if version != ENVELOPE_VERSION_V1 {
        return Err(AnvilError::UnsupportedEnvelopeVersion(version));
    }

    let nonce = XNonce::from_slice(&envelope[1..1 + NONCE_LEN]);
    let ciphertext = &envelope[1 + NONCE_LEN..];

    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AnvilError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}

/// Wraps `VaultKey` under `MasterEncryptionKey` bound to `(user_id, key_version)`.
pub fn wrap_vault_key(
    mek: &MasterEncryptionKey,
    vault_key: &VaultKey,
    user_id: Uuid,
    key_version: u32,
) -> Result<Vec<u8>, AnvilError> {
    let aad = aad_vault_key(user_id, key_version);
    encrypt_envelope(mek.as_bytes(), vault_key.as_bytes(), &aad)
}

/// Unwraps `VaultKey` from its envelope, rejecting mismatched keys, `user_id`, or `key_version`.
pub fn unwrap_vault_key(
    mek: &MasterEncryptionKey,
    wrapped: &[u8],
    user_id: Uuid,
    key_version: u32,
) -> Result<VaultKey, AnvilError> {
    let aad = aad_vault_key(user_id, key_version);
    let plaintext = decrypt_envelope(mek.as_bytes(), wrapped, &aad)?;
    VaultKey::from_slice(&plaintext)
}

/// Serializes `value` as JSON into a zeroized temporary buffer and encrypts it with `aad`.
pub fn encrypt_json<T: Serialize>(
    key: &[u8; KEY_LEN],
    value: &T,
    aad: &[u8],
) -> Result<Vec<u8>, AnvilError> {
    let json = Zeroizing::new(serde_json::to_vec(value)?);
    encrypt_envelope(key, &json, aad)
}

/// Decrypts an envelope against `aad` and deserializes the JSON payload.
pub fn decrypt_json<T: DeserializeOwned>(
    key: &[u8; KEY_LEN],
    envelope: &[u8],
    aad: &[u8],
) -> Result<T, AnvilError> {
    let json = decrypt_envelope(key, envelope, aad)?;
    Ok(serde_json::from_slice(&json)?)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::crypto::kdf::{
        KdfParams, derive_master_key_raw, derive_master_subkeys, derive_vault_subkeys,
    };
    use crate::crypto::keys::MasterPassword;

    #[test]
    fn wrap_and_unwrap_vault_key_enforces_aad_and_version() {
        let user_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let pw = MasterPassword::new("forge-pass-123");
        let salt = [0x99u8; 32];
        let mk = derive_master_key_raw(&pw, &salt, &KdfParams::fast_for_tests())
            .expect("fast kdf succeeds");
        let (mek, _) = derive_master_subkeys(&mk, &salt).expect("hkdf succeeds");
        let vk = VaultKey::generate().expect("vault key gen");

        let wrapped = wrap_vault_key(&mek, &vk, user_id, 1).expect("wrap succeeds");
        let unwrapped = unwrap_vault_key(&mek, &wrapped, user_id, 1).expect("unwrap succeeds");
        assert_eq!(vk, unwrapped);

        // Wrong user_id must fail AAD check.
        assert!(matches!(
            unwrap_vault_key(&mek, &wrapped, other_user, 1),
            Err(AnvilError::DecryptionFailed)
        ));
        // Wrong key_version must fail AAD check.
        assert!(matches!(
            unwrap_vault_key(&mek, &wrapped, user_id, 2),
            Err(AnvilError::DecryptionFailed)
        ));
    }

    #[test]
    fn item_aad_prevents_cross_user_and_cross_item_and_cross_type_substitution() {
        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();
        let item_1 = Uuid::new_v4();
        let item_2 = Uuid::new_v4();
        let blob_1 = Uuid::new_v4();

        let vk = VaultKey::generate().expect("vault key");
        let sub = derive_vault_subkeys(&vk).expect("subkeys");

        let ct = encrypt_envelope(&sub.item_key, b"secret-payload", &aad_item(user_a, item_1))
            .expect("encrypt");

        assert!(decrypt_envelope(&sub.item_key, &ct, &aad_item(user_a, item_2)).is_err());
        assert!(decrypt_envelope(&sub.item_key, &ct, &aad_item(user_b, item_1)).is_err());
        assert!(decrypt_envelope(&sub.item_key, &ct, &aad_folder(user_a, item_1)).is_err());
        assert!(decrypt_envelope(&sub.folder_key, &ct, &aad_item(user_a, item_1)).is_err());

        let blob_ct = encrypt_envelope(
            &sub.blob_key,
            b"png-bytes",
            &aad_blob(user_a, item_1, blob_1),
        )
        .expect("encrypt blob");
        assert!(
            decrypt_envelope(&sub.blob_key, &blob_ct, &aad_blob(user_a, item_2, blob_1)).is_err()
        );
    }

    #[test]
    fn tampering_any_envelope_byte_or_version_fails() {
        let user_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let key = [0x33u8; KEY_LEN];
        let aad = aad_item(user_id, item_id);
        let env = encrypt_envelope(&key, b"hello-anvil", &aad).expect("encrypt");

        let mut bad_ver = env.clone();
        bad_ver[0] = 0x02;
        assert!(matches!(
            decrypt_envelope(&key, &bad_ver, &aad),
            Err(AnvilError::UnsupportedEnvelopeVersion(2))
        ));

        for idx in 1..env.len() {
            let mut tampered = env.clone();
            tampered[idx] ^= 0x01;
            assert!(matches!(
                decrypt_envelope(&key, &tampered, &aad),
                Err(AnvilError::DecryptionFailed)
            ));
        }

        assert!(matches!(
            decrypt_envelope(&key, &env[..MIN_ENVELOPE_LEN - 1], &aad),
            Err(AnvilError::InvalidEnvelope)
        ));
    }

    proptest! {
        #[test]
        fn aead_envelope_roundtrip_arbitrary_payloads(
            key in any::<[u8; 32]>(),
            plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
            aad in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let env = encrypt_envelope(&key, &plaintext, &aad).expect("encrypt");
            prop_assert_eq!(env[0], ENVELOPE_VERSION_V1);
            prop_assert_eq!(env.len(), MIN_ENVELOPE_LEN + plaintext.len());
            let dec = decrypt_envelope(&key, &env, &aad).expect("decrypt");
            prop_assert_eq!(&dec[..], &plaintext[..]);
        }
    }
}
