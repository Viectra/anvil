//! Decryption support for password-protected Bitwarden encrypted JSON exports (`encType = 2`).

use aes::Aes256;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cbc::Decryptor;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::AnvilError;

type HmacSha256 = Hmac<Sha256>;

/// Key derivation algorithm used in Bitwarden encrypted JSON exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitwardenKdfType {
    /// PBKDF2-HMAC-SHA256 (`kdfType = 0`).
    Pbkdf2Sha256 = 0,
    /// Argon2id (`kdfType = 1`).
    Argon2id = 1,
}

impl BitwardenKdfType {
    /// Converts the numeric Bitwarden `kdfType` field.
    pub fn from_u32(val: u32) -> Result<Self, AnvilError> {
        match val {
            0 => Ok(Self::Pbkdf2Sha256),
            1 => Ok(Self::Argon2id),
            _ => Err(AnvilError::UnsupportedImportFormat),
        }
    }
}

/// KDF parameters embedded in a password-protected Bitwarden encrypted JSON export.
#[derive(Debug, Clone)]
pub struct BitwardenKdfParams {
    pub kdf_type: BitwardenKdfType,
    pub salt: String,
    pub iterations: u32,
    pub memory_mb: Option<u32>,
    pub parallelism: Option<u32>,
}

struct BitwardenKeys {
    enc_key: Zeroizing<[u8; 32]>,
    mac_key: Zeroizing<[u8; 32]>,
}

/// Derives Bitwarden's `(enc_key, mac_key)` pair (32 bytes each) for `encType = 2`.
fn derive_bitwarden_keys(
    password: &str,
    params: &BitwardenKdfParams,
) -> Result<BitwardenKeys, AnvilError> {
    if params.iterations == 0 || params.iterations > 10_000_000 {
        return Err(AnvilError::KdfParamsOutOfBounds(
            "bitwarden kdfIterations out of bounds".to_owned(),
        ));
    }

    let mut master_key = Zeroizing::new([0u8; 32]);
    match params.kdf_type {
        BitwardenKdfType::Pbkdf2Sha256 => {
            pbkdf2_hmac::<Sha256>(
                password.as_bytes(),
                params.salt.as_bytes(),
                params.iterations,
                &mut *master_key,
            );
        }
        BitwardenKdfType::Argon2id => {
            let mem_mb = params.memory_mb.unwrap_or(64);
            let par = params.parallelism.unwrap_or(4);
            if !(1..=1024).contains(&mem_mb) || !(1..=16).contains(&par) {
                return Err(AnvilError::KdfParamsOutOfBounds(
                    "bitwarden Argon2id parameters out of bounds".to_owned(),
                ));
            }
            let salt_hash = Sha256::digest(params.salt.as_bytes());
            let argon_params = Params::new(mem_mb * 1024, params.iterations, par, Some(32))
                .map_err(|e| AnvilError::KdfFailed(e.to_string()))?;
            let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
            argon
                .hash_password_into(password.as_bytes(), &salt_hash, &mut *master_key)
                .map_err(|e| AnvilError::KdfFailed(e.to_string()))?;
        }
    }

    // Bitwarden stretches `master_key` with HKDF-Expand-only (no HKDF-Extract).
    let hk = Hkdf::<Sha256>::from_prk(&*master_key).map_err(|_| AnvilError::HkdfFailed)?;
    let mut enc_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"enc", &mut *enc_key)
        .map_err(|_| AnvilError::HkdfFailed)?;
    let mut mac_key = Zeroizing::new([0u8; 32]);
    hk.expand(b"mac", &mut *mac_key)
        .map_err(|_| AnvilError::HkdfFailed)?;

    Ok(BitwardenKeys { enc_key, mac_key })
}

/// Decrypts a Bitwarden CipherString (`2.<iv_b64>|<ct_b64>|<mac_b64>`) using Encrypt-then-MAC.
pub fn decrypt_bitwarden_cipher_string(
    cipher_string: &str,
    password: &str,
    params: &BitwardenKdfParams,
) -> Result<Zeroizing<String>, AnvilError> {
    let (enc_type, body) = cipher_string
        .split_once('.')
        .ok_or(AnvilError::InvalidEnvelope)?;
    if enc_type != "2" {
        return Err(AnvilError::UnsupportedImportFormat);
    }

    let mut parts = body.split('|');
    let iv_b64 = parts.next().ok_or(AnvilError::InvalidEnvelope)?;
    let ct_b64 = parts.next().ok_or(AnvilError::InvalidEnvelope)?;
    let mac_b64 = parts.next().ok_or(AnvilError::InvalidEnvelope)?;
    if parts.next().is_some() {
        return Err(AnvilError::InvalidEnvelope);
    }

    let iv = BASE64_STANDARD
        .decode(iv_b64)
        .map_err(|_| AnvilError::InvalidEnvelope)?;
    if iv.len() != 16 {
        return Err(AnvilError::InvalidEnvelope);
    }
    let mut ct = BASE64_STANDARD
        .decode(ct_b64)
        .map_err(|_| AnvilError::InvalidEnvelope)?;
    let mac = BASE64_STANDARD
        .decode(mac_b64)
        .map_err(|_| AnvilError::InvalidEnvelope)?;
    if mac.len() != 32 {
        return Err(AnvilError::InvalidEnvelope);
    }

    let keys = derive_bitwarden_keys(password, params)?;

    // Verify HMAC-SHA256(mac_key, iv || ciphertext) in constant time before decrypting.
    let mut mac_calc =
        HmacSha256::new_from_slice(&*keys.mac_key).map_err(|_| AnvilError::WrongBackupPassword)?;
    mac_calc.update(&iv);
    mac_calc.update(&ct);
    let expected_mac = mac_calc.finalize().into_bytes();
    if expected_mac.ct_eq(&mac).unwrap_u8() != 1 {
        return Err(AnvilError::WrongBackupPassword);
    }

    let decryptor = Decryptor::<Aes256>::new_from_slices(&*keys.enc_key, &iv)
        .map_err(|_| AnvilError::WrongBackupPassword)?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut ct)
        .map_err(|_| AnvilError::WrongBackupPassword)?;

    let pt_owned = Zeroizing::new(
        String::from_utf8(plaintext.to_vec()).map_err(|_| AnvilError::WrongBackupPassword)?,
    );
    Ok(pt_owned)
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use cbc::Encryptor;
    use cbc::cipher::BlockEncryptMut;

    use super::*;

    pub(crate) fn encrypt_bitwarden_cipher_string(
        plaintext: &str,
        password: &str,
        params: &BitwardenKdfParams,
        iv: [u8; 16],
    ) -> String {
        let keys = derive_bitwarden_keys(password, params).expect("derive keys");
        let pt_bytes = plaintext.as_bytes();
        let mut buf = vec![0u8; pt_bytes.len() + 16];
        buf[..pt_bytes.len()].copy_from_slice(pt_bytes);
        let encryptor =
            Encryptor::<Aes256>::new_from_slices(&*keys.enc_key, &iv).expect("encryptor");
        let ct = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_bytes.len())
            .expect("pad");

        let mut mac_calc = HmacSha256::new_from_slice(&*keys.mac_key).expect("hmac");
        mac_calc.update(&iv);
        mac_calc.update(ct);
        let mac = mac_calc.finalize().into_bytes();

        format!(
            "2.{}|{}|{}",
            BASE64_STANDARD.encode(iv),
            BASE64_STANDARD.encode(ct),
            BASE64_STANDARD.encode(mac),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::encrypt_bitwarden_cipher_string;
    use super::*;

    #[test]
    fn bitwarden_pbkdf2_decrypt_roundtrip_and_rejects_wrong_password() {
        let params = BitwardenKdfParams {
            kdf_type: BitwardenKdfType::Pbkdf2Sha256,
            salt: "export-salt-123".to_owned(),
            iterations: 5_000,
            memory_mb: None,
            parallelism: None,
        };
        let cipher = encrypt_bitwarden_cipher_string(
            r#"{"items":[{"name":"GitHub"}]}"#,
            "bw-secret",
            &params,
            [0x55u8; 16],
        );

        let dec = decrypt_bitwarden_cipher_string(&cipher, "bw-secret", &params)
            .expect("decryption succeeds");
        assert_eq!(&*dec, r#"{"items":[{"name":"GitHub"}]}"#);

        assert!(matches!(
            decrypt_bitwarden_cipher_string(&cipher, "wrong-pass", &params),
            Err(AnvilError::WrongBackupPassword)
        ));

        // Flip one bit in the decoded MAC tag while keeping valid Base64 encoding.
        let mut parts: Vec<String> = cipher.split('|').map(str::to_owned).collect();
        let mut mac_bytes = BASE64_STANDARD.decode(&parts[2]).expect("valid base64 mac");
        mac_bytes[0] ^= 0x01;
        parts[2] = BASE64_STANDARD.encode(mac_bytes);
        let tampered = parts.join("|");
        assert!(matches!(
            decrypt_bitwarden_cipher_string(&tampered, "bw-secret", &params),
            Err(AnvilError::WrongBackupPassword)
        ));
    }

    #[test]
    fn bitwarden_argon2id_decrypt_roundtrip() {
        let params = BitwardenKdfParams {
            kdf_type: BitwardenKdfType::Argon2id,
            salt: "argon2-export-salt".to_owned(),
            iterations: 2,
            memory_mb: Some(16),
            parallelism: Some(1),
        };
        let cipher = encrypt_bitwarden_cipher_string(
            r#"{"encrypted":false,"items":[]}"#,
            "argon-pass",
            &params,
            [0x12u8; 16],
        );
        let dec = decrypt_bitwarden_cipher_string(&cipher, "argon-pass", &params)
            .expect("argon2id decryption succeeds");
        assert_eq!(&*dec, r#"{"encrypted":false,"items":[]}"#);
    }
}
