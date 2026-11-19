//! Server-side email normalization, anti-enumeration prelogin salts, Argon2id+pepper hashing, and opaque tokens.

use anvil_core::crypto::fill_random_bytes;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::ApiError;

/// Length in bytes of random per-account server auth salts.
pub const SERVER_AUTH_SALT_LEN: usize = 16;
/// Length in bytes of opaque refresh and invitation tokens.
pub const OPAQUE_TOKEN_BYTES: usize = 32;

/// Production OWASP Argon2id server re-hash parameters (`m = 19 MiB`, `t = 2`, `p = 1`).
pub const DEFAULT_SERVER_KDF_MEMORY_KIB: u32 = 19_456;
pub const DEFAULT_SERVER_KDF_ITERATIONS: u32 = 2;
pub const DEFAULT_SERVER_KDF_PARALLELISM: u32 = 1;

const PRELOGIN_DOMAIN_PREFIX: &[u8] = b"anvil:v1:prelogin-salt|";
const MAX_EMAIL_LEN: usize = 254;
const MAX_LOCAL_PART_LEN: usize = 64;
const MAX_VERIFY_MEMORY_KIB: u32 = 524_288;
const MAX_VERIFY_ITERATIONS: u32 = 20;
const MAX_VERIFY_PARALLELISM: u32 = 8;

type HmacSha256 = Hmac<Sha256>;

/// Normalizes an email address (trim + lowercase) and checks RFC-compatible structural bounds.
pub fn normalize_email(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim().to_lowercase();
    if trimmed.is_empty() || trimmed.len() > MAX_EMAIL_LEN {
        return Err(ApiError::bad_request(
            "INVALID_EMAIL",
            "Email address must be between 1 and 254 bytes",
        ));
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(ApiError::bad_request(
            "INVALID_EMAIL",
            "Email address contains invalid whitespace or control characters",
        ));
    }

    let mut parts = trimmed.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if parts.next().is_some()
        || local.is_empty()
        || local.len() > MAX_LOCAL_PART_LEN
        || domain.is_empty()
        || !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.split('.').any(str::is_empty)
    {
        return Err(ApiError::bad_request(
            "INVALID_EMAIL",
            "Malformed email address",
        ));
    }

    Ok(trimmed)
}

/// Computes a deterministic 32-byte fake prelogin salt for non-existent emails to block enumeration.
pub fn compute_fake_prelogin_salt(
    prelogin_secret: &[u8],
    normalized_email: &str,
) -> Result<[u8; 32], anyhow::Error> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(prelogin_secret)
        .map_err(|_| anyhow::anyhow!("invalid prelogin secret length"))?;
    mac.update(PRELOGIN_DOMAIN_PREFIX);
    mac.update(normalized_email.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// Generates a 256-bit opaque URL-safe token along with its SHA-256 storage digest.
pub fn generate_opaque_token() -> Result<(Zeroizing<String>, [u8; 32]), anyhow::Error> {
    let mut raw = Zeroizing::new([0u8; OPAQUE_TOKEN_BYTES]);
    fill_random_bytes(&mut *raw).map_err(|e| anyhow::anyhow!("csprng error: {e}"))?;
    let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(&*raw));
    let hash = hash_opaque_token(&token);
    Ok((token, hash))
}

/// Computes the canonical SHA-256 storage digest for an opaque refresh or invite token string.
pub fn hash_opaque_token(token: &str) -> [u8; 32] {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Server-side Argon2id (+ optional HMAC pepper) hasher for client `MasterAuthHash` values.
#[derive(Clone)]
pub struct ServerAuthHasher {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    pepper: Option<Zeroizing<Vec<u8>>>,
}

impl ServerAuthHasher {
    /// Creates a production hasher using OWASP-aligned Argon2id defaults (`19 MiB`, `t = 2`, `p = 1`).
    pub fn new(pepper: Option<Zeroizing<Vec<u8>>>) -> Self {
        Self::with_params(
            DEFAULT_SERVER_KDF_MEMORY_KIB,
            DEFAULT_SERVER_KDF_ITERATIONS,
            DEFAULT_SERVER_KDF_PARALLELISM,
            pepper,
        )
    }

    /// Creates a hasher with custom Argon2id parameters.
    pub fn with_params(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
        pepper: Option<Zeroizing<Vec<u8>>>,
    ) -> Self {
        Self {
            memory_kib,
            iterations,
            parallelism,
            pepper,
        }
    }

    fn apply_pepper(
        &self,
        master_auth_hash: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, anyhow::Error> {
        let Some(pepper) = &self.pepper else {
            return Ok(Zeroizing::new(*master_auth_hash));
        };
        let mut mac = <HmacSha256 as Mac>::new_from_slice(pepper)
            .map_err(|_| anyhow::anyhow!("invalid server auth pepper"))?;
        mac.update(master_auth_hash);
        let bytes = mac.finalize().into_bytes();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    /// Generates a fresh 16-byte server salt and re-hashes `master_auth_hash` for storage.
    pub fn hash_master_auth_hash(
        &self,
        master_auth_hash: &[u8; 32],
    ) -> Result<(Vec<u8>, String), anyhow::Error> {
        let mut salt = [0u8; SERVER_AUTH_SALT_LEN];
        fill_random_bytes(&mut salt).map_err(|e| anyhow::anyhow!("csprng error: {e}"))?;
        let ikm = self.apply_pepper(master_auth_hash)?;
        let digest = derive_argon2id_digest(
            &*ikm,
            &salt,
            self.memory_kib,
            self.iterations,
            self.parallelism,
        )?;
        let encoded = format!(
            "v1:argon2id:m={},t={},p={}:{}",
            self.memory_kib,
            self.iterations,
            self.parallelism,
            URL_SAFE_NO_PAD.encode(&*digest)
        );
        Ok((salt.to_vec(), encoded))
    }

    /// Verifies `master_auth_hash` against a stored salt and encoded hash in constant time.
    pub fn verify_master_auth_hash(
        &self,
        master_auth_hash: &[u8; 32],
        salt: &[u8],
        stored_hash: &str,
    ) -> Result<bool, anyhow::Error> {
        if salt.len() != SERVER_AUTH_SALT_LEN {
            return Ok(false);
        }
        let Some((m, t, p, expected_digest)) = decode_stored_hash(stored_hash)? else {
            return Ok(false);
        };
        if m > MAX_VERIFY_MEMORY_KIB || t > MAX_VERIFY_ITERATIONS || p > MAX_VERIFY_PARALLELISM {
            return Err(anyhow::anyhow!(
                "stored server hash parameters exceed safety bounds"
            ));
        }
        let ikm = self.apply_pepper(master_auth_hash)?;
        let computed = derive_argon2id_digest(&*ikm, salt, m, t, p)?;
        Ok(bool::from(
            computed.as_slice().ct_eq(expected_digest.as_slice()),
        ))
    }

    /// Executes an equivalent Argon2id computation when an account is absent or inactive.
    pub fn dummy_verify(&self) {
        const DUMMY_INPUT: [u8; 32] = [0xA5u8; 32];
        const DUMMY_SALT: [u8; SERVER_AUTH_SALT_LEN] = [0x5Au8; SERVER_AUTH_SALT_LEN];
        let _ = self.apply_pepper(&DUMMY_INPUT).and_then(|ikm| {
            derive_argon2id_digest(
                &*ikm,
                &DUMMY_SALT,
                self.memory_kib,
                self.iterations,
                self.parallelism,
            )
        });
    }
}

fn derive_argon2id_digest(
    ikm: &[u8; 32],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<[u8; 32]>, anyhow::Error> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(ikm, salt, &mut *out)
        .map_err(|e| anyhow::anyhow!("argon2 server hash failed: {e}"))?;
    Ok(out)
}

fn decode_stored_hash(
    encoded: &str,
) -> Result<Option<(u32, u32, u32, Zeroizing<[u8; 32]>)>, anyhow::Error> {
    let mut parts = encoded.split(':');
    let Some(ver) = parts.next() else {
        return Ok(None);
    };
    let Some(alg) = parts.next() else {
        return Ok(None);
    };
    let Some(params_str) = parts.next() else {
        return Ok(None);
    };
    let Some(digest_b64) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some() || ver != "v1" || alg != "argon2id" {
        return Ok(None);
    }

    let mut m = None;
    let mut t = None;
    let mut p = None;
    for kv in params_str.split(',') {
        if let Some(val) = kv.strip_prefix("m=") {
            m = val.parse::<u32>().ok();
        } else if let Some(val) = kv.strip_prefix("t=") {
            t = val.parse::<u32>().ok();
        } else if let Some(val) = kv.strip_prefix("p=") {
            p = val.parse::<u32>().ok();
        }
    }
    let (Some(m), Some(t), Some(p)) = (m, t, p) else {
        return Ok(None);
    };

    let Ok(digest_vec) = URL_SAFE_NO_PAD.decode(digest_b64) else {
        return Ok(None);
    };
    if digest_vec.len() != 32 {
        return Ok(None);
    }
    let mut digest = Zeroizing::new([0u8; 32]);
    digest.copy_from_slice(&digest_vec);
    Ok(Some((m, t, p, digest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_validates_email_addresses() {
        assert_eq!(
            normalize_email("  Alice.Smith@Example.COM  ").expect("valid email"),
            "alice.smith@example.com"
        );
        assert!(normalize_email("").is_err());
        assert!(normalize_email("not-an-email").is_err());
        assert!(normalize_email("alice@localhost").is_err());
        assert!(normalize_email("a b@example.com").is_err());
        assert!(normalize_email("alice@.example.com").is_err());
    }

    #[test]
    fn fake_prelogin_salt_is_deterministic_and_email_bound() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let s1 = compute_fake_prelogin_salt(secret, "alice@example.com").expect("salt");
        let s2 = compute_fake_prelogin_salt(secret, "alice@example.com").expect("salt");
        let s3 = compute_fake_prelogin_salt(secret, "bob@example.com").expect("salt");
        assert_eq!(s1, s2);
        assert_ne!(s1, s3);
    }

    #[test]
    fn server_auth_hash_with_pepper_verifies_and_rejects_mismatches() {
        let pepper = Zeroizing::new(b"server-pepper-secret-0123456789ab".to_vec());
        let hasher = ServerAuthHasher::new(Some(pepper));
        let wrong_pepper_hasher = ServerAuthHasher::new(None);
        let auth_hash = [0x42u8; 32];
        let mut wrong_hash = auth_hash;
        wrong_hash[0] ^= 0x01;

        let (salt, encoded) = hasher.hash_master_auth_hash(&auth_hash).expect("hash");
        assert_eq!(salt.len(), SERVER_AUTH_SALT_LEN);
        assert!(
            hasher
                .verify_master_auth_hash(&auth_hash, &salt, &encoded)
                .expect("verify")
        );
        assert!(
            !hasher
                .verify_master_auth_hash(&wrong_hash, &salt, &encoded)
                .expect("verify")
        );
        assert!(
            !wrong_pepper_hasher
                .verify_master_auth_hash(&auth_hash, &salt, &encoded)
                .expect("verify")
        );
    }
}
