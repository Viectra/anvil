//! Ed25519 (EdDSA) JWT issuance and verification for short-lived access tokens.

use anvil_core::crypto::fill_random_bytes;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, KeypairBytes};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::db::UserRole;

/// Access token lifetime in minutes (`15 min`).
pub const ACCESS_TOKEN_TTL_MINUTES: i64 = 15;
/// Refresh token lifetime in days (`30 days`).
pub const REFRESH_TOKEN_TTL_DAYS: i64 = 30;
const JWT_ISSUER: &str = "anvil";

/// Claims carried inside every EdDSA access token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessTokenClaims {
    pub sub: Uuid,
    pub role: UserRole,
    pub sid: Uuid,
    pub jti: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub iss: String,
}

/// Ed25519 JWT signing and verification key pair.
pub struct JwtManager {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtManager {
    /// Parses a PKCS#8 Ed25519 private key supplied as PEM (with literal or `\n`-escaped newlines) or Base64 DER.
    pub fn from_private_key_str(raw: &str) -> Result<Self, anyhow::Error> {
        let normalized = raw.trim().replace("\\n", "\n");
        let signing_key = if normalized.contains("-----BEGIN") {
            SigningKey::from_pkcs8_pem(&normalized)
                .map_err(|e| anyhow::anyhow!("invalid Ed25519 PKCS#8 PEM private key: {e}"))?
        } else {
            let der = Zeroizing::new(
                STANDARD
                    .decode(normalized.trim())
                    .map_err(|e| anyhow::anyhow!("invalid Base64 Ed25519 private key: {e}"))?,
            );
            SigningKey::from_pkcs8_der(&der)
                .map_err(|e| anyhow::anyhow!("invalid Ed25519 PKCS#8 DER private key: {e}"))?
        };

        Self::from_signing_key(&signing_key)
    }

    fn from_signing_key(signing_key: &SigningKey) -> Result<Self, anyhow::Error> {
        let verifying_key = signing_key.verifying_key();
        // Build PKCS#8 v2 DER with embedded public key so `ring` accepts both v1 and v2 inputs uniformly.
        let keypair = KeypairBytes {
            secret_key: signing_key.to_bytes(),
            public_key: Some(ed25519_dalek::pkcs8::PublicKeyBytes(
                verifying_key.to_bytes(),
            )),
        };
        let pkcs8_der = keypair
            .to_pkcs8_der()
            .map_err(|e| anyhow::anyhow!("failed to encode Ed25519 PKCS#8 DER: {e}"))?;

        let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());
        let decoding_key = DecodingKey::from_ed_der(verifying_key.as_bytes());

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[JWT_ISSUER]);
        validation.set_required_spec_claims(&["exp", "sub", "iss"]);
        validation.leeway = 5;

        Ok(Self {
            encoding_key,
            decoding_key,
            validation,
        })
    }

    /// Generates a fresh PKCS#8 v2 PEM Ed25519 private key for instance setup.
    pub fn generate_private_key_pem() -> Result<Zeroizing<String>, anyhow::Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random_bytes(&mut *seed).map_err(|e| anyhow::anyhow!("csprng error: {e}"))?;
        let signing_key = SigningKey::from_bytes(&seed);
        let keypair = KeypairBytes {
            secret_key: signing_key.to_bytes(),
            public_key: Some(ed25519_dalek::pkcs8::PublicKeyBytes(
                signing_key.verifying_key().to_bytes(),
            )),
        };
        let pem = keypair
            .to_pkcs8_pem(LineEnding::LF)
            .map_err(|e| anyhow::anyhow!("failed to format Ed25519 PEM: {e}"))?;
        Ok(Zeroizing::new(pem.to_string()))
    }

    /// Issues a signed 15-minute EdDSA JWT access token bound to `(user_id, role, session_id)`.
    pub fn issue_access_token(
        &self,
        user_id: Uuid,
        role: UserRole,
        session_id: Uuid,
    ) -> Result<(String, i64), anyhow::Error> {
        let now = Utc::now();
        let exp = now + Duration::minutes(ACCESS_TOKEN_TTL_MINUTES);
        let claims = AccessTokenClaims {
            sub: user_id,
            role,
            sid: session_id,
            jti: Uuid::new_v4(),
            iat: now.timestamp(),
            exp: exp.timestamp(),
            iss: JWT_ISSUER.to_owned(),
        };
        let header = Header::new(Algorithm::EdDSA);
        let token = encode(&header, &claims, &self.encoding_key)?;
        Ok((token, ACCESS_TOKEN_TTL_MINUTES * 60))
    }

    /// Verifies signature, algorithm (`EdDSA`), issuer, and expiration on an access token.
    pub fn verify_access_token(&self, token: &str) -> Result<AccessTokenClaims, anyhow::Error> {
        let data = decode::<AccessTokenClaims>(token, &self.decoding_key, &self.validation)?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_jwt_pem_and_base64_der_roundtrips() {
        let pem = JwtManager::generate_private_key_pem().expect("generate key");
        let escaped_pem = pem.replace('\n', "\\n");

        let jwt_from_pem = JwtManager::from_private_key_str(&pem).expect("load pem");
        let jwt_from_escaped =
            JwtManager::from_private_key_str(&escaped_pem).expect("load escaped");

        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let (token, ttl) = jwt_from_pem
            .issue_access_token(user_id, UserRole::Admin, session_id)
            .expect("issue token");
        assert_eq!(ttl, 900);

        let claims = jwt_from_escaped
            .verify_access_token(&token)
            .expect("verify token");
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.role, UserRole::Admin);
        assert_eq!(claims.sid, session_id);
        assert_eq!(claims.iss, "anvil");
    }

    #[test]
    fn rejects_wrong_key_tampered_payload_and_expired_tokens() {
        let key_a = JwtManager::generate_private_key_pem().expect("key a");
        let key_b = JwtManager::generate_private_key_pem().expect("key b");
        let mgr_a = JwtManager::from_private_key_str(&key_a).expect("mgr a");
        let mgr_b = JwtManager::from_private_key_str(&key_b).expect("mgr b");

        let (token, _) = mgr_a
            .issue_access_token(Uuid::new_v4(), UserRole::User, Uuid::new_v4())
            .expect("issue");
        assert!(mgr_b.verify_access_token(&token).is_err());

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let mut sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("valid base64url jwt signature");
        sig_bytes[0] ^= 0xff;
        let tampered = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes)
        );
        assert!(mgr_a.verify_access_token(&tampered).is_err());

        let expired_claims = AccessTokenClaims {
            sub: Uuid::new_v4(),
            role: UserRole::User,
            sid: Uuid::new_v4(),
            jti: Uuid::new_v4(),
            iat: 1_600_000_000,
            exp: 1_600_000_100,
            iss: JWT_ISSUER.to_owned(),
        };
        let expired_token = encode(
            &Header::new(Algorithm::EdDSA),
            &expired_claims,
            &mgr_a.encoding_key,
        )
        .expect("encode expired");
        assert!(mgr_a.verify_access_token(&expired_token).is_err());
    }
}
