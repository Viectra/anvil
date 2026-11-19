//! RFC 6238 / RFC 4226 TOTP code generator and `otpauth://` URI parser.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::AnvilError;

/// Default TOTP time step in seconds.
pub const DEFAULT_TOTP_PERIOD: u64 = 30;
/// Default number of TOTP digits.
pub const DEFAULT_TOTP_DIGITS: u32 = 6;

/// HMAC hash algorithm used by TOTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

impl TotpAlgorithm {
    /// Returns the canonical uppercase algorithm name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    fn from_str_insensitive(value: &str) -> Result<Self, AnvilError> {
        match value.trim().to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "SHA-256" => Ok(Self::Sha256),
            "SHA512" | "SHA-512" => Ok(Self::Sha512),
            other => Err(AnvilError::InvalidTotpUri(format!(
                "unsupported TOTP algorithm: {other}"
            ))),
        }
    }
}

/// Generated TOTP code along with its remaining validity window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpCode {
    pub code: String,
    pub remaining_seconds: u64,
    pub period_seconds: u64,
}

/// TOTP authenticator configuration stored inside a login entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct TotpConfig {
    pub secret_base32: String,
    #[zeroize(skip)]
    pub algorithm: TotpAlgorithm,
    #[zeroize(skip)]
    pub digits: u32,
    #[zeroize(skip)]
    pub period_seconds: u64,
    pub issuer: Option<String>,
    pub label: Option<String>,
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TotpConfig")
            .field("secret_base32", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period_seconds", &self.period_seconds)
            .field("issuer", &self.issuer)
            .field("label", &self.label)
            .finish()
    }
}

impl TotpConfig {
    /// Parses either a raw Base32 secret or an `otpauth://totp/...` URI.
    pub fn from_input(input: &str) -> Result<Self, AnvilError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(AnvilError::InvalidBase32);
        }
        const OTPAUTH_PREFIX: &str = "otpauth://";
        if trimmed
            .get(..OTPAUTH_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(OTPAUTH_PREFIX))
        {
            Self::from_otpauth_uri(trimmed)
        } else {
            let normalized = normalize_base32_secret(trimmed)?;
            Ok(Self {
                secret_base32: normalized,
                algorithm: TotpAlgorithm::Sha1,
                digits: DEFAULT_TOTP_DIGITS,
                period_seconds: DEFAULT_TOTP_PERIOD,
                issuer: None,
                label: None,
            })
        }
    }

    /// Parses an `otpauth://totp/...` URI and validates all parameters.
    pub fn from_otpauth_uri(uri: &str) -> Result<Self, AnvilError> {
        let parsed = Url::parse(uri.trim())
            .map_err(|e| AnvilError::InvalidTotpUri(format!("malformed URI: {e}")))?;

        if !parsed.scheme().eq_ignore_ascii_case("otpauth") {
            return Err(AnvilError::InvalidTotpUri(
                "scheme must be otpauth".to_owned(),
            ));
        }

        let host = parsed.host_str().unwrap_or_default();
        if !host.eq_ignore_ascii_case("totp") {
            return Err(AnvilError::InvalidTotpUri(format!(
                "unsupported OTP type '{host}', expected 'totp'"
            )));
        }

        let raw_path = parsed.path().trim_start_matches('/');
        let decoded_path = percent_decode(raw_path);
        let (path_issuer, label) = if decoded_path.is_empty() {
            (None, None)
        } else if let Some((iss, acct)) = decoded_path.split_once(':') {
            let clean_iss = iss.trim();
            let clean_acct = acct.trim();
            (
                (!clean_iss.is_empty()).then(|| clean_iss.to_owned()),
                (!clean_acct.is_empty()).then(|| clean_acct.to_owned()),
            )
        } else {
            (None, Some(decoded_path))
        };

        let mut secret_raw: Option<String> = None;
        let mut algorithm = TotpAlgorithm::Sha1;
        let mut digits = DEFAULT_TOTP_DIGITS;
        let mut period_seconds = DEFAULT_TOTP_PERIOD;
        let mut query_issuer: Option<String> = None;

        for (key, value) in parsed.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret_raw = Some(value.into_owned()),
                "algorithm" => algorithm = TotpAlgorithm::from_str_insensitive(&value)?,
                "digits" => {
                    let parsed_digits = value
                        .parse::<u32>()
                        .map_err(|_| AnvilError::InvalidTotpUri("invalid digits".to_owned()))?;
                    if !(6..=8).contains(&parsed_digits) {
                        return Err(AnvilError::InvalidTotpUri(
                            "digits must be 6, 7, or 8".to_owned(),
                        ));
                    }
                    digits = parsed_digits;
                }
                "period" => {
                    let parsed_period = value
                        .parse::<u64>()
                        .map_err(|_| AnvilError::InvalidTotpUri("invalid period".to_owned()))?;
                    if !(1..=300).contains(&parsed_period) {
                        return Err(AnvilError::InvalidTotpUri(
                            "period must be between 1 and 300 seconds".to_owned(),
                        ));
                    }
                    period_seconds = parsed_period;
                }
                "issuer" => {
                    let clean = value.trim().to_owned();
                    if !clean.is_empty() {
                        query_issuer = Some(clean);
                    }
                }
                _ => {}
            }
        }

        let secret_input = secret_raw
            .ok_or_else(|| AnvilError::InvalidTotpUri("missing secret parameter".to_owned()))?;
        let secret_base32 = normalize_base32_secret(&secret_input)?;

        Ok(Self {
            secret_base32,
            algorithm,
            digits,
            period_seconds,
            issuer: query_issuer.or(path_issuer),
            label,
        })
    }

    /// Generates the TOTP code for the given Unix timestamp (in seconds).
    pub fn generate_at(&self, unix_timestamp: u64) -> Result<TotpCode, AnvilError> {
        if self.period_seconds == 0 {
            return Err(AnvilError::InvalidTotpUri(
                "period_seconds must be non-zero".to_owned(),
            ));
        }
        if !(6..=8).contains(&self.digits) {
            return Err(AnvilError::InvalidTotpUri(
                "digits must be 6, 7, or 8".to_owned(),
            ));
        }

        let secret_bytes = decode_base32_secret(&self.secret_base32)?;
        let counter = unix_timestamp / self.period_seconds;
        let counter_bytes = counter.to_be_bytes();

        let digest: Zeroizing<Vec<u8>> = match self.algorithm {
            TotpAlgorithm::Sha1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(&secret_bytes)
                    .map_err(|_| AnvilError::InvalidBase32)?;
                mac.update(&counter_bytes);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }
            TotpAlgorithm::Sha256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&secret_bytes)
                    .map_err(|_| AnvilError::InvalidBase32)?;
                mac.update(&counter_bytes);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }
            TotpAlgorithm::Sha512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(&secret_bytes)
                    .map_err(|_| AnvilError::InvalidBase32)?;
                mac.update(&counter_bytes);
                Zeroizing::new(mac.finalize().into_bytes().to_vec())
            }
        };

        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let truncated = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        let modulus = 10u32.pow(self.digits);
        let code = format!(
            "{:0width$}",
            truncated % modulus,
            width = self.digits as usize
        );
        let remaining_seconds = self.period_seconds - (unix_timestamp % self.period_seconds);

        Ok(TotpCode {
            code,
            remaining_seconds,
            period_seconds: self.period_seconds,
        })
    }

    /// Formats this configuration into a standard `otpauth://totp/...` URI.
    pub fn to_otpauth_uri(&self, fallback_label: &str) -> String {
        let account = self
            .label
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(fallback_label);
        let path_label = match self.issuer.as_deref().filter(|s| !s.is_empty()) {
            Some(iss) => format!("{iss}:{account}"),
            None => account.to_owned(),
        };

        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("secret", &self.secret_base32);
        if let Some(iss) = self.issuer.as_deref().filter(|s| !s.is_empty()) {
            query.append_pair("issuer", iss);
        }
        query.append_pair("algorithm", self.algorithm.as_str());
        query.append_pair("digits", &self.digits.to_string());
        query.append_pair("period", &self.period_seconds.to_string());

        format!(
            "otpauth://totp/{}?{}",
            percent_encode_segment(&path_label),
            query.finish()
        )
    }
}

fn percent_encode_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' | b'@'
        ) {
            out.push(char::from(b));
        } else {
            out.push('%');
            let hi = (b >> 4) & 0x0f;
            let lo = b & 0x0f;
            out.push(char::from(if hi < 10 {
                b'0' + hi
            } else {
                b'A' + (hi - 10)
            }));
            out.push(char::from(if lo < 10 {
                b'0' + lo
            } else {
                b'A' + (lo - 10)
            }));
        }
    }
    out
}

/// Normalizes a Base32 string by removing whitespace, hyphens, padding, and uppercasing.
pub fn normalize_base32_secret(raw: &str) -> Result<String, AnvilError> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(AnvilError::InvalidBase32);
    }
    let _decoded = decode_base32_secret(&cleaned)?;
    Ok(cleaned)
}

fn decode_base32_secret(normalized_unpadded: &str) -> Result<Zeroizing<Vec<u8>>, AnvilError> {
    let bytes = BASE32_NOPAD
        .decode(normalized_unpadded.as_bytes())
        .map_err(|_| AnvilError::InvalidBase32)?;
    if bytes.is_empty() {
        return Err(AnvilError::InvalidBase32);
    }
    Ok(Zeroizing::new(bytes))
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_appendix_b_vectors_sha1_sha256_sha512() {
        let secret_sha1 = BASE32_NOPAD.encode(b"12345678901234567890");
        let secret_sha256 = BASE32_NOPAD.encode(b"12345678901234567890123456789012");
        let secret_sha512 = BASE32_NOPAD
            .encode(b"1234567890123456789012345678901234567890123456789012345678901234");

        let vectors: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];

        for &(ts, exp_sha1, exp_sha256, exp_sha512) in vectors {
            let cfg_sha1 = TotpConfig {
                secret_base32: secret_sha1.clone(),
                algorithm: TotpAlgorithm::Sha1,
                digits: 8,
                period_seconds: 30,
                issuer: None,
                label: None,
            };
            assert_eq!(
                cfg_sha1.generate_at(ts).expect("sha1 totp").code,
                exp_sha1,
                "SHA1 mismatch at ts={ts}"
            );

            let cfg_sha256 = TotpConfig {
                secret_base32: secret_sha256.clone(),
                algorithm: TotpAlgorithm::Sha256,
                digits: 8,
                period_seconds: 30,
                issuer: None,
                label: None,
            };
            assert_eq!(
                cfg_sha256.generate_at(ts).expect("sha256 totp").code,
                exp_sha256,
                "SHA256 mismatch at ts={ts}"
            );

            let cfg_sha512 = TotpConfig {
                secret_base32: secret_sha512.clone(),
                algorithm: TotpAlgorithm::Sha512,
                digits: 8,
                period_seconds: 30,
                issuer: None,
                label: None,
            };
            assert_eq!(
                cfg_sha512.generate_at(ts).expect("sha512 totp").code,
                exp_sha512,
                "SHA512 mismatch at ts={ts}"
            );
        }
    }

    #[test]
    fn parses_raw_base32_and_otpauth_uri_and_roundtrips() {
        let raw = TotpConfig::from_input("jbsw y3dp-ehpk 3pxp==").expect("valid raw base32");
        assert_eq!(raw.secret_base32, "JBSWY3DPEHPK3PXP");
        assert_eq!(raw.digits, 6);
        assert_eq!(raw.period_seconds, 30);

        let uri = "otpauth://totp/GitHub:dev%40corp.io?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=6&period=30";
        let cfg = TotpConfig::from_input(uri).expect("valid otpauth uri");
        assert_eq!(cfg.issuer.as_deref(), Some("GitHub"));
        assert_eq!(cfg.label.as_deref(), Some("dev@corp.io"));
        assert_eq!(cfg.algorithm, TotpAlgorithm::Sha256);
        assert!(!format!("{cfg:?}").contains("JBSWY3DPEHPK3PXP"));

        let rebuilt = cfg.to_otpauth_uri("fallback");
        let reparsed = TotpConfig::from_input(&rebuilt).expect("roundtrip uri");
        assert_eq!(reparsed.secret_base32, cfg.secret_base32);
        assert_eq!(reparsed.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(reparsed.issuer, cfg.issuer);
        assert_eq!(reparsed.label, cfg.label);

        assert!(TotpConfig::from_input("otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP").is_err());
        assert!(TotpConfig::from_input("not-valid-base32!@#").is_err());
    }
}
