//! Runtime configuration loaded from `ANVIL_*` environment variables.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors returned when required configuration is missing or malformed.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable `{0}`")]
    Missing(&'static str),
    #[error("invalid value for environment variable `{name}`: {reason}")]
    Invalid { name: &'static str, reason: String },
}

/// Output log formatting mode controlled by `ANVIL_LOG_FORMAT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    #[default]
    Pretty,
    Json,
}

impl LogFormat {
    pub fn from_env() -> Result<Self, ConfigError> {
        match optional_trimmed("ANVIL_LOG_FORMAT").as_deref() {
            None | Some("pretty") => Ok(Self::Pretty),
            Some("json") => Ok(Self::Json),
            Some(other) => Err(ConfigError::Invalid {
                name: "ANVIL_LOG_FORMAT",
                reason: format!("expected `pretty` or `json`, got `{other}`"),
            }),
        }
    }
}

/// Minimal configuration needed by administrative database CLI commands.
#[derive(Clone)]
pub struct DatabaseConfig {
    pub database_url: String,
    pub log_format: LogFormat,
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("database_url", &"[REDACTED]")
            .field("log_format", &self.log_format)
            .finish()
    }
}

impl DatabaseConfig {
    /// Loads `ANVIL_DATABASE_URL` and `ANVIL_LOG_FORMAT` from the environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            database_url: required_non_empty("ANVIL_DATABASE_URL")?,
            log_format: LogFormat::from_env()?,
        })
    }
}

/// Full configuration required to run the HTTP server (`anvil-server serve`).
#[derive(Clone)]
pub struct ServerConfig {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub allow_signups: bool,
    pub jwt_private_key: Zeroizing<String>,
    pub auth_pepper: Option<Zeroizing<Vec<u8>>>,
    pub prelogin_secret: Zeroizing<Vec<u8>>,
    pub trusted_proxies: Vec<IpNet>,
    pub cors_origins: Vec<String>,
    pub enable_favicon_proxy: bool,
    pub public_url: Option<String>,
    pub log_format: LogFormat,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("database_url", &"[REDACTED]")
            .field("bind_addr", &self.bind_addr)
            .field("allow_signups", &self.allow_signups)
            .field("jwt_private_key", &"[REDACTED]")
            .field(
                "auth_pepper",
                &self.auth_pepper.as_ref().map(|_| "[REDACTED]"),
            )
            .field("prelogin_secret", &"[REDACTED]")
            .field("trusted_proxies", &self.trusted_proxies)
            .field("cors_origins", &self.cors_origins)
            .field("enable_favicon_proxy", &self.enable_favicon_proxy)
            .field("public_url", &self.public_url)
            .field("log_format", &self.log_format)
            .finish()
    }
}

impl ServerConfig {
    /// Loads and validates all `ANVIL_*` settings from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = required_non_empty("ANVIL_DATABASE_URL")?;
        let bind_addr = match optional_trimmed("ANVIL_BIND_ADDR") {
            Some(raw) => raw
                .parse::<SocketAddr>()
                .map_err(|e| ConfigError::Invalid {
                    name: "ANVIL_BIND_ADDR",
                    reason: e.to_string(),
                })?,
            None => SocketAddr::from(([0, 0, 0, 0], 8080)),
        };

        let allow_signups = parse_bool_env("ANVIL_ALLOW_SIGNUPS", false)?;
        let jwt_private_key = Zeroizing::new(required_non_empty("ANVIL_JWT_PRIVATE_KEY")?);

        let auth_pepper = match optional_trimmed("ANVIL_AUTH_PEPPER") {
            Some(raw) => {
                let bytes = parse_secret_bytes("ANVIL_AUTH_PEPPER", &raw)?;
                if bytes.is_empty() { None } else { Some(bytes) }
            }
            None => None,
        };

        let raw_prelogin = required_non_empty("ANVIL_PRELOGIN_SECRET")?;
        let prelogin_secret = parse_secret_bytes("ANVIL_PRELOGIN_SECRET", &raw_prelogin)?;
        if prelogin_secret.len() < 32 {
            return Err(ConfigError::Invalid {
                name: "ANVIL_PRELOGIN_SECRET",
                reason: "must contain at least 32 bytes of key material".to_owned(),
            });
        }

        let trusted_proxies = parse_trusted_proxies(optional_trimmed("ANVIL_TRUSTED_PROXIES"))?;
        let cors_origins = parse_csv_list(optional_trimmed("ANVIL_CORS_ORIGINS"));
        let enable_favicon_proxy = parse_bool_env("ANVIL_ENABLE_FAVICON_PROXY", false)?;
        let public_url =
            optional_trimmed("ANVIL_PUBLIC_URL").map(|url| url.trim_end_matches('/').to_owned());
        let log_format = LogFormat::from_env()?;

        Ok(Self {
            database_url,
            bind_addr,
            allow_signups,
            jwt_private_key,
            auth_pepper,
            prelogin_secret,
            trusted_proxies,
            cors_origins,
            enable_favicon_proxy,
            public_url,
            log_format,
        })
    }
}

fn optional_trimmed(name: &'static str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn required_non_empty(name: &'static str) -> Result<String, ConfigError> {
    optional_trimmed(name).ok_or(ConfigError::Missing(name))
}

fn parse_bool_env(name: &'static str, default: bool) -> Result<bool, ConfigError> {
    match optional_trimmed(name) {
        None => Ok(default),
        Some(val) => match val.to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Ok(true),
            "false" | "0" | "no" | "off" => Ok(false),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("expected boolean, got `{val}`"),
            }),
        },
    }
}

fn parse_csv_list(raw: Option<String>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(ToOwned::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

/// Parses comma-separated CIDRs or single IPs into `IpNet` entries.
pub fn parse_trusted_proxies(raw: Option<String>) -> Result<Vec<IpNet>, ConfigError> {
    let items = parse_csv_list(raw);
    let mut out = Vec::with_capacity(items.len());
    for entry in items {
        let net = if let Ok(net) = entry.parse::<IpNet>() {
            net
        } else if let Ok(ip) = entry.parse::<IpAddr>() {
            IpNet::from(ip)
        } else {
            return Err(ConfigError::Invalid {
                name: "ANVIL_TRUSTED_PROXIES",
                reason: format!("invalid IP or CIDR entry `{entry}`"),
            });
        };
        out.push(net);
    }
    Ok(out)
}

/// Parses raw secret strings as well as explicit `b64:`, `base64:`, or `hex:` prefixed values.
pub fn parse_secret_bytes(
    name: &'static str,
    raw: &str,
) -> Result<Zeroizing<Vec<u8>>, ConfigError> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    if let Some(rest) = raw
        .strip_prefix("b64:")
        .or_else(|| raw.strip_prefix("base64:"))
    {
        let decoded = STANDARD
            .decode(rest)
            .or_else(|_| URL_SAFE_NO_PAD.decode(rest))
            .map_err(|e| ConfigError::Invalid {
                name,
                reason: format!("invalid base64 secret: {e}"),
            })?;
        return Ok(Zeroizing::new(decoded));
    }

    if let Some(rest) = raw.strip_prefix("hex:") {
        let decoded = decode_hex(rest).map_err(|reason| ConfigError::Invalid { name, reason })?;
        return Ok(Zeroizing::new(decoded));
    }

    Ok(Zeroizing::new(raw.as_bytes().to_vec()))
}

fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let trimmed = hex.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err("hex secret must have an even number of characters".to_owned());
    }
    let bytes = trimmed.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let (pairs, _) = bytes.as_chunks::<2>();
    for pair in pairs {
        let s = std::str::from_utf8(pair).map_err(|_| "invalid UTF-8 in hex secret".to_owned())?;
        let val = u8::from_str_radix(s, 16).map_err(|_| format!("invalid hex byte `{s}`"))?;
        out.push(val);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_trusted_proxies_cidr_and_single_ip() {
        let nets =
            parse_trusted_proxies(Some("127.0.0.1, 172.16.0.0/12, ::1, fd00::/8".to_owned()))
                .expect("valid proxy entries");
        assert_eq!(nets.len(), 4);
        assert_eq!(nets[0].to_string(), "127.0.0.1/32");
        assert_eq!(nets[1].to_string(), "172.16.0.0/12");
        assert_eq!(nets[2].to_string(), "::1/128");
        assert_eq!(nets[3].to_string(), "fd00::/8");
    }

    #[test]
    fn parses_secret_bytes_with_prefixes() {
        let raw =
            parse_secret_bytes("TEST", "super-secret-value-at-least-32-bytes").expect("raw bytes");
        assert!(raw.len() >= 32);

        let b64 = parse_secret_bytes("TEST", "b64:AQIDBA==").expect("base64 secret");
        assert_eq!(&*b64, &[1, 2, 3, 4]);

        let hex = parse_secret_bytes("TEST", "hex:deadbeef").expect("hex secret");
        assert_eq!(&*hex, &[0xde, 0xad, 0xbe, 0xef]);
    }
}
