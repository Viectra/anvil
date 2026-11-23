//! QR payload parsers supporting self-hosted onboarding (`anvil://setup`) and RFC 6238 TOTP (`otpauth://`).

use std::net::IpAddr;

use anvil_core::totp::TotpConfig;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::MobileError;

/// Self-hosted instance onboarding configuration decoded from an enrollment QR code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnvilOnboardingQr {
    pub server_url: String,
    pub email: Option<String>,
    pub invite_token: Option<String>,
}

impl AnvilOnboardingQr {
    /// Serializes this onboarding configuration into an `anvil://setup?...` deep-link URI.
    pub fn encode_uri(&self) -> Result<String, MobileError> {
        let valid_url = validate_mobile_server_url(&self.server_url)?;
        let mut out = Url::parse("anvil://setup")
            .map_err(|e| MobileError::InvalidQrPayload(e.to_string()))?;
        {
            let mut qp = out.query_pairs_mut();
            qp.append_pair("server", &valid_url);
            if let Some(email) = self.email.as_deref().filter(|s| !s.trim().is_empty()) {
                qp.append_pair("email", email.trim());
            }
            if let Some(invite) = self
                .invite_token
                .as_deref()
                .filter(|s| !s.trim().is_empty())
            {
                qp.append_pair("invite", invite.trim());
            }
        }
        Ok(out.to_string())
    }
}

/// Decoded QR code payload routed to onboarding or TOTP enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "payload", rename_all = "snake_case")]
pub enum QrScanResult {
    Onboarding(AnvilOnboardingQr),
    Totp(TotpConfig),
}

#[derive(Deserialize)]
struct JsonOnboardingPayload {
    server: Option<String>,
    server_url: Option<String>,
    email: Option<String>,
    invite: Option<String>,
    invite_token: Option<String>,
}

/// Validates a self-hosted server URL (`https://` or local loopback development hosts only).
pub fn validate_mobile_server_url(raw: &str) -> Result<String, MobileError> {
    let trimmed = raw.trim();
    let parsed = Url::parse(trimmed).map_err(|e| MobileError::InvalidInput(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| MobileError::InvalidInput("server URL missing host".to_owned()))?;

    let is_https = parsed.scheme() == "https";
    let is_loopback_http = parsed.scheme() == "http" && is_loopback_host(host);
    if !is_https && !is_loopback_http {
        return Err(MobileError::InsecureServerUrl(
            "remote self-hosted Anvil instances must use HTTPS".to_owned(),
        ));
    }

    let formatted = match parsed.port() {
        Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
        None => format!("{}://{host}", parsed.scheme()),
    };
    Ok(formatted)
}

fn is_loopback_host(host: &str) -> bool {
    let clean = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if clean == "localhost" {
        return true;
    }
    clean.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Parses an `anvil://setup?...` URI, JSON onboarding payload, `otpauth://totp/...`, or raw Base32 secret.
pub fn parse_qr_payload(raw: &str) -> Result<QrScanResult, MobileError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(MobileError::InvalidQrPayload(
            "empty QR code payload".to_owned(),
        ));
    }

    if trimmed
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("anvil://"))
    {
        return parse_onboarding_uri(trimmed).map(QrScanResult::Onboarding);
    }

    if trimmed.starts_with('{') {
        let json: JsonOnboardingPayload = serde_json::from_str(trimmed)
            .map_err(|e| MobileError::InvalidQrPayload(e.to_string()))?;
        let raw_server = json
            .server
            .or(json.server_url)
            .ok_or_else(|| MobileError::InvalidQrPayload("missing server URL".to_owned()))?;
        let server_url = validate_mobile_server_url(&raw_server)?;
        return Ok(QrScanResult::Onboarding(AnvilOnboardingQr {
            server_url,
            email: normalize_opt(json.email),
            invite_token: normalize_opt(json.invite.or(json.invite_token)),
        }));
    }

    let totp = TotpConfig::from_input(trimmed)
        .map_err(|e| MobileError::InvalidQrPayload(e.to_string()))?;
    Ok(QrScanResult::Totp(totp))
}

fn parse_onboarding_uri(raw: &str) -> Result<AnvilOnboardingQr, MobileError> {
    let parsed = Url::parse(raw).map_err(|e| MobileError::InvalidQrPayload(e.to_string()))?;
    if parsed.host_str() != Some("setup") {
        return Err(MobileError::InvalidQrPayload(
            "unsupported anvil:// host (expected anvil://setup)".to_owned(),
        ));
    }

    let mut server: Option<String> = None;
    let mut email: Option<String> = None;
    let mut invite: Option<String> = None;

    for (key, value) in parsed.query_pairs() {
        match key.as_ref() {
            "server" | "server_url" => server = Some(value.into_owned()),
            "email" => email = normalize_opt(Some(value.into_owned())),
            "invite" | "invite_token" => invite = normalize_opt(Some(value.into_owned())),
            _ => {}
        }
    }

    let raw_server = server.ok_or_else(|| {
        MobileError::InvalidQrPayload("onboarding QR missing 'server' query parameter".to_owned())
    })?;
    let server_url = validate_mobile_server_url(&raw_server)?;

    Ok(AnvilOnboardingQr {
        server_url,
        email,
        invite_token: invite,
    })
}

fn normalize_opt(input: Option<String>) -> Option<String> {
    input.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{AnvilOnboardingQr, QrScanResult, parse_qr_payload};

    #[test]
    fn parses_onboarding_uri_json_and_rejects_remote_http() -> Result<(), Box<dyn std::error::Error>>
    {
        let qr = AnvilOnboardingQr {
            server_url: "https://vault.example.internal:8443".to_owned(),
            email: Some("viktor@example.internal".to_owned()),
            invite_token: Some("inv-9988".to_owned()),
        };
        let uri = qr.encode_uri()?;
        match parse_qr_payload(&uri)? {
            QrScanResult::Onboarding(decoded) => assert_eq!(decoded, qr),
            QrScanResult::Totp(_) => return Err("expected onboarding result".into()),
        }

        let json = r#"{"v":1,"server":"https://vault.example.internal","email":"alice@anvil.io"}"#;
        match parse_qr_payload(json)? {
            QrScanResult::Onboarding(decoded) => {
                assert_eq!(decoded.server_url, "https://vault.example.internal");
                assert_eq!(decoded.email.as_deref(), Some("alice@anvil.io"));
            }
            QrScanResult::Totp(_) => return Err("expected JSON onboarding".into()),
        }

        assert!(parse_qr_payload("anvil://setup?server=http://evil.example.com").is_err());
        assert!(parse_qr_payload("anvil://setup?server=http://127.0.0.1:8080").is_ok());

        match parse_qr_payload(
            "otpauth://totp/GitHub:dev%40anvil.io?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )? {
            QrScanResult::Totp(cfg) => {
                assert_eq!(cfg.issuer.as_deref(), Some("GitHub"));
                assert_eq!(cfg.generate_at(59)?.code, "996554");
            }
            QrScanResult::Onboarding(_) => return Err("expected TOTP config".into()),
        }

        Ok(())
    }
}
