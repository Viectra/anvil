//! Anti-phishing context verification (`eTLD+1`, IDN homographs, cross-origin iframes, TLS).

use std::net::IpAddr;

use anvil_core::models::VaultItem;
use anvil_core::search::{extract_base_domain, extract_host, uri_matches};
use serde::{Deserialize, Serialize};
use url::Url;

/// Severity outcome of an autofill or page-matching security check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityRiskLevel {
    Safe,
    WarnHttp,
    BlockedInvalidUrl,
    BlockedCrossOriginIframe,
    BlockedIdnHomograph,
    BlockedDomainMismatch,
}

/// Security evaluation returned to extension content scripts and popup UI before any secret leaves RAM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillSecurityVerdict {
    pub allowed: bool,
    pub silent_autofill_allowed: bool,
    pub risk_level: SecurityRiskLevel,
    pub host: Option<String>,
    pub registrable_domain: Option<String>,
    pub origin: Option<String>,
    pub is_secure_context: bool,
    pub is_idn_punycode: bool,
    pub is_mixed_script: bool,
    pub reasons: Vec<String>,
}

/// Extracts the normalized registrable `eTLD+1` domain via the embedded Public Suffix List.
pub fn extract_registrable_domain(raw_url: &str) -> Option<String> {
    extract_base_domain(raw_url)
}

/// Normalizes an HTTP(S) origin string to `scheme://host` or `scheme://host:port`.
pub fn normalize_http_origin(raw_url: &str) -> Option<String> {
    let parsed = Url::parse(raw_url.trim()).ok()?;
    match parsed.scheme() {
        "https" | "http" => {}
        _ => return None,
    }
    let host = parsed.host_str()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    match parsed.port() {
        Some(port) => Some(format!("{}://{host}:{port}", parsed.scheme())),
        None => Some(format!("{}://{host}", parsed.scheme())),
    }
}

/// Returns `true` when host is a local loopback development target (`localhost`, `127.0.0.1`, `::1`).
pub fn is_loopback_host(host: &str) -> bool {
    let normalized = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if normalized == "localhost" {
        return true;
    }
    normalized
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharScript {
    Latin,
    Cyrillic,
    Greek,
    Armenian,
    Hebrew,
    Arabic,
    OtherAlphabetic,
}

fn classify_alphabetic_script(ch: char) -> Option<CharScript> {
    if !ch.is_alphabetic() {
        return None;
    }
    let cp = ch as u32;
    let script = match cp {
        0x0041..=0x024F | 0x1E00..=0x1EFF => CharScript::Latin,
        0x0400..=0x052F => CharScript::Cyrillic,
        0x0370..=0x03FF | 0x1F00..=0x1FFF => CharScript::Greek,
        0x0530..=0x058F => CharScript::Armenian,
        0x0590..=0x05FF => CharScript::Hebrew,
        0x0600..=0x06FF => CharScript::Arabic,
        _ => CharScript::OtherAlphabetic,
    };
    Some(script)
}

fn extract_raw_host_slice(raw_url: &str) -> Option<&str> {
    let trimmed = raw_url.trim();
    let after_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let host_port = authority
        .rsplit_once('@')
        .map(|(_, hp)| hp)
        .unwrap_or(authority);
    if host_port.starts_with('[') {
        let end = host_port.find(']')?;
        Some(&host_port[1..end])
    } else {
        Some(host_port.split(':').next().unwrap_or(host_port))
    }
}

/// Detects Punycode (`xn--`) and mixed-script IDN homograph spoofs in a URL host.
pub fn analyze_idn_host(raw_url: &str) -> (bool, bool) {
    let raw_mixed = extract_raw_host_slice(raw_url).is_some_and(|raw_host| {
        raw_host.split('.').any(|label| {
            let mut has_latin = false;
            let mut has_non_latin = false;
            for ch in label.chars() {
                match classify_alphabetic_script(ch) {
                    Some(CharScript::Latin) => has_latin = true,
                    Some(_) => has_non_latin = true,
                    None => {}
                }
            }
            has_latin && has_non_latin
        })
    });

    let has_punycode = Url::parse(raw_url.trim())
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|host| host.split('.').any(|label| label.starts_with("xn--")));

    (has_punycode, raw_mixed)
}

/// Evaluates frame origin, TLS context, cross-origin iframe rules, and IDN homograph safety.
pub fn evaluate_autofill_context(
    top_frame_url: &str,
    active_frame_url: &str,
    is_iframe: bool,
    approved_iframe_origins: &[String],
) -> AutofillSecurityVerdict {
    let mut reasons = Vec::new();

    let Some(active_origin) = normalize_http_origin(active_frame_url) else {
        reasons.push("scheme non HTTP(S) ou URL cible invalide".to_owned());
        return AutofillSecurityVerdict {
            allowed: false,
            silent_autofill_allowed: false,
            risk_level: SecurityRiskLevel::BlockedInvalidUrl,
            host: None,
            registrable_domain: None,
            origin: None,
            is_secure_context: false,
            is_idn_punycode: false,
            is_mixed_script: false,
            reasons,
        };
    };

    let active_host = extract_host(active_frame_url);
    let registrable_domain = extract_registrable_domain(active_frame_url);
    let (is_idn_punycode, is_mixed_script) = analyze_idn_host(active_frame_url);
    let (top_punycode, top_mixed) = analyze_idn_host(top_frame_url);

    let parsed_active = Url::parse(active_frame_url.trim()).ok();
    let is_https = parsed_active
        .as_ref()
        .is_some_and(|u| u.scheme() == "https");
    let is_local = active_host.as_deref().is_some_and(is_loopback_host);
    let is_secure_context = is_https || is_local;

    if is_mixed_script || top_mixed {
        reasons.push(
            "nom de domaine homographe multi-scripts détecté (tentative probable d'usurpation IDN)"
                .to_owned(),
        );
        return AutofillSecurityVerdict {
            allowed: false,
            silent_autofill_allowed: false,
            risk_level: SecurityRiskLevel::BlockedIdnHomograph,
            host: active_host,
            registrable_domain,
            origin: Some(active_origin),
            is_secure_context,
            is_idn_punycode: is_idn_punycode || top_punycode,
            is_mixed_script: true,
            reasons,
        };
    }

    if is_iframe {
        let Some(top_origin) = normalize_http_origin(top_frame_url) else {
            reasons.push("iframe intégrée dans un document parent non HTTP(S)".to_owned());
            return AutofillSecurityVerdict {
                allowed: false,
                silent_autofill_allowed: false,
                risk_level: SecurityRiskLevel::BlockedCrossOriginIframe,
                host: active_host,
                registrable_domain,
                origin: Some(active_origin),
                is_secure_context,
                is_idn_punycode,
                is_mixed_script,
                reasons,
            };
        };

        if top_origin != active_origin {
            let explicitly_approved = approved_iframe_origins
                .iter()
                .filter_map(|origin| normalize_http_origin(origin))
                .any(|allowed_origin| allowed_origin == active_origin);

            if !explicitly_approved {
                reasons.push(format!(
                    "remplissage bloqué dans une iframe cross-origin ({active_origin} != {top_origin})"
                ));
                return AutofillSecurityVerdict {
                    allowed: false,
                    silent_autofill_allowed: false,
                    risk_level: SecurityRiskLevel::BlockedCrossOriginIframe,
                    host: active_host,
                    registrable_domain,
                    origin: Some(active_origin),
                    is_secure_context,
                    is_idn_punycode,
                    is_mixed_script,
                    reasons,
                };
            }
        }
    }

    let mut risk_level = SecurityRiskLevel::Safe;
    let mut silent_autofill_allowed = true;

    if !is_secure_context {
        risk_level = SecurityRiskLevel::WarnHttp;
        silent_autofill_allowed = false;
        reasons.push(
            "connexion HTTP non chiffrée : vérifiez le site avant de saisir un mot de passe"
                .to_owned(),
        );
    }

    if is_idn_punycode {
        silent_autofill_allowed = false;
        reasons.push(
            "domaine internationalisé Punycode (xn--) : validation manuelle requise".to_owned(),
        );
    }

    AutofillSecurityVerdict {
        allowed: true,
        silent_autofill_allowed,
        risk_level,
        host: active_host,
        registrable_domain,
        origin: Some(active_origin),
        is_secure_context,
        is_idn_punycode,
        is_mixed_script: false,
        reasons,
    }
}

/// Validates both page security context and strict `eTLD+1` URI ownership for a specific vault item.
pub fn verify_item_autofill(
    item: &VaultItem,
    top_frame_url: &str,
    active_frame_url: &str,
    is_iframe: bool,
    approved_iframe_origins: &[String],
) -> AutofillSecurityVerdict {
    let mut verdict = evaluate_autofill_context(
        top_frame_url,
        active_frame_url,
        is_iframe,
        approved_iframe_origins,
    );
    if !verdict.allowed {
        return verdict;
    }

    if item.trashed_at.is_some() {
        verdict.allowed = false;
        verdict.silent_autofill_allowed = false;
        verdict.risk_level = SecurityRiskLevel::BlockedDomainMismatch;
        verdict
            .reasons
            .push("la fiche est dans la corbeille".to_owned());
        return verdict;
    }

    let uris = item
        .login
        .as_ref()
        .map(|l| l.uris.as_slice())
        .unwrap_or(&[]);

    let matched = uris.iter().any(|u| uri_matches(u, active_frame_url));
    if !matched {
        verdict.allowed = false;
        verdict.silent_autofill_allowed = false;
        verdict.risk_level = SecurityRiskLevel::BlockedDomainMismatch;
        verdict.reasons.push(
            "aucune URI autorisée de cette fiche ne correspond au domaine courant".to_owned(),
        );
        return verdict;
    }

    if verdict.is_idn_punycode {
        let host_matches_punycode = verdict.host.as_deref().is_some_and(|active_host| {
            uris.iter().any(|u| {
                extract_host(&u.uri).is_some_and(|stored_host| {
                    stored_host == active_host && uri_matches(u, active_frame_url)
                })
            })
        });
        if !host_matches_punycode {
            verdict.allowed = false;
            verdict.silent_autofill_allowed = false;
            verdict.risk_level = SecurityRiskLevel::BlockedIdnHomograph;
            verdict
                .reasons
                .push("hôte Punycode différent des URIs enregistrées".to_owned());
            return verdict;
        }
    }

    verdict
}
