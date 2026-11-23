//! Android AutofillService and iOS AutoFill Credential Provider matching and credential resolution.

use anvil_client_core::lock_manager::VaultItemSummary;
use anvil_client_core::sync_engine::ClientSyncEngine;
use anvil_core::media::fallback_initials;
use anvil_core::models::VaultItem;
use anvil_core::search::{extract_host, find_matching_items};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::error::MobileError;

/// Native mobile platform invoking OS autofill queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobilePlatform {
    Android,
    Ios,
}

/// Verified caller context extracted from Android `AssistStructure` or iOS `ASCredentialServiceIdentifier`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillCallerContext {
    pub platform: MobilePlatform,
    pub web_domain: Option<String>,
    pub android_package_name: Option<String>,
    pub ios_associated_domains: Vec<String>,
}

/// Non-secret autofill suggestion surfaced in the OS keyboard/sheet picker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillCandidate {
    pub item_id: String,
    pub title: String,
    pub subtitle: String,
    pub has_totp: bool,
    pub fallback_color: String,
    pub fallback_initials: String,
}

/// Decrypted credentials returned only after explicit user selection and strict URI verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillFillPayload {
    pub item_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
}

/// Matches unlocked vault entries against verified Android app packages and Web/iOS associated domains.
pub struct MobileAutofillEngine;

impl MobileAutofillEngine {
    pub fn query_candidates(
        engine: &ClientSyncEngine,
        ctx: &AutofillCallerContext,
    ) -> Result<Vec<AutofillCandidate>, MobileError> {
        let snapshot = engine.lock.snapshot()?;
        let web_urls = collect_web_targets(ctx)?;
        let android_pkg = normalize_android_package(ctx.android_package_name.as_deref())?;

        if web_urls.is_empty() && android_pkg.is_none() {
            return Ok(Vec::new());
        }

        let mut ordered_ids: Vec<Uuid> = Vec::new();
        for url in &web_urls {
            for id in find_matching_items(&snapshot.items, url) {
                if !ordered_ids.contains(&id) {
                    ordered_ids.push(id);
                }
            }
        }

        if let Some(pkg) = android_pkg.as_deref() {
            for item in &snapshot.items {
                if item.trashed_at.is_none()
                    && item_matches_android_package(item, pkg)
                    && !ordered_ids.contains(&item.id)
                {
                    ordered_ids.push(item.id);
                }
            }
        }

        let mut candidates = Vec::new();
        for id in ordered_ids {
            if let Some(item) = snapshot.items.iter().find(|entry| entry.id == id) {
                let summary: VaultItemSummary =
                    anvil_client_core::lock_manager::summarize_item(item);
                candidates.push(AutofillCandidate {
                    item_id: summary.id.to_string(),
                    title: summary.title.clone(),
                    subtitle: summary.subtitle,
                    has_totp: summary.has_totp,
                    fallback_color: summary.fallback_color,
                    fallback_initials: fallback_initials(&summary.title),
                });
            }
        }
        Ok(candidates)
    }

    pub fn resolve_fill_payload(
        engine: &ClientSyncEngine,
        item_id: &str,
        ctx: &AutofillCallerContext,
        unix_timestamp_seconds: u64,
    ) -> Result<AutofillFillPayload, MobileError> {
        let id = Uuid::parse_str(item_id.trim())
            .map_err(|err| MobileError::InvalidInput(err.to_string()))?;
        let item = engine.lock.get_item(id)?;
        if item.trashed_at.is_some() {
            return Err(MobileError::AutofillDenied("item is in trash".to_owned()));
        }

        let web_urls = collect_web_targets(ctx)?;
        let android_pkg = normalize_android_package(ctx.android_package_name.as_deref())?;

        let web_matched = web_urls
            .iter()
            .any(|url| find_matching_items(std::slice::from_ref(&item), url).contains(&item.id));
        let pkg_matched = android_pkg
            .as_deref()
            .is_some_and(|pkg| item_matches_android_package(&item, pkg));

        if !web_matched && !pkg_matched {
            return Err(MobileError::AutofillDenied(
                "caller domain or Android package does not match item URIs".to_owned(),
            ));
        }

        let login = item
            .login
            .as_ref()
            .ok_or_else(|| MobileError::AutofillDenied("item has no login data".to_owned()))?;
        let username = if !login.username.trim().is_empty() {
            login.username.clone()
        } else {
            login.email.clone()
        };
        let totp_code = match login.totp.as_ref() {
            Some(cfg) => Some(cfg.generate_at(unix_timestamp_seconds)?.code),
            None => None,
        };

        Ok(AutofillFillPayload {
            item_id: item.id.to_string(),
            title: item.title.clone(),
            username,
            password: login.password.clone(),
            totp_code,
        })
    }
}

fn item_matches_android_package(item: &VaultItem, package_name: &str) -> bool {
    let Some(login) = item.login.as_ref() else {
        return false;
    };
    login.uris.iter().any(|uri_entry| {
        let trimmed = uri_entry.uri.trim();
        let prefix = "androidapp://";
        trimmed
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
            && trimmed[prefix.len()..]
                .trim_end_matches('/')
                .eq_ignore_ascii_case(package_name)
    })
}

fn normalize_android_package(raw: Option<&str>) -> Result<Option<String>, MobileError> {
    let Some(pkg) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let valid = pkg.contains('.')
        && !pkg.contains('/')
        && !pkg.contains(':')
        && pkg
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '_');
    if !valid {
        return Err(MobileError::AutofillDenied(format!(
            "invalid Android application package name: {pkg}"
        )));
    }
    Ok(Some(pkg.to_ascii_lowercase()))
}

fn collect_web_targets(ctx: &AutofillCallerContext) -> Result<Vec<String>, MobileError> {
    let mut urls = Vec::new();
    if let Some(raw) = ctx
        .web_domain
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        urls.push(normalize_web_target(raw)?);
    }
    for assoc in &ctx.ios_associated_domains {
        let clean = assoc
            .trim()
            .strip_prefix("webcredentials:")
            .unwrap_or(assoc)
            .trim();
        if !clean.is_empty() {
            urls.push(normalize_web_target(clean)?);
        }
    }
    Ok(urls)
}

fn normalize_web_target(raw: &str) -> Result<String, MobileError> {
    if raw.contains("://") {
        let parsed = Url::parse(raw)
            .map_err(|_| MobileError::AutofillDenied("invalid caller web URL".to_owned()))?;
        if parsed.scheme() != "https" && parsed.scheme() != "http" {
            return Err(MobileError::AutofillDenied(
                "non-HTTP(S) caller URL rejected".to_owned(),
            ));
        }
        return Ok(parsed.to_string());
    }
    let host = extract_host(raw)
        .ok_or_else(|| MobileError::AutofillDenied("invalid caller web host".to_owned()))?;
    Ok(format!("https://{host}"))
}
