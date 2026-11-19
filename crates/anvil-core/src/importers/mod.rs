//! Multi-manager vault import pipelines with dry-run previews and deduplication.

pub mod bitwarden_csv;
pub mod bitwarden_json;
pub mod browser_csv;
pub mod generic_csv;
pub mod keepass;
pub mod onepassword;

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AnvilError;
use crate::models::{
    ItemKind, LoginData, PasswordHistoryEntry, VaultFolder, VaultItem, VaultSnapshot,
};
use crate::search::extract_base_domain;
use crate::totp::TotpConfig;

pub use generic_csv::ColumnMapping;

/// Supported source formats for vault import.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportFormat {
    BitwardenJson,
    BitwardenEncryptedJson,
    BitwardenCsv,
    ChromeCsv,
    EdgeCsv,
    BraveCsv,
    FirefoxCsv,
    KeePassCsv,
    KeePassXml,
    OnePasswordCsv,
    OnePassword1pux,
    ProtonPassCsv,
    DashlaneCsv,
    GenericCsv(ColumnMapping),
}

/// Strategy for handling imported items matching an existing vault entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DuplicatePolicy {
    #[default]
    Skip,
    Merge,
    CreateNew,
}

/// Raw parsed folders, items, and non-fatal parser warnings prior to vault insertion.
#[derive(Debug, Clone, Default)]
pub struct ParsedVaultData {
    pub folders: Vec<VaultFolder>,
    pub items: Vec<VaultItem>,
    pub warnings: Vec<String>,
}

/// Duplicate match detected during dry-run import preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicateCandidate {
    pub imported_index: usize,
    pub existing_item_id: Uuid,
    pub title: String,
    pub identity: String,
    pub domain: Option<String>,
}

/// Dry-run preview produced before committing any imported records to the vault.
#[derive(Debug, Clone)]
pub struct ImportPreview {
    pub format: ImportFormat,
    pub parsed: ParsedVaultData,
    pub duplicates: Vec<DuplicateCandidate>,
    pub total_items: usize,
    pub totp_count: usize,
}

/// Final summary returned after applying an `ImportPreview` to a vault snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSummary {
    pub created: usize,
    pub merged: usize,
    pub skipped: usize,
    pub folders_created: usize,
    pub warnings: Vec<String>,
}

/// Parses an export file without modifying `existing` and detects duplicate accounts.
pub fn preview_import(
    format: ImportFormat,
    input: &[u8],
    backup_password: Option<&str>,
    existing: &VaultSnapshot,
) -> Result<ImportPreview, AnvilError> {
    let parsed = match &format {
        ImportFormat::BitwardenJson => bitwarden_json::parse_unencrypted(input)?,
        ImportFormat::BitwardenEncryptedJson => {
            let pw = backup_password.ok_or(AnvilError::WrongBackupPassword)?;
            bitwarden_json::parse_encrypted(input, pw)?
        }
        ImportFormat::BitwardenCsv => bitwarden_csv::parse(input)?,
        ImportFormat::ChromeCsv
        | ImportFormat::EdgeCsv
        | ImportFormat::BraveCsv
        | ImportFormat::FirefoxCsv => browser_csv::parse(input)?,
        ImportFormat::KeePassCsv => keepass::parse_csv(input)?,
        ImportFormat::KeePassXml => keepass::parse_xml(input)?,
        ImportFormat::OnePasswordCsv => onepassword::parse_csv(input)?,
        ImportFormat::OnePassword1pux => onepassword::parse_1pux(input)?,
        ImportFormat::ProtonPassCsv | ImportFormat::DashlaneCsv => generic_csv::parse_auto(input)?,
        ImportFormat::GenericCsv(mapping) => generic_csv::parse_with_mapping(input, mapping)?,
    };

    let existing_index = build_dedup_index(&existing.items);
    let mut duplicates = Vec::new();
    let mut totp_count = 0usize;

    for (idx, item) in parsed.items.iter().enumerate() {
        if item.login.as_ref().and_then(|l| l.totp.as_ref()).is_some() {
            totp_count += 1;
        }
        let key = dedup_key(item);
        if let Some(&existing_id) = existing_index.get(&key) {
            duplicates.push(DuplicateCandidate {
                imported_index: idx,
                existing_item_id: existing_id,
                title: item.title.clone(),
                identity: item_identity(item),
                domain: item_primary_domain(item),
            });
        }
    }

    let total_items = parsed.items.len();
    Ok(ImportPreview {
        format,
        parsed,
        duplicates,
        total_items,
        totp_count,
    })
}

/// Commits an `ImportPreview` into `target` according to `policy`.
pub fn apply_import(
    preview: ImportPreview,
    policy: DuplicatePolicy,
    target: &mut VaultSnapshot,
) -> ImportSummary {
    let mut folder_by_name: HashMap<String, Uuid> = target
        .folders
        .iter()
        .map(|f| (f.name.trim().to_ascii_lowercase(), f.id))
        .collect();

    let mut folder_remap: HashMap<Uuid, Uuid> = HashMap::new();
    let mut folders_created = 0usize;

    for folder in preview.parsed.folders {
        let norm = folder.name.trim().to_ascii_lowercase();
        if norm.is_empty() {
            continue;
        }
        if let Some(&existing_id) = folder_by_name.get(&norm) {
            folder_remap.insert(folder.id, existing_id);
        } else {
            folder_by_name.insert(norm, folder.id);
            folder_remap.insert(folder.id, folder.id);
            target.folders.push(folder);
            folders_created += 1;
        }
    }

    let dup_map: HashMap<usize, Uuid> = preview
        .duplicates
        .into_iter()
        .map(|d| (d.imported_index, d.existing_item_id))
        .collect();

    let mut created = 0usize;
    let mut merged = 0usize;
    let mut skipped = 0usize;

    for (idx, mut item) in preview.parsed.items.into_iter().enumerate() {
        if let Some(old_fid) = item.folder_id {
            item.folder_id = folder_remap.get(&old_fid).copied();
        }

        if let Some(&existing_id) = dup_map.get(&idx) {
            match policy {
                DuplicatePolicy::Skip => {
                    skipped += 1;
                }
                DuplicatePolicy::Merge => {
                    if let Some(existing_item) =
                        target.items.iter_mut().find(|x| x.id == existing_id)
                    {
                        merge_items(existing_item, &item);
                        merged += 1;
                    } else {
                        target.items.push(item);
                        created += 1;
                    }
                }
                DuplicatePolicy::CreateNew => {
                    target.items.push(item);
                    created += 1;
                }
            }
        } else {
            target.items.push(item);
            created += 1;
        }
    }

    ImportSummary {
        created,
        merged,
        skipped,
        folders_created,
        warnings: preview.parsed.warnings,
    }
}

fn merge_items(existing: &mut VaultItem, incoming: &VaultItem) {
    let now = Utc::now();
    if let (Some(ex_login), Some(in_login)) = (existing.login.as_mut(), incoming.login.as_ref()) {
        if !in_login.password.is_empty() && ex_login.password != in_login.password {
            if !ex_login.password.is_empty() {
                ex_login.password_history.push(PasswordHistoryEntry {
                    password: ex_login.password.clone(),
                    changed_at: now,
                });
            }
            ex_login.password = in_login.password.clone();
        }
        if ex_login.username.is_empty() && !in_login.username.is_empty() {
            ex_login.username = in_login.username.clone();
        }
        if ex_login.email.is_empty() && !in_login.email.is_empty() {
            ex_login.email = in_login.email.clone();
        }
        if ex_login.totp.is_none() && in_login.totp.is_some() {
            ex_login.totp = in_login.totp.clone();
        }
        let known_uris: HashSet<String> = ex_login
            .uris
            .iter()
            .map(|u| u.uri.trim().to_ascii_lowercase())
            .collect();
        for uri in &in_login.uris {
            if !known_uris.contains(&uri.uri.trim().to_ascii_lowercase()) {
                ex_login.uris.push(uri.clone());
            }
        }
    }

    if existing.notes.is_empty() && !incoming.notes.is_empty() {
        existing.notes = incoming.notes.clone();
    } else if !incoming.notes.is_empty() && !existing.notes.contains(&incoming.notes) {
        existing.notes.push_str("\n\n");
        existing.notes.push_str(&incoming.notes);
    }

    existing.item_version = existing.item_version.saturating_add(1);
    existing.updated_at = now;
}

fn build_dedup_index(items: &[VaultItem]) -> HashMap<(String, String), Uuid> {
    let mut index = HashMap::new();
    for item in items.iter().filter(|i| i.trashed_at.is_none()) {
        index.entry(dedup_key(item)).or_insert(item.id);
    }
    index
}

fn dedup_key(item: &VaultItem) -> (String, String) {
    match item.kind {
        ItemKind::Login => {
            let domain_or_title =
                item_primary_domain(item).unwrap_or_else(|| item.title.trim().to_ascii_lowercase());
            (domain_or_title, item_identity(item))
        }
        ItemKind::SecureNote => ("note".to_owned(), item.title.trim().to_ascii_lowercase()),
    }
}

fn item_identity(item: &VaultItem) -> String {
    match &item.login {
        Some(login) => {
            let email = login.email.trim().to_ascii_lowercase();
            if !email.is_empty() {
                email
            } else {
                login.username.trim().to_ascii_lowercase()
            }
        }
        None => String::new(),
    }
}

fn item_primary_domain(item: &VaultItem) -> Option<String> {
    item.login
        .as_ref()?
        .uris
        .iter()
        .find_map(|u| extract_base_domain(&u.uri))
}

pub(crate) fn split_username_and_email(raw: &str) -> (String, String) {
    let trimmed = raw.trim();
    if trimmed.contains('@') && !trimmed.contains(' ') {
        (trimmed.to_owned(), trimmed.to_owned())
    } else {
        (trimmed.to_owned(), String::new())
    }
}

pub(crate) fn parse_optional_totp(
    raw: Option<&str>,
    title: &str,
    warnings: &mut Vec<String>,
) -> Option<TotpConfig> {
    let text = raw?.trim();
    if text.is_empty() {
        return None;
    }
    match TotpConfig::from_input(text) {
        Ok(cfg) => Some(cfg),
        Err(err) => {
            warnings.push(format!("Skipped invalid TOTP on '{title}': {err}"));
            None
        }
    }
}

pub(crate) fn decode_utf8_input(bytes: &[u8]) -> Result<&str, AnvilError> {
    let s = std::str::from_utf8(bytes)
        .map_err(|_| AnvilError::ImportError("input is not valid UTF-8".to_owned()))?;
    Ok(s.strip_prefix('\u{feff}').unwrap_or(s))
}

pub(crate) fn ensure_folder(
    name: &str,
    folder_ids: &mut HashMap<String, Uuid>,
    folders: &mut Vec<VaultFolder>,
) -> Option<Uuid> {
    let clean = name.trim();
    if clean.is_empty() {
        return None;
    }
    if let Some(&id) = folder_ids.get(clean) {
        return Some(id);
    }
    let folder = VaultFolder::new(clean);
    let id = folder.id;
    folder_ids.insert(clean.to_owned(), id);
    folders.push(folder);
    Some(id)
}

pub(crate) struct LoginParts<'a> {
    pub(crate) title: String,
    pub(crate) url_raw: &'a str,
    pub(crate) username_raw: &'a str,
    pub(crate) email_raw: &'a str,
    pub(crate) password: String,
    pub(crate) totp_raw: Option<&'a str>,
    pub(crate) notes: String,
}

pub(crate) fn login_from_parts(parts: LoginParts<'_>, warnings: &mut Vec<String>) -> VaultItem {
    let (username, email) = if parts.email_raw.trim().is_empty() {
        split_username_and_email(parts.username_raw)
    } else {
        (
            parts.username_raw.trim().to_owned(),
            parts.email_raw.trim().to_owned(),
        )
    };

    let uris = parts
        .url_raw
        .split([',', ';', '\n'])
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(|u| crate::models::ItemUri {
            uri: u.to_owned(),
            match_mode: crate::models::UriMatchMode::BaseDomain,
        })
        .collect();

    let totp = parse_optional_totp(parts.totp_raw, &parts.title, warnings);
    let mut item = VaultItem::new_login(
        if parts.title.trim().is_empty() {
            extract_base_domain(parts.url_raw).unwrap_or_else(|| "Imported Entry".to_owned())
        } else {
            parts.title.trim().to_owned()
        },
        LoginData {
            username,
            email,
            password: parts.password,
            password_history: Vec::new(),
            uris,
            totp,
        },
    );
    item.notes = parts.notes;
    item
}
