//! Bitwarden JSON importer (unencrypted and password-protected encrypted exports).

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

use crate::crypto::{BitwardenKdfParams, BitwardenKdfType, decrypt_bitwarden_cipher_string};
use crate::error::AnvilError;
use crate::importers::{
    ParsedVaultData, decode_utf8_input, parse_optional_totp, split_username_and_email,
};
use crate::models::{
    CustomField, ItemUri, LoginData, PasswordHistoryEntry, UriMatchMode, VaultFolder, VaultItem,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwEncryptedExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    password_protected: bool,
    salt: Option<String>,
    kdf_type: Option<u32>,
    kdf_iterations: Option<u32>,
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    data: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwPlainExport {
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwFolder {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    #[serde(rename = "type")]
    item_type: u8,
    name: Option<String>,
    notes: Option<String>,
    folder_id: Option<String>,
    #[serde(default)]
    favorite: bool,
    login: Option<BwLogin>,
    #[serde(default)]
    fields: Vec<BwField>,
    #[serde(default)]
    password_history: Vec<BwHistory>,
}

#[derive(Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    #[serde(default)]
    uris: Vec<BwUri>,
}

#[derive(Deserialize)]
struct BwUri {
    uri: Option<String>,
    #[serde(rename = "match")]
    match_mode: Option<u8>,
}

#[derive(Deserialize)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    field_type: Option<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwHistory {
    password: String,
    last_used_date: Option<String>,
}

/// Parses an unencrypted Bitwarden JSON vault export.
pub fn parse_unencrypted(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let raw: BwPlainExport = serde_json::from_str(text)
        .map_err(|e| AnvilError::ImportError(format!("invalid Bitwarden JSON: {e}")))?;
    convert_plain_export(raw)
}

/// Decrypts and parses a password-protected Bitwarden encrypted JSON export (`encType = 2`).
pub fn parse_encrypted(input: &[u8], password: &str) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let env: BwEncryptedExport = serde_json::from_str(text)
        .map_err(|e| AnvilError::ImportError(format!("invalid Bitwarden encrypted JSON: {e}")))?;

    if !env.encrypted {
        return parse_unencrypted(input);
    }
    if !env.password_protected {
        return Err(AnvilError::ImportError(
            "account-key-encrypted Bitwarden JSON without password protection cannot be decrypted offline"
                .to_owned(),
        ));
    }

    let kdf_type = BitwardenKdfType::from_u32(env.kdf_type.unwrap_or(0))?;
    let salt = env
        .salt
        .ok_or_else(|| AnvilError::ImportError("missing kdf salt".to_owned()))?;
    let iterations = env.kdf_iterations.unwrap_or(100_000);
    let data_cipher = env
        .data
        .ok_or_else(|| AnvilError::ImportError("missing encrypted data payload".to_owned()))?;

    let params = BitwardenKdfParams {
        kdf_type,
        salt,
        iterations,
        memory_mb: env.kdf_memory,
        parallelism: env.kdf_parallelism,
    };

    let decrypted_json = decrypt_bitwarden_cipher_string(&data_cipher, password, &params)?;
    let plain: BwPlainExport = serde_json::from_str(&decrypted_json).map_err(|e| {
        AnvilError::ImportError(format!("decrypted Bitwarden payload invalid: {e}"))
    })?;
    convert_plain_export(plain)
}

fn convert_plain_export(raw: BwPlainExport) -> Result<ParsedVaultData, AnvilError> {
    let mut parsed = ParsedVaultData::default();
    let mut bw_folder_map: HashMap<String, Uuid> = HashMap::new();

    for f in raw.folders {
        if f.name.trim().is_empty() {
            continue;
        }
        let folder = VaultFolder::new(f.name.trim());
        bw_folder_map.insert(f.id, folder.id);
        parsed.folders.push(folder);
    }

    for entry in raw.items {
        let title = entry
            .name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("Untitled")
            .to_owned();
        let notes = entry.notes.unwrap_or_default();
        let mapped_folder = entry
            .folder_id
            .as_deref()
            .and_then(|id| bw_folder_map.get(id).copied());

        let custom_fields: Vec<CustomField> = entry
            .fields
            .into_iter()
            .filter_map(|f| {
                let name = f.name?;
                Some(CustomField {
                    name,
                    value: f.value.unwrap_or_default(),
                    hidden: f.field_type == Some(1),
                })
            })
            .collect();

        let mut item = match entry.item_type {
            1 => {
                let bw_login = entry.login.unwrap_or(BwLogin {
                    username: None,
                    password: None,
                    totp: None,
                    uris: Vec::new(),
                });
                let (username, email) =
                    split_username_and_email(bw_login.username.as_deref().unwrap_or_default());
                let uris = bw_login
                    .uris
                    .into_iter()
                    .filter_map(|u| {
                        let uri_str = u.uri?.trim().to_owned();
                        if uri_str.is_empty() {
                            return None;
                        }
                        Some(ItemUri {
                            uri: uri_str,
                            match_mode: map_bw_match_mode(u.match_mode),
                        })
                    })
                    .collect();
                let totp =
                    parse_optional_totp(bw_login.totp.as_deref(), &title, &mut parsed.warnings);
                let password_history = entry
                    .password_history
                    .into_iter()
                    .map(|h| PasswordHistoryEntry {
                        password: h.password,
                        changed_at: h
                            .last_used_date
                            .as_deref()
                            .and_then(|d| DateTime::parse_from_rfc3339(d).ok())
                            .map_or_else(Utc::now, |dt| dt.with_timezone(&Utc)),
                    })
                    .collect();

                VaultItem::new_login(
                    title,
                    LoginData {
                        username,
                        email,
                        password: bw_login.password.unwrap_or_default(),
                        password_history,
                        uris,
                        totp,
                    },
                )
            }
            2 => VaultItem::new_secure_note(title, notes.clone()),
            other => {
                parsed.warnings.push(format!(
                    "Skipped unsupported Bitwarden item type {other} ('{title}')"
                ));
                continue;
            }
        };

        item.folder_id = mapped_folder;
        item.favorite = entry.favorite;
        item.notes = notes;
        item.custom_fields = custom_fields;
        parsed.items.push(item);
    }

    Ok(parsed)
}

fn map_bw_match_mode(mode: Option<u8>) -> UriMatchMode {
    match mode {
        Some(1) => UriMatchMode::Host,
        Some(2) => UriMatchMode::StartsWith,
        Some(3) => UriMatchMode::Exact,
        Some(4) => UriMatchMode::Regex,
        Some(5) => UriMatchMode::Never,
        _ => UriMatchMode::BaseDomain,
    }
}
