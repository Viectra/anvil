//! 1Password CSV and `.1pux` ZIP archive importers with zip-bomb protection.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;
use zip::ZipArchive;

use crate::error::AnvilError;
use crate::importers::{
    LoginParts, ParsedVaultData, decode_utf8_input, ensure_folder, login_from_parts,
    parse_optional_totp, split_username_and_email,
};
use crate::models::{
    CustomField, ItemUri, LoginData, PasswordHistoryEntry, UriMatchMode, VaultItem,
};

/// Maximum uncompressed byte limit when reading `.1pux` archives (32 MiB anti zip-bomb guard).
pub const MAX_1PUX_UNCOMPRESSED_BYTES: usize = 32 * 1024 * 1024;
/// Maximum ZIP entry count allowed inside `.1pux` archives.
pub const MAX_1PUX_ENTRIES: usize = 10_000;

/// Parses a 1Password CSV export.
pub fn parse_csv(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AnvilError::ImportError(format!("invalid 1Password CSV header: {e}")))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    let col: HashMap<String, usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| (h.clone(), i))
        .collect();

    let title_col = col.get("title").or_else(|| col.get("name")).copied();
    let url_col = col
        .get("url")
        .or_else(|| col.get("website"))
        .or_else(|| col.get("urls"))
        .copied();
    let user_col = col.get("username").copied();
    let pass_col = col.get("password").copied();
    let notes_col = col.get("notes").or_else(|| col.get("notesplain")).copied();
    let totp_col = col
        .get("otpauth")
        .or_else(|| col.get("totp"))
        .or_else(|| col.get("one-time password"))
        .copied();
    let folder_col = col
        .get("vault")
        .or_else(|| col.get("category"))
        .or_else(|| col.get("tags"))
        .copied();

    let mut parsed = ParsedVaultData::default();
    let mut folder_ids: HashMap<String, Uuid> = HashMap::new();

    for (idx, rec_res) in reader.records().enumerate() {
        let rec = rec_res.map_err(|e| {
            AnvilError::ImportError(format!("1Password CSV error on row {}: {e}", idx + 1))
        })?;
        let get =
            |c: Option<usize>| -> &str { c.and_then(|i| rec.get(i)).unwrap_or_default().trim() };

        let folder_id = ensure_folder(get(folder_col), &mut folder_ids, &mut parsed.folders);
        let mut item = login_from_parts(
            LoginParts {
                title: get(title_col).to_owned(),
                url_raw: get(url_col),
                username_raw: get(user_col),
                email_raw: "",
                password: get(pass_col).to_owned(),
                totp_raw: Some(get(totp_col)),
                notes: get(notes_col).to_owned(),
            },
            &mut parsed.warnings,
        );
        item.folder_id = folder_id;
        parsed.items.push(item);
    }

    Ok(parsed)
}

#[derive(Deserialize)]
struct OnePuxExport {
    #[serde(default)]
    accounts: Vec<OnePuxAccount>,
}

#[derive(Deserialize)]
struct OnePuxAccount {
    #[serde(default)]
    vaults: Vec<OnePuxVault>,
}

#[derive(Deserialize)]
struct OnePuxVault {
    attrs: OnePuxVaultAttrs,
    #[serde(default)]
    items: Vec<OnePuxItem>,
}

#[derive(Deserialize)]
struct OnePuxVaultAttrs {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnePuxItem {
    #[serde(default)]
    fav_index: u32,
    overview: OnePuxOverview,
    details: OnePuxDetails,
}

#[derive(Deserialize)]
struct OnePuxOverview {
    #[serde(default)]
    title: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    urls: Vec<OnePuxUrl>,
}

#[derive(Deserialize)]
struct OnePuxUrl {
    url: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OnePuxDetails {
    #[serde(default)]
    login_fields: Vec<OnePuxLoginField>,
    #[serde(default)]
    notes_plain: String,
    #[serde(default)]
    sections: Vec<OnePuxSection>,
    #[serde(default)]
    password_history: Vec<OnePuxHistory>,
}

#[derive(Deserialize)]
struct OnePuxLoginField {
    #[serde(default)]
    designation: String,
    #[serde(default)]
    value: String,
}

#[derive(Deserialize)]
struct OnePuxSection {
    #[serde(default)]
    fields: Vec<OnePuxSectionField>,
}

#[derive(Deserialize)]
struct OnePuxSectionField {
    #[serde(default)]
    title: String,
    value: OnePuxFieldValue,
}

#[derive(Deserialize, Default)]
struct OnePuxFieldValue {
    totp: Option<String>,
    string: Option<String>,
    concealed: Option<String>,
}

#[derive(Deserialize)]
struct OnePuxHistory {
    value: String,
    time: Option<i64>,
}

/// Parses a 1Password `.1pux` ZIP export with strict entry-count and decompression limits.
pub fn parse_1pux(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let mut archive = ZipArchive::new(Cursor::new(input))
        .map_err(|e| AnvilError::ImportError(format!("invalid .1pux archive: {e}")))?;

    if archive.len() > MAX_1PUX_ENTRIES {
        return Err(AnvilError::ArchiveLimitExceeded(format!(
            ".1pux entry count {} exceeds limit {MAX_1PUX_ENTRIES}",
            archive.len()
        )));
    }

    let export_data_bytes = {
        let entry = archive
            .by_name("export.data")
            .map_err(|_| AnvilError::ImportError(".1pux archive missing export.data".to_owned()))?;
        let mut buf = Vec::new();
        let read_limit = (MAX_1PUX_UNCOMPRESSED_BYTES as u64) + 1;
        entry
            .take(read_limit)
            .read_to_end(&mut buf)
            .map_err(|e| AnvilError::ImportError(format!("failed reading export.data: {e}")))?;
        if buf.len() > MAX_1PUX_UNCOMPRESSED_BYTES {
            return Err(AnvilError::ArchiveLimitExceeded(format!(
                "export.data exceeds {MAX_1PUX_UNCOMPRESSED_BYTES} uncompressed bytes"
            )));
        }
        buf
    };

    let data_str = decode_utf8_input(&export_data_bytes)?;
    let root: OnePuxExport = serde_json::from_str(data_str)
        .map_err(|e| AnvilError::ImportError(format!("invalid .1pux export.data JSON: {e}")))?;

    let mut parsed = ParsedVaultData::default();
    let mut folder_ids: HashMap<String, Uuid> = HashMap::new();

    for account in root.accounts {
        for vault in account.vaults {
            let folder_id = ensure_folder(&vault.attrs.name, &mut folder_ids, &mut parsed.folders);
            for raw_item in vault.items {
                let mut username_raw = String::new();
                let mut password = String::new();
                for lf in raw_item.details.login_fields {
                    if lf.designation == "username" && username_raw.is_empty() {
                        username_raw = lf.value;
                    } else if lf.designation == "password" && password.is_empty() {
                        password = lf.value;
                    }
                }

                let mut totp_raw: Option<String> = None;
                let mut custom_fields = Vec::new();
                for section in raw_item.details.sections {
                    for field in section.fields {
                        if let Some(totp) = field.value.totp
                            && totp_raw.is_none()
                        {
                            totp_raw = Some(totp);
                        } else if let Some(secret) = field.value.concealed {
                            custom_fields.push(CustomField {
                                name: field.title,
                                value: secret,
                                hidden: true,
                            });
                        } else if let Some(val) = field.value.string
                            && !field.title.trim().is_empty()
                        {
                            custom_fields.push(CustomField {
                                name: field.title,
                                value: val,
                                hidden: false,
                            });
                        }
                    }
                }

                let mut uris = Vec::new();
                if !raw_item.overview.url.trim().is_empty() {
                    uris.push(ItemUri {
                        uri: raw_item.overview.url.trim().to_owned(),
                        match_mode: UriMatchMode::BaseDomain,
                    });
                }
                for u in raw_item.overview.urls {
                    if !u.url.trim().is_empty()
                        && !uris.iter().any(|existing| existing.uri == u.url.trim())
                    {
                        uris.push(ItemUri {
                            uri: u.url.trim().to_owned(),
                            match_mode: UriMatchMode::BaseDomain,
                        });
                    }
                }

                let title = if raw_item.overview.title.trim().is_empty() {
                    "1Password Entry".to_owned()
                } else {
                    raw_item.overview.title.trim().to_owned()
                };

                let mut item = if username_raw.is_empty() && password.is_empty() && uris.is_empty()
                {
                    VaultItem::new_secure_note(title, raw_item.details.notes_plain.clone())
                } else {
                    let (username, email) = split_username_and_email(&username_raw);
                    let totp =
                        parse_optional_totp(totp_raw.as_deref(), &title, &mut parsed.warnings);
                    let password_history = raw_item
                        .details
                        .password_history
                        .into_iter()
                        .map(|h| PasswordHistoryEntry {
                            password: h.value,
                            changed_at: h
                                .time
                                .and_then(|ts| DateTime::<Utc>::from_timestamp(ts, 0))
                                .unwrap_or_else(Utc::now),
                        })
                        .collect();

                    VaultItem::new_login(
                        title,
                        LoginData {
                            username,
                            email,
                            password,
                            password_history,
                            uris,
                            totp,
                        },
                    )
                };

                item.folder_id = folder_id;
                item.favorite = raw_item.fav_index > 0;
                item.notes = raw_item.details.notes_plain;
                item.custom_fields = custom_fields;
                parsed.items.push(item);
            }
        }
    }

    Ok(parsed)
}
