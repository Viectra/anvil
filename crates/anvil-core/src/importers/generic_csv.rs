//! Generic, Proton Pass, and Dashlane CSV importer with configurable column mapping.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AnvilError;
use crate::importers::{
    LoginParts, ParsedVaultData, decode_utf8_input, ensure_folder, login_from_parts,
};

/// Explicit CSV column indices for manual mapping of arbitrary CSV exports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ColumnMapping {
    pub title: Option<usize>,
    pub url: Option<usize>,
    pub username: Option<usize>,
    pub email: Option<usize>,
    pub password: Option<usize>,
    pub totp: Option<usize>,
    pub notes: Option<usize>,
    pub folder: Option<usize>,
}

/// Auto-detects column headers for Proton Pass, Dashlane, and generic CSV exports.
pub fn parse_auto(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AnvilError::ImportError(format!("invalid CSV header: {e}")))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    let find_any = |aliases: &[&str]| -> Option<usize> {
        headers
            .iter()
            .position(|h| aliases.iter().any(|alias| h == alias))
    };

    let mapping = ColumnMapping {
        title: find_any(&["name", "title", "account", "service"]),
        url: find_any(&["url", "uri", "website", "login_uri", "domain"]),
        username: find_any(&["username", "login_username", "login", "user"]),
        email: find_any(&["email", "e-mail", "username2"]),
        password: find_any(&["password", "login_password", "pass"]),
        totp: find_any(&["totp", "otp", "otpsecret", "otp_secret", "login_totp"]),
        notes: find_any(&["note", "notes", "comment", "comments"]),
        folder: find_any(&["vault", "folder", "category", "group"]),
    };

    if mapping.password.is_none() && mapping.username.is_none() && mapping.email.is_none() {
        return Err(AnvilError::ImportError(
            "could not detect password/username/email columns in CSV".to_owned(),
        ));
    }

    parse_records(&mut reader, &mapping)
}

/// Parses a CSV export using user-supplied explicit column indices.
pub fn parse_with_mapping(
    input: &[u8],
    mapping: &ColumnMapping,
) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());
    let _headers = reader
        .headers()
        .map_err(|e| AnvilError::ImportError(format!("invalid CSV header: {e}")))?;
    parse_records(&mut reader, mapping)
}

fn parse_records(
    reader: &mut csv::Reader<&[u8]>,
    mapping: &ColumnMapping,
) -> Result<ParsedVaultData, AnvilError> {
    let mut parsed = ParsedVaultData::default();
    let mut folder_ids: HashMap<String, Uuid> = HashMap::new();

    for (idx, rec_res) in reader.records().enumerate() {
        let rec = rec_res.map_err(|e| {
            AnvilError::ImportError(format!("CSV parse error on row {}: {e}", idx + 1))
        })?;
        let get = |col: Option<usize>| -> &str {
            col.and_then(|c| rec.get(c)).unwrap_or_default().trim()
        };

        let folder_id = ensure_folder(get(mapping.folder), &mut folder_ids, &mut parsed.folders);
        let mut item = login_from_parts(
            LoginParts {
                title: get(mapping.title).to_owned(),
                url_raw: get(mapping.url),
                username_raw: get(mapping.username),
                email_raw: get(mapping.email),
                password: get(mapping.password).to_owned(),
                totp_raw: Some(get(mapping.totp)),
                notes: get(mapping.notes).to_owned(),
            },
            &mut parsed.warnings,
        );
        item.folder_id = folder_id;
        parsed.items.push(item);
    }

    Ok(parsed)
}
