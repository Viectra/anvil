//! Browser CSV importer supporting Chrome, Edge, Brave, and Firefox exports.

use std::collections::HashMap;

use crate::error::AnvilError;
use crate::importers::{LoginParts, ParsedVaultData, decode_utf8_input, login_from_parts};

/// Parses Chromium (`name,url,username,password,note`) or Firefox (`url,username,password,...`) CSV exports.
pub fn parse(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AnvilError::ImportError(format!("invalid browser CSV header: {e}")))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    let col_map: HashMap<String, usize> = headers
        .iter()
        .enumerate()
        .map(|(i, name)| (name.clone(), i))
        .collect();

    let url_col = col_map
        .get("url")
        .or_else(|| col_map.get("origin"))
        .copied()
        .ok_or_else(|| AnvilError::ImportError("browser CSV missing 'url' column".to_owned()))?;
    let user_col = col_map.get("username").copied().ok_or_else(|| {
        AnvilError::ImportError("browser CSV missing 'username' column".to_owned())
    })?;
    let pass_col = col_map.get("password").copied().ok_or_else(|| {
        AnvilError::ImportError("browser CSV missing 'password' column".to_owned())
    })?;
    let name_col = col_map
        .get("name")
        .or_else(|| col_map.get("title"))
        .copied();
    let note_col = col_map
        .get("note")
        .or_else(|| col_map.get("notes"))
        .copied();

    let mut parsed = ParsedVaultData::default();

    for (idx, rec_res) in reader.records().enumerate() {
        let rec = rec_res.map_err(|e| {
            AnvilError::ImportError(format!("browser CSV error on row {}: {e}", idx + 1))
        })?;

        let url = rec.get(url_col).unwrap_or_default().trim();
        let username = rec.get(user_col).unwrap_or_default().trim();
        let password = rec.get(pass_col).unwrap_or_default();
        let title = name_col
            .and_then(|c| rec.get(c))
            .unwrap_or_default()
            .trim()
            .to_owned();
        let notes = note_col
            .and_then(|c| rec.get(c))
            .unwrap_or_default()
            .trim()
            .to_owned();

        // Skip internal browser metadata rows such as Firefox sync keys.
        if url.starts_with("chrome://") || url.starts_with("about:") {
            continue;
        }
        if url.is_empty() && username.is_empty() && password.is_empty() {
            continue;
        }

        let item = login_from_parts(
            LoginParts {
                title,
                url_raw: url,
                username_raw: username,
                email_raw: "",
                password: password.to_owned(),
                totp_raw: None,
                notes,
            },
            &mut parsed.warnings,
        );
        parsed.items.push(item);
    }

    Ok(parsed)
}
