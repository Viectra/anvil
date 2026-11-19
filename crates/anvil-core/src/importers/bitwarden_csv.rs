//! Bitwarden standard CSV importer.

use std::collections::HashMap;

use serde::Deserialize;
use uuid::Uuid;

use crate::error::AnvilError;
use crate::importers::{
    LoginParts, ParsedVaultData, decode_utf8_input, ensure_folder, login_from_parts,
};
use crate::models::{CustomField, VaultItem};

#[derive(Deserialize)]
struct BwCsvRow {
    #[serde(default)]
    folder: String,
    #[serde(default)]
    favorite: String,
    #[serde(rename = "type", default)]
    item_type: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    fields: String,
    #[serde(default)]
    login_uri: String,
    #[serde(default)]
    login_username: String,
    #[serde(default)]
    login_password: String,
    #[serde(default)]
    login_totp: String,
}

/// Parses a Bitwarden CSV export into folders and vault items.
pub fn parse(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());

    let mut parsed = ParsedVaultData::default();
    let mut folder_ids: HashMap<String, Uuid> = HashMap::new();

    for (idx, row_res) in reader.deserialize::<BwCsvRow>().enumerate() {
        let row = row_res.map_err(|e| {
            AnvilError::ImportError(format!("Bitwarden CSV error on row {}: {e}", idx + 1))
        })?;

        let folder_id = ensure_folder(&row.folder, &mut folder_ids, &mut parsed.folders);
        let favorite = row.favorite.trim().eq_ignore_ascii_case("1")
            || row.favorite.trim().eq_ignore_ascii_case("true");
        let item_type = row.item_type.trim().to_ascii_lowercase();

        let mut item = if item_type == "note" {
            let title = if row.name.trim().is_empty() {
                "Secure Note".to_owned()
            } else {
                row.name.trim().to_owned()
            };
            VaultItem::new_secure_note(title, row.notes)
        } else {
            login_from_parts(
                LoginParts {
                    title: row.name,
                    url_raw: &row.login_uri,
                    username_raw: &row.login_username,
                    email_raw: "",
                    password: row.login_password,
                    totp_raw: Some(&row.login_totp),
                    notes: row.notes,
                },
                &mut parsed.warnings,
            )
        };

        for line in row.fields.lines() {
            if let Some((k, v)) = line.split_once(':') {
                let name = k.trim();
                if !name.is_empty() {
                    item.custom_fields.push(CustomField {
                        name: name.to_owned(),
                        value: v.trim().to_owned(),
                        hidden: false,
                    });
                }
            }
        }

        item.folder_id = folder_id;
        item.favorite = favorite;
        parsed.items.push(item);
    }

    Ok(parsed)
}
