//! Standard RFC 4180 CSV exporter (Bitwarden-compatible column layout).

use std::collections::HashMap;

use uuid::Uuid;

use crate::error::AnvilError;
use crate::models::{ItemKind, VaultSnapshot};

/// Exports active vault items to a standard UTF-8 CSV string.
pub fn export_csv(snapshot: &VaultSnapshot) -> Result<String, AnvilError> {
    let folder_names: HashMap<Uuid, &str> = snapshot
        .folders
        .iter()
        .map(|f| (f.id, f.name.as_str()))
        .collect();

    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "folder",
            "favorite",
            "type",
            "name",
            "notes",
            "fields",
            "reprompt",
            "login_uri",
            "login_username",
            "login_password",
            "login_totp",
        ])
        .map_err(|e| AnvilError::ExportError(format!("CSV header write failed: {e}")))?;

    for item in snapshot.items.iter().filter(|i| i.trashed_at.is_none()) {
        let folder = item
            .folder_id
            .and_then(|fid| folder_names.get(&fid).copied())
            .unwrap_or_default();
        let favorite = if item.favorite { "1" } else { "" };
        let item_type = match item.kind {
            ItemKind::Login => "login",
            ItemKind::SecureNote => "note",
        };
        let fields = item
            .custom_fields
            .iter()
            .map(|cf| format!("{}: {}", cf.name, cf.value))
            .collect::<Vec<_>>()
            .join("\n");

        let (uri, username, password, totp) = match &item.login {
            Some(login) => {
                let first_uri = login
                    .uris
                    .iter()
                    .map(|u| u.uri.as_str())
                    .collect::<Vec<_>>()
                    .join(",");
                let ident = if !login.username.trim().is_empty() {
                    login.username.clone()
                } else {
                    login.email.clone()
                };
                let totp_uri = login
                    .totp
                    .as_ref()
                    .map(|t| t.to_otpauth_uri(&item.title))
                    .unwrap_or_default();
                (first_uri, ident, login.password.clone(), totp_uri)
            }
            None => (String::new(), String::new(), String::new(), String::new()),
        };

        writer
            .write_record([
                folder,
                favorite,
                item_type,
                &item.title,
                &item.notes,
                &fields,
                "0",
                &uri,
                &username,
                &password,
                &totp,
            ])
            .map_err(|e| AnvilError::ExportError(format!("CSV row write failed: {e}")))?;
    }

    let raw = writer
        .into_inner()
        .map_err(|e| AnvilError::ExportError(format!("CSV flush failed: {e}")))?;
    String::from_utf8(raw)
        .map_err(|e| AnvilError::ExportError(format!("CSV UTF-8 conversion failed: {e}")))
}
