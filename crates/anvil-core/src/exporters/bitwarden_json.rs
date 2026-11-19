//! Bitwarden-compatible unencrypted JSON exporter.

use serde::Serialize;

use crate::error::AnvilError;
use crate::models::{ItemKind, UriMatchMode, VaultSnapshot};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportRoot {
    encrypted: bool,
    folders: Vec<BwExportFolder>,
    items: Vec<BwExportItem>,
}

#[derive(Serialize)]
struct BwExportFolder {
    id: String,
    name: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportItem {
    id: String,
    #[serde(rename = "type")]
    item_type: u8,
    name: String,
    notes: Option<String>,
    folder_id: Option<String>,
    favorite: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    login: Option<BwExportLogin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secure_note: Option<BwExportSecureNote>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    fields: Vec<BwExportField>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    password_history: Vec<BwExportHistory>,
}

#[derive(Serialize)]
struct BwExportSecureNote {
    #[serde(rename = "type")]
    note_type: u8,
}

#[derive(Serialize)]
struct BwExportLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Vec<BwExportUri>,
}

#[derive(Serialize)]
struct BwExportUri {
    uri: String,
    #[serde(rename = "match")]
    match_mode: u8,
}

#[derive(Serialize)]
struct BwExportField {
    name: String,
    value: String,
    #[serde(rename = "type")]
    field_type: u8,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BwExportHistory {
    password: String,
    last_used_date: String,
}

/// Serializes active vault folders and items into Bitwarden-compatible JSON.
pub fn export_bitwarden_json(snapshot: &VaultSnapshot) -> Result<String, AnvilError> {
    let folders = snapshot
        .folders
        .iter()
        .map(|f| BwExportFolder {
            id: f.id.to_string(),
            name: f.name.clone(),
        })
        .collect();

    let items = snapshot
        .items
        .iter()
        .filter(|i| i.trashed_at.is_none())
        .map(|item| {
            let notes = (!item.notes.is_empty()).then(|| item.notes.clone());
            let fields = item
                .custom_fields
                .iter()
                .map(|cf| BwExportField {
                    name: cf.name.clone(),
                    value: cf.value.clone(),
                    field_type: u8::from(cf.hidden),
                })
                .collect();

            match item.kind {
                ItemKind::Login => {
                    let login_data = item.login.as_ref();
                    let identity = login_data.and_then(|l| {
                        if !l.username.trim().is_empty() {
                            Some(l.username.clone())
                        } else if !l.email.trim().is_empty() {
                            Some(l.email.clone())
                        } else {
                            None
                        }
                    });
                    let password = login_data
                        .and_then(|l| (!l.password.is_empty()).then(|| l.password.clone()));
                    let totp = login_data
                        .and_then(|l| l.totp.as_ref().map(|t| t.to_otpauth_uri(&item.title)));
                    let uris = login_data
                        .map(|l| {
                            l.uris
                                .iter()
                                .map(|u| BwExportUri {
                                    uri: u.uri.clone(),
                                    match_mode: map_match_mode(u.match_mode),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let password_history = login_data
                        .map(|l| {
                            l.password_history
                                .iter()
                                .map(|h| BwExportHistory {
                                    password: h.password.clone(),
                                    last_used_date: h.changed_at.to_rfc3339(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    BwExportItem {
                        id: item.id.to_string(),
                        item_type: 1,
                        name: item.title.clone(),
                        notes,
                        folder_id: item.folder_id.map(|id| id.to_string()),
                        favorite: item.favorite,
                        login: Some(BwExportLogin {
                            username: identity,
                            password,
                            totp,
                            uris,
                        }),
                        secure_note: None,
                        fields,
                        password_history,
                    }
                }
                ItemKind::SecureNote => BwExportItem {
                    id: item.id.to_string(),
                    item_type: 2,
                    name: item.title.clone(),
                    notes,
                    folder_id: item.folder_id.map(|id| id.to_string()),
                    favorite: item.favorite,
                    login: None,
                    secure_note: Some(BwExportSecureNote { note_type: 0 }),
                    fields,
                    password_history: Vec::new(),
                },
            }
        })
        .collect();

    let root = BwExportRoot {
        encrypted: false,
        folders,
        items,
    };
    Ok(serde_json::to_string_pretty(&root)?)
}

fn map_match_mode(mode: UriMatchMode) -> u8 {
    match mode {
        UriMatchMode::BaseDomain => 0,
        UriMatchMode::Host => 1,
        UriMatchMode::StartsWith => 2,
        UriMatchMode::Exact => 3,
        UriMatchMode::Regex => 4,
        UriMatchMode::Never => 5,
    }
}
