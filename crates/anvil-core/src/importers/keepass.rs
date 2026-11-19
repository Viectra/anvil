//! KeePass and KeePassXC CSV and XML 2.x importers.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use quick_xml::Reader;
use quick_xml::events::Event;
use uuid::Uuid;

use crate::error::AnvilError;
use crate::importers::{
    LoginParts, ParsedVaultData, decode_utf8_input, ensure_folder, login_from_parts,
    parse_optional_totp, split_username_and_email,
};
use crate::models::{
    CustomField, ItemUri, LoginData, PasswordHistoryEntry, UriMatchMode, VaultItem,
};

/// Parses a KeePass / KeePassXC CSV export.
pub fn parse_csv(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AnvilError::ImportError(format!("invalid KeePass CSV header: {e}")))?
        .iter()
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    let col: HashMap<String, usize> = headers
        .iter()
        .enumerate()
        .map(|(i, h)| (h.clone(), i))
        .collect();

    let group_col = col.get("group").copied();
    let title_col = col.get("title").or_else(|| col.get("name")).copied();
    let user_col = col.get("username").or_else(|| col.get("account")).copied();
    let pass_col = col.get("password").copied();
    let url_col = col.get("url").or_else(|| col.get("web site")).copied();
    let notes_col = col.get("notes").or_else(|| col.get("comments")).copied();
    let totp_col = col.get("totp").or_else(|| col.get("otp")).copied();

    let mut parsed = ParsedVaultData::default();
    let mut folder_ids: HashMap<String, Uuid> = HashMap::new();

    for (idx, rec_res) in reader.records().enumerate() {
        let rec = rec_res.map_err(|e| {
            AnvilError::ImportError(format!("KeePass CSV error on row {}: {e}", idx + 1))
        })?;
        let get =
            |c: Option<usize>| -> &str { c.and_then(|i| rec.get(i)).unwrap_or_default().trim() };

        let group = get(group_col);
        if group.eq_ignore_ascii_case("Recycle Bin") {
            continue;
        }
        let folder_id = ensure_folder(group, &mut folder_ids, &mut parsed.folders);
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

#[derive(Default)]
struct XmlEntryBuilder {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    totp: Option<String>,
    custom_fields: Vec<CustomField>,
    history: Vec<PasswordHistoryEntry>,
}

/// Parses a KeePass 2.x XML database export (`<KeePassFile>`).
pub fn parse_xml(input: &[u8]) -> Result<ParsedVaultData, AnvilError> {
    let text = decode_utf8_input(input)?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(true);

    let mut parsed = ParsedVaultData::default();
    let mut folder_ids: HashMap<String, Uuid> = HashMap::new();

    let mut group_stack: Vec<String> = Vec::new();
    let mut tag_stack: Vec<String> = Vec::new();
    let mut in_history = false;

    let mut current_entry: Option<XmlEntryBuilder> = None;
    let mut history_entry: Option<XmlEntryBuilder> = None;
    let mut current_key = String::new();
    let mut current_value = String::new();
    let mut current_value_protected = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if tag == "Group" {
                    group_stack.push(String::new());
                } else if tag == "History" {
                    in_history = true;
                } else if tag == "Entry" {
                    if in_history {
                        history_entry = Some(XmlEntryBuilder::default());
                    } else {
                        current_entry = Some(XmlEntryBuilder::default());
                    }
                } else if tag == "String" {
                    current_key.clear();
                    current_value.clear();
                    current_value_protected = false;
                } else if tag == "Value" {
                    current_value_protected = e.attributes().flatten().any(|attr| {
                        attr.key.as_ref() == b"Protected"
                            && attr.value.as_ref().eq_ignore_ascii_case(b"True")
                    });
                }
                tag_stack.push(tag);
            }
            Ok(Event::Text(t)) => {
                let text_val = t
                    .unescape()
                    .map_err(|e| AnvilError::ImportError(format!("KeePass XML decode error: {e}")))?
                    .into_owned();
                if let Some(current_tag) = tag_stack.last() {
                    if current_tag == "Name"
                        && tag_stack
                            .get(tag_stack.len().saturating_sub(2))
                            .map(String::as_str)
                            == Some("Group")
                        && let Some(last_group) = group_stack.last_mut()
                    {
                        *last_group = text_val;
                    } else if current_tag == "Key" {
                        current_key = text_val;
                    } else if current_tag == "Value" {
                        current_value = text_val;
                    }
                }
            }
            Ok(Event::End(e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                tag_stack.pop();

                if tag == "String" {
                    let target = if in_history {
                        history_entry.as_mut()
                    } else {
                        current_entry.as_mut()
                    };
                    if let Some(entry) = target {
                        apply_xml_kv(entry, &current_key, &current_value, current_value_protected);
                    }
                } else if tag == "Entry" {
                    if in_history {
                        if let (Some(hist), Some(parent)) =
                            (history_entry.take(), current_entry.as_mut())
                            && !hist.password.is_empty()
                        {
                            parent.history.push(PasswordHistoryEntry {
                                password: hist.password,
                                changed_at: DateTime::<Utc>::from_timestamp(0, 0)
                                    .unwrap_or_else(Utc::now),
                            });
                        }
                    } else if let Some(entry) = current_entry.take() {
                        let folder_path = build_folder_path(&group_stack);
                        if !folder_path.eq_ignore_ascii_case("Recycle Bin") {
                            let folder_id =
                                ensure_folder(&folder_path, &mut folder_ids, &mut parsed.folders);
                            let mut item = finalize_xml_entry(entry, &mut parsed.warnings);
                            item.folder_id = folder_id;
                            parsed.items.push(item);
                        }
                    }
                } else if tag == "History" {
                    in_history = false;
                } else if tag == "Group" {
                    group_stack.pop();
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(AnvilError::ImportError(format!(
                    "KeePass XML parse error: {e}"
                )));
            }
            _ => {}
        }
    }

    Ok(parsed)
}

fn apply_xml_kv(entry: &mut XmlEntryBuilder, key: &str, value: &str, protected: bool) {
    match key {
        "Title" => entry.title = value.to_owned(),
        "UserName" => entry.username = value.to_owned(),
        "Password" => entry.password = value.to_owned(),
        "URL" => entry.url = value.to_owned(),
        "Notes" => entry.notes = value.to_owned(),
        "otp" | "TOTP Seed" | "TOTP" => entry.totp = Some(value.to_owned()),
        _ if !key.trim().is_empty() => {
            entry.custom_fields.push(CustomField {
                name: key.to_owned(),
                value: value.to_owned(),
                hidden: protected,
            });
        }
        _ => {}
    }
}

fn build_folder_path(stack: &[String]) -> String {
    let parts: Vec<&str> = stack
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() > 1 {
        // Skip synthetic root database group name when nested subfolders exist.
        parts[1..].join("/")
    } else {
        parts.join("/")
    }
}

fn finalize_xml_entry(entry: XmlEntryBuilder, warnings: &mut Vec<String>) -> VaultItem {
    let title = if entry.title.trim().is_empty() {
        "KeePass Entry".to_owned()
    } else {
        entry.title.trim().to_owned()
    };
    let (username, email) = split_username_and_email(&entry.username);
    let uris = if entry.url.trim().is_empty() {
        Vec::new()
    } else {
        vec![ItemUri {
            uri: entry.url.trim().to_owned(),
            match_mode: UriMatchMode::BaseDomain,
        }]
    };
    let totp = parse_optional_totp(entry.totp.as_deref(), &title, warnings);

    let mut item = VaultItem::new_login(
        title,
        LoginData {
            username,
            email,
            password: entry.password,
            password_history: entry.history,
            uris,
            totp,
        },
    );
    item.notes = entry.notes;
    item.custom_fields = entry.custom_fields;
    item
}
