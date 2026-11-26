//! Plaintext in-memory vault entities with memory zeroization and redacted Debug.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::totp::TotpConfig;

/// Current JSON payload schema version for encrypted vault items.
pub const VAULT_ITEM_SCHEMA_VERSION: u32 = 1;

/// Supported vault entry kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    #[default]
    Login,
    SecureNote,
}

/// URI matching rule for browser autofill and anti-phishing checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UriMatchMode {
    #[default]
    BaseDomain,
    Host,
    StartsWith,
    Exact,
    Regex,
    Never,
}

/// Associated URL and matching rule on a login item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemUri {
    pub uri: String,
    #[serde(default)]
    pub match_mode: UriMatchMode,
}

/// Historical password entry retained across password updates.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PasswordHistoryEntry {
    pub password: String,
    #[zeroize(skip)]
    pub changed_at: DateTime<Utc>,
}

impl fmt::Debug for PasswordHistoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHistoryEntry")
            .field("password", &"[REDACTED]")
            .field("changed_at", &self.changed_at)
            .finish()
    }
}

/// Custom field attached to a vault entry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[zeroize(skip)]
    pub hidden: bool,
}

impl fmt::Debug for CustomField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field(
                "value",
                if self.hidden {
                    &"[REDACTED]"
                } else {
                    &self.value
                },
            )
            .field("hidden", &self.hidden)
            .finish()
    }
}

/// Custom logo reference and fallback accent color for an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemLogo {
    pub blob_id: Option<Uuid>,
    pub fallback_color: String,
}

impl Default for ItemLogo {
    fn default() -> Self {
        Self {
            blob_id: None,
            fallback_color: "#7C6DFA".to_owned(),
        }
    }
}

/// Login credentials and optional 2FA TOTP configuration.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct LoginData {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_history: Vec<PasswordHistoryEntry>,
    #[zeroize(skip)]
    pub uris: Vec<ItemUri>,
    pub totp: Option<TotpConfig>,
}

impl fmt::Debug for LoginData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginData")
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password", &"[REDACTED]")
            .field("password_history_len", &self.password_history.len())
            .field("uris", &self.uris)
            .field("has_totp", &self.totp.is_some())
            .finish()
    }
}

/// Decrypted vault entry held in memory while the vault is unlocked.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultItem {
    pub id: Uuid,
    pub schema_version: u32,
    pub kind: ItemKind,
    pub title: String,
    pub folder_id: Option<Uuid>,
    pub favorite: bool,
    pub trashed_at: Option<DateTime<Utc>>,
    pub item_version: u64,
    pub logo: ItemLogo,
    pub login: Option<LoginData>,
    pub custom_fields: Vec<CustomField>,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Zeroize for VaultItem {
    fn zeroize(&mut self) {
        self.login.zeroize();
        self.custom_fields.zeroize();
        self.notes.zeroize();
    }
}

impl Drop for VaultItem {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl fmt::Debug for VaultItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultItem")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("title", &self.title)
            .field("folder_id", &self.folder_id)
            .field("favorite", &self.favorite)
            .field("trashed_at", &self.trashed_at)
            .field("item_version", &self.item_version)
            .finish()
    }
}

impl VaultItem {
    /// Creates a new `Login` item with sane defaults and a fresh UUIDv4 identifier.
    pub fn new_login(title: impl Into<String>, login: LoginData) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            schema_version: VAULT_ITEM_SCHEMA_VERSION,
            kind: ItemKind::Login,
            title: title.into(),
            folder_id: None,
            favorite: false,
            trashed_at: None,
            item_version: 1,
            logo: ItemLogo::default(),
            login: Some(login),
            custom_fields: Vec::new(),
            notes: String::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a new `SecureNote` item with a fresh UUIDv4 identifier.
    pub fn new_secure_note(title: impl Into<String>, notes: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            schema_version: VAULT_ITEM_SCHEMA_VERSION,
            kind: ItemKind::SecureNote,
            title: title.into(),
            folder_id: None,
            favorite: false,
            trashed_at: None,
            item_version: 1,
            logo: ItemLogo::default(),
            login: None,
            custom_fields: Vec::new(),
            notes: notes.into(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// Decrypted vault folder metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultFolder {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl VaultFolder {
    /// Creates a new folder with a random UUIDv4 identifier.
    pub fn new(name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            created_at: now,
            updated_at: now,
        }
    }
}

/// Decrypted binary blob (custom account logo) associated with a vault item.
#[derive(Clone, PartialEq, Eq)]
pub struct VaultBlob {
    pub id: Uuid,
    pub item_id: Uuid,
    pub mime_type: String,
    pub data: Zeroizing<Vec<u8>>,
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for VaultBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultBlob")
            .field("id", &self.id)
            .field("item_id", &self.item_id)
            .field("mime_type", &self.mime_type)
            .field("byte_len", &self.data.len())
            .finish()
    }
}

/// Complete decrypted in-memory snapshot of a user vault.
#[derive(Debug, Clone, Default)]
pub struct VaultSnapshot {
    pub folders: Vec<VaultFolder>,
    pub items: Vec<VaultItem>,
    pub blobs: Vec<VaultBlob>,
}

impl VaultSnapshot {
    /// Clears all decrypted entries, folders, and blobs from memory.
    pub fn clear(&mut self) {
        self.items.clear();
        self.folders.clear();
        self.blobs.clear();
    }
}
