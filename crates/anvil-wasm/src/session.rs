//! Volatile WASM linear-memory vault session with zeroized secrets and AAD-validated wire sync.

use std::collections::{HashMap, HashSet};

use anvil_core::crypto::{
    KEY_LEN, KdfParams, MasterPassword, VaultKey, VaultSubKeys, decrypt_envelope,
    derive_master_key, derive_master_subkeys, derive_vault_subkeys, encrypt_envelope,
    fill_random_bytes, generate_kdf_salt, unwrap_vault_key, wrap_vault_key,
};
use anvil_core::exporters::{export_anvil_archive, export_bitwarden_json, export_csv};
use anvil_core::importers::{
    DuplicatePolicy, ImportFormat, ImportPreview, apply_import, preview_import,
};
use anvil_core::media::{fallback_accent_color, fallback_initials};
use anvil_core::models::{
    CustomField, EncryptedFolderRecord, EncryptedItemRecord, ItemKind, ItemLogo, ItemUri,
    LoginData, PasswordHistoryEntry, VAULT_ITEM_SCHEMA_VERSION, VaultFolder, VaultItem,
    VaultSnapshot, decrypt_folder, decrypt_item, encrypt_folder, encrypt_item,
};
use anvil_core::password::{
    PassphraseConfig, PasswordGeneratorConfig, evaluate_password_strength, generate_passphrase,
    generate_password,
};
use anvil_core::search::{find_matching_items, search_items};
use anvil_core::totp::{TotpCode, TotpConfig};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::error::WasmError;
use crate::security::{AutofillSecurityVerdict, evaluate_autofill_context, verify_item_autofill};

const MV3_SESSION_TTL_MAX_SECONDS: u64 = 3600;

/// Account KDF + wrapped `VaultKey` metadata persisted encrypted on the extension side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmAccountMeta {
    pub user_id: Uuid,
    pub email: String,
    pub kdf_params: KdfParams,
    pub kdf_salt_b64: String,
    pub key_version: u32,
    pub encrypted_vault_key_b64: String,
}

/// Server/cache wire representation of an encrypted folder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFolderEnvelopeDto {
    pub id: Uuid,
    pub encrypted_data_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Server/cache wire representation of an encrypted vault item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedItemEnvelopeDto {
    pub id: Uuid,
    pub encrypted_data_b64: String,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Output of client-side Zero-Knowledge registration key generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationPayloadDto {
    pub user_id: Uuid,
    pub email: String,
    pub kdf_params: KdfParams,
    pub kdf_salt_b64: String,
    pub master_auth_hash_b64: String,
    pub encrypted_vault_key_b64: String,
}

/// Derived authentication hash and wrapped key candidate produced for `/auth/login`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAuthDerivationDto {
    pub master_auth_hash_b64: String,
}

/// Short-lived MV3 Service Worker resume envelope wrapping `VaultKey` under a random key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EphemeralSessionSealDto {
    pub user_id: Uuid,
    pub key_version: u32,
    pub sealed_vault_key_b64: String,
    pub ephemeral_key_b64: String,
    pub expires_at_unix: u64,
}

/// Plaintext folder DTO exposed to the ephemeral popup UI while unlocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmFolderDto {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Non-secret summary row matching `@anvil/ui` `ItemSummaryDto`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmItemSummaryDto {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub trashed: bool,
    pub subtitle: String,
    pub primary_url: Option<String>,
    pub has_totp: bool,
    pub logo_blob_id: Option<String>,
    pub fallback_color: String,
    pub fallback_initials: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemLogoDto {
    pub blob_id: Option<String>,
    pub fallback_color: String,
    pub data_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginDataDto {
    pub username: String,
    pub email: String,
    pub password: String,
    pub password_history: Vec<PasswordHistoryEntry>,
    pub uris: Vec<ItemUri>,
    pub totp: Option<TotpConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmItemDetailDto {
    pub id: String,
    pub schema_version: u32,
    pub kind: ItemKind,
    pub title: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub trashed_at: Option<String>,
    pub item_version: u64,
    pub logo: ItemLogoDto,
    pub login: Option<LoginDataDto>,
    pub custom_fields: Vec<CustomField>,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveItemInputDto {
    pub id: Option<String>,
    pub kind: ItemKind,
    pub title: String,
    pub folder_id: Option<String>,
    pub favorite: bool,
    pub trashed_at: Option<String>,
    pub login: Option<LoginDataDto>,
    pub custom_fields: Vec<CustomField>,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlMatchResponseDto {
    pub security: AutofillSecurityVerdict,
    pub items: Vec<WasmItemSummaryDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutofillCredentialDto {
    pub item_id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub totp_code: Option<String>,
    pub security: AutofillSecurityVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordGenOptionsDto {
    pub mode: String,
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub word_count: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrengthDto {
    pub score: u8,
    pub entropy_bits: f64,
    pub crack_time_display: String,
    pub feedback_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedPasswordDto {
    pub value: String,
    pub strength: PasswordStrengthDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateCandidateDto {
    pub imported_index: usize,
    pub existing_item_id: String,
    pub title: String,
    pub identity: String,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportPreviewDto {
    pub preview_id: String,
    pub total_items: usize,
    pub folder_count: usize,
    pub totp_count: usize,
    pub duplicates: Vec<DuplicateCandidateDto>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReportDto {
    pub created: usize,
    pub merged: usize,
    pub skipped: usize,
    pub folders_created: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportCommitPayloadDto {
    pub report: ImportReportDto,
    pub encrypted_folders: Vec<EncryptedFolderEnvelopeDto>,
    pub encrypted_items: Vec<EncryptedItemEnvelopeDto>,
}

struct UnlockedWasmState {
    user_id: Uuid,
    key_version: u32,
    vault_key: VaultKey,
    subkeys: VaultSubKeys,
    folders: Vec<VaultFolder>,
    items: Vec<VaultItem>,
    pending_imports: HashMap<Uuid, ImportPreview>,
}

impl Drop for UnlockedWasmState {
    fn drop(&mut self) {
        self.items.clear();
        self.folders.clear();
        self.pending_imports.clear();
    }
}

/// Volatile linear-memory session holding decrypted keys only between unlock and lock().
#[derive(Default)]
pub struct WasmVaultSession {
    state: Option<UnlockedWasmState>,
}

impl std::fmt::Debug for WasmVaultSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmVaultSession")
            .field("unlocked", &self.state.is_some())
            .finish()
    }
}

impl WasmVaultSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_unlocked(&self) -> bool {
        self.state.is_some()
    }

    /// Immediately wipes `VaultKey`, subkeys, decrypted items, and pending imports from WASM RAM.
    pub fn lock(&mut self) {
        self.state = None;
    }

    /// Unlocks from local encrypted envelopes using the Master Password.
    pub fn unlock_with_password(
        &mut self,
        account: &WasmAccountMeta,
        master_password: &str,
        encrypted_folders: &[EncryptedFolderEnvelopeDto],
        encrypted_items: &[EncryptedItemEnvelopeDto],
    ) -> Result<(), WasmError> {
        account.kdf_params.validate()?;
        let salt = decode_fixed_32(&account.kdf_salt_b64, "kdf_salt_b64")?;
        let wrapped_vk = STANDARD
            .decode(account.encrypted_vault_key_b64.trim())
            .map_err(|_| WasmError::InvalidInput("invalid encrypted_vault_key_b64".to_owned()))?;

        let pw = MasterPassword::new(master_password);
        let mk = derive_master_key(&pw, &salt, &account.kdf_params)?;
        let (mek, _) = derive_master_subkeys(&mk, &salt)?;
        let vault_key = unwrap_vault_key(&mek, &wrapped_vk, account.user_id, account.key_version)
            .map_err(|_| WasmError::InvalidMasterPassword)?;

        self.activate_with_vault_key(
            account.user_id,
            account.key_version,
            vault_key,
            encrypted_folders,
            encrypted_items,
        )
    }

    /// Wraps the active `VaultKey` into a short-lived MV3 hibernation seal bound to expiration timestamp.
    pub fn export_ephemeral_session(
        &self,
        ttl_seconds: u64,
        now_unix: u64,
    ) -> Result<EphemeralSessionSealDto, WasmError> {
        let st = self.require_unlocked()?;
        if ttl_seconds == 0 || ttl_seconds > MV3_SESSION_TTL_MAX_SECONDS {
            return Err(WasmError::InvalidInput(
                "ephemeral TTL must be between 1 and 3600 seconds".to_owned(),
            ));
        }

        let expires_at_unix = now_unix.saturating_add(ttl_seconds);
        let mut ephemeral_key = Zeroizing::new([0u8; KEY_LEN]);
        fill_random_bytes(&mut *ephemeral_key)?;

        let aad = mv3_session_aad(st.user_id, expires_at_unix);
        let sealed = encrypt_envelope(&ephemeral_key, st.vault_key.as_bytes(), &aad)?;

        Ok(EphemeralSessionSealDto {
            user_id: st.user_id,
            key_version: st.key_version,
            sealed_vault_key_b64: STANDARD.encode(sealed),
            ephemeral_key_b64: STANDARD.encode(*ephemeral_key),
            expires_at_unix,
        })
    }

    /// Resumes an active MV3 session after Service Worker hibernation after validating expiry & AAD.
    pub fn unlock_with_ephemeral_session(
        &mut self,
        account: &WasmAccountMeta,
        seal: &EphemeralSessionSealDto,
        now_unix: u64,
        encrypted_folders: &[EncryptedFolderEnvelopeDto],
        encrypted_items: &[EncryptedItemEnvelopeDto],
    ) -> Result<(), WasmError> {
        if seal.user_id != account.user_id {
            return Err(WasmError::InvalidInput(
                "ephemeral seal user_id mismatch".to_owned(),
            ));
        }
        if now_unix > seal.expires_at_unix {
            return Err(WasmError::SessionExpired);
        }

        let mut eph_bytes = Zeroizing::new(decode_fixed_32(
            &seal.ephemeral_key_b64,
            "ephemeral_key_b64",
        )?);
        let sealed_bytes = STANDARD
            .decode(seal.sealed_vault_key_b64.trim())
            .map_err(|_| WasmError::InvalidInput("invalid sealed_vault_key_b64".to_owned()))?;

        let aad = mv3_session_aad(seal.user_id, seal.expires_at_unix);
        let raw_vk = decrypt_envelope(&eph_bytes, &sealed_bytes, &aad)?;
        eph_bytes.zeroize();
        let vault_key = VaultKey::from_slice(&raw_vk)?;

        self.activate_with_vault_key(
            account.user_id,
            seal.key_version,
            vault_key,
            encrypted_folders,
            encrypted_items,
        )
    }

    /// Decrypts server delta records and merges them cleanly into the unlocked WASM state.
    pub fn apply_sync_delta(
        &mut self,
        encrypted_folders: &[EncryptedFolderEnvelopeDto],
        encrypted_items: &[EncryptedItemEnvelopeDto],
    ) -> Result<(), WasmError> {
        let st = self.state.as_mut().ok_or(WasmError::VaultLocked)?;

        for folder_env in encrypted_folders {
            if folder_env.deleted {
                st.folders.retain(|f| f.id != folder_env.id);
            } else {
                let decrypted = decrypt_folder_dto(&st.subkeys, st.user_id, folder_env)?;
                if let Some(slot) = st.folders.iter_mut().find(|f| f.id == decrypted.id) {
                    *slot = decrypted;
                } else {
                    st.folders.push(decrypted);
                }
            }
        }

        for item_env in encrypted_items {
            if item_env.deleted {
                st.items.retain(|i| i.id != item_env.id);
            } else {
                let decrypted = decrypt_item_dto(&st.subkeys, st.user_id, item_env)?;
                if let Some(slot) = st.items.iter_mut().find(|i| i.id == decrypted.id) {
                    *slot = decrypted;
                } else {
                    st.items.push(decrypted);
                }
            }
        }

        Ok(())
    }

    pub fn list_folders(&self) -> Result<Vec<WasmFolderDto>, WasmError> {
        let st = self.require_unlocked()?;
        let mut folders: Vec<WasmFolderDto> = st
            .folders
            .iter()
            .map(|f| WasmFolderDto {
                id: f.id.to_string(),
                name: f.name.clone(),
                created_at: f.created_at.to_rfc3339(),
                updated_at: f.updated_at.to_rfc3339(),
            })
            .collect();
        folders.sort_by_key(|a| a.name.to_lowercase());
        Ok(folders)
    }

    /// Encrypts a folder creation/rename into a wire envelope ready for `/vault/sync` & cache.
    pub fn encrypt_folder_upsert(
        &mut self,
        id: Option<&str>,
        name: &str,
    ) -> Result<(WasmFolderDto, EncryptedFolderEnvelopeDto), WasmError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(WasmError::InvalidInput(
                "folder name cannot be empty".to_owned(),
            ));
        }
        let st = self.state.as_mut().ok_or(WasmError::VaultLocked)?;
        let now = Utc::now();

        let folder = match id.filter(|s| !s.trim().is_empty()) {
            Some(raw_id) => {
                let fid = parse_uuid(raw_id)?;
                let existing = st
                    .folders
                    .iter_mut()
                    .find(|f| f.id == fid)
                    .ok_or(WasmError::NotFound)?;
                existing.name = trimmed.to_owned();
                existing.updated_at = now;
                existing.clone()
            }
            None => {
                let created = VaultFolder::new(trimmed);
                st.folders.push(created.clone());
                created
            }
        };

        let rec = encrypt_folder(&st.subkeys, st.user_id, &folder, 1)?;
        let envelope = EncryptedFolderEnvelopeDto {
            id: rec.id,
            encrypted_data_b64: STANDARD.encode(&rec.encrypted_data),
            revision: rec.revision,
            deleted: rec.deleted,
            updated_at: rec.updated_at,
        };
        let dto = WasmFolderDto {
            id: folder.id.to_string(),
            name: folder.name,
            created_at: folder.created_at.to_rfc3339(),
            updated_at: folder.updated_at.to_rfc3339(),
        };
        Ok((dto, envelope))
    }

    /// Encrypts an item create/update into a wire envelope preserving password history.
    pub fn encrypt_item_upsert(
        &mut self,
        input: SaveItemInputDto,
    ) -> Result<(WasmItemDetailDto, EncryptedItemEnvelopeDto), WasmError> {
        let title = input.title.trim();
        if title.is_empty() {
            return Err(WasmError::InvalidInput(
                "item title cannot be empty".to_owned(),
            ));
        }
        let folder_id = input
            .folder_id
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(parse_uuid)
            .transpose()?;
        let trashed_at = input
            .trashed_at
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(parse_rfc3339)
            .transpose()?;

        let st = self.state.as_mut().ok_or(WasmError::VaultLocked)?;
        let now = Utc::now();

        let existing = match input.id.as_deref().filter(|s| !s.is_empty()) {
            Some(raw_id) => {
                let item_id = parse_uuid(raw_id)?;
                st.items.iter().find(|i| i.id == item_id).cloned()
            }
            None => None,
        };

        let login = input.login.map(|in_login| {
            let mut history = in_login.password_history;
            if let Some(prev_pw) = existing
                .as_ref()
                .and_then(|ex| ex.login.as_ref())
                .map(|ex_l| ex_l.password.as_str())
                .filter(|pw| !pw.is_empty() && *pw != in_login.password)
            {
                let already_recorded = history.iter().any(|h| h.password == prev_pw);
                if !already_recorded {
                    history.insert(
                        0,
                        PasswordHistoryEntry {
                            password: prev_pw.to_owned(),
                            changed_at: now,
                        },
                    );
                }
            }
            LoginData {
                username: in_login.username,
                email: in_login.email,
                password: in_login.password,
                password_history: history,
                uris: in_login
                    .uris
                    .into_iter()
                    .filter(|u| !u.uri.trim().is_empty())
                    .map(|u| ItemUri {
                        uri: u.uri.trim().to_owned(),
                        match_mode: u.match_mode,
                    })
                    .collect(),
                totp: in_login.totp,
            }
        });

        let item = match existing {
            Some(mut ex) => {
                ex.kind = input.kind;
                ex.title = title.to_owned();
                ex.folder_id = folder_id;
                ex.favorite = input.favorite;
                ex.trashed_at = trashed_at;
                ex.item_version = ex.item_version.saturating_add(1);
                ex.logo.fallback_color = fallback_accent_color(title).to_owned();
                ex.login = login;
                ex.custom_fields = input.custom_fields;
                ex.notes = input.notes;
                ex.updated_at = now;
                ex
            }
            None => VaultItem {
                id: Uuid::new_v4(),
                schema_version: VAULT_ITEM_SCHEMA_VERSION,
                kind: input.kind,
                title: title.to_owned(),
                folder_id,
                favorite: input.favorite,
                trashed_at,
                item_version: 1,
                logo: ItemLogo {
                    blob_id: None,
                    fallback_color: fallback_accent_color(title).to_owned(),
                },
                login,
                custom_fields: input.custom_fields,
                notes: input.notes,
                created_at: now,
                updated_at: now,
            },
        };

        let rec = encrypt_item(&st.subkeys, st.user_id, &item, 1)?;
        if let Some(slot) = st.items.iter_mut().find(|i| i.id == item.id) {
            *slot = item.clone();
        } else {
            st.items.push(item.clone());
        }

        let detail = item_to_detail_dto(&item);
        let envelope = EncryptedItemEnvelopeDto {
            id: rec.id,
            encrypted_data_b64: STANDARD.encode(&rec.encrypted_data),
            revision: rec.revision,
            deleted: rec.deleted,
            updated_at: rec.updated_at,
        };
        Ok((detail, envelope))
    }

    pub fn remove_item_local(&mut self, item_id: &str) -> Result<Uuid, WasmError> {
        let id = parse_uuid(item_id)?;
        let st = self.state.as_mut().ok_or(WasmError::VaultLocked)?;
        let before = st.items.len();
        st.items.retain(|i| i.id != id);
        if st.items.len() == before {
            return Err(WasmError::NotFound);
        }
        Ok(id)
    }

    pub fn remove_folder_local(&mut self, folder_id: &str) -> Result<Uuid, WasmError> {
        let id = parse_uuid(folder_id)?;
        let st = self.state.as_mut().ok_or(WasmError::VaultLocked)?;
        let before = st.folders.len();
        st.folders.retain(|f| f.id != id);
        if st.folders.len() == before {
            return Err(WasmError::NotFound);
        }
        Ok(id)
    }

    pub fn search_items(
        &self,
        query: &str,
        folder_id: Option<&str>,
        favorites_only: bool,
        trashed_only: bool,
    ) -> Result<Vec<WasmItemSummaryDto>, WasmError> {
        let st = self.require_unlocked()?;
        let parsed_folder = folder_id
            .filter(|s| !s.is_empty())
            .map(parse_uuid)
            .transpose()?;

        let filtered: Vec<&VaultItem> = st
            .items
            .iter()
            .filter(|item| {
                let is_trashed = item.trashed_at.is_some();
                if trashed_only != is_trashed {
                    return false;
                }
                if favorites_only && !item.favorite {
                    return false;
                }
                if let Some(fid) = parsed_folder
                    && item.folder_id != Some(fid)
                {
                    return false;
                }
                true
            })
            .collect();

        let trimmed = query.trim();
        if trimmed.is_empty() {
            let mut rows: Vec<WasmItemSummaryDto> =
                filtered.into_iter().map(summarize_wasm_item).collect();
            rows.sort_by_key(|a| a.title.to_lowercase());
            return Ok(rows);
        }

        let by_id: HashMap<Uuid, &VaultItem> = filtered.iter().map(|i| (i.id, *i)).collect();
        let candidates: Vec<VaultItem> = filtered.into_iter().cloned().collect();
        let hits = find_or_search_order(&candidates, &st.folders, trimmed);
        Ok(hits
            .into_iter()
            .filter_map(|id| by_id.get(&id).copied().map(summarize_wasm_item))
            .collect())
    }

    /// Evaluates frame anti-phishing policy and returns matching credentials for the active URL.
    pub fn match_items_for_url(
        &self,
        top_frame_url: &str,
        active_frame_url: &str,
        is_iframe: bool,
        approved_iframe_origins: &[String],
    ) -> Result<UrlMatchResponseDto, WasmError> {
        let st = self.require_unlocked()?;
        let security = evaluate_autofill_context(
            top_frame_url,
            active_frame_url,
            is_iframe,
            approved_iframe_origins,
        );
        if !security.allowed {
            return Ok(UrlMatchResponseDto {
                security,
                items: Vec::new(),
            });
        }

        let matched_ids = find_matching_items(&st.items, active_frame_url);
        let items: Vec<WasmItemSummaryDto> = matched_ids
            .into_iter()
            .filter_map(|id| st.items.iter().find(|item| item.id == id))
            .filter(|item| {
                verify_item_autofill(
                    item,
                    top_frame_url,
                    active_frame_url,
                    is_iframe,
                    approved_iframe_origins,
                )
                .allowed
            })
            .map(summarize_wasm_item)
            .collect();

        Ok(UrlMatchResponseDto { security, items })
    }

    /// Returns autofill credentials for `item_id` ONLY when strict anti-phishing & URI checks pass.
    pub fn get_autofill_credentials(
        &self,
        item_id: &str,
        top_frame_url: &str,
        active_frame_url: &str,
        is_iframe: bool,
        approved_iframe_origins: &[String],
        unix_timestamp_seconds: u64,
    ) -> Result<AutofillCredentialDto, WasmError> {
        let st = self.require_unlocked()?;
        let id = parse_uuid(item_id)?;
        let item = st
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or(WasmError::NotFound)?;

        let security = verify_item_autofill(
            item,
            top_frame_url,
            active_frame_url,
            is_iframe,
            approved_iframe_origins,
        );
        if !security.allowed {
            return Err(WasmError::AutofillBlocked(security.reasons.join("; ")));
        }

        let login = item
            .login
            .as_ref()
            .ok_or_else(|| WasmError::InvalidInput("item has no login credentials".to_owned()))?;
        let username = if !login.username.trim().is_empty() {
            login.username.clone()
        } else {
            login.email.clone()
        };
        let totp_code = match login.totp.as_ref() {
            Some(totp) => Some(totp.generate_at(unix_timestamp_seconds)?.code),
            None => None,
        };

        Ok(AutofillCredentialDto {
            item_id: item.id.to_string(),
            title: item.title.clone(),
            username,
            password: login.password.clone(),
            totp_code,
            security,
        })
    }

    pub fn get_item_detail(&self, item_id: &str) -> Result<WasmItemDetailDto, WasmError> {
        let st = self.require_unlocked()?;
        let id = parse_uuid(item_id)?;
        let item = st
            .items
            .iter()
            .find(|i| i.id == id)
            .ok_or(WasmError::NotFound)?;
        Ok(item_to_detail_dto(item))
    }

    pub fn generate_totp(
        &self,
        secret_or_uri: &str,
        unix_timestamp_seconds: u64,
    ) -> Result<TotpCode, WasmError> {
        let _ = self.require_unlocked()?;
        let cfg = TotpConfig::from_input(secret_or_uri)?;
        Ok(cfg.generate_at(unix_timestamp_seconds)?)
    }

    pub fn preview_import(
        &mut self,
        format: ImportFormat,
        bytes: &[u8],
        backup_password: Option<&str>,
    ) -> Result<ImportPreviewDto, WasmError> {
        let st = self.state.as_mut().ok_or(WasmError::VaultLocked)?;
        let snapshot = VaultSnapshot {
            folders: st.folders.clone(),
            items: st.items.clone(),
            blobs: Vec::new(),
        };
        let preview = preview_import(format, bytes, backup_password, &snapshot)?;
        let preview_id = Uuid::new_v4();
        let dto = ImportPreviewDto {
            preview_id: preview_id.to_string(),
            total_items: preview.total_items,
            folder_count: preview.parsed.folders.len(),
            totp_count: preview.totp_count,
            duplicates: preview
                .duplicates
                .iter()
                .map(|d| DuplicateCandidateDto {
                    imported_index: d.imported_index,
                    existing_item_id: d.existing_item_id.to_string(),
                    title: d.title.clone(),
                    identity: d.identity.clone(),
                    domain: d.domain.clone(),
                })
                .collect(),
            warnings: preview.parsed.warnings.clone(),
        };
        st.pending_imports.insert(preview_id, preview);
        Ok(dto)
    }

    pub fn execute_import(
        &mut self,
        preview_id: &str,
        policy: DuplicatePolicy,
    ) -> Result<ImportCommitPayloadDto, WasmError> {
        let pid = parse_uuid(preview_id)?;
        let st = self.state.as_mut().ok_or(WasmError::VaultLocked)?;
        let preview = st
            .pending_imports
            .remove(&pid)
            .ok_or(WasmError::ImportPreviewNotFound)?;

        let before_folders: HashSet<Uuid> = st.folders.iter().map(|f| f.id).collect();
        let before_items: HashMap<Uuid, VaultItem> =
            st.items.iter().map(|i| (i.id, i.clone())).collect();

        let mut working = VaultSnapshot {
            folders: st.folders.clone(),
            items: st.items.clone(),
            blobs: Vec::new(),
        };
        let summary = apply_import(preview, policy, &mut working);

        let mut encrypted_folders = Vec::new();
        for folder in &working.folders {
            if !before_folders.contains(&folder.id) {
                let rec = encrypt_folder(&st.subkeys, st.user_id, folder, 1)?;
                encrypted_folders.push(EncryptedFolderEnvelopeDto {
                    id: rec.id,
                    encrypted_data_b64: STANDARD.encode(&rec.encrypted_data),
                    revision: rec.revision,
                    deleted: rec.deleted,
                    updated_at: rec.updated_at,
                });
            }
        }

        let mut encrypted_items = Vec::new();
        for item in &working.items {
            let changed = match before_items.get(&item.id) {
                Some(prev) => prev != item,
                None => true,
            };
            if changed {
                let rec = encrypt_item(&st.subkeys, st.user_id, item, 1)?;
                encrypted_items.push(EncryptedItemEnvelopeDto {
                    id: rec.id,
                    encrypted_data_b64: STANDARD.encode(&rec.encrypted_data),
                    revision: rec.revision,
                    deleted: rec.deleted,
                    updated_at: rec.updated_at,
                });
            }
        }

        st.folders = working.folders;
        st.items = working.items;

        Ok(ImportCommitPayloadDto {
            report: ImportReportDto {
                created: summary.created,
                merged: summary.merged,
                skipped: summary.skipped,
                folders_created: summary.folders_created,
                warnings: summary.warnings,
            },
            encrypted_folders,
            encrypted_items,
        })
    }

    pub fn export_vault(
        &self,
        account: &WasmAccountMeta,
        format: &str,
        master_password: &str,
        backup_password: Option<&str>,
    ) -> Result<Vec<u8>, WasmError> {
        let st = self.require_unlocked()?;
        account.kdf_params.validate()?;
        let salt = decode_fixed_32(&account.kdf_salt_b64, "kdf_salt_b64")?;
        let wrapped_vk = STANDARD
            .decode(account.encrypted_vault_key_b64.trim())
            .map_err(|_| WasmError::InvalidInput("invalid encrypted_vault_key_b64".to_owned()))?;
        let pw = MasterPassword::new(master_password);
        let mk = derive_master_key(&pw, &salt, &account.kdf_params)?;
        let (mek, _) = derive_master_subkeys(&mk, &salt)?;
        let _ = unwrap_vault_key(&mek, &wrapped_vk, account.user_id, account.key_version)
            .map_err(|_| WasmError::InvalidMasterPassword)?;

        let snapshot = VaultSnapshot {
            folders: st.folders.clone(),
            items: st.items.clone(),
            blobs: Vec::new(),
        };

        match format.trim().to_ascii_lowercase().as_str() {
            "anvil" => {
                let archive_pw = backup_password
                    .filter(|p| !p.is_empty())
                    .map(MasterPassword::new)
                    .unwrap_or_else(|| MasterPassword::new(master_password));
                Ok(export_anvil_archive(&snapshot, &archive_pw)?)
            }
            "bitwarden_json" => Ok(export_bitwarden_json(&snapshot)?.into_bytes()),
            "csv" => Ok(export_csv(&snapshot)?.into_bytes()),
            other => Err(WasmError::InvalidInput(format!(
                "unsupported export format: {other}"
            ))),
        }
    }

    fn require_unlocked(&self) -> Result<&UnlockedWasmState, WasmError> {
        self.state.as_ref().ok_or(WasmError::VaultLocked)
    }

    fn activate_with_vault_key(
        &mut self,
        user_id: Uuid,
        key_version: u32,
        vault_key: VaultKey,
        encrypted_folders: &[EncryptedFolderEnvelopeDto],
        encrypted_items: &[EncryptedItemEnvelopeDto],
    ) -> Result<(), WasmError> {
        let subkeys = derive_vault_subkeys(&vault_key)?;

        let mut folders = Vec::new();
        for f in encrypted_folders {
            if !f.deleted {
                folders.push(decrypt_folder_dto(&subkeys, user_id, f)?);
            }
        }

        let mut items = Vec::new();
        for i in encrypted_items {
            if !i.deleted {
                items.push(decrypt_item_dto(&subkeys, user_id, i)?);
            }
        }

        self.state = Some(UnlockedWasmState {
            user_id,
            key_version,
            vault_key,
            subkeys,
            folders,
            items,
            pending_imports: HashMap::new(),
        });
        Ok(())
    }
}

/// Derives client Zero-Knowledge registration parameters & wrapped `VaultKey`.
pub fn prepare_registration(
    email: &str,
    master_password: &str,
    kdf_params: KdfParams,
) -> Result<RegistrationPayloadDto, WasmError> {
    kdf_params.validate()?;
    let user_id = Uuid::new_v4();
    let kdf_salt = generate_kdf_salt()?;
    let pw = MasterPassword::new(master_password);
    let mk = derive_master_key(&pw, &kdf_salt, &kdf_params)?;
    let (mek, auth_hash) = derive_master_subkeys(&mk, &kdf_salt)?;
    let vault_key = VaultKey::generate()?;
    let wrapped_vk = wrap_vault_key(&mek, &vault_key, user_id, 1)?;

    Ok(RegistrationPayloadDto {
        user_id,
        email: email.trim().to_lowercase(),
        kdf_params,
        kdf_salt_b64: STANDARD.encode(kdf_salt),
        master_auth_hash_b64: STANDARD.encode(auth_hash.as_bytes()),
        encrypted_vault_key_b64: STANDARD.encode(wrapped_vk),
    })
}

/// Derives only `master_auth_hash_b64` from prelogin salt + KDF parameters for `/auth/login`.
pub fn derive_login_auth(
    master_password: &str,
    kdf_salt_b64: &str,
    kdf_params: KdfParams,
) -> Result<LoginAuthDerivationDto, WasmError> {
    kdf_params.validate()?;
    let salt = decode_fixed_32(kdf_salt_b64, "kdf_salt_b64")?;
    let pw = MasterPassword::new(master_password);
    let mk = derive_master_key(&pw, &salt, &kdf_params)?;
    let (_, auth_hash) = derive_master_subkeys(&mk, &salt)?;
    Ok(LoginAuthDerivationDto {
        master_auth_hash_b64: STANDARD.encode(auth_hash.as_bytes()),
    })
}

/// Generates a CSPRNG password or diceware passphrase along with zxcvbn entropy feedback.
pub fn generate_password_with_strength(
    options: PasswordGenOptionsDto,
) -> Result<GeneratedPasswordDto, WasmError> {
    let generated = if options.mode.eq_ignore_ascii_case("passphrase") {
        generate_passphrase(&PassphraseConfig {
            word_count: options.word_count,
            separator: options.separator,
            capitalize: options.capitalize,
            include_number: options.include_number,
        })?
    } else {
        generate_password(&PasswordGeneratorConfig {
            length: options.length,
            uppercase: options.uppercase,
            lowercase: options.lowercase,
            digits: options.digits,
            symbols: options.symbols,
            exclude_ambiguous: options.exclude_ambiguous,
            min_digits: usize::from(options.digits),
            min_symbols: usize::from(options.symbols),
        })?
    };

    let strength = evaluate_password_dto(&generated);
    Ok(GeneratedPasswordDto {
        value: (*generated).clone(),
        strength,
    })
}

/// Evaluates password strength and zxcvbn crack-time estimate cleanly without network calls.
pub fn evaluate_password_dto(value: &str) -> PasswordStrengthDto {
    let strength = evaluate_password_strength(value, &[]);
    PasswordStrengthDto {
        score: strength.score,
        entropy_bits: strength.entropy_bits,
        crack_time_display: strength.crack_time_display,
        feedback_warning: strength.feedback_warning,
    }
}

fn find_or_search_order(items: &[VaultItem], folders: &[VaultFolder], query: &str) -> Vec<Uuid> {
    search_items(items, folders, query)
        .into_iter()
        .map(|hit| hit.item_id)
        .collect()
}

fn summarize_wasm_item(item: &VaultItem) -> WasmItemSummaryDto {
    let subtitle = item
        .login
        .as_ref()
        .map(|l| {
            if !l.email.is_empty() {
                l.email.clone()
            } else {
                l.username.clone()
            }
        })
        .unwrap_or_default();
    let primary_url = item
        .login
        .as_ref()
        .and_then(|l| l.uris.first())
        .map(|u| u.uri.clone());

    WasmItemSummaryDto {
        id: item.id.to_string(),
        kind: item.kind,
        title: item.title.clone(),
        folder_id: item.folder_id.map(|u| u.to_string()),
        favorite: item.favorite,
        trashed: item.trashed_at.is_some(),
        subtitle,
        primary_url,
        has_totp: item.login.as_ref().and_then(|l| l.totp.as_ref()).is_some(),
        logo_blob_id: item.logo.blob_id.map(|u| u.to_string()),
        fallback_color: item.logo.fallback_color.clone(),
        fallback_initials: fallback_initials(&item.title),
        updated_at: item.updated_at.to_rfc3339(),
    }
}

fn item_to_detail_dto(item: &VaultItem) -> WasmItemDetailDto {
    WasmItemDetailDto {
        id: item.id.to_string(),
        schema_version: item.schema_version,
        kind: item.kind,
        title: item.title.clone(),
        folder_id: item.folder_id.map(|u| u.to_string()),
        favorite: item.favorite,
        trashed_at: item.trashed_at.map(|ts| ts.to_rfc3339()),
        item_version: item.item_version,
        logo: ItemLogoDto {
            blob_id: item.logo.blob_id.map(|u| u.to_string()),
            fallback_color: item.logo.fallback_color.clone(),
            data_url: None,
        },
        login: item.login.as_ref().map(|l| LoginDataDto {
            username: l.username.clone(),
            email: l.email.clone(),
            password: l.password.clone(),
            password_history: l.password_history.clone(),
            uris: l.uris.clone(),
            totp: l.totp.clone(),
        }),
        custom_fields: item.custom_fields.clone(),
        notes: item.notes.clone(),
        created_at: item.created_at.to_rfc3339(),
        updated_at: item.updated_at.to_rfc3339(),
    }
}

fn decrypt_folder_dto(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    dto: &EncryptedFolderEnvelopeDto,
) -> Result<VaultFolder, WasmError> {
    let raw = STANDARD
        .decode(dto.encrypted_data_b64.trim())
        .map_err(|_| WasmError::InvalidInput("invalid folder base64 ciphertext".to_owned()))?;
    let rec = EncryptedFolderRecord {
        id: dto.id,
        encrypted_data: raw,
        revision: dto.revision,
        deleted: dto.deleted,
        updated_at: dto.updated_at,
    };
    Ok(decrypt_folder(subkeys, user_id, &rec)?)
}

fn decrypt_item_dto(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    dto: &EncryptedItemEnvelopeDto,
) -> Result<VaultItem, WasmError> {
    let raw = STANDARD
        .decode(dto.encrypted_data_b64.trim())
        .map_err(|_| WasmError::InvalidInput("invalid item base64 ciphertext".to_owned()))?;
    let rec = EncryptedItemRecord {
        id: dto.id,
        encrypted_data: raw,
        revision: dto.revision,
        deleted: dto.deleted,
        updated_at: dto.updated_at,
    };
    Ok(decrypt_item(subkeys, user_id, &rec)?)
}

fn mv3_session_aad(user_id: Uuid, expires_at_unix: u64) -> Vec<u8> {
    format!(
        "anvil:v1:mv3-session|{}|{expires_at_unix}",
        user_id.hyphenated()
    )
    .into_bytes()
}

fn decode_fixed_32(b64: &str, field: &str) -> Result<[u8; 32], WasmError> {
    let bytes = STANDARD
        .decode(b64.trim())
        .map_err(|_| WasmError::InvalidInput(format!("invalid base64 in {field}")))?;
    if bytes.len() != 32 {
        return Err(WasmError::InvalidInput(format!(
            "{field} must decode to 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_uuid(raw: &str) -> Result<Uuid, WasmError> {
    Uuid::parse_str(raw.trim()).map_err(|err| WasmError::InvalidInput(err.to_string()))
}

fn parse_rfc3339(raw: &str) -> Result<DateTime<Utc>, WasmError> {
    DateTime::parse_from_rfc3339(raw.trim())
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| WasmError::InvalidInput(err.to_string()))
}
