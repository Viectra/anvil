//! Typed IPC command host connecting Svelte `@anvil/ui` to `anvil-client-core` and OS security hooks.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use anvil_client_core::api_client::AnvilApiClient;
use anvil_client_core::cache::EncryptedLocalCache;
use anvil_client_core::error::ClientError;
use anvil_client_core::lock_manager::{DEFAULT_INACTIVITY_TIMEOUT, VaultLockManager};
use anvil_client_core::sync_engine::{
    ClientSyncEngine, ConflictResolution, DecryptedConflictView, SyncReport, account_kdf_params,
    fixed_salt,
};
use anvil_core::crypto::{KdfParams, MasterPassword};
use anvil_core::exporters::{export_anvil_archive, export_bitwarden_json, export_csv};
use anvil_core::importers::{
    DuplicatePolicy, ImportFormat, ImportPreview, apply_import, preview_import,
};
use anvil_core::media::{fallback_accent_color, fallback_initials};
use anvil_core::models::{
    CustomField, ItemKind, ItemLogo, ItemUri, LoginData, PasswordHistoryEntry, UriMatchMode,
    VAULT_ITEM_SCHEMA_VERSION, VaultFolder, VaultItem, VaultSnapshot,
};
use anvil_core::password::{
    PassphraseConfig, PasswordGeneratorConfig, evaluate_password_strength, generate_passphrase,
    generate_password,
};
use anvil_core::totp::{TotpCode, TotpConfig};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::biometric::{BiometricError, BiometricProvider};
use crate::clipboard::{
    ClipboardCopyReceipt, ClipboardError, DEFAULT_CLIPBOARD_CLEAR_TTL, SecureClipboardManager,
};
use crate::platform::windows::{
    OsSessionLockEvent, OsSessionLockMonitor, TitlebarHitConfig, Win32HitZone, WindowRect,
    compute_hit_zone,
};
use crate::tray::{SystemTrayController, TrayVisualState};

/// Errors returned by desktop IPC commands.
#[derive(Debug, Error)]
pub enum DesktopError {
    #[error("{0}")]
    Client(#[from] ClientError),
    #[error("{0}")]
    Core(#[from] anvil_core::error::AnvilError),
    #[error("{0}")]
    Clipboard(#[from] ClipboardError),
    #[error("{0}")]
    Biometric(#[from] BiometricError),
    #[error("biometric unlock has not been enabled for this local account")]
    BiometricNotEnabled,
    #[error("import preview session expired or was not found")]
    ImportPreviewNotFound,
    #[error("invalid identifier or timestamp: {0}")]
    InvalidInput(String),
    #[error("unknown IPC command: {0}")]
    UnknownCommand(String),
    #[error("internal host synchronization error")]
    InternalState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultStatusDto {
    pub configured: bool,
    pub authenticated: bool,
    pub unlocked: bool,
    pub biometric_available: bool,
    pub biometric_enabled: bool,
    pub server_url: Option<String>,
    pub email: Option<String>,
    pub sync_revision: i64,
    pub pending_conflicts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderDto {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemSummaryDto {
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
pub struct ItemDetailDto {
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
pub struct GeneratedPasswordDto {
    pub value: String,
    pub strength: PasswordStrengthDto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordStrengthDto {
    pub score: u8,
    pub entropy_bits: f64,
    pub crack_time_display: String,
    pub feedback_warning: Option<String>,
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
pub struct ConflictItemDto {
    pub conflict_id: String,
    pub entity_id: String,
    pub entity_kind: String,
    pub title: String,
    pub local_summary: String,
    pub server_summary: String,
    pub server_deleted: bool,
    pub server_revision: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowChromeStateDto {
    pub platform: String,
    pub is_maximized: bool,
    pub is_focused: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSourceKindDto {
    BitwardenJson,
    BitwardenEncryptedJson,
    BitwardenCsv,
    ChromeCsv,
    EdgeCsv,
    BraveCsv,
    FirefoxCsv,
    KeePassCsv,
    KeePassXml,
    OnePasswordCsv,
    OnePassword1pux,
    ProtonPassCsv,
    DashlaneCsv,
}

impl From<ImportSourceKindDto> for ImportFormat {
    fn from(value: ImportSourceKindDto) -> Self {
        match value {
            ImportSourceKindDto::BitwardenJson => Self::BitwardenJson,
            ImportSourceKindDto::BitwardenEncryptedJson => Self::BitwardenEncryptedJson,
            ImportSourceKindDto::BitwardenCsv => Self::BitwardenCsv,
            ImportSourceKindDto::ChromeCsv => Self::ChromeCsv,
            ImportSourceKindDto::EdgeCsv => Self::EdgeCsv,
            ImportSourceKindDto::BraveCsv => Self::BraveCsv,
            ImportSourceKindDto::FirefoxCsv => Self::FirefoxCsv,
            ImportSourceKindDto::KeePassCsv => Self::KeePassCsv,
            ImportSourceKindDto::KeePassXml => Self::KeePassXml,
            ImportSourceKindDto::OnePasswordCsv => Self::OnePasswordCsv,
            ImportSourceKindDto::OnePassword1pux => Self::OnePassword1pux,
            ImportSourceKindDto::ProtonPassCsv => Self::ProtonPassCsv,
            ImportSourceKindDto::DashlaneCsv => Self::DashlaneCsv,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormatDto {
    Anvil,
    BitwardenJson,
    Csv,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HitTestRequestDto {
    pub rect: WindowRect,
    pub cursor_x: i32,
    pub cursor_y: i32,
    pub is_maximized: bool,
    pub search_width: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HitTestResponseDto {
    pub zone: Win32HitZone,
    pub code: isize,
}

/// Core command host orchestrating vault sync engine, secure clipboard, OS lock events, and DPAPI seal.
pub struct DesktopCommandHost {
    cache: EncryptedLocalCache,
    engine: Arc<RwLock<Arc<ClientSyncEngine>>>,
    clipboard: Arc<SecureClipboardManager>,
    biometric: Arc<dyn BiometricProvider>,
    tray: Arc<SystemTrayController>,
    lock_monitor: Arc<OsSessionLockMonitor>,
    pending_imports: Mutex<HashMap<Uuid, ImportPreview>>,
    chrome: RwLock<WindowChromeStateDto>,
    device_name: String,
    device_platform: String,
}

impl DesktopCommandHost {
    /// Initializes a desktop host bound to `cache` and installs immediate RAM lock on OS lock/suspend events.
    pub fn new(
        cache: EncryptedLocalCache,
        default_server_url: &str,
        clipboard: Arc<SecureClipboardManager>,
        biometric: Arc<dyn BiometricProvider>,
        tray: Arc<SystemTrayController>,
        lock_monitor: Arc<OsSessionLockMonitor>,
    ) -> Result<Self, DesktopError> {
        let api = AnvilApiClient::new(default_server_url)?;
        let device_platform = current_platform_name().to_owned();
        let device_name = format!("Anvil Desktop ({device_platform})");
        let engine = Arc::new(ClientSyncEngine::new(
            api,
            cache.clone(),
            VaultLockManager::new(DEFAULT_INACTIVITY_TIMEOUT),
            device_name.clone(),
            device_platform.clone(),
        ));
        let engine_holder = Arc::new(RwLock::new(engine));

        let engine_for_hook = Arc::clone(&engine_holder);
        let clipboard_for_hook = Arc::clone(&clipboard);
        let tray_for_hook = Arc::clone(&tray);
        lock_monitor.subscribe(move |evt| {
            tracing::info!(?evt, "OS session transition detected; locking vault RAM");
            if let Ok(guard) = engine_for_hook.read() {
                guard.lock_vault();
            }
            let _ = clipboard_for_hook.clear_on_lock();
            tray_for_hook.set_state(TrayVisualState::Locked);
        });

        Ok(Self {
            cache,
            engine: engine_holder,
            clipboard,
            biometric,
            tray,
            lock_monitor,
            pending_imports: Mutex::new(HashMap::new()),
            chrome: RwLock::new(WindowChromeStateDto {
                platform: device_platform.clone(),
                is_maximized: false,
                is_focused: true,
            }),
            device_name,
            device_platform,
        })
    }

    pub fn tray(&self) -> &Arc<SystemTrayController> {
        &self.tray
    }

    pub fn lock_monitor(&self) -> &Arc<OsSessionLockMonitor> {
        &self.lock_monitor
    }

    pub fn clipboard(&self) -> &Arc<SecureClipboardManager> {
        &self.clipboard
    }

    fn active_engine(&self) -> Result<Arc<ClientSyncEngine>, DesktopError> {
        let guard = self
            .engine
            .read()
            .map_err(|_| DesktopError::InternalState)?;
        Ok(Arc::clone(&guard))
    }

    fn replace_engine_for_server(
        &self,
        server_url: &str,
    ) -> Result<Arc<ClientSyncEngine>, DesktopError> {
        let api = AnvilApiClient::new(server_url)?;
        let next = Arc::new(ClientSyncEngine::new(
            api,
            self.cache.clone(),
            VaultLockManager::new(DEFAULT_INACTIVITY_TIMEOUT),
            self.device_name.clone(),
            self.device_platform.clone(),
        ));
        let mut guard = self
            .engine
            .write()
            .map_err(|_| DesktopError::InternalState)?;
        *guard = Arc::clone(&next);
        Ok(next)
    }

    async fn sync_tray_count(&self, engine: &ClientSyncEngine) {
        if !engine.lock.is_unlocked() {
            self.tray.set_state(TrayVisualState::Locked);
            return;
        }
        let item_count = engine
            .lock
            .snapshot()
            .map(|snap| snap.items.iter().filter(|i| i.trashed_at.is_none()).count())
            .unwrap_or(0);
        self.tray
            .set_state(TrayVisualState::Unlocked { item_count });
    }

    pub async fn cmd_status(&self) -> Result<VaultStatusDto, DesktopError> {
        let engine = self.active_engine()?;
        let account = self.cache.load_account().await?;
        let authenticated = engine.api.has_session().await;
        let unlocked = engine.lock.is_unlocked();

        let (configured, biometric_enabled, server_url, email, sync_revision, pending_conflicts) =
            match account {
                Some(acct) => {
                    let conflicts = self.cache.list_conflicts(acct.user_id).await?;
                    (
                        true,
                        acct.biometric_sealed_vault_key.is_some(),
                        Some(acct.server_url),
                        Some(acct.email),
                        acct.last_synced_revision,
                        conflicts.len(),
                    )
                }
                None => (false, false, None, None, 0, 0),
            };

        Ok(VaultStatusDto {
            configured,
            authenticated,
            unlocked,
            biometric_available: self.biometric.is_available(),
            biometric_enabled,
            server_url,
            email,
            sync_revision,
            pending_conflicts,
        })
    }

    pub async fn cmd_register(
        &self,
        server_url: &str,
        email: &str,
        master_password: &str,
        invite_token: Option<&str>,
    ) -> Result<VaultStatusDto, DesktopError> {
        let engine = self.replace_engine_for_server(server_url)?;
        engine
            .register_and_unlock(email, master_password, invite_token, KdfParams::default())
            .await?;
        self.sync_tray_count(&engine).await;
        self.cmd_status().await
    }

    pub async fn cmd_login(
        &self,
        server_url: &str,
        email: &str,
        master_password: &str,
    ) -> Result<VaultStatusDto, DesktopError> {
        let engine = self.replace_engine_for_server(server_url)?;
        engine.login_and_unlock(email, master_password).await?;
        let _ = engine.sync_now().await;
        self.sync_tray_count(&engine).await;
        self.cmd_status().await
    }

    pub async fn cmd_unlock_password(
        &self,
        master_password: &str,
    ) -> Result<VaultStatusDto, DesktopError> {
        let engine = self.active_engine()?;
        engine.unlock_with_password(master_password).await?;
        self.sync_tray_count(&engine).await;
        self.cmd_status().await
    }

    pub async fn cmd_enable_biometric(
        &self,
        master_password: &str,
    ) -> Result<VaultStatusDto, DesktopError> {
        if !self.biometric.is_available() {
            return Err(DesktopError::Biometric(BiometricError::Unavailable));
        }
        let engine = self.active_engine()?;
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let kdf_salt = fixed_salt(&acct.kdf_salt)?;
        let kdf_params = account_kdf_params(&acct)?;
        let pw = MasterPassword::new(master_password);
        let (_, vault_key) = engine.lock.verify_master_password_reauth(
            &pw,
            &kdf_params,
            &kdf_salt,
            &acct.encrypted_vault_key,
            acct.user_id,
            acct.key_version,
        )?;
        let sealed = self.biometric.seal_vault_key(acct.user_id, &vault_key)?;
        self.cache
            .set_biometric_seal(acct.user_id, Some(&sealed))
            .await?;
        self.cmd_status().await
    }

    pub async fn cmd_unlock_biometric(&self) -> Result<VaultStatusDto, DesktopError> {
        if !self.biometric.is_available() {
            return Err(DesktopError::Biometric(BiometricError::Unavailable));
        }
        let engine = self.active_engine()?;
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let sealed = acct
            .biometric_sealed_vault_key
            .as_deref()
            .ok_or(DesktopError::BiometricNotEnabled)?;
        let vault_key = self.biometric.unseal_vault_key(acct.user_id, sealed)?;
        engine.unlock_with_vault_key(vault_key).await?;
        self.sync_tray_count(&engine).await;
        self.cmd_status().await
    }

    pub async fn cmd_lock(&self) -> Result<VaultStatusDto, DesktopError> {
        let engine = self.active_engine()?;
        engine.lock_vault();
        let _ = self.clipboard.clear_on_lock();
        if let Ok(mut pending) = self.pending_imports.lock() {
            pending.clear();
        }
        self.tray.set_state(TrayVisualState::Locked);
        self.cmd_status().await
    }

    pub async fn cmd_on_os_session_lock(
        &self,
        event: OsSessionLockEvent,
    ) -> Result<VaultStatusDto, DesktopError> {
        self.lock_monitor.trigger(event);
        if let Ok(mut pending) = self.pending_imports.lock() {
            pending.clear();
        }
        self.cmd_status().await
    }

    pub async fn cmd_list_folders(&self) -> Result<Vec<FolderDto>, DesktopError> {
        let engine = self.active_engine()?;
        let folders = engine.lock.list_folders()?;
        Ok(folders
            .into_iter()
            .map(|f| FolderDto {
                id: f.id.to_string(),
                name: f.name,
                created_at: f.created_at.to_rfc3339(),
                updated_at: f.updated_at.to_rfc3339(),
            })
            .collect())
    }

    pub async fn cmd_save_folder(
        &self,
        name: &str,
        id: Option<&str>,
    ) -> Result<FolderDto, DesktopError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(DesktopError::InvalidInput(
                "folder name cannot be empty".to_owned(),
            ));
        }
        let engine = self.active_engine()?;
        let existing_id = id.map(parse_uuid).transpose()?;
        let folder = match existing_id {
            Some(fid) => {
                let mut current = engine
                    .lock
                    .list_folders()?
                    .into_iter()
                    .find(|f| f.id == fid)
                    .ok_or(ClientError::NotFound)?;
                current.name = trimmed.to_owned();
                engine.save_folder(current).await?
            }
            None => engine.save_folder(VaultFolder::new(trimmed)).await?,
        };
        Ok(FolderDto {
            id: folder.id.to_string(),
            name: folder.name,
            created_at: folder.created_at.to_rfc3339(),
            updated_at: folder.updated_at.to_rfc3339(),
        })
    }

    pub async fn cmd_delete_folder(&self, id: &str) -> Result<(), DesktopError> {
        let engine = self.active_engine()?;
        let fid = parse_uuid(id)?;
        engine.delete_folder(fid).await?;
        Ok(())
    }

    pub async fn cmd_list_items(
        &self,
        query: &str,
        folder_id: Option<&str>,
        favorites_only: bool,
        trashed_only: bool,
    ) -> Result<Vec<ItemSummaryDto>, DesktopError> {
        let engine = self.active_engine()?;
        let parsed_folder = folder_id
            .filter(|s| !s.is_empty())
            .map(parse_uuid)
            .transpose()?;
        let summaries =
            engine
                .lock
                .search_summaries(query, parsed_folder, favorites_only, trashed_only)?;
        Ok(summaries
            .into_iter()
            .map(|s| ItemSummaryDto {
                id: s.id.to_string(),
                kind: s.kind,
                title: s.title.clone(),
                folder_id: s.folder_id.map(|u| u.to_string()),
                favorite: s.favorite,
                trashed: s.trashed,
                subtitle: s.subtitle,
                primary_url: s.primary_url,
                has_totp: s.has_totp,
                logo_blob_id: s.logo_blob_id.map(|u| u.to_string()),
                fallback_color: s.fallback_color,
                fallback_initials: fallback_initials(&s.title),
                updated_at: s.updated_at.to_rfc3339(),
            })
            .collect())
    }

    pub async fn cmd_get_item(&self, id: &str) -> Result<ItemDetailDto, DesktopError> {
        let engine = self.active_engine()?;
        let item_id = parse_uuid(id)?;
        let item = engine.lock.get_item(item_id)?;
        self.to_item_detail_dto(&engine, &item).await
    }

    pub async fn cmd_save_item(
        &self,
        input: SaveItemInputDto,
    ) -> Result<ItemDetailDto, DesktopError> {
        let engine = self.active_engine()?;
        let title = input.title.trim();
        if title.is_empty() {
            return Err(DesktopError::InvalidInput(
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

        let now = Utc::now();
        let existing = match input.id.as_deref().filter(|s| !s.is_empty()) {
            Some(raw_id) => {
                let uuid = parse_uuid(raw_id)?;
                engine.lock.get_item(uuid).ok()
            }
            None => None,
        };

        let login = match input.login {
            Some(in_login) => {
                let normalized_totp = match in_login.totp {
                    Some(t) if !t.secret_base32.trim().is_empty() => {
                        let raw = t.secret_base32.trim();
                        if raw
                            .get(..10)
                            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
                        {
                            Some(TotpConfig::from_otpauth_uri(raw)?)
                        } else {
                            let mut parsed = TotpConfig::from_input(raw)?;
                            parsed.algorithm = t.algorithm;
                            parsed.digits = t.digits;
                            parsed.period_seconds = t.period_seconds;
                            if let Some(ref issuer) = t.issuer {
                                parsed.issuer = Some(issuer.clone());
                            }
                            if let Some(ref label) = t.label {
                                parsed.label = Some(label.clone());
                            }
                            Some(parsed)
                        }
                    }
                    _ => None,
                };
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
                Some(LoginData {
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
                    totp: normalized_totp,
                })
            }
            None => None,
        };

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

        let saved = engine.save_item(item).await?;
        self.sync_tray_count(&engine).await;
        self.to_item_detail_dto(&engine, &saved).await
    }

    pub async fn cmd_delete_item(&self, id: &str) -> Result<(), DesktopError> {
        let engine = self.active_engine()?;
        let item_id = parse_uuid(id)?;
        engine.delete_item(item_id).await?;
        self.sync_tray_count(&engine).await;
        Ok(())
    }

    pub async fn cmd_upload_item_logo(
        &self,
        item_id: &str,
        bytes: Vec<u8>,
    ) -> Result<ItemDetailDto, DesktopError> {
        let engine = self.active_engine()?;
        let parsed_id = parse_uuid(item_id)?;
        let (_, updated) = engine.attach_custom_logo(parsed_id, &bytes).await?;
        self.to_item_detail_dto(&engine, &updated).await
    }

    pub async fn cmd_copy_secret(
        &self,
        label: &str,
        value: &str,
    ) -> Result<ClipboardCopyReceipt, DesktopError> {
        let engine = self.active_engine()?;
        if !engine.lock.is_unlocked() {
            return Err(DesktopError::Client(ClientError::VaultLocked));
        }
        engine.lock.touch_activity();
        Ok(self
            .clipboard
            .copy_secret(label, value, DEFAULT_CLIPBOARD_CLEAR_TTL)?)
    }

    pub fn cmd_generate_totp(
        &self,
        secret_or_uri: &str,
        unix_timestamp_seconds: u64,
    ) -> Result<TotpCode, DesktopError> {
        let engine = self.active_engine()?;
        if !engine.lock.is_unlocked() {
            return Err(DesktopError::Client(ClientError::VaultLocked));
        }
        let cfg = TotpConfig::from_input(secret_or_uri)?;
        Ok(cfg.generate_at(unix_timestamp_seconds)?)
    }

    pub fn cmd_generate_password(
        &self,
        options: PasswordGenOptionsDto,
    ) -> Result<GeneratedPasswordDto, DesktopError> {
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
        let strength = evaluate_password_strength(&generated, &[]);
        Ok(GeneratedPasswordDto {
            value: (*generated).clone(),
            strength: PasswordStrengthDto {
                score: strength.score,
                entropy_bits: strength.entropy_bits,
                crack_time_display: strength.crack_time_display,
                feedback_warning: strength.feedback_warning,
            },
        })
    }

    pub fn cmd_evaluate_password(&self, value: &str) -> PasswordStrengthDto {
        let strength = evaluate_password_strength(value, &[]);
        PasswordStrengthDto {
            score: strength.score,
            entropy_bits: strength.entropy_bits,
            crack_time_display: strength.crack_time_display,
            feedback_warning: strength.feedback_warning,
        }
    }

    pub fn cmd_preview_import(
        &self,
        format: ImportSourceKindDto,
        bytes: Vec<u8>,
        backup_password: Option<String>,
    ) -> Result<ImportPreviewDto, DesktopError> {
        let engine = self.active_engine()?;
        let snapshot = engine.lock.snapshot()?;
        let preview = preview_import(format.into(), &bytes, backup_password.as_deref(), &snapshot)?;
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

        let mut guard = self
            .pending_imports
            .lock()
            .map_err(|_| DesktopError::InternalState)?;
        guard.insert(preview_id, preview);
        Ok(dto)
    }

    pub async fn cmd_execute_import(
        &self,
        preview_id: &str,
        policy: DuplicatePolicy,
    ) -> Result<ImportReportDto, DesktopError> {
        let engine = self.active_engine()?;
        let id = parse_uuid(preview_id)?;
        let preview = {
            let mut guard = self
                .pending_imports
                .lock()
                .map_err(|_| DesktopError::InternalState)?;
            guard
                .remove(&id)
                .ok_or(DesktopError::ImportPreviewNotFound)?
        };

        let before = engine.lock.snapshot()?;
        let before_folders: HashSet<Uuid> = before.folders.iter().map(|f| f.id).collect();
        let before_items: HashMap<Uuid, VaultItem> =
            before.items.iter().map(|i| (i.id, i.clone())).collect();

        let mut working = before;
        let report = apply_import(preview, policy, &mut working);

        let delta = VaultSnapshot {
            folders: working
                .folders
                .into_iter()
                .filter(|f| !before_folders.contains(&f.id))
                .collect(),
            items: working
                .items
                .into_iter()
                .filter(|item| match before_items.get(&item.id) {
                    Some(prev) => prev != item,
                    None => true,
                })
                .collect(),
            blobs: Vec::new(),
        };

        engine.commit_import_snapshot(delta).await?;
        self.sync_tray_count(&engine).await;

        Ok(ImportReportDto {
            created: report.created,
            merged: report.merged,
            skipped: report.skipped,
            folders_created: report.folders_created,
            warnings: report.warnings,
        })
    }

    pub async fn cmd_export_vault(
        &self,
        format: ExportFormatDto,
        master_password: &str,
        backup_password: Option<String>,
    ) -> Result<Vec<u8>, DesktopError> {
        let engine = self.active_engine()?;
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let salt = fixed_salt(&acct.kdf_salt)?;
        let kdf_params = account_kdf_params(&acct)?;
        let pw = MasterPassword::new(master_password);
        engine.lock.verify_master_password_reauth(
            &pw,
            &kdf_params,
            &salt,
            &acct.encrypted_vault_key,
            acct.user_id,
            acct.key_version,
        )?;

        let snapshot = engine.lock.snapshot()?;
        match format {
            ExportFormatDto::Anvil => {
                let archive_pw = backup_password
                    .as_deref()
                    .filter(|p| !p.is_empty())
                    .map(MasterPassword::new)
                    .unwrap_or_else(|| MasterPassword::new(master_password));
                Ok(export_anvil_archive(&snapshot, &archive_pw)?)
            }
            ExportFormatDto::BitwardenJson => Ok(export_bitwarden_json(&snapshot)?.into_bytes()),
            ExportFormatDto::Csv => Ok(export_csv(&snapshot)?.into_bytes()),
        }
    }

    pub async fn cmd_sync(&self) -> Result<SyncReport, DesktopError> {
        let engine = self.active_engine()?;
        self.tray.set_state(TrayVisualState::Syncing);
        let result = engine.sync_now().await;
        self.sync_tray_count(&engine).await;
        Ok(result?)
    }

    pub async fn cmd_list_conflicts(&self) -> Result<Vec<ConflictItemDto>, DesktopError> {
        let engine = self.active_engine()?;
        let conflicts = engine.list_decrypted_conflicts().await?;
        Ok(conflicts
            .into_iter()
            .map(|view| match view {
                DecryptedConflictView::Item {
                    conflict_id,
                    entity_id,
                    local,
                    server,
                    server_deleted,
                    server_revision,
                } => ConflictItemDto {
                    conflict_id: conflict_id.to_string(),
                    entity_id: entity_id.to_string(),
                    entity_kind: "item".to_owned(),
                    title: local.title.clone(),
                    local_summary: format_item_conflict_summary(&local),
                    server_summary: server
                        .as_deref()
                        .map(format_item_conflict_summary)
                        .unwrap_or_else(|| "Supprimée sur le serveur".to_owned()),
                    server_deleted,
                    server_revision,
                },
                DecryptedConflictView::Folder {
                    conflict_id,
                    entity_id,
                    local,
                    server,
                    server_deleted,
                    server_revision,
                } => ConflictItemDto {
                    conflict_id: conflict_id.to_string(),
                    entity_id: entity_id.to_string(),
                    entity_kind: "folder".to_owned(),
                    title: local.name.clone(),
                    local_summary: format!("Dossier « {} »", local.name),
                    server_summary: server
                        .map(|f| format!("Dossier « {} »", f.name))
                        .unwrap_or_else(|| "Dossier supprimé".to_owned()),
                    server_deleted,
                    server_revision,
                },
            })
            .collect())
    }

    pub async fn cmd_resolve_conflict(
        &self,
        conflict_id: &str,
        resolution: ConflictResolution,
    ) -> Result<SyncReport, DesktopError> {
        let engine = self.active_engine()?;
        let cid = parse_uuid(conflict_id)?;
        let report = engine.resolve_conflict(cid, resolution).await?;
        self.sync_tray_count(&engine).await;
        Ok(report)
    }

    pub async fn cmd_rotate_password(
        &self,
        current_password: &str,
        new_password: &str,
        revoke_other_sessions: bool,
    ) -> Result<u32, DesktopError> {
        let engine = self.active_engine()?;
        Ok(engine
            .rotate_master_password(current_password, new_password, revoke_other_sessions)
            .await?)
    }

    pub fn cmd_window_chrome(&self) -> Result<WindowChromeStateDto, DesktopError> {
        self.chrome
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| DesktopError::InternalState)
    }

    pub fn set_window_chrome(&self, is_maximized: bool, is_focused: bool) {
        if let Ok(mut guard) = self.chrome.write() {
            guard.is_maximized = is_maximized;
            guard.is_focused = is_focused;
        }
    }

    pub fn cmd_hit_test(&self, req: HitTestRequestDto) -> HitTestResponseDto {
        let cfg = match req.search_width {
            Some(sw) => TitlebarHitConfig::with_centered_search(req.rect.width(), sw),
            None => TitlebarHitConfig::default(),
        };
        let zone = compute_hit_zone(req.rect, req.cursor_x, req.cursor_y, req.is_maximized, &cfg);
        HitTestResponseDto {
            zone,
            code: zone as isize,
        }
    }

    /// Validates that an item URI uses a safe HTTP(S) scheme before launching external browser.
    pub fn cmd_open_external_url(&self, raw_url: &str) -> Result<String, DesktopError> {
        let trimmed = raw_url.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("https://") || lower.starts_with("http://") {
            return Ok(trimmed.to_owned());
        }
        Err(DesktopError::InvalidInput(
            "only http:// and https:// URLs may be launched externally".to_owned(),
        ))
    }

    /// JSON command dispatcher used by the headless/Tauri IPC bridge.
    pub async fn dispatch_ipc(
        &self,
        command: &str,
        payload_json: &str,
    ) -> Result<String, DesktopError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RegisterArgs {
            server_url: String,
            email: String,
            master_password: String,
            invite_token: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct LoginArgs {
            server_url: String,
            email: String,
            master_password: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PasswordArg {
            master_password: String,
        }
        #[derive(Deserialize)]
        struct IdArg {
            id: String,
        }
        #[derive(Deserialize)]
        struct SaveFolderArgs {
            id: Option<String>,
            name: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ListItemsArgs {
            query: String,
            folder_id: Option<String>,
            favorites_only: bool,
            trashed_only: bool,
        }
        #[derive(Deserialize)]
        struct SaveItemArgs {
            input: SaveItemInputDto,
        }
        #[derive(Deserialize)]
        struct CopyArgs {
            label: String,
            value: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct TotpArgs {
            secret_or_uri: String,
            unix_timestamp_seconds: u64,
        }
        #[derive(Deserialize)]
        struct GenPwArgs {
            options: PasswordGenOptionsDto,
        }
        #[derive(Deserialize)]
        struct EvalPwArgs {
            value: String,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PreviewImportArgs {
            format: ImportSourceKindDto,
            bytes: Vec<u8>,
            backup_password: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ExecuteImportArgs {
            preview_id: String,
            policy: DuplicatePolicy,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ExportArgs {
            format: ExportFormatDto,
            master_password: String,
            backup_password: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct ResolveConflictArgs {
            conflict_id: String,
            resolution: ConflictResolution,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct UploadLogoArgs {
            item_id: String,
            bytes: Vec<u8>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RotatePasswordArgs {
            current_password: String,
            new_password: String,
            revoke_other_sessions: bool,
        }
        #[derive(Deserialize)]
        struct OpenUrlArgs {
            url: String,
        }

        let body = if payload_json.trim().is_empty() {
            "{}"
        } else {
            payload_json
        };

        let encoded = match command {
            "cmd_status" => serialize_json(&self.cmd_status().await?)?,
            "cmd_register" => {
                let a: RegisterArgs = parse_json(body)?;
                serialize_json(
                    &self
                        .cmd_register(
                            &a.server_url,
                            &a.email,
                            &a.master_password,
                            a.invite_token.as_deref(),
                        )
                        .await?,
                )?
            }
            "cmd_login" => {
                let a: LoginArgs = parse_json(body)?;
                serialize_json(
                    &self
                        .cmd_login(&a.server_url, &a.email, &a.master_password)
                        .await?,
                )?
            }
            "cmd_unlock_password" => {
                let a: PasswordArg = parse_json(body)?;
                serialize_json(&self.cmd_unlock_password(&a.master_password).await?)?
            }
            "cmd_unlock_biometric" => serialize_json(&self.cmd_unlock_biometric().await?)?,
            "cmd_enable_biometric" => {
                let a: PasswordArg = parse_json(body)?;
                serialize_json(&self.cmd_enable_biometric(&a.master_password).await?)?
            }
            "cmd_lock" => serialize_json(&self.cmd_lock().await?)?,
            "cmd_list_folders" => serialize_json(&self.cmd_list_folders().await?)?,
            "cmd_save_folder" => {
                let a: SaveFolderArgs = parse_json(body)?;
                serialize_json(&self.cmd_save_folder(&a.name, a.id.as_deref()).await?)?
            }
            "cmd_delete_folder" => {
                let a: IdArg = parse_json(body)?;
                self.cmd_delete_folder(&a.id).await?;
                "null".to_owned()
            }
            "cmd_list_items" => {
                let a: ListItemsArgs = parse_json(body)?;
                serialize_json(
                    &self
                        .cmd_list_items(
                            &a.query,
                            a.folder_id.as_deref(),
                            a.favorites_only,
                            a.trashed_only,
                        )
                        .await?,
                )?
            }
            "cmd_get_item" => {
                let a: IdArg = parse_json(body)?;
                serialize_json(&self.cmd_get_item(&a.id).await?)?
            }
            "cmd_save_item" => {
                let a: SaveItemArgs = parse_json(body)?;
                serialize_json(&self.cmd_save_item(a.input).await?)?
            }
            "cmd_delete_item" => {
                let a: IdArg = parse_json(body)?;
                self.cmd_delete_item(&a.id).await?;
                "null".to_owned()
            }
            "cmd_copy_secret" => {
                let a: CopyArgs = parse_json(body)?;
                serialize_json(&self.cmd_copy_secret(&a.label, &a.value).await?)?
            }
            "cmd_generate_totp" => {
                let a: TotpArgs = parse_json(body)?;
                serialize_json(
                    &self.cmd_generate_totp(&a.secret_or_uri, a.unix_timestamp_seconds)?,
                )?
            }
            "cmd_generate_password" => {
                let a: GenPwArgs = parse_json(body)?;
                serialize_json(&self.cmd_generate_password(a.options)?)?
            }
            "cmd_evaluate_password" => {
                let a: EvalPwArgs = parse_json(body)?;
                serialize_json(&self.cmd_evaluate_password(&a.value))?
            }
            "cmd_preview_import" => {
                let a: PreviewImportArgs = parse_json(body)?;
                serialize_json(&self.cmd_preview_import(a.format, a.bytes, a.backup_password)?)?
            }
            "cmd_execute_import" => {
                let a: ExecuteImportArgs = parse_json(body)?;
                serialize_json(&self.cmd_execute_import(&a.preview_id, a.policy).await?)?
            }
            "cmd_export_vault" => {
                let a: ExportArgs = parse_json(body)?;
                serialize_json(
                    &self
                        .cmd_export_vault(a.format, &a.master_password, a.backup_password)
                        .await?,
                )?
            }
            "cmd_sync" => serialize_json(&self.cmd_sync().await?)?,
            "cmd_list_conflicts" => serialize_json(&self.cmd_list_conflicts().await?)?,
            "cmd_resolve_conflict" => {
                let a: ResolveConflictArgs = parse_json(body)?;
                serialize_json(
                    &self
                        .cmd_resolve_conflict(&a.conflict_id, a.resolution)
                        .await?,
                )?
            }
            "cmd_upload_item_logo" => {
                let a: UploadLogoArgs = parse_json(body)?;
                serialize_json(&self.cmd_upload_item_logo(&a.item_id, a.bytes).await?)?
            }
            "cmd_rotate_password" => {
                let a: RotatePasswordArgs = parse_json(body)?;
                serialize_json(
                    &self
                        .cmd_rotate_password(
                            &a.current_password,
                            &a.new_password,
                            a.revoke_other_sessions,
                        )
                        .await?,
                )?
            }
            "cmd_open_external_url" => {
                let a: OpenUrlArgs = parse_json(body)?;
                serialize_json(&self.cmd_open_external_url(&a.url)?)?
            }
            "cmd_window_chrome" => serialize_json(&self.cmd_window_chrome()?)?,
            "cmd_window_minimize" => "null".to_owned(),
            "cmd_window_toggle_maximize" => {
                let next_maximized = !self.cmd_window_chrome()?.is_maximized;
                if let Ok(mut guard) = self.chrome.write() {
                    guard.is_maximized = next_maximized;
                }
                "null".to_owned()
            }
            "cmd_window_close" => "null".to_owned(),
            "cmd_hit_test" => {
                let a: HitTestRequestDto = parse_json(body)?;
                serialize_json(&self.cmd_hit_test(a))?
            }
            other => return Err(DesktopError::UnknownCommand(other.to_owned())),
        };
        Ok(encoded)
    }

    async fn to_item_detail_dto(
        &self,
        engine: &ClientSyncEngine,
        item: &VaultItem,
    ) -> Result<ItemDetailDto, DesktopError> {
        let data_url = match item.logo.blob_id {
            Some(blob_id) => match engine.load_custom_logo(item.id, blob_id).await {
                Ok(blob) => Some(format!(
                    "data:{};base64,{}",
                    blob.mime_type,
                    STANDARD.encode(&*blob.data)
                )),
                Err(_) => None,
            },
            None => None,
        };

        Ok(ItemDetailDto {
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
                data_url,
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
        })
    }
}

fn current_platform_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn parse_uuid(raw: &str) -> Result<Uuid, DesktopError> {
    Uuid::parse_str(raw.trim()).map_err(|err| DesktopError::InvalidInput(err.to_string()))
}

fn parse_rfc3339(raw: &str) -> Result<DateTime<Utc>, DesktopError> {
    DateTime::parse_from_rfc3339(raw.trim())
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| DesktopError::InvalidInput(err.to_string()))
}

fn parse_json<'a, T: Deserialize<'a>>(raw: &'a str) -> Result<T, DesktopError> {
    serde_json::from_str(raw).map_err(|err| DesktopError::InvalidInput(err.to_string()))
}

fn serialize_json<T: Serialize>(value: &T) -> Result<String, DesktopError> {
    serde_json::to_string(value).map_err(|err| DesktopError::InvalidInput(err.to_string()))
}

fn format_item_conflict_summary(item: &VaultItem) -> String {
    let identity = item
        .login
        .as_ref()
        .map(|l| {
            if !l.email.is_empty() {
                l.email.as_str()
            } else {
                l.username.as_str()
            }
        })
        .unwrap_or("-");
    let url = item
        .login
        .as_ref()
        .and_then(|l| l.uris.first())
        .map(|u| u.uri.as_str())
        .unwrap_or("-");
    let has_pw = item.login.as_ref().is_some_and(|l| !l.password.is_empty());
    format!(
        "{} | identifiant: {} | URL: {} | mdp défini: {} | v{}",
        item.title,
        identity,
        url,
        if has_pw { "oui" } else { "non" },
        item.item_version
    )
}

pub fn default_uri(uri: String) -> ItemUri {
    ItemUri {
        uri,
        match_mode: UriMatchMode::BaseDomain,
    }
}
