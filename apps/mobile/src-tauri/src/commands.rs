//! Typed IPC command host coordinating mobile vault sync, QR onboarding/2FA, biometric enclave, and autofill.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};

use anvil_client_core::api_client::AnvilApiClient;
use anvil_client_core::cache::EncryptedLocalCache;
use anvil_client_core::error::ClientError;
use anvil_client_core::lock_manager::{DEFAULT_INACTIVITY_TIMEOUT, VaultLockManager};
use anvil_client_core::sync_engine::{
    ClientSyncEngine, ConflictResolution, DecryptedConflictView, SyncReport, account_kdf_params,
    fixed_salt,
};
use anvil_core::crypto::{KdfParams, MasterPassword};
use anvil_core::media::{fallback_accent_color, fallback_initials};
use anvil_core::models::{
    CustomField, ItemKind, ItemLogo, ItemUri, LoginData, PasswordHistoryEntry,
    VAULT_ITEM_SCHEMA_VERSION, VaultFolder, VaultItem,
};
use anvil_core::password::{
    PassphraseConfig, PasswordGeneratorConfig, evaluate_password_strength, generate_passphrase,
    generate_password,
};
use anvil_core::totp::{TotpCode, TotpConfig};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::autofill::{
    AutofillCallerContext, AutofillCandidate, AutofillFillPayload, MobileAutofillEngine,
};
use crate::biometric::{LowMemoryAutofillUnlocker, MobileBiometricEnclave, MobileEnclaveKind};
use crate::error::MobileError;
use crate::qr::{QrScanResult, parse_qr_payload, validate_mobile_server_url};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileStatusDto {
    pub configured: bool,
    pub authenticated: bool,
    pub unlocked: bool,
    pub biometric_available: bool,
    pub biometric_enabled: bool,
    pub biometric_kind: MobileEnclaveKind,
    pub server_url: Option<String>,
    pub email: Option<String>,
    pub sync_revision: i64,
    pub pending_conflicts: usize,
    pub flag_secure_enabled: bool,
    pub lock_on_background: bool,
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

/// Core command coordinator for `Anvil Mobile` (Android & iOS).
pub struct MobileCommandHost {
    cache: EncryptedLocalCache,
    engine: RwLock<Arc<ClientSyncEngine>>,
    enclave: Arc<dyn MobileBiometricEnclave>,
    device_name: String,
    device_platform: String,
    kdf_params: KdfParams,
    flag_secure_enabled: AtomicBool,
    lock_on_background: AtomicBool,
}

impl MobileCommandHost {
    pub fn new(
        cache: EncryptedLocalCache,
        default_server_url: &str,
        enclave: Arc<dyn MobileBiometricEnclave>,
        device_platform: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Result<Self, MobileError> {
        let valid_url = validate_mobile_server_url(default_server_url)?;
        let api = AnvilApiClient::new(&valid_url)?;
        let platform_str = device_platform.into();
        let name_str = device_name.into();
        let engine = Arc::new(ClientSyncEngine::new(
            api,
            cache.clone(),
            VaultLockManager::new(DEFAULT_INACTIVITY_TIMEOUT),
            name_str.clone(),
            platform_str.clone(),
        ));

        Ok(Self {
            cache,
            engine: RwLock::new(engine),
            enclave,
            device_name: name_str,
            device_platform: platform_str,
            kdf_params: KdfParams::default(),
            flag_secure_enabled: AtomicBool::new(true),
            lock_on_background: AtomicBool::new(true),
        })
    }

    pub fn with_kdf_params(mut self, kdf_params: KdfParams) -> Self {
        self.kdf_params = kdf_params;
        self
    }

    pub fn enclave(&self) -> &Arc<dyn MobileBiometricEnclave> {
        &self.enclave
    }

    fn active_engine(&self) -> Result<Arc<ClientSyncEngine>, MobileError> {
        let guard = self.engine.read().map_err(|_| MobileError::InternalState)?;
        Ok(Arc::clone(&guard))
    }

    fn replace_engine_for_server(
        &self,
        server_url: &str,
    ) -> Result<Arc<ClientSyncEngine>, MobileError> {
        let valid_url = validate_mobile_server_url(server_url)?;
        let api = AnvilApiClient::new(&valid_url)?;
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
            .map_err(|_| MobileError::InternalState)?;
        *guard = Arc::clone(&next);
        Ok(next)
    }

    pub async fn cmd_status(&self) -> Result<MobileStatusDto, MobileError> {
        let engine = self.active_engine()?;
        let acct = self.cache.load_account().await?;
        let authenticated = engine.api.has_session().await;
        let unlocked = engine.lock.is_unlocked();

        let (configured, biometric_enabled, server_url, email, sync_revision, pending_conflicts) =
            match acct {
                Some(a) => {
                    let conflicts = self.cache.list_conflicts(a.user_id).await?;
                    (
                        true,
                        a.biometric_sealed_vault_key.is_some(),
                        Some(a.server_url),
                        Some(a.email),
                        a.last_synced_revision,
                        conflicts.len(),
                    )
                }
                None => (false, false, None, None, 0, 0),
            };

        Ok(MobileStatusDto {
            configured,
            authenticated,
            unlocked,
            biometric_available: self.enclave.is_available(),
            biometric_enabled,
            biometric_kind: self.enclave.kind(),
            server_url,
            email,
            sync_revision,
            pending_conflicts,
            flag_secure_enabled: self.flag_secure_enabled.load(Ordering::Relaxed),
            lock_on_background: self.lock_on_background.load(Ordering::Relaxed),
        })
    }

    pub fn cmd_parse_qr(&self, raw_payload: &str) -> Result<QrScanResult, MobileError> {
        parse_qr_payload(raw_payload)
    }

    pub async fn cmd_register(
        &self,
        server_url: &str,
        email: &str,
        master_password: &str,
        invite_token: Option<&str>,
    ) -> Result<MobileStatusDto, MobileError> {
        let engine = self.replace_engine_for_server(server_url)?;
        engine
            .register_and_unlock(email, master_password, invite_token, self.kdf_params)
            .await?;
        self.cmd_status().await
    }

    pub async fn cmd_login(
        &self,
        server_url: &str,
        email: &str,
        master_password: &str,
    ) -> Result<MobileStatusDto, MobileError> {
        let engine = self.replace_engine_for_server(server_url)?;
        engine.login_and_unlock(email, master_password).await?;
        let _ = engine.sync_now().await;
        self.cmd_status().await
    }

    pub async fn cmd_unlock_password(
        &self,
        master_password: &str,
    ) -> Result<MobileStatusDto, MobileError> {
        let engine = self.active_engine()?;
        engine.unlock_with_password(master_password).await?;
        self.cmd_status().await
    }

    pub async fn cmd_enable_biometric(
        &self,
        master_password: &str,
    ) -> Result<MobileStatusDto, MobileError> {
        if !self.enclave.is_available() {
            return Err(MobileError::BiometricUnavailable);
        }
        let engine = self.active_engine()?;
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let salt = fixed_salt(&acct.kdf_salt)?;
        let kdf_params = account_kdf_params(&acct)?;
        let pw = MasterPassword::new(master_password);

        let (_, vault_key) = engine.lock.verify_master_password_reauth(
            &pw,
            &kdf_params,
            &salt,
            &acct.encrypted_vault_key,
            acct.user_id,
            acct.key_version,
        )?;
        let sealed = self.enclave.seal_vault_key(acct.user_id, &vault_key)?;
        self.cache
            .set_biometric_seal(acct.user_id, Some(&sealed))
            .await?;
        self.cmd_status().await
    }

    pub async fn cmd_unlock_biometric(&self) -> Result<MobileStatusDto, MobileError> {
        let engine = self.active_engine()?;
        LowMemoryAutofillUnlocker::unlock_without_kdf(&self.cache, &engine, self.enclave.as_ref())
            .await?;
        self.cmd_status().await
    }

    pub async fn cmd_lock(&self) -> Result<MobileStatusDto, MobileError> {
        let engine = self.active_engine()?;
        engine.lock_vault();
        self.cmd_status().await
    }

    pub async fn cmd_on_app_backgrounded(&self) -> Result<MobileStatusDto, MobileError> {
        if self.lock_on_background.load(Ordering::Relaxed) {
            tracing::info!("mobile app moved to background; locking vault RAM");
            let engine = self.active_engine()?;
            engine.lock_vault();
        }
        self.cmd_status().await
    }

    pub async fn cmd_set_privacy(
        &self,
        flag_secure_enabled: bool,
        lock_on_background: bool,
    ) -> Result<MobileStatusDto, MobileError> {
        self.flag_secure_enabled
            .store(flag_secure_enabled, Ordering::Relaxed);
        self.lock_on_background
            .store(lock_on_background, Ordering::Relaxed);
        self.cmd_status().await
    }

    pub async fn cmd_list_folders(&self) -> Result<Vec<FolderDto>, MobileError> {
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
    ) -> Result<FolderDto, MobileError> {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return Err(MobileError::InvalidInput(
                "folder name cannot be empty".to_owned(),
            ));
        }
        let engine = self.active_engine()?;
        let folder = match id.filter(|s| !s.trim().is_empty()) {
            Some(raw_id) => {
                let fid = parse_uuid(raw_id)?;
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

    pub async fn cmd_delete_folder(&self, id: &str) -> Result<(), MobileError> {
        let engine = self.active_engine()?;
        engine.delete_folder(parse_uuid(id)?).await?;
        Ok(())
    }

    pub async fn cmd_list_items(
        &self,
        query: &str,
        folder_id: Option<&str>,
        favorites_only: bool,
        trashed_only: bool,
    ) -> Result<Vec<ItemSummaryDto>, MobileError> {
        let engine = self.active_engine()?;
        let parsed_folder = folder_id
            .filter(|s| !s.is_empty())
            .map(parse_uuid)
            .transpose()?;
        let rows =
            engine
                .lock
                .search_summaries(query, parsed_folder, favorites_only, trashed_only)?;
        Ok(rows
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

    pub async fn cmd_get_item(&self, id: &str) -> Result<ItemDetailDto, MobileError> {
        let engine = self.active_engine()?;
        let item = engine.lock.get_item(parse_uuid(id)?)?;
        Ok(item_to_detail_dto(&item))
    }

    pub async fn cmd_save_item(
        &self,
        input: SaveItemInputDto,
    ) -> Result<ItemDetailDto, MobileError> {
        let engine = self.active_engine()?;
        let title = input.title.trim();
        if title.is_empty() {
            return Err(MobileError::InvalidInput(
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
            Some(raw_id) => engine.lock.get_item(parse_uuid(raw_id)?).ok(),
            None => None,
        };

        let login = input.login.map(|in_login| {
            let mut history = in_login.password_history;
            if let Some(prev_pw) = existing
                .as_ref()
                .and_then(|ex| ex.login.as_ref())
                .map(|ex_l| ex_l.password.as_str())
                .filter(|pw| !pw.is_empty() && *pw != in_login.password)
                && !history.iter().any(|h| h.password == prev_pw)
            {
                history.insert(
                    0,
                    PasswordHistoryEntry {
                        password: prev_pw.to_owned(),
                        changed_at: now,
                    },
                );
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

        let saved = engine.save_item(item).await?;
        Ok(item_to_detail_dto(&saved))
    }

    pub async fn cmd_delete_item(&self, id: &str) -> Result<(), MobileError> {
        let engine = self.active_engine()?;
        engine.delete_item(parse_uuid(id)?).await?;
        Ok(())
    }

    /// Scans a camera QR TOTP URI/secret and persists it directly onto an existing login entry.
    pub async fn cmd_attach_totp_from_qr(
        &self,
        item_id: &str,
        raw_qr: &str,
    ) -> Result<ItemDetailDto, MobileError> {
        let cfg = match parse_qr_payload(raw_qr)? {
            QrScanResult::Totp(cfg) => cfg,
            QrScanResult::Onboarding(_) => {
                return Err(MobileError::InvalidQrPayload(
                    "expected otpauth://totp/ or Base32 secret, found onboarding URI".to_owned(),
                ));
            }
        };
        let engine = self.active_engine()?;
        let mut item = engine.lock.get_item(parse_uuid(item_id)?)?;
        let Some(ref mut login) = item.login else {
            return Err(MobileError::InvalidInput(
                "cannot attach TOTP to a secure note item".to_owned(),
            ));
        };
        login.totp = Some(cfg);
        item.item_version = item.item_version.saturating_add(1);
        item.updated_at = Utc::now();
        let saved = engine.save_item(item).await?;
        Ok(item_to_detail_dto(&saved))
    }

    pub fn cmd_generate_totp(
        &self,
        secret_or_uri: &str,
        unix_timestamp_seconds: u64,
    ) -> Result<TotpCode, MobileError> {
        let engine = self.active_engine()?;
        if !engine.lock.is_unlocked() {
            return Err(MobileError::Client(ClientError::VaultLocked));
        }
        let cfg = TotpConfig::from_input(secret_or_uri)?;
        Ok(cfg.generate_at(unix_timestamp_seconds)?)
    }

    pub fn cmd_generate_password(
        &self,
        options: PasswordGenOptionsDto,
    ) -> Result<GeneratedPasswordDto, MobileError> {
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

    pub async fn cmd_sync(&self) -> Result<SyncReport, MobileError> {
        let engine = self.active_engine()?;
        Ok(engine.sync_now().await?)
    }

    pub async fn cmd_list_conflicts(&self) -> Result<Vec<ConflictItemDto>, MobileError> {
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
                    local_summary: format!("{} (v{})", local.title, local.item_version),
                    server_summary: server
                        .map(|s| format!("{} (v{})", s.title, s.item_version))
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
    ) -> Result<SyncReport, MobileError> {
        let engine = self.active_engine()?;
        Ok(engine
            .resolve_conflict(parse_uuid(conflict_id)?, resolution)
            .await?)
    }

    pub fn cmd_autofill_query(
        &self,
        ctx: &AutofillCallerContext,
    ) -> Result<Vec<AutofillCandidate>, MobileError> {
        let engine = self.active_engine()?;
        MobileAutofillEngine::query_candidates(&engine, ctx)
    }

    pub fn cmd_autofill_fill(
        &self,
        item_id: &str,
        ctx: &AutofillCallerContext,
        unix_timestamp_seconds: u64,
    ) -> Result<AutofillFillPayload, MobileError> {
        let engine = self.active_engine()?;
        MobileAutofillEngine::resolve_fill_payload(&engine, item_id, ctx, unix_timestamp_seconds)
    }

    /// Dispatches JSON IPC calls emitted by the Tauri WebView, Kotlin AutofillService, or Swift provider.
    pub async fn dispatch_ipc(
        &self,
        command: &str,
        payload_json: &str,
    ) -> Result<String, MobileError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct QrArgs {
            raw: String,
        }
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
        #[serde(rename_all = "camelCase")]
        struct PrivacyArgs {
            flag_secure_enabled: bool,
            lock_on_background: bool,
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
        #[serde(rename_all = "camelCase")]
        struct AttachTotpArgs {
            item_id: String,
            raw_qr: String,
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
        struct ResolveConflictArgs {
            conflict_id: String,
            resolution: ConflictResolution,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct AutofillFillArgs {
            item_id: String,
            context: AutofillCallerContext,
            unix_timestamp_seconds: u64,
        }

        let body = if payload_json.trim().is_empty() {
            "{}"
        } else {
            payload_json
        };

        let out = match command {
            "cmd_status" => to_json(&self.cmd_status().await?)?,
            "cmd_parse_qr" => {
                let a: QrArgs = from_json(body)?;
                to_json(&self.cmd_parse_qr(&a.raw)?)?
            }
            "cmd_register" => {
                let a: RegisterArgs = from_json(body)?;
                to_json(
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
                let a: LoginArgs = from_json(body)?;
                to_json(
                    &self
                        .cmd_login(&a.server_url, &a.email, &a.master_password)
                        .await?,
                )?
            }
            "cmd_unlock_password" => {
                let a: PasswordArg = from_json(body)?;
                to_json(&self.cmd_unlock_password(&a.master_password).await?)?
            }
            "cmd_enable_biometric" => {
                let a: PasswordArg = from_json(body)?;
                to_json(&self.cmd_enable_biometric(&a.master_password).await?)?
            }
            "cmd_unlock_biometric" => to_json(&self.cmd_unlock_biometric().await?)?,
            "cmd_lock" => to_json(&self.cmd_lock().await?)?,
            "cmd_on_app_backgrounded" => to_json(&self.cmd_on_app_backgrounded().await?)?,
            "cmd_set_privacy" => {
                let a: PrivacyArgs = from_json(body)?;
                to_json(
                    &self
                        .cmd_set_privacy(a.flag_secure_enabled, a.lock_on_background)
                        .await?,
                )?
            }
            "cmd_list_folders" => to_json(&self.cmd_list_folders().await?)?,
            "cmd_save_folder" => {
                let a: SaveFolderArgs = from_json(body)?;
                to_json(&self.cmd_save_folder(&a.name, a.id.as_deref()).await?)?
            }
            "cmd_delete_folder" => {
                let a: IdArg = from_json(body)?;
                self.cmd_delete_folder(&a.id).await?;
                "null".to_owned()
            }
            "cmd_list_items" => {
                let a: ListItemsArgs = from_json(body)?;
                to_json(
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
                let a: IdArg = from_json(body)?;
                to_json(&self.cmd_get_item(&a.id).await?)?
            }
            "cmd_save_item" => {
                let a: SaveItemArgs = from_json(body)?;
                to_json(&self.cmd_save_item(a.input).await?)?
            }
            "cmd_delete_item" => {
                let a: IdArg = from_json(body)?;
                self.cmd_delete_item(&a.id).await?;
                "null".to_owned()
            }
            "cmd_attach_totp_from_qr" => {
                let a: AttachTotpArgs = from_json(body)?;
                to_json(&self.cmd_attach_totp_from_qr(&a.item_id, &a.raw_qr).await?)?
            }
            "cmd_generate_totp" => {
                let a: TotpArgs = from_json(body)?;
                to_json(&self.cmd_generate_totp(&a.secret_or_uri, a.unix_timestamp_seconds)?)?
            }
            "cmd_generate_password" => {
                let a: GenPwArgs = from_json(body)?;
                to_json(&self.cmd_generate_password(a.options)?)?
            }
            "cmd_evaluate_password" => {
                let a: EvalPwArgs = from_json(body)?;
                to_json(&self.cmd_evaluate_password(&a.value))?
            }
            "cmd_sync" => to_json(&self.cmd_sync().await?)?,
            "cmd_list_conflicts" => to_json(&self.cmd_list_conflicts().await?)?,
            "cmd_resolve_conflict" => {
                let a: ResolveConflictArgs = from_json(body)?;
                to_json(
                    &self
                        .cmd_resolve_conflict(&a.conflict_id, a.resolution)
                        .await?,
                )?
            }
            "cmd_autofill_query" => {
                let ctx: AutofillCallerContext = from_json(body)?;
                to_json(&self.cmd_autofill_query(&ctx)?)?
            }
            "cmd_autofill_fill" => {
                let a: AutofillFillArgs = from_json(body)?;
                to_json(&self.cmd_autofill_fill(
                    &a.item_id,
                    &a.context,
                    a.unix_timestamp_seconds,
                )?)?
            }
            other => return Err(MobileError::UnknownCommand(other.to_owned())),
        };
        Ok(out)
    }
}

fn item_to_detail_dto(item: &VaultItem) -> ItemDetailDto {
    ItemDetailDto {
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

fn parse_uuid(raw: &str) -> Result<Uuid, MobileError> {
    Uuid::parse_str(raw.trim()).map_err(|err| MobileError::InvalidInput(err.to_string()))
}

fn parse_rfc3339(raw: &str) -> Result<DateTime<Utc>, MobileError> {
    DateTime::parse_from_rfc3339(raw.trim())
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|err| MobileError::InvalidInput(err.to_string()))
}

fn from_json<'a, T: Deserialize<'a>>(raw: &'a str) -> Result<T, MobileError> {
    serde_json::from_str(raw).map_err(|err| MobileError::InvalidInput(err.to_string()))
}

fn to_json<T: Serialize>(value: &T) -> Result<String, MobileError> {
    serde_json::to_string(value).map_err(|err| MobileError::InvalidInput(err.to_string()))
}
