//! Differential offline-first vault synchronization, semantic conflict detection, and password rotation.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use anvil_core::crypto::{
    KdfParams, MasterPassword, VaultKey, VaultSubKeys, aad_blob, decrypt_envelope,
    derive_master_key, derive_master_subkeys, derive_vault_subkeys, encrypt_envelope,
    generate_kdf_salt, unwrap_vault_key, wrap_vault_key,
};
use anvil_core::media::process_custom_logo;
use anvil_core::models::{
    EncryptedFolderRecord, EncryptedItemRecord, VaultBlob, VaultFolder, VaultItem, VaultSnapshot,
    decrypt_blob, decrypt_folder, decrypt_item, encrypt_blob, encrypt_folder, encrypt_item,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::api_client::{
    AnvilApiClient, BlobReencryptUpsertDto, FolderUpsertDto, ItemUpsertDto, PushSyncOutcome,
    ReencryptRecordUpsertDto, RegisterRequestDto, RotatePasswordRequestDto,
    RotateVaultKeyRequestDto, SyncPushRequestDto, SyncResponseDto,
};
use crate::cache::{
    CachedAccount, CachedEncryptedBlob, CachedEncryptedFolder, CachedEncryptedItem,
    ConflictEntityKind, EncryptedLocalCache, MutationEntityKind, MutationOpKind,
    StoredSyncConflict,
};
use crate::error::ClientError;
use crate::lock_manager::VaultLockManager;

/// Interactive conflict resolution choice presented when local and server records diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictResolution {
    KeepLocal,
    KeepServer,
    DuplicateBoth,
}

/// Decrypted side-by-side view of an item or folder conflict.
#[derive(Debug, Clone)]
pub enum DecryptedConflictView {
    Item {
        conflict_id: Uuid,
        entity_id: Uuid,
        local: Box<VaultItem>,
        server: Option<Box<VaultItem>>,
        server_deleted: bool,
        server_revision: i64,
    },
    Folder {
        conflict_id: Uuid,
        entity_id: Uuid,
        local: VaultFolder,
        server: Option<VaultFolder>,
        server_deleted: bool,
        server_revision: i64,
    },
}

/// Outcome report from a synchronization pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub current_revision: i64,
    pub pushed_mutations: usize,
    pub auto_merged_identical: usize,
    pub pending_conflicts: usize,
}

/// Summary of an emergency `VaultKey` rotation and full ciphertext re-encryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmergencyKeyRotationReport {
    pub key_version: u32,
    pub new_revision: i64,
    pub reencrypted_folders: usize,
    pub reencrypted_items: usize,
    pub reencrypted_blobs: usize,
}

/// High-level client coordinator binding `AnvilApiClient`, `EncryptedLocalCache`, and `VaultLockManager`.
#[derive(Debug)]
pub struct ClientSyncEngine {
    pub api: AnvilApiClient,
    pub cache: EncryptedLocalCache,
    pub lock: VaultLockManager,
    device_name: String,
    device_platform: String,
}

impl ClientSyncEngine {
    pub fn new(
        api: AnvilApiClient,
        cache: EncryptedLocalCache,
        lock: VaultLockManager,
        device_name: impl Into<String>,
        device_platform: impl Into<String>,
    ) -> Self {
        Self {
            api,
            cache,
            lock,
            device_name: device_name.into(),
            device_platform: device_platform.into(),
        }
    }

    pub async fn register_and_unlock(
        &self,
        email: &str,
        master_password: &str,
        invite_token: Option<&str>,
        kdf_params: KdfParams,
    ) -> Result<CachedAccount, ClientError> {
        kdf_params.validate()?;
        let normalized_email = email.trim().to_lowercase();
        let user_id = Uuid::new_v4();
        let kdf_salt = generate_kdf_salt()?;
        let pw = MasterPassword::new(master_password);
        let mk = derive_master_key(&pw, &kdf_salt, &kdf_params)?;
        let (mek, auth_hash) = derive_master_subkeys(&mk, &kdf_salt)?;
        let vault_key = VaultKey::generate()?;
        let wrapped_vk = wrap_vault_key(&mek, &vault_key, user_id, 1)?;

        let reg_resp = self
            .api
            .register(&RegisterRequestDto {
                user_id,
                email: normalized_email.clone(),
                kdf_params,
                kdf_salt_b64: STANDARD.encode(kdf_salt),
                master_auth_hash_b64: STANDARD.encode(auth_hash.as_bytes()),
                encrypted_vault_key_b64: STANDARD.encode(&wrapped_vk),
                invite_token: invite_token.map(ToOwned::to_owned),
                device_name: self.device_name.clone(),
                device_platform: self.device_platform.clone(),
            })
            .await?;

        let account = CachedAccount {
            user_id: reg_resp.user.user_id,
            server_url: self.api.base_url().to_owned(),
            email: reg_resp.user.email,
            role: reg_resp.user.role,
            kdf_memory_kib: reg_resp.user.kdf_params.memory_kib,
            kdf_iterations: reg_resp.user.kdf_params.iterations,
            kdf_parallelism: reg_resp.user.kdf_params.parallelism,
            kdf_salt: kdf_salt.to_vec(),
            key_version: reg_resp.user.key_version,
            encrypted_vault_key: wrapped_vk,
            last_synced_revision: reg_resp.user.sync_revision,
            biometric_sealed_vault_key: None,
            updated_at: Utc::now(),
        };
        self.cache.clear_all().await?;
        self.cache.save_account(&account).await?;

        let subkeys = derive_vault_subkeys(&vault_key)?;
        self.lock.unlock(
            account.user_id,
            account.key_version,
            vault_key,
            subkeys,
            Vec::new(),
            Vec::new(),
        );
        Ok(account)
    }

    pub async fn login_and_unlock(
        &self,
        email: &str,
        master_password: &str,
    ) -> Result<CachedAccount, ClientError> {
        let normalized_email = email.trim().to_lowercase();
        let pre = self.api.prelogin(&normalized_email).await?;
        let kdf_params = KdfParams {
            algorithm: pre.kdf_algorithm,
            memory_kib: pre.kdf_memory_kib,
            iterations: pre.kdf_iterations,
            parallelism: pre.kdf_parallelism,
        };
        kdf_params.validate()?;

        let salt_bytes = STANDARD
            .decode(pre.kdf_salt_b64.trim())
            .map_err(|_| ClientError::CacheIntegrity("invalid server kdf_salt_b64".to_owned()))?;
        if salt_bytes.len() != 32 {
            return Err(ClientError::CacheIntegrity(
                "server returned non-32-byte KDF salt".to_owned(),
            ));
        }
        let mut kdf_salt = [0u8; 32];
        kdf_salt.copy_from_slice(&salt_bytes);

        let pw = MasterPassword::new(master_password);
        let mk = derive_master_key(&pw, &kdf_salt, &kdf_params)?;
        let (mek, auth_hash) = derive_master_subkeys(&mk, &kdf_salt)?;

        let login_resp = self
            .api
            .login(
                &normalized_email,
                auth_hash.as_bytes(),
                &self.device_name,
                &self.device_platform,
            )
            .await?;

        let wrapped_vk = STANDARD
            .decode(login_resp.encrypted_vault_key_b64.trim())
            .map_err(|_| ClientError::CacheIntegrity("invalid wrapped vault key".to_owned()))?;
        let vault_key = unwrap_vault_key(
            &mek,
            &wrapped_vk,
            login_resp.user_id,
            login_resp.key_version,
        )?;
        let subkeys = derive_vault_subkeys(&vault_key)?;

        let existing = self.cache.load_account().await?;
        let reset_cache = existing
            .as_ref()
            .is_none_or(|a| a.user_id != login_resp.user_id);
        if reset_cache {
            self.cache.clear_all().await?;
        }

        let initial_rev = if reset_cache {
            0
        } else {
            existing.map_or(0, |a| a.last_synced_revision)
        };

        let account = CachedAccount {
            user_id: login_resp.user_id,
            server_url: self.api.base_url().to_owned(),
            email: login_resp.email,
            role: login_resp.role,
            kdf_memory_kib: kdf_params.memory_kib,
            kdf_iterations: kdf_params.iterations,
            kdf_parallelism: kdf_params.parallelism,
            kdf_salt: kdf_salt.to_vec(),
            key_version: login_resp.key_version,
            encrypted_vault_key: wrapped_vk,
            last_synced_revision: initial_rev,
            biometric_sealed_vault_key: None,
            updated_at: Utc::now(),
        };
        self.cache.save_account(&account).await?;

        self.lock.unlock(
            account.user_id,
            account.key_version,
            vault_key,
            subkeys,
            Vec::new(),
            Vec::new(),
        );
        self.sync_now().await?;
        self.cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)
    }

    /// Unlocks from the local encrypted cache using the Master Password (works offline).
    pub async fn unlock_with_password(&self, master_password: &str) -> Result<(), ClientError> {
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let kdf_salt = fixed_salt(&acct.kdf_salt)?;
        let kdf_params = account_kdf_params(&acct)?;
        let pw = MasterPassword::new(master_password);

        let (_, vault_key) = self.lock.verify_master_password_reauth(
            &pw,
            &kdf_params,
            &kdf_salt,
            &acct.encrypted_vault_key,
            acct.user_id,
            acct.key_version,
        )?;
        let subkeys = derive_vault_subkeys(&vault_key)?;
        let (folders, items) = self.decrypt_cached_vault(&subkeys, acct.user_id).await?;

        self.lock.unlock(
            acct.user_id,
            acct.key_version,
            vault_key,
            subkeys,
            folders,
            items,
        );
        Ok(())
    }

    /// Unlocks from an already unsealed `VaultKey` (typically retrieved from OS biometric enclave).
    pub async fn unlock_with_vault_key(&self, vault_key: VaultKey) -> Result<(), ClientError> {
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let subkeys = derive_vault_subkeys(&vault_key)?;
        let (folders, items) = self.decrypt_cached_vault(&subkeys, acct.user_id).await?;
        self.lock.unlock(
            acct.user_id,
            acct.key_version,
            vault_key,
            subkeys,
            folders,
            items,
        );
        Ok(())
    }

    pub fn lock_vault(&self) {
        self.lock.lock();
    }

    pub fn check_inactivity(&self) -> bool {
        self.lock.check_inactivity_and_lock(Instant::now())
    }

    pub async fn save_folder(&self, mut folder: VaultFolder) -> Result<VaultFolder, ClientError> {
        let (user_id, _, _, subkeys) = self.lock.keys_snapshot()?;
        folder.updated_at = Utc::now();
        let rec = encrypt_folder(&subkeys, user_id, &folder, 1)?;
        self.cache
            .upsert_cached_folder(
                user_id,
                &CachedEncryptedFolder {
                    id: rec.id,
                    encrypted_data: rec.encrypted_data.clone(),
                    revision: rec.revision,
                    deleted: false,
                    updated_at: rec.updated_at,
                },
            )
            .await?;
        self.cache
            .queue_mutation(
                user_id,
                MutationEntityKind::Folder,
                folder.id,
                MutationOpKind::Upsert,
                None,
                Some(&rec.encrypted_data),
            )
            .await?;
        self.lock.upsert_folder(folder.clone())?;
        Ok(folder)
    }

    pub async fn delete_folder(&self, folder_id: Uuid) -> Result<(), ClientError> {
        let (user_id, _, _, _) = self.lock.keys_snapshot()?;
        self.cache
            .upsert_cached_folder(
                user_id,
                &CachedEncryptedFolder {
                    id: folder_id,
                    encrypted_data: Vec::new(),
                    revision: 1,
                    deleted: true,
                    updated_at: Utc::now(),
                },
            )
            .await?;
        self.cache
            .queue_mutation(
                user_id,
                MutationEntityKind::Folder,
                folder_id,
                MutationOpKind::Delete,
                None,
                None,
            )
            .await?;
        self.lock.remove_folder(folder_id)?;
        Ok(())
    }

    pub async fn save_item(&self, mut item: VaultItem) -> Result<VaultItem, ClientError> {
        let (user_id, _, _, subkeys) = self.lock.keys_snapshot()?;
        item.updated_at = Utc::now();
        item.item_version = item.item_version.saturating_add(1);
        let rec = encrypt_item(&subkeys, user_id, &item, 1)?;
        self.cache
            .upsert_cached_item(
                user_id,
                &CachedEncryptedItem {
                    id: rec.id,
                    encrypted_data: rec.encrypted_data.clone(),
                    revision: rec.revision,
                    deleted: false,
                    updated_at: rec.updated_at,
                },
            )
            .await?;
        self.cache
            .queue_mutation(
                user_id,
                MutationEntityKind::Item,
                item.id,
                MutationOpKind::Upsert,
                None,
                Some(&rec.encrypted_data),
            )
            .await?;
        self.lock.upsert_item(item.clone())?;
        Ok(item)
    }

    pub async fn delete_item(&self, item_id: Uuid) -> Result<(), ClientError> {
        let (user_id, _, _, _) = self.lock.keys_snapshot()?;
        self.cache
            .upsert_cached_item(
                user_id,
                &CachedEncryptedItem {
                    id: item_id,
                    encrypted_data: Vec::new(),
                    revision: 1,
                    deleted: true,
                    updated_at: Utc::now(),
                },
            )
            .await?;
        self.cache
            .queue_mutation(
                user_id,
                MutationEntityKind::Item,
                item_id,
                MutationOpKind::Delete,
                None,
                None,
            )
            .await?;
        self.lock.remove_item(item_id)?;
        Ok(())
    }

    /// Resizes, strips EXIF metadata, encrypts under `(user_id, item_id, blob_id)`, and queues upload.
    pub async fn attach_custom_logo(
        &self,
        item_id: Uuid,
        raw_image_bytes: &[u8],
    ) -> Result<(Uuid, VaultItem), ClientError> {
        let (user_id, _, _, subkeys) = self.lock.keys_snapshot()?;
        let mut item = self.lock.get_item(item_id)?;
        let processed = process_custom_logo(raw_image_bytes)?;
        let blob_id = Uuid::new_v4();
        let now = Utc::now();

        let blob = VaultBlob {
            id: blob_id,
            item_id,
            mime_type: processed.mime_type,
            data: Zeroizing::new(processed.bytes),
            updated_at: now,
        };
        let enc_blob = encrypt_blob(&subkeys, user_id, &blob, 1)?;
        let sha = Sha256::digest(&enc_blob.encrypted_blob);
        let byte_size = i32::try_from(enc_blob.encrypted_blob.len())
            .map_err(|_| ClientError::CacheIntegrity("blob size overflow".to_owned()))?;

        self.cache
            .upsert_cached_blob(
                user_id,
                &CachedEncryptedBlob {
                    id: blob_id,
                    item_id,
                    encrypted_blob: enc_blob.encrypted_blob.clone(),
                    byte_size,
                    sha256_ciphertext: sha.to_vec(),
                    revision: 1,
                    deleted: false,
                    updated_at: now,
                },
            )
            .await?;

        self.cache
            .queue_mutation(
                user_id,
                MutationEntityKind::Blob,
                blob_id,
                MutationOpKind::Upsert,
                Some(item_id),
                Some(&enc_blob.encrypted_blob),
            )
            .await?;

        item.logo.blob_id = Some(blob_id);
        let saved_item = self.save_item(item).await?;
        Ok((blob_id, saved_item))
    }

    /// Loads and decrypts an attached logo blob from the offline cache or server.
    pub async fn load_custom_logo(
        &self,
        item_id: Uuid,
        blob_id: Uuid,
    ) -> Result<VaultBlob, ClientError> {
        let (user_id, _, _, subkeys) = self.lock.keys_snapshot()?;
        if let Some(cached) = self.cache.get_cached_blob(user_id, blob_id).await? {
            let rec = anvil_core::models::EncryptedBlobRecord {
                id: cached.id,
                item_id: cached.item_id,
                encrypted_blob: cached.encrypted_blob,
                revision: cached.revision,
                deleted: cached.deleted,
                updated_at: cached.updated_at,
            };
            return Ok(decrypt_blob(&subkeys, user_id, &rec)?);
        }

        let dl = self.api.get_blob(blob_id).await?;
        let sha = Sha256::digest(&dl.encrypted_bytes);
        let byte_size = i32::try_from(dl.encrypted_bytes.len())
            .map_err(|_| ClientError::CacheIntegrity("downloaded blob overflow".to_owned()))?;
        let resolved_item_id = dl.item_id.unwrap_or(item_id);

        self.cache
            .upsert_cached_blob(
                user_id,
                &CachedEncryptedBlob {
                    id: blob_id,
                    item_id: resolved_item_id,
                    encrypted_blob: dl.encrypted_bytes.clone(),
                    byte_size,
                    sha256_ciphertext: sha.to_vec(),
                    revision: dl.revision,
                    deleted: false,
                    updated_at: Utc::now(),
                },
            )
            .await?;

        let rec = anvil_core::models::EncryptedBlobRecord {
            id: blob_id,
            item_id: resolved_item_id,
            encrypted_blob: dl.encrypted_bytes,
            revision: dl.revision,
            deleted: false,
            updated_at: Utc::now(),
        };
        Ok(decrypt_blob(&subkeys, user_id, &rec)?)
    }

    /// Executes offline-first differential sync, semantic merge, conflict capture, and RAM refresh.
    pub async fn sync_now(&self) -> Result<SyncReport, ClientError> {
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        if !self.api.has_session().await {
            return Err(ClientError::NotAuthenticated);
        }

        let user_id = acct.user_id;
        let subkeys = self.lock.keys_snapshot().ok().map(|(_, _, _, sk)| sk);
        let mut base_revision = acct.last_synced_revision;
        let mut pushed_mutations = 0usize;
        let mut auto_merged_identical = 0usize;

        for _attempt in 0..3 {
            let queued = self.cache.list_queued_mutations(user_id).await?;
            let batch_mutations: Vec<_> = queued
                .iter()
                .filter(|m| m.entity_kind != MutationEntityKind::Blob)
                .cloned()
                .collect();

            if batch_mutations.is_empty() {
                let delta = self.api.pull_sync(base_revision).await?;
                self.apply_server_delta(user_id, &delta, &HashSet::new())
                    .await?;
                base_revision = delta.current_revision;
                self.cache
                    .update_synced_revision(user_id, base_revision)
                    .await?;
                break;
            }

            let push_req = build_push_request(base_revision, &batch_mutations);
            match self.api.push_sync(&push_req).await? {
                PushSyncOutcome::Committed(resp) => {
                    for m in &batch_mutations {
                        self.cache
                            .remove_queued_mutation(user_id, m.entity_kind, m.entity_id)
                            .await?;
                    }
                    pushed_mutations += batch_mutations.len();
                    base_revision = resp.new_revision;
                    let tail = self.api.pull_sync(base_revision).await?;
                    self.apply_server_delta(user_id, &tail, &HashSet::new())
                        .await?;
                    base_revision = tail.current_revision;
                    self.cache
                        .update_synced_revision(user_id, base_revision)
                        .await?;
                    break;
                }
                PushSyncOutcome::Conflict(server_delta) => {
                    let server_folders: HashMap<Uuid, _> = server_delta
                        .folders
                        .iter()
                        .map(|f| (f.id, f.clone()))
                        .collect();
                    let server_items: HashMap<Uuid, _> = server_delta
                        .items
                        .iter()
                        .map(|i| (i.id, i.clone()))
                        .collect();

                    let mut overlapped_keys = HashSet::new();
                    for m in &batch_mutations {
                        match m.entity_kind {
                            MutationEntityKind::Folder => {
                                if let Some(srv) = server_folders.get(&m.entity_id) {
                                    overlapped_keys
                                        .insert((MutationEntityKind::Folder, m.entity_id));
                                    let identical = folders_semantically_identical(
                                        subkeys.as_ref(),
                                        user_id,
                                        m,
                                        srv,
                                    )?;
                                    if identical {
                                        auto_merged_identical += 1;
                                    } else {
                                        self.cache
                                            .save_conflict(&StoredSyncConflict {
                                                id: Uuid::new_v4(),
                                                user_id,
                                                entity_kind: ConflictEntityKind::Folder,
                                                entity_id: m.entity_id,
                                                local_encrypted_data: m
                                                    .encrypted_payload
                                                    .clone()
                                                    .unwrap_or_default(),
                                                server_encrypted_data: (!srv.deleted)
                                                    .then(|| {
                                                        STANDARD
                                                            .decode(srv.encrypted_data_b64.trim())
                                                    })
                                                    .transpose()
                                                    .map_err(|_| {
                                                        ClientError::CacheIntegrity(
                                                            "invalid server folder b64".to_owned(),
                                                        )
                                                    })?,
                                                server_deleted: srv.deleted,
                                                server_revision: srv.revision,
                                                detected_at: Utc::now(),
                                            })
                                            .await?;
                                    }
                                    self.cache
                                        .remove_queued_mutation(
                                            user_id,
                                            MutationEntityKind::Folder,
                                            m.entity_id,
                                        )
                                        .await?;
                                }
                            }
                            MutationEntityKind::Item => {
                                if let Some(srv) = server_items.get(&m.entity_id) {
                                    overlapped_keys.insert((MutationEntityKind::Item, m.entity_id));
                                    let identical = items_semantically_identical(
                                        subkeys.as_ref(),
                                        user_id,
                                        m,
                                        srv,
                                    )?;
                                    if identical {
                                        auto_merged_identical += 1;
                                    } else {
                                        self.cache
                                            .save_conflict(&StoredSyncConflict {
                                                id: Uuid::new_v4(),
                                                user_id,
                                                entity_kind: ConflictEntityKind::Item,
                                                entity_id: m.entity_id,
                                                local_encrypted_data: m
                                                    .encrypted_payload
                                                    .clone()
                                                    .unwrap_or_default(),
                                                server_encrypted_data: (!srv.deleted)
                                                    .then(|| {
                                                        STANDARD
                                                            .decode(srv.encrypted_data_b64.trim())
                                                    })
                                                    .transpose()
                                                    .map_err(|_| {
                                                        ClientError::CacheIntegrity(
                                                            "invalid server item b64".to_owned(),
                                                        )
                                                    })?,
                                                server_deleted: srv.deleted,
                                                server_revision: srv.revision,
                                                detected_at: Utc::now(),
                                            })
                                            .await?;
                                    }
                                    self.cache
                                        .remove_queued_mutation(
                                            user_id,
                                            MutationEntityKind::Item,
                                            m.entity_id,
                                        )
                                        .await?;
                                }
                            }
                            MutationEntityKind::Blob => {}
                        }
                    }

                    // Keep non-conflicting queued local writes intact while applying all server delta rows
                    // for overlapped or non-queued IDs.
                    let remaining = self.cache.list_queued_mutations(user_id).await?;
                    let preserve_local: HashSet<(MutationEntityKind, Uuid)> = remaining
                        .iter()
                        .filter(|m| m.entity_kind != MutationEntityKind::Blob)
                        .map(|m| (m.entity_kind, m.entity_id))
                        .collect();

                    self.apply_server_delta(user_id, &server_delta, &preserve_local)
                        .await?;
                    base_revision = server_delta.current_revision;
                    self.cache
                        .update_synced_revision(user_id, base_revision)
                        .await?;
                }
            }
        }

        // Process queued encrypted blob uploads/deletions after item batches succeed on server.
        let remaining_blobs: Vec<_> = self
            .cache
            .list_queued_mutations(user_id)
            .await?
            .into_iter()
            .filter(|m| m.entity_kind == MutationEntityKind::Blob)
            .collect();

        for blob_mut in remaining_blobs {
            match blob_mut.op_kind {
                MutationOpKind::Upsert => {
                    if let (Some(item_id), Some(payload)) =
                        (blob_mut.item_id, blob_mut.encrypted_payload.clone())
                    {
                        let resp = self
                            .api
                            .put_blob(item_id, blob_mut.entity_id, payload)
                            .await?;
                        base_revision = resp.revision;
                        self.cache
                            .update_synced_revision(user_id, base_revision)
                            .await?;
                        pushed_mutations += 1;
                    }
                }
                MutationOpKind::Delete => {
                    let rev = self.api.delete_blob(blob_mut.entity_id).await?;
                    base_revision = rev;
                    self.cache
                        .update_synced_revision(user_id, base_revision)
                        .await?;
                    pushed_mutations += 1;
                }
            }
            self.cache
                .remove_queued_mutation(user_id, MutationEntityKind::Blob, blob_mut.entity_id)
                .await?;
        }

        if let Some(sk) = subkeys {
            let (folders, items) = self.decrypt_cached_vault(&sk, user_id).await?;
            self.lock.replace_decrypted_data(folders, items);
        }

        let pending_conflicts = self.cache.list_conflicts(user_id).await?.len();
        Ok(SyncReport {
            current_revision: base_revision,
            pushed_mutations,
            auto_merged_identical,
            pending_conflicts,
        })
    }

    pub async fn list_decrypted_conflicts(
        &self,
    ) -> Result<Vec<DecryptedConflictView>, ClientError> {
        let (user_id, _, _, subkeys) = self.lock.keys_snapshot()?;
        let stored = self.cache.list_conflicts(user_id).await?;
        let mut out = Vec::with_capacity(stored.len());

        for c in stored {
            match c.entity_kind {
                ConflictEntityKind::Item => {
                    let local = decrypt_item(
                        &subkeys,
                        user_id,
                        &EncryptedItemRecord {
                            id: c.entity_id,
                            encrypted_data: c.local_encrypted_data,
                            revision: c.server_revision,
                            deleted: false,
                            updated_at: c.detected_at,
                        },
                    )?;
                    let server = c
                        .server_encrypted_data
                        .map(|bytes| {
                            decrypt_item(
                                &subkeys,
                                user_id,
                                &EncryptedItemRecord {
                                    id: c.entity_id,
                                    encrypted_data: bytes,
                                    revision: c.server_revision,
                                    deleted: false,
                                    updated_at: c.detected_at,
                                },
                            )
                        })
                        .transpose()?;
                    out.push(DecryptedConflictView::Item {
                        conflict_id: c.id,
                        entity_id: c.entity_id,
                        local: Box::new(local),
                        server: server.map(Box::new),
                        server_deleted: c.server_deleted,
                        server_revision: c.server_revision,
                    });
                }
                ConflictEntityKind::Folder => {
                    let local = decrypt_folder(
                        &subkeys,
                        user_id,
                        &EncryptedFolderRecord {
                            id: c.entity_id,
                            encrypted_data: c.local_encrypted_data,
                            revision: c.server_revision,
                            deleted: false,
                            updated_at: c.detected_at,
                        },
                    )?;
                    let server = c
                        .server_encrypted_data
                        .map(|bytes| {
                            decrypt_folder(
                                &subkeys,
                                user_id,
                                &EncryptedFolderRecord {
                                    id: c.entity_id,
                                    encrypted_data: bytes,
                                    revision: c.server_revision,
                                    deleted: false,
                                    updated_at: c.detected_at,
                                },
                            )
                        })
                        .transpose()?;
                    out.push(DecryptedConflictView::Folder {
                        conflict_id: c.id,
                        entity_id: c.entity_id,
                        local,
                        server,
                        server_deleted: c.server_deleted,
                        server_revision: c.server_revision,
                    });
                }
            }
        }
        Ok(out)
    }

    pub async fn resolve_conflict(
        &self,
        conflict_id: Uuid,
        resolution: ConflictResolution,
    ) -> Result<SyncReport, ClientError> {
        let (user_id, _, _, subkeys) = self.lock.keys_snapshot()?;
        let conflicts = self.cache.list_conflicts(user_id).await?;
        let conflict = conflicts
            .into_iter()
            .find(|c| c.id == conflict_id)
            .ok_or(ClientError::ConflictNotFound)?;

        match resolution {
            ConflictResolution::KeepServer => {
                // Server state was already written to cache; dropping the conflict suffices.
                self.cache.delete_conflict(user_id, conflict_id).await?;
            }
            ConflictResolution::KeepLocal => {
                match conflict.entity_kind {
                    ConflictEntityKind::Item => {
                        let rec = CachedEncryptedItem {
                            id: conflict.entity_id,
                            encrypted_data: conflict.local_encrypted_data.clone(),
                            revision: conflict.server_revision,
                            deleted: false,
                            updated_at: Utc::now(),
                        };
                        self.cache.upsert_cached_item(user_id, &rec).await?;
                        self.cache
                            .queue_mutation(
                                user_id,
                                MutationEntityKind::Item,
                                conflict.entity_id,
                                MutationOpKind::Upsert,
                                None,
                                Some(&conflict.local_encrypted_data),
                            )
                            .await?;
                    }
                    ConflictEntityKind::Folder => {
                        let rec = CachedEncryptedFolder {
                            id: conflict.entity_id,
                            encrypted_data: conflict.local_encrypted_data.clone(),
                            revision: conflict.server_revision,
                            deleted: false,
                            updated_at: Utc::now(),
                        };
                        self.cache.upsert_cached_folder(user_id, &rec).await?;
                        self.cache
                            .queue_mutation(
                                user_id,
                                MutationEntityKind::Folder,
                                conflict.entity_id,
                                MutationOpKind::Upsert,
                                None,
                                Some(&conflict.local_encrypted_data),
                            )
                            .await?;
                    }
                }
                self.cache.delete_conflict(user_id, conflict_id).await?;
            }
            ConflictResolution::DuplicateBoth => {
                match conflict.entity_kind {
                    ConflictEntityKind::Item => {
                        let mut duplicate = decrypt_item(
                            &subkeys,
                            user_id,
                            &EncryptedItemRecord {
                                id: conflict.entity_id,
                                encrypted_data: conflict.local_encrypted_data,
                                revision: conflict.server_revision,
                                deleted: false,
                                updated_at: conflict.detected_at,
                            },
                        )?;
                        duplicate.id = Uuid::new_v4();
                        duplicate.title = format!("{} (Conflit)", duplicate.title);
                        duplicate.updated_at = Utc::now();
                        self.save_item(duplicate).await?;
                    }
                    ConflictEntityKind::Folder => {
                        let mut duplicate = decrypt_folder(
                            &subkeys,
                            user_id,
                            &EncryptedFolderRecord {
                                id: conflict.entity_id,
                                encrypted_data: conflict.local_encrypted_data,
                                revision: conflict.server_revision,
                                deleted: false,
                                updated_at: conflict.detected_at,
                            },
                        )?;
                        duplicate.id = Uuid::new_v4();
                        duplicate.name = format!("{} (Conflit)", duplicate.name);
                        duplicate.updated_at = Utc::now();
                        self.save_folder(duplicate).await?;
                    }
                }
                self.cache.delete_conflict(user_id, conflict_id).await?;
            }
        }

        let (folders, items) = self.decrypt_cached_vault(&subkeys, user_id).await?;
        self.lock.replace_decrypted_data(folders, items);

        if self.api.has_session().await {
            self.sync_now().await
        } else {
            let acct = self
                .cache
                .load_account()
                .await?
                .ok_or(ClientError::NotConfigured)?;
            let pending = self.cache.list_conflicts(user_id).await?.len();
            Ok(SyncReport {
                current_revision: acct.last_synced_revision,
                pushed_mutations: 0,
                auto_merged_identical: 0,
                pending_conflicts: pending,
            })
        }
    }

    pub async fn rotate_master_password(
        &self,
        current_password: &str,
        new_password: &str,
        revoke_other_sessions: bool,
    ) -> Result<u32, ClientError> {
        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let old_salt = fixed_salt(&acct.kdf_salt)?;
        let kdf_params = account_kdf_params(&acct)?;
        let cur_pw = MasterPassword::new(current_password);

        let (cur_auth_hash, vault_key) = self.lock.verify_master_password_reauth(
            &cur_pw,
            &kdf_params,
            &old_salt,
            &acct.encrypted_vault_key,
            acct.user_id,
            acct.key_version,
        )?;

        let new_salt = generate_kdf_salt()?;
        let new_pw = MasterPassword::new(new_password);
        let new_mk = derive_master_key(&new_pw, &new_salt, &kdf_params)?;
        let (new_mek, new_auth_hash) = derive_master_subkeys(&new_mk, &new_salt)?;
        let new_key_version = acct.key_version.saturating_add(1);
        let new_wrapped_vk = wrap_vault_key(&new_mek, &vault_key, acct.user_id, new_key_version)?;

        let resp = self
            .api
            .rotate_password(&RotatePasswordRequestDto {
                current_master_auth_hash_b64: STANDARD.encode(cur_auth_hash),
                new_master_auth_hash_b64: STANDARD.encode(new_auth_hash.as_bytes()),
                new_kdf_salt_b64: STANDARD.encode(new_salt),
                new_kdf_params: kdf_params,
                new_key_version,
                new_encrypted_vault_key_b64: STANDARD.encode(&new_wrapped_vk),
                revoke_other_sessions,
            })
            .await?;

        self.cache
            .update_key_material(
                acct.user_id,
                kdf_params,
                &new_salt,
                resp.key_version,
                &new_wrapped_vk,
            )
            .await?;
        let _ = self.lock.update_key_version(resp.key_version);
        Ok(resp.key_version)
    }

    /// Generates a brand-new `VaultKey`, re-encrypts all active folders, items, and blobs,
    /// clears stale biometric enclave seals, and optionally revokes all other active sessions.
    pub async fn emergency_rotate_vault_key(
        &self,
        current_master_password: &str,
        revoke_other_sessions: bool,
    ) -> Result<EmergencyKeyRotationReport, ClientError> {
        let initial_acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let pending_conflicts = self.cache.list_conflicts(initial_acct.user_id).await?;
        if !pending_conflicts.is_empty() {
            return Err(ClientError::UnresolvedConflicts {
                conflict_count: pending_conflicts.len(),
            });
        }

        let sync_report = self.sync_now().await?;
        if sync_report.pending_conflicts > 0 {
            return Err(ClientError::UnresolvedConflicts {
                conflict_count: sync_report.pending_conflicts,
            });
        }

        let acct = self
            .cache
            .load_account()
            .await?
            .ok_or(ClientError::NotConfigured)?;
        let salt = fixed_salt(&acct.kdf_salt)?;
        let kdf_params = account_kdf_params(&acct)?;
        let pw = MasterPassword::new(current_master_password);
        let mk = derive_master_key(&pw, &salt, &kdf_params)?;
        let (mek, cur_auth_hash) = derive_master_subkeys(&mk, &salt)?;
        let old_vk = unwrap_vault_key(
            &mek,
            &acct.encrypted_vault_key,
            acct.user_id,
            acct.key_version,
        )
        .map_err(|_| ClientError::InvalidMasterPassword)?;
        let old_subkeys = derive_vault_subkeys(&old_vk)?;

        let new_vk = VaultKey::generate()?;
        let new_subkeys = derive_vault_subkeys(&new_vk)?;
        let new_key_version = acct.key_version.saturating_add(1);
        let wrapped_new_vk = wrap_vault_key(&mek, &new_vk, acct.user_id, new_key_version)?;
        let next_rev_hint = acct.last_synced_revision.saturating_add(1);

        let cached_folders = self.cache.list_active_folders(acct.user_id).await?;
        let mut decrypted_folders = Vec::with_capacity(cached_folders.len());
        let mut req_folders = Vec::with_capacity(cached_folders.len());
        let mut new_folder_records = Vec::with_capacity(cached_folders.len());

        for cf in cached_folders {
            let folder = decrypt_folder(
                &old_subkeys,
                acct.user_id,
                &EncryptedFolderRecord {
                    id: cf.id,
                    encrypted_data: cf.encrypted_data,
                    revision: cf.revision,
                    deleted: cf.deleted,
                    updated_at: cf.updated_at,
                },
            )?;
            let reenc = encrypt_folder(&new_subkeys, acct.user_id, &folder, next_rev_hint)?;
            req_folders.push(ReencryptRecordUpsertDto {
                id: reenc.id,
                encrypted_data_b64: STANDARD.encode(&reenc.encrypted_data),
            });
            new_folder_records.push(reenc);
            decrypted_folders.push(folder);
        }

        let cached_items = self.cache.list_active_items(acct.user_id).await?;
        let mut decrypted_items = Vec::with_capacity(cached_items.len());
        let mut req_items = Vec::with_capacity(cached_items.len());
        let mut new_item_records = Vec::with_capacity(cached_items.len());
        let mut req_blobs = Vec::new();
        let mut new_blob_records = Vec::new();

        for ci in cached_items {
            let item = decrypt_item(
                &old_subkeys,
                acct.user_id,
                &EncryptedItemRecord {
                    id: ci.id,
                    encrypted_data: ci.encrypted_data,
                    revision: ci.revision,
                    deleted: ci.deleted,
                    updated_at: ci.updated_at,
                },
            )?;
            let reenc_item = encrypt_item(&new_subkeys, acct.user_id, &item, next_rev_hint)?;
            req_items.push(ReencryptRecordUpsertDto {
                id: reenc_item.id,
                encrypted_data_b64: STANDARD.encode(&reenc_item.encrypted_data),
            });
            new_item_records.push(reenc_item);

            if let Some(blob_id) = item.logo.blob_id {
                let old_blob_rec = if let Some(cached) =
                    self.cache.get_cached_blob(acct.user_id, blob_id).await?
                {
                    anvil_core::models::EncryptedBlobRecord {
                        id: cached.id,
                        item_id: cached.item_id,
                        encrypted_blob: cached.encrypted_blob,
                        revision: cached.revision,
                        deleted: cached.deleted,
                        updated_at: cached.updated_at,
                    }
                } else {
                    let dl = self.api.get_blob(blob_id).await?;
                    anvil_core::models::EncryptedBlobRecord {
                        id: blob_id,
                        item_id: dl.item_id.unwrap_or(item.id),
                        encrypted_blob: dl.encrypted_bytes,
                        revision: dl.revision,
                        deleted: false,
                        updated_at: Utc::now(),
                    }
                };
                let plain_blob = decrypt_blob(&old_subkeys, acct.user_id, &old_blob_rec)?;
                let reenc_blob =
                    encrypt_blob(&new_subkeys, acct.user_id, &plain_blob, next_rev_hint)?;
                req_blobs.push(BlobReencryptUpsertDto {
                    id: reenc_blob.id,
                    item_id: reenc_blob.item_id,
                    encrypted_blob_b64: STANDARD.encode(&reenc_blob.encrypted_blob),
                });
                new_blob_records.push(reenc_blob);
            }

            decrypted_items.push(item);
        }

        let resp = self
            .api
            .rotate_vault_key(&RotateVaultKeyRequestDto {
                current_master_auth_hash_b64: STANDARD.encode(cur_auth_hash.as_bytes()),
                base_revision: acct.last_synced_revision,
                new_key_version,
                new_encrypted_vault_key_b64: STANDARD.encode(&wrapped_new_vk),
                folders: req_folders,
                items: req_items,
                blobs: req_blobs,
                revoke_other_sessions,
            })
            .await?;

        self.cache
            .update_key_material(
                acct.user_id,
                kdf_params,
                &acct.kdf_salt,
                resp.key_version,
                &wrapped_new_vk,
            )
            .await?;
        self.cache
            .update_synced_revision(acct.user_id, resp.new_revision)
            .await?;
        self.cache.set_biometric_seal(acct.user_id, None).await?;

        let folder_count = new_folder_records.len();
        for f in new_folder_records {
            self.cache
                .upsert_cached_folder(
                    acct.user_id,
                    &CachedEncryptedFolder {
                        id: f.id,
                        encrypted_data: f.encrypted_data,
                        revision: resp.new_revision,
                        deleted: false,
                        updated_at: f.updated_at,
                    },
                )
                .await?;
        }

        let item_count = new_item_records.len();
        for i in new_item_records {
            self.cache
                .upsert_cached_item(
                    acct.user_id,
                    &CachedEncryptedItem {
                        id: i.id,
                        encrypted_data: i.encrypted_data,
                        revision: resp.new_revision,
                        deleted: false,
                        updated_at: i.updated_at,
                    },
                )
                .await?;
        }

        let blob_count = new_blob_records.len();
        for b in new_blob_records {
            let sha = Sha256::digest(&b.encrypted_blob).to_vec();
            let byte_size = i32::try_from(b.encrypted_blob.len())
                .map_err(|_| ClientError::CacheIntegrity("rotated blob overflow".to_owned()))?;
            self.cache
                .upsert_cached_blob(
                    acct.user_id,
                    &CachedEncryptedBlob {
                        id: b.id,
                        item_id: b.item_id,
                        encrypted_blob: b.encrypted_blob,
                        byte_size,
                        sha256_ciphertext: sha,
                        revision: resp.new_revision,
                        deleted: false,
                        updated_at: b.updated_at,
                    },
                )
                .await?;
        }

        if self.lock.is_unlocked() {
            self.lock
                .replace_vault_keys(resp.key_version, new_vk, new_subkeys)?;
        } else {
            self.lock.unlock(
                acct.user_id,
                resp.key_version,
                new_vk,
                new_subkeys,
                decrypted_folders,
                decrypted_items,
            );
        }

        Ok(EmergencyKeyRotationReport {
            key_version: resp.key_version,
            new_revision: resp.new_revision,
            reencrypted_folders: folder_count,
            reencrypted_items: item_count,
            reencrypted_blobs: blob_count,
        })
    }

    /// Commits a parsed `ImportPreview` (encrypting every imported folder and item into local cache + queue).
    pub async fn commit_import_snapshot(&self, imported: VaultSnapshot) -> Result<(), ClientError> {
        for folder in imported.folders {
            let existing = self.lock.list_folders()?;
            if !existing.iter().any(|f| f.id == folder.id) {
                self.save_folder(folder).await?;
            }
        }
        for item in imported.items {
            self.save_item(item).await?;
        }
        Ok(())
    }

    async fn apply_server_delta(
        &self,
        user_id: Uuid,
        delta: &SyncResponseDto,
        preserve_local: &HashSet<(MutationEntityKind, Uuid)>,
    ) -> Result<(), ClientError> {
        let env_vk = STANDARD
            .decode(delta.encrypted_vault_key_b64.trim())
            .map_err(|_| ClientError::CacheIntegrity("invalid server vault key".to_owned()))?;
        if let Some(acct) = self.cache.load_account().await?
            && acct.user_id == user_id
        {
            let kdf_params = account_kdf_params(&acct)?;
            self.cache
                .update_key_material(
                    user_id,
                    kdf_params,
                    &acct.kdf_salt,
                    delta.key_version,
                    &env_vk,
                )
                .await?;
        }

        for f in &delta.folders {
            if preserve_local.contains(&(MutationEntityKind::Folder, f.id)) {
                continue;
            }
            let bytes = STANDARD.decode(f.encrypted_data_b64.trim()).map_err(|_| {
                ClientError::CacheIntegrity("invalid folder envelope b64".to_owned())
            })?;
            self.cache
                .upsert_cached_folder(
                    user_id,
                    &CachedEncryptedFolder {
                        id: f.id,
                        encrypted_data: bytes,
                        revision: f.revision,
                        deleted: f.deleted,
                        updated_at: f.updated_at,
                    },
                )
                .await?;
        }

        for item in &delta.items {
            if preserve_local.contains(&(MutationEntityKind::Item, item.id)) {
                continue;
            }
            let bytes = STANDARD
                .decode(item.encrypted_data_b64.trim())
                .map_err(|_| ClientError::CacheIntegrity("invalid item envelope b64".to_owned()))?;
            self.cache
                .upsert_cached_item(
                    user_id,
                    &CachedEncryptedItem {
                        id: item.id,
                        encrypted_data: bytes,
                        revision: item.revision,
                        deleted: item.deleted,
                        updated_at: item.updated_at,
                    },
                )
                .await?;
        }

        for blob in &delta.blobs_meta {
            if blob.deleted {
                self.cache.mark_blob_deleted(user_id, blob.id).await?;
            }
        }
        Ok(())
    }

    async fn decrypt_cached_vault(
        &self,
        subkeys: &VaultSubKeys,
        user_id: Uuid,
    ) -> Result<(Vec<VaultFolder>, Vec<VaultItem>), ClientError> {
        let enc_folders = self.cache.list_active_folders(user_id).await?;
        let mut folders = Vec::with_capacity(enc_folders.len());
        for f in enc_folders {
            let rec = EncryptedFolderRecord {
                id: f.id,
                encrypted_data: f.encrypted_data,
                revision: f.revision,
                deleted: f.deleted,
                updated_at: f.updated_at,
            };
            folders.push(decrypt_folder(subkeys, user_id, &rec)?);
        }

        let enc_items = self.cache.list_active_items(user_id).await?;
        let mut items = Vec::with_capacity(enc_items.len());
        for item in enc_items {
            let rec = EncryptedItemRecord {
                id: item.id,
                encrypted_data: item.encrypted_data,
                revision: item.revision,
                deleted: item.deleted,
                updated_at: item.updated_at,
            };
            items.push(decrypt_item(subkeys, user_id, &rec)?);
        }
        Ok((folders, items))
    }
}

fn build_push_request(
    base_revision: i64,
    mutations: &[crate::cache::QueuedMutation],
) -> SyncPushRequestDto {
    let mut folders_upsert = Vec::new();
    let mut folders_delete_ids = Vec::new();
    let mut items_upsert = Vec::new();
    let mut items_delete_ids = Vec::new();

    for m in mutations {
        match (m.entity_kind, m.op_kind) {
            (MutationEntityKind::Folder, MutationOpKind::Upsert) => {
                if let Some(payload) = &m.encrypted_payload {
                    folders_upsert.push(FolderUpsertDto {
                        id: m.entity_id,
                        encrypted_data_b64: STANDARD.encode(payload),
                    });
                }
            }
            (MutationEntityKind::Folder, MutationOpKind::Delete) => {
                folders_delete_ids.push(m.entity_id);
            }
            (MutationEntityKind::Item, MutationOpKind::Upsert) => {
                if let Some(payload) = &m.encrypted_payload {
                    items_upsert.push(ItemUpsertDto {
                        id: m.entity_id,
                        encrypted_data_b64: STANDARD.encode(payload),
                    });
                }
            }
            (MutationEntityKind::Item, MutationOpKind::Delete) => {
                items_delete_ids.push(m.entity_id);
            }
            (MutationEntityKind::Blob, _) => {}
        }
    }

    SyncPushRequestDto {
        base_revision,
        folders_upsert,
        folders_delete_ids,
        items_upsert,
        items_delete_ids,
    }
}

fn items_semantically_identical(
    subkeys: Option<&VaultSubKeys>,
    user_id: Uuid,
    local_mut: &crate::cache::QueuedMutation,
    server_wire: &crate::api_client::WireItemDto,
) -> Result<bool, ClientError> {
    if local_mut.op_kind == MutationOpKind::Delete && server_wire.deleted {
        return Ok(true);
    }
    if local_mut.op_kind == MutationOpKind::Delete || server_wire.deleted {
        return Ok(false);
    }
    let Some(sk) = subkeys else {
        return Ok(false);
    };
    let Some(local_bytes) = &local_mut.encrypted_payload else {
        return Ok(false);
    };
    let server_bytes = STANDARD
        .decode(server_wire.encrypted_data_b64.trim())
        .map_err(|_| ClientError::CacheIntegrity("invalid server item b64".to_owned()))?;

    let local = decrypt_item(
        sk,
        user_id,
        &EncryptedItemRecord {
            id: local_mut.entity_id,
            encrypted_data: local_bytes.clone(),
            revision: 1,
            deleted: false,
            updated_at: local_mut.queued_at,
        },
    )?;
    let server = decrypt_item(
        sk,
        user_id,
        &EncryptedItemRecord {
            id: server_wire.id,
            encrypted_data: server_bytes,
            revision: server_wire.revision,
            deleted: server_wire.deleted,
            updated_at: server_wire.updated_at,
        },
    )?;

    Ok(local.kind == server.kind
        && local.title == server.title
        && local.folder_id == server.folder_id
        && local.favorite == server.favorite
        && local.trashed_at == server.trashed_at
        && local.logo == server.logo
        && local.login == server.login
        && local.custom_fields == server.custom_fields
        && local.notes == server.notes)
}

fn folders_semantically_identical(
    subkeys: Option<&VaultSubKeys>,
    user_id: Uuid,
    local_mut: &crate::cache::QueuedMutation,
    server_wire: &crate::api_client::WireFolderDto,
) -> Result<bool, ClientError> {
    if local_mut.op_kind == MutationOpKind::Delete && server_wire.deleted {
        return Ok(true);
    }
    if local_mut.op_kind == MutationOpKind::Delete || server_wire.deleted {
        return Ok(false);
    }
    let Some(sk) = subkeys else {
        return Ok(false);
    };
    let Some(local_bytes) = &local_mut.encrypted_payload else {
        return Ok(false);
    };
    let server_bytes = STANDARD
        .decode(server_wire.encrypted_data_b64.trim())
        .map_err(|_| ClientError::CacheIntegrity("invalid server folder b64".to_owned()))?;

    let local = decrypt_folder(
        sk,
        user_id,
        &EncryptedFolderRecord {
            id: local_mut.entity_id,
            encrypted_data: local_bytes.clone(),
            revision: 1,
            deleted: false,
            updated_at: local_mut.queued_at,
        },
    )?;
    let server = decrypt_folder(
        sk,
        user_id,
        &EncryptedFolderRecord {
            id: server_wire.id,
            encrypted_data: server_bytes,
            revision: server_wire.revision,
            deleted: server_wire.deleted,
            updated_at: server_wire.updated_at,
        },
    )?;

    Ok(local.name == server.name)
}

pub fn fixed_salt(slice: &[u8]) -> Result<[u8; 32], ClientError> {
    if slice.len() != 32 {
        return Err(ClientError::CacheIntegrity(
            "cached kdf_salt must be 32 bytes".to_owned(),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(out)
}

pub fn account_kdf_params(acct: &CachedAccount) -> Result<KdfParams, ClientError> {
    let params = KdfParams {
        algorithm: anvil_core::crypto::KdfAlgorithm::Argon2id,
        memory_kib: acct.kdf_memory_kib,
        iterations: acct.kdf_iterations,
        parallelism: acct.kdf_parallelism,
    };
    params.validate()?;
    Ok(params)
}

/// Seals a `VaultKey` using a random wrapping envelope under a caller-supplied 32-byte sealing key.
pub fn seal_bytes_with_aad(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, ClientError> {
    Ok(encrypt_envelope(key, plaintext, aad)?)
}

/// Unseals an envelope sealed with `seal_bytes_with_aad`.
pub fn unseal_bytes_with_aad(
    key: &[u8; 32],
    envelope: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ClientError> {
    Ok(decrypt_envelope(key, envelope, aad)?)
}

/// Helper to construct canonical AAD for a cached blob record.
pub fn blob_aad(user_id: Uuid, item_id: Uuid, blob_id: Uuid) -> Vec<u8> {
    aad_blob(user_id, item_id, blob_id)
}
