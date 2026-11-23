//! RAM-only unlocked vault manager with deterministic zeroization and inactivity auto-lock.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use anvil_core::crypto::{
    KdfParams, MasterPassword, VaultKey, VaultSubKeys, derive_master_key, derive_master_subkeys,
    derive_vault_subkeys, unwrap_vault_key,
};
use anvil_core::models::{VaultFolder, VaultItem, VaultSnapshot};
use anvil_core::search::{find_matching_items, search_items};
use serde::Serialize;
use uuid::Uuid;

use crate::error::ClientError;

/// Default auto-lock inactivity threshold (`5 minutes`).
pub const DEFAULT_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(300);

/// Non-sensitive summary item representation returned to lists without exposing secret passwords/TOTP seeds.
#[derive(Debug, Clone, Serialize)]
pub struct VaultItemSummary {
    pub id: Uuid,
    pub kind: anvil_core::models::ItemKind,
    pub title: String,
    pub folder_id: Option<Uuid>,
    pub favorite: bool,
    pub trashed: bool,
    pub subtitle: String,
    pub primary_url: Option<String>,
    pub has_totp: bool,
    pub logo_blob_id: Option<Uuid>,
    pub fallback_color: String,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

struct UnlockedSession {
    user_id: Uuid,
    key_version: u32,
    vault_key: VaultKey,
    subkeys: VaultSubKeys,
    folders: Vec<VaultFolder>,
    items: Vec<VaultItem>,
    last_activity: Instant,
}

impl Drop for UnlockedSession {
    fn drop(&mut self) {
        self.items.clear();
        self.folders.clear();
    }
}

/// Thread-safe volatile vault lock container wiping keys and plaintext items on lock or inactivity.
pub struct VaultLockManager {
    session: RwLock<Option<UnlockedSession>>,
    inactivity_timeout: RwLock<Duration>,
}

impl Default for VaultLockManager {
    fn default() -> Self {
        Self::new(DEFAULT_INACTIVITY_TIMEOUT)
    }
}

impl fmt::Debug for VaultLockManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultLockManager")
            .field("unlocked", &self.is_unlocked())
            .finish()
    }
}

impl VaultLockManager {
    pub fn new(inactivity_timeout: Duration) -> Self {
        Self {
            session: RwLock::new(None),
            inactivity_timeout: RwLock::new(inactivity_timeout),
        }
    }

    pub fn set_inactivity_timeout(&self, timeout: Duration) {
        if let Ok(mut guard) = self.inactivity_timeout.write() {
            *guard = timeout;
        }
    }

    pub fn inactivity_timeout(&self) -> Duration {
        self.inactivity_timeout
            .read()
            .map(|d| *d)
            .unwrap_or(DEFAULT_INACTIVITY_TIMEOUT)
    }

    pub fn is_unlocked(&self) -> bool {
        self.session
            .read()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    /// Immediately clears and drops `VaultKey`, `VaultSubKeys`, and all decrypted vault entries in RAM.
    pub fn lock(&self) {
        if let Ok(mut guard) = self.session.write() {
            *guard = None;
        }
    }

    pub fn unlock(
        &self,
        user_id: Uuid,
        key_version: u32,
        vault_key: VaultKey,
        subkeys: VaultSubKeys,
        folders: Vec<VaultFolder>,
        items: Vec<VaultItem>,
    ) {
        if let Ok(mut guard) = self.session.write() {
            *guard = Some(UnlockedSession {
                user_id,
                key_version,
                vault_key,
                subkeys,
                folders,
                items,
                last_activity: Instant::now(),
            });
        }
    }

    pub fn replace_decrypted_data(&self, folders: Vec<VaultFolder>, items: Vec<VaultItem>) -> bool {
        if let Ok(mut guard) = self.session.write()
            && let Some(sess) = guard.as_mut()
        {
            sess.folders = folders;
            sess.items = items;
            sess.last_activity = Instant::now();
            return true;
        }
        false
    }

    pub fn touch_activity(&self) {
        self.touch_activity_at(Instant::now());
    }

    pub fn touch_activity_at(&self, now: Instant) {
        if let Ok(mut guard) = self.session.write()
            && let Some(sess) = guard.as_mut()
        {
            sess.last_activity = now;
        }
    }

    /// Locks the vault and returns `true` when idle duration since `last_activity` exceeds threshold.
    pub fn check_inactivity_and_lock(&self, now: Instant) -> bool {
        let timeout = self.inactivity_timeout();
        if let Ok(mut guard) = self.session.write()
            && let Some(sess) = guard.as_ref()
            && now.saturating_duration_since(sess.last_activity) >= timeout
        {
            *guard = None;
            return true;
        }
        false
    }

    pub fn keys_snapshot(&self) -> Result<(Uuid, u32, VaultKey, VaultSubKeys), ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.last_activity = Instant::now();
        Ok((
            sess.user_id,
            sess.key_version,
            sess.vault_key.clone(),
            sess.subkeys.clone(),
        ))
    }

    pub fn update_key_version(&self, key_version: u32) -> Result<(), ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.key_version = key_version;
        sess.last_activity = Instant::now();
        Ok(())
    }

    /// Atomically swaps in a freshly rotated `VaultKey` and `VaultSubKeys` in volatile RAM.
    pub fn replace_vault_keys(
        &self,
        key_version: u32,
        vault_key: VaultKey,
        subkeys: VaultSubKeys,
    ) -> Result<(), ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.key_version = key_version;
        sess.vault_key = vault_key;
        sess.subkeys = subkeys;
        sess.last_activity = Instant::now();
        Ok(())
    }

    pub fn list_folders(&self) -> Result<Vec<VaultFolder>, ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.last_activity = Instant::now();
        Ok(sess.folders.clone())
    }

    pub fn upsert_folder(&self, folder: VaultFolder) -> Result<(), ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        if let Some(existing) = sess.folders.iter_mut().find(|f| f.id == folder.id) {
            *existing = folder;
        } else {
            sess.folders.push(folder);
        }
        sess.last_activity = Instant::now();
        Ok(())
    }

    pub fn remove_folder(&self, folder_id: Uuid) -> Result<(), ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.folders.retain(|f| f.id != folder_id);
        sess.last_activity = Instant::now();
        Ok(())
    }

    pub fn upsert_item(&self, item: VaultItem) -> Result<(), ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        if let Some(existing) = sess.items.iter_mut().find(|i| i.id == item.id) {
            *existing = item;
        } else {
            sess.items.push(item);
        }
        sess.last_activity = Instant::now();
        Ok(())
    }

    pub fn remove_item(&self, item_id: Uuid) -> Result<(), ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.items.retain(|i| i.id != item_id);
        sess.last_activity = Instant::now();
        Ok(())
    }

    pub fn get_item(&self, item_id: Uuid) -> Result<VaultItem, ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.last_activity = Instant::now();
        sess.items
            .iter()
            .find(|item| item.id == item_id)
            .cloned()
            .ok_or(ClientError::NotFound)
    }

    pub fn search_summaries(
        &self,
        query: &str,
        folder_id: Option<Uuid>,
        favorites_only: bool,
        trashed_only: bool,
    ) -> Result<Vec<VaultItemSummary>, ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.last_activity = Instant::now();

        let filtered: Vec<VaultItem> = sess
            .items
            .iter()
            .filter(|item| {
                let is_trashed = item.trashed_at.is_some();
                if is_trashed != trashed_only {
                    return false;
                }
                if favorites_only && !item.favorite {
                    return false;
                }
                if let Some(fid) = folder_id
                    && item.folder_id != Some(fid)
                {
                    return false;
                }
                true
            })
            .cloned()
            .collect();

        if query.trim().is_empty() {
            let mut summaries: Vec<VaultItemSummary> =
                filtered.iter().map(summarize_item).collect();
            summaries.sort_by_key(|a| a.title.to_lowercase());
            return Ok(summaries);
        }

        let by_id: HashMap<Uuid, &VaultItem> = filtered.iter().map(|i| (i.id, i)).collect();
        let hits = search_items(&filtered, &sess.folders, query);
        Ok(hits
            .into_iter()
            .filter_map(|hit| by_id.get(&hit.item_id).map(|item| summarize_item(item)))
            .collect())
    }

    pub fn find_matching_items_for_url(
        &self,
        target_url: &str,
    ) -> Result<Vec<VaultItem>, ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.last_activity = Instant::now();

        let ids = find_matching_items(&sess.items, target_url);
        let by_id: HashMap<Uuid, &VaultItem> = sess.items.iter().map(|i| (i.id, i)).collect();
        Ok(ids
            .into_iter()
            .filter_map(|id| by_id.get(&id).cloned().cloned())
            .collect())
    }

    pub fn snapshot(&self) -> Result<VaultSnapshot, ClientError> {
        let mut guard = self.session.write().map_err(|_| ClientError::VaultLocked)?;
        let Some(sess) = guard.as_mut() else {
            return Err(ClientError::VaultLocked);
        };
        sess.last_activity = Instant::now();
        Ok(VaultSnapshot {
            folders: sess.folders.clone(),
            items: sess.items.clone(),
            blobs: Vec::new(),
        })
    }

    /// Re-verifies the user's Master Password against cached KDF parameters and wrapped `VaultKey`.
    pub fn verify_master_password_reauth(
        &self,
        password: &MasterPassword,
        kdf_params: &KdfParams,
        kdf_salt: &[u8; 32],
        encrypted_vault_key: &[u8],
        user_id: Uuid,
        key_version: u32,
    ) -> Result<([u8; 32], VaultKey), ClientError> {
        let mk = derive_master_key(password, kdf_salt, kdf_params)?;
        let (mek, auth_hash) = derive_master_subkeys(&mk, kdf_salt)?;
        let vk = unwrap_vault_key(&mek, encrypted_vault_key, user_id, key_version)
            .map_err(|_| ClientError::InvalidMasterPassword)?;
        Ok((*auth_hash.as_bytes(), vk))
    }
}

/// Converts a decrypted `VaultItem` into a non-secret UI summary row.
pub fn summarize_item(item: &VaultItem) -> VaultItemSummary {
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
    let has_totp = item.login.as_ref().and_then(|l| l.totp.as_ref()).is_some();

    VaultItemSummary {
        id: item.id,
        kind: item.kind,
        title: item.title.clone(),
        folder_id: item.folder_id,
        favorite: item.favorite,
        trashed: item.trashed_at.is_some(),
        subtitle,
        primary_url,
        has_totp,
        logo_blob_id: item.logo.blob_id,
        fallback_color: item.logo.fallback_color.clone(),
        updated_at: item.updated_at,
    }
}

/// Derives subkeys directly from an already unwrapped `VaultKey`.
pub fn subkeys_from_vault_key(vault_key: &VaultKey) -> Result<VaultSubKeys, ClientError> {
    Ok(derive_vault_subkeys(vault_key)?)
}
