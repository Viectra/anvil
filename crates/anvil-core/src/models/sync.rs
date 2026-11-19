//! Encrypted wire payloads and item/folder/blob sealing helpers.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{
    VaultSubKeys, aad_blob, aad_folder, aad_item, decrypt_envelope, decrypt_json, encrypt_envelope,
    encrypt_json,
};
use crate::error::AnvilError;
use crate::models::vault::{
    CustomField, ItemKind, ItemLogo, LoginData, VaultBlob, VaultFolder, VaultItem,
};

/// Wire representation of an encrypted vault item stored on the server and offline cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedItemRecord {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Wire representation of an encrypted vault folder stored on the server and offline cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedFolderRecord {
    pub id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Wire representation of an encrypted binary blob (custom logo).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedBlobRecord {
    pub id: Uuid,
    pub item_id: Uuid,
    pub encrypted_blob: Vec<u8>,
    pub revision: i64,
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

/// Differential synchronization batch returned by `/api/v1/vault/sync`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncDelta {
    pub current_revision: i64,
    pub folders: Vec<EncryptedFolderRecord>,
    pub items: Vec<EncryptedItemRecord>,
    pub blobs: Vec<EncryptedBlobRecord>,
}

#[derive(Serialize, Deserialize)]
struct ItemCipherPayload {
    schema_version: u32,
    kind: ItemKind,
    title: String,
    folder_id: Option<Uuid>,
    favorite: bool,
    trashed_at: Option<DateTime<Utc>>,
    item_version: u64,
    logo: ItemLogo,
    login: Option<LoginData>,
    custom_fields: Vec<CustomField>,
    notes: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct FolderCipherPayload {
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize)]
struct BlobCipherPayload {
    mime_type: String,
    data: Vec<u8>,
    updated_at: DateTime<Utc>,
}

/// Encrypts a `VaultItem` under `subkeys.item_key` bound to `(user_id, item.id)`.
pub fn encrypt_item(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    item: &VaultItem,
    revision: i64,
) -> Result<EncryptedItemRecord, AnvilError> {
    let payload = ItemCipherPayload {
        schema_version: item.schema_version,
        kind: item.kind,
        title: item.title.clone(),
        folder_id: item.folder_id,
        favorite: item.favorite,
        trashed_at: item.trashed_at,
        item_version: item.item_version,
        logo: item.logo.clone(),
        login: item.login.clone(),
        custom_fields: item.custom_fields.clone(),
        notes: item.notes.clone(),
        created_at: item.created_at,
        updated_at: item.updated_at,
    };
    let aad = aad_item(user_id, item.id);
    let encrypted_data = encrypt_json(&subkeys.item_key, &payload, &aad)?;
    Ok(EncryptedItemRecord {
        id: item.id,
        encrypted_data,
        revision,
        deleted: false,
        updated_at: item.updated_at,
    })
}

/// Decrypts an `EncryptedItemRecord` after validating AAD `(user_id, record.id)`.
pub fn decrypt_item(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    record: &EncryptedItemRecord,
) -> Result<VaultItem, AnvilError> {
    let aad = aad_item(user_id, record.id);
    let payload: ItemCipherPayload = decrypt_json(&subkeys.item_key, &record.encrypted_data, &aad)?;
    Ok(VaultItem {
        id: record.id,
        schema_version: payload.schema_version,
        kind: payload.kind,
        title: payload.title,
        folder_id: payload.folder_id,
        favorite: payload.favorite,
        trashed_at: payload.trashed_at,
        item_version: payload.item_version,
        logo: payload.logo,
        login: payload.login,
        custom_fields: payload.custom_fields,
        notes: payload.notes,
        created_at: payload.created_at,
        updated_at: payload.updated_at,
    })
}

/// Encrypts a `VaultFolder` under `subkeys.folder_key` bound to `(user_id, folder.id)`.
pub fn encrypt_folder(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    folder: &VaultFolder,
    revision: i64,
) -> Result<EncryptedFolderRecord, AnvilError> {
    let payload = FolderCipherPayload {
        name: folder.name.clone(),
        created_at: folder.created_at,
        updated_at: folder.updated_at,
    };
    let aad = aad_folder(user_id, folder.id);
    let encrypted_data = encrypt_json(&subkeys.folder_key, &payload, &aad)?;
    Ok(EncryptedFolderRecord {
        id: folder.id,
        encrypted_data,
        revision,
        deleted: false,
        updated_at: folder.updated_at,
    })
}

/// Decrypts an `EncryptedFolderRecord` after validating AAD `(user_id, record.id)`.
pub fn decrypt_folder(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    record: &EncryptedFolderRecord,
) -> Result<VaultFolder, AnvilError> {
    let aad = aad_folder(user_id, record.id);
    let payload: FolderCipherPayload =
        decrypt_json(&subkeys.folder_key, &record.encrypted_data, &aad)?;
    Ok(VaultFolder {
        id: record.id,
        name: payload.name,
        created_at: payload.created_at,
        updated_at: payload.updated_at,
    })
}

/// Encrypts a `VaultBlob` under `subkeys.blob_key` bound to `(user_id, blob.item_id, blob.id)`.
pub fn encrypt_blob(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    blob: &VaultBlob,
    revision: i64,
) -> Result<EncryptedBlobRecord, AnvilError> {
    let payload = BlobCipherPayload {
        mime_type: blob.mime_type.clone(),
        data: blob.data.to_vec(),
        updated_at: blob.updated_at,
    };
    let json = Zeroizing::new(serde_json::to_vec(&payload)?);
    let aad = aad_blob(user_id, blob.item_id, blob.id);
    let encrypted_blob = encrypt_envelope(&subkeys.blob_key, &json, &aad)?;
    Ok(EncryptedBlobRecord {
        id: blob.id,
        item_id: blob.item_id,
        encrypted_blob,
        revision,
        deleted: false,
        updated_at: blob.updated_at,
    })
}

/// Decrypts an `EncryptedBlobRecord` after validating AAD `(user_id, record.item_id, record.id)`.
pub fn decrypt_blob(
    subkeys: &VaultSubKeys,
    user_id: Uuid,
    record: &EncryptedBlobRecord,
) -> Result<VaultBlob, AnvilError> {
    let aad = aad_blob(user_id, record.item_id, record.id);
    let json = decrypt_envelope(&subkeys.blob_key, &record.encrypted_blob, &aad)?;
    let payload: BlobCipherPayload = serde_json::from_slice(&json)?;
    Ok(VaultBlob {
        id: record.id,
        item_id: record.item_id,
        mime_type: payload.mime_type,
        data: Zeroizing::new(payload.data),
        updated_at: payload.updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{VaultKey, derive_vault_subkeys};
    use crate::models::vault::{ItemUri, UriMatchMode};
    use crate::totp::TotpConfig;

    #[test]
    fn item_folder_blob_roundtrips_and_cross_binding_rejection() {
        let user_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();
        let vk = VaultKey::generate().expect("vk");
        let subkeys = derive_vault_subkeys(&vk).expect("subkeys");

        let folder = VaultFolder::new("Travail");
        let enc_folder = encrypt_folder(&subkeys, user_id, &folder, 1).expect("enc folder");
        let dec_folder = decrypt_folder(&subkeys, user_id, &enc_folder).expect("dec folder");
        assert_eq!(dec_folder.name, "Travail");
        assert!(decrypt_folder(&subkeys, other_user, &enc_folder).is_err());

        let mut item = VaultItem::new_login(
            "GitHub",
            LoginData {
                username: "dev_anvil".to_owned(),
                email: "dev@corp.io".to_owned(),
                password: "secret-password".to_owned(),
                password_history: vec![],
                uris: vec![ItemUri {
                    uri: "https://github.com/login".to_owned(),
                    match_mode: UriMatchMode::BaseDomain,
                }],
                totp: Some(TotpConfig::from_input("JBSWY3DPEHPK3PXP").expect("totp")),
            },
        );
        item.folder_id = Some(folder.id);
        item.favorite = true;

        let enc_item = encrypt_item(&subkeys, user_id, &item, 2).expect("enc item");
        let dec_item = decrypt_item(&subkeys, user_id, &enc_item).expect("dec item");
        assert_eq!(dec_item.title, "GitHub");
        assert_eq!(dec_item.folder_id, Some(folder.id));
        assert!(dec_item.favorite);
        assert!(decrypt_item(&subkeys, other_user, &enc_item).is_err());

        let blob = VaultBlob {
            id: Uuid::new_v4(),
            item_id: item.id,
            mime_type: "image/png".to_owned(),
            data: Zeroizing::new(vec![0x89, 0x50, 0x4E, 0x47]),
            updated_at: Utc::now(),
        };
        let enc_blob = encrypt_blob(&subkeys, user_id, &blob, 3).expect("enc blob");
        let dec_blob = decrypt_blob(&subkeys, user_id, &enc_blob).expect("dec blob");
        assert_eq!(&*dec_blob.data, &[0x89, 0x50, 0x4E, 0x47]);

        let mut swapped_blob = enc_blob.clone();
        swapped_blob.item_id = Uuid::new_v4();
        assert!(decrypt_blob(&subkeys, user_id, &swapped_blob).is_err());
    }
}
