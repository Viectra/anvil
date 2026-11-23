#![no_main]

use anvil_core::crypto::{
    MasterEncryptionKey, VaultKey, decrypt_envelope, derive_vault_subkeys, unwrap_vault_key,
};
use anvil_core::models::{
    EncryptedBlobRecord, EncryptedFolderRecord, EncryptedItemRecord, decrypt_blob, decrypt_folder,
    decrypt_item,
};
use chrono::Utc;
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    let key = [0x42u8; 32];
    let _ = decrypt_envelope(&key, data, b"anvil:v1:fuzz");

    let mek = MasterEncryptionKey::from_bytes([0x11u8; 32]);
    let uid = Uuid::nil();
    let _ = unwrap_vault_key(&mek, data, uid, 1);

    let vk = VaultKey::from_bytes([0x22u8; 32]);
    if let Ok(subkeys) = derive_vault_subkeys(&vk) {
        let now = Utc::now();
        let _ = decrypt_item(
            &subkeys,
            uid,
            &EncryptedItemRecord {
                id: Uuid::nil(),
                encrypted_data: data.to_vec(),
                revision: 1,
                deleted: false,
                updated_at: now,
            },
        );
        let _ = decrypt_folder(
            &subkeys,
            uid,
            &EncryptedFolderRecord {
                id: Uuid::nil(),
                encrypted_data: data.to_vec(),
                revision: 1,
                deleted: false,
                updated_at: now,
            },
        );
        let _ = decrypt_blob(
            &subkeys,
            uid,
            &EncryptedBlobRecord {
                id: Uuid::nil(),
                item_id: Uuid::nil(),
                encrypted_blob: data.to_vec(),
                revision: 1,
                deleted: false,
                updated_at: now,
            },
        );
    }
});
