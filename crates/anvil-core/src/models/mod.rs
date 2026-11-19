//! Vault domain models and encrypted wire synchronization records.

pub mod sync;
pub mod vault;

pub use sync::{
    EncryptedBlobRecord, EncryptedFolderRecord, EncryptedItemRecord, SyncDelta, decrypt_blob,
    decrypt_folder, decrypt_item, encrypt_blob, encrypt_folder, encrypt_item,
};
pub use vault::{
    CustomField, ItemKind, ItemLogo, ItemUri, LoginData, PasswordHistoryEntry, UriMatchMode,
    VAULT_ITEM_SCHEMA_VERSION, VaultBlob, VaultFolder, VaultItem, VaultSnapshot,
};
