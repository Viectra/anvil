//! Property-based fuzzing across AEAD envelopes, TOTP URIs, importers, search, and Debug redaction.

use anvil_core::crypto::{
    KdfAlgorithm, KdfParams, MasterEncryptionKey, MasterPassword, VaultKey, decrypt_envelope,
    derive_master_key, derive_master_subkeys, derive_vault_subkeys, unwrap_vault_key,
};
use anvil_core::exporters::import_anvil_archive;
use anvil_core::importers::{ImportFormat, preview_import};
use anvil_core::models::{
    CustomField, EncryptedBlobRecord, EncryptedFolderRecord, EncryptedItemRecord, ItemUri,
    LoginData, PasswordHistoryEntry, UriMatchMode, VaultBlob, VaultFolder, VaultItem,
    VaultSnapshot, decrypt_blob, decrypt_folder, decrypt_item,
};
use anvil_core::search::{extract_base_domain, search_items, uri_matches};
use anvil_core::totp::TotpConfig;
use chrono::Utc;
use proptest::prelude::*;
use uuid::Uuid;
use zeroize::Zeroizing;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn fuzz_aead_decoders_never_panic_on_arbitrary_bytes(
        payload in proptest::collection::vec(any::<u8>(), 0..1024),
        aad in proptest::collection::vec(any::<u8>(), 0..128),
    ) {
        let key = [0x5Au8; 32];
        let _ = decrypt_envelope(&key, &payload, &aad);

        let mek = MasterEncryptionKey::from_bytes([0x19u8; 32]);
        let uid = Uuid::nil();
        let _ = unwrap_vault_key(&mek, &payload, uid, 1);

        let vk = VaultKey::from_bytes([0x3Cu8; 32]);
        if let Ok(subkeys) = derive_vault_subkeys(&vk) {
            let now = Utc::now();
            let _ = decrypt_item(
                &subkeys,
                uid,
                &EncryptedItemRecord {
                    id: uid,
                    encrypted_data: payload.clone(),
                    revision: 1,
                    deleted: false,
                    updated_at: now,
                },
            );
            let _ = decrypt_folder(
                &subkeys,
                uid,
                &EncryptedFolderRecord {
                    id: uid,
                    encrypted_data: payload.clone(),
                    revision: 1,
                    deleted: false,
                    updated_at: now,
                },
            );
            let _ = decrypt_blob(
                &subkeys,
                uid,
                &EncryptedBlobRecord {
                    id: uid,
                    item_id: uid,
                    encrypted_blob: payload.clone(),
                    revision: 1,
                    deleted: false,
                    updated_at: now,
                },
            );
        }

        let _ = import_anvil_archive(&payload, &MasterPassword::new("pw"));
    }

    #[test]
    fn fuzz_totp_parser_never_panics_on_arbitrary_strings(raw in ".*") {
        if let Ok(cfg) = TotpConfig::from_input(&raw) {
            let _ = cfg.generate_at(1_700_000_000);
            let uri = cfg.to_otpauth_uri("FuzzIssuer");
            let _ = TotpConfig::from_input(&uri);
        }
    }

    #[test]
    fn fuzz_importers_and_search_never_panic_on_malformed_payloads(
        raw in proptest::collection::vec(any::<u8>(), 0..2048),
        query in ".*",
    ) {
        let snapshot = VaultSnapshot::default();
        for fmt in [
            ImportFormat::BitwardenJson,
            ImportFormat::BitwardenEncryptedJson,
            ImportFormat::BitwardenCsv,
            ImportFormat::ChromeCsv,
            ImportFormat::KeePassCsv,
            ImportFormat::KeePassXml,
            ImportFormat::OnePasswordCsv,
            ImportFormat::OnePassword1pux,
            ImportFormat::ProtonPassCsv,
        ] {
            let _ = preview_import(fmt, &raw, Some("fuzz-pass"), &snapshot);
        }

        let _ = extract_base_domain(&query);
        let uri = ItemUri {
            uri: query.clone(),
            match_mode: UriMatchMode::Regex,
        };
        let _ = uri_matches(&uri, "https://github.com/login");
        let items = vec![VaultItem::new_secure_note("Test", "notes")];
        let folders = vec![VaultFolder::new("Folder")];
        let _ = search_items(&items, &folders, &query);
    }
}

#[test]
fn debug_formatting_redacts_all_secret_core_types() -> Result<(), Box<dyn std::error::Error>> {
    let mp_secret = "UltraSecretMasterPass!99";
    let pw_secret = "LoginSecretValue#88";
    let hist_secret = "HistoricalPass!77";
    let totp_secret = "JBSWY3DPEHPK3PXP";
    let field_secret = "HiddenApiToken#66";

    let mp = MasterPassword::new(mp_secret);
    let kdf = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    };
    let salt = [0xAAu8; 32];
    let mk = derive_master_key(&mp, &salt, &kdf)?;
    let (mek, auth) = derive_master_subkeys(&mk, &salt)?;
    let vk = VaultKey::from_bytes([0xDEu8; 32]);

    let totp = TotpConfig::from_input(totp_secret)?;
    let history = PasswordHistoryEntry {
        password: hist_secret.to_owned(),
        changed_at: Utc::now(),
    };
    let field = CustomField {
        name: "api_key".to_owned(),
        value: field_secret.to_owned(),
        hidden: true,
    };
    let login = LoginData {
        username: "public-user".to_owned(),
        email: "user@example.internal".to_owned(),
        password: pw_secret.to_owned(),
        password_history: vec![history.clone()],
        uris: Vec::new(),
        totp: Some(totp.clone()),
    };
    let mut item = VaultItem::new_login("Bank Account", login.clone());
    item.custom_fields.push(field.clone());
    item.notes = "SensitiveRecoveryNote#55".to_owned();

    let blob = VaultBlob {
        id: Uuid::new_v4(),
        item_id: item.id,
        mime_type: "image/png".to_owned(),
        data: Zeroizing::new(vec![0xCA, 0xFE, 0xBA, 0xBE]),
        updated_at: Utc::now(),
    };

    let dumped = format!(
        "{mp:?} | {mk:?} | {mek:?} | {auth:?} | {vk:?} | {totp:?} | {history:?} | {field:?} | {login:?} | {item:?} | {blob:?}"
    );

    assert!(!dumped.contains(mp_secret));
    assert!(!dumped.contains(pw_secret));
    assert!(!dumped.contains(hist_secret));
    assert!(!dumped.contains(totp_secret));
    assert!(!dumped.contains(field_secret));
    assert!(!dumped.contains("SensitiveRecoveryNote#55"));
    assert!(!dumped.contains(&format!("{:02x}", 0xDEu8).repeat(8)));

    Ok(())
}
