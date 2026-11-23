//! Cryptographic parity (`anvil-core` <-> `anvil-wasm`), anti-phishing, and MV3 session tests.

use anvil_core::crypto::{
    KdfParams, MasterPassword, VaultKey, derive_master_key, derive_master_subkeys,
    derive_vault_subkeys, generate_kdf_salt, wrap_vault_key,
};
use anvil_core::importers::{DuplicatePolicy, ImportFormat};
use anvil_core::models::{
    EncryptedItemRecord, ItemKind, ItemUri, LoginData, UriMatchMode, VaultFolder, VaultItem,
    decrypt_item, encrypt_folder, encrypt_item,
};
use anvil_core::totp::TotpConfig;
use anvil_wasm::error::WasmError;
use anvil_wasm::security::{
    SecurityRiskLevel, evaluate_autofill_context, extract_registrable_domain, verify_item_autofill,
};
use anvil_wasm::session::{
    EncryptedFolderEnvelopeDto, EncryptedItemEnvelopeDto, LoginDataDto, SaveItemInputDto,
    WasmAccountMeta, WasmVaultSession, derive_login_auth, prepare_registration,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use uuid::Uuid;

struct SeededVault {
    account: WasmAccountMeta,
    vault_key: VaultKey,
    folder_envs: Vec<EncryptedFolderEnvelopeDto>,
    item_envs: Vec<EncryptedItemEnvelopeDto>,
    native_item: VaultItem,
}

fn build_seeded_vault() -> Result<SeededVault, Box<dyn std::error::Error>> {
    let kdf_params = KdfParams::default();
    let salt = generate_kdf_salt()?;
    let user_id = Uuid::new_v4();
    let pw = MasterPassword::new("Forge#Master2026!");
    let mk = derive_master_key(&pw, &salt, &kdf_params)?;
    let (mek, _) = derive_master_subkeys(&mk, &salt)?;
    let vk = VaultKey::generate()?;
    let wrapped_vk = wrap_vault_key(&mek, &vk, user_id, 1)?;
    let subkeys = derive_vault_subkeys(&vk)?;

    let folder = VaultFolder::new("Infrastructure");
    let enc_folder = encrypt_folder(&subkeys, user_id, &folder, 1)?;

    let mut item = VaultItem::new_login(
        "GitHub Production",
        LoginData {
            username: "viectra".to_owned(),
            email: "viktor@example.internal".to_owned(),
            password: "NativeToWasm#Secret99".to_owned(),
            password_history: Vec::new(),
            uris: vec![ItemUri {
                uri: "https://github.com/login".to_owned(),
                match_mode: UriMatchMode::BaseDomain,
            }],
            totp: Some(TotpConfig::from_input("JBSWY3DPEHPK3PXP")?),
        },
    );
    item.folder_id = Some(folder.id);
    let enc_item = encrypt_item(&subkeys, user_id, &item, 2)?;

    let meta = WasmAccountMeta {
        user_id,
        email: "viktor@example.internal".to_owned(),
        kdf_params,
        kdf_salt_b64: STANDARD.encode(salt),
        key_version: 1,
        encrypted_vault_key_b64: STANDARD.encode(wrapped_vk),
    };

    let folder_envs = vec![EncryptedFolderEnvelopeDto {
        id: enc_folder.id,
        encrypted_data_b64: STANDARD.encode(enc_folder.encrypted_data),
        revision: enc_folder.revision,
        deleted: enc_folder.deleted,
        updated_at: enc_folder.updated_at,
    }];
    let item_envs = vec![EncryptedItemEnvelopeDto {
        id: enc_item.id,
        encrypted_data_b64: STANDARD.encode(enc_item.encrypted_data),
        revision: enc_item.revision,
        deleted: enc_item.deleted,
        updated_at: enc_item.updated_at,
    }];

    Ok(SeededVault {
        account: meta,
        vault_key: vk,
        folder_envs,
        item_envs,
        native_item: item,
    })
}

#[test]
fn native_and_wasm_cryptography_are_bit_identical() -> Result<(), Box<dyn std::error::Error>> {
    let SeededVault {
        account,
        vault_key,
        folder_envs,
        item_envs,
        native_item,
    } = build_seeded_vault()?;

    let mut session = WasmVaultSession::new();
    let bad_unlock = session
        .unlock_with_password(&account, "WrongPassword!", &folder_envs, &item_envs)
        .err();
    assert!(matches!(bad_unlock, Some(WasmError::InvalidMasterPassword)));

    session.unlock_with_password(&account, "Forge#Master2026!", &folder_envs, &item_envs)?;
    assert!(session.is_unlocked());

    let detail = session.get_item_detail(&native_item.id.to_string())?;
    assert_eq!(detail.title, "GitHub Production");
    assert_eq!(
        detail.login.as_ref().map(|l| l.password.as_str()),
        Some("NativeToWasm#Secret99")
    );

    let creds = session.get_autofill_credentials(
        &native_item.id.to_string(),
        "https://gist.github.com/auth",
        "https://gist.github.com/auth",
        false,
        &[],
        59,
    )?;
    assert_eq!(creds.password, "NativeToWasm#Secret99");
    assert_eq!(creds.totp_code.as_deref(), Some("996554"));

    // Encrypt new item inside WASM session and verify native `anvil-core` decrypts it identically.
    let (_created_dto, wasm_envelope) = session.encrypt_item_upsert(SaveItemInputDto {
        id: None,
        kind: ItemKind::Login,
        title: "Cloudflare Edge".to_owned(),
        folder_id: None,
        favorite: false,
        trashed_at: None,
        login: Some(LoginDataDto {
            username: "ops".to_owned(),
            email: "ops@anvil.io".to_owned(),
            password: "WasmToNative#Key42".to_owned(),
            password_history: Vec::new(),
            uris: vec![ItemUri {
                uri: "https://dash.cloudflare.com".to_owned(),
                match_mode: UriMatchMode::Host,
            }],
            totp: None,
        }),
        custom_fields: Vec::new(),
        notes: "Created in WASM".to_owned(),
    })?;

    let native_subkeys = derive_vault_subkeys(&vault_key)?;
    let raw_cipher = STANDARD.decode(wasm_envelope.encrypted_data_b64)?;
    let native_decrypted = decrypt_item(
        &native_subkeys,
        account.user_id,
        &EncryptedItemRecord {
            id: wasm_envelope.id,
            encrypted_data: raw_cipher.clone(),
            revision: wasm_envelope.revision,
            deleted: wasm_envelope.deleted,
            updated_at: wasm_envelope.updated_at,
        },
    )?;
    assert_eq!(native_decrypted.title, "Cloudflare Edge");
    assert_eq!(
        native_decrypted.login.as_ref().map(|l| l.password.as_str()),
        Some("WasmToNative#Key42")
    );

    // Cross-user AAD tampering must fail decryption.
    let other_user = Uuid::new_v4();
    let cross_user_err = decrypt_item(
        &native_subkeys,
        other_user,
        &EncryptedItemRecord {
            id: wasm_envelope.id,
            encrypted_data: raw_cipher,
            revision: wasm_envelope.revision,
            deleted: wasm_envelope.deleted,
            updated_at: wasm_envelope.updated_at,
        },
    );
    assert!(cross_user_err.is_err());

    let reg = prepare_registration(
        "alice@example.internal",
        "Alice#Secret2026!",
        account.kdf_params,
    )?;
    let login_auth = derive_login_auth("Alice#Secret2026!", &reg.kdf_salt_b64, account.kdf_params)?;
    assert_eq!(login_auth.master_auth_hash_b64, reg.master_auth_hash_b64);

    Ok(())
}

#[test]
fn anti_phishing_blocks_spoofer_subdomains_homographs_and_untrusted_iframes()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        extract_registrable_domain("https://login.portal.bank.co.uk:8443/sign").as_deref(),
        Some("bank.co.uk")
    );
    assert_eq!(
        extract_registrable_domain("https://myproject.github.io/login").as_deref(),
        Some("myproject.github.io")
    );

    let github_pages_item = VaultItem::new_login(
        "My Project",
        LoginData {
            username: "dev".to_owned(),
            email: String::new(),
            password: "pw".to_owned(),
            password_history: Vec::new(),
            uris: vec![ItemUri {
                uri: "https://myproject.github.io".to_owned(),
                match_mode: UriMatchMode::BaseDomain,
            }],
            totp: None,
        },
    );

    // Attacker subdomain on public suffix .github.io MUST NOT match.
    let spoof_pages = verify_item_autofill(
        &github_pages_item,
        "https://attacker.github.io/phish",
        "https://attacker.github.io/phish",
        false,
        &[],
    );
    assert!(!spoof_pages.allowed);
    assert_eq!(
        spoof_pages.risk_level,
        SecurityRiskLevel::BlockedDomainMismatch
    );

    // paypal.com.evil.co.uk MUST resolve eTLD+1 as evil.co.uk and block paypal.com credentials.
    let paypal_item = VaultItem::new_login(
        "PayPal",
        LoginData {
            username: "buyer".to_owned(),
            email: String::new(),
            password: "pw".to_owned(),
            password_history: Vec::new(),
            uris: vec![ItemUri {
                uri: "https://www.paypal.com/signin".to_owned(),
                match_mode: UriMatchMode::BaseDomain,
            }],
            totp: None,
        },
    );
    let phishing_co_uk = verify_item_autofill(
        &paypal_item,
        "https://paypal.com.evil.co.uk/login",
        "https://paypal.com.evil.co.uk/login",
        false,
        &[],
    );
    assert!(!phishing_co_uk.allowed);
    assert_eq!(
        phishing_co_uk.registrable_domain.as_deref(),
        Some("evil.co.uk")
    );

    // Mixed Cyrillic/Latin homograph ("аpple.com" with Cyrillic U+0430) must be blocked completely.
    let homograph = evaluate_autofill_context(
        "https://\u{0430}pple.com/login",
        "https://\u{0430}pple.com/login",
        false,
        &[],
    );
    assert!(!homograph.allowed);
    assert_eq!(homograph.risk_level, SecurityRiskLevel::BlockedIdnHomograph);
    assert!(homograph.is_mixed_script);
    assert!(homograph.is_idn_punycode);

    // Cross-origin iframe blocked unless origin is explicitly approved; same-origin iframe allowed.
    let cross_iframe = evaluate_autofill_context(
        "https://bank.co.uk/dashboard",
        "https://cdn-tracker.example/embed",
        true,
        &[],
    );
    assert!(!cross_iframe.allowed);
    assert_eq!(
        cross_iframe.risk_level,
        SecurityRiskLevel::BlockedCrossOriginIframe
    );

    let approved_iframe = evaluate_autofill_context(
        "https://bank.co.uk/dashboard",
        "https://auth.partner.example/widget",
        true,
        &["https://auth.partner.example".to_owned()],
    );
    assert!(approved_iframe.allowed);

    // HTTP warns and disables silent autofill, whereas http://localhost stays Safe.
    let http_warn = evaluate_autofill_context(
        "http://legacy.corp.example/login",
        "http://legacy.corp.example/login",
        false,
        &[],
    );
    assert!(http_warn.allowed);
    assert!(!http_warn.silent_autofill_allowed);
    assert!(!http_warn.is_secure_context);
    assert_eq!(http_warn.risk_level, SecurityRiskLevel::WarnHttp);

    let local_dev = evaluate_autofill_context(
        "http://localhost:8080/login",
        "http://localhost:8080/login",
        false,
        &[],
    );
    assert!(local_dev.allowed);
    assert!(local_dev.silent_autofill_allowed);
    assert_eq!(local_dev.risk_level, SecurityRiskLevel::Safe);

    Ok(())
}

#[test]
fn ephemeral_mv3_session_lock_and_import_export_roundtrip() -> Result<(), Box<dyn std::error::Error>>
{
    let SeededVault {
        account,
        folder_envs,
        item_envs,
        ..
    } = build_seeded_vault()?;

    let mut session = WasmVaultSession::new();
    session.unlock_with_password(&account, "Forge#Master2026!", &folder_envs, &item_envs)?;

    let seal = session.export_ephemeral_session(300, 1_700_000_000)?;
    session.lock();
    assert!(!session.is_unlocked());
    assert!(matches!(
        session.list_folders().err(),
        Some(WasmError::VaultLocked)
    ));

    // Expired ephemeral session seal must be rejected.
    let expired = session
        .unlock_with_ephemeral_session(&account, &seal, 1_700_000_500, &folder_envs, &item_envs)
        .err();
    assert!(matches!(expired, Some(WasmError::SessionExpired)));

    // Valid window resumes cleanly.
    session.unlock_with_ephemeral_session(
        &account,
        &seal,
        1_700_000_120,
        &folder_envs,
        &item_envs,
    )?;
    assert!(session.is_unlocked());
    assert_eq!(session.list_folders()?.len(), 1);

    // Import Bitwarden JSON dry-run + commit emits encrypted envelopes ready for sync.
    let bw_json = br#"{
        "encrypted": false,
        "folders": [{ "id": "f9", "name": "ImportedFolder" }],
        "items": [{
            "id": "i9",
            "type": 1,
            "folderId": "f9",
            "name": "Proton Mail",
            "login": {
                "username": "viktor@proton.me",
                "password": "Proton!Password77",
                "uris": [{ "uri": "https://account.proton.me", "match": 0 }]
            }
        }]
    }"#;
    let preview = session.preview_import(ImportFormat::BitwardenJson, bw_json, None)?;
    assert_eq!(preview.total_items, 1);

    let commit = session.execute_import(&preview.preview_id, DuplicatePolicy::Skip)?;
    assert_eq!(commit.report.created, 1);
    assert_eq!(commit.encrypted_folders.len(), 1);
    assert_eq!(commit.encrypted_items.len(), 1);

    let exported = session.export_vault(&account, "bitwarden_json", "Forge#Master2026!", None)?;
    let exported_text = String::from_utf8(exported)?;
    assert!(exported_text.contains("Proton Mail"));
    assert!(exported_text.contains("GitHub Production"));

    Ok(())
}
