//! Integration tests covering desktop command host, Win+L session locking, DPAPI seal,
//! Bitwarden import, RFC 6238 TOTP generation, clipboard hash auto-clear, and Snap Layouts hit-testing.

use std::sync::Arc;
use std::time::Duration;

use anvil_client_core::cache::{CachedAccount, EncryptedLocalCache};
use anvil_client_core::lock_manager::VaultLockManager;
use anvil_core::crypto::{
    KdfParams, MasterPassword, VaultKey, derive_master_key, derive_master_subkeys,
    generate_kdf_salt, wrap_vault_key,
};
use anvil_core::importers::DuplicatePolicy;
use anvil_core::models::ItemKind;
use anvil_desktop::biometric::{BiometricProvider, default_biometric_provider};
use anvil_desktop::clipboard::{ClipboardBackend, MemoryClipboardBackend, SecureClipboardManager};
use anvil_desktop::commands::{
    DesktopCommandHost, DesktopError, HitTestRequestDto, ImportSourceKindDto, ItemDetailDto,
    LoginDataDto, SaveItemInputDto, default_uri,
};
use anvil_desktop::platform::windows::{
    OsSessionLockEvent, OsSessionLockMonitor, Win32HitZone, WindowRect,
};
use anvil_desktop::tray::{SystemTrayController, TrayVisualState};
use chrono::Utc;
use tempfile::TempDir;
use uuid::Uuid;

fn sqlite_url(path: &std::path::Path) -> String {
    format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"))
}

struct TestHarness {
    _dir: TempDir,
    host: DesktopCommandHost,
    clipboard_backend: Arc<MemoryClipboardBackend>,
}

async fn setup_seeded_host(
    biometric: Arc<dyn BiometricProvider>,
) -> Result<TestHarness, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("desktop_cache.db");
    let cache = EncryptedLocalCache::connect(&sqlite_url(&db_path)).await?;

    let user_id = Uuid::new_v4();
    let kdf_params = KdfParams::default();
    let salt = generate_kdf_salt()?;
    let pw = MasterPassword::new("Master#Forge2026!");
    let mk = derive_master_key(&pw, &salt, &kdf_params)?;
    let (mek, _) = derive_master_subkeys(&mk, &salt)?;
    let vk = VaultKey::generate()?;
    let wrapped_vk = wrap_vault_key(&mek, &vk, user_id, 1)?;

    cache
        .save_account(&CachedAccount {
            user_id,
            server_url: "https://vault.example.internal".to_owned(),
            email: "viktor@example.internal".to_owned(),
            role: "user".to_owned(),
            kdf_memory_kib: kdf_params.memory_kib,
            kdf_iterations: kdf_params.iterations,
            kdf_parallelism: kdf_params.parallelism,
            kdf_salt: salt.to_vec(),
            key_version: 1,
            encrypted_vault_key: wrapped_vk,
            last_synced_revision: 0,
            biometric_sealed_vault_key: None,
            updated_at: Utc::now(),
        })
        .await?;

    let clipboard_backend = Arc::new(MemoryClipboardBackend::new());
    let clipboard = Arc::new(SecureClipboardManager::new(
        Arc::clone(&clipboard_backend) as Arc<dyn ClipboardBackend>
    ));

    let host = DesktopCommandHost::new(
        cache,
        "https://vault.example.internal",
        clipboard,
        biometric,
        Arc::new(SystemTrayController::new(true)),
        Arc::new(OsSessionLockMonitor::new()),
    )?;

    let _lock = VaultLockManager::default();
    Ok(TestHarness {
        _dir: dir,
        host,
        clipboard_backend,
    })
}

#[tokio::test]
async fn win_l_and_ctrl_l_immediately_purge_unlocked_vault()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = setup_seeded_host(default_biometric_provider()).await?;

    let unlocked = harness
        .host
        .cmd_unlock_password("Master#Forge2026!")
        .await?;
    assert!(unlocked.unlocked);

    let saved: ItemDetailDto = harness
        .host
        .cmd_save_item(SaveItemInputDto {
            id: None,
            kind: ItemKind::Login,
            title: "GitHub Forge".to_owned(),
            folder_id: None,
            favorite: true,
            trashed_at: None,
            login: Some(LoginDataDto {
                username: "viectra".to_owned(),
                email: "viktor@example.internal".to_owned(),
                password: "CorrectHorseBattery!99".to_owned(),
                password_history: Vec::new(),
                uris: vec![default_uri("https://github.com/login".to_owned())],
                totp: None,
            }),
            custom_fields: Vec::new(),
            notes: String::new(),
        })
        .await?;
    assert_eq!(saved.title, "GitHub Forge");
    assert_eq!(
        harness.host.tray().state(),
        TrayVisualState::Unlocked { item_count: 1 }
    );

    // Simulate OS Win+L notification callback firing synchronously via WTS monitor.
    let status_after_win_l = harness
        .host
        .cmd_on_os_session_lock(OsSessionLockEvent::SessionLock)
        .await?;
    assert!(!status_after_win_l.unlocked);
    assert_eq!(harness.host.tray().state(), TrayVisualState::Locked);
    assert!(
        harness
            .host
            .cmd_list_items("", None, false, false)
            .await
            .is_err()
    );

    // Unlock again and verify manual Ctrl+L lock triggers identical RAM purge.
    harness
        .host
        .cmd_unlock_password("Master#Forge2026!")
        .await?;
    let status_after_ctrl_l = harness.host.cmd_lock().await?;
    assert!(!status_after_ctrl_l.unlocked);
    assert_eq!(harness.host.tray().state(), TrayVisualState::Locked);
    Ok(())
}

#[tokio::test]
async fn biometric_dpapi_unlock_works_without_storing_master_password()
-> Result<(), Box<dyn std::error::Error>> {
    let bio = default_biometric_provider();
    if !bio.is_available() {
        return Ok(());
    }
    let harness = setup_seeded_host(bio).await?;

    harness
        .host
        .cmd_unlock_password("Master#Forge2026!")
        .await?;
    let enabled = harness
        .host
        .cmd_enable_biometric("Master#Forge2026!")
        .await?;
    assert!(enabled.biometric_enabled);

    harness
        .host
        .cmd_save_item(SaveItemInputDto {
            id: None,
            kind: ItemKind::SecureNote,
            title: "Recovery Key".to_owned(),
            folder_id: None,
            favorite: false,
            trashed_at: None,
            login: None,
            custom_fields: Vec::new(),
            notes: "ANVIL-9921".to_owned(),
        })
        .await?;

    harness.host.cmd_lock().await?;
    assert!(!harness.host.cmd_status().await?.unlocked);

    let unlocked_via_bio = harness.host.cmd_unlock_biometric().await?;
    assert!(unlocked_via_bio.unlocked);
    let items = harness
        .host
        .cmd_list_items("Recovery", None, false, false)
        .await?;
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].fallback_initials, "RK");
    Ok(())
}

#[tokio::test]
async fn bitwarden_json_import_totp_and_clipboard_autoclear_work_end_to_end()
-> Result<(), Box<dyn std::error::Error>> {
    let harness = setup_seeded_host(default_biometric_provider()).await?;
    harness
        .host
        .cmd_unlock_password("Master#Forge2026!")
        .await?;

    let bw_json = r#"{
        "encrypted": false,
        "folders": [{ "id": "f1", "name": "Cloud" }],
        "items": [{
            "id": "i1",
            "type": 1,
            "folderId": "f1",
            "name": "Cloudflare Production",
            "favorite": true,
            "login": {
                "username": "ops@anvil.io",
                "password": "Cf!SecretPassword#88",
                "totp": "JBSWY3DPEHPK3PXP",
                "uris": [{ "uri": "https://dash.cloudflare.com", "match": 0 }]
            }
        }]
    }"#;

    let preview = harness.host.cmd_preview_import(
        ImportSourceKindDto::BitwardenJson,
        bw_json.as_bytes().to_vec(),
        None,
    )?;
    assert_eq!(preview.total_items, 1);
    assert_eq!(preview.folder_count, 1);
    assert_eq!(preview.totp_count, 1);

    let report = harness
        .host
        .cmd_execute_import(&preview.preview_id, DuplicatePolicy::Skip)
        .await?;
    assert_eq!(report.created, 1);
    assert_eq!(report.folders_created, 1);

    // Executing the same preview ID a second time fails cleanly.
    let reuse_err = harness
        .host
        .cmd_execute_import(&preview.preview_id, DuplicatePolicy::Skip)
        .await
        .err();
    assert!(matches!(
        reuse_err,
        Some(DesktopError::ImportPreviewNotFound)
    ));

    let items = harness
        .host
        .cmd_list_items("Cloudflare", None, false, false)
        .await?;
    assert_eq!(items.len(), 1);
    assert!(items[0].has_totp);

    let detail = harness.host.cmd_get_item(&items[0].id).await?;
    let totp = detail
        .login
        .as_ref()
        .and_then(|l| l.totp.as_ref())
        .ok_or("missing TOTP config")?;
    let code = harness.host.cmd_generate_totp(&totp.secret_base32, 59)?;
    assert_eq!(code.code, "996554");
    assert_eq!(code.remaining_seconds, 1);
    assert_eq!(code.period_seconds, 30);

    // Copy secret -> unchanged clear purges it; overwritten clipboard is spared.
    let receipt = harness
        .host
        .cmd_copy_secret("Code TOTP", &code.code)
        .await?;
    assert_eq!(receipt.clear_after_seconds, 30);
    assert_eq!(
        harness.clipboard_backend.read_text()?.as_deref(),
        Some("996554")
    );
    assert!(harness.host.clipboard().clear_if_unchanged()?);
    assert_eq!(harness.clipboard_backend.read_text()?, None);

    harness
        .host
        .cmd_copy_secret("Password", "SecretTwo")
        .await?;
    harness
        .clipboard_backend
        .write_secret("KeepUserClipboard")?;
    assert!(!harness.host.clipboard().clear_if_unchanged()?);
    assert_eq!(
        harness.clipboard_backend.read_text()?.as_deref(),
        Some("KeepUserClipboard")
    );

    // Verify Windows 11 Snap Layouts hit-testing zones cleanly via IPC.
    let max_hit = harness.host.cmd_hit_test(HitTestRequestDto {
        rect: WindowRect {
            left: 0,
            top: 0,
            right: 1240,
            bottom: 800,
        },
        cursor_x: 1170,
        cursor_y: 16,
        is_maximized: false,
        search_width: Some(340),
    });
    assert_eq!(max_hit.zone, Win32HitZone::MaxButton);
    assert_eq!(max_hit.code, 9);

    let border_hit = harness.host.cmd_hit_test(HitTestRequestDto {
        rect: WindowRect {
            left: 0,
            top: 0,
            right: 1240,
            bottom: 800,
        },
        cursor_x: 3,
        cursor_y: 250,
        is_maximized: false,
        search_width: Some(340),
    });
    assert_eq!(border_hit.zone, Win32HitZone::Left);

    let search_hit = harness.host.cmd_hit_test(HitTestRequestDto {
        rect: WindowRect {
            left: 0,
            top: 0,
            right: 1240,
            bottom: 800,
        },
        cursor_x: 620,
        cursor_y: 20,
        is_maximized: false,
        search_width: Some(340),
    });
    assert_eq!(search_hit.zone, Win32HitZone::Client);

    let _ = Duration::from_secs(1);
    Ok(())
}
