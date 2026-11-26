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
            avatar_png: None,
            encrypted_refresh_token: None,
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

#[tokio::test]
async fn http_bridge_enforces_token_loopback_and_dispatches_ipc()
-> Result<(), Box<dyn std::error::Error>> {
    use std::net::SocketAddr;

    use anvil_desktop::http_bridge::{
        BRIDGE_TOKEN_HEADER, HttpBridgeError, build_bridge_router, serve_http_bridge,
    };
    use axum::body::Body;
    use http::{Method, Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let harness = setup_seeded_host(default_biometric_provider()).await?;
    let host = Arc::new(harness.host);

    let weak_err = build_bridge_router(Arc::clone(&host), "too-short".to_owned())
        .err()
        .ok_or("expected weak token error")?;
    assert!(matches!(weak_err, HttpBridgeError::WeakToken));

    let valid_token = "0123456789abcdef0123456789abcdef".to_owned();
    let non_loopback: SocketAddr = "0.0.0.0:1425".parse()?;
    let addr_err = serve_http_bridge(Arc::clone(&host), non_loopback, valid_token.clone())
        .await
        .err()
        .ok_or("expected non-loopback bind rejection")?;
    assert!(matches!(addr_err, HttpBridgeError::NonLoopbackAddress(_)));

    let router = build_bridge_router(Arc::clone(&host), valid_token.clone())?;

    let health_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/desktop-health")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(health_resp.status(), StatusCode::OK);
    let health_bytes = health_resp.into_body().collect().await?.to_bytes();
    let health_json: serde_json::Value = serde_json::from_slice(&health_bytes)?;
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["version"], env!("CARGO_PKG_VERSION"));

    let unauth_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/desktop-ipc")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"command":"cmd_status","payload":{}}"#))?,
        )
        .await?;
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    let wrong_tok_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/desktop-ipc")
                .header(header::CONTENT_TYPE, "application/json")
                .header(BRIDGE_TOKEN_HEADER, "wrong-token-value-with-32-chars-ok")
                .body(Body::from(r#"{"command":"cmd_status","payload":{}}"#))?,
        )
        .await?;
    assert_eq!(wrong_tok_resp.status(), StatusCode::UNAUTHORIZED);

    let status_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/desktop-ipc")
                .header(header::CONTENT_TYPE, "application/json")
                .header(BRIDGE_TOKEN_HEADER, &valid_token)
                .body(Body::from(r#"{"command":"cmd_status","payload":{}}"#))?,
        )
        .await?;
    assert_eq!(status_resp.status(), StatusCode::OK);
    assert_eq!(
        status_resp
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let status_bytes = status_resp.into_body().collect().await?.to_bytes();
    let status_json: serde_json::Value = serde_json::from_slice(&status_bytes)?;
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["data"]["configured"], true);
    assert_eq!(status_json["data"]["unlocked"], false);

    let toggle_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/desktop-ipc")
                .header(header::CONTENT_TYPE, "application/json")
                .header(BRIDGE_TOKEN_HEADER, &valid_token)
                .body(Body::from(
                    r#"{"command":"cmd_window_toggle_maximize","payload":{}}"#,
                ))?,
        )
        .await?;
    assert_eq!(toggle_resp.status(), StatusCode::OK);

    let chrome_resp = router
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/desktop-ipc")
                .header(header::CONTENT_TYPE, "application/json")
                .header(BRIDGE_TOKEN_HEADER, &valid_token)
                .body(Body::from(
                    r#"{"command":"cmd_window_chrome","payload":{}}"#,
                ))?,
        )
        .await?;
    assert_eq!(chrome_resp.status(), StatusCode::OK);
    let chrome_bytes = chrome_resp.into_body().collect().await?.to_bytes();
    let chrome_json: serde_json::Value = serde_json::from_slice(&chrome_bytes)?;
    assert_eq!(chrome_json["ok"], true);
    assert_eq!(chrome_json["data"]["is_maximized"], true);

    Ok(())
}

#[tokio::test]
async fn embedded_server_and_ui_bridge_support_full_standalone_flow()
-> Result<(), Box<dyn std::error::Error>> {
    use anvil_desktop::biometric::MemoryBiometricProvider;
    use anvil_desktop::embedded_server::start_embedded_server;
    use anvil_desktop::http_bridge::{BRIDGE_TOKEN_HEADER, build_embedded_ui_router};
    use axum::body::Body;
    use http::{Method, Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let dir = tempfile::tempdir()?;
    let server = start_embedded_server(dir.path(), 0).await?;

    let cache = EncryptedLocalCache::connect(&sqlite_url(&dir.path().join("client.db"))).await?;
    let host = Arc::new(DesktopCommandHost::new(
        cache,
        &server.url,
        Arc::new(SecureClipboardManager::new(Arc::new(
            MemoryClipboardBackend::new(),
        ))),
        Arc::new(MemoryBiometricProvider::available()),
        Arc::new(SystemTrayController::default()),
        Arc::new(OsSessionLockMonitor::new()),
    )?);

    let token = "fedcba9876543210fedcba9876543210".to_owned();
    let router = build_embedded_ui_router(
        host,
        token.clone(),
        server.url.clone(),
        include_str!("../assets/desktop_app.html"),
    )?;

    let html_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(html_resp.status(), StatusCode::OK);
    assert_eq!(
        html_resp
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    let html_body = String::from_utf8(html_resp.into_body().collect().await?.to_bytes().to_vec())?;
    assert!(html_body.contains("<title>Anvil</title>"));
    assert!(html_body.contains("http:\\u002f\\u002f127.0.0.1:"));

    let send_ipc = |cmd: &str, payload: serde_json::Value| {
        let app = router.clone();
        let tok = token.clone();
        let body = serde_json::json!({ "command": cmd, "payload": payload }).to_string();
        async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri("/api/desktop-ipc")
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(BRIDGE_TOKEN_HEADER, &tok)
                        .body(Body::from(body))?,
                )
                .await?;
            let status = resp.status();
            let bytes = resp.into_body().collect().await?.to_bytes();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes)?;
            Ok::<_, Box<dyn std::error::Error>>((status, parsed))
        }
    };

    let (st, res) = send_ipc("cmd_status", serde_json::json!({})).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(res["data"]["configured"], false);

    let (st, res) = send_ipc(
        "cmd_register",
        serde_json::json!({
            "serverUrl": server.url,
            "email": "standalone@example.com",
            "masterPassword": "ForgeMaster#2026!",
            "inviteToken": null
        }),
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(res["data"]["configured"], true);
    assert_eq!(res["data"]["unlocked"], true);

    let (st, res) = send_ipc(
        "cmd_save_item",
        serde_json::json!({
            "input": {
                "id": null,
                "kind": "login",
                "title": "Forge Console",
                "folder_id": null,
                "favorite": true,
                "trashed_at": null,
                "login": {
                    "username": "admin",
                    "email": "standalone@example.com",
                    "password": "VaultItem#Password99!",
                    "password_history": [],
                    "uris": [{ "uri": "https://forge.example.com", "match_mode": "base_domain" }],
                    "totp": {
                        "secret_base32": "otpauth://totp/Anvil:standalone@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Anvil",
                        "algorithm": "SHA1",
                        "digits": 6,
                        "period_seconds": 30,
                        "issuer": null,
                        "label": null
                    }
                },
                "custom_fields": [{ "name": "PIN", "value": "9421", "hidden": true }],
                "notes": "Standalone desktop note"
            }
        }),
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(res["data"]["title"], "Forge Console");
    assert_eq!(
        res["data"]["login"]["totp"]["secret_base32"],
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    );

    let (st, totp_res) = send_ipc(
        "cmd_generate_totp",
        serde_json::json!({
            "secretOrUri": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            "unixTimestampSeconds": 59
        }),
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(totp_res["data"]["code"], "287082");

    let (st, sync_res) = send_ipc("cmd_sync", serde_json::json!({})).await?;
    assert_eq!(st, StatusCode::OK);
    assert!(sync_res["data"]["current_revision"].as_i64().unwrap_or(0) >= 1);

    let (st, lock_res) = send_ipc("cmd_lock", serde_json::json!({})).await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(lock_res["data"]["unlocked"], false);

    let (st, unlock_res) = send_ipc(
        "cmd_unlock_password",
        serde_json::json!({ "masterPassword": "ForgeMaster#2026!" }),
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(unlock_res["data"]["unlocked"], true);

    let (st, list_res) = send_ipc(
        "cmd_list_items",
        serde_json::json!({
            "query": "Forge",
            "folderId": null,
            "favoritesOnly": false,
            "trashedOnly": false
        }),
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(list_res["data"].as_array().map(|a| a.len()), Some(1));

    // Change email and upload/delete validated profile picture via IPC.
    let (st, email_res) = send_ipc(
        "cmd_change_email",
        serde_json::json!({
            "currentPassword": "ForgeMaster#2026!",
            "newEmail": "standalone.updated@example.com"
        }),
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(email_res["data"]["email"], "standalone.updated@example.com");

    // Malicious SVG avatar payload must be rejected cleanly with HTTP 400.
    let (bad_av_st, _) = send_ipc(
        "cmd_upload_avatar",
        serde_json::json!({
            "bytes": b"<svg onload='alert(1)'></svg>".to_vec()
        }),
    )
    .await?;
    assert_eq!(bad_av_st, StatusCode::BAD_REQUEST);

    // Valid PNG avatar payload succeeds and exposes avatar_data_url in status.
    let sample_png: Vec<u8> = [
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 11, 73, 68, 65, 84, 120, 218, 99, 96, 0, 2, 0, 0, 5, 0,
        1, 233, 250, 220, 216, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ]
    .to_vec();
    let (ok_av_st, ok_av_res) = send_ipc(
        "cmd_upload_avatar",
        serde_json::json!({ "bytes": sample_png }),
    )
    .await?;
    assert_eq!(ok_av_st, StatusCode::OK);
    assert!(
        ok_av_res["data"]["avatar_data_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("data:image/png;base64,")
    );

    // Enabling and disabling Windows Hello/biometric seal clears sealed key.
    let (bio_on_st, bio_on_res) = send_ipc(
        "cmd_enable_biometric",
        serde_json::json!({ "masterPassword": "ForgeMaster#2026!" }),
    )
    .await?;
    assert_eq!(bio_on_st, StatusCode::OK);
    assert_eq!(bio_on_res["data"]["biometric_enabled"], true);

    let (bio_off_st, bio_off_res) =
        send_ipc("cmd_disable_biometric", serde_json::json!({})).await?;
    assert_eq!(bio_off_st, StatusCode::OK);
    assert_eq!(bio_off_res["data"]["biometric_enabled"], false);

    // Logout wipes RAM keys and local SQLite account, redirecting state back to unconfigured.
    let (logout_st, logout_res) = send_ipc("cmd_logout", serde_json::json!({})).await?;
    assert_eq!(logout_st, StatusCode::OK);
    assert_eq!(logout_res["data"]["configured"], false);
    assert_eq!(logout_res["data"]["unlocked"], false);

    server.shutdown().await;
    Ok(())
}
