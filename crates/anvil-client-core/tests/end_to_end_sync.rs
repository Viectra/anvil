//! End-to-end tests for offline encrypted SQLite cache, multi-device sync, conflict resolution, and RAM lock.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anvil_core::crypto::{KdfAlgorithm, KdfParams};
use anvil_core::models::{ItemUri, LoginData, UriMatchMode, VaultFolder, VaultItem};
use anvil_core::totp::TotpConfig;
use anvil_server::auth::jwt::JwtManager;
use anvil_server::auth::password::ServerAuthHasher;
use anvil_server::config::{LogFormat, ServerConfig};
use anvil_server::db::DbPool;
use anvil_server::routes::build_router;
use anvil_server::state::AppState;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tempfile::TempDir;
use zeroize::Zeroizing;

use anvil_client_core::api_client::AnvilApiClient;
use anvil_client_core::cache::EncryptedLocalCache;
use anvil_client_core::error::ClientError;
use anvil_client_core::lock_manager::VaultLockManager;
use anvil_client_core::sync_engine::{ClientSyncEngine, ConflictResolution, DecryptedConflictView};

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

const SAMPLE_PNG_B64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVQI12NgAAIAAAUAAeImBZsAAAAASUVORK5CYII=";

struct TestServerGuard {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for TestServerGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn fast_client_kdf() -> KdfParams {
    KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    }
}

async fn spawn_test_server() -> AppResult<TestServerGuard> {
    let db = DbPool::connect("sqlite::memory:").await?;
    db.migrate().await?;

    let jwt_pem = JwtManager::generate_private_key_pem()?;
    let jwt = JwtManager::from_private_key_str(&jwt_pem)?;
    let config = ServerConfig {
        database_url: "sqlite::memory:".to_owned(),
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        allow_signups: true,
        jwt_private_key: jwt_pem,
        auth_pepper: Some(Zeroizing::new(b"test-pepper-0123456789abcdef0123".to_vec())),
        prelogin_secret: Zeroizing::new(b"prelogin-test-secret-0123456789ab".to_vec()),
        trusted_proxies: Vec::new(),
        cors_origins: Vec::new(),
        enable_favicon_proxy: false,
        public_url: None,
        log_format: LogFormat::Pretty,
    };

    let hasher = ServerAuthHasher::with_params(1_024, 1, 1, config.auth_pepper.clone());
    let state = AppState {
        db,
        config: Arc::new(config),
        jwt: Arc::new(jwt),
        hasher: Arc::new(hasher),
        rate_limit_enabled: false,
    };

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    Ok(TestServerGuard {
        base_url: format!("http://{addr}"),
        handle,
    })
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn disk_cache_holds_zero_plaintext_and_supports_offline_unlock() -> AppResult<()> {
    let srv = spawn_test_server().await?;
    let dir = TempDir::new()?;
    let db_path = dir.path().join("anvil_client.db");
    let db_url = format!("sqlite:{}", db_path.to_string_lossy().replace('\\', "/"));

    let cache = EncryptedLocalCache::connect(&db_url).await?;
    let api = AnvilApiClient::new(&srv.base_url)?;
    let engine = ClientSyncEngine::new(
        api,
        cache,
        VaultLockManager::default(),
        "Desktop-Win11",
        "windows",
    );

    engine
        .register_and_unlock(
            "alice@example.com",
            "master-forge-pw-2026!",
            None,
            fast_client_kdf(),
        )
        .await?;

    let folder = VaultFolder::new("UNIQUE_SECRET_FINANCE_FOLDER");
    let saved_folder = engine.save_folder(folder).await?;

    let mut item = VaultItem::new_login(
        "UNIQUE_SECRET_BANK_TITLE",
        LoginData {
            username: "unique_bank_user".to_owned(),
            email: "alice@example.com".to_owned(),
            password: "MyUltraSecretBankPassword!99".to_owned(),
            password_history: Vec::new(),
            uris: vec![ItemUri {
                uri: "https://secure.examplebank.test/login".to_owned(),
                match_mode: UriMatchMode::BaseDomain,
            }],
            totp: Some(TotpConfig::from_input("JBSWY3DPEHPK3PXP")?),
        },
    );
    item.folder_id = Some(saved_folder.id);
    item.notes = "UniqueSecretNoteMarker".to_owned();
    let saved_item = engine.save_item(item).await?;

    let png_bytes = STANDARD.decode(SAMPLE_PNG_B64)?;
    let (blob_id, _) = engine.attach_custom_logo(saved_item.id, &png_bytes).await?;

    let report = engine.sync_now().await?;
    assert!(report.current_revision >= 2);
    assert_eq!(report.pending_conflicts, 0);

    // Lock vault -> RAM is wiped, item access fails with VaultLocked.
    engine.lock_vault();
    assert!(!engine.lock.is_unlocked());
    assert!(matches!(
        engine.lock.get_item(saved_item.id),
        Err(ClientError::VaultLocked)
    ));

    // Flush WAL pages cleanly into the main `.db` file and inspect all bytes on disk.
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(engine.cache.pool())
        .await?;
    engine.cache.pool().close().await;

    let mut inspected_bytes = Vec::new();
    inspected_bytes.extend_from_slice(&std::fs::read(&db_path)?);
    for suffix in ["-wal", "-shm"] {
        let aux = db_path.with_extension(format!("db{suffix}"));
        if let Ok(extra) = std::fs::read(&aux) {
            inspected_bytes.extend_from_slice(&extra);
        }
    }
    assert!(!inspected_bytes.is_empty());

    for sensitive in [
        b"UNIQUE_SECRET_FINANCE_FOLDER".as_slice(),
        b"UNIQUE_SECRET_BANK_TITLE".as_slice(),
        b"unique_bank_user".as_slice(),
        b"MyUltraSecretBankPassword!99".as_slice(),
        b"UniqueSecretNoteMarker".as_slice(),
        b"JBSWY3DPEHPK3PXP".as_slice(),
        b"examplebank.test".as_slice(),
    ] {
        assert!(
            !contains_bytes(&inspected_bytes, sensitive),
            "found unencrypted secret in client SQLite cache"
        );
    }

    // Reopen cache on a dead server URL and unlock offline from encrypted cache.
    let dead_api = AnvilApiClient::new("http://127.0.0.1:9")?;
    let offline_cache = EncryptedLocalCache::connect(&db_url).await?;
    let offline_engine = ClientSyncEngine::new(
        dead_api,
        offline_cache,
        VaultLockManager::default(),
        "Desktop-Win11",
        "windows",
    );

    assert!(matches!(
        offline_engine.unlock_with_password("wrong-password").await,
        Err(ClientError::InvalidMasterPassword)
    ));
    offline_engine
        .unlock_with_password("master-forge-pw-2026!")
        .await?;

    let loaded_item = offline_engine.lock.get_item(saved_item.id)?;
    assert_eq!(loaded_item.title, "UNIQUE_SECRET_BANK_TITLE");
    assert_eq!(loaded_item.logo.blob_id, Some(blob_id));
    let loaded_logo = offline_engine
        .load_custom_logo(saved_item.id, blob_id)
        .await?;
    assert_eq!(loaded_logo.mime_type, "image/png");
    assert!(!loaded_logo.data.is_empty());

    // Inactivity lock verifies automatic wipe without waiting minutes.
    let base_instant = Instant::now();
    offline_engine
        .lock
        .set_inactivity_timeout(Duration::from_secs(60));
    offline_engine.lock.touch_activity_at(base_instant);
    assert!(
        !offline_engine
            .lock
            .check_inactivity_and_lock(base_instant + Duration::from_secs(30))
    );
    assert!(
        offline_engine
            .lock
            .check_inactivity_and_lock(base_instant + Duration::from_secs(61))
    );
    assert!(!offline_engine.lock.is_unlocked());
    Ok(())
}

#[tokio::test]
async fn multi_device_differential_sync_conflicts_and_password_rotation() -> AppResult<()> {
    let srv = spawn_test_server().await?;

    let dev_a = ClientSyncEngine::new(
        AnvilApiClient::new(&srv.base_url)?,
        EncryptedLocalCache::connect("sqlite::memory:").await?,
        VaultLockManager::default(),
        "Workstation-A",
        "windows",
    );
    dev_a
        .register_and_unlock(
            "sync@example.com",
            "pw-initial-2026",
            None,
            fast_client_kdf(),
        )
        .await?;

    let item = dev_a
        .save_item(VaultItem::new_login(
            "Cloudflare",
            LoginData {
                username: "ops@example.com".to_owned(),
                email: "ops@example.com".to_owned(),
                password: "cf-initial-password".to_owned(),
                password_history: Vec::new(),
                uris: vec![ItemUri {
                    uri: "https://dash.cloudflare.com".to_owned(),
                    match_mode: UriMatchMode::BaseDomain,
                }],
                totp: None,
            },
        ))
        .await?;
    let rep_a1 = dev_a.sync_now().await?;
    assert_eq!(rep_a1.current_revision, 1);

    // Device B logs in and pulls existing vault.
    let dev_b = ClientSyncEngine::new(
        AnvilApiClient::new(&srv.base_url)?,
        EncryptedLocalCache::connect("sqlite::memory:").await?,
        VaultLockManager::default(),
        "Laptop-B",
        "linux",
    );
    dev_b
        .login_and_unlock("sync@example.com", "pw-initial-2026")
        .await?;
    assert_eq!(dev_b.lock.get_item(item.id)?.title, "Cloudflare");

    // Test 1: Identical concurrent offline edits auto-merge silently.
    let mut item_a_same = dev_a.lock.get_item(item.id)?;
    item_a_same.favorite = true;
    dev_a.save_item(item_a_same).await?;
    dev_a.sync_now().await?;

    let mut item_b_same = dev_b.lock.get_item(item.id)?;
    item_b_same.favorite = true;
    dev_b.save_item(item_b_same).await?;
    let rep_b_auto = dev_b.sync_now().await?;
    assert_eq!(rep_b_auto.auto_merged_identical, 1);
    assert_eq!(rep_b_auto.pending_conflicts, 0);

    // Test 2: Divergent edits on the same item + disjoint offline add on B.
    let mut item_a_div = dev_a.lock.get_item(item.id)?;
    item_a_div.notes = "Edited on A".to_owned();
    dev_a.save_item(item_a_div).await?;
    dev_a.sync_now().await?;

    let mut item_b_div = dev_b.lock.get_item(item.id)?;
    item_b_div.notes = "Edited offline on B".to_owned();
    dev_b.save_item(item_b_div).await?;
    let extra_b = dev_b
        .save_item(VaultItem::new_secure_note("B Note", "disjoint item"))
        .await?;

    let rep_b_conflict = dev_b.sync_now().await?;
    assert_eq!(rep_b_conflict.pending_conflicts, 1);
    // Disjoint note still pushed cleanly while conflict was captured.
    dev_a.sync_now().await?;
    assert_eq!(dev_a.lock.get_item(extra_b.id)?.title, "B Note");

    let conflicts = dev_b.list_decrypted_conflicts().await?;
    assert_eq!(conflicts.len(), 1);
    let conflict_id = match &conflicts[0] {
        DecryptedConflictView::Item {
            conflict_id,
            local,
            server,
            ..
        } => {
            assert_eq!(local.notes, "Edited offline on B");
            assert_eq!(
                server.as_ref().map(|s| s.notes.as_str()),
                Some("Edited on A")
            );
            *conflict_id
        }
        DecryptedConflictView::Folder { .. } => return Err("unexpected folder conflict".into()),
    };

    // Resolve via DuplicateBoth -> preserves both notes distinctly across devices.
    let after_res = dev_b
        .resolve_conflict(conflict_id, ConflictResolution::DuplicateBoth)
        .await?;
    assert_eq!(after_res.pending_conflicts, 0);

    dev_a.sync_now().await?;
    let summaries_a = dev_a.lock.search_summaries("", None, false, false)?;
    assert_eq!(summaries_a.len(), 3);

    // Rotate Master Password on Device A (revoking Device B's session).
    let new_ver = dev_a
        .rotate_master_password("pw-initial-2026", "pw-rotated-2026!", true)
        .await?;
    assert_eq!(new_ver, 2);

    // Device B can re-authenticate with the rotated Master Password and read all 3 items.
    dev_b
        .login_and_unlock("sync@example.com", "pw-rotated-2026!")
        .await?;
    let summaries_b = dev_b
        .lock
        .search_summaries("Cloudflare", None, false, false)?;
    assert_eq!(summaries_b.len(), 2);
    Ok(())
}

#[tokio::test]
async fn emergency_vault_key_rotation_invalidates_compromised_key_and_syncs_cleanly()
-> AppResult<()> {
    let srv = spawn_test_server().await?;
    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;

    let cache_a = EncryptedLocalCache::connect(&format!(
        "sqlite:{}",
        dir_a
            .path()
            .join("rot_a.db")
            .to_string_lossy()
            .replace('\\', "/")
    ))
    .await?;
    let cache_b = EncryptedLocalCache::connect(&format!(
        "sqlite:{}",
        dir_b
            .path()
            .join("rot_b.db")
            .to_string_lossy()
            .replace('\\', "/")
    ))
    .await?;

    let dev_a = ClientSyncEngine::new(
        AnvilApiClient::new(&srv.base_url)?,
        cache_a.clone(),
        VaultLockManager::new(Duration::from_secs(300)),
        "Workstation",
        "windows",
    );
    dev_a
        .register_and_unlock(
            "emergency@example.com",
            "MasterEmerg#2026!",
            None,
            fast_client_kdf(),
        )
        .await?;

    let folder = dev_a.save_folder(VaultFolder::new("Finance")).await?;
    let mut item = VaultItem::new_login(
        "Stripe Admin",
        LoginData {
            username: "treasury".to_owned(),
            email: "emergency@example.com".to_owned(),
            password: "Stripe#OldCipherSecret".to_owned(),
            password_history: Vec::new(),
            uris: vec![ItemUri {
                uri: "https://dashboard.stripe.com".to_owned(),
                match_mode: UriMatchMode::BaseDomain,
            }],
            totp: None,
        },
    );
    item.folder_id = Some(folder.id);
    let saved_item = dev_a.save_item(item).await?;
    let png_bytes = STANDARD.decode(SAMPLE_PNG_B64)?;
    let (blob_id, _) = dev_a.attach_custom_logo(saved_item.id, &png_bytes).await?;
    dev_a.sync_now().await?;

    // Simulate leaked biometric seal + compromised old VaultKey & active Device B session.
    let acct_a = cache_a.load_account().await?.ok_or("missing account A")?;
    cache_a
        .set_biometric_seal(acct_a.user_id, Some(b"stale-compromised-seal"))
        .await?;
    let (_, _, leaked_old_vk, leaked_old_subkeys) = dev_a.lock.keys_snapshot()?;

    let dev_b = ClientSyncEngine::new(
        AnvilApiClient::new(&srv.base_url)?,
        cache_b.clone(),
        VaultLockManager::new(Duration::from_secs(300)),
        "Phone",
        "ios",
    );
    dev_b
        .login_and_unlock("emergency@example.com", "MasterEmerg#2026!")
        .await?;

    // Perform atomic emergency rotation on Device A and revoke all other sessions.
    let report = dev_a
        .emergency_rotate_vault_key("MasterEmerg#2026!", true)
        .await?;
    assert_eq!(report.key_version, 2);
    assert_eq!(report.reencrypted_folders, 1);
    assert_eq!(report.reencrypted_items, 1);
    assert_eq!(report.reencrypted_blobs, 1);

    // Local stale biometric seal must have been wiped.
    let acct_after = cache_a
        .load_account()
        .await?
        .ok_or("missing account after rotation")?;
    assert_eq!(acct_after.biometric_sealed_vault_key, None);
    assert_eq!(acct_after.key_version, 2);

    // Compromised Device B session was revoked on the server.
    assert!(dev_b.sync_now().await.is_err());

    // Old leaked VaultKey cannot decrypt rotated folder, item, or blob ciphertexts on Device A.
    let rotated_folders = cache_a.list_active_folders(acct_after.user_id).await?;
    let rotated_items = cache_a.list_active_items(acct_after.user_id).await?;
    let rotated_blob = cache_a
        .get_cached_blob(acct_after.user_id, blob_id)
        .await?
        .ok_or("missing rotated cached blob")?;

    assert!(
        anvil_core::models::decrypt_folder(
            &leaked_old_subkeys,
            acct_after.user_id,
            &anvil_core::models::EncryptedFolderRecord {
                id: rotated_folders[0].id,
                encrypted_data: rotated_folders[0].encrypted_data.clone(),
                revision: rotated_folders[0].revision,
                deleted: false,
                updated_at: rotated_folders[0].updated_at,
            },
        )
        .is_err()
    );
    assert!(
        anvil_core::models::decrypt_item(
            &leaked_old_subkeys,
            acct_after.user_id,
            &anvil_core::models::EncryptedItemRecord {
                id: rotated_items[0].id,
                encrypted_data: rotated_items[0].encrypted_data.clone(),
                revision: rotated_items[0].revision,
                deleted: false,
                updated_at: rotated_items[0].updated_at,
            },
        )
        .is_err()
    );
    assert!(
        anvil_core::models::decrypt_blob(
            &leaked_old_subkeys,
            acct_after.user_id,
            &anvil_core::models::EncryptedBlobRecord {
                id: rotated_blob.id,
                item_id: rotated_blob.item_id,
                encrypted_blob: rotated_blob.encrypted_blob.clone(),
                revision: rotated_blob.revision,
                deleted: false,
                updated_at: rotated_blob.updated_at,
            },
        )
        .is_err()
    );

    // Fresh Device B login receives key_version 2 with new VaultKey and decrypts item & logo cleanly.
    dev_b
        .login_and_unlock("emergency@example.com", "MasterEmerg#2026!")
        .await?;
    let (_, b_ver, new_b_vk, _) = dev_b.lock.keys_snapshot()?;
    assert_eq!(b_ver, 2);
    assert_ne!(new_b_vk.as_bytes(), leaked_old_vk.as_bytes());
    assert_eq!(dev_b.lock.get_item(saved_item.id)?.title, "Stripe Admin");
    let loaded_logo = dev_b.load_custom_logo(saved_item.id, blob_id).await?;
    assert!(!loaded_logo.data.is_empty());

    Ok(())
}

#[tokio::test]
async fn account_profile_email_avatar_refresh_and_logout_lifecycle() -> AppResult<()> {
    let srv = spawn_test_server().await?;
    let dir = TempDir::new()?;
    let db_path = dir.path().join("legacy_v1_cache.db");
    let db_url = format!("sqlite:{}", db_path.to_string_lossy().replace('\\', "/"));

    // Simulate an existing v1 vault_cache.db missing avatar_png and encrypted_refresh_token columns.
    {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(&format!("{db_url}?mode=rwc"))
            .await?;
        sqlx::raw_sql(
            "CREATE TABLE local_account (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                user_id TEXT NOT NULL UNIQUE,
                server_url TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL,
                kdf_memory_kib INTEGER NOT NULL,
                kdf_iterations INTEGER NOT NULL,
                kdf_parallelism INTEGER NOT NULL,
                kdf_salt BLOB NOT NULL,
                key_version INTEGER NOT NULL,
                encrypted_vault_key BLOB NOT NULL,
                last_synced_revision INTEGER NOT NULL DEFAULT 0,
                biometric_sealed_vault_key BLOB NULL,
                updated_at TEXT NOT NULL
            );",
        )
        .execute(&pool)
        .await?;
        pool.close().await;
    }

    let cache = EncryptedLocalCache::connect(&db_url).await?;
    let engine = ClientSyncEngine::new(
        AnvilApiClient::new(&srv.base_url)?,
        cache.clone(),
        VaultLockManager::default(),
        "Desktop-Test",
        "windows",
    );

    engine
        .register_and_unlock(
            "profile@example.com",
            "Profile#Pass2026!",
            None,
            fast_client_kdf(),
        )
        .await?;

    let png_bytes = STANDARD.decode(SAMPLE_PNG_B64)?;
    assert!(engine.upload_avatar(b"<svg></svg>").await.is_err());
    let uploaded_png = engine.upload_avatar(&png_bytes).await?;
    assert!(uploaded_png.starts_with(b"\x89PNG\r\n\x1a\n"));

    let updated_email = engine
        .change_email("Profile#Pass2026!", "Renamed@Example.com")
        .await?;
    assert_eq!(updated_email, "renamed@example.com");

    // Lock, drop RAM bearer tokens, and verify unlock_with_password restores session & profile cleanly.
    engine.lock_vault();
    engine.api.clear_tokens().await;
    engine.unlock_with_password("Profile#Pass2026!").await?;
    assert!(engine.api.has_session().await);

    let cached_after = cache.load_account().await?.ok_or("missing cached acct")?;
    assert_eq!(cached_after.email, "renamed@example.com");
    assert!(cached_after.avatar_png.is_some());

    engine.delete_avatar().await?;
    assert!(
        cache
            .load_account()
            .await?
            .ok_or("missing acct")?
            .avatar_png
            .is_none()
    );

    engine.logout_and_clear_local_account().await?;
    assert!(!engine.lock.is_unlocked());
    assert!(!engine.api.has_session().await);
    assert!(cache.load_account().await?.is_none());

    Ok(())
}
