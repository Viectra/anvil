//! End-to-end mobile validation: QR onboarding & otpauth:// scan, bidirectional server sync,
//! biometric hardware enclave unlock (zero KDF), Android package & iOS domain autofill safety.

use std::net::SocketAddr;
use std::sync::Arc;

use anvil_client_core::cache::EncryptedLocalCache;
use anvil_core::crypto::{KdfAlgorithm, KdfParams};
use anvil_core::models::{ItemKind, ItemUri, UriMatchMode};
use anvil_mobile::autofill::{AutofillCallerContext, MobilePlatform};
use anvil_mobile::biometric::{MobileEnclaveKind, SimulatedHardwareEnclave};
use anvil_mobile::commands::{LoginDataDto, MobileCommandHost, SaveItemInputDto};
use anvil_mobile::error::MobileError;
use anvil_mobile::qr::{AnvilOnboardingQr, QrScanResult};
use anvil_server::auth::jwt::JwtManager;
use anvil_server::auth::password::ServerAuthHasher;
use anvil_server::config::{LogFormat, ServerConfig};
use anvil_server::db::DbPool;
use anvil_server::routes::build_router;
use anvil_server::state::AppState;
use tempfile::TempDir;
use zeroize::Zeroizing;

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;

struct TestServerGuard {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for TestServerGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn fast_mobile_kdf() -> KdfParams {
    KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    }
}

fn sqlite_url(path: &std::path::Path) -> String {
    format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"))
}

async fn spawn_test_server() -> TestResult<TestServerGuard> {
    let db = DbPool::connect("sqlite::memory:").await?;
    db.migrate().await?;

    let jwt_pem = JwtManager::generate_private_key_pem()?;
    let jwt = JwtManager::from_private_key_str(&jwt_pem)?;
    let config = ServerConfig {
        database_url: "sqlite::memory:".to_owned(),
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        allow_signups: true,
        jwt_private_key: jwt_pem,
        auth_pepper: Some(Zeroizing::new(
            b"mobile-test-pepper-0123456789abcdef".to_vec(),
        )),
        prelogin_secret: Zeroizing::new(b"mobile-prelogin-secret-0123456789".to_vec()),
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
        base_url: format!("http://127.0.0.1:{}", addr.port()),
        handle,
    })
}

#[tokio::test]
async fn qr_onboarding_otpauth_scan_and_bidirectional_sync_work() -> TestResult<()> {
    let srv = spawn_test_server().await?;
    let dir_a = TempDir::new()?;
    let dir_b = TempDir::new()?;

    let cache_a = EncryptedLocalCache::connect(&sqlite_url(&dir_a.path().join("mob_a.db"))).await?;
    let cache_b = EncryptedLocalCache::connect(&sqlite_url(&dir_b.path().join("mob_b.db"))).await?;

    let enclave_a = Arc::new(SimulatedHardwareEnclave::available(
        MobileEnclaveKind::AndroidKeystoreStrongBox,
    )?);
    let enclave_b = Arc::new(SimulatedHardwareEnclave::available(
        MobileEnclaveKind::IosSecureEnclave,
    )?);

    let host_a =
        MobileCommandHost::new(cache_a, &srv.base_url, enclave_a, "android", "Pixel 9 Pro")?
            .with_kdf_params(fast_mobile_kdf());

    let host_b = MobileCommandHost::new(cache_b, &srv.base_url, enclave_b, "ios", "iPhone 16")?
        .with_kdf_params(fast_mobile_kdf());

    // Device A decodes onboarding QR deep link and registers against self-hosted server.
    let qr_uri = AnvilOnboardingQr {
        server_url: srv.base_url.clone(),
        email: Some("mobile@example.internal".to_owned()),
        invite_token: None,
    }
    .encode_uri()?;

    let QrScanResult::Onboarding(setup) = host_a.cmd_parse_qr(&qr_uri)? else {
        return Err("expected onboarding QR result".into());
    };

    let reg_status = host_a
        .cmd_register(
            &setup.server_url,
            setup.email.as_deref().ok_or("missing email")?,
            "MobileMaster#Forge2026!",
            setup.invite_token.as_deref(),
        )
        .await?;
    assert!(reg_status.unlocked);

    let saved = host_a
        .cmd_save_item(SaveItemInputDto {
            id: None,
            kind: ItemKind::Login,
            title: "GitHub".to_owned(),
            folder_id: None,
            favorite: true,
            trashed_at: None,
            login: Some(LoginDataDto {
                username: "viectra".to_owned(),
                email: "mobile@example.internal".to_owned(),
                password: "InitialPassword!88".to_owned(),
                password_history: Vec::new(),
                uris: vec![
                    ItemUri {
                        uri: "https://github.com/login".to_owned(),
                        match_mode: UriMatchMode::BaseDomain,
                    },
                    ItemUri {
                        uri: "androidapp://com.github.android".to_owned(),
                        match_mode: UriMatchMode::Exact,
                    },
                ],
                totp: None,
            }),
            custom_fields: Vec::new(),
            notes: String::new(),
        })
        .await?;

    // Camera scans otpauth:// QR and attaches TOTP directly onto the item.
    let with_totp = host_a
        .cmd_attach_totp_from_qr(
            &saved.id,
            "otpauth://totp/GitHub:viectra?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
        )
        .await?;
    let secret = with_totp
        .login
        .as_ref()
        .and_then(|l| l.totp.as_ref())
        .ok_or("TOTP not attached")?
        .secret_base32
        .clone();
    assert_eq!(host_a.cmd_generate_totp(&secret, 59)?.code, "996554");

    let push_report = host_a.cmd_sync().await?;
    assert_eq!(push_report.current_revision, 1);

    // Device B (iOS) logs in and receives decrypted account + TOTP code cleanly.
    let login_status = host_b
        .cmd_login(
            &srv.base_url,
            "mobile@example.internal",
            "MobileMaster#Forge2026!",
        )
        .await?;
    assert!(login_status.unlocked);

    let items_b = host_b.cmd_list_items("GitHub", None, false, false).await?;
    assert_eq!(items_b.len(), 1);
    assert!(items_b[0].has_totp);
    let detail_b = host_b.cmd_get_item(&items_b[0].id).await?;
    let mut updated_login = detail_b.login.ok_or("missing login")?;
    updated_login.password = "RotatedOnIos!99".to_owned();
    host_b
        .cmd_save_item(SaveItemInputDto {
            id: Some(detail_b.id.clone()),
            kind: ItemKind::Login,
            title: detail_b.title,
            folder_id: detail_b.folder_id,
            favorite: detail_b.favorite,
            trashed_at: None,
            login: Some(updated_login),
            custom_fields: Vec::new(),
            notes: String::new(),
        })
        .await?;
    let rev2 = host_b.cmd_sync().await?;
    assert_eq!(rev2.current_revision, 2);

    // Device A pulls iOS update cleanly.
    let pull_a = host_a.cmd_sync().await?;
    assert_eq!(pull_a.current_revision, 2);
    let detail_a = host_a.cmd_get_item(&saved.id).await?;
    assert_eq!(
        detail_a.login.as_ref().map(|l| l.password.as_str()),
        Some("RotatedOnIos!99")
    );

    Ok(())
}

#[tokio::test]
async fn biometric_enclave_background_lock_and_mobile_os_autofill_enforce_isolation()
-> TestResult<()> {
    let srv = spawn_test_server().await?;
    let dir = TempDir::new()?;
    let cache = EncryptedLocalCache::connect(&sqlite_url(&dir.path().join("bio.db"))).await?;
    let enclave = Arc::new(SimulatedHardwareEnclave::available(
        MobileEnclaveKind::IosSecureEnclave,
    )?);

    let host = MobileCommandHost::new(cache, &srv.base_url, enclave, "ios", "iPhone Test")?
        .with_kdf_params(fast_mobile_kdf());

    host.cmd_register(
        &srv.base_url,
        "sec@example.internal",
        "BioMaster#2026!",
        None,
    )
    .await?;
    host.cmd_enable_biometric("BioMaster#2026!").await?;

    let item = host
        .cmd_save_item(SaveItemInputDto {
            id: None,
            kind: ItemKind::Login,
            title: "GitHub".to_owned(),
            folder_id: None,
            favorite: false,
            trashed_at: None,
            login: Some(LoginDataDto {
                username: "sec-user".to_owned(),
                email: "sec@example.internal".to_owned(),
                password: "AutofillSecret#77".to_owned(),
                password_history: Vec::new(),
                uris: vec![
                    ItemUri {
                        uri: "https://github.com/login".to_owned(),
                        match_mode: UriMatchMode::BaseDomain,
                    },
                    ItemUri {
                        uri: "androidapp://com.github.android".to_owned(),
                        match_mode: UriMatchMode::Exact,
                    },
                ],
                totp: Some(anvil_core::totp::TotpConfig::from_input(
                    "JBSWY3DPEHPK3PXP",
                )?),
            }),
            custom_fields: Vec::new(),
            notes: String::new(),
        })
        .await?;

    // Backgrounding mobile app locks RAM immediately.
    let bg_status = host.cmd_on_app_backgrounded().await?;
    assert!(!bg_status.unlocked);
    assert!(host.cmd_list_items("", None, false, false).await.is_err());

    // Biometric enclave unseals VaultKey directly without Master Password / Argon2id.
    let bio_status = host.cmd_unlock_biometric().await?;
    assert!(bio_status.unlocked);
    assert!(bio_status.biometric_enabled);

    // Android package autofill matches exact package ID and rejects lookalike packages.
    let android_ctx = AutofillCallerContext {
        platform: MobilePlatform::Android,
        web_domain: None,
        android_package_name: Some("com.github.android".to_owned()),
        ios_associated_domains: Vec::new(),
    };
    let candidates = host.cmd_autofill_query(&android_ctx)?;
    assert_eq!(candidates.len(), 1);
    let fill = host.cmd_autofill_fill(&item.id, &android_ctx, 59)?;
    assert_eq!(fill.password, "AutofillSecret#77");
    assert_eq!(fill.totp_code.as_deref(), Some("996554"));

    let evil_android = AutofillCallerContext {
        platform: MobilePlatform::Android,
        web_domain: None,
        android_package_name: Some("com.github.android.fake".to_owned()),
        ios_associated_domains: Vec::new(),
    };
    assert!(host.cmd_autofill_query(&evil_android)?.is_empty());
    assert!(matches!(
        host.cmd_autofill_fill(&item.id, &evil_android, 59).err(),
        Some(MobileError::AutofillDenied(_))
    ));

    // iOS associated domain matches gist.github.com and rejects github.com.evil.co.uk.
    let ios_ctx = AutofillCallerContext {
        platform: MobilePlatform::Ios,
        web_domain: None,
        android_package_name: None,
        ios_associated_domains: vec!["webcredentials:gist.github.com".to_owned()],
    };
    assert_eq!(host.cmd_autofill_query(&ios_ctx)?.len(), 1);

    let phish_ios = AutofillCallerContext {
        platform: MobilePlatform::Ios,
        web_domain: Some("https://github.com.evil.co.uk/login".to_owned()),
        android_package_name: None,
        ios_associated_domains: Vec::new(),
    };
    assert!(host.cmd_autofill_query(&phish_ios)?.is_empty());
    assert!(matches!(
        host.cmd_autofill_fill(&item.id, &phish_ios, 59).err(),
        Some(MobileError::AutofillDenied(_))
    ));

    Ok(())
}
