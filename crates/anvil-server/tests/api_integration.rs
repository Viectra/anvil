//! End-to-end Zero-Knowledge, multi-user isolation, anti-replay, concurrency, admin, and rate-limit tests.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anvil_core::crypto::{
    KdfAlgorithm, KdfParams, MasterPassword, VaultKey, derive_master_key, derive_master_subkeys,
    derive_vault_subkeys, unwrap_vault_key, wrap_vault_key,
};
use anvil_core::models::{
    EncryptedBlobRecord, EncryptedFolderRecord, EncryptedItemRecord, ItemUri, LoginData,
    UriMatchMode, VaultBlob, VaultFolder, VaultItem, decrypt_blob, decrypt_folder, decrypt_item,
    encrypt_blob, encrypt_folder, encrypt_item,
};
use anvil_core::totp::TotpConfig;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{Duration, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use uuid::Uuid;
use zeroize::Zeroizing;

use anvil_server::auth::jwt::JwtManager;
use anvil_server::auth::password::{ServerAuthHasher, generate_opaque_token};
use anvil_server::config::{LogFormat, ServerConfig, parse_trusted_proxies};
use anvil_server::db::{DbPool, UpdateUserAdminInput, UserRole, VaultRepository};
use anvil_server::routes::build_router;
use anvil_server::state::AppState;

type DynError = Box<dyn std::error::Error>;
type AppResult<T> = Result<T, DynError>;

struct TestApp {
    router: Router,
    db: DbPool,
    _temp_dir: Option<TempDir>,
}

struct ClientAccount {
    user_id: Uuid,
    email: String,
    password: String,
    kdf_params: KdfParams,
    kdf_salt: [u8; 32],
    master_auth_hash: [u8; 32],
    vault_key: VaultKey,
    access_token: String,
    refresh_token: String,
}

fn fast_client_kdf() -> KdfParams {
    KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: 19_456,
        iterations: 2,
        parallelism: 1,
    }
}

async fn setup_app(
    database_url: &str,
    allow_signups: bool,
    enable_favicon_proxy: bool,
    rate_limit_enabled: bool,
    trusted_proxies_raw: Option<&str>,
    temp_dir: Option<TempDir>,
) -> AppResult<TestApp> {
    let db = DbPool::connect(database_url).await?;
    db.migrate().await?;

    let jwt_pem = JwtManager::generate_private_key_pem()?;
    let jwt = JwtManager::from_private_key_str(&jwt_pem)?;
    let trusted_proxies = parse_trusted_proxies(trusted_proxies_raw.map(ToOwned::to_owned))?;

    let config = ServerConfig {
        database_url: database_url.to_owned(),
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        allow_signups,
        jwt_private_key: jwt_pem,
        auth_pepper: Some(Zeroizing::new(b"test-pepper-0123456789abcdef0123".to_vec())),
        prelogin_secret: Zeroizing::new(b"prelogin-test-secret-0123456789ab".to_vec()),
        trusted_proxies,
        cors_origins: vec![],
        enable_favicon_proxy,
        public_url: Some("https://vault.test".to_owned()),
        log_format: LogFormat::Pretty,
    };

    let hasher = ServerAuthHasher::with_params(1_024, 1, 1, config.auth_pepper.clone());
    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
        jwt: Arc::new(jwt),
        hasher: Arc::new(hasher),
        rate_limit_enabled,
    };
    let router = build_router(state);

    Ok(TestApp {
        router,
        db,
        _temp_dir: temp_dir,
    })
}

async fn setup_sqlite_memory(allow_signups: bool) -> AppResult<TestApp> {
    setup_app("sqlite::memory:", allow_signups, false, false, None, None).await
}

struct ReqOpts<'a> {
    bearer: Option<&'a str>,
    body: Option<Vec<u8>>,
    content_type: Option<&'a str>,
    extra_headers: &'a [(&'a str, &'a str)],
    peer_ip: Option<&'a str>,
}

async fn send_inner(
    router: &Router,
    method: Method,
    uri: &str,
    opts: ReqOpts<'_>,
) -> AppResult<(StatusCode, HeaderMap, Vec<u8>)> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(tok) = opts.bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    if let Some(ct) = opts.content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    for (k, v) in opts.extra_headers {
        builder = builder.header(*k, *v);
    }
    let body_obj = opts.body.map(Body::from).unwrap_or_else(Body::empty);
    let mut req = builder.body(body_obj)?;

    if let Some(raw_ip) = opts.peer_ip {
        let ip: IpAddr = raw_ip.parse()?;
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::new(ip, 44321)));
    }

    let response = router.clone().oneshot(req).await?;
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await?.to_bytes().to_vec();
    Ok((status, headers, bytes))
}

async fn send_request(
    router: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
) -> AppResult<(StatusCode, HeaderMap, Vec<u8>)> {
    send_inner(
        router,
        method,
        uri,
        ReqOpts {
            bearer,
            body,
            content_type,
            extra_headers: &[],
            peer_ip: None,
        },
    )
    .await
}

async fn send_from_ip(
    router: &Router,
    uri: &str,
    body: Vec<u8>,
    extra_headers: &[(&str, &str)],
    peer_ip: &str,
) -> AppResult<(StatusCode, HeaderMap, Vec<u8>)> {
    send_inner(
        router,
        Method::POST,
        uri,
        ReqOpts {
            bearer: None,
            body: Some(body),
            content_type: Some("application/json"),
            extra_headers,
            peer_ip: Some(peer_ip),
        },
    )
    .await
}

async fn send_json(
    router: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
    payload: Option<Value>,
) -> AppResult<(StatusCode, HeaderMap, Value)> {
    let body = payload.map(|v| serde_json::to_vec(&v)).transpose()?;
    let (status, headers, bytes) =
        send_request(router, method, uri, bearer, body, Some("application/json")).await?;
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)?
    };
    Ok((status, headers, json))
}

async fn register_zk_account(
    router: &Router,
    email: &str,
    password: &str,
    invite_token: Option<&str>,
) -> AppResult<ClientAccount> {
    let user_id = Uuid::new_v4();
    let kdf_params = fast_client_kdf();
    let mut kdf_salt = [0u8; 32];
    anvil_core::crypto::fill_random_bytes(&mut kdf_salt)?;

    let pw = MasterPassword::new(password);
    let mk = derive_master_key(&pw, &kdf_salt, &kdf_params)?;
    let (mek, auth_hash) = derive_master_subkeys(&mk, &kdf_salt)?;
    let vault_key = VaultKey::generate()?;
    let wrapped_vk = wrap_vault_key(&mek, &vault_key, user_id, 1)?;

    let payload = json!({
        "user_id": user_id,
        "email": email,
        "kdf_params": kdf_params,
        "kdf_salt_b64": STANDARD.encode(kdf_salt),
        "master_auth_hash_b64": STANDARD.encode(auth_hash.as_bytes()),
        "encrypted_vault_key_b64": STANDARD.encode(&wrapped_vk),
        "invite_token": invite_token,
        "device_name": "Test Workstation",
        "device_platform": "windows"
    });

    let (status, _, body) = send_json(
        router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(payload),
    )
    .await?;
    if status != StatusCode::CREATED {
        return Err(format!("expected 201 on register, got {status}: {body}").into());
    }

    let access_token = body["access_token"]
        .as_str()
        .ok_or("missing access_token")?
        .to_owned();
    let refresh_token = body["refresh_token"]
        .as_str()
        .ok_or("missing refresh_token")?
        .to_owned();

    Ok(ClientAccount {
        user_id,
        email: email.to_owned(),
        password: password.to_owned(),
        kdf_params,
        kdf_salt,
        master_auth_hash: *auth_hash.as_bytes(),
        vault_key,
        access_token,
        refresh_token,
    })
}

async fn login_zk_account(
    router: &Router,
    email: &str,
    password: &str,
    device_name: &str,
) -> AppResult<(String, String, VaultKey, u32)> {
    let (_, _, pre) = send_json(
        router,
        Method::POST,
        "/api/v1/auth/prelogin",
        None,
        Some(json!({ "email": email })),
    )
    .await?;

    let kdf_params = KdfParams {
        algorithm: KdfAlgorithm::Argon2id,
        memory_kib: u32::try_from(pre["kdf_memory_kib"].as_u64().ok_or("kdf_memory_kib")?)?,
        iterations: u32::try_from(pre["kdf_iterations"].as_u64().ok_or("kdf_iterations")?)?,
        parallelism: u32::try_from(pre["kdf_parallelism"].as_u64().ok_or("kdf_parallelism")?)?,
    };
    let salt_vec = STANDARD.decode(pre["kdf_salt_b64"].as_str().ok_or("kdf_salt_b64")?)?;
    let mut kdf_salt = [0u8; 32];
    kdf_salt.copy_from_slice(&salt_vec);

    let pw = MasterPassword::new(password);
    let mk = derive_master_key(&pw, &kdf_salt, &kdf_params)?;
    let (mek, auth_hash) = derive_master_subkeys(&mk, &kdf_salt)?;

    let (status, _, login_body) = send_json(
        router,
        Method::POST,
        "/api/v1/auth/login",
        None,
        Some(json!({
            "email": email,
            "master_auth_hash_b64": STANDARD.encode(auth_hash.as_bytes()),
            "device_name": device_name,
            "device_platform": "linux"
        })),
    )
    .await?;
    if status != StatusCode::OK {
        return Err(format!("login failed with {status}: {login_body}").into());
    }

    let user_id: Uuid = login_body["user_id"].as_str().ok_or("user_id")?.parse()?;
    let key_version = u32::try_from(login_body["key_version"].as_u64().ok_or("key_version")?)?;
    let wrapped_vk = STANDARD.decode(
        login_body["encrypted_vault_key_b64"]
            .as_str()
            .ok_or("encrypted_vault_key_b64")?,
    )?;
    let vk = unwrap_vault_key(&mek, &wrapped_vk, user_id, key_version)?;

    Ok((
        login_body["access_token"]
            .as_str()
            .ok_or("access_token")?
            .to_owned(),
        login_body["refresh_token"]
            .as_str()
            .ok_or("refresh_token")?
            .to_owned(),
        vk,
        key_version,
    ))
}

#[tokio::test]
async fn zk_lifecycle_prelogin_sync_and_wal_file_persistence() -> AppResult<()> {
    let dir = TempDir::new()?;
    let db_path = dir.path().join("anvil_wal.db");
    let db_url = format!("sqlite:{}", db_path.to_string_lossy().replace('\\', "/"));
    let app = setup_app(&db_url, false, false, false, None, Some(dir)).await?;

    let (health_status, health_headers, health) =
        send_json(&app.router, Method::GET, "/api/v1/health", None, None).await?;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health["status"], "ok");
    assert_eq!(health["db_ok"], true);
    assert_eq!(
        health_headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert!(health_headers.get("x-request-id").is_some());

    let (meta_status, _, meta) =
        send_json(&app.router, Method::GET, "/api/v1/meta", None, None).await?;
    assert_eq!(meta_status, StatusCode::OK);
    assert_eq!(meta["signups_enabled"], false);
    assert_eq!(meta["favicon_proxy_enabled"], false);
    assert_eq!(meta["max_blob_bytes"], 262_144);

    // Malformed JSON still returns uniform JSON envelope populated with request_id.
    let (bad_json_status, _, bad_json_bytes) = send_request(
        &app.router,
        Method::POST,
        "/api/v1/auth/prelogin",
        None,
        Some(b"{not valid json".to_vec()),
        Some("application/json"),
    )
    .await?;
    assert_eq!(bad_json_status, StatusCode::BAD_REQUEST);
    let bad_json: Value = serde_json::from_slice(&bad_json_bytes)?;
    assert_eq!(bad_json["error"]["code"], "INVALID_JSON");
    assert!(
        !bad_json["error"]["request_id"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );

    // Prelogin anti-enumeration: repeated unknown email queries yield identical deterministic salt.
    let (_, _, pre1) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/prelogin",
        None,
        Some(json!({ "email": "alice@example.com" })),
    )
    .await?;
    let (_, _, pre2) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/prelogin",
        None,
        Some(json!({ "email": "ALICE@EXAMPLE.COM" })),
    )
    .await?;
    assert_eq!(pre1["kdf_salt_b64"], pre2["kdf_salt_b64"]);
    assert_eq!(pre1["kdf_memory_kib"], 65_536);

    let (invite_token, invite_hash) = generate_opaque_token()?;
    app.db
        .create_invitation(
            &invite_hash,
            Some("alice@example.com"),
            None,
            1,
            Utc::now() + Duration::hours(24),
        )
        .await?;

    let alice = register_zk_account(
        &app.router,
        "Alice@Example.com",
        "correct-horse-forge-pw-2026!",
        Some(&invite_token),
    )
    .await?;

    // Now prelogin returns Alice's actual salt instead of fake salt.
    let (_, _, pre_real) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/prelogin",
        None,
        Some(json!({ "email": "alice@example.com" })),
    )
    .await?;
    assert_eq!(pre_real["kdf_salt_b64"], STANDARD.encode(alice.kdf_salt));
    assert_ne!(pre_real["kdf_salt_b64"], pre1["kdf_salt_b64"]);

    let (access_token, _, unwrapped_vk, _) = login_zk_account(
        &app.router,
        "alice@example.com",
        "correct-horse-forge-pw-2026!",
        "Laptop",
    )
    .await?;
    assert_eq!(unwrapped_vk, alice.vault_key);

    let subkeys = derive_vault_subkeys(&unwrapped_vk)?;
    let folder = VaultFolder::new("Work");
    let enc_folder = encrypt_folder(&subkeys, alice.user_id, &folder, 1)?;

    let mut item = VaultItem::new_login(
        "GitHub Enterprise",
        LoginData {
            username: "viectra".to_owned(),
            email: "alice@example.com".to_owned(),
            password: "s3cur3-github-password".to_owned(),
            password_history: vec![],
            uris: vec![ItemUri {
                uri: "https://github.com/login".to_owned(),
                match_mode: UriMatchMode::BaseDomain,
            }],
            totp: Some(TotpConfig::from_input("JBSWY3DPEHPK3PXP")?),
        },
    );
    item.folder_id = Some(folder.id);
    item.favorite = true;
    let enc_item = encrypt_item(&subkeys, alice.user_id, &item, 1)?;

    let (push_status, _, push_body) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/vault/sync",
        Some(&access_token),
        Some(json!({
            "base_revision": 0,
            "folders_upsert": [{
                "id": enc_folder.id,
                "encrypted_data_b64": STANDARD.encode(&enc_folder.encrypted_data)
            }],
            "items_upsert": [{
                "id": enc_item.id,
                "encrypted_data_b64": STANDARD.encode(&enc_item.encrypted_data)
            }]
        })),
    )
    .await?;
    assert_eq!(push_status, StatusCode::OK);
    assert_eq!(push_body["new_revision"], 1);

    // Upload an encrypted custom logo blob and verify >256 KiB cap enforcement.
    let blob_id = Uuid::new_v4();
    let blob = VaultBlob {
        id: blob_id,
        item_id: item.id,
        mime_type: "image/png".to_owned(),
        data: Zeroizing::new(vec![0x89, 0x50, 0x4E, 0x47, 1, 2, 3, 4]),
        updated_at: Utc::now(),
    };
    let enc_blob = encrypt_blob(&subkeys, alice.user_id, &blob, 2)?;
    let (blob_status, _, blob_bytes) = send_request(
        &app.router,
        Method::PUT,
        &format!("/api/v1/vault/blobs/{blob_id}?item_id={}", item.id),
        Some(&access_token),
        Some(enc_blob.encrypted_blob.clone()),
        Some("application/octet-stream"),
    )
    .await?;
    assert_eq!(blob_status, StatusCode::OK);
    let blob_meta_resp: Value = serde_json::from_slice(&blob_bytes)?;
    assert_eq!(blob_meta_resp["revision"], 2);

    let (oversized_status, _, oversized_bytes) = send_request(
        &app.router,
        Method::PUT,
        &format!("/api/v1/vault/blobs/{}?item_id={}", Uuid::new_v4(), item.id),
        Some(&access_token),
        Some(vec![0x01u8; 262_145]),
        Some("application/octet-stream"),
    )
    .await?;
    assert_eq!(oversized_status, StatusCode::PAYLOAD_TOO_LARGE);
    let oversized_json: Value = serde_json::from_slice(&oversized_bytes)?;
    assert_eq!(oversized_json["error"]["code"], "BLOB_TOO_LARGE");

    // Pull sync and decrypt everything with anvil-core.
    let (pull_status, _, pull_body) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/vault/sync?since_revision=0",
        Some(&access_token),
        None,
    )
    .await?;
    assert_eq!(pull_status, StatusCode::OK);
    assert_eq!(pull_body["current_revision"], 2);
    assert_eq!(pull_body["folders"].as_array().map(Vec::len), Some(1));
    assert_eq!(pull_body["items"].as_array().map(Vec::len), Some(1));
    assert_eq!(pull_body["blobs_meta"].as_array().map(Vec::len), Some(1));

    let wire_item = EncryptedItemRecord {
        id: pull_body["items"][0]["id"].as_str().ok_or("id")?.parse()?,
        encrypted_data: STANDARD.decode(
            pull_body["items"][0]["encrypted_data_b64"]
                .as_str()
                .ok_or("data")?,
        )?,
        revision: pull_body["items"][0]["revision"].as_i64().ok_or("rev")?,
        deleted: pull_body["items"][0]["deleted"].as_bool().ok_or("del")?,
        updated_at: Utc::now(),
    };
    let dec_item = decrypt_item(&subkeys, alice.user_id, &wire_item)?;
    assert_eq!(dec_item.title, "GitHub Enterprise");
    assert_eq!(
        dec_item.login.as_ref().map(|l| l.password.as_str()),
        Some("s3cur3-github-password")
    );

    let wire_folder = EncryptedFolderRecord {
        id: pull_body["folders"][0]["id"]
            .as_str()
            .ok_or("fid")?
            .parse()?,
        encrypted_data: STANDARD.decode(
            pull_body["folders"][0]["encrypted_data_b64"]
                .as_str()
                .ok_or("fdata")?,
        )?,
        revision: pull_body["folders"][0]["revision"].as_i64().ok_or("frev")?,
        deleted: false,
        updated_at: Utc::now(),
    };
    let dec_folder = decrypt_folder(&subkeys, alice.user_id, &wire_folder)?;
    assert_eq!(dec_folder.name, "Work");

    let (dl_status, dl_headers, dl_bytes) = send_request(
        &app.router,
        Method::GET,
        &format!("/api/v1/vault/blobs/{blob_id}"),
        Some(&access_token),
        None,
        None,
    )
    .await?;
    assert_eq!(dl_status, StatusCode::OK);
    assert!(dl_headers.get(header::ETAG).is_some());
    let dec_blob = decrypt_blob(
        &subkeys,
        alice.user_id,
        &EncryptedBlobRecord {
            id: blob_id,
            item_id: item.id,
            encrypted_blob: dl_bytes,
            revision: 2,
            deleted: false,
            updated_at: Utc::now(),
        },
    )?;
    assert_eq!(&*dec_blob.data, &[0x89, 0x50, 0x4E, 0x47, 1, 2, 3, 4]);

    // Delete item -> verify tombstone appears in incremental sync (`since_revision=1`).
    let (del_status, _, del_body) = send_json(
        &app.router,
        Method::DELETE,
        &format!("/api/v1/vault/items/{}", item.id),
        Some(&access_token),
        None,
    )
    .await?;
    assert_eq!(del_status, StatusCode::OK);
    assert_eq!(del_body["revision"], 3);

    let (_, _, inc_sync) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/vault/sync?since_revision=1",
        Some(&access_token),
        None,
    )
    .await?;
    assert_eq!(inc_sync["items"][0]["deleted"], true);
    assert_eq!(inc_sync["blobs_meta"][0]["deleted"], true);
    Ok(())
}

#[tokio::test]
async fn signup_control_and_invitation_constraints() -> AppResult<()> {
    let app = setup_sqlite_memory(false).await?;

    // Missing invite when signups disabled -> 403.
    let (no_inv_status, _, no_inv_body) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({
            "user_id": Uuid::new_v4(),
            "email": "bob@example.com",
            "kdf_params": fast_client_kdf(),
            "kdf_salt_b64": STANDARD.encode([1u8; 32]),
            "master_auth_hash_b64": STANDARD.encode([2u8; 32]),
            "encrypted_vault_key_b64": STANDARD.encode([0x01u8; 64]),
        })),
    )
    .await?;
    assert_eq!(no_inv_status, StatusCode::FORBIDDEN);
    assert_eq!(no_inv_body["error"]["code"], "SIGNUPS_DISABLED");

    let (expired_tok, expired_hash) = generate_opaque_token()?;
    app.db
        .create_invitation(
            &expired_hash,
            None,
            None,
            1,
            Utc::now() - Duration::minutes(5),
        )
        .await?;

    let (revoked_tok, revoked_hash) = generate_opaque_token()?;
    let rev_inv = app
        .db
        .create_invitation(
            &revoked_hash,
            None,
            None,
            1,
            Utc::now() + Duration::hours(1),
        )
        .await?;
    app.db.revoke_invitation(rev_inv.id).await?;

    let (bob_tok, bob_hash) = generate_opaque_token()?;
    app.db
        .create_invitation(
            &bob_hash,
            Some("bob@example.com"),
            None,
            1,
            Utc::now() + Duration::hours(1),
        )
        .await?;

    for bad_tok in [
        "nonexistent-token",
        expired_tok.as_str(),
        revoked_tok.as_str(),
        bob_tok.as_str(),
    ] {
        let email = if bad_tok == bob_tok.as_str() {
            "eve@example.com"
        } else {
            "bob@example.com"
        };
        let (st, _, b) = send_json(
            &app.router,
            Method::POST,
            "/api/v1/auth/register",
            None,
            Some(json!({
                "user_id": Uuid::new_v4(),
                "email": email,
                "kdf_params": fast_client_kdf(),
                "kdf_salt_b64": STANDARD.encode([1u8; 32]),
                "master_auth_hash_b64": STANDARD.encode([2u8; 32]),
                "encrypted_vault_key_b64": STANDARD.encode([0x01u8; 64]),
                "invite_token": bad_tok,
            })),
        )
        .await?;
        assert_eq!(st, StatusCode::FORBIDDEN);
        assert_eq!(b["error"]["code"], "INVALID_INVITATION");
    }

    // Valid invite still has 1 remaining use because wrong-email attempt failed.
    let _bob = register_zk_account(
        &app.router,
        "bob@example.com",
        "bob-strong-password-42",
        Some(&bob_tok),
    )
    .await?;

    // Reusing exhausted single-use token is rejected.
    let (reuse_status, _, reuse_body) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({
            "user_id": Uuid::new_v4(),
            "email": "carol@example.com",
            "kdf_params": fast_client_kdf(),
            "kdf_salt_b64": STANDARD.encode([1u8; 32]),
            "master_auth_hash_b64": STANDARD.encode([2u8; 32]),
            "encrypted_vault_key_b64": STANDARD.encode([0x01u8; 64]),
            "invite_token": bob_tok.as_str(),
        })),
    )
    .await?;
    assert_eq!(reuse_status, StatusCode::FORBIDDEN);
    assert_eq!(reuse_body["error"]["code"], "INVALID_INVITATION");

    // Open signups reject duplicate emails cleanly with 409 Conflict.
    let open_app = setup_sqlite_memory(true).await?;
    let _u1 =
        register_zk_account(&open_app.router, "dup@example.com", "pw-1234567890", None).await?;
    let (dup_status, _, dup_body) = send_json(
        &open_app.router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({
            "user_id": Uuid::new_v4(),
            "email": "DUP@example.com",
            "kdf_params": fast_client_kdf(),
            "kdf_salt_b64": STANDARD.encode([1u8; 32]),
            "master_auth_hash_b64": STANDARD.encode([2u8; 32]),
            "encrypted_vault_key_b64": STANDARD.encode([0x01u8; 64]),
        })),
    )
    .await?;
    assert_eq!(dup_status, StatusCode::CONFLICT);
    assert_eq!(dup_body["error"]["code"], "EMAIL_ALREADY_REGISTERED");
    Ok(())
}

#[tokio::test]
async fn strict_multi_user_isolation() -> AppResult<()> {
    let app = setup_sqlite_memory(true).await?;
    let alice =
        register_zk_account(&app.router, "alice@example.com", "alice-pw-0001", None).await?;
    let bob = register_zk_account(&app.router, "bob@example.com", "bob-pw-0002", None).await?;

    let subkeys_a = derive_vault_subkeys(&alice.vault_key)?;
    let subkeys_b = derive_vault_subkeys(&bob.vault_key)?;

    let item_a = VaultItem::new_login(
        "Alice Bank",
        LoginData {
            username: "alice_bank".to_owned(),
            email: "alice@example.com".to_owned(),
            password: "bank-secret-password".to_owned(),
            password_history: vec![],
            uris: vec![],
            totp: None,
        },
    );
    let enc_a = encrypt_item(&subkeys_a, alice.user_id, &item_a, 1)?;
    let (c_status, _, _) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/vault/items",
        Some(&alice.access_token),
        Some(json!({
            "id": item_a.id,
            "encrypted_data_b64": STANDARD.encode(&enc_a.encrypted_data)
        })),
    )
    .await?;
    assert_eq!(c_status, StatusCode::CREATED);

    let blob_a_id = Uuid::new_v4();
    let blob_a = VaultBlob {
        id: blob_a_id,
        item_id: item_a.id,
        mime_type: "image/png".to_owned(),
        data: Zeroizing::new(vec![1, 2, 3, 4]),
        updated_at: Utc::now(),
    };
    let enc_blob_a = encrypt_blob(&subkeys_a, alice.user_id, &blob_a, 2)?;
    let (put_a_status, _, _) = send_request(
        &app.router,
        Method::PUT,
        &format!("/api/v1/vault/blobs/{blob_a_id}?item_id={}", item_a.id),
        Some(&alice.access_token),
        Some(enc_blob_a.encrypted_blob.clone()),
        Some("application/octet-stream"),
    )
    .await?;
    assert_eq!(put_a_status, StatusCode::OK);

    let (_, _, alice_sessions) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/sessions",
        Some(&alice.access_token),
        None,
    )
    .await?;
    let alice_session_id = alice_sessions[0]["id"].as_str().ok_or("sid")?.to_owned();

    // Bob sees zero records in his vault sync.
    let (bob_sync_st, _, bob_sync) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/vault/sync?since_revision=0",
        Some(&bob.access_token),
        None,
    )
    .await?;
    assert_eq!(bob_sync_st, StatusCode::OK);
    assert_eq!(bob_sync["items"].as_array().map(Vec::len), Some(0));
    assert_eq!(bob_sync["blobs_meta"].as_array().map(Vec::len), Some(0));

    // Bob cannot update, delete, or read Alice's item, blob, or session.
    let (st, _, _) = send_json(
        &app.router,
        Method::PUT,
        &format!("/api/v1/vault/items/{}", item_a.id),
        Some(&bob.access_token),
        Some(json!({
            "expected_revision": 1,
            "encrypted_data_b64": STANDARD.encode([0x01u8; 64])
        })),
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = send_json(
        &app.router,
        Method::DELETE,
        &format!("/api/v1/vault/items/{}", item_a.id),
        Some(&bob.access_token),
        None,
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = send_request(
        &app.router,
        Method::GET,
        &format!("/api/v1/vault/blobs/{blob_a_id}"),
        Some(&bob.access_token),
        None,
        None,
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = send_request(
        &app.router,
        Method::PUT,
        &format!(
            "/api/v1/vault/blobs/{}?item_id={}",
            Uuid::new_v4(),
            item_a.id
        ),
        Some(&bob.access_token),
        Some(vec![0x01u8; 64]),
        Some("application/octet-stream"),
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = send_json(
        &app.router,
        Method::DELETE,
        &format!("/api/v1/vault/blobs/{blob_a_id}"),
        Some(&bob.access_token),
        None,
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = send_json(
        &app.router,
        Method::DELETE,
        &format!("/api/v1/account/sessions/{alice_session_id}"),
        Some(&bob.access_token),
        None,
    )
    .await?;
    assert_eq!(st, StatusCode::NOT_FOUND);

    let (st, _, _) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/admin/users",
        Some(&bob.access_token),
        None,
    )
    .await?;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // Bob pushing the exact same item UUID only writes under Bob's partition, never overwriting Alice's row.
    let mut bob_clone_item = item_a.clone();
    bob_clone_item.title = "Bob Own Item".to_owned();
    let enc_b = encrypt_item(&subkeys_b, bob.user_id, &bob_clone_item, 1)?;
    let (push_b_st, _, _) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/vault/sync",
        Some(&bob.access_token),
        Some(json!({
            "base_revision": 0,
            "items_upsert": [{
                "id": item_a.id,
                "encrypted_data_b64": STANDARD.encode(&enc_b.encrypted_data)
            }]
        })),
    )
    .await?;
    assert_eq!(push_b_st, StatusCode::OK);

    // Alice's original ciphertext & item are intact.
    let (_, _, alice_sync) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/vault/sync?since_revision=0",
        Some(&alice.access_token),
        None,
    )
    .await?;
    let decrypted = decrypt_item(
        &subkeys_a,
        alice.user_id,
        &EncryptedItemRecord {
            id: item_a.id,
            encrypted_data: STANDARD.decode(
                alice_sync["items"][0]["encrypted_data_b64"]
                    .as_str()
                    .ok_or("data")?,
            )?,
            revision: 1,
            deleted: false,
            updated_at: Utc::now(),
        },
    )?;
    assert_eq!(decrypted.title, "Alice Bank");
    Ok(())
}

#[tokio::test]
async fn refresh_token_rotation_and_replay_revokes_family() -> AppResult<()> {
    let app = setup_sqlite_memory(true).await?;
    let alice =
        register_zk_account(&app.router, "alice@example.com", "alice-pw-0001", None).await?;
    let rt0 = alice.refresh_token.clone();

    let (st1, _, r1) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": rt0 })),
    )
    .await?;
    assert_eq!(st1, StatusCode::OK);
    let rt1 = r1["refresh_token"].as_str().ok_or("rt1")?.to_owned();

    let (st2, _, r2) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": rt1 })),
    )
    .await?;
    assert_eq!(st2, StatusCode::OK);
    let at2 = r2["access_token"].as_str().ok_or("at2")?.to_owned();
    let rt2 = r2["refresh_token"].as_str().ok_or("rt2")?.to_owned();

    let (me_ok, _, _) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&at2),
        None,
    )
    .await?;
    assert_eq!(me_ok, StatusCode::OK);

    // Multi-step replay of already rotated rt0 revokes the entire session family.
    let (replay_st, _, replay_body) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": rt0 })),
    )
    .await?;
    assert_eq!(replay_st, StatusCode::UNAUTHORIZED);
    assert_eq!(replay_body["error"]["code"], "TOKEN_REUSE_DETECTED");

    // Legitimate rt2 and active access token at2 are now permanently revoked.
    let (rt2_st, _, _) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": rt2 })),
    )
    .await?;
    assert_eq!(rt2_st, StatusCode::UNAUTHORIZED);

    let (at2_st, _, at2_body) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&at2),
        None,
    )
    .await?;
    assert_eq!(at2_st, StatusCode::UNAUTHORIZED);
    assert_eq!(at2_body["error"]["code"], "SESSION_REVOKED");

    // Explicit logout revokes current session immediately.
    let (at_fresh, _, _, _) =
        login_zk_account(&app.router, "alice@example.com", "alice-pw-0001", "CLI").await?;
    let (lo_st, _, _) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/logout",
        Some(&at_fresh),
        None,
    )
    .await?;
    assert_eq!(lo_st, StatusCode::NO_CONTENT);

    let (after_lo_st, _, _) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&at_fresh),
        None,
    )
    .await?;
    assert_eq!(after_lo_st, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn optimistic_concurrency_returns_409_conflict_without_overwriting() -> AppResult<()> {
    let app = setup_sqlite_memory(true).await?;
    let alice =
        register_zk_account(&app.router, "alice@example.com", "alice-pw-0001", None).await?;
    let subkeys = derive_vault_subkeys(&alice.vault_key)?;

    let item1 = VaultItem::new_login(
        "Item 1",
        LoginData {
            username: "u1".to_owned(),
            email: "".to_owned(),
            password: "p1".to_owned(),
            password_history: vec![],
            uris: vec![],
            totp: None,
        },
    );
    let enc1 = encrypt_item(&subkeys, alice.user_id, &item1, 1)?;

    let (st1, _, _) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/vault/sync",
        Some(&alice.access_token),
        Some(json!({
            "base_revision": 0,
            "items_upsert": [{
                "id": item1.id,
                "encrypted_data_b64": STANDARD.encode(&enc1.encrypted_data)
            }]
        })),
    )
    .await?;
    assert_eq!(st1, StatusCode::OK);

    // Stale base_revision=0 returns 409 Conflict with server delta.
    let item2 = VaultItem::new_login(
        "Stale Item 2",
        LoginData {
            username: "u2".to_owned(),
            email: "".to_owned(),
            password: "p2".to_owned(),
            password_history: vec![],
            uris: vec![],
            totp: None,
        },
    );
    let enc2 = encrypt_item(&subkeys, alice.user_id, &item2, 1)?;
    let (conflict_st, _, conflict_body) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/vault/sync",
        Some(&alice.access_token),
        Some(json!({
            "base_revision": 0,
            "items_upsert": [{
                "id": item2.id,
                "encrypted_data_b64": STANDARD.encode(&enc2.encrypted_data)
            }]
        })),
    )
    .await?;
    assert_eq!(conflict_st, StatusCode::CONFLICT);
    assert_eq!(conflict_body["error"]["code"], "SYNC_REVISION_CONFLICT");
    assert_eq!(conflict_body["sync"]["current_revision"], 1);
    assert_eq!(
        conflict_body["sync"]["items"][0]["id"].as_str(),
        Some(item1.id.hyphenated().to_string().as_str())
    );

    // Item-level PUT conflict check.
    let (put_conflict_st, _, put_conflict_body) = send_json(
        &app.router,
        Method::PUT,
        &format!("/api/v1/vault/items/{}", item1.id),
        Some(&alice.access_token),
        Some(json!({
            "expected_revision": 99,
            "encrypted_data_b64": STANDARD.encode(&enc2.encrypted_data)
        })),
    )
    .await?;
    assert_eq!(put_conflict_st, StatusCode::CONFLICT);
    assert_eq!(put_conflict_body["error"]["code"], "ITEM_REVISION_CONFLICT");
    assert_eq!(put_conflict_body["current_item"]["revision"], 1);
    Ok(())
}

#[tokio::test]
async fn atomic_password_rotation_and_account_deletion() -> AppResult<()> {
    let app = setup_sqlite_memory(true).await?;
    let alice =
        register_zk_account(&app.router, "alice@example.com", "old-master-pw-1", None).await?;
    let (other_at, other_rt, _, _) =
        login_zk_account(&app.router, &alice.email, &alice.password, "Phone").await?;

    let subkeys = derive_vault_subkeys(&alice.vault_key)?;
    let secret_item = VaultItem::new_secure_note("Recovery Key", "vault-key-must-survive-rotation");
    let enc_item = encrypt_item(&subkeys, alice.user_id, &secret_item, 1)?;
    let (c_st, _, _) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/vault/items",
        Some(&alice.access_token),
        Some(json!({
            "id": secret_item.id,
            "encrypted_data_b64": STANDARD.encode(&enc_item.encrypted_data)
        })),
    )
    .await?;
    assert_eq!(c_st, StatusCode::CREATED);

    // Client computes new KDF + wraps the SAME VaultKey under new key_version=2.
    let new_pw_str = "new-stronger-master-pw-2";
    let mut new_salt = [0u8; 32];
    anvil_core::crypto::fill_random_bytes(&mut new_salt)?;
    let new_pw = MasterPassword::new(new_pw_str);
    let new_mk = derive_master_key(&new_pw, &new_salt, &alice.kdf_params)?;
    let (new_mek, new_auth_hash) = derive_master_subkeys(&new_mk, &new_salt)?;
    let new_wrapped_vk = wrap_vault_key(&new_mek, &alice.vault_key, alice.user_id, 2)?;

    let (rot_st, _, rot_body) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/account/rotate-password",
        Some(&alice.access_token),
        Some(json!({
            "current_master_auth_hash_b64": STANDARD.encode(alice.master_auth_hash),
            "new_master_auth_hash_b64": STANDARD.encode(new_auth_hash.as_bytes()),
            "new_kdf_salt_b64": STANDARD.encode(new_salt),
            "new_kdf_params": alice.kdf_params,
            "new_key_version": 2,
            "new_encrypted_vault_key_b64": STANDARD.encode(&new_wrapped_vk),
            "revoke_other_sessions": true
        })),
    )
    .await?;
    assert_eq!(rot_st, StatusCode::OK);
    assert_eq!(rot_body["key_version"], 2);

    // Other session is immediately revoked, while current session stays active.
    let (other_me_st, _, _) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&other_at),
        None,
    )
    .await?;
    assert_eq!(other_me_st, StatusCode::UNAUTHORIZED);
    let (other_rf_st, _, _) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/auth/refresh",
        None,
        Some(json!({ "refresh_token": other_rt })),
    )
    .await?;
    assert_eq!(other_rf_st, StatusCode::UNAUTHORIZED);

    let (cur_me_st, _, cur_me) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&alice.access_token),
        None,
    )
    .await?;
    assert_eq!(cur_me_st, StatusCode::OK);
    assert_eq!(cur_me["key_version"], 2);

    // Old password login rejected, new password unwraps VaultKey and decrypts existing note.
    assert!(
        login_zk_account(&app.router, &alice.email, &alice.password, "Bad")
            .await
            .is_err()
    );
    let (new_at, _, new_vk, new_ver) =
        login_zk_account(&app.router, &alice.email, new_pw_str, "Desktop-2").await?;
    assert_eq!(new_ver, 2);
    assert_eq!(new_vk, alice.vault_key);

    // Account deletion requires valid current MasterAuthHash.
    let (bad_del_st, _, _) = send_json(
        &app.router,
        Method::DELETE,
        "/api/v1/account/me",
        Some(&new_at),
        Some(json!({
            "current_master_auth_hash_b64": STANDARD.encode(alice.master_auth_hash)
        })),
    )
    .await?;
    assert_eq!(bad_del_st, StatusCode::UNAUTHORIZED);

    let (ok_del_st, _, _) = send_json(
        &app.router,
        Method::DELETE,
        "/api/v1/account/me",
        Some(&new_at),
        Some(json!({
            "current_master_auth_hash_b64": STANDARD.encode(new_auth_hash.as_bytes())
        })),
    )
    .await?;
    assert_eq!(ok_del_st, StatusCode::NO_CONTENT);

    let (gone_st, _, _) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&new_at),
        None,
    )
    .await?;
    assert_eq!(gone_st, StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn admin_endpoints_last_admin_guard_and_ssrf() -> AppResult<()> {
    let app = setup_app("sqlite::memory:", true, true, false, None, None).await?;

    let alice =
        register_zk_account(&app.router, "alice@example.com", "alice-pw-0001", None).await?;
    let bob = register_zk_account(&app.router, "bob@example.com", "bob-pw-0002", None).await?;

    app.db
        .update_user_admin(UpdateUserAdminInput {
            target_user_id: alice.user_id,
            is_active: None,
            role: Some(UserRole::Admin),
        })
        .await?;

    // Last active admin cannot demote or deactivate themselves.
    let (demote_last_st, _, demote_last_body) = send_json(
        &app.router,
        Method::PATCH,
        &format!("/api/v1/admin/users/{}", alice.user_id),
        Some(&alice.access_token),
        Some(json!({ "role": "user" })),
    )
    .await?;
    assert_eq!(demote_last_st, StatusCode::CONFLICT);
    assert_eq!(demote_last_body["error"]["code"], "LAST_ADMIN_PROTECTED");

    let (disable_last_st, _, _) = send_json(
        &app.router,
        Method::PATCH,
        &format!("/api/v1/admin/users/{}", alice.user_id),
        Some(&alice.access_token),
        Some(json!({ "is_active": false })),
    )
    .await?;
    assert_eq!(disable_last_st, StatusCode::CONFLICT);

    // Admin creates, lists, and revokes invitation via REST.
    let (inv_st, _, inv_body) = send_json(
        &app.router,
        Method::POST,
        "/api/v1/admin/invitations",
        Some(&alice.access_token),
        Some(json!({
            "invited_email": "guest@example.com",
            "max_uses": 2,
            "expires_in_hours": 48
        })),
    )
    .await?;
    assert_eq!(inv_st, StatusCode::CREATED);
    let inv_id = inv_body["id"].as_str().ok_or("inv_id")?;

    let (list_inv_st, _, list_inv_body) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/admin/invitations",
        Some(&alice.access_token),
        None,
    )
    .await?;
    assert_eq!(list_inv_st, StatusCode::OK);
    assert_eq!(list_inv_body.as_array().map(Vec::len), Some(1));

    let (rev_inv_st, _, _) = send_json(
        &app.router,
        Method::DELETE,
        &format!("/api/v1/admin/invitations/{inv_id}"),
        Some(&alice.access_token),
        None,
    )
    .await?;
    assert_eq!(rev_inv_st, StatusCode::NO_CONTENT);

    // Disable Bob -> Bob's active sessions are immediately invalidated.
    let (dis_bob_st, _, dis_bob_body) = send_json(
        &app.router,
        Method::PATCH,
        &format!("/api/v1/admin/users/{}", bob.user_id),
        Some(&alice.access_token),
        Some(json!({ "is_active": false })),
    )
    .await?;
    assert_eq!(dis_bob_st, StatusCode::OK);
    assert_eq!(dis_bob_body["is_active"], false);

    let (bob_after_st, _, _) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&bob.access_token),
        None,
    )
    .await?;
    assert_eq!(bob_after_st, StatusCode::UNAUTHORIZED);

    // Favicon SSRF protection blocks internal hostnames and IP literals.
    for blocked_domain in ["localhost", "127.0.0.1", "169.254.169.254", "db.internal"] {
        let (fav_st, _, fav_body) = send_json(
            &app.router,
            Method::GET,
            &format!("/api/v1/utils/favicon?domain={blocked_domain}"),
            Some(&alice.access_token),
            None,
        )
        .await?;
        assert_eq!(fav_st, StatusCode::BAD_REQUEST);
        assert_eq!(fav_body["error"]["code"], "SSRF_BLOCKED");
    }

    // Disabled favicon proxy returns 404 even when queried with a valid domain.
    let no_fav_app = setup_sqlite_memory(true).await?;
    let u_no_fav =
        register_zk_account(&no_fav_app.router, "u@example.com", "pw-1234567890", None).await?;
    let (fav_disabled_st, _, _) = send_json(
        &no_fav_app.router,
        Method::GET,
        "/api/v1/utils/favicon?domain=github.com",
        Some(&u_no_fav.access_token),
        None,
    )
    .await?;
    assert_eq!(fav_disabled_st, StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn rate_limiting_and_trusted_proxies() -> AppResult<()> {
    let app = setup_app(
        "sqlite::memory:",
        true,
        false,
        true,
        Some("127.0.0.1/32"),
        None,
    )
    .await?;

    // Rate limiting ignores spoofed X-Forwarded-For from untrusted peer (burst=5 on /register).
    for i in 0..5 {
        let spoofed_xff = format!("198.51.100.{}", i + 10);
        let (st, _, _) = send_from_ip(
            &app.router,
            "/api/v1/auth/register",
            b"{}".to_vec(),
            &[("x-forwarded-for", &spoofed_xff)],
            "198.51.100.1",
        )
        .await?;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    let (rl_untrusted_st, _, rl_untrusted_bytes) = send_from_ip(
        &app.router,
        "/api/v1/auth/register",
        b"{}".to_vec(),
        &[("x-forwarded-for", "203.0.113.200")],
        "198.51.100.1",
    )
    .await?;
    assert_eq!(rl_untrusted_st, StatusCode::TOO_MANY_REQUESTS);
    let rl_json: Value = serde_json::from_slice(&rl_untrusted_bytes)?;
    assert_eq!(rl_json["error"]["code"], "RATE_LIMITED");
    assert!(
        !rl_json["error"]["request_id"]
            .as_str()
            .unwrap_or_default()
            .is_empty()
    );

    // Requests arriving from trusted proxy `127.0.0.1` are keyed per real X-Forwarded-For client IP.
    for i in 0..6 {
        let client_xff = format!("203.0.113.{}", i + 1);
        let (st, _, _) = send_from_ip(
            &app.router,
            "/api/v1/auth/register",
            b"{}".to_vec(),
            &[("x-forwarded-for", &client_xff)],
            "127.0.0.1",
        )
        .await?;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    // Repeating requests for the same forwarded client IP `203.0.113.1` consumes its remaining burst (4 left) and triggers 429.
    for _ in 0..4 {
        let (st, _, _) = send_from_ip(
            &app.router,
            "/api/v1/auth/register",
            b"{}".to_vec(),
            &[("x-forwarded-for", "203.0.113.1")],
            "127.0.0.1",
        )
        .await?;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }
    let (same_client_rl, _, _) = send_from_ip(
        &app.router,
        "/api/v1/auth/register",
        b"{}".to_vec(),
        &[("x-forwarded-for", "203.0.113.1")],
        "127.0.0.1",
    )
    .await?;
    assert_eq!(same_client_rl, StatusCode::TOO_MANY_REQUESTS);
    Ok(())
}

#[tokio::test]
async fn optional_postgres_integration_suite() -> AppResult<()> {
    let Ok(pg_url) = std::env::var("ANVIL_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let app = setup_app(&pg_url, true, false, false, None, None).await?;
    let alice = register_zk_account(
        &app.router,
        &format!("pg-alice-{}@example.com", Uuid::new_v4()),
        "pg-test-password-42",
        None,
    )
    .await?;
    let (st, _, me) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&alice.access_token),
        None,
    )
    .await?;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(me["user_id"], alice.user_id.hyphenated().to_string());
    Ok(())
}

#[tokio::test]
async fn account_email_change_and_avatar_security_validation() -> AppResult<()> {
    let app = setup_sqlite_memory(true).await?;
    let alice =
        register_zk_account(&app.router, "alice@example.com", "alice-pw-9999", None).await?;
    let _bob = register_zk_account(&app.router, "bob@example.com", "bob-pw-9999", None).await?;

    // Wrong password rejected for email change.
    let (bad_pw_st, _, _) = send_json(
        &app.router,
        Method::PATCH,
        "/api/v1/account/email",
        Some(&alice.access_token),
        Some(json!({
            "current_master_auth_hash_b64": STANDARD.encode([0u8; 32]),
            "new_email": "alice-new@example.com"
        })),
    )
    .await?;
    assert_eq!(bad_pw_st, StatusCode::UNAUTHORIZED);

    // Duplicate email rejected with 409 Conflict.
    let (dup_st, _, dup_body) = send_json(
        &app.router,
        Method::PATCH,
        "/api/v1/account/email",
        Some(&alice.access_token),
        Some(json!({
            "current_master_auth_hash_b64": STANDARD.encode(alice.master_auth_hash),
            "new_email": "BOB@example.com"
        })),
    )
    .await?;
    assert_eq!(dup_st, StatusCode::CONFLICT);
    assert_eq!(dup_body["error"]["code"], "EMAIL_ALREADY_REGISTERED");

    // Valid email change updates /account/me and allows login with the new email + same MasterPassword.
    let (ok_email_st, _, ok_email_body) = send_json(
        &app.router,
        Method::PATCH,
        "/api/v1/account/email",
        Some(&alice.access_token),
        Some(json!({
            "current_master_auth_hash_b64": STANDARD.encode(alice.master_auth_hash),
            "new_email": "Alice.Updated@Example.com"
        })),
    )
    .await?;
    assert_eq!(ok_email_st, StatusCode::OK);
    assert_eq!(ok_email_body["email"], "alice.updated@example.com");

    let (_, _, logged_vk, _) = login_zk_account(
        &app.router,
        "alice.updated@example.com",
        "alice-pw-9999",
        "Workstation",
    )
    .await?;
    assert_eq!(logged_vk, alice.vault_key);

    // Malicious SVG/HTML rejected on avatar upload.
    let (svg_st, _, svg_body) = send_json(
        &app.router,
        Method::PUT,
        "/api/v1/account/avatar",
        Some(&alice.access_token),
        Some(json!({
            "image_b64": STANDARD.encode(b"<svg onload=\"alert(1)\"><script>1</script></svg>")
        })),
    )
    .await?;
    assert_eq!(svg_st, StatusCode::BAD_REQUEST);
    assert_eq!(svg_body["error"]["code"], "INVALID_IMAGE");

    // Valid PNG image accepted, resized/sanitized, and exposed on /account/me.
    let raw_img = {
        let img = image::RgbaImage::from_fn(32, 24, |x, y| {
            image::Rgba([(x * 5) as u8, (y * 8) as u8, 250, 255])
        });
        let mut buf = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(img).write_to(&mut buf, image::ImageFormat::Png)?;
        buf.into_inner()
    };
    let (put_av_st, _, put_av_body) = send_json(
        &app.router,
        Method::PUT,
        "/api/v1/account/avatar",
        Some(&alice.access_token),
        Some(json!({ "image_b64": STANDARD.encode(&raw_img) })),
    )
    .await?;
    assert_eq!(put_av_st, StatusCode::OK);
    let returned_b64 = put_av_body["avatar_b64"].as_str().ok_or("avatar_b64")?;
    let returned_png = STANDARD.decode(returned_b64)?;
    assert!(returned_png.starts_with(b"\x89PNG\r\n\x1a\n"));

    let (me_av_st, _, me_av_body) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&alice.access_token),
        None,
    )
    .await?;
    assert_eq!(me_av_st, StatusCode::OK);
    assert_eq!(me_av_body["avatar_b64"], returned_b64);

    // Deleting avatar clears it from /account/me.
    let (del_av_st, _, _) = send_json(
        &app.router,
        Method::DELETE,
        "/api/v1/account/avatar",
        Some(&alice.access_token),
        None,
    )
    .await?;
    assert_eq!(del_av_st, StatusCode::NO_CONTENT);

    let (me_cleared_st, _, me_cleared_body) = send_json(
        &app.router,
        Method::GET,
        "/api/v1/account/me",
        Some(&alice.access_token),
        None,
    )
    .await?;
    assert_eq!(me_cleared_st, StatusCode::OK);
    assert!(me_cleared_body["avatar_b64"].is_null());
    Ok(())
}
