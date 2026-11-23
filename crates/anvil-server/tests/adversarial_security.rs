//! Adversarial HTTP security checks: SQL injection, SSRF filters, security headers, and log redaction.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;
use zeroize::Zeroizing;

use anvil_server::auth::jwt::JwtManager;
use anvil_server::auth::password::ServerAuthHasher;
use anvil_server::config::{LogFormat, ServerConfig};
use anvil_server::db::DbPool;
use anvil_server::routes::build_router;
use anvil_server::state::AppState;

type AppResult<T> = Result<T, Box<dyn std::error::Error>>;

async fn spawn_adversarial_router(
    enable_favicon_proxy: bool,
    allow_signups: bool,
) -> AppResult<(Router, DbPool)> {
    let db = DbPool::connect("sqlite::memory:").await?;
    db.migrate().await?;

    let jwt_pem = JwtManager::generate_private_key_pem()?;
    let jwt = JwtManager::from_private_key_str(&jwt_pem)?;
    let config = ServerConfig {
        database_url: "sqlite::memory:".to_owned(),
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        allow_signups,
        jwt_private_key: jwt_pem,
        auth_pepper: Some(Zeroizing::new(b"adversarial-pepper-secret-012345".to_vec())),
        prelogin_secret: Zeroizing::new(b"adversarial-prelogin-secret-6789".to_vec()),
        trusted_proxies: Vec::new(),
        cors_origins: Vec::new(),
        enable_favicon_proxy,
        public_url: None,
        log_format: LogFormat::Json,
    };

    let hasher = ServerAuthHasher::with_params(1_024, 1, 1, config.auth_pepper.clone());
    let state = AppState {
        db: db.clone(),
        config: Arc::new(config),
        jwt: Arc::new(jwt),
        hasher: Arc::new(hasher),
        rate_limit_enabled: false,
    };
    Ok((build_router(state), db))
}

async fn send_json(
    router: &Router,
    method: Method,
    uri: &str,
    bearer_token: Option<&str>,
    payload: Option<Value>,
) -> AppResult<(StatusCode, axum::http::HeaderMap, String)> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(tok) = bearer_token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let body = match payload {
        Some(v) => Body::from(serde_json::to_vec(&v)?),
        None => {
            builder = builder.header(header::CONTENT_LENGTH, "0");
            Body::empty()
        }
    };
    let mut req = builder.body(body)?;
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        IpAddr::from([203, 0, 113, 42]),
        40_000,
    )));
    let resp = router.clone().oneshot(req).await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, headers, String::from_utf8_lossy(&bytes).to_string()))
}

#[tokio::test]
async fn sql_injection_payloads_never_bypass_auth_or_corrupt_schema() -> AppResult<()> {
    let (router, _db) = spawn_adversarial_router(false, false).await?;

    let sqli_emails = [
        "' OR '1'='1",
        "admin@example.com' OR 1=1 --",
        "\"; DROP TABLE users; --",
        "alice@example.com\0injected",
    ];

    for payload in sqli_emails {
        let (st_pre, headers, _) = send_json(
            &router,
            Method::POST,
            "/api/v1/auth/prelogin",
            None,
            Some(json!({ "email": payload })),
        )
        .await?;
        assert!(
            st_pre == StatusCode::OK || st_pre == StatusCode::BAD_REQUEST,
            "unexpected prelogin status {st_pre}"
        );
        assert_eq!(
            headers
                .get(header::X_FRAME_OPTIONS)
                .and_then(|v| v.to_str().ok()),
            Some("DENY")
        );

        let (st_login, _, _) = send_json(
            &router,
            Method::POST,
            "/api/v1/auth/login",
            None,
            Some(json!({
                "email": payload,
                "master_auth_hash_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "device_name": "EvilDevice",
                "device_platform": "unknown"
            })),
        )
        .await?;
        assert!(
            st_login == StatusCode::UNAUTHORIZED || st_login == StatusCode::BAD_REQUEST,
            "SQLi payload must not authenticate: {st_login}"
        );
    }

    // Healthcheck still reports clean schema & intact DB.
    let (st_health, headers, body) =
        send_json(&router, Method::GET, "/api/v1/health", None, None).await?;
    assert_eq!(st_health, StatusCode::OK);
    assert!(body.contains("\"db_ok\":true"));
    assert_eq!(
        headers
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        headers
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("default-src 'none'; frame-ancestors 'none'")
    );

    Ok(())
}

#[tokio::test]
async fn ssrf_matrix_and_config_redaction_are_enforced() -> AppResult<()> {
    let (router, _) = spawn_adversarial_router(true, true).await?;

    let (reg_status, _, reg_body) = send_json(
        &router,
        Method::POST,
        "/api/v1/auth/register",
        None,
        Some(json!({
            "user_id": uuid::Uuid::new_v4(),
            "email": "ssrf-tester@example.com",
            "kdf_params": {
                "algorithm": "argon2id",
                "memory_kib": 19_456,
                "iterations": 2,
                "parallelism": 1
            },
            "kdf_salt_b64": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
            "master_auth_hash_b64": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
            "encrypted_vault_key_b64": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "device_name": "Tester",
            "device_platform": "linux"
        })),
    )
    .await?;
    assert_eq!(
        reg_status,
        StatusCode::CREATED,
        "register failed: {reg_body}"
    );
    let reg_json: Value = serde_json::from_str(&reg_body)?;
    let token = reg_json["access_token"]
        .as_str()
        .ok_or("missing access_token")?;

    let ssrf_targets = [
        "127.0.0.1",
        "localhost",
        "169.254.169.254",
        "10.0.0.1",
        "192.168.1.1",
        "100.64.0.1",
        "http://127.0.0.1:8080/api/v1/health",
        "file:///etc/passwd",
        "[::1]",
    ];

    for target in ssrf_targets {
        let uri = format!("/api/v1/utils/favicon?domain={target}");
        let (status, _, _) = send_json(&router, Method::GET, &uri, Some(token), None).await?;
        assert!(
            status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
            "SSRF target `{target}` returned unexpected status {status}"
        );
    }

    let cfg = ServerConfig {
        database_url: "postgres://anvil:SuperSecretDbPass!99@postgres:5432/anvil".to_owned(),
        bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
        allow_signups: false,
        jwt_private_key: Zeroizing::new("PRIVATE_PEM_SECRET_MARKER".to_owned()),
        auth_pepper: Some(Zeroizing::new(b"AUTH_PEPPER_SECRET_MARKER".to_vec())),
        prelogin_secret: Zeroizing::new(b"PRELOGIN_SECRET_MARKER".to_vec()),
        trusted_proxies: Vec::new(),
        cors_origins: Vec::new(),
        enable_favicon_proxy: false,
        public_url: None,
        log_format: LogFormat::Json,
    };

    let dbg = format!("{cfg:?}");
    assert!(!dbg.contains("SuperSecretDbPass!99"));
    assert!(!dbg.contains("PRIVATE_PEM_SECRET_MARKER"));
    assert!(!dbg.contains("AUTH_PEPPER_SECRET_MARKER"));
    assert!(!dbg.contains("PRELOGIN_SECRET_MARKER"));

    Ok(())
}
