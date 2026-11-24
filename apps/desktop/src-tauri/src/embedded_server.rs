//! Embedded loopback Anvil server lifecycle and persisted instance keypair storage.

#![forbid(unsafe_code)]

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anvil_core::crypto::fill_random_bytes;
use anvil_server::auth::jwt::JwtManager;
use anvil_server::auth::password::ServerAuthHasher;
use anvil_server::config::{LogFormat, ServerConfig};
use anvil_server::db::{DbError, DbPool};
use anvil_server::routes::build_router;
use anvil_server::state::AppState;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

pub const DEFAULT_EMBEDDED_SERVER_PORT: u16 = 18420;

#[derive(Debug, Error)]
pub enum EmbeddedServerError {
    #[error("embedded server I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("embedded server database error: {0}")]
    Db(#[from] DbError),
    #[error("embedded server configuration error: {0}")]
    Config(String),
    #[error("key serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct PersistedServerSecrets {
    jwt_private_key: String,
    prelogin_secret_hex: String,
    auth_pepper_hex: String,
}

/// Running handle for the embedded local `anvil-server` instance.
pub struct EmbeddedServerHandle {
    pub url: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl EmbeddedServerHandle {
    /// Signals graceful HTTP shutdown and waits for the server task to exit.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

fn load_or_generate_secrets(path: &Path) -> Result<PersistedServerSecrets, EmbeddedServerError> {
    if path.exists() {
        let raw = fs::read_to_string(path)?;
        return Ok(serde_json::from_str(&raw)?);
    }

    let jwt_private_key = JwtManager::generate_private_key_pem()
        .map_err(|err| EmbeddedServerError::Config(err.to_string()))?;

    let mut prelogin = [0u8; 32];
    fill_random_bytes(&mut prelogin)
        .map_err(|err| EmbeddedServerError::Config(format!("csprng failed: {err}")))?;
    let mut pepper = [0u8; 32];
    fill_random_bytes(&mut pepper)
        .map_err(|err| EmbeddedServerError::Config(format!("csprng failed: {err}")))?;

    let secrets = PersistedServerSecrets {
        jwt_private_key: (*jwt_private_key).clone(),
        prelogin_secret_hex: encode_hex(&prelogin),
        auth_pepper_hex: encode_hex(&pepper),
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let encoded = serde_json::to_string_pretty(&secrets)?;
    fs::write(path, encoded)?;
    Ok(secrets)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex(raw: &str) -> Result<Vec<u8>, EmbeddedServerError> {
    let trimmed = raw.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(EmbeddedServerError::Config(
            "invalid hex length in server_keys.json".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, EmbeddedServerError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(EmbeddedServerError::Config(
            "invalid hex character in server_keys.json".to_owned(),
        )),
    }
}

fn sqlite_url(path: &Path) -> String {
    format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"))
}

/// Starts an isolated loopback zero-knowledge `anvil-server` backed by SQLite inside `data_dir`.
pub async fn start_embedded_server(
    data_dir: &Path,
    preferred_port: u16,
) -> Result<EmbeddedServerHandle, EmbeddedServerError> {
    fs::create_dir_all(data_dir)?;

    let secrets = load_or_generate_secrets(&data_dir.join("server_keys.json"))?;
    let prelogin_secret = Zeroizing::new(decode_hex(&secrets.prelogin_secret_hex)?);
    let auth_pepper = Zeroizing::new(decode_hex(&secrets.auth_pepper_hex)?);
    let jwt_private_key = Zeroizing::new(secrets.jwt_private_key);

    let db_path = data_dir.join("vault_server.db");
    let db_url = sqlite_url(&db_path);
    let db = DbPool::connect(&db_url).await?;
    db.migrate().await?;

    let jwt = JwtManager::from_private_key_str(&jwt_private_key)
        .map_err(|err| EmbeddedServerError::Config(err.to_string()))?;
    let hasher = ServerAuthHasher::new(Some(auth_pepper.clone()));

    let preferred_addr = SocketAddr::from(([127, 0, 0, 1], preferred_port));
    let listener = match TcpListener::bind(preferred_addr).await {
        Ok(l) => l,
        Err(_) => TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?,
    };
    let local_addr = listener.local_addr()?;

    let config = ServerConfig {
        database_url: db_url,
        bind_addr: local_addr,
        allow_signups: true,
        jwt_private_key,
        auth_pepper: Some(auth_pepper),
        prelogin_secret,
        trusted_proxies: Vec::new(),
        cors_origins: Vec::new(),
        enable_favicon_proxy: false,
        public_url: None,
        log_format: LogFormat::Pretty,
    };

    let state = AppState {
        db,
        config: Arc::new(config),
        jwt: Arc::new(jwt),
        hasher: Arc::new(hasher),
        rate_limit_enabled: false,
    };

    let router = build_router(state);
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    Ok(EmbeddedServerHandle {
        url: format!("http://127.0.0.1:{}", local_addr.port()),
        shutdown_tx: Some(shutdown_tx),
        task,
    })
}
