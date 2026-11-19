//! Anvil self-hosted zero-knowledge vault server and admin CLI.
#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anvil_core::crypto::fill_random_bytes;
use anyhow::Context;
use chrono::{Duration as ChronoDuration, Utc};
use clap::{Args, Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

use anvil_server::auth::jwt::JwtManager;
use anvil_server::auth::password::{ServerAuthHasher, generate_opaque_token, normalize_email};
use anvil_server::config::{DatabaseConfig, LogFormat, ServerConfig};
use anvil_server::db::{
    DbPool, UpdateUserAdminInput, UpdateUserAdminOutcome, UserRole, VaultRepository,
};
use anvil_server::routes::build_router;
use anvil_server::state::AppState;

#[derive(Debug, Parser)]
#[command(
    name = "anvil-server",
    version,
    about = "Anvil self-hosted vault server and admin CLI"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Starts the HTTP API server.
    Serve(ServeArgs),
    /// Applies pending SQL schema migrations.
    Migrate,
    /// Generates fresh Ed25519 JWT and HMAC secrets for instance configuration.
    Keygen,
    /// Checks local or remote `/api/v1/health` readiness without external tools.
    Healthcheck(HealthcheckArgs),
    /// Manages registration invitations.
    Invite {
        #[command(subcommand)]
        action: InviteCommand,
    },
    /// Manages registered user accounts.
    User {
        #[command(subcommand)]
        action: UserCommand,
    },
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// Skips running pending database migrations at startup.
    #[arg(long)]
    no_migrate: bool,
}

#[derive(Debug, Args)]
struct HealthcheckArgs {
    /// Plain HTTP health endpoint URL.
    #[arg(long, default_value = "http://127.0.0.1:8080/api/v1/health")]
    url: String,
}

#[derive(Debug, Subcommand)]
enum InviteCommand {
    /// Generates a new invitation token and prints it once.
    Create {
        #[arg(long)]
        email: Option<String>,
        #[arg(long, default_value_t = 1)]
        max_uses: i32,
        #[arg(long, default_value_t = 72)]
        expires_hours: i64,
    },
    /// Lists all invitations.
    List,
    /// Revokes an active invitation by UUID.
    Revoke { id: Uuid },
}

#[derive(Debug, Subcommand)]
enum UserCommand {
    /// Lists all user accounts without exposing vault records.
    List,
    /// Disables a user account and revokes all active sessions.
    Disable { identifier: String },
    /// Re-enables a previously disabled user account.
    Enable { identifier: String },
    /// Grants `admin` role to a user account.
    Promote { identifier: String },
    /// Demotes an `admin` account back to `user` (protects last active admin).
    Demote { identifier: String },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run_command(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run_command(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Keygen => cmd_keygen(),
        Command::Healthcheck(args) => cmd_healthcheck(&args.url),
        Command::Serve(args) => {
            let config = ServerConfig::from_env().context("failed to load server configuration")?;
            init_tracing(config.log_format);
            cmd_serve(config, !args.no_migrate).await
        }
        Command::Migrate => {
            let db_cfg = DatabaseConfig::from_env().context("failed to load ANVIL_DATABASE_URL")?;
            init_tracing(db_cfg.log_format);
            let db = DbPool::connect(&db_cfg.database_url).await?;
            db.migrate().await?;
            tracing::info!("database migrations applied");
            Ok(())
        }
        Command::Invite { action } => {
            let db_cfg = DatabaseConfig::from_env().context("failed to load ANVIL_DATABASE_URL")?;
            init_tracing(db_cfg.log_format);
            let db = DbPool::connect(&db_cfg.database_url).await?;
            db.migrate().await?;
            cmd_invite(&db, action).await
        }
        Command::User { action } => {
            let db_cfg = DatabaseConfig::from_env().context("failed to load ANVIL_DATABASE_URL")?;
            init_tracing(db_cfg.log_format);
            let db = DbPool::connect(&db_cfg.database_url).await?;
            db.migrate().await?;
            cmd_user(&db, action).await
        }
    }
}

fn init_tracing(format: LogFormat) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("anvil_server=info,tower_http=info"));
    match format {
        LogFormat::Pretty => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .try_init();
        }
        LogFormat::Json => {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .json()
                .try_init();
        }
    }
}

async fn cmd_serve(config: ServerConfig, run_migrations: bool) -> anyhow::Result<()> {
    let db = DbPool::connect(&config.database_url).await?;
    if run_migrations {
        db.migrate().await?;
    }

    let jwt = JwtManager::from_private_key_str(&config.jwt_private_key)?;
    let hasher = ServerAuthHasher::new(config.auth_pepper.clone());
    let bind_addr = config.bind_addr;

    let state = AppState {
        db,
        config: Arc::new(config),
        jwt: Arc::new(jwt),
        hasher: Arc::new(hasher),
        rate_limit_enabled: true,
    };

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;
    tracing::info!(%bind_addr, "anvil-server listening");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("server exited with error")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        } else {
            std::future::pending::<()>().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}

fn cmd_keygen() -> anyhow::Result<()> {
    let pem = JwtManager::generate_private_key_pem()?;
    let inline_pem = pem.trim_end().replace('\n', "\\n");

    let mut prelogin = [0u8; 32];
    fill_random_bytes(&mut prelogin).map_err(|e| anyhow::anyhow!("csprng failed: {e}"))?;
    let mut pepper = [0u8; 32];
    fill_random_bytes(&mut pepper).map_err(|e| anyhow::anyhow!("csprng failed: {e}"))?;

    println!("ANVIL_JWT_PRIVATE_KEY=\"{inline_pem}\"");
    println!("ANVIL_PRELOGIN_SECRET=hex:{}", encode_hex(&prelogin));
    println!("ANVIL_AUTH_PEPPER=hex:{}", encode_hex(&pepper));
    Ok(())
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

fn cmd_healthcheck(url: &str) -> anyhow::Result<()> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("healthcheck supports plain `http://` URLs only"))?;

    let (authority, path) = match rest.split_once('/') {
        Some((auth, p)) => (auth, format!("/{p}")),
        None => (rest, "/".to_owned()),
    };

    let host_port = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };

    let addr = host_port
        .to_socket_addrs()
        .context("failed to resolve healthcheck host")?
        .next()
        .ok_or_else(|| anyhow::anyhow!("no socket addresses resolved for `{host_port}`"))?;

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(3))
        .with_context(|| format!("failed to connect to {addr}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let req = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes())?;

    let mut buf = [0u8; 1024];
    let n = stream.read(&mut buf)?;
    let head = std::str::from_utf8(&buf[..n]).unwrap_or_default();
    let status_line = head.lines().next().unwrap_or_default();

    if status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200") {
        Ok(())
    } else {
        Err(anyhow::anyhow!("unhealthy response: {status_line}"))
    }
}

async fn cmd_invite(db: &DbPool, action: InviteCommand) -> anyhow::Result<()> {
    match action {
        InviteCommand::Create {
            email,
            max_uses,
            expires_hours,
        } => {
            if !(1..=1000).contains(&max_uses) {
                anyhow::bail!("--max-uses must be between 1 and 1000");
            }
            if !(1..=8760).contains(&expires_hours) {
                anyhow::bail!("--expires-hours must be between 1 and 8760");
            }
            let normalized_email = match email {
                Some(raw) => Some(
                    normalize_email(&raw)
                        .map_err(|_| anyhow::anyhow!("invalid email address `{raw}`"))?,
                ),
                None => None,
            };
            let (token, token_hash) = generate_opaque_token()?;
            let expires_at = Utc::now() + ChronoDuration::hours(expires_hours);
            let inv = db
                .create_invitation(
                    &token_hash,
                    normalized_email.as_deref(),
                    None,
                    max_uses,
                    expires_at,
                )
                .await?;
            println!("invitation_id={}", inv.id);
            println!("invite_token={}", token.as_str());
            println!("max_uses={}", inv.max_uses);
            println!("expires_at={}", inv.expires_at.to_rfc3339());
            if let Some(em) = inv.invited_email {
                println!("invited_email={em}");
            }
            Ok(())
        }
        InviteCommand::List => {
            let invites = db.list_invitations().await?;
            if invites.is_empty() {
                println!("no invitations found");
                return Ok(());
            }
            for inv in invites {
                let status = if inv.revoked_at.is_some() {
                    "revoked"
                } else if inv.expires_at <= Utc::now() {
                    "expired"
                } else if inv.used_count >= inv.max_uses {
                    "exhausted"
                } else {
                    "active"
                };
                println!(
                    "{} status={} uses={}/{} email={} expires_at={}",
                    inv.id,
                    status,
                    inv.used_count,
                    inv.max_uses,
                    inv.invited_email.as_deref().unwrap_or("*"),
                    inv.expires_at.to_rfc3339()
                );
            }
            Ok(())
        }
        InviteCommand::Revoke { id } => {
            if !db.revoke_invitation(id).await? {
                anyhow::bail!("invitation `{id}` not found");
            }
            println!("revoked invitation {id}");
            Ok(())
        }
    }
}

async fn cmd_user(db: &DbPool, action: UserCommand) -> anyhow::Result<()> {
    match action {
        UserCommand::List => {
            let users = db.list_users_admin().await?;
            if users.is_empty() {
                println!("no users registered");
                return Ok(());
            }
            for u in users {
                println!(
                    "{} email={} role={} active={} rev={}",
                    u.id,
                    u.email,
                    u.role.as_str(),
                    u.is_active,
                    u.sync_revision
                );
            }
            Ok(())
        }
        UserCommand::Disable { identifier } => {
            apply_user_update(db, &identifier, Some(false), None).await
        }
        UserCommand::Enable { identifier } => {
            apply_user_update(db, &identifier, Some(true), None).await
        }
        UserCommand::Promote { identifier } => {
            apply_user_update(db, &identifier, None, Some(UserRole::Admin)).await
        }
        UserCommand::Demote { identifier } => {
            apply_user_update(db, &identifier, None, Some(UserRole::User)).await
        }
    }
}

async fn apply_user_update(
    db: &DbPool,
    identifier: &str,
    is_active: Option<bool>,
    role: Option<UserRole>,
) -> anyhow::Result<()> {
    let user = db
        .find_user_by_identifier(identifier)
        .await?
        .ok_or_else(|| anyhow::anyhow!("user `{identifier}` not found"))?;

    match db
        .update_user_admin(UpdateUserAdminInput {
            target_user_id: user.id,
            is_active,
            role,
        })
        .await?
    {
        UpdateUserAdminOutcome::Updated(u) => {
            println!(
                "updated {} email={} role={} active={}",
                u.id,
                u.email,
                u.role.as_str(),
                u.is_active
            );
            Ok(())
        }
        UpdateUserAdminOutcome::NotFound => anyhow::bail!("user `{identifier}` not found"),
        UpdateUserAdminOutcome::LastAdminProtected => {
            anyhow::bail!("refusing to demote or disable the last active administrator")
        }
    }
}
