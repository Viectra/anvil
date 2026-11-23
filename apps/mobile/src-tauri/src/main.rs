//! Entry point for the Anvil Mobile native backend host.

use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anvil_client_core::cache::EncryptedLocalCache;
use anvil_mobile::biometric::{MobileEnclaveKind, SimulatedHardwareEnclave};
use anvil_mobile::commands::MobileCommandHost;
use tracing_subscriber::EnvFilter;

fn default_mobile_cache_path() -> PathBuf {
    if let Some(dir) = env::var_os("LOCALAPPDATA").or_else(|| env::var_os("HOME")) {
        return PathBuf::from(dir)
            .join("AnvilMobile")
            .join("mobile_cache.db");
    }
    env::temp_dir().join("anvil_mobile_cache.db")
}

fn sqlite_url(path: &std::path::Path) -> String {
    format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"))
}

fn print_help() {
    println!(
        "Anvil Mobile Host v{}\n\
         Usage: anvil-mobile [OPTIONS]\n\n\
         Options:\n\
         \t--cache <PATH>       Path to encrypted mobile SQLite cache\n\
         \t--server <URL>       Default self-hosted HTTPS/localhost server URL\n\
         \t--ipc-stdio          Run JSON-line IPC command loop on stdin/stdout\n\
         \t--version            Print version and exit\n\
         \t-h, --help           Print help",
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();

    let mut args = env::args().skip(1);
    let mut cache_path = default_mobile_cache_path();
    let mut server_url = "https://vault.anvil.invalid".to_owned();
    let mut ipc_stdio = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("anvil-mobile {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--ipc-stdio" => ipc_stdio = true,
            "--cache" => match args.next() {
                Some(path) => cache_path = PathBuf::from(path),
                None => {
                    eprintln!("missing value for --cache");
                    return ExitCode::FAILURE;
                }
            },
            "--server" => match args.next() {
                Some(url) => server_url = url,
                None => {
                    eprintln!("missing value for --server");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    if let Some(parent) = cache_path.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "failed to create mobile cache directory {}: {err}",
            parent.display()
        );
        return ExitCode::FAILURE;
    }

    let cache = match EncryptedLocalCache::connect(&sqlite_url(&cache_path)).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("failed to open mobile cache: {err}");
            return ExitCode::FAILURE;
        }
    };

    let enclave = match SimulatedHardwareEnclave::available(MobileEnclaveKind::SimulatedHardware) {
        Ok(e) => Arc::new(e),
        Err(err) => {
            eprintln!("failed to initialize mobile enclave: {err}");
            return ExitCode::FAILURE;
        }
    };

    let host = match MobileCommandHost::new(
        cache,
        &server_url,
        enclave,
        "android",
        "Anvil Mobile Device",
    ) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("failed to initialize mobile command host: {err}");
            return ExitCode::FAILURE;
        }
    };

    if ipc_stdio {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        for line in stdin.lock().lines() {
            let Ok(raw) = line else {
                break;
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut parts = trimmed.splitn(2, ' ');
            let cmd = parts.next().unwrap_or("");
            let body = parts.next().unwrap_or("{}");
            match host.dispatch_ipc(cmd, body).await {
                Ok(out) => {
                    let _ = writeln!(stdout, "{{\"ok\":true,\"data\":{out}}}");
                }
                Err(err) => {
                    let msg = serde_json::to_string(&err.to_string())
                        .unwrap_or_else(|_| "\"error\"".to_owned());
                    let _ = writeln!(stdout, "{{\"ok\":false,\"error\":{msg}}}");
                }
            }
            let _ = stdout.flush();
        }
        return ExitCode::SUCCESS;
    }

    match host.cmd_status().await {
        Ok(status) => {
            println!(
                "Anvil Mobile host ready (configured={}, unlocked={}, flag_secure={})",
                status.configured, status.unlocked, status.flag_secure_enabled
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("failed to query mobile status: {err}");
            ExitCode::FAILURE
        }
    }
}
