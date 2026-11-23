//! Entry point for the Anvil Desktop native backend host.

#![forbid(unsafe_code)]

use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anvil_client_core::cache::EncryptedLocalCache;
use anvil_desktop::biometric::default_biometric_provider;
use anvil_desktop::clipboard::SecureClipboardManager;
use anvil_desktop::commands::DesktopCommandHost;
use anvil_desktop::platform::windows::{
    OsSessionLockMonitor, TitlebarHitConfig, WindowRect, compute_hit_zone,
};
use anvil_desktop::tray::SystemTrayController;
use tracing_subscriber::EnvFilter;

fn default_cache_path() -> PathBuf {
    if let Some(dir) = env::var_os("LOCALAPPDATA").or_else(|| env::var_os("XDG_DATA_HOME")) {
        return PathBuf::from(dir).join("Anvil").join("vault_cache.db");
    }
    env::temp_dir().join("anvil_vault_cache.db")
}

fn sqlite_url(path: &std::path::Path) -> String {
    format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"))
}

fn print_help() {
    println!(
        "Anvil Desktop Host v{}\n\
         Usage: anvil-desktop [OPTIONS]\n\n\
         Options:\n\
         \t--cache <PATH>       Path to encrypted SQLite vault cache\n\
         \t--server <URL>       Default Anvil server URL (default: http://127.0.0.1:8080)\n\
         \t--ipc-stdio          Run JSON-line IPC command loop on stdin/stdout\n\
         \t--hit-check          Print default custom titlebar hit zones\n\
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
    let mut cache_path = default_cache_path();
    let mut server_url = "http://127.0.0.1:8080".to_owned();
    let mut ipc_stdio = false;
    let mut hit_check = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("anvil-desktop {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--ipc-stdio" => ipc_stdio = true,
            "--hit-check" => hit_check = true,
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

    if hit_check {
        let rect = WindowRect {
            left: 0,
            top: 0,
            right: 1240,
            bottom: 800,
        };
        let cfg = TitlebarHitConfig::with_centered_search(rect.width(), 340);
        let max_btn = compute_hit_zone(rect, 1170, 16, false, &cfg);
        let resize_left = compute_hit_zone(rect, 2, 200, false, &cfg);
        println!(
            "hit_check max_button={:?}({}) left_border={:?}({})",
            max_btn, max_btn as isize, resize_left, resize_left as isize
        );
        return ExitCode::SUCCESS;
    }

    if let Some(parent) = cache_path.parent()
        && let Err(err) = std::fs::create_dir_all(parent)
    {
        eprintln!(
            "failed to create cache directory {}: {err}",
            parent.display()
        );
        return ExitCode::FAILURE;
    }

    let cache = match EncryptedLocalCache::connect(&sqlite_url(&cache_path)).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("failed to open local encrypted cache: {err}");
            return ExitCode::FAILURE;
        }
    };

    let host = match DesktopCommandHost::new(
        cache,
        &server_url,
        SecureClipboardManager::native_windows(),
        default_biometric_provider(),
        Arc::new(SystemTrayController::default()),
        Arc::new(OsSessionLockMonitor::new()),
    ) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("failed to initialize desktop command host: {err}");
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
                "Anvil Desktop host ready (configured={}, unlocked={}, biometric_available={})",
                status.configured, status.unlocked, status.biometric_available
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("failed to query host status: {err}");
            ExitCode::FAILURE
        }
    }
}
