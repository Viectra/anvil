//! Standalone GUI entry point for Anvil Desktop (`anvil.exe`).

#![forbid(unsafe_code)]
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anvil_client_core::cache::EncryptedLocalCache;
use anvil_core::crypto::fill_random_bytes;
use anvil_desktop::biometric::default_biometric_provider;
use anvil_desktop::clipboard::SecureClipboardManager;
use anvil_desktop::commands::DesktopCommandHost;
use anvil_desktop::embedded_server::{DEFAULT_EMBEDDED_SERVER_PORT, start_embedded_server};
use anvil_desktop::http_bridge::spawn_embedded_ui_bridge;
use anvil_desktop::platform::windows::OsSessionLockMonitor;
use anvil_desktop::tray::SystemTrayController;
use tracing_subscriber::EnvFilter;

const EMBEDDED_UI_HTML: &str = include_str!("../assets/desktop_app.html");

fn default_data_dir() -> PathBuf {
    if let Some(dir) = env::var_os("LOCALAPPDATA").or_else(|| env::var_os("XDG_DATA_HOME")) {
        return PathBuf::from(dir).join("Anvil");
    }
    env::temp_dir().join("Anvil")
}

fn sqlite_url(path: &std::path::Path) -> String {
    format!("sqlite:{}", path.to_string_lossy().replace('\\', "/"))
}

fn generate_hex_token_32() -> Result<String, String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut raw = [0u8; 32];
    fill_random_bytes(&mut raw).map_err(|err| format!("CSPRNG failure: {err}"))?;
    let mut out = String::with_capacity(64);
    for byte in raw {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(out)
}

#[cfg(target_os = "windows")]
fn build_anvil_window_icon() -> Option<tao::window::Icon> {
    const SIZE: usize = 32;
    let mut rgba = Vec::with_capacity(SIZE * SIZE * 4);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let (r, g, b, a) = if (10..=12).contains(&y) && (6..=25).contains(&x) {
                (224u8, 122u8, 47u8, 255u8)
            } else if ((13..=15).contains(&y) && (8..=23).contains(&x))
                || ((16..=20).contains(&y) && (11..=20).contains(&x))
                || ((21..=23).contains(&y) && (8..=23).contains(&x))
            {
                (241u8, 243u8, 247u8, 255u8)
            } else if (2..30).contains(&x) && (2..30).contains(&y) {
                (25u8, 28u8, 36u8, 255u8)
            } else {
                (14u8, 16u8, 21u8, 255u8)
            };
            rgba.extend_from_slice(&[r, g, b, a]);
        }
    }
    tao::window::Icon::from_rgba(rgba, SIZE as u32, SIZE as u32).ok()
}

#[cfg(target_os = "windows")]
fn open_external_url_os(url: &str) {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        let _ = std::process::Command::new("explorer.exe")
            .arg(trimmed)
            .spawn();
    }
}

#[cfg(target_os = "windows")]
fn report_startup_error(message: &str) {
    tracing::error!("{message}");
    let _ = std::process::Command::new("powershell")
        .env("ANVIL_ERR_MSG", message)
        .args([
            "-NoProfile",
            "-WindowStyle",
            "Hidden",
            "-Command",
            "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show($env:ANVIL_ERR_MSG, 'Anvil', 'OK', 'Error') | Out-Null",
        ])
        .spawn();
}

#[cfg(not(target_os = "windows"))]
fn report_startup_error(message: &str) {
    eprintln!("Anvil error: {message}");
}

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            report_startup_error(&format!("Impossible de démarrer Tokio : {err}"));
            return ExitCode::FAILURE;
        }
    };

    let data_dir = default_data_dir();
    if let Err(err) = std::fs::create_dir_all(&data_dir) {
        report_startup_error(&format!(
            "Impossible de créer le dossier de données {} : {err}",
            data_dir.display()
        ));
        return ExitCode::FAILURE;
    }

    let bootstrap = runtime.block_on(async {
        let server_handle = start_embedded_server(&data_dir, DEFAULT_EMBEDDED_SERVER_PORT)
            .await
            .map_err(|err| format!("Échec serveur local : {err}"))?;

        let cache = EncryptedLocalCache::connect(&sqlite_url(&data_dir.join("vault_cache.db")))
            .await
            .map_err(|err| format!("Échec ouverture du cache chiffré : {err}"))?;

        let host = Arc::new(
            DesktopCommandHost::new(
                cache,
                &server_handle.url,
                SecureClipboardManager::native_windows(),
                default_biometric_provider(),
                Arc::new(SystemTrayController::default()),
                Arc::new(OsSessionLockMonitor::new()),
            )
            .map_err(|err| format!("Échec initialisation hôte desktop : {err}"))?,
        );

        let token = generate_hex_token_32()?;
        let bridge_handle = spawn_embedded_ui_bridge(
            Arc::clone(&host),
            token,
            server_handle.url.clone(),
            EMBEDDED_UI_HTML,
        )
        .await
        .map_err(|err| format!("Échec démarrage interface locale : {err}"))?;

        Ok::<_, String>((server_handle, bridge_handle))
    });

    let (server_handle, bridge_handle) = match bootstrap {
        Ok(pair) => pair,
        Err(msg) => {
            report_startup_error(&msg);
            return ExitCode::FAILURE;
        }
    };

    let exit_code = run_ui_loop(&data_dir, &bridge_handle.url);

    runtime.block_on(async move {
        bridge_handle.shutdown().await;
        server_handle.shutdown().await;
    });

    exit_code
}

#[cfg(target_os = "windows")]
fn run_ui_loop(data_dir: &std::path::Path, bridge_url: &str) -> ExitCode {
    use tao::dpi::LogicalSize;
    use tao::event::{Event, WindowEvent};
    use tao::event_loop::{ControlFlow, EventLoop};
    use tao::window::{Theme, WindowBuilder};
    use wry::{NewWindowResponse, WebContext, WebViewBuilder};

    let event_loop = EventLoop::new();
    let window = match WindowBuilder::new()
        .with_title("Anvil")
        .with_inner_size(LogicalSize::new(1240.0, 800.0))
        .with_min_inner_size(LogicalSize::new(960.0, 620.0))
        .with_theme(Some(Theme::Dark))
        .with_window_icon(build_anvil_window_icon())
        .build(&event_loop)
    {
        Ok(w) => w,
        Err(err) => {
            report_startup_error(&format!("Impossible de créer la fenêtre Windows : {err}"));
            return ExitCode::FAILURE;
        }
    };

    let webview_dir = data_dir.join("webview2");
    let _ = std::fs::create_dir_all(&webview_dir);
    let mut web_context = WebContext::new(Some(webview_dir));

    let _webview = match WebViewBuilder::new_with_web_context(&mut web_context)
        .with_url(bridge_url)
        .with_background_color((14, 16, 21, 255))
        .with_general_autofill_enabled(false)
        .with_new_window_req_handler(|url, _features| {
            open_external_url_os(&url);
            NewWindowResponse::Deny
        })
        .build(&window)
    {
        Ok(wv) => wv,
        Err(err) => {
            report_startup_error(&format!("WebView2 indisponible sur cet ordinateur : {err}"));
            return ExitCode::FAILURE;
        }
    };

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    });
}

#[cfg(not(target_os = "windows"))]
fn run_ui_loop(_data_dir: &std::path::Path, bridge_url: &str) -> ExitCode {
    println!("Anvil Desktop interface available on {bridge_url}");
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(_) => return ExitCode::FAILURE,
    };
    let _ = rt.block_on(tokio::signal::ctrl_c());
    ExitCode::SUCCESS
}
