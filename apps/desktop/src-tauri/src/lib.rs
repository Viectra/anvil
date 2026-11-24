//! Anvil Desktop application backend: typed IPC commands, OS lock listeners, clipboard protection, and DPAPI seal.

pub mod biometric;
pub mod clipboard;
pub mod commands;
pub mod embedded_server;
pub mod http_bridge;
pub mod platform;
pub mod tray;

pub use commands::DesktopCommandHost;
