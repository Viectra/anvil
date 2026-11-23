//! Anvil Desktop application backend: typed IPC commands, OS lock listeners, clipboard protection, and DPAPI seal.

pub mod biometric;
pub mod clipboard;
pub mod commands;
pub mod platform;
pub mod tray;

pub use commands::DesktopCommandHost;
