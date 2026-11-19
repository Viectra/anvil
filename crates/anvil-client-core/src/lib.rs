//! Shared client-side encrypted SQLite cache, HTTP sync client, and RAM lock manager.
#![forbid(unsafe_code)]

pub mod api_client;
pub mod cache;
pub mod error;
pub mod lock_manager;
pub mod sync_engine;
