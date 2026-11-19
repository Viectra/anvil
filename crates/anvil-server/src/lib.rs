//! Self-hosted zero-knowledge vault server for Anvil.
#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod routes;
pub mod state;
