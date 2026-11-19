//! Shared server application state passed to Axum routes and middleware.

use std::sync::Arc;

use crate::auth::jwt::JwtManager;
use crate::auth::password::ServerAuthHasher;
use crate::config::ServerConfig;
use crate::db::DbPool;

/// Shared server dependencies wrapped in cheap-to-clone `Arc` handles.
#[derive(Clone)]
pub struct AppState {
    pub db: DbPool,
    pub config: Arc<ServerConfig>,
    pub jwt: Arc<JwtManager>,
    pub hasher: Arc<ServerAuthHasher>,
    pub rate_limit_enabled: bool,
}
