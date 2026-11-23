//! HTTP router composition, rate limiting, security headers, CORS, and error request-id binding.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{delete, get, patch, post, put};
use tower::ServiceBuilder;
use tower_governor::GovernorError;
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::request_id::{
    MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer,
};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use crate::auth::middleware::TrustedProxyIpKeyExtractor;
use crate::error::{ApiErrorMarker, ErrorDetail, ErrorEnvelope};
use crate::state::AppState;

pub mod account;
pub mod admin;
pub mod auth;
pub mod favicon;
pub mod system;
pub mod vault;

const MAX_JSON_BODY_BYTES: usize = 4 * 1024 * 1024;
const MAX_ERROR_PATCH_BYTES: usize = 1024 * 1024;

macro_rules! with_rate_limit {
    ($method_router:expr, $enabled:expr, $period_secs:expr, $burst:expr, $proxies:expr, $methods:expr) => {{
        if $enabled {
            let mut base = GovernorConfigBuilder::default();
            let mut builder = base
                .per_second($period_secs)
                .burst_size($burst)
                .key_extractor(TrustedProxyIpKeyExtractor::new($proxies));
            if let Some(m) = $methods {
                builder.methods(m);
            }
            builder.error_handler(rate_limit_error_response);
            match builder.finish() {
                Some(cfg) => $method_router.route_layer(GovernorLayer {
                    config: Arc::new(cfg),
                }),
                None => $method_router,
            }
        } else {
            $method_router
        }
    }};
}

/// Builds the full `/api/v1` router configured from `state`.
pub fn build_router(state: AppState) -> Router {
    let trusted_proxies = Arc::new(state.config.trusted_proxies.clone());
    let rl = state.rate_limit_enabled;

    let prelogin_route = with_rate_limit!(
        post(auth::prelogin),
        rl,
        3,
        20,
        trusted_proxies.clone(),
        Option::<Vec<Method>>::None
    );
    let register_route = with_rate_limit!(
        post(auth::register),
        rl,
        180,
        5,
        trusted_proxies.clone(),
        Option::<Vec<Method>>::None
    );
    let login_route = with_rate_limit!(
        post(auth::login),
        rl,
        30,
        10,
        trusted_proxies.clone(),
        Option::<Vec<Method>>::None
    );
    let refresh_route = with_rate_limit!(
        post(auth::refresh),
        rl,
        2,
        30,
        trusted_proxies.clone(),
        Option::<Vec<Method>>::None
    );
    let rotate_password_route = with_rate_limit!(
        post(account::rotate_password),
        rl,
        300,
        3,
        trusted_proxies.clone(),
        Option::<Vec<Method>>::None
    );
    let rotate_vault_key_route = with_rate_limit!(
        post(account::rotate_vault_key).layer(DefaultBodyLimit::max(32 * 1024 * 1024)),
        rl,
        300,
        2,
        trusted_proxies.clone(),
        Option::<Vec<Method>>::None
    );
    let account_me_router = with_rate_limit!(
        get(account::get_me).delete(account::delete_me),
        rl,
        1800,
        2,
        trusted_proxies,
        Some(vec![Method::DELETE])
    );

    let cors = build_cors_layer(&state.config.cors_origins);
    let x_request_id = HeaderName::from_static("x-request-id");

    Router::new()
        .route("/api/v1/health", get(system::health))
        .route("/api/v1/meta", get(system::meta))
        .route("/api/v1/auth/prelogin", prelogin_route)
        .route("/api/v1/auth/register", register_route)
        .route("/api/v1/auth/login", login_route)
        .route("/api/v1/auth/refresh", refresh_route)
        .route("/api/v1/auth/logout", post(auth::logout))
        .route("/api/v1/account/me", account_me_router)
        .route("/api/v1/account/rotate-password", rotate_password_route)
        .route("/api/v1/account/rotate-vault-key", rotate_vault_key_route)
        .route("/api/v1/account/sessions", get(account::list_sessions))
        .route(
            "/api/v1/account/sessions/{session_id}",
            delete(account::revoke_session),
        )
        .route(
            "/api/v1/vault/sync",
            get(vault::pull_sync).post(vault::push_sync),
        )
        .route("/api/v1/vault/items", post(vault::create_item))
        .route(
            "/api/v1/vault/items/{id}",
            put(vault::update_item).delete(vault::delete_item),
        )
        .route(
            "/api/v1/vault/blobs/{blob_id}",
            put(vault::put_blob)
                .get(vault::get_blob)
                .delete(vault::delete_blob),
        )
        .route("/api/v1/utils/favicon", get(favicon::get_favicon))
        .route(
            "/api/v1/admin/invitations",
            post(admin::create_invitation).get(admin::list_invitations),
        )
        .route(
            "/api/v1/admin/invitations/{id}",
            delete(admin::revoke_invitation),
        )
        .route("/api/v1/admin/users", get(admin::list_users))
        .route("/api/v1/admin/users/{id}", patch(admin::update_user))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::new(
                    x_request_id.clone(),
                    MakeRequestUuid,
                ))
                .layer(PropagateRequestIdLayer::new(x_request_id))
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_CONTENT_TYPE_OPTIONS,
                    HeaderValue::from_static("nosniff"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::X_FRAME_OPTIONS,
                    HeaderValue::from_static("DENY"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::REFERRER_POLICY,
                    HeaderValue::from_static("no-referrer"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
                ))
                .layer(SetResponseHeaderLayer::if_not_present(
                    header::CACHE_CONTROL,
                    HeaderValue::from_static("no-store"),
                ))
                .layer(cors)
                .layer(DefaultBodyLimit::max(MAX_JSON_BODY_BYTES))
                .layer(middleware::from_fn(inject_request_id_on_errors)),
        )
}

fn rate_limit_error_response(err: GovernorError) -> Response<Body> {
    match err {
        GovernorError::TooManyRequests { wait_time, headers } => {
            let envelope = ErrorEnvelope {
                error: ErrorDetail {
                    code: "RATE_LIMITED",
                    message: format!("Too many requests; retry after {wait_time}s"),
                    request_id: String::new(),
                },
                sync: None,
                current_item: None,
            };
            let mut resp = (StatusCode::TOO_MANY_REQUESTS, Json(envelope)).into_response();
            if let Some(hdrs) = headers {
                for (name, val) in hdrs.iter() {
                    resp.headers_mut().insert(name, val.clone());
                }
            }
            resp.extensions_mut().insert(ApiErrorMarker);
            resp
        }
        GovernorError::UnableToExtractKey | GovernorError::Other { .. } => {
            let envelope = ErrorEnvelope {
                error: ErrorDetail {
                    code: "CLIENT_IP_UNAVAILABLE",
                    message: "Unable to resolve client address for rate limiting".to_owned(),
                    request_id: String::new(),
                },
                sync: None,
                current_item: None,
            };
            let mut resp = (StatusCode::BAD_REQUEST, Json(envelope)).into_response();
            resp.extensions_mut().insert(ApiErrorMarker);
            resp
        }
    }
}

fn build_cors_layer(origins: &[String]) -> CorsLayer {
    let allowed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            HeaderName::from_static("x-anvil-item-id"),
        ])
}

async fn inject_request_id_on_errors(req: Request<Body>, next: Next) -> Response<Body> {
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .and_then(|id| id.header_value().to_str().ok())
        .map(ToOwned::to_owned)
        .unwrap_or_default();

    let response = next.run(req).await;
    if response.extensions().get::<ApiErrorMarker>().is_none() || request_id.is_empty() {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_ERROR_PATCH_BYTES).await else {
        return Response::from_parts(parts, Body::empty());
    };

    if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes)
        && let Some(err_obj) = value.get_mut("error").and_then(|v| v.as_object_mut())
    {
        err_obj.insert(
            "request_id".to_owned(),
            serde_json::Value::String(request_id),
        );
        if let Ok(patched) = serde_json::to_vec(&value) {
            parts.headers.remove(header::CONTENT_LENGTH);
            return Response::from_parts(parts, Body::from(patched));
        }
    }

    Response::from_parts(parts, Body::from(bytes))
}
