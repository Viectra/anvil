//! Axum authentication extractors and trusted-proxy IP resolution for rate limiting.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Request, header};
use chrono::Utc;
use ipnet::IpNet;
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;
use uuid::Uuid;

use crate::db::{UserRole, VaultRepository};
use crate::error::ApiError;
use crate::state::AppState;

/// Authenticated user context derived from a verified EdDSA JWT and active DB session check.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub role: UserRole,
    pub client_ip: Option<IpAddr>,
}

/// Authenticated administrator context requiring `UserRole::Admin`.
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ApiError::unauthorized(
                    "MISSING_AUTHORIZATION",
                    "Missing Bearer authorization token",
                )
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .or_else(|| auth_header.strip_prefix("bearer "))
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                ApiError::unauthorized(
                    "INVALID_AUTHORIZATION",
                    "Expected Bearer authorization scheme",
                )
            })?;

        let claims = state.jwt.verify_access_token(token).map_err(|_| {
            ApiError::unauthorized("INVALID_TOKEN", "Invalid or expired access token")
        })?;

        let session_user = state
            .db
            .verify_active_session(claims.sub, claims.sid, Utc::now())
            .await?;

        let Some(active) = session_user else {
            return Err(ApiError::unauthorized(
                "SESSION_REVOKED",
                "Session is expired or has been revoked",
            ));
        };

        if !active.is_active {
            return Err(ApiError::forbidden(
                "ACCOUNT_DISABLED",
                "Account has been deactivated",
            ));
        }

        let peer_ip = extract_peer_ip_from_parts(parts);
        let client_ip = resolve_client_ip(peer_ip, &parts.headers, &state.config.trusted_proxies);

        Ok(Self {
            user_id: active.user_id,
            session_id: claims.sid,
            role: active.role,
            client_ip,
        })
    }
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth = AuthUser::from_request_parts(parts, state).await?;
        if auth.role != UserRole::Admin {
            return Err(ApiError::forbidden(
                "ADMIN_REQUIRED",
                "Administrator privileges are required",
            ));
        }
        Ok(Self(auth))
    }
}

/// Rate-limiter key extractor trusting `X-Forwarded-For` solely from configured `ANVIL_TRUSTED_PROXIES`.
#[derive(Debug, Clone)]
pub struct TrustedProxyIpKeyExtractor {
    trusted_proxies: Arc<Vec<IpNet>>,
}

impl TrustedProxyIpKeyExtractor {
    pub fn new(trusted_proxies: Arc<Vec<IpNet>>) -> Self {
        Self { trusted_proxies }
    }
}

impl KeyExtractor for TrustedProxyIpKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let peer_ip = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.ip())
            .or_else(|| req.extensions().get::<SocketAddr>().map(SocketAddr::ip));

        resolve_client_ip(peer_ip, req.headers(), &self.trusted_proxies)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

/// Extracts peer IP from request extensions (`ConnectInfo<SocketAddr>` or raw `SocketAddr`).
pub fn extract_peer_ip_from_parts(parts: &Parts) -> Option<IpAddr> {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.ip())
        .or_else(|| parts.extensions.get::<SocketAddr>().map(SocketAddr::ip))
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

fn is_trusted_proxy(ip: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    let norm = normalize_ip(ip);
    trusted_proxies.iter().any(|net| net.contains(&norm))
}

/// Resolves the originating client IP, ignoring `X-Forwarded-For` unless the direct peer matches `trusted_proxies`.
pub fn resolve_client_ip(
    peer_ip: Option<IpAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> Option<IpAddr> {
    let peer = normalize_ip(peer_ip?);
    if !is_trusted_proxy(peer, trusted_proxies) {
        return Some(peer);
    }

    let mut chain = Vec::new();
    for hv in headers.get_all("x-forwarded-for") {
        let Ok(raw) = hv.to_str() else {
            return Some(peer);
        };
        for seg in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match seg.parse::<IpAddr>() {
                Ok(ip) => chain.push(normalize_ip(ip)),
                Err(_) => return Some(peer),
            }
        }
    }

    for ip in chain.iter().rev() {
        if !is_trusted_proxy(*ip, trusted_proxies) {
            return Some(*ip);
        }
    }

    chain.first().copied().or(Some(peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn resolve_client_ip_ignores_spoofed_xff_when_peer_untrusted() {
        let proxies = vec!["127.0.0.1/32".parse::<IpNet>().expect("cidr")];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.99, 10.0.0.5"),
        );

        let untrusted_peer = Some("198.51.100.42".parse::<IpAddr>().expect("ip"));
        assert_eq!(
            resolve_client_ip(untrusted_peer, &headers, &proxies),
            untrusted_peer
        );
    }

    #[test]
    fn resolve_client_ip_walks_right_to_left_through_trusted_chain() {
        let proxies = vec![
            "127.0.0.1/32".parse::<IpNet>().expect("cidr"),
            "172.16.0.0/12".parse::<IpNet>().expect("cidr"),
            "fd00::/8".parse::<IpNet>().expect("cidr"),
        ];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.1.1.1, 203.0.113.7, 172.18.0.10"),
        );

        let trusted_peer = Some("127.0.0.1".parse::<IpAddr>().expect("ip"));
        // Even if the client injected `1.1.1.1`, the trusted proxy chain stops at `203.0.113.7`.
        assert_eq!(
            resolve_client_ip(trusted_peer, &headers, &proxies),
            Some("203.0.113.7".parse::<IpAddr>().expect("ip"))
        );

        let ipv6_mapped_peer = Some("::ffff:172.17.0.2".parse::<IpAddr>().expect("ip"));
        assert_eq!(
            resolve_client_ip(ipv6_mapped_peer, &headers, &proxies),
            Some("203.0.113.7".parse::<IpAddr>().expect("ip"))
        );
    }
}
