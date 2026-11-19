//! Opt-in SSRF-hardened website favicon proxy (`/api/v1/utils/favicon`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axum::extract::{Query, State};
use axum::response::Response;
use serde::Deserialize;

use crate::auth::middleware::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

const MAX_DOMAIN_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Deserialize)]
pub struct FaviconQuery {
    pub domain: String,
}

/// Fetches a target domain's favicon only when `ANVIL_ENABLE_FAVICON_PROXY=true` and all resolved IPs are publicly routable.
pub async fn get_favicon(
    State(state): State<AppState>,
    _auth: AuthUser,
    Query(query): Query<FaviconQuery>,
) -> Result<Response, ApiError> {
    if !state.config.enable_favicon_proxy {
        return Err(ApiError::not_found(
            "FAVICON_PROXY_DISABLED",
            "Favicon proxy is disabled on this server",
        ));
    }

    let domain = validate_favicon_domain(&query.domain)?;
    fetch_favicon_impl(&domain).await
}

#[cfg(feature = "favicon-proxy")]
async fn fetch_favicon_impl(domain: &str) -> Result<Response, ApiError> {
    use std::net::SocketAddr;
    use std::time::Duration;

    use axum::http::{HeaderValue, StatusCode, header};
    use axum::response::IntoResponse;

    const MAX_FAVICON_BYTES: usize = 131_072;

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((domain, 443))
        .await
        .map_err(|_| {
            ApiError::bad_gateway("FAVICON_DNS_FAILED", "Failed to resolve target domain")
        })?
        .collect();

    if addrs.is_empty() {
        return Err(ApiError::bad_gateway(
            "FAVICON_DNS_FAILED",
            "No IP addresses resolved for target domain",
        ));
    }

    if !addrs.iter().all(|addr| is_public_routable_ip(addr.ip())) {
        return Err(ApiError::bad_request(
            "SSRF_BLOCKED",
            "Target resolves to a private, loopback, link-local, or reserved IP address",
        ));
    }

    let pinned_addr = addrs[0];
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .connect_timeout(Duration::from_secs(3))
        .resolve(domain, pinned_addr)
        .user_agent("Anvil-Favicon-Proxy/0.1")
        .build()
        .map_err(|e| ApiError::internal(anyhow::anyhow!("reqwest client build error: {e}")))?;

    let target_url = format!("https://{domain}/favicon.ico");
    let mut upstream =
        client.get(&target_url).send().await.map_err(|_| {
            ApiError::bad_gateway("FAVICON_FETCH_FAILED", "Unable to retrieve favicon")
        })?;

    if !upstream.status().is_success() {
        return Err(ApiError::not_found(
            "FAVICON_NOT_FOUND",
            "Target favicon not found",
        ));
    }

    if let Some(len) = upstream.content_length()
        && len > MAX_FAVICON_BYTES as u64
    {
        return Err(ApiError::bad_gateway(
            "FAVICON_TOO_LARGE",
            "Upstream favicon exceeds 128 KiB limit",
        ));
    }

    let content_type = upstream
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
        .unwrap_or_else(|| "image/x-icon".to_owned());

    if !content_type.starts_with("image/") || content_type == "image/svg+xml" {
        return Err(ApiError::bad_gateway(
            "UNSUPPORTED_FAVICON_TYPE",
            "Upstream resource is not a permitted raster or icon image",
        ));
    }

    let mut buf = Vec::new();
    while let Some(chunk) = upstream.chunk().await.map_err(|_| {
        ApiError::bad_gateway("FAVICON_FETCH_FAILED", "Error reading favicon stream")
    })? {
        if buf.len().saturating_add(chunk.len()) > MAX_FAVICON_BYTES {
            return Err(ApiError::bad_gateway(
                "FAVICON_TOO_LARGE",
                "Upstream favicon exceeds 128 KiB limit",
            ));
        }
        buf.extend_from_slice(&chunk);
    }

    if buf.is_empty() {
        return Err(ApiError::not_found(
            "FAVICON_NOT_FOUND",
            "Target favicon is empty",
        ));
    }

    let mut response = (StatusCode::OK, buf).into_response();
    let headers = response.headers_mut();
    if let Ok(ct) = HeaderValue::from_str(&content_type) {
        headers.insert(header::CONTENT_TYPE, ct);
    }
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=3600"),
    );
    Ok(response)
}

#[cfg(not(feature = "favicon-proxy"))]
async fn fetch_favicon_impl(_domain: &str) -> Result<Response, ApiError> {
    Err(ApiError::not_found(
        "FAVICON_PROXY_DISABLED",
        "Favicon proxy support is disabled at compile time",
    ))
}

/// Validates and normalizes a public DNS hostname, rejecting IP literals and internal suffixes.
pub fn validate_favicon_domain(raw: &str) -> Result<String, ApiError> {
    let trimmed = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() || trimmed.len() > MAX_DOMAIN_LEN {
        return Err(ApiError::bad_request(
            "INVALID_DOMAIN",
            "Domain must be between 1 and 253 ASCII characters",
        ));
    }

    if trimmed.parse::<IpAddr>().is_ok() {
        return Err(ApiError::bad_request(
            "SSRF_BLOCKED",
            "Direct IP literals are forbidden in favicon requests",
        ));
    }

    if !trimmed.contains('.')
        || trimmed == "localhost"
        || trimmed.ends_with(".localhost")
        || trimmed.ends_with(".local")
        || trimmed.ends_with(".internal")
        || trimmed.ends_with(".arpa")
        || trimmed.ends_with(".lan")
    {
        return Err(ApiError::bad_request(
            "SSRF_BLOCKED",
            "Local, single-label, and internal hostnames are forbidden",
        ));
    }

    for label in trimmed.split('.') {
        if label.is_empty()
            || label.len() > MAX_LABEL_LEN
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(ApiError::bad_request(
                "INVALID_DOMAIN",
                "Domain contains invalid hostname characters or labels",
            ));
        }
    }

    Ok(trimmed)
}

/// Returns `true` only if `ip` is globally routable on the public internet.
pub fn is_public_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return is_public_ipv4(mapped_v4);
            }
            is_public_ipv6(v6)
        }
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let is_this_network = a == 0;
    let is_cgnat = a == 100 && (b & 0b1100_0000) == 64;
    let is_ietf_protocol = a == 192 && b == 0 && c == 0;
    let is_benchmark = a == 198 && (b == 18 || b == 19);
    let is_multicast_or_reserved = a >= 224;

    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || is_this_network
        || is_cgnat
        || is_ietf_protocol
        || is_benchmark
        || is_multicast_or_reserved)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    let segs = ip.segments();
    let is_ula = (segs[0] & 0xfe00) == 0xfc00;
    let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
    let is_documentation = segs[0] == 0x2001 && segs[1] == 0x0db8;
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || is_ula
        || is_link_local
        || is_documentation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_loopback_metadata_and_cgnat_ips() {
        let blocked = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ];
        for raw in blocked {
            let ip: IpAddr = raw.parse().expect("valid ip");
            assert!(!is_public_routable_ip(ip), "{raw} must be blocked");
        }

        let public = [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ];
        for raw in public {
            let ip: IpAddr = raw.parse().expect("valid ip");
            assert!(is_public_routable_ip(ip), "{raw} should be allowed");
        }
    }

    #[test]
    fn validates_favicon_domains_strictly() {
        assert_eq!(
            validate_favicon_domain("GitHub.COM.").expect("valid"),
            "github.com"
        );
        for bad in [
            "",
            "localhost",
            "db.local",
            "metadata.google.internal",
            "127.0.0.1",
            "169.254.169.254",
            "[::1]",
            "github.com:443",
            "github.com/login",
            "-bad.com",
        ] {
            assert!(validate_favicon_domain(bad).is_err(), "{bad} must fail");
        }
    }
}
