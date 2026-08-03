use std::net::{IpAddr, ToSocketAddrs};

use super::is_non_routable;

/// Error type for SSRF validation failures.
#[derive(Debug)]
pub enum SsrfError {
    /// The URL is malformed.
    InvalidUrl(String),
    /// The URL host resolves to a non-routable IP address.
    NonRoutableIp(String),
    /// DNS resolution failed for the URL host.
    DnsResolutionFailed(String),
}

impl std::fmt::Display for SsrfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "SSRF: invalid URL: {msg}"),
            Self::NonRoutableIp(msg) => write!(f, "SSRF: non-routable IP: {msg}"),
            Self::DnsResolutionFailed(msg) => write!(f, "SSRF: DNS resolution failed: {msg}"),
        }
    }
}

impl std::error::Error for SsrfError {}

fn parse_host_ip_literal(host: &str) -> Option<IpAddr> {
    host.strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host)
        .parse::<IpAddr>()
        .ok()
}

/// Validate URL hosts that are already known without DNS resolution.
///
/// This rejects localhost-style names and non-routable IP literals while leaving
/// ordinary hostnames to the outbound resolver used at fetch time.
///
/// # Errors
///
/// Returns an error when the URL has no host or contains a non-routable literal host.
pub fn validate_url_host_not_non_routable_literal(parsed: &url::Url) -> Result<(), SsrfError> {
    let host = parsed
        .host_str()
        .ok_or_else(|| SsrfError::InvalidUrl("URL has no host".into()))?;
    if crate::util::is_loopback_host(host) {
        return Err(SsrfError::NonRoutableIp(format!(
            "URL host targets loopback: {host}"
        )));
    }
    if let Some(ip) = parse_host_ip_literal(host) {
        if is_non_routable(ip) {
            return Err(SsrfError::NonRoutableIp(format!(
                "URL host resolves to non-routable IP: {ip}"
            )));
        }
    }
    Ok(())
}

/// Validate that a URL's hostname does not resolve to a non-routable IP.
///
/// Defense-in-depth against SSRF (P8-SSRF-1): resolves the hostname and
/// rejects all addresses that fall into private/reserved/link-local ranges.
/// IP-literal hostnames are checked directly without DNS resolution.
///
/// Note: a TOCTOU gap exists between this pre-flight check and the actual TCP
/// connection unless the caller also installs `NonRoutableDnsResolver` on the
/// outbound HTTP client. The redirect policy (P8-SSRF-2) provides an
/// additional layer by also validating redirect targets.
///
/// # Errors
///
/// Returns an error when the URL is invalid, DNS resolution fails, or any
/// resolved address is non-routable.
pub fn validate_url_not_private(url_str: &str) -> Result<(), SsrfError> {
    let parsed =
        url::Url::parse(url_str).map_err(|_| SsrfError::InvalidUrl("malformed URL".into()))?;

    validate_url_host_not_non_routable_literal(&parsed)?;

    let host = parsed
        .host_str()
        .ok_or_else(|| SsrfError::InvalidUrl("URL has no host".into()))?;

    // IP literal — check directly, no DNS needed
    if parse_host_ip_literal(host).is_some() {
        return Ok(());
    }

    // DNS resolution for hostnames
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<std::net::SocketAddr> = addr_str
        .to_socket_addrs()
        .map_err(|e| SsrfError::DnsResolutionFailed(format!("{host}: {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(SsrfError::DnsResolutionFailed(format!(
            "no addresses returned for {host}"
        )));
    }

    for addr in &addrs {
        if is_non_routable(addr.ip()) {
            return Err(SsrfError::NonRoutableIp(format!(
                "URL host '{host}' resolves to non-routable IP: {}",
                addr.ip()
            )));
        }
    }

    Ok(())
}
