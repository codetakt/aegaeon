use std::net::{IpAddr, ToSocketAddrs};

use super::is_non_routable;

/// Build a redirect policy that enforces HTTPS, domain allowlist, and private
/// IP blocking on redirect targets (P8-SSRF-2).
///
/// Validates each redirect target:
/// 1. Must use HTTPS scheme
/// 2. Must match the domain allowlist (if configured)
/// 3. Must not resolve to a non-routable IP (P8-SSRF-1)
/// 4. Max 3 redirects total
#[must_use]
pub fn build_redirect_policy(allowed_domains: Option<Vec<String>>) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 3 {
            return attempt.stop();
        }

        if let Err(message) = validate_redirect_target(attempt.url(), allowed_domains.as_deref()) {
            return attempt.error(message);
        }

        attempt.follow()
    })
}

/// Return `true` when `host` is exactly an allowed domain or a subdomain of one.
#[must_use]
pub fn host_matches_domain_allowlist(host: &str, allowed_domains: &[String]) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    allowed_domains.iter().any(|domain| {
        let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        host == domain
            || host
                .strip_suffix(&domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

pub(super) fn validate_redirect_target(
    url: &url::Url,
    allowed_domains: Option<&[String]>,
) -> Result<(), String> {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("");
    let port = url.port_or_known_default().unwrap_or(443);

    if scheme != "https" {
        return Err(format!("redirect to non-HTTPS URL blocked: {scheme}"));
    }

    if host.is_empty() {
        return Err("redirect target has no host".to_string());
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("redirect target must not include userinfo".to_string());
    }

    if let Some(allowed) = allowed_domains {
        if !host_matches_domain_allowlist(host, allowed) {
            return Err(format!(
                "redirect to host '{host}' blocked: not in domain allowlist"
            ));
        }
    }

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_non_routable(ip) {
            return Err(format!("redirect to non-routable IP blocked: {ip}"));
        }
        return Ok(());
    }

    let addrs: Vec<std::net::SocketAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|err| format!("redirect host '{host}' DNS resolution failed: {err}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!(
            "redirect host '{host}' DNS resolution returned no addresses"
        ));
    }
    for addr in addrs {
        if is_non_routable(addr.ip()) {
            return Err(format!(
                "redirect host '{host}' resolves to non-routable IP: {}",
                addr.ip()
            ));
        }
    }

    Ok(())
}
