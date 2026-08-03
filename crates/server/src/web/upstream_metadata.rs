use reqwest::Client;
#[cfg(not(test))]
use std::sync::Arc;
use std::time::Duration;
use url::Url;

mod discovery;
mod federation;
mod jwks;

#[cfg(test)]
pub(super) use discovery::parse_upstream_discovery_body;
pub(super) use discovery::{fetch_upstream_discovery_cached, validate_upstream_discovery};
pub(super) use federation::verify_upstream_federation_metadata_blocking;
#[cfg(test)]
pub(super) use federation::{
    validate_upstream_discovery_matches_federation_metadata,
    validate_upstream_jwks_matches_federation_metadata,
};
#[cfg(test)]
pub(super) use jwks::parse_upstream_jwks_body;
pub(super) use jwks::{fetch_upstream_jwks_cached, select_upstream_signing_key};

const UPSTREAM_HTTP_TIMEOUT_SECS: u64 = 5;

pub(super) fn build_upstream_http_client(allowed_domains: &[String]) -> Result<Client, String> {
    let allowed_domains =
        crate::upstream::normalize_upstream_outbound_allowed_domains(allowed_domains)?;
    let redirect_allowed_domains = (!allowed_domains.is_empty()).then_some(allowed_domains);
    let builder = Client::builder()
        .timeout(Duration::from_secs(UPSTREAM_HTTP_TIMEOUT_SECS))
        .redirect(crate::ssrf::build_redirect_policy(redirect_allowed_domains));
    // T-RP-1: defense-in-depth -- enforce HTTPS at transport level.
    // Rust tests may talk to loopback mock IdPs over HTTP.
    #[cfg(not(test))]
    let builder = builder
        .dns_resolver(Arc::new(crate::ssrf::NonRoutableDnsResolver))
        .https_only(true);
    builder
        .build()
        .map_err(|_| "failed to build upstream http client".to_string())
}

#[cfg(test)]
pub(super) fn validate_https_endpoint(value: &str, label: &str) -> Result<(), String> {
    validate_upstream_endpoint(value, label)
}

fn upstream_test_http_loopback_allowed(url: &Url) -> bool {
    cfg!(test)
        && url.scheme() == "http"
        && url.host_str().is_some_and(crate::util::is_loopback_host)
}

fn validate_upstream_endpoint_url(value: &str, label: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| format!("{label} is invalid"))?;
    if url.host_str().is_none() {
        return Err(format!("{label} must be https"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{label} must not contain credentials"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{label} must not include query or fragment"));
    }
    if upstream_test_http_loopback_allowed(&url) {
        return Ok(url);
    }
    if url.scheme() != "https" {
        return Err(format!("{label} must be https"));
    }
    Ok(url)
}

fn validate_upstream_endpoint(value: &str, label: &str) -> Result<(), String> {
    validate_upstream_endpoint_url(value, label).map(|_| ())
}

pub(super) fn validate_upstream_metadata_endpoint(
    value: &str,
    label: &str,
    allowed_domains: &[String],
) -> Result<(), String> {
    let url = validate_upstream_endpoint_url(value, label)?;
    if upstream_test_http_loopback_allowed(&url) {
        return Ok(());
    }
    let normalized_allowed =
        crate::upstream::normalize_upstream_outbound_allowed_domains(allowed_domains)?;
    if !normalized_allowed.is_empty() {
        let host = url
            .host_str()
            .ok_or_else(|| format!("{label} must be https"))?;
        if !crate::ssrf::host_matches_domain_allowlist(host, &normalized_allowed) {
            return Err(format!(
                "{label} host is not in the upstream domain allowlist"
            ));
        }
    }
    crate::ssrf::validate_url_host_not_non_routable_literal(&url)
        .map_err(|err| format!("{label} rejected by SSRF policy: {err}"))
}

pub(super) fn validate_upstream_outbound_url(
    value: &str,
    label: &str,
    allowed_domains: &[String],
) -> Result<(), String> {
    let url = validate_upstream_endpoint_url(value, label)?;
    if upstream_test_http_loopback_allowed(&url) {
        return Ok(());
    }
    let normalized_allowed =
        crate::upstream::normalize_upstream_outbound_allowed_domains(allowed_domains)?;
    if !normalized_allowed.is_empty() {
        let host = url
            .host_str()
            .ok_or_else(|| format!("{label} must be https"))?;
        if !crate::ssrf::host_matches_domain_allowlist(host, &normalized_allowed) {
            return Err(format!(
                "{label} host is not in the upstream domain allowlist"
            ));
        }
    }
    crate::ssrf::validate_url_not_private(value)
        .map_err(|err| format!("{label} rejected by SSRF policy: {err}"))
}
