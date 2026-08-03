use std::sync::Arc;

use super::super::jwks_url::{
    jwks_http_loopback_allowed_for_tests, jwks_insecure_skip_verify_allowed,
};
use super::super::JwksRuntimePolicy;

pub(super) fn build_jwks_refresh_client(
    policy: &JwksRuntimePolicy,
    uri: &str,
) -> Result<reqwest::blocking::Client, String> {
    let insecure = jwks_insecure_skip_verify_allowed(policy, uri);
    let timeout_secs = policy.http_timeout_secs;
    let mut builder = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .redirect(crate::ssrf::build_redirect_policy(None))
        .danger_accept_invalid_certs(insecure)
        .timeout(std::time::Duration::from_secs(timeout_secs));
    if !jwks_http_loopback_allowed_for_tests(policy, uri) {
        builder = builder
            .dns_resolver(Arc::new(crate::ssrf::NonRoutableDnsResolver))
            .https_only(true);
    }
    if let Some(ca_path) = policy.ca_bundle.as_ref() {
        let pem = std::fs::read(ca_path).map_err(|err| {
            format!(
                "failed to read AEGAEON_JWKS_CA_BUNDLE {}: {err}",
                ca_path.display()
            )
        })?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|err| {
            format!(
                "failed to parse AEGAEON_JWKS_CA_BUNDLE {} as PEM certificate: {err}",
                ca_path.display()
            )
        })?;
        builder = builder.add_root_certificate(cert);
    }
    builder
        .build()
        .map_err(|err| format!("failed to build JWKS refresh HTTP client: {err}"))
}
