use super::JwksRuntimePolicy;

pub(super) fn jwks_http_loopback_allowed_for_tests(policy: &JwksRuntimePolicy, uri: &str) -> bool {
    if !cfg!(test) || !policy.allow_http_loopback_for_tests {
        return false;
    }
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    parsed.scheme() == "http"
        && parsed.host_str().is_some_and(crate::util::is_loopback_host)
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none()
}

pub(super) fn jwks_insecure_skip_verify_allowed(policy: &JwksRuntimePolicy, uri: &str) -> bool {
    cfg!(test) && jwks_http_loopback_allowed_for_tests(policy, uri) && policy.insecure_skip_verify
}

pub(super) fn validate_jwks_fetch_url(policy: &JwksRuntimePolicy, uri: &str) -> Result<(), String> {
    let parsed = url::Url::parse(uri).map_err(|_| "invalid jwks_uri".to_string())?;
    if parsed.fragment().is_some() {
        return Err("jwks_uri must not include fragment".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("jwks_uri must not include userinfo".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("jwks_uri must include host".to_string());
    }
    if jwks_http_loopback_allowed_for_tests(policy, uri) {
        return Ok(());
    }
    if parsed.scheme() != "https" {
        return Err("jwks_uri must use https".to_string());
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        return Err("jwks_uri must not target non-routable hosts".to_string());
    }
    crate::ssrf::validate_url_not_private(uri).map_err(|err| err.to_string())
}
