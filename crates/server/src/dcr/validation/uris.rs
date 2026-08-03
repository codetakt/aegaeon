use crate::config::try_env_flag;

fn env_flag_fail_closed(key: &str, default: bool) -> bool {
    try_env_flag(key, default).unwrap_or_else(|err| {
        tracing::warn!(error = %err, key, "invalid DCR runtime flag ignored");
        default
    })
}

pub(super) fn validate_server_callback_uri(uri: &str, field_name: &str) -> Result<(), String> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return Err(format!("{field_name} must not be blank"));
    }
    let parsed = url::Url::parse(trimmed).map_err(|_| format!("invalid {field_name}"))?;
    if parsed.fragment().is_some() {
        return Err(format!("{field_name} must not include fragment"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!("{field_name} must not include userinfo"));
    }
    if parsed.host_str().is_none() {
        return Err(format!("{field_name} must include host"));
    }
    if parsed.scheme() != "https" {
        return Err(format!("{field_name} must use https"));
    }
    if crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err() {
        return Err(format!("{field_name} must not target non-routable hosts"));
    }
    Ok(())
}

pub(super) fn validate_jwks_uri(uri: &str) -> Result<(), String> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return Err("jwks_uri must not be blank".to_string());
    }
    let parsed = url::Url::parse(trimmed).map_err(|_| "invalid jwks_uri".to_string())?;
    if parsed.fragment().is_some() {
        return Err("jwks_uri must not include fragment".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("jwks_uri must not include userinfo".to_string());
    }
    let Some(host) = parsed.host_str() else {
        return Err("jwks_uri must include host".to_string());
    };
    let allow_http_loopback = crate::config::test_runtime_helpers_allowed_by_build()
        && env_flag_fail_closed("AEGAEON_JWKS_ALLOW_HTTP_LOOPBACK_FOR_TESTS", false)
        && parsed.scheme() == "http"
        && crate::util::is_loopback_host(host);
    if parsed.scheme() != "https" && !allow_http_loopback {
        return Err("jwks_uri must use https".to_string());
    }
    if !allow_http_loopback
        && crate::ssrf::validate_url_host_not_non_routable_literal(&parsed).is_err()
    {
        return Err("jwks_uri must not target non-routable hosts".to_string());
    }
    Ok(())
}

/// Validate redirect URIs against DCR and logout transport requirements.
///
/// # Errors
///
/// Returns an error when any redirect URI is blank, malformed, or uses an unsupported transport.
pub fn validate_redirect_uris(uris: &[String]) -> Result<(), String> {
    if uris.is_empty() {
        return Err("redirect_uris empty".into());
    }
    for u in uris {
        let parsed = url::Url::parse(u).map_err(|_| "invalid redirect_uri".to_string())?;
        if parsed.fragment().is_some() {
            return Err("redirect_uri must not include fragment".into());
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("redirect_uri must not include userinfo".into());
        }
        let scheme = parsed.scheme();
        if scheme != "https" {
            let host = parsed.host_str().unwrap_or("");
            if !(scheme == "http" && crate::util::is_loopback_host(host)) {
                return Err("redirect_uri must use https (except loopback)".into());
            }
        }
    }
    Ok(())
}
