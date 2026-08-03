use super::auth_session::{AuthSession, AuthSessionTimes, UpstreamLogoutSession};
use super::form_helpers::apply_auth_session_clear_cookie;
use super::oauth_errors::{json_error_with_iss, no_cache_json_error_with_iss};
use super::upstream_logout_sessions::build_upstream_logout_redirect_target;
use super::AuthSessionStore;
use crate::upstream::UpstreamClaimReleasePolicy;
use axum::{http::StatusCode, response::Response};

#[cfg(test)]
pub(super) fn local_logout_redirect_target(session: Option<&AuthSession>) -> String {
    local_logout_redirect_target_with_policy(session, &[])
}

pub(super) fn local_logout_redirect_target_with_policy(
    session: Option<&AuthSession>,
    allowed_domains: &[String],
) -> String {
    session
        .and_then(|session| session.upstream_logout.as_ref())
        .and_then(|session| build_upstream_logout_redirect_target(session, allowed_domains))
        .unwrap_or_else(|| "/auth/login".to_string())
}

pub(super) fn validate_return_to(value: Option<String>) -> Result<Option<String>, String> {
    let Some(raw) = value else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if !trimmed.starts_with('/')
        || trimmed.starts_with("//")
        || trimmed.contains("://")
        || trimmed.contains('\\')
        || trimmed.chars().any(char::is_control)
    {
        return Err("return_to must be a relative path".to_string());
    }
    Ok(Some(trimmed.to_string()))
}

pub(super) fn normalized_acr(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(super) fn local_password_session_acr(
    local_password_acr: Option<&str>,
    requested_acr: Option<&str>,
) -> Result<Option<String>, &'static str> {
    let requested_acr = normalized_acr(requested_acr);
    match (requested_acr.as_deref(), local_password_acr) {
        (Some(requested), Some(local)) if requested == local => Ok(Some(local.to_string())),
        (Some(_), _) => Err("requested acr cannot be satisfied by local password authentication"),
        (None, Some(local)) => Ok(Some(local.to_string())),
        (None, None) => Ok(None),
    }
}

pub(super) fn auth_session_store_lookup_error_response(issuer_base: &str, error: &str) -> Response {
    tracing::error!(error, "auth session store lookup failed");
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("authentication session store unavailable"),
        issuer_base,
    )
}

pub(super) async fn create_auth_session_or_error_response_async(
    auth_sessions: &AuthSessionStore,
    issuer_base: &str,
    user_id: String,
    times: AuthSessionTimes,
    acr: Option<String>,
    claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    upstream_logout: Option<UpstreamLogoutSession>,
) -> Result<String, Response> {
    match auth_sessions
        .try_create_async(user_id, times, acr, claim_release_policy, upstream_logout)
        .await
    {
        Ok(Some(sid)) => Ok(sid),
        Ok(None) => Err(json_error_with_iss(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            Some("failed to create authentication session"),
            issuer_base,
        )),
        Err(err) => Err(auth_session_store_create_error_response(issuer_base, &err)),
    }
}

fn auth_session_store_create_error_response(issuer_base: &str, error: &str) -> Response {
    tracing::error!(error, "auth session store create failed");
    no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("authentication session store unavailable"),
        issuer_base,
    )
}

pub(super) fn auth_session_store_logout_error_response(issuer_base: &str, error: &str) -> Response {
    tracing::error!(error, "auth session store operation failed during logout");
    let mut response = no_cache_json_error_with_iss(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        Some("failed to update authentication session"),
        issuer_base,
    );
    apply_auth_session_clear_cookie(&mut response);
    response
}
