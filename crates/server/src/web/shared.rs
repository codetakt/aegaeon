use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use url::Url;

use super::oauth_errors::no_cache_json_error_with_iss;
use crate::util;

pub(super) use crate::policy::{DEVICE_CODE_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};

pub(super) const AUTH_SESSION_COOKIE_NAME: &str = "aegaeon_auth_session";
pub(super) const CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
pub(super) const OAUTH_TOKEN_TYPE_ACCESS_TOKEN: &str =
    "urn:ietf:params:oauth:token-type:access_token";
pub(super) const OAUTH_PROFILE_TYPE_DOWNSTREAM: &str = "downstream";
pub(super) const OAUTH_PROFILE_TYPE_UPSTREAM: &str = "upstream";
pub(super) const LOCAL_AUTH_CSRF_COOKIE_NAME: &str = "aegaeon_local_csrf";
pub(super) const CSRF_COOKIE_MAX_AGE_SECS: u64 = 600;
pub(super) const X_FORWARDED_CLIENT_CERT_HEADER: &str = "x-forwarded-client-cert";
pub(super) const UPSTREAM_MAX_BODY_BYTES: usize = 256 * 1024;
pub(super) const RESOURCE_SCOPES: [&str; 1] = ["read"];

pub(super) fn now_epoch_secs() -> Result<u64, String> {
    util::now_unix_epoch_secs().map_err(|err| {
        util::log_clock_error("web clock", &err);
        err.to_string()
    })
}

pub(super) fn clock_error_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some("system clock is outside supported Unix epoch range"),
        issuer_base,
    )
}

pub(super) fn parse_acr_values(raw: Option<&str>) -> Vec<String> {
    raw.map_or_else(Vec::new, |values| {
        values
            .split_whitespace()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    })
}

pub(super) fn select_supported_acr(requested: &[String], supported: &[String]) -> Option<String> {
    requested
        .iter()
        .find(|value| supported.iter().any(|supported| supported == *value))
        .cloned()
}

pub(super) fn issuer_host_from_url(issuer: &str) -> Option<String> {
    let url = Url::parse(issuer).ok()?;
    util::canonical_url_host_port(&url)
}

pub(super) fn normalize_issuer(issuer: &str) -> Option<String> {
    let url = Url::parse(issuer).ok()?;
    if url.scheme() != "https" || url.host_str().is_none() {
        return None;
    }
    if url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    let host_port = util::canonical_url_host_port(&url)?;
    let mut path = url.path().to_string();
    if path.ends_with('/') && path.len() > 1 {
        path.pop();
    }
    Some(format!("{}://{}{}", url.scheme(), host_port, path))
}

pub(super) fn build_upstream_logout_callback_uri(base_url: &str) -> String {
    format!(
        "{}/oauth/upstream/logout/callback",
        base_url.trim_end_matches('/')
    )
}

pub(super) fn no_cache_redirect_response(location: &str) -> Response {
    let mut response = StatusCode::FOUND.into_response();
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    util::apply_no_cache_headers(&mut response);
    response
}
