use axum::{
    http::{header, HeaderMap, Method},
    response::Response,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use crate::util::constant_time_eq;

use super::super::{forbidden, management_single_header, ManagementState};

pub(in crate::web::management) fn is_write_method(method: &Method) -> bool {
    matches!(
        method,
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    )
}

pub(in crate::web::management) fn enforce_management_csrf(
    headers: &HeaderMap,
    csrf_cookie: &str,
    mgmt: &ManagementState,
    request_id: &str,
) -> Result<(), Response> {
    let origin = management_single_header(headers, header::ORIGIN.as_str(), "Origin", request_id)?;
    let origin = origin
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| forbidden("csrf_origin_required", "Origin header required", request_id))?;

    if mgmt.cfg.allowed_origins.is_empty() {
        return Err(forbidden(
            "csrf_origin_unconfigured",
            "Management API origin allowlist is not configured",
            request_id,
        ));
    }

    if !mgmt
        .cfg
        .allowed_origins
        .iter()
        .any(|allowed| allowed == origin)
    {
        return Err(forbidden(
            "csrf_origin_mismatch",
            "Origin header did not match the configured admin console origin",
            request_id,
        ));
    }

    let header_token =
        management_single_header(headers, "x-csrf-token", "X-CSRF-Token", request_id)?
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| forbidden("csrf_missing", "X-CSRF-Token header required", request_id))?;

    if !constant_time_eq(header_token.as_bytes(), csrf_cookie.as_bytes()) {
        return Err(forbidden(
            "csrf_mismatch",
            "CSRF token did not match",
            request_id,
        ));
    }

    Ok(())
}

pub(in crate::web::management) fn generate_csrf_token() -> Result<String, ()> {
    let mut bytes = [0u8; 32];
    if aegaeon_crypto::rand::fill_random(&mut bytes).is_err() {
        return Err(());
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
