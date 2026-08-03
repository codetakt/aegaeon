use super::environment_support::ManagementEnvironmentRecord;
use super::http_errors::{error_response, invalid_field_details};
use axum::{http::StatusCode, response::Response};
use url::Url;
use uuid::Uuid;

pub(super) fn ensure_base_configuration_matches(
    base_configuration_version_id: Uuid,
    environment: &ManagementEnvironmentRecord,
    request_id: &str,
) -> Result<(), Response> {
    if environment.active_configuration_version_id != base_configuration_version_id {
        return Err(error_response(
            StatusCode::CONFLICT,
            "base_version_mismatch",
            "baseConfigurationVersionId did not match the active configuration version",
            None,
            Some(request_id),
        ));
    }

    Ok(())
}

/// Validate redirect URIs: each must be a valid URL, use https (or http for loopback),
/// and must not contain a fragment (RFC 6749 section 3.1.2).
pub(super) fn validate_redirect_uris(
    uris: &[String],
    request_id: &str,
) -> Result<Vec<String>, Response> {
    let mut validated = Vec::with_capacity(uris.len());
    for raw in uris {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed = Url::parse(trimmed).map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Invalid redirect URI",
                Some(invalid_field_details("redirectUri")),
                Some(request_id),
            )
        })?;
        match parsed.scheme() {
            "https" => {}
            "http" if parsed.host_str().is_some_and(crate::util::is_loopback_host) => {}
            _ => {
                return Err(error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Redirect URI must use https (or http for loopback)",
                    Some(invalid_field_details("redirectUri")),
                    Some(request_id),
                ));
            }
        }
        if parsed.fragment().is_some() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Redirect URI must not contain a fragment",
                Some(invalid_field_details("redirectUri")),
                Some(request_id),
            ));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Redirect URI must not contain userinfo",
                Some(invalid_field_details("redirectUri")),
                Some(request_id),
            ));
        }
        validated.push(parsed.to_string());
    }
    Ok(validated)
}
