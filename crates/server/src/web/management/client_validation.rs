use super::environment_support::ManagementEnvironmentRecord;
use super::http_errors::{error_response, invalid_field_details};
use axum::{http::StatusCode, response::Response};
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
    if !uris.is_empty() {
        crate::dcr::validate_redirect_uris(uris).map_err(|message| {
            error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &message,
                Some(invalid_field_details("redirectUri")),
                Some(request_id),
            )
        })?;
    }
    Ok(uris.to_vec())
}
