use super::super::error_response;
use super::iso8601::audit_time_span_seconds;
use axum::{http::StatusCode, response::Response};

/// Maximum allowed time range for audit queries (90 days in seconds).
pub(in crate::web::management) const AUDIT_MAX_RANGE_SECONDS: u64 = 90 * 24 * 3600;

/// Validate that the time range does not exceed 90 days.
pub(in crate::web::management) fn validate_audit_time_range(
    from: &str,
    to: &str,
    request_id: &str,
) -> Result<(), Response> {
    match audit_time_span_seconds(from, to) {
        Some(seconds) if seconds > AUDIT_MAX_RANGE_SECONDS => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Time range must not exceed 90 days",
            None,
            Some(request_id),
        )),
        None => Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Cannot parse time range dates",
            None,
            Some(request_id),
        )),
        _ => Ok(()),
    }
}
