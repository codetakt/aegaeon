use super::super::super::audit_time::is_valid_iso8601;
use super::super::super::{error_response, validate_audit_time_range};
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management::audit_events) struct AuditWindow {
    pub(in crate::web::management::audit_events) from: String,
    pub(in crate::web::management::audit_events) to: String,
}

fn require_audit_timestamp(
    value: Option<&str>,
    field: &str,
    request_id: &str,
) -> Result<String, Response> {
    match value {
        Some(timestamp) if is_valid_iso8601(timestamp) => Ok(timestamp.to_string()),
        Some(_) => {
            let message = format!("Invalid '{field}' timestamp; use ISO 8601 format");
            Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &message,
                None,
                Some(request_id),
            ))
        }
        None => {
            let message = format!("Missing required '{field}' parameter for time range");
            Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                &message,
                None,
                Some(request_id),
            ))
        }
    }
}

pub(in crate::web::management::audit_events) fn require_audit_window(
    from: Option<&str>,
    to: Option<&str>,
    request_id: &str,
) -> Result<AuditWindow, Response> {
    let window = AuditWindow {
        from: require_audit_timestamp(from, "from", request_id)?,
        to: require_audit_timestamp(to, "to", request_id)?,
    };
    validate_audit_time_range(&window.from, &window.to, request_id)?;
    Ok(window)
}
