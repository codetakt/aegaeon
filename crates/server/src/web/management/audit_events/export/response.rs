use super::super::super::audit_query::{audit_export_format, AuditExportFormat, AuditExportQuery};
use super::super::super::{error_response, management_internal_error};
use crate::management::types::{AuditEvent, ExportAuditEventsResponse, ExportTimeRange};
use crate::util;
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

pub(super) fn parse_audit_export_format(
    format: Option<&str>,
    request_id: &str,
) -> Result<AuditExportFormat, Response> {
    audit_export_format(format).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Invalid format; must be 'json' or 'csv'",
            None,
            Some(request_id),
        )
    })
}

fn audit_exported_at(request_id: &str) -> Result<String, Response> {
    util::now_unix_epoch_secs()
        .map(|secs| secs.to_string())
        .map_err(|err| {
            util::log_clock_error("management audit export clock", &err);
            management_internal_error(request_id, "System clock unavailable")
        })
}

pub(super) fn audit_csv_response(csv_body: String, content_disposition: &'static str) -> Response {
    let mut response = (StatusCode::OK, csv_body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/csv; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_static(content_disposition),
    );
    response
}

pub(super) fn audit_json_response(
    query: AuditExportQuery,
    audit_events: Vec<AuditEvent>,
    request_id: &str,
) -> Result<Response, Response> {
    let total_count = u64::try_from(audit_events.len()).unwrap_or(u64::MAX);
    let exported_at = audit_exported_at(request_id)?;
    Ok((
        StatusCode::OK,
        Json(ExportAuditEventsResponse {
            total_count,
            exported_at,
            time_range: ExportTimeRange {
                from: query.from,
                to: query.to,
            },
            audit_events,
        }),
    )
        .into_response())
}
