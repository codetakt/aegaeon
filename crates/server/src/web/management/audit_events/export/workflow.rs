use super::super::super::audit_csv::audit_events_to_csv;
use super::super::super::audit_query::{
    audit_export_filter_query, audit_export_limit, AuditExportFormat, AuditExportQuery,
};
use super::super::scope::{require_audit_window, AuditScope};
use super::super::store::{collect_redacted_audit_events, fetch_audit_export_rows};
use super::response::{audit_csv_response, audit_json_response, parse_audit_export_format};
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn export_audit_events_inner(
    pool: &PgPool,
    scope: AuditScope,
    query: AuditExportQuery,
    content_disposition: &'static str,
    request_id: &str,
) -> Result<Response, Response> {
    let window = require_audit_window(Some(&query.from), Some(&query.to), request_id)?;
    let export_format = parse_audit_export_format(query.format.as_deref(), request_id)?;
    let export_limit = audit_export_limit(query.limit);
    let filter_query = audit_export_filter_query(&query);
    let rows = fetch_audit_export_rows(
        pool,
        scope,
        &filter_query,
        &window,
        export_limit,
        request_id,
    )
    .await?;
    let audit_events = collect_redacted_audit_events(&rows, export_limit, request_id)?;

    match export_format {
        AuditExportFormat::Csv => Ok(audit_csv_response(
            audit_events_to_csv(&audit_events),
            content_disposition,
        )),
        AuditExportFormat::Json => audit_json_response(query, audit_events, request_id),
    }
}
