use super::types::{AuditEventListQuery, AuditExportFormat, AuditExportQuery};

pub(in crate::web::management) fn audit_export_filter_query(
    query: &AuditExportQuery,
) -> AuditEventListQuery {
    AuditEventListQuery {
        page_size: None,
        page_token: None,
        event_type: query.event_type.clone(),
        category: query.category.clone(),
        target_type: query.target_type.clone(),
        outcome: query.outcome.clone(),
        severity: query.severity.clone(),
        from: Some(query.from.clone()),
        to: Some(query.to.clone()),
    }
}

pub(in crate::web::management) fn audit_export_format(
    format: Option<&str>,
) -> Option<AuditExportFormat> {
    match format.unwrap_or("json") {
        "json" => Some(AuditExportFormat::Json),
        "csv" => Some(AuditExportFormat::Csv),
        _ => None,
    }
}
