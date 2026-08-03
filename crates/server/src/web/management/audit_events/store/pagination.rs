use super::super::super::audit_time::encode_audit_cursor;
use super::super::super::pagination::pagination_limit;
use super::super::super::{
    audit_event_from_row_result, collect_page_rows_result, redact_audit_event,
};
use crate::management::types::{AuditEvent, PageInfo};
use axum::response::Response;
use sqlx::postgres::PgRow;

fn audit_next_page_token(
    rows_len: usize,
    limit: i64,
    audit_events: &[AuditEvent],
) -> Option<String> {
    if rows_len <= pagination_limit(limit) {
        return None;
    }

    audit_events
        .last()
        .map(|event| encode_audit_cursor(&event.occurred_at, &event.id))
}

pub(in crate::web::management::audit_events) fn audit_page_info(
    rows_len: usize,
    limit: i64,
    audit_events: &[AuditEvent],
) -> Option<PageInfo> {
    audit_next_page_token(rows_len, limit, audit_events).map(|token| PageInfo {
        next_page_token: Some(token),
    })
}

pub(in crate::web::management::audit_events) fn collect_redacted_audit_events(
    rows: &[PgRow],
    limit: i64,
    request_id: &str,
) -> Result<Vec<AuditEvent>, Response> {
    collect_page_rows_result(rows, limit, |row| {
        let mut event = audit_event_from_row_result(row, request_id)?;
        redact_audit_event(&mut event);
        Ok(event)
    })
}
