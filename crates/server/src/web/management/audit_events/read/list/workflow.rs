use super::super::super::super::audit_cursor_from_page_token;
use super::super::super::super::audit_query::{audit_list_limit, AuditEventListQuery};
use super::super::super::scope::{require_audit_window, AuditScope};
use super::super::super::store::{
    audit_page_info, collect_redacted_audit_events, fetch_audit_list_rows,
};
use crate::management::types::ListAuditEventsResponse;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn list_audit_events_inner(
    pool: &PgPool,
    scope: AuditScope,
    query: AuditEventListQuery,
    request_id: &str,
) -> Result<ListAuditEventsResponse, Response> {
    let window = require_audit_window(query.from.as_deref(), query.to.as_deref(), request_id)?;
    let limit = audit_list_limit(query.page_size);
    let limit_plus_one = limit.saturating_add(1);
    let cursor = audit_cursor_from_page_token(query.page_token.as_deref(), request_id)?;
    let rows = fetch_audit_list_rows(
        pool,
        scope,
        &query,
        &window,
        cursor.as_ref(),
        limit_plus_one,
        request_id,
    )
    .await?;
    let audit_events = collect_redacted_audit_events(&rows, limit, request_id)?;

    Ok(ListAuditEventsResponse {
        page_info: audit_page_info(rows.len(), limit, &audit_events),
        audit_events,
    })
}
