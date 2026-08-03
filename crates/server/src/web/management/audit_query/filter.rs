use std::fmt::Write as _;

use super::types::AuditEventListQuery;

/// Build dynamic SQL filter clause and return the clause string + next bind index.
pub(in crate::web::management) fn build_audit_filter_sql(
    query: &AuditEventListQuery,
    base_bind_idx: usize,
) -> (String, usize) {
    let mut sql = String::new();
    let mut idx = base_bind_idx;

    if query.event_type.is_some() {
        idx += 1;
        let _ = write!(sql, " AND event_type = ${idx}");
    }
    if query.category.is_some() {
        idx += 1;
        let _ = write!(sql, " AND category = ${idx}");
    }
    if query.target_type.is_some() {
        idx += 1;
        let _ = write!(sql, " AND target_type = ${idx}");
    }
    if query.outcome.is_some() {
        idx += 1;
        let _ = write!(sql, " AND outcome = ${idx}");
    }
    if query.severity.is_some() {
        idx += 1;
        let _ = write!(sql, " AND severity = ${idx}");
    }
    if query.from.is_some() {
        idx += 1;
        let _ = write!(sql, " AND occurred_at >= ${idx}::timestamptz");
    }
    if query.to.is_some() {
        idx += 1;
        let _ = write!(sql, " AND occurred_at <= ${idx}::timestamptz");
    }

    (sql, idx)
}
