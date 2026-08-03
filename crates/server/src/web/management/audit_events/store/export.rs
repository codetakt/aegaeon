use super::super::super::audit_query::{build_audit_filter_sql, AuditEventListQuery};
use super::super::super::management_internal_error;
use super::super::scope::{AuditScope, AuditWindow};
use super::query::{bind_audit_filters, bind_audit_scope};
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};

pub(in crate::web::management::audit_events) async fn fetch_audit_export_rows(
    pool: &PgPool,
    scope: AuditScope,
    query: &AuditEventListQuery,
    window: &AuditWindow,
    export_limit: i64,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    let (filter_sql, last_idx) = build_audit_filter_sql(query, scope.base_bind_idx());
    let limit_idx = last_idx + 1;
    let sql = format!(
        r#"
SELECT
  id, team_id, tenant_id, environment_id,
  event_type, category, outcome, severity,
  to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS occurred_at,
  actor_type, actor_id, host(ip_address)::text AS ip_address, user_agent, mfa,
  target_type, target_id,
  request_id, trace_id, span_id,
  from_configuration_version_id, to_configuration_version_id,
  json_patch, data
FROM aegaeon.audit_events
WHERE {}{filter_sql}
ORDER BY occurred_at DESC, id DESC
LIMIT ${limit_idx}
        "#,
        scope.where_clause(),
    );

    let query_builder =
        bind_audit_filters(bind_audit_scope(sqlx::query(&sql), scope), query, window)
            .bind(export_limit);

    let Ok(rows) = query_builder.fetch_all(pool).await else {
        return Err(management_internal_error(
            request_id,
            "Database query failed",
        ));
    };

    Ok(rows)
}
