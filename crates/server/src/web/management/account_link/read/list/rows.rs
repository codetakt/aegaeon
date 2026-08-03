use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool};
use uuid::Uuid;

use super::super::super::super::management_internal_error;
use super::super::filters::AccountLinkListFilters;
use crate::upstream::upstream_subject_link_hash;
use crate::web::management::pagination::KeysetPagination;

pub(in crate::web::management) const LIST_ACCOUNT_LINK_ROWS_SQL: &str = r#"
SELECT
  al.id,
  al.environment_id,
  al.connection_id,
  c.connection_identifier,
  c.name AS connection_name,
  al.upstream_issuer,
  al.end_user_id,
  u.subject AS end_user_subject,
  u.email AS end_user_email,
  u.status::text AS end_user_status,
  (al.upstream_refresh_token_encrypted IS NOT NULL) AS has_refresh_token,
  to_char(al.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_cursor,
  al.id::text AS id_cursor,
  to_char(al.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(al.last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS last_used_at
FROM aegaeon.account_links al
JOIN aegaeon.connections c ON c.id = al.connection_id AND c.environment_id = al.environment_id
JOIN aegaeon.end_users u ON u.id = al.end_user_id AND u.environment_id = al.environment_id
JOIN aegaeon.environments e ON e.id = al.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE al.environment_id = $1
  AND t.team_id = $2
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
  AND ($3::text IS NULL OR al.upstream_issuer ILIKE '%' || $3 || '%')
  AND (NOT $4::boolean OR al.upstream_sub_hash = ANY($5::text[]))
  AND ($6::text IS NULL OR u.subject ILIKE '%' || $6 || '%')
  AND ($7::text IS NULL OR COALESCE(u.email, '') ILIKE '%' || $7 || '%')
  AND ($8::text IS NULL OR c.connection_identifier ILIKE '%' || $8 || '%')
  AND ($9::timestamptz IS NULL OR (al.created_at, al.id) > ($9::timestamptz, $10::uuid))
ORDER BY al.created_at ASC, al.id ASC
LIMIT $11
        "#;

pub(super) async fn load_account_link_subject_hash_candidates(
    pool: &PgPool,
    environment_id: Uuid,
    upstream_subject: &str,
    request_id: &str,
) -> Result<Vec<String>, Response> {
    let issuers = sqlx::query_scalar::<_, String>(
        r"
SELECT DISTINCT upstream_issuer
FROM aegaeon.account_links
WHERE environment_id = $1
ORDER BY upstream_issuer ASC
        ",
    )
    .bind(environment_id)
    .fetch_all(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    Ok(issuers
        .iter()
        .map(|issuer| upstream_subject_link_hash(issuer, upstream_subject))
        .collect())
}

pub(super) async fn list_account_link_rows(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    filters: &AccountLinkListFilters,
    pagination: &KeysetPagination,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    sqlx::query(LIST_ACCOUNT_LINK_ROWS_SQL)
        .bind(environment_id)
        .bind(team_id)
        .bind(&filters.upstream_issuer)
        .bind(filters.upstream_subject_filter_enabled)
        .bind(&filters.upstream_subject_hashes)
        .bind(&filters.end_user_subject)
        .bind(&filters.end_user_email)
        .bind(&filters.connection_identifier)
        .bind(pagination.cursor_value(0))
        .bind(pagination.cursor_value(1))
        .bind(pagination.limit.saturating_add(1))
        .fetch_all(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
