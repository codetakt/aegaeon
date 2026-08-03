use axum::response::Response;
use sqlx::{Executor, Postgres, Transaction};
use uuid::Uuid;

use crate::management::types::AccountLinkSummary;

use super::super::super::super::super::management_internal_error;
use super::super::super::super::mapper::account_link_from_row_result;

pub(in crate::web::management) const LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_SQL: &str = r#"
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
  AND al.upstream_issuer = $3
  AND al.upstream_sub_hash = $4
LIMIT 1
        "#;

const LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_FOR_UPDATE_SQL: &str = r#"
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
  AND al.upstream_issuer = $3
  AND al.upstream_sub_hash = $4
LIMIT 1
FOR UPDATE OF al
        "#;

pub(in crate::web::management) async fn load_account_link_summary_by_upstream_subject<'e, E>(
    executor: E,
    team_id: Uuid,
    environment_id: Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    request_id: &str,
) -> Result<Option<AccountLinkSummary>, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    load_account_link_summary_by_upstream_subject_with_sql(
        executor,
        LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_SQL,
        team_id,
        environment_id,
        upstream_issuer,
        upstream_sub_hash,
        request_id,
    )
    .await
}

pub(in crate::web::management) async fn load_account_link_summary_by_upstream_subject_for_update(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    environment_id: Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    request_id: &str,
) -> Result<Option<AccountLinkSummary>, Response> {
    load_account_link_summary_by_upstream_subject_with_sql(
        &mut **tx,
        LOAD_ACCOUNT_LINK_SUMMARY_BY_UPSTREAM_SUBJECT_FOR_UPDATE_SQL,
        team_id,
        environment_id,
        upstream_issuer,
        upstream_sub_hash,
        request_id,
    )
    .await
}

async fn load_account_link_summary_by_upstream_subject_with_sql<'e, E>(
    executor: E,
    sql: &str,
    team_id: Uuid,
    environment_id: Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
    request_id: &str,
) -> Result<Option<AccountLinkSummary>, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let row = sqlx::query(sql)
        .bind(environment_id)
        .bind(team_id)
        .bind(upstream_issuer)
        .bind(upstream_sub_hash)
        .fetch_optional(executor)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    row.map(|row| account_link_from_row_result(&row, request_id))
        .transpose()
}
