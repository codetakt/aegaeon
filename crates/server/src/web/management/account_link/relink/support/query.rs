use super::super::super::super::{
    account_link_from_row_result, management_internal_error, ManagementEnvironmentScope,
};
use super::errors::account_links_not_found;
use crate::management::types::AccountLinkSummary;
use axum::response::Response;
use sqlx::{Executor, Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) const LOAD_ACCOUNT_LINK_SUMMARIES_BY_IDS_SQL: &str = r#"
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
WHERE al.id = ANY($1::uuid[])
  AND al.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
        "#;

const LOAD_ACCOUNT_LINK_SUMMARIES_BY_IDS_FOR_UPDATE_SQL: &str = r#"
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
WHERE al.id = ANY($1::uuid[])
  AND al.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
ORDER BY al.id
FOR UPDATE OF al
        "#;

pub(in crate::web::management::account_link::relink) async fn load_account_link_summaries_by_ids<
    'e,
    E,
>(
    executor: E,
    scope: ManagementEnvironmentScope,
    account_link_ids: &[Uuid],
    request_id: &str,
) -> Result<Vec<AccountLinkSummary>, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    load_account_link_summaries_by_ids_with_sql(
        executor,
        LOAD_ACCOUNT_LINK_SUMMARIES_BY_IDS_SQL,
        scope,
        account_link_ids,
        request_id,
    )
    .await
}

pub(in crate::web::management::account_link::relink) async fn load_account_link_summaries_by_ids_for_update(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    account_link_ids: &[Uuid],
    request_id: &str,
) -> Result<Vec<AccountLinkSummary>, Response> {
    load_account_link_summaries_by_ids_with_sql(
        &mut **tx,
        LOAD_ACCOUNT_LINK_SUMMARIES_BY_IDS_FOR_UPDATE_SQL,
        scope,
        account_link_ids,
        request_id,
    )
    .await
}

async fn load_account_link_summaries_by_ids_with_sql<'e, E>(
    executor: E,
    sql: &str,
    scope: ManagementEnvironmentScope,
    account_link_ids: &[Uuid],
    request_id: &str,
) -> Result<Vec<AccountLinkSummary>, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let rows = sqlx::query(sql)
        .bind(account_link_ids)
        .bind(scope.environment)
        .bind(scope.team)
        .fetch_all(executor)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    if rows.len() != account_link_ids.len() {
        return Err(account_links_not_found(request_id));
    }

    let account_links = rows
        .iter()
        .map(|row| account_link_from_row_result(row, request_id))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(account_links)
}
