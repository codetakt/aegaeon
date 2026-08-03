pub(super) fn load_user_for_status_sql(status_filter_sql: &str) -> String {
    format!(
        r#"
SELECT
  u.id,
  u.environment_id,
  u.subject,
  u.email,
  u.status::text AS status,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.end_users u
JOIN aegaeon.environments e ON e.id = u.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.id = $1
  AND u.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
  {status_filter_sql}
FOR UPDATE OF u
        "#,
    )
}

pub(super) fn update_user_status_sql(status_filter_sql: &str, set_clause_sql: &str) -> String {
    format!(
        r#"
UPDATE aegaeon.end_users u
SET
  {set_clause_sql}
FROM aegaeon.environments e
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE u.id = $1
  AND u.environment_id = $2
  AND u.environment_id = e.id
  {status_filter_sql}
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
RETURNING
  u.id,
  u.environment_id,
  u.subject,
  u.email,
  u.status::text AS status,
  to_char(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
}
