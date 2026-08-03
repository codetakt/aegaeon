use super::super::super::{management_internal_error, ManagementEnvironmentScope};
use super::super::filters::FederationLogoutRecoveryIncidentFilters;
use super::projection::FederationLogoutRecoveryIncidentProjection;
use axum::response::Response;
use sqlx::{postgres::PgRow, PgPool, Postgres, QueryBuilder};

pub(in crate::web::management::federation_logout_recovery) async fn list_federation_logout_recovery_incident_rows(
    pool: &PgPool,
    scope: ManagementEnvironmentScope,
    filters: &FederationLogoutRecoveryIncidentFilters,
    cursor_created_at: Option<&str>,
    cursor_id: Option<&str>,
    limit: i64,
    request_id: &str,
) -> Result<Vec<PgRow>, Response> {
    let projection = FederationLogoutRecoveryIncidentProjection::new();
    let mut query = QueryBuilder::<Postgres>::new(format!(
        r"
{select_sql}
FROM aegaeon.federation_logout_recovery_incidents fri
LEFT JOIN aegaeon.connections c
  ON c.id = fri.connection_id
WHERE fri.team_id = ",
        select_sql = projection.select_sql()
    ));
    query.push_bind(scope.team);
    query.push(" AND fri.environment_id = ");
    query.push_bind(scope.environment);
    if let Some(connection_id) = filters.connection_id {
        query.push(" AND fri.connection_id = ");
        query.push_bind(connection_id);
    }
    if let Some(status) = filters.status.as_deref() {
        query.push(" AND ");
        query.push(projection.status_sql());
        query.push(" = ");
        query.push_bind(status);
    }
    if let Some(recovery_policy) = filters.recovery_policy.as_deref() {
        query.push(" AND fri.recovery_policy = ");
        query.push_bind(recovery_policy);
    }
    query.push(" AND (");
    query.push_bind(cursor_created_at);
    query.push("::timestamptz IS NULL OR (fri.created_at, fri.id) < (");
    query.push_bind(cursor_created_at);
    query.push("::timestamptz, ");
    query.push_bind(cursor_id);
    query.push("::uuid))");
    query.push(
        r"
ORDER BY fri.created_at DESC, fri.id DESC
LIMIT ",
    );
    query.push_bind(limit);

    query
        .build()
        .fetch_all(pool)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))
}
