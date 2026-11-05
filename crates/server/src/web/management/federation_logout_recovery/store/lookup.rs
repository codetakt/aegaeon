use super::super::super::ManagementEnvironmentScope;
use super::projection;
use crate::web::management::http_errors::management_database_error as database_error;
use axum::response::Response;
use sqlx::{postgres::PgRow, Executor, Postgres};
use uuid::Uuid;

pub(in crate::web::management::federation_logout_recovery) async fn load_federation_logout_recovery_incident_row<
    'e,
    E,
>(
    executor: E,
    scope: ManagementEnvironmentScope,
    incident_id: Uuid,
    lock_for_update: bool,
    request_id: &str,
    error_message: &str,
) -> Result<Option<PgRow>, Response>
where
    E: Executor<'e, Database = Postgres>,
{
    let sql = projection::federation_logout_recovery_incident_select_sql(lock_for_update);
    sqlx::query(&sql)
        .bind(scope.team)
        .bind(scope.environment)
        .bind(incident_id)
        .fetch_optional(executor)
        .await
        .map_err(|error| database_error(request_id, &error, error_message))
}
