use super::super::super::{management_internal_error, ManagementEnvironmentScope};
use super::projection;
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
        .map_err(|_| management_internal_error(request_id, error_message))
}
