use crate::web::management::http_errors::management_database_error as database_error;
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use super::super::super::management_environment_not_found;
use super::super::rows::load_environment_row;
use super::super::types::ManagementEnvironmentRecord;
use super::mapper::management_environment_record_from_row;

pub(in crate::web::management) async fn load_management_environment_record(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<ManagementEnvironmentRecord, Response> {
    let Some(row) = load_environment_row(pool, team_id, environment_id)
        .await
        .map_err(|error| database_error(request_id, &error, "Database query failed"))?
    else {
        return Err(management_environment_not_found(request_id));
    };

    management_environment_record_from_row(team_id, environment_id, row, request_id)
}
