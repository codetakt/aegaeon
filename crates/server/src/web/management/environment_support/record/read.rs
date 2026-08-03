use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use super::super::super::{management_environment_not_found, management_internal_error};
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
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?
    else {
        return Err(management_environment_not_found(request_id));
    };

    management_environment_record_from_row(team_id, environment_id, row, request_id)
}
