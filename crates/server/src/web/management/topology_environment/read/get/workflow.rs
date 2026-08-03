use super::rows::get_environment_row;
use crate::management::types::Environment;
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    ensure_environment_visible, environment_response_from_row, error_response,
    parse_team_environment_scope,
};
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(in crate::web::management) async fn get_environment_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Environment, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    ensure_environment_visible(pool, team_id, environment_id, session, request_id).await?;

    let Some(row) = get_environment_row(pool, team_id, environment_id, request_id).await? else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Environment not found",
            None,
            Some(request_id),
        ));
    };

    environment_response_from_row(&row, team_id, request_id)
}
