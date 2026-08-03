use super::super::super::support::{parse_team_id_param, team_from_management_row};
use super::rows::get_team_row;
use crate::management::types::Team;
use crate::web::management::{ensure_team_visible, error_response, state::ManagementSession};
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(in crate::web::management) async fn get_team_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Team, Response> {
    let team_id = parse_team_id_param(params, request_id)?;
    ensure_team_visible(pool, team_id, session, request_id).await?;
    let Some(row) = get_team_row(pool, team_id, session.administrator_id, request_id).await? else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Team not found",
            None,
            Some(request_id),
        ));
    };

    team_from_management_row(&row, request_id)
}
