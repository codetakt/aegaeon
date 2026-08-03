use super::super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
};
use super::super::super::support::{parse_team_id_param, team_from_management_row};
use super::rows::update_team_row;
use crate::management::types::{Team, UpdateTeamRequest};
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn update_team_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamPath,
    req: &UpdateTeamRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Team, Response> {
    let team_id = parse_team_id_param(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for team lifecycle operations",
    )
    .await?;

    let Some(name) = req.name.as_deref().map(str::trim).filter(|v| !v.is_empty()) else {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "No updatable fields provided",
            None,
            Some(request_id),
        ));
    };

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for team lifecycle operations",
    )
    .await?;

    let Some(row) = update_team_row(&mut tx, team_id, name, request_id).await? else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Team not found",
            None,
            Some(request_id),
        ));
    };

    let team = team_from_management_row(&row, request_id)?;
    commit_management_transaction(tx, request_id).await?;

    Ok(team)
}
