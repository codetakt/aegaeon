use super::super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
};
use super::super::super::support::parse_team_id_param;
use super::rows::{delete_team_row, lock_team_lifecycle_row, team_has_active_tenants};
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn delete_team_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let team_id = parse_team_id_param(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for team lifecycle operations",
    )
    .await?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for team lifecycle operations",
    )
    .await?;
    if !lock_team_lifecycle_row(&mut tx, team_id, request_id).await? {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Team not found",
            None,
            Some(request_id),
        ));
    }

    if team_has_active_tenants(&mut tx, team_id, request_id).await? {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Team has active tenants",
            None,
            Some(request_id),
        ));
    }

    delete_team_row(&mut tx, team_id, request_id).await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(())
}
