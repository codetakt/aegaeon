use super::super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    insert_team_owner_membership, insert_team_record,
};
use crate::management::types::{CreateTeamRequest, Team};
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn create_team_inner(
    pool: &PgPool,
    req: &CreateTeamRequest,
    administrator_id: Uuid,
    request_id: &str,
) -> Result<Team, Response> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Team name must not be empty",
            None,
            Some(request_id),
        ));
    }
    let slug = req
        .slug
        .as_deref()
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty());

    let mut tx = begin_management_transaction(pool, request_id).await?;
    let (team_id, team) = insert_team_record(&mut tx, name, slug.as_deref(), request_id).await?;
    insert_team_owner_membership(&mut tx, team_id, administrator_id, request_id).await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(team)
}
