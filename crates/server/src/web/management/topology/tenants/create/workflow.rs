use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response, parse_team_scope,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
    tenant_response_from_row,
};
use super::rows::{insert_tenant_row, lock_active_team_for_tenant_creation};
use crate::management::types::{CreateTenantRequest, Tenant};
use crate::web::management::state::ManagementSession;
use crate::web::management::topology_support::parse_create_tenant_input;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn create_tenant_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamPath,
    req: &CreateTenantRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Tenant, Response> {
    let team_id = parse_team_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for tenant lifecycle operations",
    )
    .await?;

    let input = parse_create_tenant_input(req, request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for tenant lifecycle operations",
    )
    .await?;
    if !lock_active_team_for_tenant_creation(&mut tx, team_id, request_id).await? {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Team not found",
            None,
            Some(request_id),
        ));
    }
    let row = insert_tenant_row(&mut tx, team_id, &input, request_id).await?;
    commit_management_transaction(tx, request_id).await?;

    tenant_response_from_row(&row, team_id, request_id)
}
