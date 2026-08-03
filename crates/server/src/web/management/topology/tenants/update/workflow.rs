use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    parse_team_tenant_scope, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction, tenant_response_from_row,
};
use super::rows::update_tenant_row;
use crate::management::types::{Tenant, UpdateTenantRequest};
use crate::web::management::state::ManagementSession;
use crate::web::management::topology_support::parse_update_name;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn update_tenant_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamTenantPath,
    req: &UpdateTenantRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Tenant, Response> {
    let (team_id, tenant_id) = parse_team_tenant_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for tenant lifecycle operations",
    )
    .await?;
    let name = parse_update_name(req.name.as_deref(), request_id)?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for tenant lifecycle operations",
    )
    .await?;

    let Some(row) = update_tenant_row(&mut tx, team_id, tenant_id, &name, request_id).await? else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Tenant not found",
            None,
            Some(request_id),
        ));
    };

    let tenant = tenant_response_from_row(&row, team_id, request_id)?;
    commit_management_transaction(tx, request_id).await?;

    Ok(tenant)
}
