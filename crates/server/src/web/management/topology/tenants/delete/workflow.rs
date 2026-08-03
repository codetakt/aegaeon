use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    parse_team_tenant_scope, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction,
};
use super::rows::{delete_tenant_row, lock_tenant_lifecycle_row, tenant_has_active_environments};
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(super) async fn delete_tenant_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamTenantPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let (team_id, tenant_id) = parse_team_tenant_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for tenant lifecycle operations",
    )
    .await?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for tenant lifecycle operations",
    )
    .await?;
    if !lock_tenant_lifecycle_row(&mut tx, team_id, tenant_id, request_id).await? {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Tenant not found",
            None,
            Some(request_id),
        ));
    }

    if tenant_has_active_environments(&mut tx, team_id, tenant_id, request_id).await? {
        return Err(error_response(
            StatusCode::CONFLICT,
            "conflict",
            "Tenant has active environments",
            None,
            Some(request_id),
        ));
    }

    delete_tenant_row(&mut tx, team_id, tenant_id, request_id).await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(())
}
