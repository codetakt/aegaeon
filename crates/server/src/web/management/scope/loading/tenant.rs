use super::super::super::{
    load_tenant_slug_and_region, management_internal_error, management_tenant_not_found,
};
use super::super::parsing::{parse_team_tenant_scope, TeamTenantScopedPath};
use super::super::roles::{ensure_team_visible_as, require_team_lifecycle_role};
use super::super::ManagementTenantScope;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

async fn load_management_tenant_scope(
    pool: &PgPool,
    team_id: Uuid,
    tenant_id: Uuid,
    request_id: &str,
) -> Result<ManagementTenantScope, Response> {
    let tenant = load_tenant_slug_and_region(pool, team_id, tenant_id)
        .await
        .map_err(|_| management_internal_error(request_id, "Database query failed"))?
        .ok_or_else(|| management_tenant_not_found(request_id))?;

    Ok(ManagementTenantScope {
        team: team_id,
        tenant: tenant_id,
        slug: tenant.0,
        region: tenant.1,
    })
}

pub(in crate::web::management) async fn ensure_tenant_visible(
    pool: &PgPool,
    team_id: Uuid,
    tenant_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ManagementTenantScope, Response> {
    ensure_team_visible_as(
        pool,
        team_id,
        session,
        request_id,
        management_tenant_not_found,
    )
    .await?;
    load_management_tenant_scope(pool, team_id, tenant_id, request_id).await
}

pub(in crate::web::management) async fn require_tenant_lifecycle_scope<P>(
    pool: &PgPool,
    params: &P,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<ManagementTenantScope, Response>
where
    P: TeamTenantScopedPath,
{
    let (team_id, tenant_id) = parse_team_tenant_scope(params, request_id)?;
    require_team_lifecycle_role(pool, team_id, session, request_id, forbidden_message).await?;
    load_management_tenant_scope(pool, team_id, tenant_id, request_id).await
}
