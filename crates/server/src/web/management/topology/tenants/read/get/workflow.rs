use super::super::super::super::super::{
    ensure_tenant_visible, error_response, parse_team_tenant_scope, tenant_response_from_row,
};
use super::rows::get_tenant_row;
use crate::management::types::Tenant;
use crate::web::management::state::ManagementSession;
use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

pub(in crate::web::management) async fn get_tenant_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamTenantPath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<Tenant, Response> {
    let (team_id, tenant_id) = parse_team_tenant_scope(params, request_id)?;
    ensure_tenant_visible(pool, team_id, tenant_id, session, request_id).await?;

    let Some(row) = get_tenant_row(pool, team_id, tenant_id, request_id).await? else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Tenant not found",
            None,
            Some(request_id),
        ));
    };

    tenant_response_from_row(&row, team_id, request_id)
}
