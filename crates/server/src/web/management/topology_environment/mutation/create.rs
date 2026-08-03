use super::super::super::topology_support::{
    build_initial_environment_configuration, create_environment_with_initial_configuration,
    lock_environment_creation_parent, parse_create_environment_input,
};
use super::super::super::{
    begin_management_transaction, commit_management_transaction, error_response,
    management_db_pool, require_management_session_async,
    require_team_lifecycle_role_in_transaction, require_tenant_lifecycle_scope, AppState,
    RequestContext,
};
use crate::management::types::{CreateEnvironmentRequest, Environment};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Extension, Json,
};

pub(in crate::web::management) async fn create_environment(
    State(state): State<AppState>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    Path(params): Path<crate::web::management::TeamTenantPath>,
    Json(req): Json<CreateEnvironmentRequest>,
) -> Response {
    let pool = match management_db_pool(&state, &ctx.request_id) {
        Ok(pool) => pool,
        Err(resp) => return resp,
    };
    let session = match require_management_session_async(&state, &headers, &ctx.request_id).await {
        Ok(session) => session,
        Err(resp) => return resp,
    };
    let scope = match require_tenant_lifecycle_scope(
        pool,
        &params,
        &session,
        &ctx.request_id,
        "Insufficient permissions for environment lifecycle operations",
    )
    .await
    {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };
    let input = match parse_create_environment_input(&req, &ctx.request_id) {
        Ok(input) => input,
        Err(resp) => return resp,
    };
    let mut tx = match begin_management_transaction(pool, &ctx.request_id).await {
        Ok(tx) => tx,
        Err(resp) => return resp,
    };
    if let Err(resp) = require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        &session,
        &ctx.request_id,
        "Insufficient permissions for environment lifecycle operations",
    )
    .await
    {
        return resp;
    }
    let scope = match lock_environment_creation_parent(&mut tx, &scope, &ctx.request_id).await {
        Ok(Some(scope)) => scope,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "not_found",
                "Tenant not found",
                None,
                Some(ctx.request_id.as_str()),
            );
        }
        Err(resp) => return resp,
    };
    let configuration = match build_initial_environment_configuration(
        state.management.cfg.issuer_base_domain.as_str(),
        &scope,
        &input,
        &ctx.request_id,
    ) {
        Ok(configuration) => configuration,
        Err(resp) => return resp,
    };
    let created = match create_environment_with_initial_configuration(
        &mut tx,
        &scope,
        &input,
        &configuration,
        session.administrator_id,
        &ctx.request_id,
    )
    .await
    {
        Ok(created) => created,
        Err(resp) => return resp,
    };
    if let Err(resp) = commit_management_transaction(tx, &ctx.request_id).await {
        return resp;
    }

    let environment = Environment {
        id: created.environment_id.to_string(),
        team_id: scope.team.to_string(),
        tenant_id: scope.tenant.to_string(),
        name: input.name,
        slug: input.slug,
        issuer_host: configuration.issuer_host,
        issuer_url: configuration.issuer_url,
        active_configuration_version_id: created.configuration_version_id.to_string(),
        created_at: created.created_at,
        updated_at: created.updated_at,
    };
    (StatusCode::CREATED, Json(environment)).into_response()
}
