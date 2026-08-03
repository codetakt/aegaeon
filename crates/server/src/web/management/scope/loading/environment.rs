use super::super::super::{
    load_environment_row, management_environment_not_found, management_internal_error,
};
use super::super::parsing::{parse_team_environment_scope, TeamEnvironmentScopedPath};
use super::super::roles::{ensure_team_visible_as, require_team_lifecycle_role};
use super::super::{ManagementEnvironmentIssuerScope, ManagementEnvironmentScope};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(in crate::web::management) async fn ensure_environment_visible(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    ensure_team_visible_as(
        pool,
        team_id,
        session,
        request_id,
        management_environment_not_found,
    )
    .await?;

    load_management_environment_scope(pool, team_id, environment_id, request_id)
        .await
        .map(|_| ())
}

pub(in crate::web::management) async fn load_management_environment_scope(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<ManagementEnvironmentScope, Response> {
    load_management_environment_scope_with_issuer(pool, team_id, environment_id, request_id)
        .await
        .map(|scope| scope.scope)
}

pub(in crate::web::management) async fn load_management_environment_scope_with_issuer(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<ManagementEnvironmentIssuerScope, Response> {
    let Some((tenant_id, _, _, issuer_host, _, _, _, _)) =
        load_environment_row(pool, team_id, environment_id)
            .await
            .map_err(|_| management_internal_error(request_id, "Database query failed"))?
    else {
        return Err(management_environment_not_found(request_id));
    };

    Ok(ManagementEnvironmentIssuerScope {
        scope: ManagementEnvironmentScope {
            team: team_id,
            tenant: tenant_id,
            environment: environment_id,
        },
        issuer_host,
    })
}

pub(in crate::web::management) async fn require_environment_lifecycle_scope<P>(
    pool: &PgPool,
    params: &P,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<ManagementEnvironmentScope, Response>
where
    P: TeamEnvironmentScopedPath,
{
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    require_environment_lifecycle_scope_by_ids(
        pool,
        team_id,
        environment_id,
        session,
        request_id,
        forbidden_message,
    )
    .await
}

pub(in crate::web::management) async fn require_environment_lifecycle_scope_by_ids(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<ManagementEnvironmentScope, Response> {
    require_team_lifecycle_role(pool, team_id, session, request_id, forbidden_message).await?;
    load_management_environment_scope(pool, team_id, environment_id, request_id).await
}

pub(in crate::web::management) async fn require_environment_lifecycle_scope_with_issuer_by_ids(
    pool: &PgPool,
    team_id: Uuid,
    environment_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<ManagementEnvironmentIssuerScope, Response> {
    require_team_lifecycle_role(pool, team_id, session, request_id, forbidden_message).await?;
    load_management_environment_scope_with_issuer(pool, team_id, environment_id, request_id).await
}
