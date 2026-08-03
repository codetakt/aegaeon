use super::super::{
    parse_team_environment_client_scope, parse_uuid_param, require_team_lifecycle_role,
    state::ManagementSession, TeamEnvironmentClientScopedPath, TeamEnvironmentClientSecretPath,
};
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub(in crate::web::management::client_secrets) struct ClientSecretLifecycleScope {
    pub(in crate::web::management::client_secrets) team_id: Uuid,
    pub(in crate::web::management::client_secrets) environment_id: Uuid,
    pub(in crate::web::management::client_secrets) client_id: Uuid,
    pub(in crate::web::management::client_secrets) base_configuration_version_id: Uuid,
}

pub(super) async fn prepare_client_secret_lifecycle_scope<P>(
    pool: &PgPool,
    params: &P,
    base_configuration_version_id: &str,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ClientSecretLifecycleScope, Response>
where
    P: TeamEnvironmentClientScopedPath,
{
    let (team_id, environment_id, client_id) =
        parse_team_environment_client_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions",
    )
    .await?;

    let base_configuration_version_id = parse_uuid_param(
        base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;

    Ok(ClientSecretLifecycleScope {
        team_id,
        environment_id,
        client_id,
        base_configuration_version_id,
    })
}

pub(super) fn parse_team_environment_client_secret_scope(
    params: &TeamEnvironmentClientSecretPath,
    request_id: &str,
) -> Result<(Uuid, Uuid, Uuid, Uuid), Response> {
    params.ids(request_id)
}
