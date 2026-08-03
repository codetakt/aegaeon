use super::super::parsing::TeamEnvironmentScopedPath;
use super::super::ManagementEnvironmentScope;
use super::environment::require_environment_lifecycle_scope;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(in crate::web::management) async fn require_federation_lifecycle_scope<P>(
    pool: &PgPool,
    params: &P,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<ManagementEnvironmentScope, Response>
where
    P: TeamEnvironmentScopedPath,
{
    require_environment_lifecycle_scope(pool, params, session, request_id, forbidden_message).await
}

pub(in crate::web::management) async fn require_federation_lifecycle_resource_scope<P>(
    pool: &PgPool,
    params: &P,
    resource_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<(ManagementEnvironmentScope, Uuid), Response>
where
    P: TeamEnvironmentScopedPath,
{
    let scope =
        require_federation_lifecycle_scope(pool, params, session, request_id, forbidden_message)
            .await?;
    Ok((scope, resource_id))
}
