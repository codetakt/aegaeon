use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::super::state::ManagementSession;
use super::super::{
    error_response, load_environment_row, management_db_pool, management_internal_error,
    parse_team_environment_scope, require_management_session_async, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction, AppState, TeamEnvironmentScopedPath,
};

#[derive(Clone)]
pub(in crate::web::management) struct UserManagementContext {
    pub(in crate::web::management) pool: PgPool,
    pub(in crate::web::management) session: ManagementSession,
    pub(in crate::web::management) team_id: Uuid,
    pub(in crate::web::management) environment_id: Uuid,
    pub(in crate::web::management) tenant_id: Uuid,
}

impl UserManagementContext {
    pub(in crate::web::management) async fn require_lifecycle_role_in_transaction(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        request_id: &str,
    ) -> Result<(), Response> {
        require_team_lifecycle_role_in_transaction(
            tx,
            self.team_id,
            &self.session,
            request_id,
            "Insufficient permissions for user operations",
        )
        .await
    }
}

pub(in crate::web::management) async fn require_user_management_scope<P>(
    state: &AppState,
    headers: &HeaderMap,
    params: &P,
    request_id: &str,
) -> Result<(PgPool, ManagementSession, Uuid, Uuid, Uuid), Response>
where
    P: TeamEnvironmentScopedPath,
{
    let pool = management_db_pool(state, request_id)?.clone();
    let session = require_management_session_async(state, headers, request_id).await?;
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;

    require_team_lifecycle_role(
        &pool,
        team_id,
        &session,
        request_id,
        "Insufficient permissions for user operations",
    )
    .await?;

    let Some((tenant_id, _, _, _, _, _, _, _)) =
        load_environment_row(&pool, team_id, environment_id)
            .await
            .map_err(|_| management_internal_error(request_id, "Database query failed"))?
    else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Environment not found",
            None,
            Some(request_id),
        ));
    };

    Ok((pool, session, team_id, environment_id, tenant_id))
}

pub(in crate::web::management) async fn require_user_management_context<P>(
    state: &AppState,
    headers: &HeaderMap,
    params: &P,
    request_id: &str,
) -> Result<UserManagementContext, Response>
where
    P: TeamEnvironmentScopedPath,
{
    let (pool, session, team_id, environment_id, tenant_id) =
        require_user_management_scope(state, headers, params, request_id).await?;

    Ok(UserManagementContext {
        pool,
        session,
        team_id,
        environment_id,
        tenant_id,
    })
}
