use super::super::super::{
    load_management_environment_scope, parse_team_environment_scope, parse_team_scope,
    require_team_audit_read_access, TeamEnvironmentScopedPath, TeamScopedPath,
};
use super::AuditScope;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(in crate::web::management::audit_events) async fn require_team_audit_scope<P>(
    pool: &PgPool,
    params: &P,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<AuditScope, Response>
where
    P: TeamScopedPath,
{
    let team_id = parse_team_scope(params, request_id)?;
    require_team_audit_read_access(pool, team_id, session, request_id, forbidden_message).await?;
    Ok(AuditScope::team(team_id))
}

pub(in crate::web::management::audit_events) async fn require_environment_audit_scope<P>(
    pool: &PgPool,
    params: &P,
    session: &ManagementSession,
    request_id: &str,
    forbidden_message: &str,
) -> Result<AuditScope, Response>
where
    P: TeamEnvironmentScopedPath,
{
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    require_team_audit_read_access(pool, team_id, session, request_id, forbidden_message).await?;
    let scope =
        load_management_environment_scope(pool, team_id, environment_id, request_id).await?;
    Ok(AuditScope::environment(scope))
}
