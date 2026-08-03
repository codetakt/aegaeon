use axum::{http::StatusCode, response::Response};
use sqlx::PgPool;

use super::super::{
    error_response, load_management_environment_scope, parse_team_environment_scope,
    require_team_lifecycle_role, state::ManagementSession, ManagementEnvironmentScope,
    TeamEnvironmentScopedPath,
};

pub(in crate::web::management) fn normalize_account_link_upstream_subject_filter(
    value: Option<&str>,
) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

pub(in crate::web::management) fn parse_account_link_subject(
    value: &str,
    request_id: &str,
) -> Result<String, Response> {
    let subject = value.trim();
    if subject.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "upstreamSubject must not be empty",
            None,
            Some(request_id),
        ));
    }

    Ok(subject.to_string())
}

pub(in crate::web::management) async fn require_account_link_lifecycle_scope<P>(
    pool: &PgPool,
    params: &P,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ManagementEnvironmentScope, Response>
where
    P: TeamEnvironmentScopedPath,
{
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for account link operations",
    )
    .await?;
    load_management_environment_scope(pool, team_id, environment_id, request_id).await
}
