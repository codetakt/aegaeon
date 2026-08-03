use super::super::super::{error_response, parse_uuid_param};
use super::traits::{
    TeamEnvironmentClientScopedPath, TeamEnvironmentConnectionScopedPath,
    TeamEnvironmentOAuthProfileScopedPath, TeamEnvironmentScopedPath, TeamScopedPath,
    TeamTenantScopedPath,
};
use axum::{http::StatusCode, response::Response};
use uuid::Uuid;

pub(in crate::web::management) fn missing_scope_param(request_id: &str, name: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        &format!("Missing {name}"),
        None,
        Some(request_id),
    )
}

pub(in crate::web::management) fn require_non_empty_path_value(
    value: &str,
    key: &str,
    request_id: &str,
) -> Result<String, Response> {
    let value = value.trim();
    if value.is_empty() {
        return Err(missing_scope_param(request_id, key));
    }
    Ok(value.to_string())
}

pub(in crate::web::management) fn parse_team_scope<P>(
    params: &P,
    request_id: &str,
) -> Result<Uuid, Response>
where
    P: TeamScopedPath,
{
    parse_uuid_param(params.team_id_raw(), "teamId", request_id)
}

pub(in crate::web::management) fn parse_team_tenant_scope<P>(
    params: &P,
    request_id: &str,
) -> Result<(Uuid, Uuid), Response>
where
    P: TeamTenantScopedPath,
{
    Ok((
        parse_team_scope(params, request_id)?,
        parse_uuid_param(params.tenant_id_raw(), "tenantId", request_id)?,
    ))
}

pub(in crate::web::management) fn parse_team_environment_scope<P>(
    params: &P,
    request_id: &str,
) -> Result<(Uuid, Uuid), Response>
where
    P: TeamEnvironmentScopedPath,
{
    Ok((
        parse_team_scope(params, request_id)?,
        parse_uuid_param(params.environment_id_raw(), "environmentId", request_id)?,
    ))
}

pub(in crate::web::management) fn parse_team_environment_client_scope<P>(
    params: &P,
    request_id: &str,
) -> Result<(Uuid, Uuid, Uuid), Response>
where
    P: TeamEnvironmentClientScopedPath,
{
    Ok((
        parse_team_scope(params, request_id)?,
        parse_uuid_param(params.environment_id_raw(), "environmentId", request_id)?,
        parse_uuid_param(params.client_id_raw(), "clientId", request_id)?,
    ))
}

pub(in crate::web::management) fn parse_team_environment_oauth_profile_scope<P>(
    params: &P,
    request_id: &str,
) -> Result<(Uuid, Uuid, Uuid), Response>
where
    P: TeamEnvironmentOAuthProfileScopedPath,
{
    Ok((
        parse_team_scope(params, request_id)?,
        parse_uuid_param(params.environment_id_raw(), "environmentId", request_id)?,
        parse_uuid_param(params.oauth_profile_id_raw(), "oauthProfileId", request_id)?,
    ))
}

pub(in crate::web::management) fn parse_team_environment_connection_scope<P>(
    params: &P,
    request_id: &str,
) -> Result<(Uuid, Uuid, Uuid), Response>
where
    P: TeamEnvironmentConnectionScopedPath,
{
    Ok((
        parse_team_scope(params, request_id)?,
        parse_uuid_param(params.environment_id_raw(), "environmentId", request_id)?,
        parse_uuid_param(params.connection_id_raw(), "connectionId", request_id)?,
    ))
}

pub(in crate::web::management) fn parse_optional_uuid_param(
    value: Option<&str>,
    key: &str,
    request_id: &str,
) -> Result<Option<Uuid>, Response> {
    match value {
        Some(raw) => parse_uuid_param(raw, key, request_id).map(Some),
        None => Ok(None),
    }
}
