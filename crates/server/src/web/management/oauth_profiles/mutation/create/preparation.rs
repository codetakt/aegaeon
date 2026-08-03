use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use super::super::super::super::oauth_profiles_support::{
    oauth_profile_input_from_create, validate_oauth_profile_input, OAuthProfileInput,
};
use super::super::super::super::{
    load_management_configuration_policy, resolve_management_configuration_version,
    validate_expires_at, ManagementEnvironmentRecord,
};
use super::super::super::query::OAuthProfileListQuery;
use crate::management::types::CreateOAuthProfileRequest;

#[derive(Clone, Debug)]
pub(super) struct PreparedOAuthProfileCreate {
    pub(super) input: OAuthProfileInput,
    pub(super) configuration_version_id: Uuid,
}

pub(super) async fn prepare_oauth_profile_create(
    pool: &PgPool,
    environment: &ManagementEnvironmentRecord,
    query: &OAuthProfileListQuery,
    req: &CreateOAuthProfileRequest,
    request_id: &str,
) -> Result<PreparedOAuthProfileCreate, Response> {
    let configuration_version_id = resolve_management_configuration_version(
        query.configuration_version_id.as_deref(),
        environment.active_configuration_version_id,
        request_id,
    )?;
    let mut input = oauth_profile_input_from_create(req);
    validate_expires_at(pool, input.expires_at.as_deref(), request_id).await?;
    let policy = load_management_configuration_policy(
        pool,
        environment,
        configuration_version_id,
        request_id,
    )
    .await?;
    validate_oauth_profile_input(&mut input, &policy, request_id)?;

    Ok(PreparedOAuthProfileCreate {
        input,
        configuration_version_id,
    })
}
