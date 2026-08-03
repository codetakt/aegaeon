use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use super::super::super::super::oauth_profile_store::{
    load_oauth_profile, oauth_profile_not_found,
};
use super::super::super::super::oauth_profiles_support::{
    oauth_profile_input_from_update, validate_oauth_profile_input, OAuthProfileInput,
};
use super::super::super::super::{
    load_management_configuration_policy, parse_uuid_param, validate_expires_at,
    ManagementEnvironmentRecord,
};
use crate::management::types::{OAuthProfile, UpdateOAuthProfileRequest};

#[derive(Clone, Debug)]
pub(super) struct PreparedOAuthProfileUpdate {
    pub(super) existing_profile: OAuthProfile,
    pub(super) input: OAuthProfileInput,
    pub(super) configuration_version_id: Uuid,
}

pub(super) async fn prepare_oauth_profile_update(
    pool: &PgPool,
    environment: &ManagementEnvironmentRecord,
    oauth_profile_id: Uuid,
    req: &UpdateOAuthProfileRequest,
    request_id: &str,
) -> Result<PreparedOAuthProfileUpdate, Response> {
    let Some(existing_profile) = load_oauth_profile(
        pool,
        environment.scope.team,
        environment.scope.environment,
        oauth_profile_id,
        request_id,
    )
    .await?
    else {
        return Err(oauth_profile_not_found(request_id));
    };

    let configuration_version_id = parse_uuid_param(
        &existing_profile.configuration_version_id,
        "configurationVersionId",
        request_id,
    )?;
    let mut input = oauth_profile_input_from_update(&existing_profile, req);
    validate_expires_at(pool, input.expires_at.as_deref(), request_id).await?;
    let policy = load_management_configuration_policy(
        pool,
        environment,
        configuration_version_id,
        request_id,
    )
    .await?;
    validate_oauth_profile_input(&mut input, &policy, request_id)?;

    Ok(PreparedOAuthProfileUpdate {
        existing_profile,
        input,
        configuration_version_id,
    })
}
