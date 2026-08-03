use super::super::super::super::oauth_profile_store::{
    clear_default_oauth_profiles, oauth_profile_from_row_result, oauth_profile_not_found,
    update_oauth_profile_row,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record,
    load_management_environment_record_for_update, parse_team_environment_oauth_profile_scope,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
};
use super::super::super::audit::{oauth_profile_audit_context, write_oauth_profile_updated_audit};
use super::super::metrics::record_oauth_profile_metric;
use super::preparation::{prepare_oauth_profile_update, PreparedOAuthProfileUpdate};
use crate::management::types::{OAuthProfileMutationResponse, UpdateOAuthProfileRequest};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn update_oauth_profile_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentOAuthProfilePath,
    req: &UpdateOAuthProfileRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<OAuthProfileMutationResponse, Response> {
    let (team_id, environment_id, oauth_profile_id) =
        parse_team_environment_oauth_profile_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for oauth profile operations",
    )
    .await?;

    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    let PreparedOAuthProfileUpdate {
        existing_profile,
        input,
        configuration_version_id,
    } = prepare_oauth_profile_update(pool, &environment, oauth_profile_id, req, request_id).await?;
    let audit_context = oauth_profile_audit_context(
        &environment,
        session.administrator_id,
        request_id,
        oauth_profile_id,
        configuration_version_id,
    );

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for oauth profile operations",
    )
    .await?;
    let environment =
        load_management_environment_record_for_update(&mut tx, team_id, environment_id, request_id)
            .await?;
    ensure_base_configuration_matches(configuration_version_id, &environment, request_id)?;
    if input.is_default {
        if let Err(resp) = clear_default_oauth_profiles(
            &mut tx,
            environment.scope.environment,
            configuration_version_id,
            &input.profile_type,
            request_id,
        )
        .await
        {
            record_oauth_profile_metric("update", "failure");
            return Err(resp);
        }
    }

    let row = match update_oauth_profile_row(
        &mut tx,
        oauth_profile_id,
        environment.scope.environment,
        &input,
        request_id,
    )
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            record_oauth_profile_metric("update", "failure");
            return Err(oauth_profile_not_found(request_id));
        }
        Err(resp) => {
            record_oauth_profile_metric("update", "failure");
            return Err(resp);
        }
    };

    if let Err(resp) =
        write_oauth_profile_updated_audit(&mut tx, audit_context, &existing_profile, &input).await
    {
        record_oauth_profile_metric("update", "failure");
        return Err(resp);
    }
    if let Err(resp) = commit_management_transaction(tx, request_id).await {
        record_oauth_profile_metric("update", "failure");
        return Err(resp);
    }

    let oauth_profile = match oauth_profile_from_row_result(&row, request_id) {
        Ok(profile) => profile,
        Err(resp) => {
            record_oauth_profile_metric("update", "failure");
            return Err(resp);
        }
    };
    record_oauth_profile_metric("update", "success");

    Ok(OAuthProfileMutationResponse {
        oauth_profile,
        environment: environment_from_management_record(&environment),
    })
}
