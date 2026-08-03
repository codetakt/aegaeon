use super::super::super::super::oauth_profile_store::{
    clear_default_oauth_profiles, insert_oauth_profile_row, oauth_profile_from_row_result,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record,
    load_management_environment_record_for_update, management_internal_error,
    parse_team_environment_scope, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction,
};
use super::super::super::audit::{oauth_profile_audit_context, write_oauth_profile_created_audit};
use super::super::super::query::OAuthProfileListQuery;
use super::super::metrics::record_oauth_profile_metric;
use super::preparation::{prepare_oauth_profile_create, PreparedOAuthProfileCreate};
use crate::management::types::{CreateOAuthProfileRequest, OAuthProfileMutationResponse};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::{PgPool, Row};

pub(super) async fn create_oauth_profile_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    query: &OAuthProfileListQuery,
    req: &CreateOAuthProfileRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<OAuthProfileMutationResponse, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
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
    let PreparedOAuthProfileCreate {
        input,
        configuration_version_id,
    } = prepare_oauth_profile_create(pool, &environment, query, req, request_id).await?;

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
            record_oauth_profile_metric("create", "failure");
            return Err(resp);
        }
    }

    let row = match insert_oauth_profile_row(
        &mut tx,
        environment.scope.environment,
        configuration_version_id,
        &input,
        request_id,
    )
    .await
    {
        Ok(row) => row,
        Err(resp) => {
            record_oauth_profile_metric("create", "failure");
            return Err(resp);
        }
    };

    let Ok(profile_id) = row.try_get("id") else {
        record_oauth_profile_metric("create", "failure");
        return Err(management_internal_error(
            request_id,
            "Failed to read oauth profile row",
        ));
    };
    let audit_context = oauth_profile_audit_context(
        &environment,
        session.administrator_id,
        request_id,
        profile_id,
        configuration_version_id,
    );
    if let Err(resp) = write_oauth_profile_created_audit(&mut tx, audit_context, &input).await {
        record_oauth_profile_metric("create", "failure");
        return Err(resp);
    }
    if let Err(resp) = commit_management_transaction(tx, request_id).await {
        record_oauth_profile_metric("create", "failure");
        return Err(resp);
    }

    let oauth_profile = match oauth_profile_from_row_result(&row, request_id) {
        Ok(profile) => profile,
        Err(resp) => {
            record_oauth_profile_metric("create", "failure");
            return Err(resp);
        }
    };
    record_oauth_profile_metric("create", "success");

    Ok(OAuthProfileMutationResponse {
        oauth_profile,
        environment: environment_from_management_record(&environment),
    })
}
