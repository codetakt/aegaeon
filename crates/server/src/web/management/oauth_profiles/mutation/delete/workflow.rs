use super::super::super::super::oauth_profile_store::{
    load_retirable_oauth_profile, oauth_profile_not_found, retire_oauth_profile,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction,
    load_management_environment_record_for_update, parse_team_environment_oauth_profile_scope,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
};
use super::super::super::audit::{oauth_profile_audit_context, write_oauth_profile_deleted_audit};
use super::super::metrics::record_oauth_profile_metric;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn delete_oauth_profile_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentOAuthProfilePath,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
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
    let Some(profile) = load_retirable_oauth_profile(
        &mut tx,
        environment.scope.environment,
        oauth_profile_id,
        request_id,
    )
    .await?
    else {
        return Err(oauth_profile_not_found(request_id));
    };

    if retire_oauth_profile(
        &mut tx,
        environment.scope.environment,
        oauth_profile_id,
        request_id,
    )
    .await?
        == 0
    {
        record_oauth_profile_metric("delete", "failure");
        return Err(oauth_profile_not_found(request_id));
    }

    if let Err(resp) = write_oauth_profile_deleted_audit(
        &mut tx,
        oauth_profile_audit_context(
            &environment,
            session.administrator_id,
            request_id,
            profile.profile_id,
            profile.configuration_version_id,
        ),
        &profile,
    )
    .await
    {
        record_oauth_profile_metric("delete", "failure");
        return Err(resp);
    }
    if let Err(resp) = commit_management_transaction(tx, request_id).await {
        record_oauth_profile_metric("delete", "failure");
        return Err(resp);
    }

    record_oauth_profile_metric("delete", "success");
    Ok(())
}
