use super::super::super::super::connections_audit::{
    connection_audit_context, write_connection_assignment_audit, write_connection_deleted_audit,
};
use super::super::super::super::connections_store::{
    connection_not_found, load_retirable_connection, retire_connection,
};
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    load_management_environment_record_for_update, parse_team_environment_connection_scope,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn delete_connection_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentConnectionPath,
    base_configuration_version_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let (team_id, environment_id, connection_id) =
        parse_team_environment_connection_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for connection operations",
    )
    .await?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for connection operations",
    )
    .await?;
    let environment =
        load_management_environment_record_for_update(&mut tx, team_id, environment_id, request_id)
            .await?;
    ensure_base_configuration_matches(base_configuration_version_id, &environment, request_id)?;
    let Some(connection) = load_retirable_connection(
        &mut tx,
        environment.scope.environment,
        connection_id,
        base_configuration_version_id,
        request_id,
    )
    .await?
    else {
        return Err(connection_not_found(request_id));
    };

    if retire_connection(
        &mut tx,
        environment.scope.environment,
        connection_id,
        base_configuration_version_id,
        request_id,
    )
    .await?
        == 0
    {
        return Err(connection_not_found(request_id));
    }

    let audit_context = connection_audit_context(
        &environment,
        session.administrator_id,
        request_id,
        connection_id,
        connection.configuration_version_id,
    );
    write_connection_deleted_audit(&mut tx, audit_context, &connection.connection).await?;
    if let Some(oauth_profile_id) = connection.oauth_profile_id {
        write_connection_assignment_audit(
            &mut tx,
            audit_context,
            "management.oauthProfile.unassigned.v1",
            oauth_profile_id,
            &connection.connection.connection_identifier,
        )
        .await?;
    }
    commit_management_transaction(tx, request_id).await?;

    Ok(())
}
