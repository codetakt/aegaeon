use super::super::super::super::connections_audit::{
    connection_audit_context, write_connection_assignment_audit, write_connection_created_audit,
};
use super::super::super::super::connections_store::{
    apply_connection_client_secret_action, connection_from_row_result, insert_connection_row,
};
use super::super::super::super::connections_support::ConnectionClientSecretAction;
use super::super::super::super::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record,
    load_management_environment_record_for_update, management_internal_error,
    parse_team_environment_scope, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction,
};
use super::super::super::policy_boundary::validate_connection_policy_boundary;
use super::super::super::preparation::{prepare_connection_create, PreparedConnectionCreate};
use crate::management::types::{ConnectionMutationResponse, CreateConnectionRequest};
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::{PgPool, Row};

pub(super) async fn create_connection_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    req: &CreateConnectionRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ConnectionMutationResponse, Response> {
    let (team_id, environment_id) = parse_team_environment_scope(params, request_id)?;
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for connection operations",
    )
    .await?;

    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    let PreparedConnectionCreate {
        input,
        configuration_version_id,
        oauth_profile_id,
        client_secret_action,
    } = prepare_connection_create(pool, &environment, req, request_id).await?;

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
    ensure_base_configuration_matches(configuration_version_id, &environment, request_id)?;
    validate_connection_policy_boundary(
        &mut tx,
        environment.scope.environment,
        configuration_version_id,
        oauth_profile_id,
        &input,
        request_id,
    )
    .await?;
    let row = insert_connection_row(
        &mut tx,
        environment.scope.environment,
        configuration_version_id,
        oauth_profile_id,
        &input,
        request_id,
    )
    .await?;
    let connection_id = row
        .try_get("id")
        .map_err(|_| management_internal_error(request_id, "Failed to read connection row"))?;
    if matches!(client_secret_action, ConnectionClientSecretAction::Set(_)) {
        apply_connection_client_secret_action(
            &mut tx,
            connection_id,
            environment.scope.environment,
            &input.client_auth_method,
            &client_secret_action,
            request_id,
        )
        .await?;
    }
    let audit_context = connection_audit_context(
        &environment,
        session.administrator_id,
        request_id,
        connection_id,
        configuration_version_id,
    );
    write_connection_created_audit(&mut tx, audit_context, &input, oauth_profile_id).await?;
    if let Some(oauth_profile_id) = oauth_profile_id {
        write_connection_assignment_audit(
            &mut tx,
            audit_context,
            "management.oauthProfile.assigned.v1",
            oauth_profile_id,
            &input.connection_identifier,
        )
        .await?;
    }
    commit_management_transaction(tx, request_id).await?;

    let connection = connection_from_row_result(&row, request_id)?;
    Ok(ConnectionMutationResponse {
        connection,
        environment: environment_from_management_record(&environment),
    })
}
