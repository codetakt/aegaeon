use axum::response::Response;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::management::types::{ClientMutationResponse, CreateClientRequest};
use crate::web::management::client_audit::{client_audit_context, write_client_created_audit};
use crate::web::management::client_store::{client_from_row_result, insert_client_row};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record,
    load_management_environment_record_for_update, management_internal_error,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
    RuntimeClientMutationSync,
};

use super::super::super::policy_boundary::validate_client_policy_boundary;
use super::super::super::preparation::{prepare_client_create, PreparedClientCreate};

pub(in crate::web::management::clients::mutation::create) async fn create_client_workflow(
    pool: &PgPool,
    runtime_sync: RuntimeClientMutationSync<'_>,
    team_id: Uuid,
    environment_id: Uuid,
    req: &CreateClientRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ClientMutationResponse, Response> {
    require_team_lifecycle_role(
        pool,
        team_id,
        session,
        request_id,
        "Insufficient permissions for client operations",
    )
    .await?;

    let environment =
        load_management_environment_record(pool, team_id, environment_id, request_id).await?;
    let PreparedClientCreate {
        input,
        configuration_version_id,
    } = prepare_client_create(pool, &environment, req, request_id).await?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for client operations",
    )
    .await?;
    let environment =
        load_management_environment_record_for_update(&mut tx, team_id, environment_id, request_id)
            .await?;
    ensure_base_configuration_matches(configuration_version_id, &environment, request_id)?;
    validate_client_policy_boundary(
        &mut tx,
        environment.scope.environment,
        configuration_version_id,
        &input,
        request_id,
    )
    .await?;
    let row = insert_client_row(
        &mut tx,
        environment.scope.environment,
        configuration_version_id,
        &input,
        request_id,
    )
    .await?;
    let client_id: Uuid = row
        .try_get("id")
        .map_err(|_| management_internal_error(request_id, "Failed to read created client"))?;
    let client = client_from_row_result(&row, request_id)?;
    write_client_created_audit(
        &mut tx,
        client_audit_context(
            &environment,
            session.administrator_id,
            request_id,
            client_id,
            configuration_version_id,
        ),
        &client,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    runtime_sync.sync_client(pool, &client, request_id).await?;

    Ok(ClientMutationResponse {
        client,
        environment: environment_from_management_record(&environment),
    })
}
