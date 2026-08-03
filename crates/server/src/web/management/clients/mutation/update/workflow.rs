use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use crate::management::types::{ClientMutationResponse, UpdateClientRequest};
use crate::web::management::client_audit::{
    client_audit_context, write_client_profile_assignment_delta_audit, write_client_updated_audit,
};
use crate::web::management::client_store::{
    client_not_found, load_client_for_update, update_client_row,
};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record,
    load_management_environment_record_for_update, require_team_lifecycle_role,
    require_team_lifecycle_role_in_transaction, RuntimeClientMutationSync,
};

use super::super::super::policy_boundary::validate_client_policy_boundary;
use super::super::super::preparation::{
    merge_client_update, prepare_client_update, PreparedClientUpdate,
};

pub(in crate::web::management::clients::mutation::update) struct UpdateClientWorkflowInput<'a> {
    pub(in crate::web::management::clients::mutation::update) pool: &'a PgPool,
    pub(in crate::web::management::clients::mutation::update) runtime_sync:
        RuntimeClientMutationSync<'a>,
    pub(in crate::web::management::clients::mutation::update) team_id: Uuid,
    pub(in crate::web::management::clients::mutation::update) environment_id: Uuid,
    pub(in crate::web::management::clients::mutation::update) client_id: Uuid,
    pub(in crate::web::management::clients::mutation::update) req: &'a UpdateClientRequest,
    pub(in crate::web::management::clients::mutation::update) session: &'a ManagementSession,
    pub(in crate::web::management::clients::mutation::update) request_id: &'a str,
}

pub(in crate::web::management::clients::mutation::update) async fn update_client_workflow(
    input: UpdateClientWorkflowInput<'_>,
) -> Result<ClientMutationResponse, Response> {
    let UpdateClientWorkflowInput {
        pool,
        runtime_sync,
        team_id,
        environment_id,
        client_id,
        req,
        session,
        request_id,
    } = input;

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
    let PreparedClientUpdate {
        input,
        configuration_version_id,
    } = prepare_client_update(pool, &environment, req, request_id).await?;

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
    let Some(existing_client) = load_client_for_update(
        &mut tx,
        team_id,
        environment.scope.environment,
        client_id,
        configuration_version_id,
        request_id,
    )
    .await?
    else {
        return Err(client_not_found(request_id));
    };

    let merged_input = merge_client_update(&existing_client, &input, request_id)?;
    validate_client_policy_boundary(
        &mut tx,
        environment.scope.environment,
        configuration_version_id,
        &merged_input,
        request_id,
    )
    .await?;
    let Some(client) = update_client_row(
        &mut tx,
        team_id,
        environment.scope.environment,
        client_id,
        configuration_version_id,
        &merged_input,
        request_id,
    )
    .await?
    else {
        return Err(client_not_found(request_id));
    };

    let audit_context = client_audit_context(
        &environment,
        session.administrator_id,
        request_id,
        client_id,
        configuration_version_id,
    );
    write_client_updated_audit(&mut tx, audit_context, &existing_client, &client).await?;

    write_client_profile_assignment_delta_audit(&mut tx, audit_context, &existing_client, &client)
        .await?;

    commit_management_transaction(tx, request_id).await?;
    runtime_sync.sync_client(pool, &client, request_id).await?;

    Ok(ClientMutationResponse {
        client,
        environment: environment_from_management_record(&environment),
    })
}
