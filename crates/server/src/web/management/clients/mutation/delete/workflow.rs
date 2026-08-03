use crate::web::management::client_audit::write_client_deleted_audit;
use crate::web::management::client_store::{client_not_found, delete_client_row};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    load_management_environment_record_for_update, management_internal_error,
    require_team_lifecycle_role, require_team_lifecycle_role_in_transaction,
    RuntimeClientMutationSync,
};
use axum::response::Response;
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub(super) struct DeleteClientInput<'a> {
    pub(super) pool: &'a PgPool,
    pub(super) runtime_sync: RuntimeClientMutationSync<'a>,
    pub(super) team_id: Uuid,
    pub(super) environment_id: Uuid,
    pub(super) client_id: Uuid,
    pub(super) base_configuration_version_id: Uuid,
    pub(super) session: &'a ManagementSession,
    pub(super) request_id: &'a str,
}

pub(super) async fn delete_client_inner(input: DeleteClientInput<'_>) -> Result<(), Response> {
    let DeleteClientInput {
        pool,
        runtime_sync,
        team_id,
        environment_id,
        client_id,
        base_configuration_version_id,
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
    ensure_base_configuration_matches(base_configuration_version_id, &environment, request_id)?;
    let Some(row) = delete_client_row(
        &mut tx,
        team_id,
        environment_id,
        client_id,
        base_configuration_version_id,
        request_id,
    )
    .await?
    else {
        return Err(client_not_found(request_id));
    };
    let client_identifier: String = row
        .try_get("client_identifier")
        .map_err(|_| management_internal_error(request_id, "Failed to read client row"))?;
    write_client_deleted_audit(
        &mut tx,
        environment.scope,
        session.administrator_id,
        request_id,
        client_id,
        &client_identifier,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    runtime_sync
        .remove_client(pool, &client_identifier, request_id)
        .await?;

    Ok(())
}
