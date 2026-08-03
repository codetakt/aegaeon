use super::super::super::super::{
    begin_management_transaction, client_not_found, client_secret_not_found,
    commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_management_environment_record_for_update,
    management_internal_error, require_team_lifecycle_role_in_transaction,
    RuntimeClientMutationSync,
};
use super::super::super::audit::write_client_secret_revoked_audit;
use super::super::super::scope::{
    parse_team_environment_client_secret_scope, prepare_client_secret_lifecycle_scope,
};
use super::super::super::store::revoke_client_secret_row;
use crate::management::types::{ClientSecretMutationResponse, ConfigurationTransactionRequest};
use crate::web::management::client_store::load_client_for_update;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn revoke_client_secret_inner(
    pool: &PgPool,
    runtime_sync: RuntimeClientMutationSync<'_>,
    params: &crate::web::management::TeamEnvironmentClientSecretPath,
    req: &ConfigurationTransactionRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<ClientSecretMutationResponse, Response> {
    let (team_id, environment_id, client_id, client_secret_id) =
        parse_team_environment_client_secret_scope(params, request_id)?;
    let scope = prepare_client_secret_lifecycle_scope(
        pool,
        params,
        &req.base_configuration_version_id,
        session,
        request_id,
    )
    .await?;
    if scope.client_id != client_id || scope.environment_id != environment_id {
        return Err(management_internal_error(
            request_id,
            "Client secret scope resolution mismatch",
        ));
    }

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions",
    )
    .await?;
    let environment =
        load_management_environment_record_for_update(&mut tx, team_id, environment_id, request_id)
            .await?;
    ensure_base_configuration_matches(
        scope.base_configuration_version_id,
        &environment,
        request_id,
    )?;
    let Some(client) = load_client_for_update(
        &mut tx,
        team_id,
        environment.scope.environment,
        client_id,
        environment.active_configuration_version_id,
        request_id,
    )
    .await?
    else {
        return Err(client_not_found(request_id));
    };
    let Some(client_secret) = revoke_client_secret_row(
        &mut tx,
        team_id,
        environment.scope.environment,
        client_id,
        client_secret_id,
        request_id,
    )
    .await?
    else {
        return Err(client_secret_not_found(request_id));
    };
    write_client_secret_revoked_audit(
        &mut tx,
        &environment,
        session.administrator_id,
        request_id,
        client_id,
        client_secret_id,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    runtime_sync.sync_client(pool, &client, request_id).await?;

    Ok(ClientSecretMutationResponse {
        client_secret,
        environment: environment_from_management_record(&environment),
    })
}
