use super::super::super::super::{
    begin_management_transaction, client_accepts_client_secrets, client_not_found,
    commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, hash_password,
    load_management_environment_record_for_update, reject_client_secret_lifecycle_unsupported,
    require_team_lifecycle_role_in_transaction, RuntimeClientMutationSync,
};
use super::super::super::audit::write_client_secret_issued_audit;
use super::super::super::policy::load_client_secret_expiration_policy_in_transaction;
use super::super::super::scope::prepare_client_secret_lifecycle_scope;
use super::super::super::store::insert_client_secret_row;
use crate::management::types::{IssueClientSecretRequest, IssueClientSecretResponse};
use crate::web::management::client_store::load_client_for_update;
use crate::web::management::state::ManagementSession;
use axum::response::Response;
use sqlx::PgPool;

pub(super) async fn issue_client_secret_inner(
    pool: &PgPool,
    runtime_sync: RuntimeClientMutationSync<'_>,
    params: &crate::web::management::TeamEnvironmentClientPath,
    req: &IssueClientSecretRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<IssueClientSecretResponse, Response> {
    let scope = prepare_client_secret_lifecycle_scope(
        pool,
        params,
        &req.base_configuration_version_id,
        session,
        request_id,
    )
    .await?;
    let secret_value = aegaeon_crypto::rand::random_base64url(32);
    let secret_hash = hash_password(&secret_value)?;

    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team_id,
        session,
        request_id,
        "Insufficient permissions",
    )
    .await?;
    let environment = load_management_environment_record_for_update(
        &mut tx,
        scope.team_id,
        scope.environment_id,
        request_id,
    )
    .await?;
    ensure_base_configuration_matches(
        scope.base_configuration_version_id,
        &environment,
        request_id,
    )?;
    let expiration_policy = load_client_secret_expiration_policy_in_transaction(
        &mut tx,
        environment.scope.environment,
        request_id,
    )
    .await?;
    let expires_in_days =
        expiration_policy.resolve_requested_days(req.expires_in_days, request_id)?;
    let Some(client) = load_client_for_update(
        &mut tx,
        scope.team_id,
        environment.scope.environment,
        scope.client_id,
        environment.active_configuration_version_id,
        request_id,
    )
    .await?
    else {
        return Err(client_not_found(request_id));
    };
    if !client_accepts_client_secrets(&client) {
        return Err(reject_client_secret_lifecycle_unsupported(request_id));
    }
    let client_secret = insert_client_secret_row(
        &mut tx,
        environment.scope.environment,
        scope.client_id,
        environment.active_configuration_version_id,
        &secret_hash,
        expires_in_days,
        request_id,
    )
    .await?;
    write_client_secret_issued_audit(
        &mut tx,
        &environment,
        session.administrator_id,
        request_id,
        scope.client_id,
        &client_secret,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;
    runtime_sync.sync_client(pool, &client, request_id).await?;

    Ok(IssueClientSecretResponse {
        client_secret_value: secret_value,
        client_secret,
        environment: environment_from_management_record(&environment),
    })
}
