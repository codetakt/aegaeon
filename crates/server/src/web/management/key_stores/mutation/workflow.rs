use crate::management::types::{KeyStorePublicView, KeyStoreUpdateResponse, UpdateKeyStoreRequest};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction, ensure_base_configuration_matches,
    environment_from_management_record, load_key_management_environment,
    load_management_environment_record_for_update, parse_uuid_param,
    require_team_lifecycle_role_in_transaction,
};
use axum::response::Response;
use sqlx::PgPool;

use super::super::audit::write_key_store_updated_audit;
use super::super::store::{
    key_store_public_view_from_row_result, load_key_store_row_in_tx, upsert_key_store,
};
use super::super::validation::validate_key_store_update_request;

pub(super) async fn update_key_store_inner(
    pool: &PgPool,
    params: &crate::web::management::TeamEnvironmentPath,
    req: &UpdateKeyStoreRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<KeyStoreUpdateResponse, Response> {
    let environment = load_key_management_environment(
        pool,
        params,
        session,
        request_id,
        "Insufficient permissions for key store operations",
    )
    .await?;
    let base_configuration_version_id = parse_uuid_param(
        &req.base_configuration_version_id,
        "baseConfigurationVersionId",
        request_id,
    )?;
    ensure_base_configuration_matches(base_configuration_version_id, &environment, request_id)?;
    let validated = validate_key_store_update_request(req, request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        environment.scope.team,
        session,
        request_id,
        "Insufficient permissions for key store operations",
    )
    .await?;
    let environment = load_management_environment_record_for_update(
        &mut tx,
        environment.scope.team,
        environment.scope.environment,
        request_id,
    )
    .await?;
    ensure_base_configuration_matches(base_configuration_version_id, &environment, request_id)?;
    let previous = load_key_store_row_in_tx(
        &mut tx,
        environment.scope.team,
        environment.scope.environment,
        request_id,
    )
    .await?
    .map(|row| key_store_public_view_from_row_result(&row, request_id))
    .transpose()?;
    upsert_key_store(&mut tx, &environment, &validated, request_id).await?;
    write_key_store_updated_audit(
        &mut tx,
        &environment,
        session.administrator_id,
        request_id,
        previous,
        &validated,
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(KeyStoreUpdateResponse {
        key_store: KeyStorePublicView {
            type_: validated.type_,
            configuration: validated.configuration,
            redacted: true,
        },
        environment: environment_from_management_record(&environment),
    })
}
