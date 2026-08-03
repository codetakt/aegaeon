use super::super::super::audit::{write_api_key_audit_event, ApiKeyAuditEvent};
use super::super::super::input::{
    generate_api_key_material, parse_api_key_expiration_days, validate_api_key_capabilities,
    validate_api_key_name,
};
use super::super::super::store::{api_key_from_row_result, insert_api_key_row, ApiKeyInsertInput};
use crate::management::types::{CreateApiKeyRequest, CreateApiKeyResponse};
use crate::web::management::state::{load_control_plane_policy_in_transaction, ManagementSession};
use crate::web::management::{
    begin_management_transaction, commit_management_transaction, management_internal_error,
    require_team_lifecycle_role_in_transaction,
};
use axum::response::Response;
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) async fn create_api_key_inner(
    pool: &PgPool,
    team_id: Uuid,
    req: &CreateApiKeyRequest,
    session: &ManagementSession,
    request_id: &str,
) -> Result<CreateApiKeyResponse, Response> {
    let name = validate_api_key_name(&req.name, request_id)?;
    let capabilities = validate_api_key_capabilities(&req.capabilities, request_id)?;
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_api_key_create_permission(&mut tx, team_id, session, request_id).await?;
    let policy = load_control_plane_policy_in_transaction(&mut tx)
        .await
        .map_err(|_| management_internal_error(request_id, "Failed to load API key policy"))?;
    let expires_in_days =
        parse_api_key_expiration_days(req.expires_in_days, req.never_expires, &policy, request_id)?;
    let (raw_key, key_hash, key_prefix) = generate_api_key_material();
    let api_key_id = Uuid::new_v4();
    let service_administrator_id = Uuid::new_v4();
    let row = insert_api_key_row(
        &mut tx,
        &ApiKeyInsertInput {
            api_key_id,
            team_id,
            service_administrator_id,
            name: &name,
            key_prefix: &key_prefix,
            key_hash: key_hash.as_slice(),
            capabilities: &capabilities,
            expires_in_days,
            created_by_administrator_id: session.administrator_id,
        },
        request_id,
    )
    .await?;
    let api_key_id: Uuid = row
        .try_get("id")
        .map_err(|_| management_internal_error(request_id, "Failed to read API key id"))?;
    write_api_key_audit_event(
        &mut tx,
        team_id,
        session.administrator_id,
        request_id,
        ApiKeyAuditEvent {
            event_type: "API_KEY_CREATE",
            severity: "INFO",
            api_key_id,
            data: serde_json::json!({
                "apiKeyName": name,
                "keyPrefix": key_prefix,
                "capabilities": capabilities,
            }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await?;

    Ok(CreateApiKeyResponse {
        api_key_value: raw_key,
        api_key: api_key_from_row_result(&row, request_id)?,
    })
}

async fn require_api_key_create_permission(
    tx: &mut Transaction<'_, Postgres>,
    team_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    require_team_lifecycle_role_in_transaction(
        tx,
        team_id,
        session,
        request_id,
        "Insufficient permissions for API key operations",
    )
    .await
}
