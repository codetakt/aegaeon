use super::super::super::audit::{write_api_key_audit_event, ApiKeyAuditEvent};
use super::super::super::store::{api_key_not_found, revoke_api_key_row};
use crate::web::management::state::ManagementSession;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction,
    require_team_lifecycle_role_in_transaction,
};
use axum::response::Response;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn revoke_api_key_inner(
    pool: &PgPool,
    team_id: Uuid,
    api_key_id: Uuid,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let mut tx = begin_management_transaction(pool, request_id).await?;
    require_api_key_revoke_permission(&mut tx, team_id, session, request_id).await?;
    if !revoke_api_key_row(
        &mut tx,
        team_id,
        api_key_id,
        session.administrator_id,
        request_id,
    )
    .await?
    {
        return Err(api_key_not_found(request_id));
    }

    write_api_key_audit_event(
        &mut tx,
        team_id,
        session.administrator_id,
        request_id,
        ApiKeyAuditEvent {
            event_type: "API_KEY_REVOKE",
            severity: "WARN",
            api_key_id,
            data: serde_json::json!({ "operation": "REVOKE" }),
        },
    )
    .await?;
    commit_management_transaction(tx, request_id).await
}

async fn require_api_key_revoke_permission(
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
