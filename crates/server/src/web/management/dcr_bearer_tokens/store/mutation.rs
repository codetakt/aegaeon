use super::status::configured_status_from_row;
use crate::management::types::DcrBearerTokenStatus;
use crate::web::management::http_errors::management_database_error as database_error;
use crate::web::management::transactions;
use crate::web::management::{
    begin_management_transaction, commit_management_transaction,
    require_team_lifecycle_role_in_transaction, state::ManagementSession,
    write_management_control_plane_audit_event, ManagementControlPlaneAuditEvent,
    ManagementEnvironmentScope,
};
use axum::response::Response;
use sqlx::PgPool;

pub(in crate::web::management) async fn set_dcr_bearer_token_inner(
    pool: &PgPool,
    scope: ManagementEnvironmentScope,
    session: &ManagementSession,
    request_id: &str,
    token: &str,
) -> Result<DcrBearerTokenStatus, Response> {
    let token_hash = crate::dcr_persistence::dcr_bearer_token_hash(token);
    let mut management_connection = transactions::connection(pool, request_id).await?;
    let mut tx = begin_management_transaction(&mut management_connection, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for DCR bearer token operations",
    )
    .await?;
    let row = sqlx::query(
        r#"
INSERT INTO aegaeon.environment_dcr_bearer_tokens (
  environment_id,
  token_hash,
  token_hash_algorithm
)
VALUES ($1, $2, 'sha256')
ON CONFLICT (environment_id) DO UPDATE
SET token_hash = EXCLUDED.token_hash,
    token_hash_algorithm = 'sha256',
    updated_at = now()
RETURNING
  token_hash_algorithm,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(scope.environment)
    .bind(token_hash)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| database_error(request_id, &error, "Database query failed"))?;

    let status = configured_status_from_row(scope.environment, &row, request_id)?;
    let audit_data = serde_json::json!({
        "configured": true,
        "hashAlgorithm": "sha256",
    });
    write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope,
            administrator_id: session.administrator_id,
            request_id,
            event_type: "management.dcrBearerToken.set.v1",
            target_type: "ENVIRONMENT",
            target_id: scope.environment.to_string(),
            data: audit_data,
        },
    )
    .await?;
    let commit = commit_management_transaction(tx, request_id).await;
    transactions::finish(commit, management_connection, request_id).await?;

    Ok(status)
}

pub(in crate::web::management) async fn delete_dcr_bearer_token_inner(
    pool: &PgPool,
    scope: ManagementEnvironmentScope,
    session: &ManagementSession,
    request_id: &str,
) -> Result<(), Response> {
    let mut management_connection = transactions::connection(pool, request_id).await?;
    let mut tx = begin_management_transaction(&mut management_connection, request_id).await?;
    require_team_lifecycle_role_in_transaction(
        &mut tx,
        scope.team,
        session,
        request_id,
        "Insufficient permissions for DCR bearer token operations",
    )
    .await?;
    let result =
        sqlx::query("DELETE FROM aegaeon.environment_dcr_bearer_tokens WHERE environment_id = $1")
            .bind(scope.environment)
            .execute(&mut *tx)
            .await
            .map_err(|error| database_error(request_id, &error, "Database query failed"))?;
    let audit_data = serde_json::json!({
        "configured": false,
        "removed": result.rows_affected() > 0,
    });
    write_management_control_plane_audit_event(
        &mut tx,
        ManagementControlPlaneAuditEvent {
            scope,
            administrator_id: session.administrator_id,
            request_id,
            event_type: "management.dcrBearerToken.deleted.v1",
            target_type: "ENVIRONMENT",
            target_id: scope.environment.to_string(),
            data: audit_data,
        },
    )
    .await?;
    let commit = commit_management_transaction(tx, request_id).await;
    transactions::finish(commit, management_connection, request_id).await
}
