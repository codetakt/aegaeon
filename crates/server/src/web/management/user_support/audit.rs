use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::audit_safety::redacted_audit_data;

use super::super::{begin_management_transaction, commit_management_transaction, error_response};
use super::context::UserManagementContext;

pub(in crate::web::management) struct EndUserAuditEvent {
    pub(in crate::web::management) event_type: &'static str,
    pub(in crate::web::management) target_id: Uuid,
    pub(in crate::web::management) data: serde_json::Value,
}

pub(in crate::web::management) async fn write_user_management_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    context: &UserManagementContext,
    request_id: &str,
    event: EndUserAuditEvent,
) -> Result<(), Response> {
    write_user_management_audit_event_with_outcome(
        tx, context, request_id, "SUCCESS", "INFO", event,
    )
    .await
}

pub(in crate::web::management) async fn write_user_management_audit_event_with_outcome(
    tx: &mut Transaction<'_, Postgres>,
    context: &UserManagementContext,
    request_id: &str,
    outcome: &'static str,
    severity: &'static str,
    event: EndUserAuditEvent,
) -> Result<(), Response> {
    write_end_user_control_plane_audit_event(
        tx,
        EndUserControlPlaneAuditWrite {
            team_id: context.team_id,
            tenant_id: context.tenant_id,
            environment_id: context.environment_id,
            administrator_id: context.session.administrator_id,
            request_id,
            event_type: event.event_type,
            outcome,
            severity,
            target_id: event.target_id,
            data: event.data,
        },
    )
    .await
    .map_err(|_| audit_write_failed_response(request_id))
}

pub(in crate::web::management) async fn insert_user_management_runtime_command(
    tx: &mut Transaction<'_, Postgres>,
    context: &UserManagementContext,
    request_id: &str,
    command_type: &'static str,
    target_id: Uuid,
    payload: serde_json::Value,
) -> Result<Uuid, Response> {
    let command_id = Uuid::new_v4();
    sqlx::query(
        r"
INSERT INTO aegaeon.management_user_runtime_commands (
  id,
  team_id,
  tenant_id,
  environment_id,
  end_user_id,
  actor_administrator_id,
  request_id,
  command_type,
  payload
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ",
    )
    .bind(command_id)
    .bind(context.team_id)
    .bind(context.tenant_id)
    .bind(context.environment_id)
    .bind(target_id)
    .bind(context.session.administrator_id)
    .bind(request_id)
    .bind(command_type)
    .bind(payload)
    .execute(&mut **tx)
    .await
    .map(|_| command_id)
    .map_err(|_| runtime_command_write_failed_response(request_id))
}

#[derive(Clone, Copy)]
pub(in crate::web::management) enum EndUserRuntimeCommandStatus {
    Executing,
    Applied,
    FailedTerminal,
    FailedUnconfirmed,
}

impl EndUserRuntimeCommandStatus {
    const fn as_db_value(self) -> &'static str {
        match self {
            Self::Executing => "executing",
            Self::Applied => "applied",
            Self::FailedTerminal => "failed_terminal",
            Self::FailedUnconfirmed => "failed_unconfirmed",
        }
    }
}

pub(in crate::web::management) async fn mark_user_management_runtime_command_executing(
    context: &UserManagementContext,
    request_id: &str,
    command_id: Uuid,
    phase: &'static str,
) -> Result<(), Response> {
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    let updated = sqlx::query(
        r"
UPDATE aegaeon.management_user_runtime_commands
SET status = $2,
    phase = $3,
    attempts = attempts + 1,
    execution_started_at = COALESCE(execution_started_at, now()),
    updated_at = now()
WHERE id = $1
  AND team_id = $4
  AND tenant_id = $5
  AND environment_id = $6
  AND status = 'requested'
        ",
    )
    .bind(command_id)
    .bind(EndUserRuntimeCommandStatus::Executing.as_db_value())
    .bind(phase)
    .bind(context.team_id)
    .bind(context.tenant_id)
    .bind(context.environment_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| runtime_command_write_failed_response(request_id))?
    .rows_affected();
    if updated != 1 {
        return Err(runtime_command_write_failed_response(request_id));
    }
    commit_management_transaction(tx, request_id).await
}

pub(in crate::web::management) struct EndUserRuntimeCommandOutcome {
    pub(in crate::web::management) command_id: Uuid,
    pub(in crate::web::management) status: EndUserRuntimeCommandStatus,
    pub(in crate::web::management) phase: &'static str,
    pub(in crate::web::management) result: serde_json::Value,
    pub(in crate::web::management) audit_outcome: &'static str,
    pub(in crate::web::management) audit_severity: &'static str,
    pub(in crate::web::management) audit_event: EndUserAuditEvent,
}

pub(in crate::web::management) async fn write_user_management_runtime_command_outcome(
    context: &UserManagementContext,
    request_id: &str,
    outcome: EndUserRuntimeCommandOutcome,
) -> Result<(), Response> {
    let mut tx = begin_management_transaction(&context.pool, request_id).await?;
    let updated = sqlx::query(
        r"
UPDATE aegaeon.management_user_runtime_commands
SET status = $2,
    phase = $3,
    result = $4,
    updated_at = now(),
    completed_at = now()
WHERE id = $1
  AND team_id = $5
  AND tenant_id = $6
  AND environment_id = $7
  AND status = 'executing'
        ",
    )
    .bind(outcome.command_id)
    .bind(outcome.status.as_db_value())
    .bind(outcome.phase)
    .bind(outcome.result)
    .bind(context.team_id)
    .bind(context.tenant_id)
    .bind(context.environment_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| runtime_command_write_failed_response(request_id))?
    .rows_affected();
    if updated != 1 {
        return Err(runtime_command_write_failed_response(request_id));
    }
    write_user_management_audit_event_with_outcome(
        &mut tx,
        context,
        request_id,
        outcome.audit_outcome,
        outcome.audit_severity,
        outcome.audit_event,
    )
    .await?;
    commit_management_transaction(tx, request_id).await
}

fn runtime_command_write_failed_response(request_id: &str) -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "Runtime command state write failed",
        None,
        Some(request_id),
    )
}

fn audit_write_failed_response(request_id: &str) -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "temporarily_unavailable",
        "Audit write failed",
        None,
        Some(request_id),
    )
}

struct EndUserControlPlaneAuditWrite<'a> {
    team_id: Uuid,
    tenant_id: Uuid,
    environment_id: Uuid,
    administrator_id: Uuid,
    request_id: &'a str,
    event_type: &'a str,
    outcome: &'a str,
    severity: &'a str,
    target_id: Uuid,
    data: serde_json::Value,
}

async fn write_end_user_control_plane_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    event: EndUserControlPlaneAuditWrite<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id,
  tenant_id,
  environment_id,
  event_type,
  category,
  outcome,
  severity,
  occurred_at,
  actor_type,
  actor_id,
  target_type,
  target_id,
  request_id,
  data
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), $8, $9, $10, $11, $12, $13)
        ",
    )
    .bind(event.team_id)
    .bind(event.tenant_id)
    .bind(event.environment_id)
    .bind(event.event_type)
    .bind("CONTROL_PLANE")
    .bind(event.outcome)
    .bind(event.severity)
    .bind("ADMINISTRATOR")
    .bind(event.administrator_id.to_string())
    .bind("END_USER")
    .bind(event.target_id.to_string())
    .bind(event.request_id)
    .bind(redacted_audit_data(event.data))
    .execute(&mut **tx)
    .await
    .map(|_| ())
}
