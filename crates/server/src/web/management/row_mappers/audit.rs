use axum::response::Response;
use sqlx::postgres::PgRow;
use uuid::Uuid;

use crate::management::types::{
    AuditActor, AuditChange, AuditEvent, AuditRequestContext, AuditTarget,
};

use super::super::required_row_value;

pub(in crate::web::management) fn audit_event_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<AuditEvent, Response> {
    let message = "Failed to load audit event";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let team_id: Uuid = required_row_value(row, "team_id", request_id, message)?;
    let tenant_id: Option<Uuid> = required_row_value(row, "tenant_id", request_id, message)?;
    let environment_id: Option<Uuid> =
        required_row_value(row, "environment_id", request_id, message)?;
    let event_type: String = required_row_value(row, "event_type", request_id, message)?;
    let category: String = required_row_value(row, "category", request_id, message)?;
    let outcome: String = required_row_value(row, "outcome", request_id, message)?;
    let severity: String = required_row_value(row, "severity", request_id, message)?;
    let occurred_at: String = required_row_value(row, "occurred_at", request_id, message)?;
    let actor_type: String = required_row_value(row, "actor_type", request_id, message)?;
    let actor_id: Option<String> = required_row_value(row, "actor_id", request_id, message)?;
    let ip_address: Option<String> = required_row_value(row, "ip_address", request_id, message)?;
    let user_agent: Option<String> = required_row_value(row, "user_agent", request_id, message)?;
    let mfa: Option<bool> = required_row_value(row, "mfa", request_id, message)?;
    let target_type: String = required_row_value(row, "target_type", request_id, message)?;
    let target_id: Option<String> = required_row_value(row, "target_id", request_id, message)?;
    let request_id_value: String = required_row_value(row, "request_id", request_id, message)?;
    let trace_id: Option<String> = required_row_value(row, "trace_id", request_id, message)?;
    let span_id: Option<String> = required_row_value(row, "span_id", request_id, message)?;
    let from_configuration_version_id: Option<Uuid> =
        required_row_value(row, "from_configuration_version_id", request_id, message)?;
    let to_configuration_version_id: Option<Uuid> =
        required_row_value(row, "to_configuration_version_id", request_id, message)?;
    let json_patch: Option<serde_json::Value> =
        required_row_value(row, "json_patch", request_id, message)?;
    let data: Option<serde_json::Value> = required_row_value(row, "data", request_id, message)?;

    let change = if from_configuration_version_id.is_some()
        || to_configuration_version_id.is_some()
        || json_patch.is_some()
    {
        Some(AuditChange {
            from_configuration_version_id: from_configuration_version_id.map(|v| v.to_string()),
            to_configuration_version_id: to_configuration_version_id.map(|v| v.to_string()),
            json_patch,
        })
    } else {
        None
    };

    Ok(AuditEvent {
        id: id.to_string(),
        team_id: team_id.to_string(),
        tenant_id: tenant_id.map(|v| v.to_string()),
        environment_id: environment_id.map(|v| v.to_string()),
        event_type,
        category,
        outcome,
        severity,
        occurred_at,
        actor: AuditActor {
            actor_type,
            actor_id,
            ip_address,
            user_agent,
            mfa,
        },
        target: AuditTarget {
            target_type,
            target_id,
        },
        request: AuditRequestContext {
            request_id: request_id_value,
            trace_id,
            span_id,
        },
        change,
        data,
    })
}
