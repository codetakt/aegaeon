use super::super::audit::{write_federation_logout_relay_audit, FederationLogoutRelayAuditEvent};
use super::super::model::{UpstreamLogoutIncidentRecord, UpstreamLogoutIncidentStatus};
use crate::upstream::UpstreamLogoutRecoveryPolicy;
use serde_json::json;
use sqlx::{PgPool, Row};

pub(in crate::web::upstream_logout_incidents) struct UpstreamLogoutIncidentTransition<'a> {
    pub(in crate::web::upstream_logout_incidents) next_status: UpstreamLogoutIncidentStatus,
    pub(in crate::web::upstream_logout_incidents) failure_reason: Option<&'a str>,
    pub(in crate::web::upstream_logout_incidents) event_type: &'a str,
    pub(in crate::web::upstream_logout_incidents) outcome: &'a str,
    pub(in crate::web::upstream_logout_incidents) severity: &'a str,
}

pub(in crate::web::upstream_logout_incidents) async fn update_upstream_logout_incident_status(
    pool: &PgPool,
    incident: &UpstreamLogoutIncidentRecord,
    request_id: &str,
    transition: UpstreamLogoutIncidentTransition<'_>,
) {
    if sqlx::query(
        r"
UPDATE aegaeon.federation_logout_recovery_incidents
SET
  status = $2,
  failure_reason = $3,
  resolved_at = now()
WHERE id = $1
        ",
    )
    .bind(incident.id)
    .bind(transition.next_status.as_str())
    .bind(transition.failure_reason)
    .execute(pool)
    .await
    .is_err()
    {
        tracing::warn!(
            incident_id = %incident.id,
            "failed to update upstream logout incident status"
        );
        return;
    }

    write_federation_logout_relay_audit(
        pool,
        FederationLogoutRelayAuditEvent {
            team_id: incident.team_id,
            tenant_id: incident.tenant_id,
            environment_id: incident.environment_id,
            connection_id: incident.connection_id,
            event_type: transition.event_type,
            outcome: transition.outcome,
            severity: transition.severity,
            actor_type: "system",
            actor_id: None,
            request_id,
            data: json!({
                "incidentId": incident.id.to_string(),
                "upstreamIssuer": incident.upstream_issuer,
                "recoveryPolicy": incident.recovery_policy.as_str(),
                "status": transition.next_status.as_str(),
                "failureReason": transition.failure_reason,
            }),
        },
    )
    .await;
}

async fn expire_pending_upstream_logout_incidents_for_connection(
    pool: &PgPool,
    connection_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    let rows = sqlx::query(
        r"
UPDATE aegaeon.federation_logout_recovery_incidents
SET
  status = 'expired',
  failure_reason = 'relay timeout',
  resolved_at = now()
WHERE connection_id = $1
  AND status = 'pending'
  AND expires_at <= now()
RETURNING
  id,
  team_id,
  tenant_id,
  environment_id,
  connection_id,
  upstream_issuer,
  recovery_policy
        ",
    )
    .bind(connection_id)
    .fetch_all(pool)
    .await?;

    for row in rows {
        let Some(recovery_policy) = row
            .try_get::<String, _>("recovery_policy")
            .ok()
            .and_then(|value| UpstreamLogoutRecoveryPolicy::parse(value.as_str()).ok())
        else {
            continue;
        };
        let incident = UpstreamLogoutIncidentRecord {
            id: match row.try_get("id") {
                Ok(value) => value,
                Err(_) => continue,
            },
            team_id: match row.try_get("team_id") {
                Ok(value) => value,
                Err(_) => continue,
            },
            tenant_id: match row.try_get("tenant_id") {
                Ok(value) => value,
                Err(_) => continue,
            },
            environment_id: match row.try_get("environment_id") {
                Ok(value) => value,
                Err(_) => continue,
            },
            connection_id: row
                .try_get::<Option<uuid::Uuid>, _>("connection_id")
                .ok()
                .flatten(),
            upstream_issuer: match row.try_get("upstream_issuer") {
                Ok(value) => value,
                Err(_) => continue,
            },
            recovery_policy,
            status: UpstreamLogoutIncidentStatus::Expired,
            downstream_redirect_uri: String::new(),
            downstream_state: None,
            is_expired: true,
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        write_federation_logout_relay_audit(
            pool,
            FederationLogoutRelayAuditEvent {
                team_id: incident.team_id,
                tenant_id: incident.tenant_id,
                environment_id: incident.environment_id,
                connection_id: incident.connection_id,
                event_type: "federation.upstreamLogoutRelay.expired.v1",
                outcome: "failure",
                severity: "warning",
                actor_type: "system",
                actor_id: None,
                request_id: &request_id,
                data: json!({
                    "incidentId": incident.id.to_string(),
                    "upstreamIssuer": incident.upstream_issuer,
                    "recoveryPolicy": incident.recovery_policy.as_str(),
                    "status": incident.status.as_str(),
                    "failureReason": "relay timeout",
                }),
            },
        )
        .await;
    }

    Ok(())
}

pub(in crate::web) async fn load_active_logout_recovery_policy_for_connection(
    pool: &PgPool,
    connection_id: uuid::Uuid,
) -> Result<Option<UpstreamLogoutRecoveryPolicy>, String> {
    expire_pending_upstream_logout_incidents_for_connection(pool, connection_id)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, %connection_id, "failed to refresh logout recovery incidents");
            "logout recovery state unavailable".to_string()
        })?;

    let recovery_policy = sqlx::query_scalar::<_, String>(
        r"
SELECT recovery_policy
FROM aegaeon.federation_logout_recovery_incidents
WHERE connection_id = $1
  AND status IN ('pending', 'expired', 'callback_rejected')
ORDER BY
  CASE recovery_policy
    WHEN 'disable_connection' THEN 0
    ELSE 1
  END,
  created_at DESC
LIMIT 1
        ",
    )
    .bind(connection_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        tracing::warn!(error = %error, %connection_id, "failed to query logout recovery incidents");
        "logout recovery state unavailable".to_string()
    })?;

    let Some(recovery_policy) = recovery_policy else {
        return Ok(None);
    };

    Ok(UpstreamLogoutRecoveryPolicy::parse(&recovery_policy).ok())
}
