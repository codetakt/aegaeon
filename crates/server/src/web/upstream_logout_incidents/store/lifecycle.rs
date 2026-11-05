use super::super::audit::{
    write_federation_logout_relay_audit_in_tx, FederationLogoutRelayAuditEvent,
};
use super::super::model::{UpstreamLogoutIncidentRecord, UpstreamLogoutIncidentStatus};
use crate::organizations::request_work::async_store;
use crate::upstream::UpstreamLogoutRecoveryPolicy;
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool, Row};

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
) -> Result<bool, sqlx::Error> {
    async_store::ensure_environment_if_scoped(incident.environment_id)?;
    let mut connection =
        crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(pool).await?;
    let result = update_in_tx(connection.as_mut()?, incident, request_id, transition).await;
    connection.release().await;
    super::scoped_environment()?;
    result
}

async fn update_in_tx(
    connection: &mut PgConnection,
    incident: &UpstreamLogoutIncidentRecord,
    request_id: &str,
    transition: UpstreamLogoutIncidentTransition<'_>,
) -> Result<bool, sqlx::Error> {
    let mut tx = connection.begin().await?;
    let changed = sqlx::query(
        r"
UPDATE aegaeon.federation_logout_recovery_incidents
SET
  status = $2,
  failure_reason = $3,
  resolved_at = now()
WHERE id = $1 AND environment_id = $4 AND status = 'pending'
  AND (($2 = 'completed' AND expires_at > clock_timestamp())
       OR ($2 = 'expired' AND expires_at <= clock_timestamp()))
        ",
    )
    .bind(incident.id)
    .bind(transition.next_status.as_str())
    .bind(transition.failure_reason)
    .bind(incident.environment_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if changed != 1 {
        tx.rollback().await?;
        return Ok(false);
    }

    write_federation_logout_relay_audit_in_tx(
        &mut tx,
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
    .await?;
    async_store::admit_current_commit()?;
    tx.commit().await?;
    Ok(true)
}

async fn expire_pending_upstream_logout_incidents_for_connection(
    connection: &mut PgConnection,
    connection_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    let environment = super::scoped_environment()?;
    let mut tx = connection.begin().await?;
    let rows = sqlx::query(
        r"
WITH batch AS (
 SELECT id FROM aegaeon.federation_logout_recovery_incidents
 WHERE connection_id = $1 AND status = 'pending' AND expires_at <= now()
   AND ($2::uuid IS NULL OR environment_id = $2)
 ORDER BY expires_at, id LIMIT 100 FOR UPDATE
)
UPDATE aegaeon.federation_logout_recovery_incidents
SET
  status = 'expired',
  failure_reason = 'relay timeout',
  resolved_at = now()
WHERE id IN (SELECT id FROM batch)
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
    .bind(environment)
    .fetch_all(&mut *tx)
    .await?;

    for row in rows {
        let recovery_policy =
            UpstreamLogoutRecoveryPolicy::parse(&row.try_get::<String, _>("recovery_policy")?)
                .map_err(|_| sqlx::Error::Protocol("invalid logout recovery policy".into()))?;
        let incident = UpstreamLogoutIncidentRecord {
            id: row.try_get("id")?,
            team_id: row.try_get("team_id")?,
            tenant_id: row.try_get("tenant_id")?,
            environment_id: row.try_get("environment_id")?,
            connection_id: row.try_get("connection_id")?,
            upstream_issuer: row.try_get("upstream_issuer")?,
            recovery_policy,
            status: UpstreamLogoutIncidentStatus::Expired,
            downstream_redirect_uri: String::new(),
            downstream_state: None,
            is_expired: true,
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        write_federation_logout_relay_audit_in_tx(
            &mut tx,
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
        .await?;
    }
    async_store::admit_current_commit()?;
    tx.commit().await?;
    Ok(())
}

pub(in crate::web) async fn load_active_logout_recovery_policy_for_connection(
    pool: &PgPool,
    connection_id: uuid::Uuid,
) -> Result<Option<UpstreamLogoutRecoveryPolicy>, String> {
    let environment =
        super::scoped_environment().map_err(|_| "logout recovery state unavailable")?;
    let mut connection =
        crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(pool)
            .await
            .map_err(|_| "logout recovery state unavailable")?;
    let result = load_policy(
        connection
            .as_mut()
            .map_err(|_| "logout recovery state unavailable")?,
        connection_id,
        environment,
    )
    .await;
    connection.release().await;
    super::scoped_environment().map_err(|_| "logout recovery state unavailable")?;
    result.map_err(|_| "logout recovery state unavailable".to_string())
}

async fn load_policy(
    connection: &mut PgConnection,
    connection_id: uuid::Uuid,
    environment: Option<uuid::Uuid>,
) -> Result<Option<UpstreamLogoutRecoveryPolicy>, sqlx::Error> {
    // Resolve the actual connection first; a foreign scoped reference must not
    // appear to have no restrictive incident policy.
    let actual: uuid::Uuid = sqlx::query_scalar("SELECT environment_id FROM aegaeon.connections WHERE id=$1 AND ($2::uuid IS NULL OR environment_id=$2)")
        .bind(connection_id).bind(environment).fetch_one(&mut *connection).await?;
    async_store::ensure_environment_if_scoped(actual)?;
    expire_pending_upstream_logout_incidents_for_connection(connection, connection_id).await?;
    let recovery_policy = sqlx::query_scalar::<_, String>(
        r"
SELECT recovery_policy
FROM aegaeon.federation_logout_recovery_incidents
WHERE connection_id = $1
  AND ($2::uuid IS NULL OR environment_id=$2)
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
    .bind(environment)
    .fetch_optional(connection)
    .await?;

    let Some(recovery_policy) = recovery_policy else {
        return Ok(None);
    };

    UpstreamLogoutRecoveryPolicy::parse(&recovery_policy)
        .map(Some)
        .map_err(|_| sqlx::Error::Protocol("invalid logout recovery policy".into()))
}
