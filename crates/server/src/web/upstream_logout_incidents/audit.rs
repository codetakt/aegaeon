use crate::organizations::request_work::async_store;
use serde_json::Value;
use sqlx::{Connection, PgConnection, PgPool};

use crate::audit_safety::redacted_audit_data;

pub(super) struct FederationLogoutRelayAuditEvent<'a> {
    pub(super) team_id: uuid::Uuid,
    pub(super) tenant_id: uuid::Uuid,
    pub(super) environment_id: uuid::Uuid,
    pub(super) connection_id: Option<uuid::Uuid>,
    pub(super) event_type: &'a str,
    pub(super) outcome: &'a str,
    pub(super) severity: &'a str,
    pub(super) actor_type: &'a str,
    pub(super) actor_id: Option<&'a str>,
    pub(super) request_id: &'a str,
    pub(super) data: Value,
}

pub(super) async fn write_federation_logout_relay_audit(
    pool: &PgPool,
    event: FederationLogoutRelayAuditEvent<'_>,
) -> Result<(), sqlx::Error> {
    async_store::ensure_environment_if_scoped(event.environment_id)?;
    let mut connection =
        crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(pool).await?;
    let result = async {
        let mut tx = connection.as_mut()?.begin().await?;
        write_federation_logout_relay_audit_in_tx(&mut tx, event).await?;
        async_store::admit_current_commit()?;
        tx.commit().await
    }
    .await;
    connection.release().await;
    super::store::scoped_environment()?;
    result
}

pub(super) async fn write_federation_logout_relay_audit_in_tx(
    connection: &mut PgConnection,
    event: FederationLogoutRelayAuditEvent<'_>,
) -> Result<(), sqlx::Error> {
    async_store::ensure_environment_if_scoped(event.environment_id)?;
    let target_type = if event.connection_id.is_some() {
        "connection"
    } else {
        "federation_logout"
    };
    let target_id = event.connection_id.map(|value| value.to_string());

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
VALUES (
  $1, $2, $3, $4, 'federation', $5, $6, now(),
  $7, $8, $9, $10, $11, $12
)
        ",
    )
    .bind(event.team_id)
    .bind(event.tenant_id)
    .bind(event.environment_id)
    .bind(event.event_type)
    .bind(event.outcome)
    .bind(event.severity)
    .bind(event.actor_type)
    .bind(event.actor_id)
    .bind(target_type)
    .bind(target_id)
    .bind(event.request_id)
    .bind(redacted_audit_data(event.data))
    .execute(connection)
    .await?;
    Ok(())
}
