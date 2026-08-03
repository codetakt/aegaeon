use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::audit_safety::redacted_audit_data;
use crate::client_registry::RegisteredClient;

use super::environment::ActiveDcrEnvironment;
use super::DcrDatabaseError;

pub(super) async fn write_dcr_audit_event(
    tx: &mut Transaction<'_, Postgres>,
    environment: ActiveDcrEnvironment,
    database_client_id: Uuid,
    event_type: &str,
    client: &RegisteredClient,
    response_types: &[String],
    request_id: &str,
) -> Result<(), DcrDatabaseError> {
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
  $1, $2, $3, $4, 'client_registration', 'success', 'info', now(),
  'client', $5, 'client', $6, $7, $8
)
        ",
    )
    .bind(environment.team_id)
    .bind(environment.tenant_id)
    .bind(environment.environment_id)
    .bind(event_type)
    .bind(&client.client_id)
    .bind(database_client_id.to_string())
    .bind(request_id)
    .bind(redacted_audit_data(json!({
        "clientId": client.client_id.as_str(),
        "tokenEndpointAuthMethod": client.token_endpoint_auth_method.as_str(),
        "grantTypes": &client.allowed_grant_types,
        "responseTypes": response_types,
        "redirectUriCount": client.redirect_uris.len()
    })))
    .execute(&mut **tx)
    .await?;
    Ok(())
}
