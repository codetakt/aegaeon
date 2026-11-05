use super::super::audit::{
    write_federation_logout_relay_audit_in_tx, FederationLogoutRelayAuditEvent,
};
use super::super::model::{hash_upstream_logout_secret, UpstreamLogoutIncidentRequest};
use crate::organizations::request_work::async_store;
use serde_json::json;
use sqlx::{Connection, PgConnection, PgPool};

pub(in crate::web) async fn create_upstream_logout_incident(
    pool: &PgPool,
    request: UpstreamLogoutIncidentRequest<'_>,
) -> Result<Option<uuid::Uuid>, sqlx::Error> {
    let scoped = super::scoped_environment()?;
    if scoped.is_some()
        && (request.session.environment_id != scoped
            || request.session.team_id.is_none()
            || request.session.tenant_id.is_none())
    {
        return Err(sqlx::Error::Protocol(
            "foreign logout incident Environment".into(),
        ));
    }
    let mut connection =
        crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(pool).await?;
    let result = create_in_tx(connection.as_mut()?, request).await;
    connection.release().await;
    super::scoped_environment()?;
    result
}

async fn create_in_tx(
    connection: &mut PgConnection,
    request: UpstreamLogoutIncidentRequest<'_>,
) -> Result<Option<uuid::Uuid>, sqlx::Error> {
    let session = request.session;
    let (Some(team_id), Some(tenant_id), Some(environment_id)) =
        (session.team_id, session.tenant_id, session.environment_id)
    else {
        return Ok(None);
    };

    async_store::ensure_environment_if_scoped(environment_id)?;
    let ttl = i64::try_from(request.relay_ttl_secs)
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(|| sqlx::Error::Protocol("invalid logout relay lifetime".into()))?;
    let mut tx = connection.begin().await?;
    let relay_token_hash = hash_upstream_logout_secret(request.relay_token);
    let session_hint_value_hash = session
        .session_hint_value
        .as_deref()
        .map(hash_upstream_logout_secret);

    let incident_id = sqlx::query_scalar::<_, uuid::Uuid>(CREATE_INCIDENT_QUERY)
        .bind(team_id)
        .bind(tenant_id)
        .bind(environment_id)
        .bind(session.connection_id)
        .bind(request.downstream_client_id)
        .bind(&session.issuer)
        .bind(session.recovery_policy.as_str())
        .bind(session.session_hint_claim.as_deref())
        .bind(session_hint_value_hash)
        .bind(relay_token_hash)
        .bind(request.downstream_redirect_uri)
        .bind(request.downstream_state)
        .bind(request.request_id)
        .bind(ttl)
        .fetch_one(&mut *tx)
        .await?;

    write_federation_logout_relay_audit_in_tx(
        &mut tx,
        FederationLogoutRelayAuditEvent {
            team_id,
            tenant_id,
            environment_id,
            connection_id: session.connection_id,
            event_type: "federation.upstreamLogoutRelay.started.v1",
            outcome: "success",
            severity: "info",
            actor_type: if request.actor_id.is_some() {
                "end_user"
            } else {
                "system"
            },
            actor_id: request.actor_id,
            request_id: request.request_id,
            data: json!({
                "incidentId": incident_id.to_string(),
                "upstreamIssuer": session.issuer,
                "recoveryPolicy": session.recovery_policy.as_str(),
                "downstreamClientId": request.downstream_client_id,
                "sessionHintClaim": session.session_hint_claim,
                "sessionHintPresent": session.session_hint_value.is_some(),
                "downstreamRedirectUri": request.downstream_redirect_uri,
            }),
        },
    )
    .await?;
    async_store::admit_current_commit()?;
    tx.commit().await?;
    Ok(Some(incident_id))
}

const CREATE_INCIDENT_QUERY: &str = r"
INSERT INTO aegaeon.federation_logout_recovery_incidents (
  team_id,
  tenant_id,
  environment_id,
  connection_id,
  downstream_client_id,
  upstream_issuer,
  recovery_policy,
  status,
  session_hint_claim,
  session_hint_value_hash,
  relay_token_hash,
  downstream_redirect_uri,
  downstream_state,
  request_id,
  expires_at
)
VALUES (
  $1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12, $13,
  now() + ($14::bigint || ' seconds')::interval
)
RETURNING id
        ";
