use super::super::audit::{write_federation_logout_relay_audit, FederationLogoutRelayAuditEvent};
use super::super::model::{hash_upstream_logout_secret, UpstreamLogoutIncidentRequest};
use serde_json::json;
use sqlx::PgPool;

pub(in crate::web) async fn create_upstream_logout_incident(
    pool: &PgPool,
    request: UpstreamLogoutIncidentRequest<'_>,
) -> Option<uuid::Uuid> {
    let session = request.session;
    let (Some(team_id), Some(tenant_id), Some(environment_id)) =
        (session.team_id, session.tenant_id, session.environment_id)
    else {
        return None;
    };

    let relay_token_hash = hash_upstream_logout_secret(request.relay_token);
    let session_hint_value_hash = session
        .session_hint_value
        .as_deref()
        .map(hash_upstream_logout_secret);

    let incident_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        r"
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
        ",
    )
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
    .bind(request.relay_ttl_secs.cast_signed())
    .fetch_one(pool)
    .await
    {
        Ok(id) => id,
        Err(error) => {
            tracing::warn!(error = %error, "failed to insert upstream logout incident");
            return None;
        }
    };

    write_federation_logout_relay_audit(
        pool,
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
    .await;

    Some(incident_id)
}
