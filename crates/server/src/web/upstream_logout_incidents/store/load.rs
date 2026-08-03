use super::super::super::oauth_errors::no_cache_json_error_with_iss;
use super::super::model::{UpstreamLogoutIncidentRecord, UpstreamLogoutIncidentStatus};
use crate::upstream::UpstreamLogoutRecoveryPolicy;
use axum::{http::StatusCode, response::Response};
use sqlx::{PgPool, Row};

fn load_failed_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some("failed to load logout recovery incident"),
        issuer_base,
    )
}

pub(in crate::web::upstream_logout_incidents) async fn load_upstream_logout_incident_by_hash(
    pool: &PgPool,
    relay_token_hash: &str,
    issuer_base: &str,
) -> Result<Option<UpstreamLogoutIncidentRecord>, Response> {
    let row = sqlx::query(
        r"
SELECT
  id,
  team_id,
  tenant_id,
  environment_id,
  connection_id,
  upstream_issuer,
  recovery_policy,
  status,
  downstream_redirect_uri,
  downstream_state,
  expires_at <= now() AS is_expired
FROM aegaeon.federation_logout_recovery_incidents
WHERE relay_token_hash = $1
LIMIT 1
        ",
    )
    .bind(relay_token_hash)
    .fetch_optional(pool)
    .await
    .map_err(|_| load_failed_response(issuer_base))?;

    let Some(row) = row else {
        return Ok(None);
    };

    let recovery_policy = UpstreamLogoutRecoveryPolicy::parse(
        row.try_get::<String, _>("recovery_policy")
            .map_err(|_| load_failed_response(issuer_base))?
            .as_str(),
    )
    .map_err(|_| load_failed_response(issuer_base))?;
    let status = UpstreamLogoutIncidentStatus::parse(
        row.try_get::<String, _>("status")
            .map_err(|_| load_failed_response(issuer_base))?
            .as_str(),
    )
    .ok_or_else(|| load_failed_response(issuer_base))?;

    Ok(Some(UpstreamLogoutIncidentRecord {
        id: row
            .try_get("id")
            .map_err(|_| load_failed_response(issuer_base))?,
        team_id: row
            .try_get("team_id")
            .map_err(|_| load_failed_response(issuer_base))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| load_failed_response(issuer_base))?,
        environment_id: row
            .try_get("environment_id")
            .map_err(|_| load_failed_response(issuer_base))?,
        connection_id: row
            .try_get::<Option<uuid::Uuid>, _>("connection_id")
            .map_err(|_| load_failed_response(issuer_base))?,
        upstream_issuer: row
            .try_get("upstream_issuer")
            .map_err(|_| load_failed_response(issuer_base))?,
        recovery_policy,
        status,
        downstream_redirect_uri: row
            .try_get("downstream_redirect_uri")
            .map_err(|_| load_failed_response(issuer_base))?,
        downstream_state: row
            .try_get::<Option<String>, _>("downstream_state")
            .map_err(|_| load_failed_response(issuer_base))?,
        is_expired: row
            .try_get("is_expired")
            .map_err(|_| load_failed_response(issuer_base))?,
    }))
}
