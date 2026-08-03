use super::super::issuer_host_from_url;
use super::super::oauth_errors::json_error_with_iss;
use axum::{http::StatusCode, response::Response};
use serde_json::Value;
use sqlx::{PgPool, Row};

use crate::upstream::{
    open_upstream_client_secret, upstream_client_auth_method_supported,
    upstream_client_auth_method_uses_secret, UpstreamAttributeMapping, UpstreamClaimReleasePolicy,
    UpstreamJitProvisioningPolicy, UpstreamLogoutPolicy,
};

#[derive(Clone, Debug)]
pub(in crate::web) struct UpstreamConnection {
    pub(in crate::web) id: uuid::Uuid,
    pub(in crate::web) connection_identifier: String,
    pub(in crate::web) team_id: uuid::Uuid,
    pub(in crate::web) tenant_id: uuid::Uuid,
    pub(in crate::web) environment_id: uuid::Uuid,
    pub(in crate::web) configuration_version_id: uuid::Uuid,
    pub(in crate::web) connection_type: String,
    pub(in crate::web) issuer_url: String,
    pub(in crate::web) client_id: String,
    pub(in crate::web) client_auth_method: String,
    pub(in crate::web) client_secret_encrypted: Option<Vec<u8>>,
    pub(in crate::web) jit_provisioning_policy: Option<UpstreamJitProvisioningPolicy>,
    pub(in crate::web) attribute_mappings: Vec<UpstreamAttributeMapping>,
    pub(in crate::web) claim_release_policy: Option<UpstreamClaimReleasePolicy>,
    pub(in crate::web) logout_policy: Option<UpstreamLogoutPolicy>,
}

pub(super) async fn load_upstream_connection(
    pool: &PgPool,
    issuer: &str,
    connection_identifier: &str,
) -> Result<UpstreamConnection, String> {
    let issuer_host =
        issuer_host_from_url(issuer).ok_or_else(|| "invalid issuer host".to_string())?;
    let row = sqlx::query(
        r"
SELECT
  c.id AS id,
  c.connection_identifier AS connection_identifier,
  rt.team_id,
  rt.tenant_id,
  rt.environment_id,
  rt.configuration_version_id,
  c.connection_type::text AS connection_type,
  c.issuer_url AS issuer_url,
  c.client_id AS client_id,
  c.client_auth_method AS client_auth_method,
  c.client_secret_encrypted AS client_secret_encrypted,
  rt.configuration_document AS configuration_document
FROM aegaeon.active_runtime_environments rt
JOIN aegaeon.connections c
  ON c.environment_id = rt.environment_id
  AND c.configuration_version_id = rt.configuration_version_id
  AND c.connection_identifier = $2
  AND c.status = 'ACTIVE'
WHERE rt.issuer_host = $1
LIMIT 1
        ",
    )
    .bind(issuer_host)
    .bind(connection_identifier)
    .fetch_optional(pool)
    .await
    .map_err(|_| "failed to load upstream connection".to_string())?;

    let row = row.ok_or_else(|| "upstream connection not found".to_string())?;
    let id: uuid::Uuid = row
        .try_get("id")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let team_id: uuid::Uuid = row
        .try_get("team_id")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let connection_identifier: String = row
        .try_get("connection_identifier")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let tenant_id: uuid::Uuid = row
        .try_get("tenant_id")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let environment_id: uuid::Uuid = row
        .try_get("environment_id")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let configuration_version_id: uuid::Uuid = row
        .try_get("configuration_version_id")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let connection_type: String = row
        .try_get("connection_type")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let issuer_url: String = row
        .try_get("issuer_url")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let client_id: String = row
        .try_get("client_id")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let client_auth_method: String = row
        .try_get("client_auth_method")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let client_secret_encrypted: Option<Vec<u8>> = row
        .try_get("client_secret_encrypted")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let configuration_document: Value = row
        .try_get("configuration_document")
        .map_err(|_| "upstream connection invalid".to_string())?;
    let federation = configuration_document.get("federation");
    let jit_provisioning_policy =
        crate::upstream::parse_upstream_jit_provisioning_policy(federation)
            .map_err(|_| "upstream connection invalid".to_string())?;
    let attribute_mappings = crate::upstream::parse_upstream_attribute_mappings(federation)
        .map_err(|_| "upstream connection invalid".to_string())?;
    let claim_release_policy =
        crate::upstream::parse_upstream_claim_release_policy(federation, &attribute_mappings)
            .map_err(|_| "upstream connection invalid".to_string())?;
    let logout_policy = crate::upstream::parse_upstream_logout_policy(federation)
        .map_err(|_| "upstream connection invalid".to_string())?;

    Ok(UpstreamConnection {
        id,
        connection_identifier,
        team_id,
        tenant_id,
        environment_id,
        configuration_version_id,
        connection_type,
        issuer_url,
        client_id,
        client_auth_method,
        client_secret_encrypted,
        jit_provisioning_policy,
        attribute_mappings,
        claim_release_policy,
        logout_policy,
    })
}

pub(in crate::web) fn upstream_authorize_auth_material(
    connection: &UpstreamConnection,
    issuer_base: &str,
) -> Result<String, Response> {
    let auth_method = connection.client_auth_method.to_ascii_lowercase();
    if !upstream_client_auth_method_supported(&auth_method) {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("unsupported client_auth_method"),
            issuer_base,
        ));
    }
    if upstream_client_auth_method_uses_secret(&auth_method) {
        match connection.client_secret_encrypted.as_deref() {
            Some(encrypted) => {
                let _ = open_upstream_client_secret(
                    encrypted,
                    connection.environment_id,
                    connection.id,
                )
                .map_err(|_| {
                    json_error_with_iss(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        Some("upstream connection client_secret is unavailable"),
                        issuer_base,
                    )
                })?;
            }
            None => {
                return Err(json_error_with_iss(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("upstream connection client_secret is not configured"),
                    issuer_base,
                ));
            }
        }
    }
    Ok(auth_method)
}
