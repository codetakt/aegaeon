use axum::{http::StatusCode, response::Response};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::management::types::PolicyDocument;

use super::super::configuration_documents::{
    require_configuration_policy_for_request, validate_configuration_document_for_environment,
};
use super::super::{error_response, management_internal_error, parse_uuid_param};
use super::types::ManagementEnvironmentRecord;

pub(in crate::web::management) fn resolve_management_configuration_version(
    configuration_version_id: Option<&str>,
    active_configuration_version_id: Uuid,
    request_id: &str,
) -> Result<Uuid, Response> {
    match configuration_version_id {
        Some(value) => parse_uuid_param(value, "configurationVersionId", request_id),
        None => Ok(active_configuration_version_id),
    }
}

pub(in crate::web::management) async fn load_management_configuration_policy(
    pool: &PgPool,
    environment: &ManagementEnvironmentRecord,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    load_configuration_policy(
        pool,
        environment.scope.environment,
        configuration_version_id,
        &environment.issuer_host,
        &environment.issuer_url,
        request_id,
    )
    .await
}

async fn load_configuration_policy(
    pool: &PgPool,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    issuer_host: &str,
    issuer_url: &str,
    request_id: &str,
) -> Result<PolicyDocument, Response> {
    let row = sqlx::query(
        r"
SELECT status::text AS status, configuration_document
FROM aegaeon.configuration_versions
WHERE id = $1
  AND environment_id = $2
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = row else {
        return Err(error_response(
            StatusCode::NOT_FOUND,
            "not_found",
            "Configuration version not found",
            None,
            Some(request_id),
        ));
    };

    let status: String = row.try_get("status").map_err(|_| {
        management_internal_error(request_id, "Failed to read configuration status")
    })?;
    if status == "ARCHIVED" {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Configuration version is archived",
            None,
            Some(request_id),
        ));
    }

    let configuration_document: serde_json::Value =
        row.try_get("configuration_document").map_err(|_| {
            management_internal_error(request_id, "Failed to read configuration document")
        })?;
    validate_configuration_document_for_environment(
        &configuration_document,
        issuer_host,
        issuer_url,
        request_id,
        "configurationDocument issuer fields did not match the environment",
    )?;

    require_configuration_policy_for_request(&configuration_document, request_id)
}
