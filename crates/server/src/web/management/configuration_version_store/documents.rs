use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::{error_response, management_internal_error};

pub(in crate::web::management) fn require_configuration_document_value(
    document: Option<serde_json::Value>,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    document.ok_or_else(|| {
        management_internal_error(request_id, "Active configuration document is missing")
    })
}

pub(in crate::web::management) async fn load_configuration_document_required(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let row = sqlx::query(
        r"
SELECT configuration_document
FROM aegaeon.configuration_versions
WHERE id = $1
  AND environment_id = $2
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let document = row
        .map(|row| {
            row.try_get("configuration_document").map_err(|_| {
                management_internal_error(request_id, "Failed to read configuration document")
            })
        })
        .transpose()?;
    require_configuration_document_value(document, request_id)
}

pub(in crate::web::management) async fn load_configuration_document_for_update(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_version_id: Uuid,
    request_id: &str,
) -> Result<serde_json::Value, Response> {
    let row = sqlx::query(
        r"
SELECT cv.status::text AS status, cv.configuration_document
FROM aegaeon.configuration_versions cv
WHERE cv.id = $1
  AND cv.environment_id = $2
FOR UPDATE OF cv
        ",
    )
    .bind(configuration_version_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
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

    row.try_get("configuration_document")
        .map_err(|_| management_internal_error(request_id, "Failed to read configuration document"))
}
