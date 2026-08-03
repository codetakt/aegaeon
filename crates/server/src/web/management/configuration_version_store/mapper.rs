use axum::response::Response;
use sqlx::postgres::PgRow;
use sqlx::Row;
use uuid::Uuid;

use crate::management::types::ConfigurationVersion;

use super::super::{management_internal_error, required_row_value, sha256_hex};

fn configuration_hash_from_row(row: &PgRow, request_id: &str) -> Result<String, Response> {
    let message = "Failed to read configuration version row";
    let stored_hash: String = required_row_value(row, "configuration_hash", request_id, message)?;
    let Ok(document) = row.try_get::<serde_json::Value, _>("configuration_document") else {
        return Ok(stored_hash);
    };
    let canonical =
        crate::runtime_configuration::serialize_canonical_configuration_document_v1(&document)
            .map_err(|_| management_internal_error(request_id, message))?;
    Ok(sha256_hex(canonical.as_bytes()))
}

fn configuration_version_from_row(
    row: &PgRow,
    request_id: &str,
    include_document: bool,
) -> Result<ConfigurationVersion, Response> {
    let message = "Failed to read configuration version row";
    let id: Uuid = required_row_value(row, "id", request_id, message)?;
    let environment_id: Uuid = required_row_value(row, "environment_id", request_id, message)?;
    let version_number: i64 = required_row_value(row, "version_number", request_id, message)?;
    let version_number = u64::try_from(version_number)
        .map_err(|_| management_internal_error(request_id, message))?;
    let schema_version: i32 = required_row_value(row, "schema_version", request_id, message)?;
    let schema_version = u32::try_from(schema_version)
        .map_err(|_| management_internal_error(request_id, message))?;
    let configuration_hash = configuration_hash_from_row(row, request_id)?;
    let status: String = required_row_value(row, "status", request_id, message)?;
    let comment: Option<String> = required_row_value(row, "comment", request_id, message)?;
    let created_at: String = required_row_value(row, "created_at", request_id, message)?;
    let configuration_document = if include_document {
        required_row_value(row, "configuration_document", request_id, message)?
    } else {
        None
    };

    Ok(ConfigurationVersion {
        id: id.to_string(),
        environment_id: environment_id.to_string(),
        version_number,
        schema_version,
        configuration_hash,
        status,
        created_at,
        comment,
        configuration_document,
    })
}

pub(in crate::web::management) fn configuration_version_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<ConfigurationVersion, Response> {
    configuration_version_from_row(row, request_id, true)
}

pub(in crate::web::management) fn configuration_version_summary_from_row_result(
    row: &PgRow,
    request_id: &str,
) -> Result<ConfigurationVersion, Response> {
    configuration_version_from_row(row, request_id, false)
}
