use super::super::http_errors::error_response;
use super::snapshot_ids::collect_snapshot_ids;
use axum::{http::StatusCode, response::Response};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn ensure_no_revocation_conflicts(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    configuration_document: &serde_json::Value,
    request_id: &str,
) -> Result<(), Response> {
    let client_secret_ids = collect_snapshot_ids(
        configuration_document,
        "clientSecrets",
        &["id", "clientSecretId"],
        Some(&["ACTIVE", "RETIRING"]),
    );

    if !client_secret_ids.is_empty() {
        match sqlx::query_scalar::<_, Uuid>(
            r"
SELECT client_secret_id
FROM aegaeon.environment_revoked_client_secrets
WHERE environment_id = $1
  AND client_secret_id = ANY($2)
LIMIT 1
            ",
        )
        .bind(environment_id)
        .bind(&client_secret_ids)
        .fetch_optional(&mut **tx)
        .await
        {
            Ok(Some(conflict_id)) => {
                let details = serde_json::json!({ "clientSecretId": conflict_id });
                return Err(error_response(
                    StatusCode::CONFLICT,
                    "SECURITY_LEDGER_CONFLICT",
                    "Configuration references a revoked client secret",
                    Some(details),
                    Some(request_id),
                ));
            }
            Ok(None) => {}
            Err(_) => {
                return Err(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal_error",
                    "Failed to verify client secret revocation ledger",
                    None,
                    Some(request_id),
                ));
            }
        }
    }

    Ok(())
}
