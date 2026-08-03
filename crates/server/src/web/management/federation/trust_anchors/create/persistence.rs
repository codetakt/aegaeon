use super::super::super::super::{
    error_response, is_unique_violation, management_internal_error, trust_anchor_from_row_result,
    ManagementEnvironmentScope,
};
use crate::management::types::{CreateFederationTrustAnchorRequest, FederationTrustAnchor};
use axum::{http::StatusCode, response::Response};
use sqlx::{PgPool, Postgres, Transaction};

pub(super) async fn ensure_federation_trust_anchor_unique(
    pool: &PgPool,
    scope: ManagementEnvironmentScope,
    entity_id: &str,
    request_id: &str,
) -> Result<(), Response> {
    let conflict_row = sqlx::query(
        r"
SELECT id
FROM aegaeon.federation_trust_anchors
WHERE environment_id = $1
  AND entity_id = $2
        ",
    )
    .bind(scope.environment)
    .bind(entity_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    if conflict_row.is_some() {
        return Err(trust_anchor_conflict(request_id));
    }

    Ok(())
}

pub(super) async fn insert_federation_trust_anchor(
    tx: &mut Transaction<'_, Postgres>,
    scope: ManagementEnvironmentScope,
    entity_id: &str,
    req: &CreateFederationTrustAnchorRequest,
    request_id: &str,
) -> Result<FederationTrustAnchor, Response> {
    let row = sqlx::query(
        r#"
INSERT INTO aegaeon.federation_trust_anchors (environment_id, entity_id, jwks, metadata_policy)
VALUES ($1, $2, $3, $4)
RETURNING
  id,
  environment_id,
  entity_id,
  jwks,
  metadata_policy,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
        "#,
    )
    .bind(scope.environment)
    .bind(entity_id)
    .bind(&req.jwks)
    .bind(&req.metadata_policy)
    .fetch_one(&mut **tx)
    .await
    .map_err(|err| {
        if is_unique_violation(&err) {
            trust_anchor_conflict(request_id)
        } else {
            trust_anchor_create_error(request_id)
        }
    })?;

    trust_anchor_from_row_result(&row, request_id).map_err(|_| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "Failed to load created trust anchor",
            None,
            Some(request_id),
        )
    })
}

fn trust_anchor_conflict(request_id: &str) -> Response {
    error_response(
        StatusCode::CONFLICT,
        "conflict",
        "A trust anchor with this entity_id already exists in this environment",
        None,
        Some(request_id),
    )
}

fn trust_anchor_create_error(request_id: &str) -> Response {
    error_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal_error",
        "Failed to create trust anchor",
        None,
        Some(request_id),
    )
}
