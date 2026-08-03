mod resolvable;

use super::super::{management_internal_error, trust_anchor_from_row_result};
use super::errors::federation_trust_anchor_not_found;
use crate::management::types::FederationTrustAnchor;
use axum::response::Response;
pub(super) use resolvable::load_resolvable_trust_anchors;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn load_federation_trust_anchor_entry(
    tx: &mut Transaction<'_, Postgres>,
    trust_anchor_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<FederationTrustAnchor, Response> {
    let existing_row = sqlx::query(
        r#"
SELECT
  id,
  environment_id,
  entity_id,
  jwks,
  metadata_policy,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.federation_trust_anchors
WHERE id = $1
  AND environment_id = $2
        "#,
    )
    .bind(trust_anchor_id)
    .bind(environment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to load trust anchor"))?;

    let Some(existing_row) = existing_row else {
        return Err(federation_trust_anchor_not_found(request_id));
    };

    trust_anchor_from_row_result(&existing_row, request_id)
}

pub(in crate::web::management) async fn load_visible_federation_trust_anchor(
    pool: &PgPool,
    team_id: Uuid,
    trust_anchor_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<FederationTrustAnchor, Response> {
    let row = sqlx::query(
        r#"
SELECT
  ta.id,
  ta.environment_id,
  ta.entity_id,
  ta.jwks,
  ta.metadata_policy,
  to_char(ta.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(ta.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at
FROM aegaeon.federation_trust_anchors ta
JOIN aegaeon.environments e ON e.id = ta.environment_id
JOIN aegaeon.tenants t ON t.id = e.tenant_id
WHERE ta.id = $1
  AND ta.environment_id = $2
  AND t.team_id = $3
  AND t.status <> 'DELETED'
  AND e.status <> 'DELETED'
        "#,
    )
    .bind(trust_anchor_id)
    .bind(environment_id)
    .bind(team_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    let Some(row) = row else {
        return Err(federation_trust_anchor_not_found(request_id));
    };

    trust_anchor_from_row_result(&row, request_id)
}

pub(in crate::web::management) async fn delete_federation_trust_anchor_row(
    tx: &mut Transaction<'_, Postgres>,
    trust_anchor_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    match sqlx::query(
        r"
DELETE FROM aegaeon.federation_trust_anchors
WHERE id = $1
  AND environment_id = $2
        ",
    )
    .bind(trust_anchor_id)
    .bind(environment_id)
    .execute(&mut **tx)
    .await
    {
        Ok(result) if result.rows_affected() > 0 => Ok(()),
        Ok(_) => Err(federation_trust_anchor_not_found(request_id)),
        Err(_) => Err(management_internal_error(
            request_id,
            "Failed to delete trust anchor",
        )),
    }
}
