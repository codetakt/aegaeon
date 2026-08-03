use super::super::super::{management_internal_error, stored_trust_anchor_from_row_result};
use crate::federation::TrustAnchor;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management::federation_cache) async fn load_resolvable_trust_anchors(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    request_id: &str,
) -> Result<Vec<TrustAnchor>, Response> {
    let trust_anchor_rows = sqlx::query(
        r"
SELECT
  id,
  environment_id,
  entity_id,
  jwks,
  metadata_policy,
  EXTRACT(EPOCH FROM created_at)::BIGINT AS created_epoch,
  EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_epoch
FROM aegaeon.federation_trust_anchors
WHERE environment_id = $1
        ",
    )
    .bind(environment_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| {
        management_internal_error(request_id, "Failed to load federation trust anchors")
    })?;

    trust_anchor_rows
        .iter()
        .map(|row| {
            stored_trust_anchor_from_row_result(row, request_id).and_then(|anchor| {
                anchor.to_trust_anchor().map_err(|_| {
                    management_internal_error(
                        request_id,
                        "Failed to decode federation trust anchor",
                    )
                })
            })
        })
        .collect()
}
