use super::super::super::management_internal_error;
use super::super::errors::federation_trust_chain_not_found;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn delete_federation_trust_chain_row(
    tx: &mut Transaction<'_, Postgres>,
    trust_chain_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    match sqlx::query(
        r"
DELETE FROM aegaeon.federation_trust_chains
WHERE id = $1
  AND environment_id = $2
        ",
    )
    .bind(trust_chain_id)
    .bind(environment_id)
    .execute(&mut **tx)
    .await
    {
        Ok(result) if result.rows_affected() > 0 => Ok(()),
        Ok(_) => Err(federation_trust_chain_not_found(request_id)),
        Err(_) => Err(management_internal_error(
            request_id,
            "Failed to delete federation trust chain",
        )),
    }
}
