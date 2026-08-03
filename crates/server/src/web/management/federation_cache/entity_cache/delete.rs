use super::super::super::management_internal_error;
use super::super::errors::federation_entity_cache_not_found;
use axum::response::Response;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(in crate::web::management) async fn delete_federation_entity_cache_entry_row(
    tx: &mut Transaction<'_, Postgres>,
    entity_cache_id: Uuid,
    environment_id: Uuid,
    request_id: &str,
) -> Result<(), Response> {
    match sqlx::query(
        r"
DELETE FROM aegaeon.federation_entity_cache
WHERE id = $1
  AND environment_id = $2
        ",
    )
    .bind(entity_cache_id)
    .bind(environment_id)
    .execute(&mut **tx)
    .await
    {
        Ok(result) if result.rows_affected() > 0 => Ok(()),
        Ok(_) => Err(federation_entity_cache_not_found(request_id)),
        Err(_) => Err(management_internal_error(
            request_id,
            "Failed to delete federation entity cache entry",
        )),
    }
}
