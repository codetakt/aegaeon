use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};

use crate::web::management::management_internal_error;

pub(in crate::web::management::core::bootstrap) async fn bootstrap_completed(
    tx: &mut Transaction<'_, Postgres>,
    request_id: &str,
) -> Result<bool, Response> {
    let row =
        sqlx::query("SELECT EXISTS (SELECT 1 FROM aegaeon.administrators) AS bootstrap_completed")
            .fetch_one(&mut **tx)
            .await
            .map_err(|_| {
                management_internal_error(request_id, "Failed to verify bootstrap status")
            })?;

    row.try_get("bootstrap_completed")
        .map_err(|_| management_internal_error(request_id, "Failed to read bootstrap status"))
}
