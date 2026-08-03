use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::super::super::management_internal_error;

pub(in crate::web::management) async fn load_next_configuration_version_number(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: Uuid,
    request_id: &str,
) -> Result<i64, Response> {
    let row = sqlx::query(
        r"
SELECT COALESCE(MAX(version_number), 0) + 1 AS next_version
FROM aegaeon.configuration_versions
WHERE environment_id = $1
        ",
    )
    .bind(environment_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| management_internal_error(request_id, "Database query failed"))?;

    row.try_get("next_version").map_err(|_| {
        management_internal_error(request_id, "Failed to read next configuration version")
    })
}
