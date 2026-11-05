use crate::web::management::http_errors::management_database_error as database_error;
use crate::web::management::request_support::owned::reads;
use axum::response::Response;
use sqlx::PgPool;
use uuid::Uuid;

use crate::management::types::ApiKey;

use super::mapper::api_key_from_row_result;

pub(in crate::web::management::api_keys) async fn list_api_key_rows(
    pool: &PgPool,
    team_id: Uuid,
    request_id: &str,
) -> Result<Vec<ApiKey>, Response> {
    let rows = reads::all(
        pool,
        sqlx::query(
            r#"
	SELECT
	  ak.id,
	  ak.team_id,
  ak.service_administrator_id,
	  ak.name,
	  ak.key_prefix,
	  ARRAY(
	    SELECT akc.capability::text
	    FROM aegaeon.api_key_capabilities akc
	    WHERE akc.api_key_id = ak.id
	    ORDER BY akc.capability::text
	  ) AS capabilities,
	  ak.status::text AS status,
	  to_char(ak.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
	  to_char(ak.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
	FROM aegaeon.api_keys ak
	WHERE ak.team_id = $1 AND ak.status = 'ACTIVE'
	ORDER BY ak.created_at DESC
	        "#,
        )
        .bind(team_id),
        request_id,
    )
    .await?
    .map_err(|error| database_error(request_id, &error, "Database query failed"))?;

    rows.iter()
        .map(|row| api_key_from_row_result(row, request_id))
        .collect()
}
