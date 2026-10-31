use crate::local_credentials::IssuedRecoveryToken;
use crate::management::types::{IssueRecoveryTokenResponse, RecoveryToken};
use crate::web::management::management_internal_error;
use axum::response::Response;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub(super) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    issued: IssuedRecoveryToken,
    redeem_url: String,
    request_id: &str,
) -> Result<IssueRecoveryTokenResponse, Response> {
    let id = Uuid::parse_str(&issued.id)
        .map_err(|_| management_internal_error(request_id, "Invalid issued token identity"))?;
    let result = async {
        // Exact primary key and owner: never enumerate credential history.
        let row = sqlx::query(
            r#"
SELECT id, purpose::text AS purpose,
  CASE WHEN redeemed_at IS NOT NULL THEN 'REDEEMED'
       WHEN revoked_at IS NOT NULL THEN 'REVOKED'
       WHEN expires_at <= now() THEN 'EXPIRED' ELSE 'ACTIVE' END AS status,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
  to_char(redeemed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS redeemed_at,
  to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS revoked_at,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM aegaeon.end_user_recovery_tokens WHERE id=$1 AND end_user_id=$2
"#,
        )
        .bind(id)
        .bind(user)
        .fetch_one(&mut **tx)
        .await?;
        Ok::<_, sqlx::Error>(RecoveryToken {
            id: row.try_get::<Uuid, _>("id")?.to_string(),
            purpose: row.try_get("purpose")?,
            status: row.try_get("status")?,
            expires_at: row.try_get("expires_at")?,
            redeemed_at: row.try_get("redeemed_at")?,
            revoked_at: row.try_get("revoked_at")?,
            created_at: row.try_get("created_at")?,
        })
    }
    .await
    .map_err(|_| management_internal_error(request_id, "Failed to load new activation token"))?;
    Ok(IssueRecoveryTokenResponse {
        token: issued.token,
        redeem_url,
        recovery_token: result,
    })
}
