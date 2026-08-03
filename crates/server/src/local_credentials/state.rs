use sqlx::PgPool;
use uuid::Uuid;

use super::rows::{password_credential_record_from_row, recovery_token_record_from_row};
use super::types::UserCredentialState;

/// # Errors
///
/// Returns any `SQLx` error produced while loading the user's credential state.
pub async fn load_user_credential_state(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<UserCredentialState, sqlx::Error> {
    let password = sqlx::query(
        r#"
SELECT
  id,
  status::text AS status,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
  CASE
    WHEN last_used_at IS NULL THEN NULL
    ELSE to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  END AS last_used_at
FROM aegaeon.end_user_password_credentials
WHERE end_user_id = $1
LIMIT 1
            "#,
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .as_ref()
    .map(password_credential_record_from_row)
    .transpose()?;

    let recovery_tokens = sqlx::query(
        r#"
SELECT
  id,
  purpose::text AS purpose,
  CASE
    WHEN redeemed_at IS NOT NULL THEN 'REDEEMED'
    WHEN revoked_at IS NOT NULL THEN 'REVOKED'
    WHEN expires_at <= now() THEN 'EXPIRED'
    ELSE 'ACTIVE'
  END AS status,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
  CASE
    WHEN redeemed_at IS NULL THEN NULL
    ELSE to_char(redeemed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  END AS redeemed_at,
  CASE
    WHEN revoked_at IS NULL THEN NULL
    ELSE to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  END AS revoked_at,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
FROM aegaeon.end_user_recovery_tokens
WHERE end_user_id = $1
ORDER BY created_at DESC, id DESC
            "#,
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| recovery_token_record_from_row(&row))
    .collect::<Result<Vec<_>, _>>()?;

    Ok(UserCredentialState {
        password,
        recovery_tokens,
    })
}
