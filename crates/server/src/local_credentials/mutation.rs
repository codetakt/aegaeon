use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::audit_safety::redacted_audit_data;

use super::environment::load_runtime_environment_context;
use super::recovery_token::{generate_recovery_token, hash_one_time_token};
use super::rows::{password_credential_record_from_row, recovery_token_record_from_row};
use super::types::{
    IssuedRecoveryToken, PasswordCredentialRecord, RecoveryTokenPurpose, RecoveryTokenRecord,
    RedeemedRecoveryToken,
};

/// # Errors
///
/// Returns any `SQLx` error produced while revoking existing tokens or inserting
/// the new recovery token record.
pub async fn issue_recovery_token(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    purpose: RecoveryTokenPurpose,
    expires_in_secs: i64,
    created_by_administrator_id: Option<Uuid>,
    revoked_by_administrator_id: Option<Uuid>,
) -> Result<IssuedRecoveryToken, sqlx::Error> {
    sqlx::query(
        r"
UPDATE aegaeon.end_user_recovery_tokens
SET revoked_at = now(),
    revoked_by_administrator_id = COALESCE($3, revoked_by_administrator_id)
WHERE end_user_id = $1
  AND purpose = $2::aegaeon.end_user_recovery_token_purpose
  AND redeemed_at IS NULL
  AND revoked_at IS NULL
        ",
    )
    .bind(user_id)
    .bind(purpose.as_db_value())
    .bind(revoked_by_administrator_id)
    .execute(&mut **tx)
    .await?;

    let raw_token = generate_recovery_token();
    let token_hash = hash_one_time_token(&raw_token);
    let row = sqlx::query(
        r#"
INSERT INTO aegaeon.end_user_recovery_tokens (
  end_user_id,
  token_hash,
  purpose,
  expires_at,
  created_by_administrator_id
)
VALUES (
  $1,
  $2,
  $3::aegaeon.end_user_recovery_token_purpose,
  now() + make_interval(secs => $4),
  $5
)
RETURNING
  id,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at
            "#,
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(purpose.as_db_value())
    .bind(expires_in_secs)
    .bind(created_by_administrator_id)
    .fetch_one(&mut **tx)
    .await?;

    Ok(IssuedRecoveryToken {
        id: row.try_get::<Uuid, _>("id")?.to_string(),
        token: raw_token,
        expires_at: row.try_get("expires_at")?,
        purpose,
    })
}

/// # Errors
///
/// Returns any `SQLx` error produced while revoking the password credential.
pub async fn revoke_password_credential(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    revoked_by_administrator_id: Option<Uuid>,
) -> Result<Option<PasswordCredentialRecord>, sqlx::Error> {
    let row = sqlx::query(
        r#"
UPDATE aegaeon.end_user_password_credentials
SET status = 'REVOKED',
    revoked_by_administrator_id = $2,
    updated_at = now()
WHERE end_user_id = $1
  AND status = 'ACTIVE'
RETURNING
  id,
  status::text AS status,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at,
  to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS updated_at,
  CASE
    WHEN last_used_at IS NULL THEN NULL
    ELSE to_char(last_used_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  END AS last_used_at
            "#,
    )
    .bind(user_id)
    .bind(revoked_by_administrator_id)
    .fetch_optional(&mut **tx)
    .await?;

    row.as_ref()
        .map(password_credential_record_from_row)
        .transpose()
}

/// # Errors
///
/// Returns any `SQLx` error produced while revoking the recovery token.
pub async fn revoke_recovery_token(
    tx: &mut Transaction<'_, Postgres>,
    token_id: Uuid,
    user_id: Uuid,
    revoked_by_administrator_id: Option<Uuid>,
) -> Result<Option<RecoveryTokenRecord>, sqlx::Error> {
    let row = sqlx::query(
        r#"
UPDATE aegaeon.end_user_recovery_tokens
SET revoked_at = now(),
    revoked_by_administrator_id = $3
WHERE id = $1
  AND end_user_id = $2
  AND redeemed_at IS NULL
  AND revoked_at IS NULL
RETURNING
  id,
  purpose::text AS purpose,
  'REVOKED' AS status,
  to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
  CASE
    WHEN redeemed_at IS NULL THEN NULL
    ELSE to_char(redeemed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  END AS redeemed_at,
  to_char(revoked_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS revoked_at,
  to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS created_at
            "#,
    )
    .bind(token_id)
    .bind(user_id)
    .bind(revoked_by_administrator_id)
    .fetch_optional(&mut **tx)
    .await?;

    row.as_ref().map(recovery_token_record_from_row).transpose()
}

async fn upsert_password_credential(
    tx: &mut Transaction<'_, Postgres>,
    end_user_id: Uuid,
    new_password_hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
INSERT INTO aegaeon.end_user_password_credentials (
  end_user_id,
  password_hash,
  status
)
VALUES ($1, $2, 'ACTIVE')
ON CONFLICT (end_user_id) DO UPDATE
SET password_hash = EXCLUDED.password_hash,
    status = 'ACTIVE',
    revoked_by_administrator_id = NULL,
    last_used_at = NULL,
    updated_at = now()
        ",
    )
    .bind(end_user_id)
    .bind(new_password_hash)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// # Errors
///
/// Returns any `SQLx` error produced while redeeming the token or updating the
/// password and recovery-token state.
pub async fn redeem_recovery_token(
    pool: &PgPool,
    issuer: &str,
    raw_token: &str,
    purpose: RecoveryTokenPurpose,
    new_password_hash: &str,
    request_id: &str,
) -> Result<Option<RedeemedRecoveryToken>, sqlx::Error> {
    let Some(environment) = load_runtime_environment_context(pool, issuer).await? else {
        return Ok(None);
    };
    let token_hash = hash_one_time_token(raw_token);
    let mut tx = pool.begin().await?;

    let row = sqlx::query(
        r"
SELECT
  rt.id,
  rt.end_user_id,
  u.subject
FROM aegaeon.end_user_recovery_tokens rt
JOIN aegaeon.end_users u ON u.id = rt.end_user_id
WHERE rt.token_hash = $1
  AND rt.purpose = $2::aegaeon.end_user_recovery_token_purpose
  AND rt.redeemed_at IS NULL
  AND rt.revoked_at IS NULL
  AND rt.expires_at > now()
  AND u.environment_id = $3
  AND (
    ($2::aegaeon.end_user_recovery_token_purpose = 'activation' AND u.status = 'INVITED')
    OR ($2::aegaeon.end_user_recovery_token_purpose = 'password_reset' AND u.status = 'ACTIVE')
  )
FOR UPDATE OF rt, u
        ",
    )
    .bind(token_hash)
    .bind(purpose.as_db_value())
    .bind(environment.environment_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(None);
    };

    let token_id: Uuid = row.try_get("id")?;
    let end_user_id: Uuid = row.try_get("end_user_id")?;
    let subject: String = row.try_get("subject")?;

    sqlx::query(
        r"
INSERT INTO aegaeon.audit_events (
  team_id,
  tenant_id,
  environment_id,
  event_type,
  category,
  outcome,
  severity,
  occurred_at,
  actor_type,
  actor_id,
  target_type,
  target_id,
  request_id,
  data
)
VALUES (
  $1, $2, $3, $4, 'authentication', 'success', 'info', now(),
  'end_user', $5, 'end_user', $6, $7, $8
)
        ",
    )
    .bind(environment.team_id)
    .bind(environment.tenant_id)
    .bind(environment.environment_id)
    .bind(match purpose {
        RecoveryTokenPurpose::Activation => "auth.local.activation.redeemed.v1",
        RecoveryTokenPurpose::PasswordReset => "auth.local.passwordReset.redeemed.v1",
    })
    .bind(&subject)
    .bind(end_user_id.to_string())
    .bind(request_id)
    .bind(redacted_audit_data(serde_json::json!({
        "purpose": purpose.as_audit_label()
    })))
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r"
UPDATE aegaeon.end_user_recovery_tokens
SET redeemed_at = now()
WHERE id = $1
        ",
    )
    .bind(token_id)
    .execute(&mut *tx)
    .await?;

    upsert_password_credential(&mut tx, end_user_id, new_password_hash).await?;

    if purpose == RecoveryTokenPurpose::Activation {
        sqlx::query(
            r"
UPDATE aegaeon.end_users
SET status = 'ACTIVE',
    blocked_at = NULL,
    blocked_reason = NULL,
    updated_at = now()
WHERE id = $1
  AND status = 'INVITED'
            ",
        )
        .bind(end_user_id)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query(
        r"
UPDATE aegaeon.end_user_recovery_tokens
SET revoked_at = now()
WHERE end_user_id = $1
  AND id <> $2
  AND redeemed_at IS NULL
  AND revoked_at IS NULL
        ",
    )
    .bind(end_user_id)
    .bind(token_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(Some(RedeemedRecoveryToken { subject }))
}
