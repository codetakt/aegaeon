use sqlx::{PgPool, Row};
use uuid::Uuid;

use super::environment::load_runtime_environment_context;
use super::identity::{normalize_login_identifier, LoginIdentifier};
use super::password::verify_password_or_dummy;
use super::types::AuthenticatedLocalUser;

/// # Errors
///
/// Returns any `SQLx` error produced while loading credentials for the user.
pub async fn authenticate_local_user(
    pool: &PgPool,
    issuer: &str,
    raw_identifier: &str,
    password: &str,
) -> Result<Option<AuthenticatedLocalUser>, sqlx::Error> {
    let Some(environment) = load_runtime_environment_context(pool, issuer).await? else {
        return Ok(None);
    };
    let Some(identifier) = normalize_login_identifier(raw_identifier) else {
        return Ok(None);
    };

    let rows = match identifier {
        LoginIdentifier::Subject(subject) => {
            sqlx::query(
                r"
SELECT
  u.id AS end_user_id,
  u.subject,
  u.email,
  pc.id AS credential_id,
  pc.password_hash
FROM aegaeon.end_users u
JOIN aegaeon.end_user_password_credentials pc
  ON pc.end_user_id = u.id
 AND pc.status = 'ACTIVE'
WHERE u.environment_id = $1
  AND u.status = 'ACTIVE'
  AND u.subject = $2
LIMIT 2
                ",
            )
            .bind(environment.environment_id)
            .bind(subject)
            .fetch_all(pool)
            .await?
        }
        LoginIdentifier::Email(email) => {
            sqlx::query(
                r"
SELECT
  u.id AS end_user_id,
  u.subject,
  u.email,
  pc.id AS credential_id,
  pc.password_hash
FROM aegaeon.end_users u
JOIN aegaeon.end_user_password_credentials pc
  ON pc.end_user_id = u.id
 AND pc.status = 'ACTIVE'
WHERE u.environment_id = $1
  AND u.status = 'ACTIVE'
  AND lower(u.email) = lower($2)
ORDER BY u.created_at ASC, u.id ASC
LIMIT 2
                ",
            )
            .bind(environment.environment_id)
            .bind(email)
            .fetch_all(pool)
            .await?
        }
    };

    if rows.len() != 1 {
        let _ = verify_password_or_dummy(password, None);
        return Ok(None);
    }

    let row = &rows[0];
    let password_hash: String = row.try_get("password_hash")?;
    if !verify_password_or_dummy(password, Some(&password_hash)) {
        return Ok(None);
    }

    let credential_id: Uuid = row.try_get("credential_id")?;
    let confirmed = sqlx::query(
        r"
UPDATE aegaeon.end_user_password_credentials pc
SET last_used_at = now(), updated_at = now()
FROM aegaeon.end_users u
WHERE pc.id = $1
  AND pc.password_hash = $2
  AND pc.status = 'ACTIVE'
  AND u.id = pc.end_user_id
  AND u.environment_id = $3
  AND u.status = 'ACTIVE'
RETURNING pc.id
        ",
    )
    .bind(credential_id)
    .bind(&password_hash)
    .bind(environment.environment_id)
    .fetch_optional(pool)
    .await?
    .is_some();

    if !confirmed {
        return Ok(None);
    }

    Ok(Some(AuthenticatedLocalUser {
        end_user_id: row.try_get("end_user_id")?,
        subject: row.try_get("subject")?,
        email: row.try_get("email")?,
        environment,
    }))
}
