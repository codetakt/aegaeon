use super::claims::validate_custom_claims;
use super::model::{EndUserProfileRecord, UpdateProfileError, SUBJECT_POLICY_EXPLICIT};
use super::rows::{issuer_host_from_url, profile_from_row};
use serde_json::{Map, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

const USER_PROFILE_BY_ID_SQL: &str = r#"
SELECT
  u.id AS user_id,
  u.subject,
  COALESCE(p.subject_policy, $2) AS subject_policy,
  u.email,
  COALESCE(p.email_verified, false) AS email_verified,
  p.display_name,
  COALESCE(p.custom_claims, '{}'::jsonb) AS custom_claims,
  COALESCE(p.profile_version, 1) AS version,
  COALESCE(
    to_char(p.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) AS updated_at,
  COALESCE(
    EXTRACT(EPOCH FROM p.updated_at)::bigint,
    EXTRACT(EPOCH FROM u.updated_at)::bigint
  ) AS updated_at_epoch_seconds
FROM aegaeon.end_users u
LEFT JOIN aegaeon.end_user_profiles p
  ON p.end_user_id = u.id
WHERE u.id = $1
  AND u.status <> 'DELETED'
        "#;

const USER_PROFILE_BY_ID_FOR_UPDATE_SQL: &str = r#"
SELECT
  u.id AS user_id,
  u.subject,
  COALESCE(p.subject_policy, $2) AS subject_policy,
  u.email,
  COALESCE(p.email_verified, false) AS email_verified,
  p.display_name,
  COALESCE(p.custom_claims, '{}'::jsonb) AS custom_claims,
  COALESCE(p.profile_version, 1) AS version,
  COALESCE(
    to_char(p.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) AS updated_at,
  COALESCE(
    EXTRACT(EPOCH FROM p.updated_at)::bigint,
    EXTRACT(EPOCH FROM u.updated_at)::bigint
  ) AS updated_at_epoch_seconds
FROM aegaeon.end_users u
LEFT JOIN aegaeon.end_user_profiles p
  ON p.end_user_id = u.id
WHERE u.id = $1
  AND u.status <> 'DELETED'
FOR UPDATE OF u
        "#;

struct ProfileUpdatePatch {
    email: Option<Option<String>>,
    email_verified: Option<bool>,
    display_name: Option<Option<String>>,
    custom_claims: Option<Value>,
}

impl ProfileUpdatePatch {
    fn validate(&self) -> Result<(), UpdateProfileError> {
        if let Some(ref claims) = self.custom_claims {
            validate_custom_claims(claims).map_err(UpdateProfileError::InvalidCustomClaims)?;
        }
        Ok(())
    }
}

/// Ensure the profile row exists for the given end user.
///
/// # Errors
///
/// Returns any `SQLx` error encountered while inserting the default profile stub.
pub async fn ensure_profile_row(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r"
INSERT INTO aegaeon.end_user_profiles (
  end_user_id,
  subject_policy,
  email_verified,
  display_name,
  custom_claims,
  profile_version
)
VALUES ($1, $2, false, NULL, '{}'::jsonb, 1)
ON CONFLICT (end_user_id) DO NOTHING
        ",
    )
    .bind(user_id)
    .bind(SUBJECT_POLICY_EXPLICIT)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Load the current profile view for a specific end user ID.
///
/// # Errors
///
/// Returns any `SQLx` error emitted while querying the end-user/profile join.
pub async fn load_user_profile(
    pool: &PgPool,
    user_id: Uuid,
) -> Result<Option<EndUserProfileRecord>, sqlx::Error> {
    let row = sqlx::query(USER_PROFILE_BY_ID_SQL)
        .bind(user_id)
        .bind(SUBJECT_POLICY_EXPLICIT)
        .fetch_optional(pool)
        .await?;

    row.as_ref().map(profile_from_row).transpose()
}

/// Load an active user profile using issuer/subject lookup.
///
/// # Errors
///
/// Returns any `SQLx` error emitted while querying the issuer-host/subject join.
pub async fn load_user_profile_for_subject(
    pool: &PgPool,
    issuer: &str,
    subject: &str,
) -> Result<Option<EndUserProfileRecord>, sqlx::Error> {
    let Some(issuer_host) = issuer_host_from_url(issuer) else {
        return Ok(None);
    };

    let row = sqlx::query(
        r#"
SELECT
  u.id AS user_id,
  u.subject,
  COALESCE(p.subject_policy, $3) AS subject_policy,
  u.email,
  COALESCE(p.email_verified, false) AS email_verified,
  p.display_name,
  COALESCE(p.custom_claims, '{}'::jsonb) AS custom_claims,
  COALESCE(p.profile_version, 1) AS version,
  COALESCE(
    to_char(p.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    to_char(u.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  ) AS updated_at,
  COALESCE(
    EXTRACT(EPOCH FROM p.updated_at)::bigint,
    EXTRACT(EPOCH FROM u.updated_at)::bigint
  ) AS updated_at_epoch_seconds
FROM aegaeon.end_users u
JOIN aegaeon.active_runtime_environments rt
  ON rt.environment_id = u.environment_id
LEFT JOIN aegaeon.end_user_profiles p
  ON p.end_user_id = u.id
WHERE rt.issuer_host = $1
  AND u.subject = $2
  AND u.status = 'ACTIVE'
LIMIT 1
        "#,
    )
    .bind(issuer_host)
    .bind(subject)
    .bind(SUBJECT_POLICY_EXPLICIT)
    .fetch_optional(pool)
    .await?;

    row.as_ref().map(profile_from_row).transpose()
}

/// Update mutable end-user profile fields under optimistic concurrency control.
///
/// # Errors
///
/// Returns [`UpdateProfileError`] when the profile is missing, the version check fails, custom
/// claims are invalid, or `SQLx` reports a database error during the transaction.
pub async fn update_user_profile(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    base_version: i64,
    email: Option<Option<String>>,
    email_verified: Option<bool>,
    display_name: Option<Option<String>>,
    custom_claims: Option<Value>,
) -> Result<EndUserProfileRecord, UpdateProfileError> {
    update_user_profile_with_previous(
        tx,
        user_id,
        base_version,
        email,
        email_verified,
        display_name,
        custom_claims,
    )
    .await
    .map(|(_, updated)| updated)
}

/// Update mutable end-user profile fields and return the locked pre-image plus updated record.
///
/// # Errors
///
/// Returns [`UpdateProfileError`] when the profile is missing, the version check fails, custom
/// claims are invalid, or `SQLx` reports a database error during the transaction.
pub async fn update_user_profile_with_previous(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    base_version: i64,
    email: Option<Option<String>>,
    email_verified: Option<bool>,
    display_name: Option<Option<String>>,
    custom_claims: Option<Value>,
) -> Result<(EndUserProfileRecord, EndUserProfileRecord), UpdateProfileError> {
    let patch = ProfileUpdatePatch {
        email,
        email_verified,
        display_name,
        custom_claims,
    };
    patch.validate()?;

    let existing = load_user_profile_for_update(tx, user_id).await?;
    ensure_profile_version(&existing, base_version)?;
    ensure_profile_row(tx, user_id).await?;
    update_end_user_email(tx, user_id, patch.email.as_ref()).await?;
    update_profile_fields(tx, user_id, existing.version + 1, patch).await?;
    let updated = reload_user_profile_after_update(tx, user_id).await?;
    Ok((existing, updated))
}

pub async fn load_user_profile_for_update(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<EndUserProfileRecord, UpdateProfileError> {
    sqlx::query(USER_PROFILE_BY_ID_FOR_UPDATE_SQL)
        .bind(user_id)
        .bind(SUBJECT_POLICY_EXPLICIT)
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| profile_from_row(&row))
        .transpose()?
        .ok_or(UpdateProfileError::NotFound)
}

fn ensure_profile_version(
    existing: &EndUserProfileRecord,
    base_version: i64,
) -> Result<(), UpdateProfileError> {
    if existing.version == base_version {
        Ok(())
    } else {
        Err(UpdateProfileError::VersionMismatch {
            current_version: existing.version,
        })
    }
}

async fn update_end_user_email(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    email: Option<&Option<String>>,
) -> Result<(), UpdateProfileError> {
    if let Some(email) = email {
        sqlx::query(
            r"
UPDATE aegaeon.end_users
SET email = $2,
    updated_at = now()
WHERE id = $1
            ",
        )
        .bind(user_id)
        .bind(email.clone())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

async fn update_profile_fields(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
    next_version: i64,
    patch: ProfileUpdatePatch,
) -> Result<(), UpdateProfileError> {
    sqlx::query(
        r"
UPDATE aegaeon.end_user_profiles
SET subject_policy = $2,
    email_verified = COALESCE($3, email_verified),
    display_name = CASE
      WHEN $4 THEN $5
      ELSE display_name
    END,
    custom_claims = CASE
      WHEN $6 THEN $7
      ELSE custom_claims
    END,
    profile_version = $8,
    updated_at = now()
WHERE end_user_id = $1
        ",
    )
    .bind(user_id)
    .bind(SUBJECT_POLICY_EXPLICIT)
    .bind(patch.email_verified)
    .bind(patch.display_name.is_some())
    .bind(patch.display_name.flatten())
    .bind(patch.custom_claims.is_some())
    .bind(
        patch
            .custom_claims
            .unwrap_or_else(|| Value::Object(Map::default())),
    )
    .bind(next_version)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn reload_user_profile_after_update(
    tx: &mut Transaction<'_, Postgres>,
    user_id: Uuid,
) -> Result<EndUserProfileRecord, UpdateProfileError> {
    sqlx::query(USER_PROFILE_BY_ID_SQL)
        .bind(user_id)
        .bind(SUBJECT_POLICY_EXPLICIT)
        .fetch_optional(&mut **tx)
        .await?
        .map(|row| profile_from_row(&row))
        .transpose()?
        .ok_or(UpdateProfileError::NotFound)
}
