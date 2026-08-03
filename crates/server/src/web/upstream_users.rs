use crate::end_user_profiles;
use crate::upstream::{
    merge_upstream_custom_claims, AppliedUpstreamAttributeMappings,
    UpstreamJitProvisioningCollisionPolicy, UpstreamJitProvisioningInitialStatus,
    UpstreamJitProvisioningPolicy,
};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct UpstreamResolvedUser {
    pub(super) end_user_id: uuid::Uuid,
    pub(super) subject: String,
    pub(super) status: String,
    pub(super) account_link_connection_id: Option<uuid::Uuid>,
}

fn upstream_resolved_user_from_row(row: &PgRow) -> Result<UpstreamResolvedUser, sqlx::Error> {
    Ok(UpstreamResolvedUser {
        end_user_id: row.try_get("id")?,
        subject: row.try_get("subject")?,
        status: row.try_get("status")?,
        account_link_connection_id: None,
    })
}

fn linked_upstream_resolved_user_from_row(
    row: &PgRow,
) -> Result<UpstreamResolvedUser, sqlx::Error> {
    Ok(UpstreamResolvedUser {
        end_user_id: row.try_get("id")?,
        subject: row.try_get("subject")?,
        status: row.try_get("status")?,
        account_link_connection_id: Some(row.try_get("account_link_connection_id")?),
    })
}

pub(super) fn select_upstream_jit_reuse_candidate(
    policy: &UpstreamJitProvisioningPolicy,
    proposed_subject: &str,
    matches: &[UpstreamResolvedUser],
) -> Result<Option<UpstreamResolvedUser>, &'static str> {
    match policy.collision_policy {
        UpstreamJitProvisioningCollisionPolicy::RejectExistingEmail => {
            if matches
                .iter()
                .any(|candidate| candidate.subject != proposed_subject)
            {
                return Err("upstream email is already associated with a different local user");
            }
            Ok(matches.first().cloned())
        }
        UpstreamJitProvisioningCollisionPolicy::ReuseExistingEmail => {
            if matches.len() > 1 {
                return Err("upstream email resolves to multiple local users");
            }
            Ok(matches.first().cloned())
        }
    }
}

pub(super) async fn load_linked_upstream_user(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: uuid::Uuid,
    upstream_issuer: &str,
    upstream_sub_hash: &str,
) -> Result<Option<UpstreamResolvedUser>, sqlx::Error> {
    let row = sqlx::query(
        r"
SELECT u.id, u.subject, u.status::text AS status, al.connection_id AS account_link_connection_id
FROM aegaeon.account_links al
JOIN aegaeon.end_users u
  ON u.id = al.end_user_id
 AND u.environment_id = al.environment_id
 AND u.status <> 'DELETED'
WHERE al.environment_id = $1
  AND al.upstream_issuer = $2
  AND al.upstream_sub_hash = $3
LIMIT 1
        ",
    )
    .bind(environment_id)
    .bind(upstream_issuer)
    .bind(upstream_sub_hash)
    .fetch_optional(&mut **tx)
    .await?;

    row.as_ref()
        .map(linked_upstream_resolved_user_from_row)
        .transpose()
}

pub(super) async fn load_upstream_email_matches(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: uuid::Uuid,
    email: &str,
) -> Result<Vec<UpstreamResolvedUser>, sqlx::Error> {
    let rows = sqlx::query(
        r"
SELECT id, subject, status::text AS status
FROM aegaeon.end_users
WHERE environment_id = $1
  AND status <> 'DELETED'
  AND lower(email) = lower($2)
ORDER BY id
        ",
    )
    .bind(environment_id)
    .bind(email)
    .fetch_all(&mut **tx)
    .await?;

    rows.into_iter()
        .map(|row| upstream_resolved_user_from_row(&row))
        .collect()
}

pub(super) async fn upsert_upstream_end_user(
    tx: &mut Transaction<'_, Postgres>,
    environment_id: uuid::Uuid,
    subject: &str,
    email: Option<&str>,
    initial_status: UpstreamJitProvisioningInitialStatus,
) -> Result<UpstreamResolvedUser, sqlx::Error> {
    let row = sqlx::query(
        r"
INSERT INTO aegaeon.end_users (
  environment_id,
  subject,
  email,
  status,
  blocked_at,
  blocked_reason
)
VALUES (
  $1,
  $2,
  $3,
  $4::aegaeon.end_user_status,
  CASE WHEN $4 = 'SUSPENDED' THEN now() ELSE NULL END,
  CASE WHEN $4 = 'SUSPENDED' THEN 'jit_provisioning_initial_status' ELSE NULL END
)
ON CONFLICT (environment_id, subject) WHERE status <> 'DELETED'
DO UPDATE SET updated_at = now()
RETURNING id, subject, status::text AS status
        ",
    )
    .bind(environment_id)
    .bind(subject)
    .bind(email)
    .bind(initial_status.as_db_value())
    .fetch_one(&mut **tx)
    .await?;

    upstream_resolved_user_from_row(&row)
}

fn mapped_upstream_profile_error(err: end_user_profiles::UpdateProfileError) -> String {
    match err {
        end_user_profiles::UpdateProfileError::VersionMismatch { .. } => {
            "failed to sync mapped upstream profile due to concurrent updates".to_string()
        }
        end_user_profiles::UpdateProfileError::InvalidCustomClaims(message) => {
            format!("mapped upstream profile is invalid: {message}")
        }
        end_user_profiles::UpdateProfileError::NotFound => {
            "mapped upstream user was not found".to_string()
        }
        end_user_profiles::UpdateProfileError::Database(err) => {
            format!("failed to update mapped upstream profile: {err}")
        }
    }
}

pub(super) async fn sync_upstream_profile_projection(
    tx: &mut Transaction<'_, Postgres>,
    end_user_id: uuid::Uuid,
    projection: &AppliedUpstreamAttributeMappings,
) -> Result<(), String> {
    if projection.email.is_none()
        && projection.email_verified.is_none()
        && projection.display_name.is_none()
        && projection.managed_custom_claim_keys.is_empty()
    {
        return Ok(());
    }

    let existing = end_user_profiles::load_user_profile_for_update(tx, end_user_id)
        .await
        .map_err(mapped_upstream_profile_error)?;

    let next_custom_claims = if projection.managed_custom_claim_keys.is_empty() {
        None
    } else {
        Some(merge_upstream_custom_claims(
            &existing.custom_claims,
            projection,
        ))
    };

    end_user_profiles::update_user_profile(
        tx,
        end_user_id,
        existing.version,
        projection.email.clone(),
        projection.email_verified,
        projection.display_name.clone(),
        next_custom_claims,
    )
    .await
    .map(|_| ())
    .map_err(mapped_upstream_profile_error)
}
