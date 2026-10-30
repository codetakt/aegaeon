//! Current primary identity generation; an active status alone cannot restore authority.
use super::{repository::RepositoryError, AuthorityError, Scope};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(crate) async fn revision(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    user: Uuid,
    subject: &str,
    auth_time: i64,
) -> Result<i64, RepositoryError> {
    let row: Option<(i64, i64)> = sqlx::query_as("SELECT organization_identity_revision,organization_reauthentication_after FROM aegaeon.end_users WHERE environment_id=$1 AND id=$2 AND subject=$3 COLLATE \"C\" AND status='ACTIVE' FOR SHARE")
        .bind(scope.environment_id).bind(user).bind(subject).fetch_optional(&mut **tx).await?;
    let (revision, cutoff) = row.ok_or(AuthorityError::Forbidden)?;
    if !(1..i64::MAX).contains(&revision) || cutoff < 0 || auth_time <= cutoff {
        return Err(AuthorityError::ReauthorizationRequired.into());
    }
    Ok(revision)
}

pub(crate) async fn require_current(
    tx: &mut Transaction<'_, Postgres>,
    binding: &super::Binding,
    expected_revision: i64,
    auth_time: i64,
) -> Result<(), RepositoryError> {
    if revision(
        tx,
        binding.scope,
        binding.user_id,
        &binding.subject,
        auth_time,
    )
    .await?
        != expected_revision
    {
        return Err(AuthorityError::ReauthorizationRequired.into());
    }
    Ok(())
}
