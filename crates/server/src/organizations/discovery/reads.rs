//! Discovery-only shared reads. Mutation helpers retain their exclusive locks.
use super::*;
use crate::organizations::{Membership, Organization};
use sqlx::Row;

pub(super) async fn lock_domain(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<(), RepositoryError> {
    scope.validate()?;
    let enabled: Option<bool> = sqlx::query_scalar("SELECT enabled FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 AND import_operation_id IS NULL FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_optional(&mut **tx).await?;
    if enabled != Some(true) {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(())
}

pub(super) async fn memberships(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    user: Uuid,
    ids: &[Uuid],
) -> Result<Vec<(Organization, Membership)>, RepositoryError> {
    require(ids.len() <= PAGE_SIZE as usize)?;
    // The caller already holds the domain share lock. Keep the writer's domain
    // -> organization -> membership order, acquiring each bounded set in UUID
    // order. Readers coexist; authority mutations wait until the page commits.
    let organizations = organizations(tx, scope, ids).await?;
    let rows = sqlx::query("SELECT organization_id,incarnation,state,revision,grant_generation,roles FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2 AND end_user_id=$3 AND organization_id=ANY($4) ORDER BY organization_id FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(user).bind(ids).fetch_all(&mut **tx).await?;
    if rows.len() != ids.len() {
        return Err(AuthorityError::Forbidden.into());
    }
    organizations
        .into_iter()
        .zip(rows)
        .map(|(organization, row)| {
            let member = Membership {
                scope,
                organization_id: row.try_get("organization_id")?,
                user_id: user,
                incarnation: row.try_get("incarnation")?,
                state: serde_json::from_value(serde_json::json!(
                    row.try_get::<String, _>("state")?
                ))?,
                revision: row.try_get("revision")?,
                grant_generation: row.try_get("grant_generation")?,
                roles: serde_json::from_value(row.try_get("roles")?)?,
            };
            member.validate()?;
            require(member.organization_id == organization.id)?;
            Ok((organization, member))
        })
        .collect()
}

async fn organizations(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    ids: &[Uuid],
) -> Result<Vec<Organization>, RepositoryError> {
    let rows = sqlx::query("SELECT id,external_id,state,revision,grant_generation FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 AND id=ANY($3) ORDER BY id FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(ids).fetch_all(&mut **tx).await?;
    if rows.len() != ids.len() {
        return Err(AuthorityError::Forbidden.into());
    }
    ids.iter()
        .zip(rows)
        .map(|(id, row)| {
            let organization = Organization {
                scope,
                id: row.try_get("id")?,
                external_id: row.try_get("external_id")?,
                state: serde_json::from_value(serde_json::json!(
                    row.try_get::<String, _>("state")?
                ))?,
                revision: row.try_get("revision")?,
                grant_generation: row.try_get("grant_generation")?,
            };
            organization.validate()?;
            require(organization.id == *id)?;
            Ok(organization)
        })
        .collect()
}
