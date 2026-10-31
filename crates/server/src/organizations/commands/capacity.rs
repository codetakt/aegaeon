use super::*;

pub(crate) const MAX_ORGANIZATIONS: i64 = 1_024;
pub(crate) const MAX_OPERATOR_RECEIPTS: i64 = 10_000;
pub(crate) const MAX_MEMBERS: i64 = 10_000;
pub(crate) const MAX_MEMBER_RECEIPTS: i64 = 10_000;

/// Domain serialization also covers receipt counting and retained identities.
/// Call only after replay lookup: a committed retry never consumes a new slot.
pub(super) async fn member(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    command: &Command,
) -> Result<(), RepositoryError> {
    let (Command::SetMember {
        organization_id,
        update,
    }
    | Command::SetExistingMember {
        organization_id,
        update,
        ..
    }) = command
    else {
        return Err(AuthorityError::Forbidden.into());
    };
    let organization = repository::lock_organization(tx, scope, *organization_id).await?;
    let current = repository::membership(tx, &organization, update.user_id).await?;
    let restrictive = current.as_ref().is_some_and(|member| {
        use super::super::MembershipState::{Active, Removed, Suspended};
        matches!(
            (member.state, update.state),
            (Active, Suspended | Removed) | (Suspended, Removed)
        ) && update.roles.is_subset(&member.roles)
    });
    if current.is_none() {
        if matches!(command, Command::SetExistingMember { .. }) {
            return Err(AuthorityError::Forbidden.into());
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_memberships WHERE environment_id=$1 AND domain_id=$2 LIMIT $3) bounded")
            .bind(scope.environment_id).bind(scope.domain_id).bind(MAX_MEMBERS).fetch_one(&mut **tx).await?;
        if count >= MAX_MEMBERS {
            return Err(AuthorityError::Exhausted.into());
        }
    }
    let maximum = MAX_MEMBER_RECEIPTS + if restrictive { 2 * MAX_MEMBERS } else { 0 };
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_kind='member' AND operation IN ('set_member','set_existing_member') LIMIT $3) bounded")
        .bind(scope.environment_id).bind(scope.domain_id).bind(maximum).fetch_one(&mut **tx).await?;
    if count >= maximum {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}

/// The caller holds the domain lock and has checked current authority and replay.
pub(super) async fn operator(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    command: &Command,
) -> Result<(), RepositoryError> {
    let restrictive = if let Command::SetState {
        organization_id,
        expected_revision,
        state,
    } = command
    {
        let current = repository::lock_organization(tx, scope, *organization_id).await?;
        if current.revision != *expected_revision {
            return Err(AuthorityError::PreconditionFailed.into());
        }
        matches!(
            (current.state, state),
            (OrganizationState::Active, OrganizationState::Suspended)
                | (OrganizationState::Provisioning, OrganizationState::Deleted)
                | (OrganizationState::Active, OrganizationState::Deleted)
                | (OrganizationState::Suspended, OrganizationState::Deleted)
        )
    } else {
        false
    };
    let maximum = MAX_OPERATOR_RECEIPTS
        + if restrictive {
            2 * MAX_ORGANIZATIONS
        } else {
            0
        };
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_kind='operator' AND operation IN ('create','set_state','prepare_administrator_recovery') LIMIT $3) bounded")
        .bind(scope.environment_id).bind(scope.domain_id).bind(maximum).fetch_one(&mut **tx).await?;
    if count >= maximum {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}

pub(crate) async fn creation(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    external_id: &str,
) -> Result<(), RepositoryError> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 AND external_id=$3)")
        .bind(scope.environment_id).bind(scope.domain_id).bind(external_id).fetch_one(&mut **tx).await?;
    if exists {
        return Err(AuthorityError::Conflict.into());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.application_organizations WHERE environment_id=$1 AND domain_id=$2 LIMIT $3) bounded")
        .bind(scope.environment_id).bind(scope.domain_id).bind(MAX_ORGANIZATIONS).fetch_one(&mut **tx).await?;
    if count >= MAX_ORGANIZATIONS {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}
