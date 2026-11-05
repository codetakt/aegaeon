use super::*;

/// The caller already holds domain/organization locks. Lock every existing
/// member identity so a concurrent global resume cannot invalidate the decision.
pub(crate) async fn needs_administrator(
    tx: &mut Transaction<'_, Postgres>,
    organization: &Organization,
) -> Result<bool, RepositoryError> {
    let limit = crate::organizations::commands::capacity::MAX_MEMBERS;
    let members: Vec<Uuid> = sqlx::query_scalar("SELECT u.id FROM aegaeon.organization_memberships m JOIN aegaeon.end_users u ON u.id=m.end_user_id AND u.environment_id=m.environment_id WHERE m.environment_id=$1 AND m.domain_id=$2 AND m.organization_id=$3 ORDER BY u.id LIMIT $4 FOR SHARE OF u")
        .bind(organization.scope.environment_id).bind(organization.scope.domain_id)
        .bind(organization.id).bind(limit+1).fetch_all(&mut **tx).await?;
    if i64::try_from(members.len()).map_err(|_| AuthorityError::Exhausted)? > limit {
        return Err(AuthorityError::Exhausted.into());
    }
    if organization.state == OrganizationState::Provisioning && organization.grant_generation == 1 {
        return Ok(members.is_empty());
    }
    Ok(administrator_count(tx, organization, None).await? == 0)
}

/// Current Team ownership and domain provisioning are prerequisites checked by
/// the command boundary. An ordinary state-change command cannot enter recovery.
pub(crate) async fn prepare(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    id: Uuid,
    expected_revision: i64,
    actor: &AuditActor,
) -> Result<Organization, RepositoryError> {
    let mut organization = lock_organization(tx, scope, id).await?;
    if organization.revision != expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    require(matches!(actor.kind, ActorKind::Operator))?;
    if !needs_administrator(tx, &organization).await? {
        return Err(AuthorityError::Forbidden.into());
    }
    let before = organization.clone();
    organization.prepare_administrator_recovery(expected_revision)?;
    sqlx::query("UPDATE aegaeon.application_organizations SET state='provisioning',revision=$4,grant_generation=$5 WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id)
        .bind(organization.revision).bind(organization.grant_generation).execute(&mut **tx).await?;
    event(tx, &organization, actor, "organization.administrator_recovery_prepared",
        serde_json::json!({"before":{"state":before.state,"revision":before.revision,"generation":before.grant_generation},"after":{"state":organization.state,"revision":organization.revision,"generation":organization.grant_generation}})).await?;
    Ok(organization)
}
