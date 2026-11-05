//! Machine principals may receive only Export; every other operator action
//! continues to require a human. Authentication is checked by the HTTP boundary.
use super::*;

pub(super) async fn lock_grantee(
    tx: &mut Transaction<'_, Postgres>,
    team: Uuid,
    environment: Uuid,
    principal: Uuid,
    capabilities: &BTreeSet<Capability>,
) -> Result<(), RepositoryError> {
    if capabilities == &BTreeSet::from([Capability::Export]) {
        lock_export_grantee(tx, team, environment, principal).await
    } else {
        lock_human_scope(tx, team, environment, principal, false).await
    }
}

pub(crate) async fn lock_export_grantee(
    tx: &mut Transaction<'_, Postgres>,
    team: Uuid,
    environment: Uuid,
    principal: Uuid,
) -> Result<(), RepositoryError> {
    super::super::model::require(!team.is_nil() && !environment.is_nil() && !principal.is_nil())?;
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT a.id FROM aegaeon.administrators a JOIN aegaeon.team_memberships m ON m.administrator_id=a.id JOIN aegaeon.teams t ON t.id=m.team_id JOIN aegaeon.tenants n ON n.team_id=t.id JOIN aegaeon.environments e ON e.tenant_id=n.id WHERE a.id=$1 AND t.id=$2 AND e.id=$3 AND a.status='ACTIVE' AND a.kind IN ('HUMAN','SERVICE') AND t.status='ACTIVE' AND n.status='ACTIVE' AND e.status='ACTIVE' FOR SHARE OF a,m,t,n,e",
    ).bind(principal).bind(team).bind(environment).fetch_optional(&mut **tx).await?;
    if found != Some(principal) {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(())
}

pub(crate) async fn lock_audit_export_authority(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<OperatorAuthority, RepositoryError> {
    scope.validate()?;
    lock_export_grantee(tx, team, scope.environment_id, principal).await?;
    lock_grant(tx, scope, principal, Capability::Export).await
}
