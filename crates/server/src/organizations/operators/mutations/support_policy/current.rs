use super::*;
use crate::organizations::{
    authentication::OriginalAuthentication, consent::SupportCeiling, repository as repo,
    Organization, OrganizationState,
};
use std::collections::BTreeMap;

async fn provider_current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    provider: &Provider,
) -> Result<(), RepositoryError> {
    let id:Option<Uuid>=sqlx::query_scalar("SELECT c.id FROM aegaeon.connections c JOIN aegaeon.environments e ON e.id=c.environment_id AND e.active_configuration_version_id=c.configuration_version_id JOIN aegaeon.configuration_versions cv ON cv.id=c.configuration_version_id AND cv.environment_id=e.id JOIN aegaeon.tenants n ON n.id=e.tenant_id JOIN aegaeon.teams t ON t.id=n.team_id WHERE c.id=$1 AND e.id=$2 AND c.configuration_version_id=$3 AND t.id=$4 AND c.issuer_url=$5 COLLATE \"C\" AND c.client_id=$6 COLLATE \"C\" AND c.status='ACTIVE' AND c.deleted_at IS NULL AND c.connection_type='OIDC' AND cv.status='ACTIVE' AND e.status='ACTIVE' AND n.status='ACTIVE' AND t.status='ACTIVE' FOR SHARE OF c,cv,e,n,t")
        .bind(provider.connection_id).bind(scope.environment_id).bind(provider.configuration_version_id).bind(team).bind(&provider.issuer).bind(&provider.upstream_client_id).fetch_optional(&mut **tx).await?;
    require(id == Some(provider.connection_id))?;
    Ok(())
}

pub(super) async fn validate_policy(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    policy: &Policy,
) -> Result<(), RepositoryError> {
    for provider in &policy.providers {
        provider_current(tx, scope, team, provider).await?;
    }
    let definitions = repo::roles(tx, scope).await?;
    for value in &policy.entitlements {
        lock_operator_authority(tx, scope, team, value.administrator_id, Capability::Support)
            .await?;
        let user:Option<Uuid>=sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND id=$2 AND status='ACTIVE' FOR SHARE")
            .bind(scope.environment_id).bind(value.user_id).fetch_optional(&mut **tx).await?;
        require(user == Some(value.user_id))?;
        let organization = repo::lock_organization(tx, scope, value.organization_id).await?;
        require(organization.state == OrganizationState::Active)?;
        let audience:Option<String>=sqlx::query_scalar("SELECT audience FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\" FOR SHARE")
            .bind(scope.environment_id).bind(scope.domain_id).bind(&value.audience).fetch_optional(&mut **tx).await?;
        require(audience.as_deref() == Some(&value.audience))?;
        require(value.roles.iter().all(|r| definitions.contains_key(r)))?;
    }
    Ok(())
}

pub(crate) async fn capture(
    tx: &mut Transaction<'_, Postgres>,
    organization: &Organization,
    audience: &str,
    evidence: &OriginalAuthentication,
    now: i64,
) -> Result<SupportCeiling, RepositoryError> {
    evidence.validate()?;
    require(
        now >= evidence.observed_at
            && now >= evidence.auth_time
            && now - evidence.auth_time < 300
            && evidence.context.environment_id == organization.scope.environment_id
            && organization.state == OrganizationState::Active
            && matches!(
                evidence.account_link_provenance.as_str(),
                "jit_v2" | "administrator_confirmed"
            ),
    )?;
    let config = read_locked(tx, organization.scope).await?;
    require((1..i64::MAX).contains(&config.revision))?;
    let policy = config.policy.ok_or(AuthorityError::Forbidden)?;
    let provider = policy
        .providers
        .iter()
        .find(|p| p.connection_id == evidence.context.connection_id)
        .ok_or(AuthorityError::Forbidden)?;
    require(
        provider.configuration_version_id == evidence.context.configuration_version_id
            && provider.issuer == evidence.issuer
            && provider.upstream_client_id == evidence.upstream_client_id
            && evidence.acr.as_ref() == Some(&provider.acr)
            && evidence
                .amr
                .as_ref()
                .is_some_and(|amr| provider.factors.iter().all(|f| amr.contains(&f.method))),
    )?;
    provider_current(tx, organization.scope, evidence.context.team_id, provider).await?;
    let link:Option<Uuid>=sqlx::query_scalar("SELECT l.id FROM aegaeon.account_links l JOIN aegaeon.end_users u ON u.id=l.end_user_id AND u.environment_id=l.environment_id JOIN aegaeon.environments e ON e.id=u.environment_id WHERE l.id=$1 AND l.environment_id=$2 AND l.connection_id=$3 AND l.binding_revision=$4 AND l.binding_provenance=$5 AND l.upstream_issuer=$6 COLLATE \"C\" AND l.upstream_sub_hash=$7 COLLATE \"C\" AND u.id=$8 AND u.subject=$9 COLLATE \"C\" AND u.organization_identity_revision=$10 AND u.status='ACTIVE' AND e.tenant_id=$11 AND u.organization_reauthentication_after<$12 FOR SHARE OF l,u,e")
        .bind(evidence.account_link_id).bind(organization.scope.environment_id).bind(provider.connection_id).bind(evidence.account_link_revision).bind(&evidence.account_link_provenance)
        .bind(&evidence.issuer).bind(&evidence.upstream_subject_hash).bind(evidence.user_id).bind(&evidence.subject).bind(evidence.identity_revision).bind(evidence.context.tenant_id).bind(evidence.auth_time)
        .fetch_optional(&mut **tx).await?;
    require(link == Some(evidence.account_link_id))?;
    let entitlement = policy
        .entitlements
        .iter()
        .find(|e| {
            (e.user_id, e.organization_id, e.audience.as_str())
                == (evidence.user_id, organization.id, audience)
        })
        .ok_or(AuthorityError::Forbidden)?;
    let operator = lock_operator_authority(
        tx,
        organization.scope,
        evidence.context.team_id,
        entitlement.administrator_id,
        Capability::Support,
    )
    .await?;
    require(operator.revision() < i64::MAX)?;
    let definitions = repo::roles(tx, organization.scope).await?;
    let mut role_versions = BTreeMap::new();
    let mut privileges = BTreeSet::new();
    for key in &entitlement.roles {
        let role = definitions.get(key).ok_or(AuthorityError::Forbidden)?;
        role_versions.insert(key.clone(), role.version);
        privileges.extend(role.privileges.iter().cloned());
    }
    require(!privileges.is_empty())?;
    Ok(SupportCeiling {
        organization_generation: organization.grant_generation,
        policy_revision: config.revision,
        administrator_id: entitlement.administrator_id,
        operator_grant_id: operator.grant(),
        operator_revision: operator.revision(),
        role_versions,
        privileges,
    })
}
