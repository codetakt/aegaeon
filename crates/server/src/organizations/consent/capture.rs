use super::*;
use crate::organizations::{
    operators::mutations::clients, repository as repo, AccessRequest, ORGANIZATION_ACCESS_TYPE,
};
use repo::RepositoryError;
use sqlx::{Postgres, Transaction};

pub(crate) struct CaptureContext<'a> {
    pub environment_id: Uuid,
    pub issuer: &'a str,
    pub client_id: &'a str,
    pub subject: &'a str,
    pub dpop_jkt: &'a str,
    pub auth_time: i64,
    pub captured_at: i64,
    pub original_authentication:
        Option<&'a crate::organizations::authentication::OriginalAuthentication>,
}

/// Caller owns finite transaction/deadline and must persist this before consent display.
pub(crate) async fn capture(
    tx: &mut Transaction<'_, Postgres>,
    context: CaptureContext<'_>,
    request: &GrantRequest,
) -> Result<Consent, RepositoryError> {
    request.validate()?;
    let owner = crate::organizations::request_work::async_store::current_owner()?;
    let epoch = owner.epoch_binding()?.clone();
    require(epoch.environment_id() == context.environment_id)?;
    require(serde_json::to_vec(request)?.len() <= 16 * 1024)?;
    let audience = &request.locations[0];
    let domain: Option<Uuid> = sqlx::query_scalar("SELECT domain_id FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND audience=$2 COLLATE \"C\"")
        .bind(context.environment_id).bind(audience).fetch_optional(&mut **tx).await?;
    let scope = Scope {
        environment_id: context.environment_id,
        domain_id: domain.ok_or(AuthorityError::Forbidden)?,
    };
    crate::organizations::selected::lock_primary_scope(tx, scope).await?;
    repo::lock_domain(tx, scope).await?;
    let domain_revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2",
    )
    .bind(scope.environment_id)
    .bind(scope.domain_id)
    .fetch_one(&mut **tx)
    .await?;
    require(domain_revision > 0 && domain_revision < i64::MAX)?;
    let binding = client(tx, scope, context.client_id, audience).await?;
    let user_id: Uuid = sqlx::query_scalar("SELECT id FROM aegaeon.end_users WHERE environment_id=$1 AND subject=$2 COLLATE \"C\" AND status='ACTIVE'")
        .bind(scope.environment_id).bind(context.subject).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let allowed: BTreeSet<_> = binding
        .targets
        .iter()
        .find(|t| t.audience == *audience)
        .ok_or(AuthorityError::Forbidden)?
        .privileges
        .iter()
        .cloned()
        .collect();
    let CapturedSelections {
        memberships,
        support,
    } = capture_selections(tx, &context, request, scope, user_id, &allowed).await?;
    let identity_revision = crate::organizations::identity::revision(
        tx,
        scope,
        user_id,
        context.subject,
        context.auth_time,
    )
    .await?;
    let consent = Consent {
        version: 2,
        epoch: Some(epoch),
        request: request.clone(),
        scope,
        issuer: context.issuer.into(),
        client_id: context.client_id.into(),
        client_registration_id: binding.client_registration_id,
        client_binding_id: binding.id,
        client_binding_revision: binding.revision,
        domain_revision,
        subject: context.subject.into(),
        user_id,
        identity_revision,
        dpop_jkt: context.dpop_jkt.into(),
        auth_time: context.auth_time,
        captured_at: context.captured_at,
        original_authentication: context.original_authentication.cloned(),
        memberships,
        support,
    };
    // Validate the eventual shape without inventing usable root authority.
    consent.bind(
        "validation-only",
        context
            .captured_at
            .checked_add(1)
            .ok_or(AuthorityError::Exhausted)?,
    )?;
    Ok(consent)
}

pub(crate) async fn client(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    identifier: &str,
    audience: &str,
) -> Result<clients::ClientBinding, RepositoryError> {
    let row = sqlx::query("SELECT b.id,b.client_registration_id,b.client_identifier,b.active,b.revision,b.targets FROM aegaeon.organization_client_bindings b JOIN aegaeon.clients c ON c.id=b.client_registration_id AND c.environment_id=b.environment_id JOIN aegaeon.environments e ON e.id=c.environment_id AND e.active_configuration_version_id=c.configuration_version_id WHERE b.environment_id=$1 AND b.domain_id=$2 AND b.client_identifier=$3 COLLATE \"C\" AND b.active AND c.client_identifier=b.client_identifier FOR SHARE OF b,c")
        .bind(scope.environment_id).bind(scope.domain_id).bind(identifier).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let binding = clients::decode(&row)?;
    if clients::current_client(tx, scope, binding.client_registration_id, true).await? != identifier
        || !binding.targets.iter().any(|t| t.audience == audience)
    {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(binding)
}

struct CapturedSelections {
    memberships: BTreeMap<Uuid, MembershipCeiling>,
    support: BTreeMap<Uuid, SupportCeiling>,
}
async fn capture_selections(
    tx: &mut Transaction<'_, Postgres>,
    context: &CaptureContext<'_>,
    request: &GrantRequest,
    scope: Scope,
    user_id: Uuid,
    allowed: &BTreeSet<String>,
) -> Result<CapturedSelections, RepositoryError> {
    let definitions = repo::roles(tx, scope).await?;
    let audience = &request.locations[0];
    let mut memberships = BTreeMap::new();
    let mut support = BTreeMap::new();
    // Sort exact external IDs for deterministic locks and snapshot comparison.
    let mut selections: Vec<_> = request.organizations.iter().collect();
    selections.sort_by_key(|s| &s.identifier);
    for selection in selections {
        let organization = repo::resolve_access_organization(
            tx,
            scope,
            audience,
            &AccessRequest {
                detail_type: ORGANIZATION_ACCESS_TYPE.into(),
                admin_access_grant_id: None,
                identifier: selection.identifier.clone(),
                privileges: None,
            },
        )
        .await?;
        if selection.administrative_access {
            let evidence = context
                .original_authentication
                .ok_or(AuthorityError::Forbidden)?;
            require(
                evidence.user_id == user_id
                    && evidence.subject == context.subject
                    && evidence.auth_time == context.auth_time,
            )?;
            let mut ceiling = super::super::operators::mutations::support_policy::capture(
                tx,
                &organization,
                audience,
                evidence,
                context.captured_at,
            )
            .await?;
            let requested: BTreeSet<_> = selection.privileges.iter().cloned().collect();
            if !requested.is_subset(&ceiling.privileges) || !requested.is_subset(allowed) {
                return Err(AuthorityError::Forbidden.into());
            }
            ceiling.privileges = requested;
            require(support.insert(organization.id, ceiling).is_none())?;
            continue;
        }
        let member = repo::membership(tx, &organization, user_id)
            .await?
            .ok_or(AuthorityError::Forbidden)?;
        let mut ceiling =
            AuthorizationCeiling::capture_membership(&organization, &member, &definitions)?;
        let requested: BTreeSet<_> = selection.privileges.iter().cloned().collect();
        if !requested.is_subset(&ceiling.privileges) || !requested.is_subset(allowed) {
            return Err(AuthorityError::Forbidden.into());
        }
        ceiling.privileges = requested;
        require(memberships.insert(organization.id, ceiling).is_none())?;
    }
    Ok(CapturedSelections {
        memberships,
        support,
    })
}
