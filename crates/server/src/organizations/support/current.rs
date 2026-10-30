use super::*;

pub(super) async fn ceiling(
    tx: &mut Transaction<'_, Postgres>,
    context: &Context<'_>,
    organization_id: Uuid,
    audience: &str,
) -> Result<(Organization, SupportCeiling, BTreeSet<String>), RepositoryError> {
    selected::validate_original(context.original, context.binding, context.now)?;
    let client = selected::current_client(tx, context.original, audience).await?;
    let organization = repo::lock_organization(tx, context.binding.scope, organization_id).await?;
    let original = context
        .original
        .consent
        .support
        .get(&organization_id)
        .ok_or(AuthorityError::Forbidden)?;
    let evidence = context
        .original
        .consent
        .original_authentication
        .as_ref()
        .ok_or(AuthorityError::Forbidden)?;
    let current = operators::mutations::support_policy::capture(
        tx,
        &organization,
        audience,
        evidence,
        context.now,
    )
    .await?;
    let mut narrowed = current.clone();
    narrowed.privileges = original.privileges.clone();
    require(narrowed == *original && original.privileges.is_subset(&current.privileges))?;
    let allowed: BTreeSet<_> = client
        .targets
        .iter()
        .find(|t| t.audience == audience)
        .ok_or(AuthorityError::Forbidden)?
        .privileges
        .iter()
        .cloned()
        .collect();
    Ok((organization, current, allowed))
}

pub(crate) async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    input: &selected::SelectionInput<'_>,
    organization: &Organization,
    client_privileges: &BTreeSet<String>,
) -> Result<AccessDecision, RepositoryError> {
    let id = input
        .request
        .admin_access_grant_id
        .ok_or(AuthorityError::Forbidden)?;
    let context = Context {
        original: input.original,
        binding: input.authenticated,
        parent_expires_at: input.parent_expires_at,
        now: input.now,
    };
    let grant = storage::load(tx, input.authenticated.scope, id).await?;
    grant.require_live(input.now)?;
    require(
        grant.authority.binding == *input.authenticated
            && grant.authority.organization_id == organization.id
            && grant.authority.audience == input.audience
            && grant.authority.auth_time == input.original.consent.auth_time,
    )?;
    let (current_organization, current, _) =
        ceiling(tx, &context, organization.id, input.audience).await?;
    require(
        current_organization == *organization
            && grant.authority.organization_revision == organization.revision
            && grant.authority.ceiling.organization_generation == organization.grant_generation
            && grant.authority.ceiling.policy_revision == current.policy_revision
            && grant.authority.ceiling.operator_grant_id == current.operator_grant_id
            && grant.authority.ceiling.operator_revision == current.operator_revision
            && grant.authority.ceiling.administrator_id == current.administrator_id
            && grant
                .authority
                .ceiling
                .role_versions
                .iter()
                .all(|(k, v)| current.role_versions.get(k) == Some(v)),
    )?;
    let original = input
        .original
        .consent
        .support
        .get(&organization.id)
        .ok_or(AuthorityError::Forbidden)?;
    let target = input
        .original
        .ceiling
        .audiences
        .get(input.audience)
        .ok_or(AuthorityError::Forbidden)?;
    let allowed = grant
        .authority
        .ceiling
        .privileges
        .iter()
        .filter(|p| {
            original.privileges.contains(*p)
                && current.privileges.contains(*p)
                && client_privileges.contains(*p)
                && target.contains(*p)
        })
        .cloned()
        .collect();
    let privileges = super::super::access::select_privileges(input.request, allowed)?;
    let expires_at = aegaeon_pure::organization_bounds::selected_expiry(
        input.original.ceiling.expires_at.min(grant.expires_at),
        input.parent_expires_at,
        input.now,
    )
    .map_err(|_| AuthorityError::Forbidden)?;
    Ok(AccessDecision {
        binding: input.authenticated.clone(),
        organization_id: organization.id,
        organization_identifier: organization.external_id.clone(),
        audience: input.audience.into(),
        privileges,
        organization_revision: organization.revision,
        organization_generation: organization.grant_generation,
        authority: AccessAuthority::AdministrativeGrant {
            grant_id: grant.id,
            grant_revision: grant.revision,
        },
        role_versions: grant.authority.ceiling.role_versions.clone(),
        expires_at,
    })
}
