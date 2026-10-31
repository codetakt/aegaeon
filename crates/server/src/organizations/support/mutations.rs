use super::*;
#[derive(Debug, Serialize)]
pub(crate) struct Activation {
    pub organization_id: Uuid,
    pub audience: String,
    pub roles: Vec<String>,
    pub expected_revision: i64,
    pub reason: String,
}
#[derive(Debug, Serialize)]
pub(crate) struct Revoke {
    pub id: Uuid,
    pub expected_revision: i64,
    pub reason: String,
}

pub(crate) async fn activate(
    tx: &mut Transaction<'_, Postgres>,
    context: &Context<'_>,
    request: &Activation,
    key: &str,
    request_id: &str,
) -> Result<Grant, RepositoryError> {
    storage::validate_key_reason(key, &request.reason)?;
    let roles: BTreeSet<_> = request.roles.iter().cloned().collect();
    require(
        !roles.is_empty()
            && roles.len() == request.roles.len()
            && valid_keys(&roles, MAX_ROLES)
            && request.expected_revision > 0,
    )?;
    let (organization, current, client) =
        current::ceiling(tx, context, request.organization_id, &request.audience).await?;
    let original = context
        .original
        .consent
        .support
        .get(&organization.id)
        .ok_or(AuthorityError::Forbidden)?;
    let definitions = repo::roles(tx, context.binding.scope).await?;
    let mut role_versions = BTreeMap::new();
    let mut privileges = BTreeSet::new();
    for key in roles {
        let version = original
            .role_versions
            .get(&key)
            .ok_or(AuthorityError::Forbidden)?;
        require(current.role_versions.get(&key) == Some(version))?;
        let role = definitions.get(&key).ok_or(AuthorityError::Forbidden)?;
        role_versions.insert(key, *version);
        privileges.extend(
            role.privileges
                .iter()
                .filter(|p| original.privileges.contains(*p) && client.contains(*p))
                .cloned(),
        );
    }
    require(!privileges.is_empty())?;
    let digest = storage::digest(request)?;
    let row=sqlx::query("SELECT id,request_digest FROM aegaeon.organization_admin_access_grants WHERE environment_id=$1 AND domain_id=$2 AND user_id=$3 AND client_registration_id=$4 AND root_id=$5 COLLATE \"C\" AND creation_key=$6 COLLATE \"C\"")
        .bind(context.binding.scope.environment_id).bind(context.binding.scope.domain_id).bind(context.binding.user_id).bind(context.binding.client_registration_id).bind(&context.binding.root_id).bind(key).fetch_optional(&mut **tx).await?;
    if let Some(row) = row {
        if row.try_get::<Vec<u8>, _>("request_digest")? != digest {
            return Err(AuthorityError::Conflict.into());
        }
        let grant = storage::load(tx, context.binding.scope, row.try_get("id")?).await?;
        grant.require_live(context.now)?;
        require(
            grant.authority.binding == *context.binding
                && grant.authority.organization_id == organization.id
                && grant.authority.organization_revision == organization.revision
                && grant.authority.ceiling.organization_generation == organization.grant_generation
                && grant.authority.ceiling.policy_revision == current.policy_revision
                && grant.authority.ceiling.operator_revision == current.operator_revision
                && grant.authority.ceiling.role_versions == role_versions
                && grant.authority.ceiling.privileges == privileges,
        )?;
        return Ok(grant);
    }
    if organization.revision != request.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    capacity(tx, context.binding).await?;
    let expires_at = expiry(context)?;
    let grant = Grant {
        id: Uuid::new_v4(),
        revision: 1,
        active: true,
        issued_at: context.now,
        expires_at,
        authority: Authority {
            epoch: context.original.consent.epoch.clone(),
            binding: context.binding.clone(),
            organization_id: organization.id,
            organization_revision: organization.revision,
            auth_time: context.original.consent.auth_time,
            audience: request.audience.clone(),
            ceiling: SupportCeiling {
                role_versions,
                privileges,
                ..current
            },
        },
    };
    grant.validate()?;
    sqlx::query("INSERT INTO aegaeon.organization_admin_access_grants(id,environment_id,domain_id,organization_id,user_id,client_registration_id,root_id,authority,issued_at,expires_at,creation_key,request_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
        .bind(grant.id).bind(context.binding.scope.environment_id).bind(context.binding.scope.domain_id).bind(organization.id).bind(context.binding.user_id).bind(context.binding.client_registration_id).bind(&context.binding.root_id).bind(serde_json::to_value(&grant.authority)?).bind(context.now).bind(expires_at).bind(key).bind(digest).execute(&mut **tx).await?;
    storage::event(
        tx,
        &grant,
        request_id,
        &request.reason,
        "organization.support.activated",
        None,
    )
    .await?;
    Ok(grant)
}

pub(crate) async fn revoke(
    tx: &mut Transaction<'_, Postgres>,
    context: &Context<'_>,
    request: &Revoke,
    key: &str,
    request_id: &str,
) -> Result<Grant, RepositoryError> {
    storage::validate_key_reason(key, &request.reason)?;
    let mut grant = storage::read(tx, context, request.id).await?;
    let digest = storage::digest(request)?;
    if !grant.active {
        let row=sqlx::query("SELECT revocation_key,revocation_digest FROM aegaeon.organization_admin_access_grants WHERE id=$1").bind(grant.id).fetch_one(&mut **tx).await?;
        if row
            .try_get::<Option<String>, _>("revocation_key")?
            .as_deref()
            == Some(key)
            && row.try_get::<Option<Vec<u8>>, _>("revocation_digest")? == Some(digest)
        {
            return Ok(grant);
        }
        return Err(AuthorityError::Conflict.into());
    }
    if grant.revision != request.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    grant.revision = super::super::model::increment(grant.revision, true)?;
    grant.active = false;
    sqlx::query("UPDATE aegaeon.organization_admin_access_grants SET active=false,revision=$2,revocation_key=$3,revocation_digest=$4 WHERE id=$1")
        .bind(grant.id).bind(grant.revision).bind(key).bind(digest).execute(&mut **tx).await?;
    storage::event(
        tx,
        &grant,
        request_id,
        &request.reason,
        "organization.support.revoked",
        Some(request.expected_revision),
    )
    .await?;
    Ok(grant)
}

async fn capacity(
    tx: &mut Transaction<'_, Postgres>,
    binding: &Binding,
) -> Result<(), RepositoryError> {
    let total:i64=sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_admin_access_grants WHERE environment_id=$1 AND domain_id=$2 LIMIT $3) bounded")
        .bind(binding.scope.environment_id).bind(binding.scope.domain_id).bind(MAX_GRANTS).fetch_one(&mut **tx).await?;
    let root_total:i64=sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_admin_access_grants WHERE environment_id=$1 AND domain_id=$2 AND user_id=$3 AND client_registration_id=$4 AND root_id=$5 COLLATE \"C\" LIMIT 16) bounded")
        .bind(binding.scope.environment_id).bind(binding.scope.domain_id).bind(binding.user_id).bind(binding.client_registration_id).bind(&binding.root_id).fetch_one(&mut **tx).await?;
    if total >= MAX_GRANTS || root_total >= 16 {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}

fn expiry(context: &Context<'_>) -> Result<i64, AuthorityError> {
    aegaeon_pure::organization_bounds::administrative_expiry(
        context.original.ceiling.expires_at,
        context.parent_expires_at,
        context.original.consent.auth_time,
        context.now,
    )
    .map_err(|_| AuthorityError::Forbidden)
}
