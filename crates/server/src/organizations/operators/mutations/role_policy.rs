//! Complete retained role vocabulary. Current operator checks precede receipts.
use super::*;
use crate::organizations::{
    model::{valid_keys, MAX_PRIVILEGES},
    repository, RoleDefinition, MAX_ROLES,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationRoleDefinitionInput))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Definition {
    pub key: String,
    pub privileges: Vec<String>,
    pub manages_members: bool,
    pub assignable_roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationRoleDefinition))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VersionedDefinition {
    pub key: String,
    pub privileges: Vec<String>,
    pub manages_members: bool,
    pub assignable_roles: Vec<String>,
    pub version: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RolePolicy {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    pub revision: i64,
    pub roles: Vec<VersionedDefinition>,
}

fn representation(
    scope: Scope,
    roles: &BTreeMap<String, RoleDefinition>,
) -> Result<RolePolicy, RepositoryError> {
    let mut revision = 1i64;
    let mut values = Vec::with_capacity(roles.len());
    for role in roles.values() {
        role.validate()?;
        revision = aegaeon_pure::organization_bounds::add_role_version(revision, role.version)
            .ok_or(AuthorityError::Exhausted)?;
        values.push(VersionedDefinition {
            version: role.version,
            key: role.key.clone(),
            privileges: role.privileges.iter().cloned().collect(),
            manages_members: role.manages_members,
            assignable_roles: role.assignable_roles.iter().cloned().collect(),
        });
    }
    let result = RolePolicy {
        id: scope.domain_id,
        revision,
        roles: values,
    };
    if serde_json::to_vec(&result)?.len() > 48 * 1024 || revision == i64::MAX {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(result)
}

fn configured(
    scope: Scope,
    current: &BTreeMap<String, RoleDefinition>,
    input: &[Definition],
) -> Result<BTreeMap<String, RoleDefinition>, RepositoryError> {
    require(!input.is_empty() && input.len() <= MAX_ROLES)?;
    let mut result = BTreeMap::new();
    for value in input {
        let privileges: BTreeSet<_> = value.privileges.iter().cloned().collect();
        let assignable_roles: BTreeSet<_> = value.assignable_roles.iter().cloned().collect();
        require(
            privileges.len() == value.privileges.len()
                && assignable_roles.len() == value.assignable_roles.len()
                && valid_keys(&privileges, MAX_PRIVILEGES),
        )?;
        let mut role = RoleDefinition {
            scope,
            key: value.key.clone(),
            version: 1,
            privileges,
            manages_members: value.manages_members,
            assignable_roles,
        };
        role.validate()?;
        if let Some(old) = current.get(&role.key) {
            role.version = old.version;
            if &role != old {
                role.version = increment(old.version, false)?;
            }
        }
        require(result.insert(role.key.clone(), role).is_none())?;
    }
    require(current.keys().all(|key| result.contains_key(key)))?;
    require(result.values().all(|role| {
        role.assignable_roles
            .iter()
            .all(|key| result.contains_key(key))
    }))?;
    representation(scope, &result)?;
    Ok(result)
}

pub async fn read(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<RolePolicy, RepositoryError> {
    lock_operator_authority(tx, scope, team, principal, Capability::Configure).await?;
    representation(scope, &repository::roles(tx, scope).await?)
}

pub async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    expected_revision: i64,
    input: &[Definition],
) -> Result<RolePolicy, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    let operation = "domain.role_policy.replace";
    // Canonicalize vocabulary ordering before calculating replay identity;
    // duplicate entries remain invalid, including on a purported replay.
    let input = canonical(scope, input)?;
    let digest = receipts::digest(
        &serde_json::json!({"revision":expected_revision,"roles":input,"reason":actor.reason}),
    )?;
    if let Some(previous) = receipts::previous(tx, scope, actor, key, operation, &digest).await? {
        return Ok(previous);
    }
    let before = repository::roles(tx, scope).await?;
    let previous = representation(scope, &before)?;
    if previous.revision != expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    receipts::capacity(tx, scope, false).await?;
    let roles = configured(scope, &before, &input)?;
    let result = representation(scope, &roles)?;
    let managers = managed_organizations(tx, scope).await?;
    for role in roles.values() {
        sqlx::query("INSERT INTO aegaeon.organization_role_definitions(environment_id,domain_id,role_key,version,privileges,manages_members,assignable_roles) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(environment_id,domain_id,role_key) DO UPDATE SET version=EXCLUDED.version,privileges=EXCLUDED.privileges,manages_members=EXCLUDED.manages_members,assignable_roles=EXCLUDED.assignable_roles")
            .bind(scope.environment_id).bind(scope.domain_id).bind(&role.key).bind(role.version).bind(serde_json::to_value(&role.privileges)?).bind(role.manages_members).bind(serde_json::to_value(&role.assignable_roles)?).execute(&mut **tx).await?;
    }
    if !managers.is_subset(&managed_organizations(tx, scope).await?) {
        return Err(AuthorityError::Forbidden.into());
    }
    receipts::event(tx,scope,actor,operation,serde_json::json!({"operatorGrantId":authority.grant(),"operatorGrantRevision":authority.revision(),"before":audit_versions(&previous),"after":audit_versions(&result)})).await?;
    receipts::save(tx, scope, actor, key, operation, &digest, &result).await?;
    Ok(result)
}

fn canonical(scope: Scope, input: &[Definition]) -> Result<Vec<Definition>, RepositoryError> {
    let roles = configured(scope, &BTreeMap::new(), input)?;
    let policy = representation(scope, &roles)?;
    Ok(policy
        .roles
        .into_iter()
        .map(|role| Definition {
            key: role.key,
            privileges: role.privileges,
            manages_members: role.manages_members,
            assignable_roles: role.assignable_roles,
        })
        .collect())
}

async fn managed_organizations(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<BTreeSet<Uuid>, RepositoryError> {
    let ids:Vec<Uuid>=sqlx::query_scalar("SELECT o.id FROM aegaeon.application_organizations o WHERE o.environment_id=$1 AND o.domain_id=$2 AND o.state='active' AND EXISTS (SELECT 1 FROM aegaeon.organization_memberships m JOIN aegaeon.end_users u ON u.id=m.end_user_id AND u.environment_id=m.environment_id AND u.status='ACTIVE' WHERE m.environment_id=o.environment_id AND m.domain_id=o.domain_id AND m.organization_id=o.id AND m.state='active' AND EXISTS (SELECT 1 FROM aegaeon.organization_role_definitions r WHERE r.environment_id=m.environment_id AND r.domain_id=m.domain_id AND r.manages_members AND m.roles ? r.role_key)) ORDER BY o.id LIMIT 1025")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_all(&mut **tx).await?;
    if ids.len() > 1024 {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(ids.into_iter().collect())
}

fn audit_versions(policy: &RolePolicy) -> serde_json::Value {
    serde_json::json!({"id":policy.id,"revision":policy.revision,"roles":policy.roles.iter().map(|role| (&role.key, role.version)).collect::<std::collections::BTreeMap<_,_>>()})
}
