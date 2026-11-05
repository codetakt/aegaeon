//! Reviewed support policy is configuration, never a membership or access grant.
use super::*;
use crate::organizations::model::{valid_keys, MAX_ROLES};
mod current;
pub(crate) use current::capture;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FactorClass {
    Knowledge,
    Possession,
    Inherence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Factor {
    pub method: String,
    pub class: FactorClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Provider {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub connection_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub configuration_version_id: Uuid,
    pub issuer: String,
    pub upstream_client_id: String,
    pub acr: String,
    pub factors: Vec<Factor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Entitlement {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub administrator_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub user_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub organization_id: Uuid,
    pub audience: String,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature="openapi",schema(as=OrganizationSupportPolicy))]
pub struct Policy {
    pub providers: Vec<Provider>,
    pub entitlements: Vec<Entitlement>,
}

impl Policy {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        require(
            !self.providers.is_empty()
                && self.providers.len() <= 8
                && !self.entitlements.is_empty()
                && self.entitlements.len() <= 64,
        )?;
        let mut providers = BTreeSet::new();
        for provider in &self.providers {
            require(
                !provider.connection_id.is_nil()
                    && !provider.configuration_version_id.is_nil()
                    && providers.insert(provider.connection_id)
                    && text(&provider.issuer, 2048)
                    && text(&provider.upstream_client_id, 2048)
                    && text(&provider.acr, 256)
                    && (2..=3).contains(&provider.factors.len()),
            )?;
            let mut methods = BTreeSet::new();
            let mut classes = BTreeSet::new();
            for factor in &provider.factors {
                require(
                    text(&factor.method, 128)
                        && !matches!(factor.method.as_str(), "mfa" | "mca")
                        && methods.insert(&factor.method),
                )?;
                classes.insert(factor.class);
            }
            require(classes.len() >= 2)?;
        }
        let mut entitlements = BTreeSet::new();
        for value in &self.entitlements {
            let roles: BTreeSet<_> = value.roles.iter().cloned().collect();
            require(
                !value.administrator_id.is_nil()
                    && !value.user_id.is_nil()
                    && !value.organization_id.is_nil()
                    && text(&value.audience, 2048)
                    && !roles.is_empty()
                    && roles.len() == value.roles.len()
                    && valid_keys(&roles, MAX_ROLES)
                    && entitlements.insert((value.user_id, value.organization_id, &value.audience)),
            )?;
        }
        require(
            serde_json::to_vec(self)
                .map_err(|_| AuthorityError::Invalid)?
                .len()
                <= 48 * 1024,
        )
    }
}
fn text(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature="openapi",schema(as=OrganizationSupportConfiguration))]
pub struct Configuration {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    pub revision: i64,
    pub policy: Option<Policy>,
}

pub(crate) async fn read_locked(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<Configuration, RepositoryError> {
    let row=sqlx::query("SELECT support_policy_revision AS revision,support_policy AS policy FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 FOR SHARE")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let policy: Option<Policy> = row
        .try_get::<Option<serde_json::Value>, _>("policy")?
        .map(serde_json::from_value)
        .transpose()?;
    if let Some(policy) = &policy {
        policy.validate()?;
    }
    Ok(Configuration {
        id: scope.domain_id,
        revision: row.try_get("revision")?,
        policy,
    })
}
pub async fn read(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<Configuration, RepositoryError> {
    lock_human_scope(tx, team, scope.environment_id, principal, true).await?;
    lock_operator_authority(tx, scope, team, principal, Capability::Configure).await?;
    read_locked(tx, scope).await
}
#[derive(Serialize)]
pub struct Change {
    pub expected_revision: i64,
    pub policy: Option<Policy>,
}

pub async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    change: &Change,
) -> Result<Configuration, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    if let Some(policy) = &change.policy {
        policy.validate()?;
    }
    require(change.expected_revision > 0)?;
    lock_human_scope(tx, team, scope.environment_id, actor.id, true).await?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    let operation = if change.policy.is_some() {
        "domain.support.configure"
    } else {
        "domain.support.disable"
    };
    let digest = receipts::digest(&serde_json::json!({"change":change,"reason":actor.reason}))?;
    if let Some(previous) = receipts::previous(tx, scope, actor, key, operation, &digest).await? {
        return Ok(previous);
    }
    let previous = read_locked(tx, scope).await?;
    if previous.revision != change.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    if previous.policy == change.policy {
        return Err(AuthorityError::Conflict.into());
    }
    if let Some(policy) = &change.policy {
        current::validate_policy(tx, scope, team, policy).await?;
    }
    receipts::capacity(tx, scope, change.policy.is_none()).await?;
    let revision = increment(previous.revision, change.policy.is_none())?;
    let policy = change
        .policy
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    sqlx::query("UPDATE aegaeon.authorization_domains SET support_policy=$3,support_policy_revision=$4 WHERE environment_id=$1 AND id=$2")
        .bind(scope.environment_id).bind(scope.domain_id).bind(policy).bind(revision).execute(&mut **tx).await?;
    let result = read_locked(tx, scope).await?;
    require(result.revision == revision)?;
    receipts::event(tx,scope,actor,operation,receipts::transition(serde_json::json!({"before_revision":previous.revision,"revision":revision,"enabled":result.policy.is_some()}), Some(previous.revision), revision)?).await?;
    receipts::save(tx, scope, actor, key, operation, &digest, &result).await?;
    Ok(result)
}
