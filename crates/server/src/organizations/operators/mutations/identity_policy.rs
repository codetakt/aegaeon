//! Explicit Environment-wide invitation enrollment policy, owned by human owners.
use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature="openapi",schema(as=OrganizationIdentityPolicy))]
pub struct Policy {
    pub registration: bool,
    pub password_recovery: bool,
    pub subject_format: String,
}
impl Policy {
    pub fn validate(&self) -> Result<(), AuthorityError> {
        require((self.registration || self.password_recovery) && self.subject_format == "uuid")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature="openapi",schema(as=OrganizationIdentityConfiguration))]
pub struct Configuration {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    pub revision: i64,
    pub policy: Option<Policy>,
}

pub(crate) async fn read_locked(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
) -> Result<Configuration, RepositoryError> {
    let row = sqlx::query("SELECT organization_identity_policy_revision AS revision,organization_identity_policy AS policy FROM aegaeon.environments WHERE id=$1 AND status='ACTIVE' FOR SHARE")
        .bind(environment).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let policy: Option<Policy> = row
        .try_get::<Option<serde_json::Value>, _>("policy")?
        .map(serde_json::from_value)
        .transpose()?;
    if let Some(policy) = &policy {
        policy.validate()?;
    }
    Ok(Configuration {
        id: environment,
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
    read_locked(tx, scope.environment_id).await
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
    // Serialize owner upgrades before taking shared topology locks; concurrent
    // policy changes cannot both hold a shared Environment row then upgrade.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('organization.identity-policy:' || $1::text,0))")
        .bind(scope.environment_id.to_string()).execute(&mut **tx).await?;
    lock_human_scope(tx, team, scope.environment_id, actor.id, true).await?;
    sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(scope.environment_id)
        .fetch_one(&mut **tx)
        .await?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    let operation = if change.policy.is_some() {
        "domain.identity.configure"
    } else {
        "domain.identity.disable"
    };
    let digest = receipts::digest(&serde_json::json!({"change":change,"reason":actor.reason}))?;
    if let Some(previous) = receipts::previous(tx, scope, actor, key, operation, &digest).await? {
        return Ok(previous);
    }
    let previous = read_locked(tx, scope.environment_id).await?;
    if previous.revision != change.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    if previous.policy == change.policy {
        return Err(AuthorityError::Conflict.into());
    }
    receipts::capacity(tx, scope, change.policy.is_none()).await?;
    let revision = increment(previous.revision, change.policy.is_none())?;
    let policy = change
        .policy
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    sqlx::query("UPDATE aegaeon.environments SET organization_identity_policy=$2,organization_identity_policy_revision=$3 WHERE id=$1")
        .bind(scope.environment_id).bind(policy).bind(revision).execute(&mut **tx).await?;
    let result = read_locked(tx, scope.environment_id).await?;
    require(result.revision == revision)?;
    receipts::event(tx,scope,actor,operation,receipts::transition(serde_json::json!({"environment_id":scope.environment_id,"before_revision":previous.revision,"revision":revision,"enabled":result.policy.is_some()}), Some(previous.revision), revision)?).await?;
    receipts::save(tx, scope, actor, key, operation, &digest, &result).await?;
    Ok(result)
}
