//! Explicit resource-server identities, independent of the token holder.
use super::*;

pub const MAX_RECIPIENTS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Recipient {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub client_registration_id: Uuid,
    pub client_identifier: String,
}

pub(in crate::organizations) fn validate(values: &[Recipient]) -> Result<(), AuthorityError> {
    require(values.len() <= MAX_RECIPIENTS)?;
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for value in values {
        require(
            !value.client_registration_id.is_nil()
                && ids.insert(value.client_registration_id)
                && names.insert(&value.client_identifier)
                && !value.client_identifier.is_empty()
                && value.client_identifier.len() <= 255
                && !value.client_identifier.chars().any(char::is_control),
        )?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ConfigureRecipients {
    pub expected_revision: i64,
    pub audience: String,
    /// None means explicit revoke; Some must be nonempty.
    pub registrations: Option<Vec<Uuid>>,
}

/// Caller supplies authenticated configuration authority and owns the transaction.
pub async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    command: &ConfigureRecipients,
) -> Result<DomainConfiguration, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    require(command.expected_revision > 0)?;
    let operation = if command.registrations.is_some() {
        "domain.target.recipients.replace"
    } else {
        "domain.target.recipients.revoke"
    };
    let digest = receipts::digest(&serde_json::json!({"command":command,"reason":actor.reason}))?;
    if let Some(previous) = receipts::previous(tx, scope, actor, key, operation, &digest).await? {
        return Ok(previous);
    }
    let mut result = read_locked(tx, scope).await?;
    if result.revision != command.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    let target = result
        .targets
        .iter_mut()
        .find(|t| t.audience == command.audience)
        .ok_or(AuthorityError::Forbidden)?;
    let recipients = match &command.registrations {
        None => Vec::new(),
        Some(ids) => resolve(tx, scope, ids).await?,
    };
    if target.introspection_clients == recipients {
        return Err(AuthorityError::Conflict.into());
    }
    receipts::capacity(tx, scope, command.registrations.is_none()).await?;
    target.introspection_clients = recipients.clone();
    capacity(&result.targets)?;
    result.revision = increment(result.revision, command.registrations.is_none())?;
    sqlx::query("UPDATE aegaeon.authorization_domain_targets SET introspection_clients=$4 WHERE environment_id=$1 AND domain_id=$2 AND audience=$3 COLLATE \"C\"")
        .bind(scope.environment_id).bind(scope.domain_id).bind(&command.audience)
        .bind(serde_json::to_value(&recipients)?).execute(&mut **tx).await?;
    sqlx::query(
        "UPDATE aegaeon.authorization_domains SET revision=$3 WHERE environment_id=$1 AND id=$2",
    )
    .bind(scope.environment_id)
    .bind(scope.domain_id)
    .bind(result.revision)
    .execute(&mut **tx)
    .await?;
    receipts::event(
        tx,
        scope,
        actor,
        operation,
        receipts::transition(
            serde_json::json!({"audience":command.audience,"recipients":recipients}),
            Some(command.expected_revision),
            result.revision,
        )?,
    )
    .await?;
    receipts::save(tx, scope, actor, key, operation, &digest, &result).await?;
    Ok(result)
}

async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    ids: &[Uuid],
) -> Result<Vec<Recipient>, RepositoryError> {
    require(!ids.is_empty() && ids.len() <= MAX_RECIPIENTS)?;
    let unique: BTreeSet<_> = ids.iter().copied().collect();
    require(unique.len() == ids.len() && !unique.contains(&Uuid::nil()))?;
    let mut recipients = Vec::with_capacity(ids.len());
    for id in unique {
        recipients.push(current(tx, scope, id).await?);
    }
    validate(&recipients)?;
    Ok(recipients)
}

/// Use in the current-state transaction; public identifiers never replace UUIDs.
pub(in crate::organizations) async fn current(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    registration: Uuid,
) -> Result<Recipient, RepositoryError> {
    let row = sqlx::query("SELECT c.client_identifier,c.status::text AS status,c.deleted_at IS NULL AS undeleted,c.client_type::text AS client_type,c.token_endpoint_authentication_method FROM aegaeon.clients c JOIN aegaeon.environments e ON e.id=c.environment_id AND e.active_configuration_version_id=c.configuration_version_id WHERE c.id=$1 AND c.environment_id=$2 FOR SHARE OF c")
        .bind(registration).bind(scope.environment_id).fetch_optional(&mut **tx).await?
        .ok_or(AuthorityError::Forbidden)?;
    let method: String = row.try_get("token_endpoint_authentication_method")?;
    if row.try_get::<String, _>("status")? != "ACTIVE"
        || !row.try_get::<bool, _>("undeleted")?
        || row.try_get::<String, _>("client_type")? != "CONFIDENTIAL"
        || !matches!(
            method.as_str(),
            "client_secret_basic" | "client_secret_post" | "private_key_jwt"
        )
    {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(Recipient {
        client_registration_id: registration,
        client_identifier: row.try_get("client_identifier")?,
    })
}
