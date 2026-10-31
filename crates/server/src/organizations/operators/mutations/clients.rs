//! Retained registration-scoped configuration, never a bearer authority.
use super::*;
use crate::organizations::model::{valid_keys, MAX_PRIVILEGES};

pub const MAX_CLIENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientTarget {
    pub audience: String,
    pub privileges: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientBinding {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub client_registration_id: Uuid,
    pub client_identifier: String,
    pub active: bool,
    pub revision: i64,
    pub targets: Vec<ClientTarget>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ClientCommand {
    Create {
        client_registration_id: Uuid,
        expected_revision: i64,
        active: bool,
        targets: Vec<ClientTarget>,
    },
    Update {
        id: Uuid,
        expected_revision: i64,
        active: bool,
        targets: Vec<ClientTarget>,
    },
    Revoke {
        id: Uuid,
        expected_revision: i64,
    },
}

impl ClientCommand {
    fn operation(&self) -> &'static str {
        match self {
            Self::Create { .. } => "domain.client.create",
            Self::Update { .. } => "domain.client.update",
            Self::Revoke { .. } => "domain.client.revoke",
        }
    }
}

pub(in crate::organizations) fn validate_targets(
    values: &[ClientTarget],
) -> Result<(), RepositoryError> {
    require(!values.is_empty() && values.len() <= targets::MAX_TARGETS)?;
    let mut audiences = BTreeSet::new();
    for value in values {
        targets::Target {
            audience: value.audience.clone(),
            management: false,
            introspection_clients: Vec::new(),
        }
        .validate()?;
        let keys: BTreeSet<_> = value.privileges.iter().cloned().collect();
        require(
            audiences.insert(&value.audience)
                && !keys.is_empty()
                && keys.len() == value.privileges.len()
                && valid_keys(&keys, MAX_PRIVILEGES),
        )?;
    }
    if serde_json::to_vec(values)?.len() > targets::MAX_TARGET_BYTES {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}

pub(in crate::organizations) fn decode(
    row: &sqlx::postgres::PgRow,
) -> Result<ClientBinding, RepositoryError> {
    let value = ClientBinding {
        id: row.try_get("id")?,
        client_registration_id: row.try_get("client_registration_id")?,
        client_identifier: row.try_get("client_identifier")?,
        active: row.try_get("active")?,
        revision: row.try_get("revision")?,
        targets: serde_json::from_value(row.try_get("targets")?)?,
    };
    require(
        !value.id.is_nil()
            && !value.client_registration_id.is_nil()
            && value.revision > 0
            && !value.client_identifier.is_empty()
            && value.client_identifier.len() <= 255,
    )?;
    validate_targets(&value.targets)?;
    Ok(value)
}

pub async fn list(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<Vec<ClientBinding>, RepositoryError> {
    lock_operator_authority(tx, scope, team, principal, Capability::Configure).await?;
    let rows = sqlx::query("SELECT id,client_registration_id,client_identifier,active,revision,targets FROM aegaeon.organization_client_bindings WHERE environment_id=$1 AND domain_id=$2 ORDER BY id LIMIT 65")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_all(&mut **tx).await?;
    if rows.len() > MAX_CLIENTS {
        return Err(AuthorityError::Exhausted.into());
    }
    rows.iter().map(decode).collect()
}

async fn registered_targets(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    values: &[ClientTarget],
) -> Result<(), RepositoryError> {
    validate_targets(values)?;
    for value in values {
        let found: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM aegaeon.authorization_domain_targets WHERE environment_id=$1 AND domain_id=$2 AND audience=$3)")
            .bind(scope.environment_id).bind(scope.domain_id).bind(&value.audience).fetch_one(&mut **tx).await?;
        if !found {
            return Err(AuthorityError::Forbidden.into());
        }
    }
    Ok(())
}

pub(in crate::organizations) async fn current_client(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    registration: Uuid,
    active: bool,
) -> Result<String, RepositoryError> {
    require(!registration.is_nil())?;
    let row = sqlx::query("SELECT c.client_identifier,c.status::text AS status,c.deleted_at IS NULL AS undeleted,c.client_type::text AS client_type,c.token_endpoint_authentication_method,c.dpop_bound_access_tokens,c.allowed_grant_types FROM aegaeon.clients c JOIN aegaeon.environments e ON e.id=c.environment_id AND e.active_configuration_version_id=c.configuration_version_id WHERE c.id=$1 AND c.environment_id=$2 FOR SHARE OF c")
        .bind(registration).bind(scope.environment_id).fetch_optional(&mut **tx).await?
        .ok_or(AuthorityError::Forbidden)?;
    let identifier: String = row.try_get("client_identifier")?;
    require(!identifier.is_empty() && identifier.len() <= 255)?;
    if active
        && (row.try_get::<String, _>("status")? != "ACTIVE"
            || !row.try_get::<bool, _>("undeleted")?
            || row.try_get::<String, _>("client_type")? != "CONFIDENTIAL"
            || row.try_get::<String, _>("token_endpoint_authentication_method")? == "none"
            || row.try_get::<Option<bool>, _>("dpop_bound_access_tokens")? != Some(true)
            || !row
                .try_get::<Vec<String>, _>("allowed_grant_types")?
                .iter()
                .any(|g| g == "urn:ietf:params:oauth:grant-type:token-exchange"))
    {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(identifier)
}

pub(super) async fn require_activation_ready(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<(), RepositoryError> {
    let bindings = list(tx, scope, team, principal).await?;
    let mut active = false;
    for binding in bindings.iter().filter(|b| b.active) {
        if current_client(tx, scope, binding.client_registration_id, true).await?
            != binding.client_identifier
        {
            return Err(AuthorityError::Forbidden.into());
        }
        registered_targets(tx, scope, &binding.targets).await?;
        active = true;
    }
    if !active {
        return Err(AuthorityError::Forbidden.into());
    }
    Ok(())
}

pub async fn apply(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    actor: &AuditActor,
    key: &str,
    command: &ClientCommand,
) -> Result<ClientBinding, RepositoryError> {
    receipts::validate_actor(actor, key)?;
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    let digest = receipts::digest(&serde_json::json!({"command":command,"reason":actor.reason}))?;
    if let Some(previous) =
        receipts::previous(tx, scope, actor, key, command.operation(), &digest).await?
    {
        return Ok(previous);
    }
    let result = match command {
        ClientCommand::Create {
            client_registration_id,
            expected_revision,
            active,
            targets,
        } => {
            create(
                tx,
                scope,
                *client_registration_id,
                *expected_revision,
                *active,
                targets,
            )
            .await?
        }
        ClientCommand::Update { .. } | ClientCommand::Revoke { .. } => {
            update(tx, scope, command).await?
        }
    };
    let before_revision = match command {
        ClientCommand::Create { .. } => None,
        ClientCommand::Update {
            expected_revision, ..
        }
        | ClientCommand::Revoke {
            expected_revision, ..
        } => Some(*expected_revision),
    };
    let mut data = receipts::transition(
        serde_json::json!({"id":result.id,"clientRegistrationId":result.client_registration_id,"active":result.active,"revision":result.revision,"configurationSha256":aegaeon_crypto::hash::sha256_hex(&serde_json::to_vec(&result)?)}),
        before_revision,
        result.revision,
    )?;
    if let ClientCommand::Create {
        expected_revision, ..
    } = command
    {
        data["domainBefore"] = serde_json::json!({"revision":expected_revision});
        data["domainAfter"] = serde_json::json!({"revision":increment(*expected_revision, false)?});
    }
    receipts::event(tx, scope, actor, command.operation(), data).await?;
    receipts::save(tx, scope, actor, key, command.operation(), &digest, &result).await?;
    Ok(result)
}

async fn create(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    registration: Uuid,
    expected_revision: i64,
    active: bool,
    targets: &[ClientTarget],
) -> Result<ClientBinding, RepositoryError> {
    require(expected_revision > 0)?;
    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2",
    )
    .bind(scope.environment_id)
    .bind(scope.domain_id)
    .fetch_one(&mut **tx)
    .await?;
    if revision != expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    receipts::capacity(tx, scope, false).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_client_bindings WHERE environment_id=$1 AND domain_id=$2 LIMIT 64) retained")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_one(&mut **tx).await?;
    if count >= MAX_CLIENTS as i64 {
        return Err(AuthorityError::Exhausted.into());
    }
    registered_targets(tx, scope, targets).await?;
    let result = ClientBinding {
        id: Uuid::new_v4(),
        client_registration_id: registration,
        client_identifier: current_client(tx, scope, registration, active).await?,
        active,
        revision: 1,
        targets: targets.to_vec(),
    };
    let changed = sqlx::query("INSERT INTO aegaeon.organization_client_bindings(id,environment_id,domain_id,client_registration_id,client_identifier,active,targets) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(environment_id,domain_id,client_registration_id) DO NOTHING")
        .bind(result.id).bind(scope.environment_id).bind(scope.domain_id).bind(registration)
        .bind(&result.client_identifier).bind(active).bind(serde_json::to_value(targets)?).execute(&mut **tx).await?;
    if changed.rows_affected() != 1 {
        return Err(AuthorityError::Conflict.into());
    }
    sqlx::query(
        "UPDATE aegaeon.authorization_domains SET revision=$3 WHERE environment_id=$1 AND id=$2",
    )
    .bind(scope.environment_id)
    .bind(scope.domain_id)
    .bind(increment(revision, false)?)
    .execute(&mut **tx)
    .await?;
    Ok(result)
}

async fn update(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    command: &ClientCommand,
) -> Result<ClientBinding, RepositoryError> {
    let (id, expected) = match command {
        ClientCommand::Update {
            id,
            expected_revision,
            ..
        }
        | ClientCommand::Revoke {
            id,
            expected_revision,
        } => (*id, *expected_revision),
        ClientCommand::Create { .. } => return Err(AuthorityError::Invalid.into()),
    };
    require(!id.is_nil() && expected > 0)?;
    let row = sqlx::query("SELECT id,client_registration_id,client_identifier,active,revision,targets FROM aegaeon.organization_client_bindings WHERE environment_id=$1 AND domain_id=$2 AND id=$3 FOR UPDATE")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id).fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let mut result = decode(&row)?;
    if result.revision != expected {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    let revoke = matches!(command, ClientCommand::Revoke { .. }) && result.active;
    receipts::capacity(tx, scope, revoke).await?;
    if let ClientCommand::Update {
        active, targets, ..
    } = command
    {
        registered_targets(tx, scope, targets).await?;
        if current_client(tx, scope, result.client_registration_id, *active).await?
            != result.client_identifier
        {
            return Err(AuthorityError::Forbidden.into());
        }
        result.active = *active;
        result.targets.clone_from(targets);
    } else {
        result.active = false;
    }
    result.revision = increment(result.revision, revoke)?;
    sqlx::query("UPDATE aegaeon.organization_client_bindings SET active=$4,revision=$5,targets=$6 WHERE environment_id=$1 AND domain_id=$2 AND id=$3")
        .bind(scope.environment_id).bind(scope.domain_id).bind(id).bind(result.active)
        .bind(result.revision).bind(serde_json::to_value(&result.targets)?).execute(&mut **tx).await?;
    Ok(result)
}
