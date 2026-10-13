//! Persistent capability revisions. Callers own management authentication and audit.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

use super::{model::ToolConfiguration, validate_configuration, validate_transition, LtiError};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Registration {
    pub id: Uuid,
    pub client_record_id: Uuid,
    pub client_id: String,
    pub revision: i64,
    pub active_revision: Option<i64>,
    pub configuration: ToolConfiguration,
}

fn document(value: Value) -> Result<ToolConfiguration, LtiError> {
    let config: ToolConfiguration =
        serde_json::from_value(value).map_err(|_| LtiError::Unavailable)?;
    validate_configuration(&config)?;
    Ok(config)
}

pub(crate) async fn lock_environment(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
) -> Result<(), LtiError> {
    let row = sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
        .bind(environment)
        .fetch_optional(&mut **tx)
        .await?;
    if row.is_none() {
        return Err(LtiError::Denied);
    }
    Ok(())
}

/// Observe and lock a complete latest or active revision. Environment ownership
/// is explicit; the client must still be the same current canonical row.
pub(crate) async fn load(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    client: &str,
    active: bool,
) -> Result<Option<Registration>, LtiError> {
    let row = sqlx::query("SELECT r.id,r.client_record_id,r.client_id,r.revision,r.active_revision,v.document FROM aegaeon.lti_registrations r JOIN aegaeon.lti_registration_revisions v ON v.registration_id=r.id AND v.revision=CASE WHEN $3 THEN r.active_revision ELSE r.revision END WHERE r.environment_id=$1 AND r.client_id=$2 FOR UPDATE OF r")
        .bind(environment).bind(client).bind(active).fetch_optional(&mut **tx).await?;
    row.map(|row| {
        Ok(Registration {
            id: row.try_get("id")?,
            client_record_id: row.try_get("client_record_id")?,
            client_id: row.try_get("client_id")?,
            revision: row.try_get("revision")?,
            active_revision: row.try_get("active_revision")?,
            configuration: document(row.try_get("document")?)?,
        })
    })
    .transpose()
}

pub(crate) async fn current_client(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    client: &str,
) -> Result<Uuid, LtiError> {
    let row = sqlx::query("SELECT c.id FROM aegaeon.clients c JOIN aegaeon.active_runtime_environments e ON e.environment_id=c.environment_id AND e.configuration_version_id=c.configuration_version_id WHERE c.environment_id=$1 AND c.client_identifier=$2 AND c.status='ACTIVE' AND c.deleted_at IS NULL FOR SHARE OF c")
        .bind(environment).bind(client).fetch_optional(&mut **tx).await?.ok_or(LtiError::Denied)?;
    Ok(row.try_get("id")?)
}

async fn reserve(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    registration: Uuid,
    config: &ToolConfiguration,
) -> Result<(), LtiError> {
    for deployment in &config.deployments {
        let mut identities = vec![("deployment", deployment.id.as_str(), None)];
        identities.extend(deployment.resource_links.iter().map(|link| {
            (
                "resource_link",
                link.id.as_str(),
                Some(link.context.id.as_str()),
            )
        }));
        for (kind, id, context) in identities {
            sqlx::query("INSERT INTO aegaeon.lti_identifiers(environment_id,kind,identifier,registration_id,deployment_id,context_id) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING")
                .bind(environment).bind(kind).bind(id).bind(registration).bind(&deployment.id).bind(context).execute(&mut **tx).await?;
            let row = sqlx::query("SELECT registration_id,deployment_id,context_id FROM aegaeon.lti_identifiers WHERE environment_id=$1 AND kind=$2 AND identifier=$3")
                .bind(environment).bind(kind).bind(id).fetch_one(&mut **tx).await?;
            if row.try_get::<Uuid, _>("registration_id")? != registration
                || row.try_get::<String, _>("deployment_id")? != deployment.id
                || row.try_get::<Option<String>, _>("context_id")?.as_deref() != context
            {
                return Err(LtiError::Conflict);
            }
        }
    }
    Ok(())
}

/// Save an authorized revision under the caller's role-checked, audited transaction.
///
/// # Errors
/// Rejects stale bases, changed client identity, invalid transitions and storage failure.
pub async fn replace(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    client: &str,
    base_revision: i64,
    config: &ToolConfiguration,
    author: Uuid,
) -> Result<Registration, LtiError> {
    validate_configuration(config)?;
    if base_revision < 0 {
        return Err(LtiError::Invalid);
    }
    lock_environment(tx, environment).await?;
    let previous = load(tx, environment, client, false).await?;
    if previous.as_ref().map_or(0, |entry| entry.revision) != base_revision {
        return Err(LtiError::Conflict);
    }
    let client_record = match previous
        .as_ref()
        .filter(|_| config.status != super::model::Lifecycle::Active)
    {
        Some(previous) => previous.client_record_id,
        None => current_client(tx, environment, client).await?,
    };
    if let Some(previous) = &previous {
        if previous.client_record_id != client_record {
            return Err(LtiError::Conflict);
        }
        validate_transition(&previous.configuration, config)?;
    }
    let id = previous
        .as_ref()
        .map_or_else(Uuid::new_v4, |entry| entry.id);
    let revision = base_revision.checked_add(1).ok_or(LtiError::Unavailable)?;
    let active_revision = if config.security.staged_activation {
        previous.as_ref().and_then(|entry| entry.active_revision)
    } else {
        Some(revision)
    };
    if previous.is_none() {
        sqlx::query("INSERT INTO aegaeon.lti_registrations(id,environment_id,client_record_id,client_id) VALUES($1,$2,$3,$4)")
            .bind(id).bind(environment).bind(client_record).bind(client).execute(&mut **tx).await?;
    }
    reserve(tx, environment, id, config).await?;
    let value = serde_json::to_value(config).map_err(|_| LtiError::Invalid)?;
    sqlx::query("INSERT INTO aegaeon.lti_registration_revisions(registration_id,revision,document,author_id) VALUES($1,$2,$3,$4)")
        .bind(id).bind(revision).bind(value).bind(author).execute(&mut **tx).await?;
    sqlx::query("UPDATE aegaeon.lti_registrations SET revision=$2,active_revision=$3 WHERE id=$1")
        .bind(id)
        .bind(revision)
        .bind(active_revision)
        .execute(&mut **tx)
        .await?;
    Ok(Registration {
        id,
        client_record_id: client_record,
        client_id: client.into(),
        revision,
        active_revision,
        configuration: config.clone(),
    })
}

/// Activate exactly the latest revision; historical activation is never allowed.
///
/// # Errors
/// Rejects stale bases, inactive/replaced clients and unavailable storage.
pub async fn activate(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    client: &str,
    revision: i64,
) -> Result<Registration, LtiError> {
    lock_environment(tx, environment).await?;
    let mut entry = load(tx, environment, client, false)
        .await?
        .ok_or(LtiError::Denied)?;
    if entry.revision != revision {
        return Err(LtiError::Conflict);
    }
    if entry.configuration.status == super::model::Lifecycle::Active
        && current_client(tx, environment, client).await? != entry.client_record_id
    {
        return Err(LtiError::Denied);
    }
    sqlx::query("UPDATE aegaeon.lti_registrations SET active_revision=$2 WHERE id=$1")
        .bind(entry.id)
        .bind(revision)
        .execute(&mut **tx)
        .await?;
    entry.active_revision = Some(revision);
    Ok(entry)
}

pub(crate) async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    actor: &str,
    actor_type: &str,
    target: Uuid,
    event: &str,
    data: Value,
) -> Result<(), LtiError> {
    let inserted = sqlx::query("INSERT INTO aegaeon.audit_events(id,team_id,tenant_id,environment_id,event_type,category,outcome,severity,occurred_at,actor_type,actor_id,target_type,target_id,request_id,data) SELECT $1,t.team_id,e.tenant_id,e.id,$2,'LTI','SUCCESS','INFO',clock_timestamp(),$3,$4,'LTI',$5,$6,$7 FROM aegaeon.environments e JOIN aegaeon.tenants t ON t.id=e.tenant_id WHERE e.id=$8")
        .bind(Uuid::new_v4()).bind(event).bind(actor_type).bind(actor).bind(target.to_string()).bind(Uuid::new_v4().to_string()).bind(data).bind(environment)
        .execute(&mut **tx).await?;
    if inserted.rows_affected() != 1 {
        return Err(LtiError::Unavailable);
    }
    Ok(())
}

/// Remove one bounded batch of expired launch state. Permanent identity and
/// audit records are outside this retention operation.
///
/// # Errors
/// Returns a database error when cleanup cannot complete.
pub(crate) async fn cleanup_expired(
    pool: &sqlx::PgPool,
    environment: Uuid,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM aegaeon.lti_launch_intents WHERE id IN (SELECT id FROM aegaeon.lti_launch_intents WHERE environment_id=$1 AND expires_at<=floor(extract(epoch FROM clock_timestamp()))::bigint AND created_at<=floor(extract(epoch FROM clock_timestamp()))::bigint - 300 ORDER BY expires_at LIMIT 512 FOR UPDATE SKIP LOCKED)")
        .bind(environment).execute(pool).await?.rows_affected())
}
