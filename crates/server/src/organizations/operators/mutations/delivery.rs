//! Explicit scoped transport configuration; no credential is stored here.
use super::*;

mod encryption;
mod profiles;
pub(crate) mod registration;
pub use encryption::Encryption;
pub(crate) use profiles::{hosted_current, issuing_pin, resolve, CustomPin, Resolved};
pub use profiles::{Profiles, Route, Settings};
pub(crate) use registration::HostedRegistration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature="openapi",schema(as=OrganizationInvitationDeliveryChannel))]
pub struct Channel {
    pub endpoint: String,
    pub credential_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption: Option<Encryption>,
}

impl Channel {
    pub(crate) fn validate(&self, scope: Scope) -> Result<(), AuthorityError> {
        if let Some(key) = &self.encryption {
            key.public_key(scope)?;
        }
        require(
            serde_json::to_vec(self)
                .map_err(|_| AuthorityError::Invalid)?
                .len()
                <= 4096,
        )?;
        let url = url::Url::parse(&self.endpoint).map_err(|_| AuthorityError::Invalid)?;
        require(
            self.endpoint.len() <= 2048
                && url.as_str() == self.endpoint
                && url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.port_or_known_default() == Some(443)
                && matches!(url.host(), Some(url::Host::Domain(name)) if name.contains('.') && !name.ends_with('.'))
                && self.credential_sha256.len() == 64
                && self
                    .credential_sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        )?;
        crate::ssrf::validate_url_host_not_non_routable_literal(&url)
            .map_err(|_| AuthorityError::Invalid)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature="openapi",schema(as=OrganizationInvitationDeliveryConfiguration))]
pub struct Configuration {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    pub revision: i64,
    pub channel: Option<Settings>,
}

pub(crate) async fn read_locked(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
) -> Result<Configuration, RepositoryError> {
    let row = sqlx::query("SELECT revision,invitation_delivery FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2")
        .bind(scope.environment_id).bind(scope.domain_id).fetch_one(&mut **tx).await?;
    let channel: Option<Settings> = row
        .try_get::<Option<serde_json::Value>, _>("invitation_delivery")?
        .map(serde_json::from_value)
        .transpose()?;
    if let Some(channel) = &channel {
        channel.validate(scope)?;
    }
    Ok(Configuration {
        id: scope.domain_id,
        revision: row.try_get("revision")?,
        channel,
    })
}

pub async fn read(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<Configuration, RepositoryError> {
    lock_operator_authority(tx, scope, team, principal, Capability::Configure).await?;
    read_locked(tx, scope).await
}

#[derive(Serialize)]
pub struct Change {
    pub expected_revision: i64,
    pub channel: Option<Settings>,
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
    let authority =
        lock_operator_authority(tx, scope, team, actor.id, Capability::Configure).await?;
    let audited_actor = actor.with_operator(&authority, Capability::Configure);
    let actor = &audited_actor;
    require(change.expected_revision > 0)?;
    if let Some(channel) = &change.channel {
        channel.validate(scope)?;
    }
    let operation = if change.channel.is_some() {
        "domain.delivery.configure"
    } else {
        "domain.delivery.disable"
    };
    let digest = receipts::digest(&serde_json::json!({"change":change,"reason":actor.reason}))?;
    if let Some(previous) = receipts::previous(tx, scope, actor, key, operation, &digest).await? {
        return Ok(previous);
    }
    let mut result = read_locked(tx, scope).await?;
    if result.revision != change.expected_revision {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    if result.channel == change.channel {
        return Err(AuthorityError::Conflict.into());
    }
    receipts::capacity(tx, scope, change.channel.is_none()).await?;
    let next_revision = increment(result.revision, change.channel.is_none())?;
    result.channel =
        profiles::transition(tx, scope, &result, change.channel.as_ref(), next_revision).await?;
    result.revision = next_revision;
    let value = result
        .channel
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?;
    if let Some(value) = &value {
        let size: i32 = sqlx::query_scalar("SELECT octet_length($1::jsonb::text)")
            .bind(value)
            .fetch_one(&mut **tx)
            .await?;
        require(size <= 4096)?;
    }
    sqlx::query("UPDATE aegaeon.authorization_domains SET revision=$3,invitation_delivery=$4 WHERE environment_id=$1 AND id=$2")
        .bind(scope.environment_id).bind(scope.domain_id).bind(result.revision).bind(value).execute(&mut **tx).await?;
    // Endpoint and credential digest are configuration, not ordinary audit data.
    receipts::event(
        tx,
        scope,
        actor,
        operation,
        receipts::transition(
            serde_json::json!({"revision":result.revision,"enabled":change.channel.is_some()}),
            Some(change.expected_revision),
            result.revision,
        )?,
    )
    .await?;
    receipts::save(tx, scope, actor, key, operation, &digest, &result).await?;
    Ok(result)
}
