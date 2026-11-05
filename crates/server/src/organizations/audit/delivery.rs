//! Acknowledgment changes delivery bookkeeping, never authority or audit history.
use super::*;
use crate::organizations::repository::{ActorKind, AuditActor};
use serde::{Deserialize, Serialize};

const OPERATION: &str = "audit.delivery.acknowledge";
const RECEIPT_LIMIT: i64 = super::retention::MAX_EVENTS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationAuditEventDigest))]
pub(crate) struct EventDigest {
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    pub id: Uuid,
    pub sha256: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationAuditDelivery))]
pub(crate) struct Delivery {
    event: Event,
    sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationAuditBatch))]
pub(crate) struct Batch {
    version: u8,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    environment_id: Uuid,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    domain_id: Uuid,
    deliveries: Vec<Delivery>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationAuditAcknowledgment))]
pub(crate) struct Acknowledgment {
    pub events: Vec<EventDigest>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = OrganizationAuditReceipt))]
pub(crate) struct Receipt {
    version: u8,
    batch_sha256: String,
    events: Vec<EventDigest>,
    #[cfg_attr(feature = "openapi", schema(value_type = String, format = "uuid"))]
    actor_id: Uuid,
    request_id: String,
    reason: String,
}

fn digest<T: Serialize>(value: &T) -> Result<String, RepositoryError> {
    Ok(aegaeon_crypto::hash::sha256_hex(&serde_json::to_vec(
        value,
    )?))
}

fn batch_digest(scope: Scope, events: &[EventDigest]) -> Result<String, RepositoryError> {
    digest(&serde_json::json!({"version":1,"scope":scope,"events":events}))
}

pub(crate) async fn pending(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    team: Uuid,
    principal: Uuid,
) -> Result<(Batch, String), RepositoryError> {
    lock_operator_authority(tx, scope, team, principal, Capability::Export).await?;
    let page = load(tx, scope, http_input::MAX_PAGE_SIZE, None, true, None).await?;
    let mut deliveries = Vec::with_capacity(page.events.len());
    let mut events = Vec::with_capacity(page.events.len());
    let mut bytes = 0;
    for event in page.events {
        let sha256 = digest(&event)?;
        let delivery = Delivery { event, sha256 };
        let length = serde_json::to_vec(&delivery)?.len();
        if bytes + length > PAGE_BYTES {
            if deliveries.is_empty() {
                return Err(RepositoryError::Unavailable);
            }
            break;
        }
        bytes += length;
        events.push(EventDigest {
            id: delivery.event.id,
            sha256: delivery.sha256.clone(),
        });
        deliveries.push(delivery);
    }
    Ok((
        Batch {
            version: 1,
            environment_id: scope.environment_id,
            domain_id: scope.domain_id,
            deliveries,
        },
        batch_digest(scope, &events)?,
    ))
}

fn validate(input: &Acknowledgment, actor: &AuditActor, key: &str) -> Result<(), AuthorityError> {
    actor.validate()?;
    super::super::model::require(
        matches!(actor.kind, ActorKind::Operator)
            && actor.reason == input.reason
            && !key.is_empty()
            && key.len() <= http_input::MAX_IDEMPOTENCY_BYTES
            && key.bytes().all(|b| b.is_ascii_graphic())
            && !input.events.is_empty()
            && input.events.len() <= http_input::MAX_PAGE_SIZE,
    )?;
    let mut previous = None;
    for event in &input.events {
        super::super::model::require(
            !event.id.is_nil()
                && previous.is_none_or(|id| event.id > id)
                && event.sha256.len() == 64
                && event
                    .sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        )?;
        previous = Some(event.id);
    }
    Ok(())
}

pub(crate) struct Command<'a> {
    pub scope: Scope,
    pub team: Uuid,
    pub actor: &'a AuditActor,
    pub key: &'a str,
    pub expected_batch: &'a str,
    pub input: &'a Acknowledgment,
}

pub(crate) async fn acknowledge(
    tx: &mut Transaction<'_, Postgres>,
    command: Command<'_>,
) -> Result<Receipt, RepositoryError> {
    let Command {
        scope,
        team,
        actor,
        key,
        expected_batch,
        input,
    } = command;
    validate(input, actor, key)?;
    lock_operator_authority(tx, scope, team, actor.id, Capability::Export).await?;
    let batch = batch_digest(scope, &input.events)?;
    if expected_batch != batch {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    let semantic = aegaeon_crypto::hash::sha256_digest(&serde_json::to_vec(
        &serde_json::json!({"batch":batch,"input":input}),
    )?);
    if let Some(row) = sqlx::query("SELECT request_digest,result FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_id=$3 AND actor_kind='operator' AND client_id=$4 AND client_registration_id=$5 AND operation=$6 AND idempotency_key=$7")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(&actor.client_id)
        .bind(Uuid::nil()).bind(OPERATION).bind(key).fetch_optional(&mut **tx).await? {
        if row.try_get::<Vec<u8>,_>("request_digest")? != semantic.as_slice() { return Err(AuthorityError::Conflict.into()); }
        return Ok(serde_json::from_value(row.try_get("result")?)?);
    }
    let ids: Vec<_> = input.events.iter().map(|e| e.id).collect();
    let page = load(tx, scope, input.events.len(), None, true, Some(&ids)).await?;
    let actual: Result<Vec<_>, RepositoryError> = page
        .events
        .into_iter()
        .map(|event| {
            Ok(EventDigest {
                id: event.id,
                sha256: digest(&event)?,
            })
        })
        .collect();
    if actual? != input.events {
        return Err(AuthorityError::PreconditionFailed.into());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND operation=$3 LIMIT $4) bounded")
        .bind(scope.environment_id).bind(scope.domain_id).bind(OPERATION).bind(RECEIPT_LIMIT).fetch_one(&mut **tx).await?;
    if count >= RECEIPT_LIMIT {
        return Err(AuthorityError::Exhausted.into());
    }
    let changed = sqlx::query("UPDATE aegaeon.organization_authority_outbox SET delivered_at=statement_timestamp() WHERE event_id=ANY($1) AND delivered_at IS NULL")
        .bind(&ids).execute(&mut **tx).await?.rows_affected();
    if changed != ids.len() as u64 {
        return Err(AuthorityError::Conflict.into());
    }
    let result = Receipt {
        version: 1,
        batch_sha256: batch,
        events: input.events.clone(),
        actor_id: actor.id,
        request_id: actor.request_id.clone(),
        reason: actor.reason.clone(),
    };
    sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) VALUES($1,$2,$3,'operator',$4,$5,$6,$7,$8,$9)")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(&actor.client_id)
        .bind(Uuid::nil()).bind(OPERATION).bind(key).bind(semantic.as_slice()).bind(serde_json::to_value(&result)?).execute(&mut **tx).await?;
    Ok(result)
}
