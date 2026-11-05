use super::*;
use serde::de::DeserializeOwned;

pub(crate) const MAX_CONFIGURATION_RECEIPTS: i64 = 10_000;

/// Called while holding the domain lock. Replays do not allocate another slot.
/// The reserve only accepts a currently active grant becoming inactive, so the
/// 64 operator identities, 64 client bindings, 32 target recipient sets and
/// one delivery-channel disable, one Environment identity-policy disable, one support-policy disable and one domain disable bound
/// the remaining revocations after normal admission
/// closes. No creation, reactivation or inactive-to-inactive edit uses it.
pub(super) async fn capacity(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    revocation: bool,
) -> Result<(), RepositoryError> {
    let maximum = MAX_CONFIGURATION_RECEIPTS
        + if revocation {
            (MAX_OPERATORS + clients::MAX_CLIENTS + targets::MAX_TARGETS + 4) as i64
        } else {
            0
        };
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM (SELECT 1 FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND operation LIKE 'domain.%' LIMIT $3) bounded")
        .bind(scope.environment_id).bind(scope.domain_id).bind(maximum).fetch_one(&mut **tx).await?;
    if count >= maximum {
        return Err(AuthorityError::Exhausted.into());
    }
    Ok(())
}

pub(super) fn validate_actor(actor: &AuditActor, key: &str) -> Result<(), AuthorityError> {
    actor.validate()?;
    require(matches!(actor.kind, ActorKind::Operator))?;
    require(!key.is_empty() && key.len() <= 128 && key.bytes().all(|v| v.is_ascii_graphic()))
}

pub(super) fn digest(value: &serde_json::Value) -> Result<Vec<u8>, RepositoryError> {
    Ok(aegaeon_crypto::hash::sha256_digest(&serde_json::to_vec(value)?).to_vec())
}

pub(super) async fn previous<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    key: &str,
    operation: &str,
    digest: &[u8],
) -> Result<Option<T>, RepositoryError> {
    let row = sqlx::query("SELECT request_digest,result FROM aegaeon.organization_authority_receipts WHERE environment_id=$1 AND domain_id=$2 AND actor_id=$3 AND actor_kind='operator' AND client_id=$4 AND operation=$5 AND idempotency_key=$6 AND client_registration_id=$7")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(&actor.client_id)
        .bind(operation).bind(key).bind(Uuid::nil()).fetch_optional(&mut **tx).await?;
    row.map(|row| {
        if row.try_get::<Vec<u8>, _>("request_digest")? != digest {
            return Err(AuthorityError::Conflict.into());
        }
        Ok(serde_json::from_value(row.try_get("result")?)?)
    })
    .transpose()
}

pub(super) async fn save<T: Serialize>(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    key: &str,
    operation: &str,
    digest: &[u8],
    result: &T,
) -> Result<(), RepositoryError> {
    sqlx::query("INSERT INTO aegaeon.organization_authority_receipts(environment_id,domain_id,actor_id,actor_kind,client_id,client_registration_id,operation,idempotency_key,request_digest,result) VALUES ($1,$2,$3,'operator',$4,$5,$6,$7,$8,$9)")
        .bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(&actor.client_id)
        .bind(Uuid::nil()).bind(operation).bind(key).bind(digest).bind(serde_json::to_value(result)?)
        .execute(&mut **tx).await?;
    Ok(())
}

pub(super) async fn event(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    actor: &AuditActor,
    event_type: &str,
    mut data: serde_json::Value,
) -> Result<(), RepositoryError> {
    actor.validate()?;
    if let Some(basis) = &actor.basis {
        data.as_object_mut()
            .ok_or(AuthorityError::Invalid)?
            .insert("authorityBasis".into(), basis.clone());
    }
    crate::organizations::audit::retention::validate_data(&data)?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.organization_authority_events(id,environment_id,domain_id,actor_id,actor_kind,client_id,request_id,reason,event_type,data) VALUES ($1,$2,$3,$4,'operator',$5,$6,$7,$8,$9)")
        .bind(id).bind(scope.environment_id).bind(scope.domain_id).bind(actor.id).bind(&actor.client_id)
        .bind(&actor.request_id).bind(&actor.reason).bind(event_type).bind(data).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO aegaeon.organization_authority_outbox(event_id) VALUES ($1)")
        .bind(id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Adds version provenance without rewriting prior immutable events.
pub(super) fn transition(
    mut data: serde_json::Value,
    before: Option<i64>,
    after: i64,
) -> Result<serde_json::Value, RepositoryError> {
    require(before.is_none_or(|value| value > 0) && after > 0)?;
    let object = data.as_object_mut().ok_or(AuthorityError::Invalid)?;
    object.insert(
        "before".into(),
        before.map_or(
            serde_json::Value::Null,
            |revision| serde_json::json!({"revision":revision}),
        ),
    );
    object.insert("after".into(), serde_json::json!({"revision":after}));
    Ok(data)
}
