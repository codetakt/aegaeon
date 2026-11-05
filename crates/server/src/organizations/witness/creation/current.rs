//! Domain idempotency from the selected primary. No independently committed
//! prepare/finish history: the actual creation receipt commits with its mutation.
use super::*;
use crate::organizations::request_work::Admission as LocalAdmission;
use sqlx::{Postgres, Transaction};

fn operation_id(
    environment: Uuid,
    generation: Uuid,
    kind: Kind,
    selector: &[u8; 32],
    domain: &[u8],
) -> Uuid {
    let mut bytes = b"aegaeon-current-creation-v1\0".to_vec();
    bytes.extend(domain);
    bytes.extend(environment.as_bytes());
    bytes.extend(generation.as_bytes());
    bytes.extend(kind.as_str().as_bytes());
    bytes.extend(selector);
    let hash = aegaeon_crypto::hash::sha256_digest(&bytes);
    let mut id: [u8; 16] = hash[..16].try_into().expect("fixed digest length");
    id[6] = (id[6] & 15) | 0x80;
    id[8] = (id[8] & 63) | 0x80;
    Uuid::from_bytes(id)
}

pub(in crate::organizations) async fn lookup(
    local: &LocalAdmission,
    environment: Uuid,
    kind: Kind,
    selector: [u8; 32],
) -> Result<Option<Receipt>> {
    let runtime = local.current_runtime()?.ok_or(Error::Refused)?;
    let mut connection = local.connection(&runtime.pool).await?;
    let value:Option<serde_json::Value>=sqlx::query_scalar("SELECT to_jsonb(r)-ARRAY['identity_revision','recorded_at','receipt_sha256'] || jsonb_build_object('state','committed','receipt_sha256',encode(receipt_sha256,'hex')) FROM aegaeon.organization_creation_receipts r WHERE environment_id=$1 AND kind=$2 AND selector_sha256=$3")
        .bind(environment).bind(kind.as_str()).bind(history::hex(&selector)).fetch_optional(connection.as_mut()?).await?;
    connection.release().await;
    value
        .map(|value| {
            let row: Stored = serde_json::from_value(value)?;
            if row.environment_id != environment
                || row.kind != kind
                || row.selector_sha256 != history::hex(&selector)
                || row.operation_id.is_nil()
                || row.owner_id.is_nil()
                || row.epoch.is_nil()
                || row.state != State::Committed
                || row
                    .receipt_sha256
                    .as_deref()
                    .is_none_or(|hash| hash.len() != 64)
                || row.slot.is_some()
                || row.generation.is_some()
                || row.worker_id.is_some()
                || row.principal.is_some()
            {
                return Err(Error::Refused);
            }
            history::validate_subject(&row.subject)?;
            Ok(Receipt(row, Source::Primary))
        })
        .transpose()
}

pub(in crate::organizations) async fn prepare(
    local: &LocalAdmission,
    environment: Uuid,
    input: &Input,
) -> Result<Receipt> {
    if let Some(receipt) = lookup(local, environment, input.kind, input.selector).await? {
        return if receipt.matches(input) {
            Ok(receipt)
        } else {
            Err(Error::Conflict)
        };
    }
    let selected = local.current_runtime()?.ok_or(Error::Refused)?.selection;
    let operation = operation_id(
        environment,
        selected.generation(),
        input.kind,
        &input.selector,
        b"operation\0",
    );
    let owner = operation_id(
        environment,
        selected.generation(),
        input.kind,
        &input.selector,
        b"owner\0",
    );
    Ok(Receipt(
        Stored {
            environment_id: environment,
            operation_id: operation,
            kind: input.kind,
            selector_sha256: history::hex(&input.selector),
            actor_sha256: history::hex(&input.actor),
            payload_sha256: history::hex(&input.payload),
            requested_subject: input.subject.clone(),
            owner_id: owner,
            subject: input.subject.clone().unwrap_or_else(|| owner.to_string()),
            state: State::Reserved,
            attempt: 1,
            epoch: selected.generation(),
            slot: None,
            generation: None,
            worker_id: None,
            principal: None,
            receipt_sha256: None,
        },
        Source::Primary,
    ))
}

/// Serialize only competing creation selectors inside the actual application
/// transaction. A hash collision can add contention but cannot authorize replay.
pub(super) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    receipts: &[Receipt],
) -> std::result::Result<(), sqlx::Error> {
    let mut keys = receipts
        .iter()
        .filter(|r| r.1 == Source::Primary)
        .map(|receipt| {
            let mut bytes = b"aegaeon-current-creation-lock-v1\0".to_vec();
            bytes.extend(receipt.0.environment_id.as_bytes());
            bytes.extend(receipt.0.kind.as_str().as_bytes());
            bytes.extend(receipt.0.selector_sha256.as_bytes());
            i64::from_be_bytes(
                aegaeon_crypto::hash::sha256_digest(&bytes)[..8]
                    .try_into()
                    .expect("fixed digest length"),
            )
        })
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    for key in keys {
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(key)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

pub(super) fn decision(
    receipt: &Receipt,
    exists: bool,
) -> aegaeon_pure::organization_creation::Decision {
    use aegaeon_pure::organization_creation::Decision;
    if receipt.1 == Source::Primary {
        if exists {
            Decision::Replay
        } else if receipt.state() == State::Reserved {
            Decision::Apply
        } else {
            Decision::Reconcile
        }
    } else {
        receipt.state().decision(exists)
    }
}

pub(in crate::organizations) async fn finish(
    local: &LocalAdmission,
    environment: Uuid,
    receipt: &Receipt,
    outcome: &PrimaryOutcome,
) -> Result<Receipt> {
    if receipt.1 != Source::Primary
        || receipt.0.environment_id != environment
        || outcome.operation_id != receipt.operation_id()
        || outcome.attempt != receipt.attempt()
    {
        return Err(Error::Refused);
    }
    // COMMIT/ROLLBACK is already known to the caller. There is no second state
    // transition whose failure could leave a completed primary write pending.
    let mut finished = receipt.clone();
    finished.0.state = if outcome.receipt.is_some() {
        State::Committed
    } else {
        State::Reserved
    };
    finished.0.receipt_sha256 = outcome.receipt.as_ref().map(history::hex);
    local.ensure_open()?;
    Ok(finished)
}
