use super::*;
use aegaeon_crypto::hash::sha256_digest;
use serde_json::{json, Value};

fn refused() -> sqlx::Error {
    sqlx::Error::Protocol("creation receipt mismatch".into())
}

fn payload(receipt: &Receipt, revision: i64) -> Result<(Value, [u8; 32]), sqlx::Error> {
    if !(1..i64::MAX).contains(&revision) {
        return Err(refused());
    }
    let r = &receipt.0;
    let mut bytes = b"aegaeon-creation-primary-v1\0".to_vec();
    bytes.extend(r.environment_id.as_bytes());
    bytes.extend(r.operation_id.as_bytes());
    let kind = r.kind.as_str();
    bytes.extend((kind.len() as u32).to_be_bytes());
    bytes.extend(kind.as_bytes());
    for digest in [&r.selector_sha256, &r.actor_sha256, &r.payload_sha256] {
        if digest.len() != 64 {
            return Err(refused());
        }
        for offset in (0..64).step_by(2) {
            bytes.push(u8::from_str_radix(&digest[offset..offset + 2], 16).map_err(|_| refused())?);
        }
    }
    bytes.extend(r.owner_id.as_bytes());
    bytes.extend((r.subject.len() as u32).to_be_bytes());
    bytes.extend(r.subject.as_bytes());
    bytes.extend(r.attempt.to_be_bytes());
    bytes.extend(r.epoch.as_bytes());
    bytes.extend(revision.to_be_bytes());
    Ok((
        json!({"environment_id":r.environment_id,"operation_id":r.operation_id,"kind":kind,
        "selector_sha256":r.selector_sha256,"actor_sha256":r.actor_sha256,"payload_sha256":r.payload_sha256,
        "owner_id":r.owner_id,"subject":r.subject,"attempt":r.attempt,"epoch":r.epoch,"identity_revision":revision}),
        sha256_digest(&bytes),
    ))
}

pub(super) async fn read(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &Receipt,
) -> Result<bool, sqlx::Error> {
    let row: Option<(Value, Vec<u8>, i64)> = sqlx::query_as("SELECT to_jsonb(r)-ARRAY['receipt_sha256','recorded_at'],receipt_sha256,identity_revision FROM aegaeon.organization_creation_receipts r WHERE environment_id=$1 AND operation_id=$2")
        .bind(receipt.0.environment_id).bind(receipt.operation_id()).fetch_optional(&mut **tx).await?;
    let Some((stored, digest, revision)) = row else {
        return Ok(false);
    };
    let (expected, computed) = payload(receipt, revision)?;
    if stored != expected
        || digest != computed
        || receipt
            .0
            .receipt_sha256
            .as_deref()
            .is_some_and(|v| v != history::hex(&computed))
    {
        return Err(refused());
    }
    Ok(true)
}

pub(super) async fn append(
    tx: &mut Transaction<'_, Postgres>,
    receipt: &Receipt,
) -> Result<[u8; 32], sqlx::Error> {
    let revision: i64 = sqlx::query_scalar("SELECT organization_identity_revision FROM aegaeon.end_users WHERE id=$1 AND environment_id=$2 AND subject=$3 COLLATE \"C\" AND status<>'DELETED' FOR UPDATE")
        .bind(receipt.owner_id()).bind(receipt.0.environment_id).bind(receipt.subject()).fetch_one(&mut **tx).await?;
    let (expected, computed) = payload(receipt, revision)?;
    let observed: Vec<u8> =
        sqlx::query_scalar("SELECT aegaeon.organization_creation_record_v1($1)")
            .bind(expected)
            .fetch_one(&mut **tx)
            .await?;
    if observed != computed {
        return Err(refused());
    }
    Ok(computed)
}
