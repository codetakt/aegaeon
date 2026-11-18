//! Durable ciphertext and finite attempts; purpose authorization remains external.
//!
//! Producers call enqueue in the same transaction as their proof, business state
//! and audit event. A claim is never a send permit. Send admission must retain the
//! purpose's current authority locks and recheck the exact lease and generation.

use super::{
    lifecycle::Selection,
    model::require,
    notification_envelope::{MessageContext, PublicDeliveryKey, Scope as MessageScope},
    notification_retry::MAX_ATTEMPTS,
    repository::RepositoryError,
    AuthorityError,
};
use serde_json::Value;
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const MAX_BATCH: i64 = 32;
pub const LEASE_SECONDS: i64 = 45;
const ACTIVE_LIMIT: i32 = 10_000;
const RETAINED_LIMIT: i32 = 100_000;
/// Keep minimal transport records for seven days after both termination and
/// proof expiry. Business audit and replay receipts have separate lifecycles.
pub const RETENTION_SECONDS: i64 = 7 * 24 * 60 * 60;

/// Purpose-owned immutable IDs. These do not authenticate a caller.
pub struct Object {
    pub id: Uuid,
    pub parent: Option<Uuid>,
}

/// Ciphertext plus authoritative producer metadata, never a plaintext proof.
pub struct Prepared {
    context: MessageContext,
    object: Object,
    key_version: String,
    ciphertext: String,
    created_at: i64,
}

impl Prepared {
    /// Seal once after the purpose handler has established current authority.
    ///
    /// # Errors
    /// Refuses invalid context, missing key custody or an unbounded payload.
    pub fn seal(
        context: MessageContext,
        object: Object,
        key: &PublicDeliveryKey,
        plaintext: Zeroizing<Vec<u8>>,
        now: i64,
    ) -> Result<Self, RepositoryError> {
        require(!object.id.is_nil() && object.parent.is_none_or(|id| !id.is_nil()))?;
        require(!matches!(context.scope, MessageScope::Installation))?;
        let ciphertext = key
            .seal(&context, &plaintext, now)
            .map_err(|_| RepositoryError::Unavailable)?;
        // This API consumes the secret and erases it before returning only
        // retained ciphertext metadata. Borrowing would extend its lifetime.
        drop(plaintext);
        Ok(Self {
            context,
            object,
            key_version: key.version_id().to_owned(),
            ciphertext,
            created_at: now,
        })
    }

    pub fn message_id(&self) -> Uuid {
        self.context.message_id
    }
}

/// Insert within the caller's business transaction; does not commit or send.
///
/// # Errors
/// Refuses exhausted active capacity, duplicate IDs and unavailable storage.
/// The caller must roll back the whole business transaction on an error.
pub async fn enqueue(
    tx: &mut Transaction<'_, Postgres>,
    message: &Prepared,
) -> Result<(), RepositoryError> {
    let (environment, domain, organization) = match message.context.scope {
        MessageScope::Environment { environment_id } => (environment_id, None, None),
        MessageScope::Domain {
            environment_id,
            domain_id,
        } => (environment_id, Some(domain_id), None),
        MessageScope::Organization {
            environment_id,
            domain_id,
            organization_id,
        } => (environment_id, Some(domain_id), Some(organization_id)),
        MessageScope::Installation => return Err(AuthorityError::Invalid.into()),
    };
    sqlx::query("INSERT INTO aegaeon.notification_queue_capacity(environment_id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(environment).execute(&mut **tx).await?;
    let admitted: Option<i32> = sqlx::query_scalar("UPDATE aegaeon.notification_queue_capacity SET active_messages=active_messages+1,retained_messages=retained_messages+1 WHERE environment_id=$1 AND active_messages<$2 AND retained_messages<$3 RETURNING active_messages")
        .bind(environment).bind(ACTIVE_LIMIT).bind(RETAINED_LIMIT).fetch_optional(&mut **tx).await?;
    if admitted.is_none() {
        return Err(AuthorityError::Exhausted.into());
    }
    sqlx::query("INSERT INTO aegaeon.notification_messages(id,environment_id,domain_id,organization_id,object_id,parent_id,deployment_id,runtime_generation,purpose,key_version,context,encrypted_payload,created_at,expires_at,available_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$13)")
        .bind(message.context.message_id).bind(environment).bind(domain).bind(organization)
        .bind(message.object.id).bind(message.object.parent).bind(message.context.deployment_id)
        .bind(message.context.runtime_generation).bind(&message.context.purpose)
        .bind(&message.key_version).bind(serde_json::to_value(&message.context)?)
        .bind(&message.ciphertext).bind(message.created_at).bind(message.context.expires_at)
        .execute(&mut **tx).await?;
    Ok(())
}

/// A committed claim identifies bookkeeping only. It exposes no secret payload.
pub struct Claim {
    pub environment_id: Uuid,
    pub domain_id: Option<Uuid>,
    pub message_id: Uuid,
    pub object_id: Uuid,
    pub parent_id: Option<Uuid>,
    pub purpose: String,
    pub attempt_id: Uuid,
    pub worker_id: Uuid,
    pub fence: i64,
    pub ordinal: u8,
    pub lease_until: i64,
    pub expires_at: i64,
    pub recovered_lease: bool,
}

#[derive(Default, serde::Serialize)]
pub(crate) struct Statistics {
    pub pending: i64,
    pub leased: i64,
    pub oldest_age_seconds: i64,
}

/// A bounded, non-authoritative operational snapshot of active work only.
pub(crate) async fn statistics(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    now: i64,
) -> Result<Statistics, RepositoryError> {
    require(!environment.is_nil() && now >= 0)?;
    let (pending, leased, oldest): (i64, i64, Option<i64>) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE state='pending'),count(*) FILTER (WHERE state='leased'),min(created_at) FROM aegaeon.notification_messages WHERE environment_id=$1 AND state IN ('pending','leased')",
    ).bind(environment).fetch_one(&mut **tx).await?;
    Ok(Statistics {
        pending,
        leased,
        oldest_age_seconds: oldest.map_or(0, |at| now.saturating_sub(at).max(0)),
    })
}

/// Claim only domains whose current transport credential matches this worker.
/// Routing precedes the lease/attempt mutation; purpose admission still rechecks
/// the current configuration before opening or sending any payload.
///
/// # Errors
/// Refuses invalid bounds/credential digests, exhausted fencing and store failure.
pub(crate) async fn claim_delivery(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    selection: Selection,
    worker: Uuid,
    credential_digest: &str,
    limit: i64,
    now: i64,
) -> Result<Vec<Claim>, RepositoryError> {
    require(
        credential_digest.len() == 64
            && credential_digest
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
    )?;
    claim_scoped(
        tx,
        environment,
        selection,
        worker,
        Some(credential_digest),
        limit,
        now,
    )
    .await
}

// Generic queue state-machine fixtures include Environment-scoped purposes.
// An unfiltered claim is deliberately unavailable to production workers.
#[cfg(test)]
pub(crate) async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    selection: Selection,
    worker: Uuid,
    limit: i64,
    now: i64,
) -> Result<Vec<Claim>, RepositoryError> {
    claim_scoped(tx, environment, selection, worker, None, limit, now).await
}

async fn claim_scoped(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    selection: Selection,
    worker: Uuid,
    credential_digest: Option<&str>,
    limit: i64,
    now: i64,
) -> Result<Vec<Claim>, RepositoryError> {
    require(
        !environment.is_nil() && !worker.is_nil() && now >= 0 && (1..=MAX_BATCH).contains(&limit),
    )?;
    // EXISTS does not lock domain rows in reverse order to purpose admission.
    // A concurrent configuration change is still refused by admit_current.
    let rows = sqlx::query("SELECT id,domain_id,object_id,parent_id,purpose,attempts,fence,expires_at,attempt_id FROM aegaeon.notification_messages m WHERE environment_id=$1 AND deployment_id=$2 AND runtime_generation=$3 AND state IN ('pending','leased') AND available_at<=$4 AND expires_at>$4 AND attempts<$5 AND (state='pending' OR lease_until<=$4) AND ($7::text IS NULL OR EXISTS (SELECT 1 FROM aegaeon.authorization_domains d WHERE d.environment_id=m.environment_id AND d.id=m.domain_id AND d.invitation_delivery->>'credentialSha256'=$7 AND jsonb_typeof(d.invitation_delivery->'encryption')='object')) ORDER BY available_at,id LIMIT $6 FOR UPDATE SKIP LOCKED")
        .bind(environment).bind(selection.deployment_id()).bind(selection.generation())
        .bind(now).bind(i16::from(MAX_ATTEMPTS)).bind(limit).bind(credential_digest).fetch_all(&mut **tx).await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows {
        let id: Uuid = row.try_get("id")?;
        let expires: i64 = row.try_get("expires_at")?;
        let fence = row
            .try_get::<i64, _>("fence")?
            .checked_add(1)
            .ok_or(AuthorityError::Exhausted)?;
        let ordinal = u8::try_from(row.try_get::<i16, _>("attempts")?)
            .ok()
            .and_then(|n| n.checked_add(1))
            .ok_or(AuthorityError::Invalid)?;
        require((1..=MAX_ATTEMPTS).contains(&ordinal))?;
        let lease_until = now
            .checked_add(LEASE_SECONDS)
            .ok_or(AuthorityError::Invalid)?
            .min(expires);
        let attempt_id = Uuid::new_v4();
        let previous: Option<Uuid> = row.try_get("attempt_id")?;
        if let Some(previous) = previous {
            sqlx::query("UPDATE aegaeon.notification_attempts SET completed_at=$3,outcome='uncertain' WHERE environment_id=$1 AND id=$2 AND completed_at IS NULL")
                .bind(environment).bind(previous).bind(now).execute(&mut **tx).await?;
        }
        // Persist a finite crash-recovery plan too; a process restart never
        // resamples the pending attempt's jitter or shortens its retry interval.
        let available = crash_retry_at(ordinal, lease_until, expires)?;
        sqlx::query("UPDATE aegaeon.notification_messages SET state='leased',attempts=$3,fence=$4,attempt_id=$5,worker_id=$6,lease_until=$7,available_at=$8,last_outcome=CASE WHEN attempt_id IS NULL THEN last_outcome ELSE 'uncertain' END WHERE environment_id=$1 AND id=$2")
            .bind(environment).bind(id).bind(i16::from(ordinal)).bind(fence).bind(attempt_id)
            .bind(worker).bind(lease_until).bind(available).execute(&mut **tx).await?;
        sqlx::query("INSERT INTO aegaeon.notification_attempts(environment_id,message_id,ordinal,id,worker_id,fence,claimed_at,lease_until) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(environment).bind(id).bind(i16::from(ordinal)).bind(attempt_id)
            .bind(worker).bind(fence).bind(now).bind(lease_until).execute(&mut **tx).await?;
        result.push(Claim {
            environment_id: environment,
            domain_id: row.try_get("domain_id")?,
            message_id: id,
            object_id: row.try_get("object_id")?,
            parent_id: row.try_get("parent_id")?,
            purpose: row.try_get("purpose")?,
            attempt_id,
            worker_id: worker,
            fence,
            ordinal,
            lease_until,
            expires_at: expires,
            recovered_lease: previous.is_some(),
        });
    }
    Ok(result)
}

fn crash_retry_at(ordinal: u8, lease_until: i64, expires: i64) -> Result<i64, RepositoryError> {
    use super::notification_retry::{
        jitter_limit, plan, CompletedAttempt, RetryPlan, TransportOutcome,
    };
    let limit = jitter_limit(ordinal).map_err(|_| AuthorityError::Invalid)?;
    let mut random = [0u8; 8];
    aegaeon_crypto::rand::fill_random(&mut random).map_err(|_| RepositoryError::Unavailable)?;
    let jitter = u64::from_le_bytes(random) % (limit + 1);
    let completed = CompletedAttempt {
        attempts: ordinal,
        observed_at: u64::try_from(lease_until).map_err(|_| AuthorityError::Invalid)?,
        outcome: TransportOutcome::Uncertain,
        retry_after: None,
    };
    match plan(
        completed,
        u64::try_from(expires).map_err(|_| AuthorityError::Invalid)?,
        jitter,
    )
    .map_err(|_| AuthorityError::Invalid)?
    {
        RetryPlan::At(at) => i64::try_from(at).map_err(|_| AuthorityError::Invalid.into()),
        // No legal retry fits. Keep the current attempt eligible to finish,
        // but never shorten its crash backoff to obtain another attempt.
        // Expiry/exhaustion retirement removes the ciphertext independently.
        RetryPlan::Stop(_) => Ok(expires),
    }
}

/// Check and mark the exact live attempt after purpose authorization locks.
///
/// Expected context must be reconstructed from current purpose state, never
/// trusted by deserializing the stored message header. The caller commits this
/// admission before decrypting and performing HTTP.
///
/// # Errors
/// Refuses stale ownership, changed context/generation, expiry or unavailable SQL.
pub async fn admit(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    expected: &MessageContext,
    selection: Selection,
    now: i64,
) -> Result<(String, String), RepositoryError> {
    require(
        now >= 0
            && expected.message_id == claim.message_id
            && expected.deployment_id == selection.deployment_id()
            && expected.runtime_generation == selection.generation()
            && expected.expires_at == claim.expires_at
            && now < claim.lease_until
            && now < claim.expires_at,
    )?;
    let expected: Value = serde_json::to_value(expected)?;
    let row=sqlx::query("SELECT key_version,encrypted_payload FROM aegaeon.notification_messages WHERE environment_id=$1 AND id=$2 AND state='leased' AND attempt_id=$3 AND worker_id=$4 AND fence=$5 AND lease_until>$6 AND expires_at>$6 AND context=$7 AND deployment_id=$8 AND runtime_generation=$9 FOR UPDATE")
        .bind(claim.environment_id).bind(claim.message_id).bind(claim.attempt_id)
        .bind(claim.worker_id).bind(claim.fence).bind(now).bind(expected)
        .bind(selection.deployment_id()).bind(selection.generation())
        .fetch_optional(&mut **tx).await?.ok_or(AuthorityError::Forbidden)?;
    let updated=sqlx::query("UPDATE aegaeon.notification_attempts SET admitted_at=$4 WHERE environment_id=$1 AND message_id=$2 AND id=$3 AND admitted_at IS NULL AND completed_at IS NULL AND lease_until>$4")
        .bind(claim.environment_id).bind(claim.message_id).bind(claim.attempt_id).bind(now)
        .execute(&mut **tx).await?;
    require(updated.rows_affected() == 1)?;
    Ok((
        row.try_get("key_version")?,
        row.try_get("encrypted_payload")?,
    ))
}

/// Retire a definite purpose-authority refusal before any send was admitted.
///
/// The caller must roll back provisional admission, recheck its runtime authority
/// and commit before reporting success. Earlier transport observations remain
/// unchanged: refusing this attempt cannot disprove a previous uncertain send.
///
/// # Errors
/// Refuses stale/expired leases, changed generations, already admitted attempts,
/// storage failures and inconsistent capacity. Roll back on every error.
pub(crate) async fn retire_not_admitted(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    selection: Selection,
    now: i64,
) -> Result<(), RepositoryError> {
    require(now >= 0 && now < claim.lease_until && now < claim.expires_at)?;
    let row = sqlx::query("SELECT id FROM aegaeon.notification_messages WHERE environment_id=$1 AND id=$2 AND state='leased' AND attempt_id=$3 AND worker_id=$4 AND fence=$5 AND lease_until>$6 AND expires_at=$7 AND attempts=$8 AND deployment_id=$9 AND runtime_generation=$10 FOR UPDATE")
        .bind(claim.environment_id).bind(claim.message_id).bind(claim.attempt_id)
        .bind(claim.worker_id).bind(claim.fence).bind(now).bind(claim.expires_at)
        .bind(i16::from(claim.ordinal)).bind(selection.deployment_id()).bind(selection.generation())
        .fetch_optional(&mut **tx).await?;
    require(row.is_some())?;
    let changed = sqlx::query("UPDATE aegaeon.notification_attempts SET completed_at=$4,outcome='not_admitted' WHERE environment_id=$1 AND message_id=$2 AND id=$3 AND admitted_at IS NULL AND completed_at IS NULL AND claimed_at<=$4 AND lease_until>$4")
        .bind(claim.environment_id).bind(claim.message_id).bind(claim.attempt_id).bind(now)
        .execute(&mut **tx).await?;
    require(changed.rows_affected() == 1)?;
    sqlx::query("UPDATE aegaeon.notification_messages SET state='terminal',terminal_reason='authority_changed',terminal_at=$3,encrypted_payload=NULL,attempt_id=NULL,worker_id=NULL,lease_until=NULL WHERE environment_id=$1 AND id=$2")
        .bind(claim.environment_id).bind(claim.message_id).bind(now).execute(&mut **tx).await?;
    release_capacity(tx, claim.environment_id).await
}

/// Persist an observed outcome only for the exact live lease.
///
/// # Errors
/// Refuses late or replaced owners, inconsistent attempt counts and invalid
/// scheduling input. Storage errors require rolling back the transaction.
pub async fn complete(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    completed: super::notification_retry::CompletedAttempt,
    jitter_seconds: u64,
) -> Result<super::notification_retry::RetryPlan, RepositoryError> {
    use super::notification_retry::{plan, RetryPlan, TransportOutcome};
    require(completed.attempts == claim.ordinal)?;
    let now = i64::try_from(completed.observed_at).map_err(|_| AuthorityError::Invalid)?;
    let expiry = u64::try_from(claim.expires_at).map_err(|_| AuthorityError::Invalid)?;
    let plan = plan(completed, expiry, jitter_seconds).map_err(|_| AuthorityError::Invalid)?;
    let outcome = match completed.outcome {
        TransportOutcome::Accepted => "accepted",
        TransportOutcome::Rejected => "rejected",
        TransportOutcome::Retryable => "retryable",
        TransportOutcome::Uncertain => "uncertain",
    };
    let row=sqlx::query("SELECT id FROM aegaeon.notification_messages WHERE environment_id=$1 AND id=$2 AND state='leased' AND attempt_id=$3 AND worker_id=$4 AND fence=$5 AND lease_until>$6 AND expires_at=$7 AND attempts=$8 FOR UPDATE")
        .bind(claim.environment_id).bind(claim.message_id).bind(claim.attempt_id)
        .bind(claim.worker_id).bind(claim.fence).bind(now).bind(claim.expires_at).bind(i16::from(claim.ordinal))
        .fetch_optional(&mut **tx).await?;
    require(row.is_some())?;
    let changed=sqlx::query("UPDATE aegaeon.notification_attempts SET completed_at=$4,outcome=$5 WHERE environment_id=$1 AND message_id=$2 AND id=$3 AND admitted_at IS NOT NULL AND admitted_at<=$4 AND completed_at IS NULL")
        .bind(claim.environment_id).bind(claim.message_id).bind(claim.attempt_id)
        .bind(now).bind(outcome).execute(&mut **tx).await?;
    require(changed.rows_affected() == 1)?;
    match plan {
        RetryPlan::At(at) => {
            let at = i64::try_from(at).map_err(|_| AuthorityError::Invalid)?;
            sqlx::query("UPDATE aegaeon.notification_messages SET state='pending',available_at=$3,last_outcome=$4,attempt_id=NULL,worker_id=NULL,lease_until=NULL WHERE environment_id=$1 AND id=$2")
                .bind(claim.environment_id).bind(claim.message_id).bind(at).bind(outcome)
                .execute(&mut **tx).await?;
        }
        RetryPlan::Stop(reason) => {
            let reason = reason.as_str();
            sqlx::query("UPDATE aegaeon.notification_messages SET state='terminal',terminal_reason=$3,terminal_at=$4,last_outcome=$5,encrypted_payload=NULL,attempt_id=NULL,worker_id=NULL,lease_until=NULL WHERE environment_id=$1 AND id=$2")
                .bind(claim.environment_id).bind(claim.message_id).bind(reason)
                .bind(now).bind(outcome).execute(&mut **tx).await?;
            release_capacity(tx, claim.environment_id).await?;
        }
    }
    Ok(plan)
}

async fn release_capacity(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
) -> Result<(), RepositoryError> {
    let changed=sqlx::query("UPDATE aegaeon.notification_queue_capacity SET active_messages=active_messages-1 WHERE environment_id=$1 AND active_messages>0")
        .bind(environment).execute(&mut **tx).await?;
    require(changed.rows_affected() == 1)?;
    Ok(())
}

/// Retire the active predecessor while its purpose's authorization locks are held.
/// Proof replacement and the successor enqueue must share this transaction.
///
/// # Errors
/// Refuses invalid bounds, storage failures and inconsistent capacity.
pub(crate) async fn supersede(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    purpose: &str,
    object: Uuid,
    now: i64,
) -> Result<Option<Uuid>, RepositoryError> {
    require(!environment.is_nil() && !object.is_nil() && now >= 0)?;
    let row = sqlx::query("SELECT id,attempt_id FROM aegaeon.notification_messages WHERE environment_id=$1 AND purpose=$2 AND object_id=$3 AND state<>'terminal' FOR UPDATE")
        .bind(environment).bind(purpose).bind(object).fetch_optional(&mut **tx).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let id: Uuid = row.try_get("id")?;
    if let Some(attempt) = row.try_get::<Option<Uuid>, _>("attempt_id")? {
        sqlx::query("UPDATE aegaeon.notification_attempts SET completed_at=$3,outcome='uncertain' WHERE environment_id=$1 AND id=$2 AND completed_at IS NULL")
            .bind(environment).bind(attempt).bind(now).execute(&mut **tx).await?;
    }
    sqlx::query("UPDATE aegaeon.notification_messages SET state='terminal',terminal_reason='superseded',terminal_at=$3,encrypted_payload=NULL,last_outcome=CASE WHEN attempt_id IS NULL THEN last_outcome ELSE 'uncertain' END,attempt_id=NULL,worker_id=NULL,lease_until=NULL WHERE environment_id=$1 AND id=$2")
        .bind(environment).bind(id).bind(now).execute(&mut **tx).await?;
    release_capacity(tx, environment).await?;
    Ok(Some(id))
}

#[derive(Default, serde::Serialize)]
pub struct Retirements {
    pub expired: usize,
    pub exhausted: usize,
    pub generation_changed: usize,
}

impl Retirements {
    pub fn total(&self) -> usize {
        self.expired + self.exhausted + self.generation_changed
    }
}

/// Retire a bounded batch of expired, exhausted or old-generation work.
///
/// This never labels a possibly delivered request as rejected. It is independent
/// of active queue capacity and does not renew proofs or delete audit receipts.
///
/// # Errors
/// Refuses invalid bounds and unavailable or inconsistent storage.
pub async fn retire_ineligible(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    selection: Selection,
    limit: i64,
    now: i64,
) -> Result<Retirements, RepositoryError> {
    require(!environment.is_nil() && now >= 0 && (1..=MAX_BATCH).contains(&limit))?;
    let rows=sqlx::query("SELECT id,attempt_id,state,expires_at,deployment_id,runtime_generation FROM aegaeon.notification_messages WHERE environment_id=$1 AND state<>'terminal' AND (deployment_id<>$2 OR runtime_generation<>$3 OR expires_at<=$4 OR (attempts>=$5 AND (lease_until IS NULL OR lease_until<=$4))) ORDER BY expires_at,id LIMIT $6 FOR UPDATE SKIP LOCKED")
        .bind(environment).bind(selection.deployment_id()).bind(selection.generation())
        .bind(now).bind(i16::from(MAX_ATTEMPTS)).bind(limit).fetch_all(&mut **tx).await?;
    let mut retired = Retirements::default();
    for row in &rows {
        let id: Uuid = row.try_get("id")?;
        let attempt: Option<Uuid> = row.try_get("attempt_id")?;
        if let Some(attempt) = attempt {
            sqlx::query("UPDATE aegaeon.notification_attempts SET completed_at=$3,outcome='uncertain' WHERE environment_id=$1 AND id=$2 AND completed_at IS NULL")
                .bind(environment).bind(attempt).bind(now).execute(&mut **tx).await?;
        }
        let reason = if row.try_get::<Uuid, _>("deployment_id")? != selection.deployment_id()
            || row.try_get::<Uuid, _>("runtime_generation")? != selection.generation()
        {
            retired.generation_changed += 1;
            "generation_changed"
        } else if row.try_get::<i64, _>("expires_at")? <= now {
            retired.expired += 1;
            "expired"
        } else {
            retired.exhausted += 1;
            "exhausted"
        };
        sqlx::query("UPDATE aegaeon.notification_messages SET state='terminal',terminal_reason=$3,terminal_at=$4,encrypted_payload=NULL,last_outcome=CASE WHEN attempt_id IS NULL THEN last_outcome ELSE 'uncertain' END,attempt_id=NULL,worker_id=NULL,lease_until=NULL WHERE environment_id=$1 AND id=$2")
            .bind(environment).bind(id).bind(reason).bind(now).execute(&mut **tx).await?;
        release_capacity(tx, environment).await?;
    }
    Ok(retired)
}

/// Remove a bounded number of terminal transport records past their retention.
///
/// This is independent of admission capacity and never deletes proof objects,
/// authorization history, operation receipts, or business audit events.
///
/// # Errors
/// Refuses invalid bounds, unavailable storage and inconsistent retained counts.
pub async fn collect_retained(
    tx: &mut Transaction<'_, Postgres>,
    environment: Uuid,
    limit: i64,
    now: i64,
) -> Result<usize, RepositoryError> {
    require(!environment.is_nil() && now >= 0 && (1..=MAX_BATCH).contains(&limit))?;
    let Some(before) = now.checked_sub(RETENTION_SECONDS).filter(|v| *v >= 0) else {
        return Ok(0);
    };
    let ids: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM aegaeon.notification_messages WHERE environment_id=$1 AND state='terminal' AND terminal_at<=$2 AND expires_at<=$2 ORDER BY terminal_at,expires_at,id LIMIT $3 FOR UPDATE SKIP LOCKED")
        .bind(environment).bind(before).bind(limit).fetch_all(&mut **tx).await?;
    if ids.is_empty() {
        return Ok(0);
    }
    let count = i32::try_from(ids.len()).map_err(|_| AuthorityError::Invalid)?;
    let changed = sqlx::query("DELETE FROM aegaeon.notification_messages WHERE environment_id=$1 AND id=ANY($2) AND state='terminal'")
        .bind(environment).bind(&ids).execute(&mut **tx).await?;
    require(changed.rows_affected() == u64::try_from(count).map_err(|_| AuthorityError::Invalid)?)?;
    let released = sqlx::query("UPDATE aegaeon.notification_queue_capacity SET retained_messages=retained_messages-$2 WHERE environment_id=$1 AND retained_messages-active_messages>=$2")
        .bind(environment).bind(count).execute(&mut **tx).await?;
    require(released.rows_affected() == 1)?;
    Ok(ids.len())
}
