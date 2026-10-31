//! Enrollment mail uses the same scoped transport and finite attempt budget.
use super::super::worker::Outcome;
use super::*;
use crate::organizations::operators::mutations::delivery::{self as configuration, Channel};

pub(crate) struct Claim {
    pub scope: Scope,
    pub invitation: Uuid,
    pub object: Uuid,
    pub revision: i64,
    hash: [u8; 32],
    at: i64,
    configuration_revision: i64,
    channel: Channel,
    org: Organization,
    actor: AuditActor,
}
impl Claim {
    pub(crate) fn endpoint(&self) -> &str {
        &self.channel.endpoint
    }
}

pub(crate) async fn claim(
    tx: &mut Transaction<'_, Postgres>,
    scope: Scope,
    invitation: Uuid,
    id: Uuid,
    credential_digest: &str,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<Option<(Claim, Delivery)>, RepositoryError> {
    let pending = pending(tx, scope, invitation, id, now, runtime).await?;
    let configuration = configuration::read_locked(tx, scope).await?;
    let channel = configuration.channel.ok_or(AuthorityError::Forbidden)?;
    require(channel.credential_sha256 == credential_digest)?;
    if pending.result.is_some()
        || matches!(pending.outcome.as_str(), "acknowledged" | "rejected")
        || pending.revision >= MAX_DELIVERIES
        || pending.delivered_at.is_some_and(|at| {
            now.checked_sub(at)
                .is_none_or(|age| age < DELIVERY_INTERVAL_SECONDS)
        })
    {
        return Ok(None);
    }
    require(matches!(
        pending.outcome.as_str(),
        "unclaimed" | "uncertain"
    ))?;
    let revision =
        super::super::delivery::next_attempt(pending.revision, pending.delivered_at, now)?;
    let (capability, hash) =
        super::super::delivery::generate(scope, id, revision, pending.purpose.capability())?;
    sqlx::query("UPDATE aegaeon.organization_identity_requests SET delivery_revision=$2,delivered_at=$3,capability_hash=$4,delivery_outcome='uncertain' WHERE id=$1")
        .bind(id).bind(revision).bind(now).bind(hash.as_slice()).execute(&mut **tx).await?;
    let actor = audit::delivery(&pending.invitation, id, revision, now)?;
    repo::event(tx,&pending.org,&actor,"organization.identity_delivery_claimed",
        serde_json::json!({"invitation_id":invitation,"request_id":id,"delivery_revision":revision,"configurationRevision":configuration.revision,
            "before":{"deliveryRevision":pending.revision},"after":{"deliveryRevision":revision}})).await?;
    Ok(Some((
        Claim {
            scope,
            invitation,
            object: id,
            revision,
            hash,
            at: now,
            configuration_revision: configuration.revision,
            channel,
            org: pending.org,
            actor,
        },
        Delivery {
            recipient: pending.invitation.recipient,
            object_id: id,
            purpose: pending.purpose.capability(),
            capability,
            expires_at: pending.expires,
            hash,
        },
    )))
}

pub(crate) async fn admit_send(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    now: i64,
    runtime: Option<&delegated::Runtime<'_>>,
) -> Result<(), RepositoryError> {
    let pending = pending(
        tx,
        claim.scope,
        claim.invitation,
        claim.object,
        now,
        runtime,
    )
    .await?;
    require(
        pending.result.is_none()
            && matches_claim(&pending, claim)
            && now
                .checked_sub(claim.at)
                .is_some_and(|age| (0..30).contains(&age)),
    )?;
    let configuration = configuration::read_locked(tx, claim.scope).await?;
    require(
        configuration.revision == claim.configuration_revision
            && configuration.channel.as_ref() == Some(&claim.channel),
    )?;
    Ok(())
}

fn matches_claim(pending: &Pending, claim: &Claim) -> bool {
    pending.revision == claim.revision
        && pending.delivered_at == Some(claim.at)
        && pending.outcome == "uncertain"
        && pending.hash.as_deref() == Some(claim.hash.as_slice())
}

pub(crate) async fn complete(
    tx: &mut Transaction<'_, Postgres>,
    claim: &Claim,
    outcome: Outcome,
) -> Result<bool, RepositoryError> {
    // A late transport result cannot alter identity authority; only the exact
    // durable attempt is completed, even after invitation/policy revocation.
    lock(tx, claim.scope).await?;
    sqlx::query(
        "SELECT id FROM aegaeon.authorization_domains WHERE environment_id=$1 AND id=$2 FOR UPDATE",
    )
    .bind(claim.scope.environment_id)
    .bind(claim.scope.domain_id)
    .fetch_one(&mut **tx)
    .await?;
    let outcome = match outcome {
        Outcome::Uncertain => "uncertain",
        Outcome::Acknowledged => "acknowledged",
        Outcome::Rejected => "rejected",
    };
    let changed = sqlx::query("UPDATE aegaeon.organization_identity_requests SET delivery_outcome=$7 WHERE environment_id=$1 AND domain_id=$2 AND id=$3 AND delivery_revision=$4 AND delivered_at=$5 AND capability_hash=$6 AND delivery_outcome='uncertain'")
        .bind(claim.scope.environment_id).bind(claim.scope.domain_id).bind(claim.object).bind(claim.revision).bind(claim.at).bind(claim.hash.as_slice()).bind(outcome).execute(&mut **tx).await?.rows_affected() == 1;
    if changed && outcome != "uncertain" {
        repo::event(tx,&claim.org,&claim.actor,"organization.identity_transport_result",
            serde_json::json!({"invitation_id":claim.invitation,"request_id":claim.object,"delivery_revision":claim.revision,"outcome":outcome,"configurationRevision":claim.configuration_revision,
                "before":{"deliveryRevision":claim.revision,"outcome":"uncertain"},"after":{"deliveryRevision":claim.revision,"outcome":outcome}})).await?;
    }
    Ok(changed)
}
