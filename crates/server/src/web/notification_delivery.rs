//! One bounded claim/admission/send/completion cycle for the durable worker.
use super::{organization_authority, AppState};
use crate::organizations::{
    invitations::{self, durable, transport},
    lifecycle::Selection,
    notification_envelope::PrivateKeyRing,
    notification_outbox as queue,
    notification_retry::{self, CompletedAttempt, TransportOutcome},
    request_work::{async_store, Admission, AdmittedConnection},
    Scope,
};
use crate::runtime_configuration::RuntimeAuthorityRevision;
use std::time::Duration;
use uuid::Uuid;

#[derive(Default, serde::Serialize)]
pub(crate) struct Tick {
    pub retired: queue::Retirements,
    pub collected: usize,
    pub claimed: bool,
    pub outcome: Option<&'static str>,
    pub retry_status: Option<&'static str>,
    pub statistics: queue::Statistics,
}

impl AppState {
    pub(crate) async fn process_notification(
        &self,
        worker: Uuid,
        ring: &PrivateKeyRing,
        credential: &transport::Credential,
        trust: &transport::trust::Trust,
    ) -> Result<Tick, ()> {
        tokio::time::timeout(
            Duration::from_secs(40),
            execute(self, worker, ring, credential, trust),
        )
        .await
        .map_err(|_| refused("cycle_deadline"))?
    }
}

fn now() -> Result<i64, ()> {
    crate::util::now_unix_epoch_secs()
        .ok()
        .and_then(|v| i64::try_from(v).ok())
        .ok_or(())
}

async fn execute(
    state: &AppState,
    worker: Uuid,
    ring: &PrivateKeyRing,
    credential: &transport::Credential,
    trust: &transport::trust::Trust,
) -> Result<Tick, ()> {
    state
        .require_subject_namespace()
        .map_err(|_| refused("namespace"))?;
    let owner =
        async_store::current_epoch_owner(state.environment_id).map_err(|_| refused("owner"))?;
    let selection = owner
        .epoch_binding()
        .map_err(|_| refused("epoch"))?
        .runtime_selection()
        .map_err(|_| refused("generation"))?;
    let expected = organization_authority::projection(state).map_err(|_| refused("projection"))?;
    let mut connection = owner
        .connection(&state.db_pool)
        .await
        .map_err(|_| refused("connection"))?;
    let (mut tick, claim) = claim_current(
        state,
        &owner,
        selection,
        &expected,
        &mut connection,
        worker,
        &credential.digest(),
    )
    .await?;
    let Some(claim) = claim else {
        connection.release().await;
        return Ok(tick);
    };
    tick.claimed = true;
    // This event counts committed claims, including attempts whose later
    // admission or completion fails. Fixed labels contain no object identity.
    tracing::info!(target: "notification_worker", event="notification_attempt_claimed",
        ordinal=claim.ordinal, recovered_lease=claim.recovered_lease);
    let permitted = admit_current(
        state,
        &owner,
        selection,
        &expected,
        &mut connection,
        &claim,
        credential,
    )
    .await?;
    state
        .require_subject_namespace()
        .map_err(|_| refused("send_namespace"))?;
    let at = now()?;
    // Reserve the fractional second omitted by the integer SQL deadline.
    let remaining = permitted
        .lease_until
        .checked_sub(at)
        .and_then(|n| n.checked_sub(1))
        .filter(|n| *n > 0)
        .ok_or(())?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(remaining as u64);
    let plaintext = permitted.open(ring, at).map_err(|_| refused("open"))?;
    let client =
        transport::client(&permitted.endpoint, trust).map_err(|_| refused("transport_client"))?;
    let observed = transport::durable::send(
        &client,
        &permitted.endpoint,
        claim.message_id,
        plaintext,
        credential,
        deadline.saturating_duration_since(tokio::time::Instant::now()),
    )
    .await;
    let completed = CompletedAttempt {
        attempts: claim.ordinal,
        observed_at: now()? as u64,
        outcome: observed.outcome,
        retry_after: observed.retry_after,
    };
    // HTTP observation is separate from the subsequently committed outcome.
    tracing::info!(target: "notification_worker", event="notification_transport_observed",
        outcome=outcome_name(observed.outcome));
    let limit =
        notification_retry::jitter_limit(claim.ordinal).map_err(|_| refused("retry_plan"))?;
    let mut bytes = [0u8; 8];
    aegaeon_crypto::rand::fill_random(&mut bytes).map_err(|_| refused("retry_entropy"))?;
    let jitter = u64::from_le_bytes(bytes) % (limit + 1);
    let mut tx = connection
        .begin()
        .await
        .map_err(|_| refused("completion_begin"))?;
    let plan = queue::complete(&mut tx, &claim, completed, jitter)
        .await
        .map_err(|_| refused("completion"))?;
    owner
        .admit_commit()
        .map_err(|_| refused("completion_admission"))?;
    tx.commit()
        .await
        .map_err(|_| refused("completion_commit"))?;
    connection.release().await;
    tick.outcome = Some(outcome_name(observed.outcome));
    tick.retry_status = Some(match plan {
        notification_retry::RetryPlan::At(_) => "scheduled",
        notification_retry::RetryPlan::Stop(reason) => reason.as_str(),
    });
    Ok(tick)
}

async fn claim_current(
    state: &AppState,
    owner: &Admission,
    selection: Selection,
    expected: &RuntimeAuthorityRevision,
    connection: &mut AdmittedConnection,
    worker: Uuid,
    credential_digest: &str,
) -> Result<(Tick, Option<queue::Claim>), ()> {
    let mut tx = connection
        .begin()
        .await
        .map_err(|_| refused("claim_begin"))?;
    let at = now()?;
    let tick = Tick {
        retired: queue::retire_ineligible(
            &mut tx,
            state.environment_id,
            selection,
            queue::MAX_BATCH,
            at,
        )
        .await
        .map_err(|_| refused("retire"))?,
        collected: queue::collect_retained(&mut tx, state.environment_id, queue::MAX_BATCH, at)
            .await
            .map_err(|_| refused("collect"))?,
        statistics: queue::statistics(&mut tx, state.environment_id, at)
            .await
            .map_err(|_| refused("statistics"))?,
        ..Tick::default()
    };
    // Claim one immediately before processing it; a serial batch must not let
    // leases expire behind earlier network requests.
    let mut claims = queue::claim_delivery(
        &mut tx,
        state.environment_id,
        selection,
        worker,
        credential_digest,
        1,
        at,
    )
    .await
    .map_err(|_| refused("claim"))?;
    organization_authority::recheck_projection(state, &mut tx, expected)
        .await
        .map_err(|_| refused("claim_projection"))?;
    owner
        .admit_commit()
        .map_err(|_| refused("claim_admission"))?;
    tx.commit().await.map_err(|_| refused("claim_commit"))?;
    Ok((tick, claims.pop()))
}

async fn admit_current(
    state: &AppState,
    owner: &Admission,
    selection: Selection,
    expected: &RuntimeAuthorityRevision,
    connection: &mut AdmittedConnection,
    claim: &queue::Claim,
    credential: &transport::Credential,
) -> Result<durable::Authorized, ()> {
    let scope = Scope {
        environment_id: state.environment_id,
        domain_id: claim.domain_id.ok_or(())?,
    };
    let runtime = invitations::delegated::Runtime {
        store: &state.tokens.store,
        admission: owner,
        issuer: &state.issuer,
    };
    let mut tx = connection
        .begin()
        .await
        .map_err(|_| refused("send_begin"))?;
    let permitted: durable::Authorized = durable::admit_current(
        &mut tx,
        scope,
        claim,
        selection,
        &credential.digest(),
        now()?,
        Some(&runtime),
    )
    .await
    .map_err(|_| refused("purpose_admission"))?;
    organization_authority::recheck_projection(state, &mut tx, expected)
        .await
        .map_err(|_| refused("send_projection"))?;
    invitations::recheck(
        &mut tx,
        scope,
        claim.parent_id.unwrap_or(claim.object_id),
        now()?,
        &runtime,
    )
    .await
    .map_err(|_| refused("purpose_recheck"))?;
    owner
        .admit_commit()
        .map_err(|_| refused("send_admission"))?;
    // A failed/lost commit reply never releases the secret or begins HTTP.
    // The persisted finite lease/backoff governs later reconciliation/reclaim.
    tx.commit().await.map_err(|_| refused("send_commit"))?;
    Ok(permitted)
}

fn outcome_name(outcome: TransportOutcome) -> &'static str {
    match outcome {
        TransportOutcome::Accepted => "accepted",
        TransportOutcome::Rejected => "rejected",
        TransportOutcome::Retryable => "retryable",
        TransportOutcome::Uncertain => "uncertain",
    }
}

fn refused(stage: &'static str) {
    tracing::warn!(target: "notification_worker", event="notification_cycle_refused", stage);
}
