//! One bounded claim/admission/send/completion cycle for the durable worker.
use super::{organization_authority, AppState};
use crate::organizations::{
    invitations::{self, durable, transport},
    lifecycle::Selection,
    notification_envelope::PrivateKeyRing,
    notification_outbox as queue,
    notification_retry::{self, CompletedAttempt, TransportOutcome},
    repository::RepositoryError,
    request_work::{async_store, Admission, AdmittedConnection},
    AuthorityError, Scope,
};
use crate::runtime_configuration::RuntimeAuthorityRevision;
use sqlx::Acquire;
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
        queue::ClaimRoute {
            credential_digest: &credential.digest(),
            ring,
        },
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
    let Some(permitted) = permitted else {
        connection.release().await;
        tick.outcome = Some("not_admitted");
        tick.retry_status = Some("authority_changed");
        return Ok(tick);
    };
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
    let plan = complete_current(&owner, &mut connection, &claim, completed).await?;
    connection.release().await;
    tick.outcome = Some(outcome_name(observed.outcome));
    tick.retry_status = Some(match plan {
        notification_retry::RetryPlan::At(_) => "scheduled",
        notification_retry::RetryPlan::Stop(reason) => reason.as_str(),
    });
    Ok(tick)
}

async fn complete_current(
    owner: &Admission,
    connection: &mut AdmittedConnection,
    claim: &queue::Claim,
    completed: CompletedAttempt,
) -> Result<notification_retry::RetryPlan, ()> {
    let limit =
        notification_retry::jitter_limit(claim.ordinal).map_err(|_| refused("retry_plan"))?;
    let mut bytes = [0u8; 8];
    aegaeon_crypto::rand::fill_random(&mut bytes).map_err(|_| refused("retry_entropy"))?;
    let jitter = u64::from_le_bytes(bytes) % (limit + 1);
    let mut tx = connection
        .begin()
        .await
        .map_err(|_| refused("completion_begin"))?;
    let plan = queue::complete(&mut tx, claim, completed, jitter)
        .await
        .map_err(|_| refused("completion"))?;
    owner
        .admit_commit()
        .map_err(|_| refused("completion_admission"))?;
    tx.commit()
        .await
        .map_err(|_| refused("completion_commit"))?;
    Ok(plan)
}

async fn claim_current(
    state: &AppState,
    owner: &Admission,
    selection: Selection,
    expected: &RuntimeAuthorityRevision,
    connection: &mut AdmittedConnection,
    worker: Uuid,
    route: queue::ClaimRoute<'_>,
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
        route,
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
) -> Result<Option<durable::Authorized>, ()> {
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
    // A final authority recheck may refuse after admit_current writes admitted_at.
    // Roll back that provisional admission before recording a definite refusal.
    // Storage/supplier errors never enter the terminal path.
    let mut validation = tx.begin().await.map_err(|_| refused("send_savepoint"))?;
    let mut permitted = durable::admit_current(
        &mut validation,
        scope,
        claim,
        selection,
        &credential.digest(),
        now()?,
        Some(&runtime),
    )
    .await;
    if permitted.is_ok() {
        organization_authority::recheck_projection(state, &mut validation, expected)
            .await
            .map_err(|_| refused("send_projection"))?;
        if let Err(error) = invitations::recheck(
            &mut validation,
            scope,
            claim.parent_id.unwrap_or(claim.object_id),
            now()?,
            &runtime,
        )
        .await
        {
            permitted = Err(error);
        }
    }
    let permitted = match permitted {
        Ok(permitted) => {
            validation
                .commit()
                .await
                .map_err(|_| refused("send_savepoint_commit"))?;
            Some(permitted)
        }
        Err(error) if authority_refused(&error) => {
            validation
                .rollback()
                .await
                .map_err(|_| refused("send_savepoint_rollback"))?;
            queue::retire_not_admitted(&mut tx, claim, selection, now()?)
                .await
                .map_err(|_| refused("send_retirement"))?;
            None
        }
        Err(_) => {
            refused("purpose_admission");
            return Err(());
        }
    };
    organization_authority::recheck_projection(state, &mut tx, expected)
        .await
        .map_err(|_| refused("send_projection"))?;
    owner
        .admit_commit()
        .map_err(|_| refused("send_admission"))?;
    // A failed/lost commit reply never releases the secret or begins HTTP.
    // The persisted finite lease/backoff governs later reconciliation/reclaim.
    tx.commit().await.map_err(|_| refused("send_commit"))?;
    Ok(permitted)
}

fn authority_refused(error: &RepositoryError) -> bool {
    matches!(
        error,
        RepositoryError::Authority(
            AuthorityError::Invalid
                | AuthorityError::Forbidden
                | AuthorityError::ReauthorizationRequired
                | AuthorityError::Conflict
                | AuthorityError::PreconditionFailed
        )
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_refusal_does_not_retire_supplier_or_decode_failures() {
        for authority in [
            AuthorityError::Invalid,
            AuthorityError::Forbidden,
            AuthorityError::ReauthorizationRequired,
            AuthorityError::Conflict,
            AuthorityError::PreconditionFailed,
        ] {
            assert!(authority_refused(&authority.into()));
        }
        for error in [
            RepositoryError::Unavailable,
            RepositoryError::Storage(sqlx::Error::PoolTimedOut),
            RepositoryError::Decode(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
            AuthorityError::Exhausted.into(),
        ] {
            assert!(!authority_refused(&error));
        }
    }
}
