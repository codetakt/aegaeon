//! Finite refusal after restored consumption history; no audit replay or key reset.
use super::*;
use crate::middleware::DpopNonceStore;
use std::sync::Arc;
use tokio::time::Instant;

pub(super) struct Barrier {
    assertions: Instant,
    request_objects: Instant,
    dpop: Instant,
}
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Assertion,
    RequestObject,
}
impl Barrier {
    pub(super) async fn load(pool: &PgPool) -> Result<Self, sqlx::Error> {
        let (assertions,request_objects,dpop):(i64,i64,i64)=sqlx::query_as(
            "SELECT ceil(extract(epoch FROM assertions_after-clock_timestamp())*1000)::bigint,ceil(extract(epoch FROM request_objects_after-clock_timestamp())*1000)::bigint,ceil(extract(epoch FROM dpop_after-clock_timestamp())*1000)::bigint FROM aegaeon_lifecycle.current WHERE singleton")
            .fetch_one(pool).await?;
        let now = Instant::now();
        let deadline = |remaining: i64| {
            // Activation permits 3600+300+4*3600+1 seconds; a later database
            // clock observation can move back by another two absolute bounds.
            if remaining > 25_501_000 {
                return Err(refused());
            }
            now.checked_add(Duration::from_millis(remaining.max(0) as u64))
                .ok_or_else(refused)
        };
        Ok(Self {
            assertions: deadline(assertions)?,
            request_objects: deadline(request_objects)?,
            dpop: deadline(dpop)?,
        })
    }
    fn allows(&self, kind: Kind) -> bool {
        self.allows_at(kind, Instant::now())
    }
    fn allows_at(&self, kind: Kind, now: Instant) -> bool {
        now >= match kind {
            Kind::Assertion => self.assertions,
            Kind::RequestObject => self.request_objects,
        }
    }
}
pub(crate) fn ensure_allowed(kind: Kind) -> Result<(), sqlx::Error> {
    if let Some(owner) = crate::organizations::request_work::async_store::synchronous_owner()? {
        if let Some(runtime) = owner.current_runtime()? {
            if !runtime.proofs.allows(kind) {
                return Err(sqlx::Error::Protocol(
                    "recovery proof acceptance deferred".into(),
                ));
            }
        }
    }
    Ok(())
}
/// A nonce is issued/validated in this generation's current database namespace.
/// This permits DPoP immediately without accepting an old-generation proof.
pub(crate) fn recovery_nonce() -> Result<Option<Arc<DpopNonceStore>>, sqlx::Error> {
    let Some(owner) = crate::organizations::request_work::async_store::task_owner()? else {
        return Ok(None);
    };
    let Some(runtime) = owner.current_runtime()? else {
        return Ok(None);
    };
    if Instant::now() >= runtime.proofs.dpop {
        return Ok(None);
    }
    let environment = owner.epoch_binding()?.environment_id();
    Ok(Some(Arc::new(DpopNonceStore::from_postgres(
        runtime.pool.clone(),
        runtime
            .selection
            .namespace(environment)?
            .replay_namespace("recovery-dpop-nonce"),
        Duration::from_secs(60),
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_barrier_uses_exact_monotonic_boundary() {
        let now = Instant::now();
        let barrier = Barrier {
            assertions: now + Duration::from_secs(11),
            request_objects: now + Duration::from_secs(17),
            dpop: now + Duration::from_secs(7),
        };
        assert!(!barrier.allows_at(Kind::Assertion, now + Duration::from_secs(10)));
        assert!(barrier.allows_at(Kind::Assertion, now + Duration::from_secs(11)));
        assert!(!barrier.allows_at(Kind::RequestObject, now + Duration::from_secs(16)));
        assert!(barrier.allows_at(Kind::RequestObject, now + Duration::from_secs(17)));
    }

    #[test]
    fn proof_horizon_covers_reload_clock_error_and_rejects_two_margin_model() {
        // Diagnostic arithmetic for the SQL policy, not a source refinement proof.
        for error in [0i64, 1, 300, 3600] {
            for window in [1i64, 300, 600, 3600] {
                for leeway in [0i64, 300] {
                    for old_clock in [-error, 0, error] {
                        for new_clock in [-error, 0, error] {
                            for activation_clock in [-error, 0, error] {
                                for reload_clock in [-error, 0, error] {
                                    let old_expiry = old_clock + window;
                                    let earliest_acceptance =
                                        window + leeway + 4 * error + 1 + activation_clock
                                            - reload_clock
                                            + new_clock;
                                    assert!(earliest_acceptance > old_expiry + leeway);
                                }
                            }
                        }
                    }
                }
            }
        }
        let error = 300;
        let old_expiry = error + 3600;
        let unsafe_reopen = 3600 + 300 + 2 * error + 1 - error - error - error;
        assert!(
            unsafe_reopen <= old_expiry + 300,
            "omitting activation/reload clock error must expose early acceptance"
        );
    }
}
