//! Idle time owns no work. A dispatched finite pass owns its own completion.
use super::*;
use crate::runtime_restart::RuntimeRestartState;
use std::time::Duration;

pub(in crate::organizations::witness) async fn run(
    interval_secs: u64,
    restart: RuntimeRestartState,
    mut start: impl FnMut() -> Result<work::Execution<Result<()>>>,
) -> Result<()> {
    if !crate::config::valid_runtime_sync_interval_secs(interval_secs)
        || async_store::task_owner()?.is_some()
        || tokio::runtime::Handle::try_current().is_err()
    {
        return Err(Error::Refused);
    }
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            biased;
            () = restart.notified() => return Ok(()),
            _ = interval.tick() => {}
        }
        if restart.is_requested() {
            return Ok(());
        }
        // No cancellation select around active work: result follows real cleanup.
        // Dropping this scheduler also leaves Execution's finite worker retained.
        match start() {
            Ok(execution) => execution.result().await??,
            Err(Error::CapacityExhausted) => {
                // No work/operation closure was started. Retry at the next
                // bounded tick; ordinary pressure is not authority loss.
                tracing::warn!(
                    target: "organization_periodic",
                    reason_code = "capacity_exhausted",
                    "Organizations background pass deferred"
                );
            }
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_restart::RuntimeRestartRequest;

    #[tokio::test]
    async fn organization_periodic_retries_capacity_then_completes_work() {
        let restart = RuntimeRestartState::new();
        let mut attempts = 0;
        tokio::time::timeout(
            Duration::from_secs(8),
            run(1, restart.clone(), || {
                attempts += 1;
                if attempts < 3 {
                    return Err(Error::CapacityExhausted);
                }
                let restart = restart.clone();
                Ok(work::Execution::from_worker(tokio::spawn(async move {
                    restart.request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
                        "periodic-test",
                        "issuer.example",
                        "test_complete",
                    ));
                    Ok(Ok(()))
                })))
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn organization_periodic_does_not_retry_closed_or_started_work() {
        for closed in [false, true] {
            let mut attempts = 0;
            let result = tokio::time::timeout(
                Duration::from_secs(4),
                run(1, RuntimeRestartState::new(), || {
                    attempts += 1;
                    if closed {
                        Err(Error::AdmissionClosed)
                    } else {
                        // Only a failure returned by start before execution may
                        // be skipped. The same code inside actual work fails.
                        Ok(work::Execution::from_worker(tokio::spawn(async {
                            Ok(Err(Error::CapacityExhausted))
                        })))
                    }
                }),
            )
            .await
            .unwrap();
            assert!(result.is_err());
            assert_eq!(attempts, 1);
        }
    }

    #[tokio::test]
    async fn organization_periodic_refuses_invalid_intervals_before_dispatch() {
        for value in [0, 3_601, u64::MAX] {
            assert!(run(value, RuntimeRestartState::new(), || panic!(
                "invalid dispatch"
            ))
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn organization_periodic_stopped_idle_never_dispatches() {
        let restart = RuntimeRestartState::new();
        restart.request_restart(RuntimeRestartRequest::runtime_authority_unavailable(
            "periodic-test",
            "issuer.example",
            "periodic",
        ));
        tokio::time::timeout(
            Duration::from_secs(1),
            run(3_600, restart, || panic!("stopped dispatch")),
        )
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn organization_periodic_refuses_nested_scheduler_before_dispatch() {
        let local = Admission::isolated_for_test().unwrap();
        local
            .store_scope(async {
                assert!(
                    run(1, RuntimeRestartState::new(), || panic!("nested dispatch"))
                        .await
                        .is_err()
                );
            })
            .await
            .unwrap();
        assert!(local.ensure_open().is_ok());
    }
}
