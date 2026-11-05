use super::*;
use crate::runtime_restart::RuntimeRestartRequest;

#[tokio::test]
async fn unavailable_periodic_pass_gets_fresh_work_after_its_result() {
    let restart = RuntimeRestartState::new();
    let mut attempts = 0;
    tokio::time::timeout(
        Duration::from_secs(5),
        run_with_recovery(
            1,
            restart.clone(),
            || {
                attempts += 1;
                let last = attempts == 3;
                let outer_failure = attempts == 1;
                let restart = restart.clone();
                Ok(work::Execution::from_worker(tokio::spawn(async move {
                    if last {
                        restart.request_restart(
                            RuntimeRestartRequest::runtime_authority_unavailable(
                                "periodic-test",
                                "issuer.example",
                                "test_complete",
                            ),
                        );
                        Ok(Ok(()))
                    } else if outer_failure {
                        Err(Error::Deadline)
                    } else {
                        Ok(Err(Error::BackgroundUnavailable))
                    }
                })))
            },
            |error| matches!(error, Error::Deadline | Error::BackgroundUnavailable),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(attempts, 3);
}

#[tokio::test]
async fn periodic_recovery_does_not_mask_permanent_refusal_or_worker_panic() {
    for panic in [false, true] {
        let mut attempts = 0;
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            run_with_recovery(
                1,
                RuntimeRestartState::new(),
                || {
                    attempts += 1;
                    Ok(work::Execution::from_worker(tokio::spawn(async move {
                        assert!(!panic, "injected worker panic");
                        Ok(Err(Error::SelectionRefused))
                    })))
                },
                |error| matches!(error, Error::Deadline | Error::BackgroundUnavailable),
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }
}
