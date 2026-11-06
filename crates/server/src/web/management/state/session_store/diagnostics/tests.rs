use super::*;
use crate::web::management::state::ManagementSessionStore;

#[test]
fn outage_flapping_shares_failure_and_recovery_budget() {
    let diagnostics = Diagnostics::default();
    let now = Instant::now();
    let first = diagnostics
        .record_at(Operation::Get, true, "first", now)
        .unwrap();
    assert_eq!((first.failures, first.suppressed), (1, 0));
    for seconds in 1..60 {
        assert!(diagnostics
            .record_at(
                Operation::Get,
                seconds % 2 == 0,
                "flap",
                now + Duration::from_secs(seconds)
            )
            .is_none());
    }
    // Last event was a success. Periodic cleanup must report it without a new request.
    let recovered = diagnostics
        .flush_at(Operation::Get, now + INTERVAL)
        .unwrap();
    assert!(!recovered.unavailable);
    assert_eq!(
        (
            recovered.failures,
            recovered.suppressed,
            recovered.recoveries
        ),
        (29, 29, 30)
    );
    assert!(diagnostics
        .record_at(Operation::Get, true, "new-outage", now + INTERVAL)
        .is_none());
    let next = diagnostics
        .flush_at(Operation::Get, now + INTERVAL * 2)
        .unwrap();
    assert!(next.unavailable);
    assert_eq!((next.failures, next.suppressed), (1, 1));
    assert!(diagnostics
        .flush_at(Operation::Get, now + INTERVAL * 3)
        .is_none());
}

#[test]
fn outage_store_clones_count_concurrent_failures_once_and_bound_correlation() {
    let store = ManagementSessionStore::new_process_local_with_limits(60, 16);
    let now = Instant::now();
    assert!(store
        .diagnostics
        .record_at(Operation::Get, true, "first", now)
        .is_some());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let cloned = store.clone();
            scope.spawn(move || {
                for _ in 0..100 {
                    assert!(cloned
                        .diagnostics
                        .record_at(Operation::Get, true, &"\n界".repeat(200), now)
                        .is_none());
                }
            });
        }
    });
    let summary = store
        .diagnostics
        .flush_at(Operation::Get, now + INTERVAL)
        .unwrap();
    assert_eq!((summary.failures, summary.suppressed), (800, 800));
    assert_eq!(summary.first_request.len(), 96);
    assert_eq!(summary.latest_request, "_".repeat(96));
    // Each fixed operation has its own budget, independent of the request ID.
    for op in [Operation::Create, Operation::Delete] {
        assert!(store
            .diagnostics
            .record_at(op, true, "other", now)
            .is_some());
    }
}

#[test]
fn outage_permanent_failure_does_not_claim_recovery() {
    let diagnostics = Diagnostics::default();
    let capture = crate::web::test_support::log_capture::Capture::default();
    let now = Instant::now();
    diagnostics.record_at(Operation::Get, true, "outage", now);
    tracing::subscriber::with_default(capture.subscriber(), || {
        diagnostics.record::<()>(
            Operation::Get,
            "permanent",
            &Err(SessionStoreError::InvalidState),
        );
    });
    assert!(capture.text().contains("permanent storage failure"));
    assert!(diagnostics
        .flush_at(Operation::Get, now + INTERVAL)
        .is_none());
    assert!(diagnostics.operations.lock().unwrap()[0].unavailable);
}

#[tokio::test]
async fn invalid_session_creation_does_not_claim_storage_recovery() {
    let store = ManagementSessionStore::new_process_local_with_limits(60, 16);
    store
        .diagnostics
        .record_at(Operation::Create, true, "outage", Instant::now());
    assert!(store
        .try_create_for_request(uuid::Uuid::new_v4(), u64::MAX, "invalid-lifetime")
        .await
        .unwrap()
        .is_none());
    let operations = store.diagnostics.operations.lock().unwrap();
    assert!(operations[Operation::Create as usize].unavailable);
    assert_eq!(operations[Operation::Create as usize].recoveries, 0);
}
