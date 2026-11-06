use super::*;

#[tokio::test]
async fn organization_preflight_read_only_cancellation_does_not_poison_capacity() {
    cancellation(false).await;
}

#[tokio::test]
async fn organization_preflight_mutating_cancellation_preserves_fence() {
    cancellation(true).await;
}

async fn cancellation(mutating: bool) {
    let local = Admission::isolated_for_test().unwrap();
    let retained = local.clone();
    let (started, waiting) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let mut guard = PreflightCapacity {
            local: &retained,
            attempt: Default::default(),
        };
        if mutating {
            assert!(guard.attempt.begin_mutation());
        }
        started.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(guard);
    });
    waiting.await.unwrap();
    worker.abort();
    assert!(worker.await.unwrap_err().is_cancelled());
    assert_eq!(local.ensure_open().is_err(), mutating);
}

#[test]
fn organization_preflight_confirmed_cleanup_releases_mutation_guard() {
    let local = Admission::isolated_for_test().unwrap();
    let mut guard = PreflightCapacity {
        local: &local,
        attempt: Default::default(),
    };
    assert!(guard.attempt.begin_mutation());
    guard.attempt.finish();
    drop(guard);
    assert!(local.ensure_open().is_ok());
}

#[tokio::test]
async fn organization_preflight_connection_refusal_allows_next_attempt() {
    let _environment = crate::util::SERVER_TEST_ENV_GUARD.lock().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let ca = std::env::temp_dir().join(format!("aegaeon-preflight-{}.pem", Uuid::new_v4()));
    std::fs::write(&ca, certificate.serialize_pem().unwrap()).unwrap();
    // Select a closed local port. Any refusal is bounded by the production
    // connector's timeout and occurs before database mutations.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let pg = format!("postgresql://runtime:fixture@localhost:{port}/unused");
    let redis = format!("rediss://runtime:fixture@localhost:{port}/0");
    let endpoint = |url| Endpoint {
        url,
        root_cert: &ca,
    };
    let connector = Connector::new(endpoint(&pg), endpoint(&pg), endpoint(&redis)).unwrap();
    let local = Admission::isolated_for_test().unwrap();
    let deployment = DeploymentId(Uuid::new_v4());
    let selected = Selection {
        epoch: Uuid::new_v4(),
        primary: Uuid::new_v4(),
        token_store: Uuid::new_v4(),
        source_sha256: "a".repeat(64),
        history_sha256: "b".repeat(64),
        acceptance_sha256: "c".repeat(64),
    };
    for _ in 0..2 {
        assert!(connector
            .parent(local.clone(), deployment, &selected)
            .await
            .is_err());
        assert!(local.ensure_open().is_ok());
    }
    std::fs::remove_file(ca).unwrap();
}
