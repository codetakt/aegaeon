use super::super::deployment::{
    connector::Connector,
    dispatch::{Dispatcher, Environment, Target},
    DeploymentId,
};
use super::super::work::{Execution, Starter};
use super::super::{Scope, Selection};
use super::*;
use axum::http::Method;
use std::{future::Future, sync::Arc};
use uuid::Uuid;

fn configuration() -> (Scope, Selection) {
    (
        Scope {
            environment_id: Uuid::new_v4(),
            deployment_id: Uuid::new_v4(),
        },
        Selection {
            epoch: Uuid::new_v4(),
            primary: Uuid::new_v4(),
            token_store: Uuid::new_v4(),
            source_sha256: "a".repeat(64),
            history_sha256: "b".repeat(64),
            acceptance_sha256: "c".repeat(64),
        },
    )
}

#[test]
fn organization_dispatch_rejects_invalid_and_foreign_selection() {
    let (scope, selected) = configuration();
    assert!(configured(scope, selected.clone()).is_ok());
    let dispatcher = configured(scope, selected.clone()).unwrap();
    assert!(dispatcher
        .environment(Uuid::new_v4(), "https://issuer.example")
        .is_err());
    assert!(dispatcher
        .environment(scope.environment_id, "https://foreign.example")
        .is_err());
    assert!(dispatcher
        .environment(scope.environment_id, "https://issuer.example")
        .is_ok());
    for field in 0..5 {
        let (mut scope, mut selected) = (scope, selected.clone());
        match field {
            0 => scope.environment_id = Uuid::nil(),
            1 => scope.deployment_id = Uuid::nil(),
            2 => selected.epoch = Uuid::nil(),
            3 => selected.primary = Uuid::nil(),
            _ => selected.token_store = Uuid::nil(),
        }
        assert!(configured(scope, selected).is_err());
    }
    for field in 0..3 {
        for value in [
            String::new(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            "é".repeat(32),
        ] {
            let mut selected = selected.clone();
            match field {
                0 => selected.source_sha256 = value,
                1 => selected.history_sha256 = value,
                _ => selected.acceptance_sha256 = value,
            }
            assert!(configured(scope, selected).is_err());
        }
    }
}

#[tokio::test]
async fn organization_dispatch_rejects_nested_and_thread_only_callers() {
    let owner = Admission::isolated_for_test().unwrap();
    owner
        .store_scope(async {
            for class in [
                CapacityClass::Ordinary,
                CapacityClass::Revocation,
                CapacityClass::Snapshot,
            ] {
                assert!(acquire(class).is_err());
            }
        })
        .await
        .unwrap();
    owner
        .blocking(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                assert!(acquire(CapacityClass::Ordinary).is_err());
            });
        })
        .await
        .unwrap();
    assert!(owner.ensure_open().is_ok());
}

#[test]
fn organization_dispatch_requires_current_runtime() {
    assert!(acquire(CapacityClass::Ordinary).is_err());
}

fn configured(scope: Scope, selected: Selection) -> Result<Dispatcher> {
    use super::super::connector::Endpoint;
    let _environment = crate::util::SERVER_TEST_ENV_GUARD.lock().unwrap();
    let path = std::env::temp_dir().join(format!("aegaeon-dispatch-{}.pem", Uuid::new_v4()));
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&path, certificate.serialize_pem().unwrap()).unwrap();
    let endpoint = |url| Endpoint {
        url,
        root_cert: &path,
    };
    let connector = Connector::new(
        endpoint("postgresql://runtime:fixture@control.example/control"),
        endpoint("postgresql://runtime:fixture@primary.example/primary"),
        endpoint("rediss://runtime:fixture@token.example/0"),
    );
    std::fs::remove_file(path).unwrap();
    Dispatcher::new(
        connector?,
        DeploymentId::new(scope.deployment_id)?,
        selected.clone(),
        vec![Environment {
            id: scope.environment_id,
            issuer: "https://issuer.example".into(),
            selection: Selection {
                epoch: Uuid::new_v4(),
                ..selected
            },
        }],
    )
}

#[tokio::test]
async fn organization_dispatch_full_capacity_refuses_before_work() {
    let (scope, selected) = configuration();
    let dispatcher = configured(scope, selected).unwrap();
    let target = Target::Environment(scope.environment_id);
    for class in [
        CapacityClass::Ordinary,
        CapacityClass::Revocation,
        CapacityClass::Snapshot,
    ] {
        let held = crate::organizations::request_work::reserve_class_for_test(class).await;
        assert!(dispatcher
            .start(target, class, || async { panic!("unadmitted operation") })
            .is_err());
        assert!(matches!(
            dispatcher.start_http(target, class, Method::GET, || async {
                panic!("unadmitted HTTP")
            }),
            Err(Error::CapacityExhausted)
        ));
        drop(held);
        // Capacity was not poisoned by rejection; no network or application
        // work is needed to reacquire it after the holder completes.
        assert!(acquire(class).is_ok());
    }
    assert!(dispatcher
        .start(target, CapacityClass::Snapshot, || async {})
        .is_err());
}

// A refused trusted Starter must not even construct caller work. This checks
// shared closure placement; actual role/transport failures have separate DB tests.
struct Refused;
impl Starter for Refused {
    fn start<T, F>(
        self,
        _local: Admission,
        _operation: F,
        _deadline: tokio::time::Instant,
    ) -> Execution<T>
    where
        T: Send + 'static,
        F: Future<Output = T> + Send + 'static,
    {
        Execution::from_worker(tokio::spawn(async { Err(Error::Refused) }))
    }
}

#[tokio::test]
async fn organization_dispatch_refusal_never_constructs_operation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let local = Admission::isolated_for_test().unwrap();
    let called = Arc::new(AtomicBool::new(false));
    let check = called.clone();
    let execution = Refused.dispatch(local, move || {
        check.store(true, Ordering::SeqCst);
        async {}
    });
    assert!(execution.result().await.is_err());
    assert!(!called.load(Ordering::SeqCst));
}
