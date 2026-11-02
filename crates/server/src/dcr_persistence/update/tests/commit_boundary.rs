use super::*;
use std::{
    collections::BTreeMap,
    sync::{mpsc, LazyLock},
};
use tokio::sync::Semaphore;

struct Gate {
    entered: oneshot::Sender<()>,
    release: mpsc::Receiver<()>,
}
static GATES: LazyLock<Mutex<BTreeMap<(String, bool), Gate>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(in crate::dcr_persistence::update) fn at_commit_boundary(request_id: &str, admitted: bool) {
    let gate = GATES
        .lock()
        .expect("commit gates")
        .remove(&(request_id.to_owned(), admitted));
    if let Some(gate) = gate {
        let _ = gate.entered.send(());
        gate.release
            .recv_timeout(Duration::from_secs(5))
            .expect("bounded commit gate");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires PostgreSQL; actual closure between preliminary check and commit admission"]
async fn cleanup_closure_and_commit_admission_have_one_ordering_boundary() -> TestResult {
    for already_admitted in [false, true] {
        let db = super::super::super::test_database::Database::create(false).await?;
        let result = async {
            let (stored, client) = fixture(&db.pool).await?;
            let before = snapshot(&db.pool).await?;
            let limit = Arc::new(Semaphore::new(1));
            let permit = Arc::new(limit.clone().try_acquire_owned()?);
            let closing = permit.clone();
            let request_id = uuid::Uuid::new_v4().to_string();
            let (entered, observed) = oneshot::channel();
            let (release, wait) = mpsc::channel();
            GATES.lock().expect("commit gates").insert(
                (request_id.clone(), already_admitted),
                Gate {
                    entered,
                    release: wait,
                },
            );
            let pool = db.pool.clone();
            let caller = tokio::spawn(credentials::admission::with_test_admission(
                permit,
                async move {
                    update_dynamic_registration(
                        &pool,
                        &stored,
                        &client,
                        &["code".into()],
                        "replacement-owner-token",
                        DcrClientSecretChange::Preserve,
                        None,
                        &request_id,
                    )
                    .await
                },
            ));
            tokio::time::timeout(Duration::from_secs(5), observed).await??;
            // Use the exact production cleanup transition, while the actual
            // transaction is paused on the chosen side of commit admission.
            credentials::admission::close(Some(&closing));
            assert!(limit.is_closed());
            release.send(())?;
            let outcome = tokio::time::timeout(Duration::from_secs(5), caller).await??;
            if already_admitted {
                outcome?;
                assert_ne!(
                    before,
                    snapshot(&db.pool).await?,
                    "admitted commit may finish"
                );
            } else {
                assert!(
                    matches!(outcome, Err(DcrDatabaseError::CredentialVerificationBusy)),
                    "closure winning after the preliminary check must refuse commit"
                );
                assert_eq!(before, snapshot(&db.pool).await?, "all effects roll back");
            }
            Ok::<(), Box<dyn std::error::Error>>(())
        }
        .await;
        let cleanup = db.cleanup().await;
        result?;
        cleanup?;
    }
    Ok(())
}
