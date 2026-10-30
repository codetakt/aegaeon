use super::*;
use tokio::sync::Semaphore;

#[test]
#[ignore = "requires PostgreSQL CREATEDB; actual mutation checkout interrupted by runtime shutdown"]
fn admitted_update_runtime_shutdown_during_checkout_closes_admission_without_mutation() -> TestResult
{
    let controller = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let db = controller.block_on(super::super::super::test_database::Database::create(false))?;
    let result = (|| {
        let (stored, client) = controller.block_on(fixture(&db.pool))?;
        let before = controller.block_on(snapshot(&db.pool))?;
        let limit = Arc::new(Semaphore::new(1));
        let (entered, observed) = oneshot::channel();
        let gate = Arc::new(Mutex::new(Some(entered)));
        let worker = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let pool = worker.block_on(async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .after_connect(move |_, _| {
                    let entered = gate.lock().expect("setup gate").take();
                    Box::pin(async move {
                        if let Some(entered) = entered {
                            let _ = entered.send(());
                            std::future::pending::<()>().await;
                        }
                        Ok(())
                    })
                })
                .connect_lazy_with((*db.pool.connect_options()).clone());
            let permit = Arc::new(limit.clone().try_acquire_owned()?);
            let owned_pool = pool.clone();
            tokio::spawn(credentials::admission::with_test_admission(
                permit,
                async move {
                    update_dynamic_registration(
                        &owned_pool,
                        &stored,
                        &client,
                        &["code".into()],
                        "shutdown-replacement-token",
                        DcrClientSecretChange::Preserve,
                        Some("cleanup-test-credential"),
                        "shutdown-update",
                    )
                    .await
                },
            ));
            tokio::time::timeout(Duration::from_secs(3), observed).await??;
            Ok::<_, Box<dyn std::error::Error>>(pool)
        })?;
        drop(worker);
        assert!(
            limit.is_closed(),
            "interrupted mutation checkout cannot replenish admission"
        );
        controller.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), pool.close()).await?;
            assert_eq!(before, snapshot(&db.pool).await?);
            Ok::<(), Box<dyn std::error::Error>>(())
        })?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })();
    let cleanup = controller.block_on(db.cleanup());
    result?;
    cleanup?;
    Ok(())
}
