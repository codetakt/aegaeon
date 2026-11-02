use super::*;
use tokio::sync::Semaphore;

fn runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

#[test]
#[ignore = "requires PostgreSQL; actual admitted connection cleanup interrupted by runtime shutdown"]
fn admitted_read_runtime_shutdown_does_not_reschedule_cleanup_or_reopen_admission() -> TestResult {
    for drop_outside in [false, true] {
        let worker = runtime()?;
        let limit = Arc::new(Semaphore::new(1));
        let (pool, outstanding) = worker.block_on(async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
                .await?;
            let permit = Arc::new(limit.clone().try_acquire_owned()?);
            let connection =
                admission::with_test_admission(permit, AdmittedConnection::acquire(&pool)).await?;
            assert!(limit.clone().try_acquire_owned().is_err());
            let outstanding = if drop_outside {
                Some(connection)
            } else {
                drop(connection);
                None
            };
            Ok::<_, Box<dyn std::error::Error>>((pool, outstanding))
        })?;
        drop(worker);
        drop(outstanding);
        assert!(
            limit.is_closed(),
            "unconfirmed cleanup closes its admission class"
        );
        assert!(limit.clone().try_acquire_owned().is_err());
        runtime()?
            .block_on(async { tokio::time::timeout(Duration::from_secs(3), pool.close()).await })?;
    }
    Ok(())
}

#[test]
#[ignore = "requires PostgreSQL; actual SQLx read checkout hook interrupted by runtime shutdown"]
fn admitted_read_runtime_shutdown_during_checkout_closes_admission() -> TestResult {
    let worker = runtime()?;
    let limit = Arc::new(Semaphore::new(1));
    let (entered, observed) = oneshot::channel();
    let gate = Arc::new(Mutex::new(Some(entered)));
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
            .connect_lazy(&std::env::var("AEGAEON_DATABASE_URL")?)?;
        let permit = Arc::new(limit.clone().try_acquire_owned()?);
        let owned_pool = pool.clone();
        tokio::spawn(admission::with_test_admission(permit, async move {
            AdmittedConnection::acquire(&owned_pool).await
        }));
        tokio::time::timeout(Duration::from_secs(3), observed).await??;
        assert!(limit.clone().try_acquire_owned().is_err());
        Ok::<_, Box<dyn std::error::Error>>(pool)
    })?;
    drop(worker);
    assert!(
        limit.is_closed(),
        "interrupted SQLx setup cannot replenish admission"
    );
    runtime()?
        .block_on(async { tokio::time::timeout(Duration::from_secs(3), pool.close()).await })?;
    Ok(())
}
