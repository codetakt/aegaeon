use super::*;
use crate::web::test_support::log_capture::Capture;

#[test]
#[ignore = "requires PostgreSQL; real SQLx notices and owned transaction cleanup"]
fn pg_organizations_cleanup_has_no_idle_rollback_notices() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.subscriber(), || {
        runtime.block_on(async {
        let pool = pool(PgPoolOptions::new()).await?;
        // Positive control: a real idle ROLLBACK must reach this exact capture.
        let mut raw = pool.acquire().await?;
        sqlx::Executor::execute(&mut *raw, "ROLLBACK").await?;
        raw.return_to_pool().await;
        assert!(capture.text().contains("there is no transaction in progress"));
        capture.clear();
        let limit = Arc::new(Semaphore::new(1));
        for _ in 0..5 {
            for outcome in 0..5 {
                let owner = Admission::from_limit(&limit)?;
                let mut connection = owner.connection(&pool).await?;
                drop(owner);
                sqlx::query("SELECT 1").execute(connection.as_mut()?).await?;
                if outcome > 0 {
                    let mut tx = connection.begin().await?;
                    sqlx::query("SELECT pg_advisory_xact_lock(71290305)").execute(&mut *tx).await?;
                    match outcome {
                        1 => tx.commit().await?,
                        2 => tx.rollback().await?,
                        3 => drop(tx),
                        _ => {
                            assert!(sqlx::query("SELECT 1/0").execute(&mut *tx).await.is_err());
                            drop(tx);
                        }
                    }
                }
                connection.release().await;
                assert!(!limit.is_closed());
                assert_eq!(limit.available_permits(), 1);
                let mut returned = pool.acquire().await?;
                let clean: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory')")
                    .fetch_one(&mut *returned).await?;
                assert!(clean, "transaction locks survived pool return");
                returned.return_to_pool().await;
            }
            // The legacy/unscoped wrapper has the same cleanup implementation.
            let mut connection = crate::dcr_persistence::admitted_connection::AdmittedConnection::acquire(&pool).await?;
            sqlx::query("SELECT 1").execute(connection.as_mut()?).await?;
            connection.release().await;
        }
        pool.close().await;
        assert!(!capture.text().contains("there is no transaction in progress"), "{}", capture.text());
        Ok(())
    })
    })
}
