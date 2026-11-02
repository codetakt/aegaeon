use super::*;
use tokio::sync::Semaphore;

#[tokio::test]
#[ignore = "requires PostgreSQL; actual failed SQLx cleanup with a still-live admitted caller"]
async fn failed_read_cleanup_refuses_the_already_admitted_mutation_and_further_reads() -> TestResult
{
    let db = super::super::super::test_database::Database::create(false).await?;
    let result = async {
        let (stored, client) = fixture(&db.pool).await?;
        let before = snapshot(&db.pool).await?;
        let limit = Arc::new(Semaphore::new(1));
        let permit = Arc::new(limit.clone().try_acquire_owned()?);
        let limited = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_release(|_, _| {
                Box::pin(async { panic!("fixture interrupts actual read cleanup") })
            })
            .connect_lazy_with((*db.pool.connect_options()).clone());
        let refused = credentials::admission::with_test_admission(permit, async {
            let mut connection =
                super::super::super::admitted_connection::AdmittedConnection::acquire(&limited)
                    .await?;
            sqlx::query("SELECT 1")
                .execute(connection.as_mut()?)
                .await?;
            connection.release().await;
            assert!(
                limit.is_closed(),
                "actual failed cleanup must close its admission class"
            );
            let outcome = update_dynamic_registration(
                &db.pool,
                &stored,
                &client,
                &["code".into()],
                "should-not-rotate",
                DcrClientSecretChange::Preserve,
                None,
                "closed-after-read",
            )
            .await;
            let read =
                super::super::super::admitted_connection::AdmittedConnection::acquire(&db.pool)
                    .await;
            // Release any erroneous successful read before assertions so that
            // the negative fixture also leaves no live cleanup worker.
            let read_refused = matches!(read, Err(sqlx::Error::PoolClosed));
            if let Ok(connection) = read {
                connection.release().await;
            }
            Ok::<_, Box<dyn std::error::Error>>((outcome, read_refused))
        })
        .await?;
        limited.close().await;
        assert!(
            matches!(refused.0, Err(DcrDatabaseError::CredentialVerificationBusy)),
            "closed admission must not reuse an earlier permit for mutation"
        );
        assert!(refused.1, "closed admission must refuse further reads");
        assert_eq!(before, snapshot(&db.pool).await?);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
