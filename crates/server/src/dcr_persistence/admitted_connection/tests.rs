use super::*;
use crate::dcr_persistence::{admit_http_update, credentials::admission, test_database::Database};
use crate::web::test_support::{sample_registered_client, setup_test_environment, TestResult};
use std::{sync::Mutex, time::Duration};
use tokio::sync::oneshot;

async fn cancelled_read(pool: &PgPool, authority: bool) -> TestResult {
    let env = setup_test_environment(pool).await?;
    let client = sample_registered_client("cancelled-read");
    crate::dcr_persistence::create_dynamic_registration(
        pool,
        &env.issuer_host,
        &client,
        &["code".into()],
        "read-owner-token",
        "read-create",
    )
    .await?;
    let (entered, observed) = oneshot::channel();
    let (release, wait) = oneshot::channel();
    let gate = Arc::new(Mutex::new(Some((entered, wait))));
    let limited = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let gate = gate.lock().expect("gate").take();
            Box::pin(async move {
                if let Some((entered, wait)) = gate {
                    let _ = entered.send(());
                    let _ = tokio::time::timeout(Duration::from_secs(15), wait).await;
                }
                Ok(true)
            })
        })
        .connect_lazy_with((*pool.connect_options()).clone());
    let other = admission::for_persistence(true)?.ok_or("other admission")?;
    let mut blocker = pool.begin().await?;
    sqlx::query("LOCK TABLE aegaeon.clients IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let query_pool = limited.clone();
    let caller = tokio::spawn(async move {
        admit_http_update(async {
            if authority {
                crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
                    &query_pool, &env.issuer_host).await.map(|_| ()).map_err(|e| e.to_string())
            } else {
                crate::dcr_persistence::load_dynamic_registration_by_token(
                    &query_pool, &env.issuer_host, &client.client_id, "read-owner-token")
                    .await.map(|_| ()).map_err(|e| e.to_string())
            }
        }).await
    });
    let result = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE relation='aegaeon.clients'::regclass AND NOT granted)").fetch_one(pool).await?;
                if waiting { break Ok::<(),sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.map_err(|_| "lock wait was not observed")??;
        caller.abort();
        assert!(caller.await.expect_err("cancelled caller").is_cancelled());
        assert!(admission::for_persistence(true).is_err(), "in-flight read owns admission");
        // Keep the lock held: the server statement deadline must end the query.
        tokio::time::timeout(Duration::from_secs(12), observed).await.map_err(|_| "server deadline did not reach pool return")??;
        assert!(admission::for_persistence(true).is_err(), "pool return still owns admission");
        release.send(()).map_err(|()| "release")?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(permit) = admission::for_persistence(true) { drop(permit); break; }
                tokio::task::yield_now().await;
            }
        }).await?;
        let setting: String = sqlx::query_scalar("SHOW statement_timeout").fetch_one(&limited).await?;
        assert_eq!(setting, "0", "request timeout must not leak into the pool");
        Ok::<(), Box<dyn std::error::Error>>(())
    }.await;
    blocker.rollback().await?;
    limited.close().await;
    drop(other);
    result
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; cancelled owner authentication with held table lock"]
async fn cancelled_authentication_read_keeps_admission_until_deadline_and_pool_return() -> TestResult
{
    let db = Database::create(false).await?;
    let result = cancelled_read(&db.pool, false).await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; cancelled runtime admission with held table lock"]
async fn cancelled_authority_read_keeps_admission_until_deadline_and_pool_return() -> TestResult {
    let db = Database::create(false).await?;
    let result = cancelled_read(&db.pool, true).await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; scoped timeout preserves stricter operator configuration"]
async fn admitted_reads_preserve_stricter_timeout_and_restore_settings() -> TestResult {
    let db = Database::create(false).await?;
    let limited = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*db.pool.connect_options()).clone())
        .await?;
    let result = async {
        sqlx::query("SET statement_timeout='200ms'")
            .execute(&limited)
            .await?;
        admit_http_update(async {
            let mut connection = AdmittedConnection::acquire(&limited).await?;
            let timeout: String = sqlx::query_scalar("SHOW statement_timeout")
                .fetch_one(connection.as_mut())
                .await?;
            assert_eq!(timeout, "200ms");
            let error = sqlx::query("SELECT pg_sleep(1)")
                .execute(connection.as_mut())
                .await
                .expect_err("operator deadline");
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("57014")
            );
            connection.release().await;
            Ok::<(), sqlx::Error>(())
        })
        .await??;
        let restored: String = sqlx::query_scalar("SHOW statement_timeout")
            .fetch_one(&limited)
            .await?;
        assert_eq!(restored, "200ms");
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    limited.close().await;
    let cleanup = db.cleanup().await;
    result?;
    cleanup?;
    Ok(())
}
