use super::caller_fixture::CallerFixture;
use crate::organizations::{repository_tests::Fixture, request_work::async_store};
use std::time::Duration;
use tokio::sync::oneshot;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual finite operation deadline and retained pending slot"]
async fn pg_organizations_owned_operation_deadline_does_not_complete_unfinished_work(
) -> crate::web::test_support::TestResult {
    let witness = CallerFixture::new(uuid::Uuid::new_v4()).await?;
    let result = async {
        let work = witness.begin().await?;
        let result = tokio::time::timeout(
            Duration::from_secs(40),
            work.execute(std::future::pending::<()>()),
        )
        .await?;
        assert!(matches!(
            result,
            Err(crate::organizations::witness::Error::Deadline)
        ));
        assert_eq!(witness.pending().await?, 1, "timeout is not completion");
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual SQL completion after response-waiter cancellation"]
async fn pg_organizations_owned_operation_completes_after_response_waiter_disconnects(
) -> crate::web::test_support::TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = exercise(&f, &witness).await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { error.into() });
    f.cleanup(result.and(cleanup)).await
}

async fn exercise(f: &Fixture, witness: &CallerFixture) -> crate::web::test_support::TestResult {
    let work = witness.begin().await?;
    assert_eq!(work.execute(async { 17 }).await?, 17);
    assert_eq!(witness.pending().await?, 0);

    let work = witness.begin().await?;
    let pool = f.pool.clone();
    let environment = f.env.environment_id;
    let (entered, started) = oneshot::channel();
    let waiter = tokio::spawn(work.execute(async move {
        let owner = async_store::current_epoch_owner(environment)?;
        let mut connection = owner.connection(&pool).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(connection.as_mut()?)
            .await?;
        let _ = entered.send(pid);
        sqlx::query("SELECT pg_sleep(1)")
            .execute(connection.as_mut()?)
            .await?;
        owner.admit_commit()?;
        sqlx::query("INSERT INTO aegaeon.authorization_consents
            (environment_id,issuer,subject,session_sha256,token_sha256,authorize_uri,request_snapshot,expires_at)
            VALUES ($1,'https://op.example','owned-completion','session','owned-token','/authorize','{}',statement_timestamp()+interval '1 minute')")
            .bind(environment)
            .execute(connection.as_mut()?)
            .await?;
        connection.release().await;
        Ok::<_, sqlx::Error>(())
    }));
    let pid = tokio::time::timeout(Duration::from_secs(5), started).await??;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let sleeping: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')",
            )
            .bind(pid)
            .fetch_one(&f.pool)
            .await?;
            if sleeping {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await??;
    assert_eq!(witness.pending().await?, 1);
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    let finished = tokio::time::timeout(Duration::from_secs(5), async {
        while witness.pending().await? != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM aegaeon.authorization_consents
        WHERE environment_id=$1 AND subject='owned-completion'",
    )
    .bind(environment)
    .fetch_one(&f.pool)
    .await?;
    assert!(
        finished.is_ok(),
        "response cancellation must not abandon owned execution"
    );
    finished??;
    assert_eq!(count, 1, "actual operation must finish exactly once");
    Ok(())
}
