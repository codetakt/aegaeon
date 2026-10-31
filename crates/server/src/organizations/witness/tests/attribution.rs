use super::{caller_fixture::CallerFixture, *};
use crate::organizations::request_work;
use sqlx::postgres::PgPoolOptions;

mod lost_reply;
mod permissions;

#[tokio::test]
#[ignore = "requires PostgreSQL; server work attribution and exact pool name restoration"]
async fn pg_organizations_store_label_primary_return() -> TestResult {
    let witness = CallerFixture::new(Uuid::new_v4()).await?;
    let options: PgConnectOptions = std::env::var("AEGAEON_DATABASE_URL")?.parse()?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.application_name("existing-名前"))
        .await?;
    let result: TestResult = async {
        let mut observer = PgConnection::connect_with(&pool.connect_options()).await?;
        let original: String = sqlx::query_scalar("SHOW application_name")
            .fetch_one(&pool)
            .await?;
        anyhow::ensure!(
            !original.is_empty(),
            "original fixture name must be nonempty"
        );
        let mut last = None;
        for _ in 0..2 {
            let work = witness.begin().await?;
            let label = work
                .admission()
                .store_label()?
                .ok_or_else(|| anyhow::anyhow!("missing work attribution"))?
                .to_owned();
            let pending = witness.pending_work().await?;
            anyhow::ensure!(
                pending.admissions.len() == 1 && pending.admissions[0].store_label == label,
                "pending attribution mismatch"
            );
            let mut connection = work.admission().connection(&pool).await?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(connection.as_mut()?)
                .await?;
            let actual: String =
                sqlx::query_scalar("SELECT application_name FROM pg_stat_activity WHERE pid=$1")
                    .bind(pid)
                    .fetch_one(&mut observer)
                    .await?;
            anyhow::ensure!(
                actual == label,
                "primary backend must name the actual witness work"
            );
            anyhow::ensure!(
                last.as_ref() != Some(&label),
                "successive work labels must differ"
            );
            last = Some(label);
            connection.release().await;
            anyhow::ensure!(
                work.complete().await?.pending == 0,
                "completed primary remains pending"
            );
            let restored: String = sqlx::query_scalar("SHOW application_name")
                .fetch_one(&pool)
                .await?;
            anyhow::ensure!(
                restored == original,
                "return must preserve the exact original name"
            );
        }
        observer.close().await?;
        Ok(())
    }
    .await;
    pool.close().await;
    let cleanup = witness.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; cancelled statement retains its actual work attribution"]
async fn pg_organizations_store_label_cancelled_primary() -> TestResult {
    let witness = CallerFixture::new(Uuid::new_v4()).await?;
    let options: PgConnectOptions = std::env::var("AEGAEON_DATABASE_URL")?.parse()?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.application_name(""))
        .await?;
    let result: TestResult = async {
        let mut observer = PgConnection::connect_with(&pool.connect_options()).await?;
        let work = witness.begin().await?;
        let label = work.admission().store_label()?.ok_or_else(|| anyhow::anyhow!("missing work attribution"))?.to_owned();
        let mut connection = work.admission().connection(&pool).await?;
        let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(connection.as_mut()?).await?;
        let caller = tokio::spawn(async move {
            sqlx::query("SELECT pg_sleep(0.3)").execute(connection.as_mut()?).await
        });
        let reached = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let row: (String, bool) = sqlx::query_as("SELECT application_name,COALESCE(wait_event='PgSleep',false) FROM pg_stat_activity WHERE pid=$1")
                    .bind(pid).fetch_one(&mut observer).await?;
                if row.1 { return Ok::<String,sqlx::Error>(row.0); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
        caller.abort();let _=caller.await;
        let name = reached??;
        let completion = work.complete().await?;
        anyhow::ensure!(name==label,"cancelled primary work must remain identifiable");
        anyhow::ensure!(completion.pending==0,"completed cancellation remains pending");
        let restored: String = sqlx::query_scalar("SHOW application_name").fetch_one(&pool).await?;
        anyhow::ensure!(restored.is_empty(),"original empty application name must be restored");
        observer.close().await?;
        Ok(())
    }.await;
    pool.close().await;
    let cleanup = witness.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; real Redis connection matches pending work"]
async fn shared_redis_organizations_store_label_matches_pending_work() -> TestResult {
    let witness = CallerFixture::new(Uuid::new_v4()).await?;
    let client = redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?;
    let result: TestResult = async {
        let work = witness.begin().await?;
        let label = witness
            .pending_work()
            .await?
            .admissions
            .remove(0)
            .store_label;
        let selected = client.clone();
        let actual: Option<String> = work
            .blocking(move || -> redis::RedisResult<_> {
                let mut connection = crate::redis_io::connect(&selected)?;
                redis::cmd("CLIENT").arg("GETNAME").query(&mut connection)
            })
            .await??;
        anyhow::ensure!(
            work.complete().await?.pending == 0,
            "completed Redis remains pending"
        );
        anyhow::ensure!(
            actual.as_deref() == Some(label.as_str()),
            "Redis must name actual witness work before commands"
        );
        let ordinary =
            tokio::task::spawn_blocking(move || -> redis::RedisResult<Option<String>> {
                let mut connection = crate::redis_io::connect(&client)?;
                redis::cmd("CLIENT").arg("GETNAME").query(&mut connection)
            })
            .await??;
        anyhow::ensure!(
            ordinary.is_none(),
            "ordinary connections must keep their original name"
        );
        let local = request_work::Admission::isolated_for_test()?;
        anyhow::ensure!(
            local.store_label()?.is_none(),
            "local capacity cannot invent a witness identity"
        );
        Ok(())
    }
    .await;
    let cleanup = witness.finish().await;
    result.and(cleanup)
}
