use super::*;
use crate::organizations::{request_work, witness::work::Work};

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; real primary cleanup and separate control database"]
async fn pg_organizations_witness_work_retains_cancelled_primary_cleanup() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = exercise_work(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn exercise_work(f: &mut Fixture) -> TestResult {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let mut observer = PgConnection::connect_with(&pool.connect_options()).await?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let operation = Uuid::new_v4();
    let selected = selection();
    maintenance.initialize(scope, operation).await?;
    maintenance.prepare(scope, operation, 1, &selected).await?;
    maintenance
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        request_work::Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    assert_eq!(work.epoch(), selected.epoch);
    let encoded = serde_json::to_value(work.binding())?;
    let decoded: super::super::epoch::EpochBinding = serde_json::from_value(encoded.clone())?;
    assert!(decoded.matches_admission(&work));
    for field in [
        "environment_id",
        "deployment_id",
        "epoch",
        "primary_id",
        "token_store_id",
    ] {
        let mut wrong = encoded.clone();
        wrong[field] = serde_json::json!(Uuid::new_v4());
        let wrong: super::super::epoch::EpochBinding = serde_json::from_value(wrong)?;
        assert!(
            !wrong.matches_admission(&work),
            "a different {field} cannot match live work"
        );
        let mut missing = encoded.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<super::super::epoch::EpochBinding>(missing).is_err());
        let mut nil = encoded.clone();
        nil[field] = serde_json::json!(Uuid::nil());
        assert!(serde_json::from_value::<super::super::epoch::EpochBinding>(nil).is_err());
    }
    let mut unknown = encoded.clone();
    unknown["version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<super::super::epoch::EpochBinding>(unknown).is_err());
    let mut extra = encoded;
    extra["administrator_bypass"] = serde_json::json!(true);
    assert!(serde_json::from_value::<super::super::epoch::EpochBinding>(extra).is_err());

    let mut connection = work.admission().connection(&pool).await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(connection.as_mut()?)
        .await?;
    let caller = tokio::spawn(async move {
        let result = sqlx::query("SELECT pg_sleep(2)")
            .execute(connection.as_mut()?)
            .await;
        connection.release().await;
        result
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let active: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')",
            )
            .bind(pid)
            .fetch_one(&mut observer)
            .await?;
            if active {
                break Ok::<(), sqlx::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let completing = tokio::spawn(work.complete());
    let pending = maintenance.current(scope).await?.pending;
    let premature = completing.is_finished();
    caller.abort();
    let _ = caller.await;
    let completed = tokio::time::timeout(Duration::from_secs(5), completing).await???;
    assert_eq!(
        pending, 1,
        "durable pending work must cover actual primary work"
    );
    assert!(
        !premature,
        "completion must wait for the retained primary owner"
    );
    assert_eq!(completed.pending, 0);
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event='PgSleep')",
    )
    .bind(pid)
    .fetch_one(&mut observer)
    .await?;
    assert!(!active, "server work must finish before durable completion");

    // A failed completion and a dropped coordinator cannot be converted into
    // successful drain. No test-only recovery permission enters production.
    let failed = Work::begin(
        f.connect(Role::Runtime).await?,
        request_work::Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    failed.admission().close_until_restart();
    assert!(!failed.binding().matches_admission(&failed));
    assert!(failed.complete().await.is_err());
    assert_eq!(maintenance.current(scope).await?.pending, 1);
    let abandoned = Work::begin(
        f.connect(Role::Runtime).await?,
        request_work::Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    drop(abandoned);
    assert_eq!(maintenance.current(scope).await?.pending, 2);
    let fenced = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    assert!(!fenced.is_drained_fence());
    assert!(maintenance
        .prepare(scope, fenced.operation_id, fenced.revision, &selection())
        .await
        .is_err());
    maintenance.close().await?;
    observer.close().await?;
    tokio::time::timeout(Duration::from_secs(3), pool.close()).await?;
    Ok(())
}
