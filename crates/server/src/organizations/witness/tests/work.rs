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
    // A later witness cannot justify work that already began or was handed
    // to another owner. Each refusal occurs before acquiring a durable slot.
    for mode in 0..4 {
        let local = request_work::Admission::isolated_for_test()?;
        assert!(local.epoch_binding().is_err());
        let retained = if mode == 0 { Some(local.clone()) } else { None };
        match mode {
            1 => {
                assert_eq!(local.blocking(|| 17).await?, 17);
            }
            2 => {
                local.store_scope(async {}).await?;
            }
            3 => {
                let mut connection = local.connection(&pool).await?;
                let value: i32 = sqlx::query_scalar("SELECT 17")
                    .fetch_one(connection.as_mut()?)
                    .await?;
                assert_eq!(value, 17);
                connection.release().await;
            }
            _ => {}
        }
        if retained.is_none() {
            local.wait_for_exclusive_completion().await?;
        }
        let result = Work::begin(f.connect(Role::Runtime).await?, local, scope, &selected).await;
        drop(retained);
        assert!(
            result.is_err(),
            "previous or shared work must not acquire a witness: {mode}"
        );
        assert_eq!(maintenance.current(scope).await?.pending, 0);
    }
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
    assert!(decoded.matches_owner(work.admission()));
    assert!(!decoded.matches_owner(&request_work::Admission::isolated_for_test()?));
    let owner = work.admission().clone();
    let retained_binding = decoded.clone();
    assert!(
        work.blocking(move || retained_binding.matches_owner(&owner))
            .await?
    );
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

    let snapshot = Work::begin(
        f.connect(Role::Runtime).await?,
        request_work::Admission::try_acquire_snapshot()?,
        scope,
        &selected,
    )
    .await?;
    let child = snapshot.admission().current_snapshot_authority()?;
    assert!(snapshot.binding().matches_owner(&child));
    assert!(child.prepare_witness_binding().is_err());
    drop(child);
    assert_eq!(snapshot.complete().await?.pending, 0);

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
    assert!(!failed.binding().matches_owner(failed.admission()));
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
