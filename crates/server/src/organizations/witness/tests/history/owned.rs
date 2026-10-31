use super::*;
use crate::organizations::{request_work::Admission, witness::work::Work};
use sqlx::Connection;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; live history ownership and primary rollback"]
async fn pg_organizations_owned_history_scope_conflict_and_primary_failure() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = normal(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn normal(f: &mut Fixture) -> TestResult {
    let scope = scope();
    let original = Uuid::nil();
    let plan = plan(scope, &[(original, vec!["A"])])?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let operation = enrolled(&mut maintenance, scope, &plan).await?;
    let selected = activated(&mut maintenance, scope, operation, &plan).await?;
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    let bare = Admission::isolated_for_test()?;
    anyhow::ensure!(bare
        .check_history(scope.environment_id, original, "A")
        .await
        .is_err());
    anyhow::ensure!(work
        .admission()
        .check_history(Uuid::new_v4(), original, "A")
        .await
        .is_err());
    anyhow::ensure!(
        work.admission()
            .check_history(scope.environment_id, original, "A")
            .await?
            .sequence
            == 2
    );
    for subject in [
        "".to_owned(),
        "é".to_owned(),
        "x".repeat(256),
        "a\0b".to_owned(),
    ] {
        anyhow::ensure!(work
            .admission()
            .reserve_history(scope.environment_id, Uuid::new_v4(), &subject)
            .await
            .is_err());
        work.admission().ensure_open()?;
    }
    // A confirmed conflict is a normal failure, not a process-wide availability
    // attack. It must not prevent a subsequent authorized exact reservation.
    anyhow::ensure!(work
        .admission()
        .reserve_history(scope.environment_id, Uuid::new_v4(), "A")
        .await
        .is_err());
    work.admission().ensure_open()?;
    let new_owner = Uuid::new_v4();
    let progress = work
        .admission()
        .reserve_history(scope.environment_id, new_owner, "a")
        .await?;
    anyhow::ensure!(progress.sequence == 4);
    anyhow::ensure!(
        work.admission()
            .reserve_history(scope.environment_id, new_owner, "a")
            .await?
            .sequence
            == 4
    );
    // Actual separate primary transaction fails and rolls back after reservation.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
        .await?;
    let mut primary = work.admission().connection(&pool).await?;
    let mut tx = primary.as_mut()?.begin().await?;
    anyhow::ensure!(sqlx::query("SELECT 1/0").execute(&mut *tx).await.is_err());
    tx.rollback().await?;
    primary.release().await;
    pool.close().await;
    anyhow::ensure!(
        work.admission()
            .check_history(scope.environment_id, new_owner, "a")
            .await?
            .sequence
            == 4
    );
    anyhow::ensure!(work.complete().await?.pending == 0);
    let fenced = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    let page = maintenance
        .history_read(scope, fenced.operation_id, fenced.revision, 0, 256)
        .await?;
    anyhow::ensure!(page.progress.sequence == 4 && page.entries[3].owner_id == new_owner);
    maintenance.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; history SQL outlives a cancelled response waiter"]
async fn pg_organizations_owned_history_cancel_retains_completion() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = interrupted(&mut fixture, false).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; fatal history transport retains pending admission"]
async fn pg_organizations_owned_history_fatal_refuses_completion() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = interrupted(&mut fixture, true).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn interrupted(f: &mut Fixture, fatal: bool) -> TestResult {
    let scope = scope();
    let plan = plan(scope, &[])?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let operation = enrolled(&mut maintenance, scope, &plan).await?;
    let selected = activated(&mut maintenance, scope, operation, &plan).await?;
    let local = Admission::isolated_for_test()?;
    let closure = local.closure_probe_for_test();
    let work = Work::begin(f.connect(Role::Runtime).await?, local, scope, &selected).await?;
    let mut observer = PgConnection::connect_with(&f.options).await?;
    let mut blocker = f.owner.begin().await?;
    sqlx::query("LOCK TABLE organization_witness.history_entries IN SHARE MODE")
        .execute(&mut *blocker)
        .await?;
    let owner = work.admission().clone();
    let identity = Uuid::new_v4();
    let waiter = tokio::spawn(async move {
        owner
            .reserve_history(scope.environment_id, identity, "pending")
            .await
    });
    let pid = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%organization_witness.history_reserve%'")
                .bind(&f.runtime).fetch_optional(&mut observer).await?;
            if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await??;
    if fatal {
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(&mut observer)
            .await?;
        anyhow::ensure!(waiter.await?.is_err());
        anyhow::ensure!(closure.is_closed());
        anyhow::ensure!(work.complete().await.is_err());
        blocker.rollback().await?;
        anyhow::ensure!(maintenance.current(scope).await?.pending == 1);
        let owners: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_witness.history_owners WHERE owner_id=$1",
        )
        .bind(identity)
        .fetch_one(&mut observer)
        .await?;
        anyhow::ensure!(
            owners == 0,
            "failed append must not leave a partial owner insertion"
        );
    } else {
        waiter.abort();
        anyhow::ensure!(waiter.await.unwrap_err().is_cancelled());
        let mut completion = tokio::spawn(work.complete());
        anyhow::ensure!(
            tokio::time::timeout(Duration::from_millis(40), &mut completion)
                .await
                .is_err(),
            "response cancellation released an active history owner"
        );
        blocker.rollback().await?;
        anyhow::ensure!(completion.await??.pending == 0 && !closure.is_closed());
        let fenced = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
        let page = maintenance
            .history_read(scope, fenced.operation_id, fenced.revision, 0, 256)
            .await?;
        anyhow::ensure!(page.progress.sequence == 2 && page.entries[1].owner_id == identity);
    }
    observer.close().await?;
    maintenance.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; finite history queue and normal maximum occupancy"]
async fn pg_organizations_owned_history_capacity_recovers() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = capacity(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn capacity(f: &mut Fixture) -> TestResult {
    use std::{
        future::{poll_fn, Future},
        task::Poll,
    };
    let scope = scope();
    let plan = plan(scope, &[])?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let operation = enrolled(&mut maintenance, scope, &plan).await?;
    let selected = activated(&mut maintenance, scope, operation, &plan).await?;
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        Admission::isolated_for_test()?,
        scope,
        &selected,
    )
    .await?;
    let mut blocker = f.owner.begin().await?;
    sqlx::query("LOCK TABLE organization_witness.history_entries IN SHARE MODE")
        .execute(&mut *blocker)
        .await?;
    let mut workers = Vec::new();
    for subject in ["one", "two", "three", "four"] {
        let mut future = Box::pin(work.admission().reserve_history(
            scope.environment_id,
            Uuid::new_v4(),
            subject,
        ));
        // Poll each actual call through its finite admission and spawn. The
        // store lock prevents completion before all four slots are occupied.
        poll_fn(|cx| {
            assert!(future.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        workers.push(future);
    }
    let refused = tokio::time::timeout(
        Duration::from_millis(100),
        work.admission()
            .reserve_history(scope.environment_id, Uuid::new_v4(), "excess"),
    )
    .await?;
    anyhow::ensure!(matches!(
        refused,
        Err(crate::organizations::witness::Error::Refused)
    ));
    work.admission().ensure_open()?;
    blocker.rollback().await?;
    for worker in workers {
        anyhow::ensure!(worker.await?.sealed);
    }
    anyhow::ensure!(
        work.admission()
            .reserve_history(scope.environment_id, Uuid::new_v4(), "recovered")
            .await?
            .sequence
            == 10
    );
    anyhow::ensure!(work.complete().await?.pending == 0);
    maintenance.close().await?;
    Ok(())
}
