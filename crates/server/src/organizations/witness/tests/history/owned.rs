use super::*;
use crate::organizations::request_work::Admission;
use sqlx::Connection;

async fn selected(
    f: &mut Fixture,
    owners: &[(Uuid, Vec<&str>)],
) -> anyhow::Result<(Control, Scope, deployment::Start)> {
    let (parent_control, deployment, parent, scope, child) =
        deployment::with_history(f, owners).await?;
    parent_control.close().await?;
    let starter = deployment::Start::new(f, deployment, parent, scope, child)?;
    Ok((f.connect(Role::Maintenance).await?, scope, starter))
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; live history ownership and primary rollback"]
async fn shared_redis_organizations_owned_history_scope_conflict_and_primary_failure() -> TestResult
{
    let mut fixture = Fixture::new().await?;
    let result = normal(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn normal(f: &mut Fixture) -> TestResult {
    let original = Uuid::nil();
    let (mut maintenance, scope, starter) = selected(f, &[(original, vec!["A"])]).await?;
    let work = starter.begin(Admission::isolated_for_test()?).await?;
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
    // An actual transaction on the selected primary rolls back after reservation.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(
            f.options
                .clone()
                .username(&f.runtime)
                .password(&f.runtime_password),
        )
        .await?;
    let mut primary = work.admission().connection(&pool).await?;
    let mut tx = primary.begin().await?;
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
    anyhow::ensure!(super::super::observed_work::parent_pending(f, scope).await? == 0);
    let fenced = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    let page = maintenance
        .history_read(scope, fenced.operation_id, fenced.revision, 0, 256)
        .await?;
    anyhow::ensure!(page.progress.sequence == 4 && page.entries[3].owner_id == new_owner);
    maintenance.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; history SQL outlives a cancelled response waiter"]
async fn shared_redis_organizations_owned_history_cancel_retains_completion() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = interrupted(&mut fixture, false).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; fatal history transport retains pending admission"]
async fn shared_redis_organizations_owned_history_fatal_refuses_completion() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = interrupted(&mut fixture, true).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn interrupted(f: &mut Fixture, fatal: bool) -> TestResult {
    let (mut maintenance, scope, starter) = selected(f, &[]).await?;
    let local = Admission::isolated_for_test()?;
    let closure = local.closure_probe_for_test();
    let work = starter.begin(local).await?;
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
        anyhow::ensure!(super::super::observed_work::parent_pending(f, scope).await? == 1);
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
        anyhow::ensure!(super::super::observed_work::parent_pending(f, scope).await? == 0);
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
#[ignore = "requires PostgreSQL and Redis; finite history queue and normal maximum occupancy"]
async fn shared_redis_organizations_owned_history_capacity_recovers() -> TestResult {
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
    let (maintenance, scope, starter) = selected(f, &[]).await?;
    let work = starter.begin(Admission::isolated_for_test()?).await?;
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
    anyhow::ensure!(super::super::observed_work::parent_pending(f, scope).await? == 0);
    maintenance.close().await?;
    Ok(())
}
