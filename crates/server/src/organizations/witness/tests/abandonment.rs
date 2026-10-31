use super::*;
use crate::organizations::{request_work, witness::work::Work};

async fn active(f: &Fixture) -> anyhow::Result<(Control, Scope, Selection)> {
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let selected = selection();
    let operation = Uuid::new_v4();
    maintenance.initialize(scope, operation).await?;
    maintenance.prepare(scope, operation, 1, &selected).await?;
    maintenance
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    Ok((maintenance, scope, selected))
}

async fn backend(control: &mut Control) -> anyhow::Result<i32> {
    Ok(sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(
            control
                .connection
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("live control"))?,
        )
        .await?)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; abandoned work and actual control backend termination"]
async fn pg_organizations_witness_abandoned_work_closes_admission() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = abandoned(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn abandoned(f: &mut Fixture) -> TestResult {
    let (mut maintenance, scope, selected) = active(f).await?;
    let local = request_work::Admission::isolated_for_test()?;
    let successful = local.closure_probe_for_test();
    let work = Work::begin(f.connect(Role::Runtime).await?, local, scope, &selected).await?;
    anyhow::ensure!(work.complete().await?.pending == 0);
    let success_open = !successful.is_closed();

    let local = request_work::Admission::isolated_for_test()?;
    let dropped = local.closure_probe_for_test();
    let work = Work::begin(f.connect(Role::Runtime).await?, local, scope, &selected).await?;
    drop(work);
    let after_drop = maintenance.current(scope).await?.pending;

    let local = request_work::Admission::isolated_for_test()?;
    let failed = local.closure_probe_for_test();
    let mut control = f.connect(Role::Runtime).await?;
    let pid = backend(&mut control).await?;
    let work = Work::begin(control, local, scope, &selected).await?;
    let terminated: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(&mut f.admin)
        .await?;
    let completion_failed = work.complete().await.is_err();
    let after_failure = maintenance.current(scope).await?.pending;

    let local = request_work::Admission::isolated_for_test()?;
    let refused = local.closure_probe_for_test();
    let rejected = Work::begin(f.connect(Role::Runtime).await?, local, scope, &selection())
        .await
        .is_err();
    let fenced = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    maintenance.close().await?;
    anyhow::ensure!(
        success_open,
        "successful completion must preserve admission"
    );
    anyhow::ensure!(
        dropped.is_closed(),
        "abandonment must close local admission"
    );
    anyhow::ensure!(terminated && completion_failed);
    anyhow::ensure!(
        failed.is_closed(),
        "failed completion must close local admission"
    );
    anyhow::ensure!(
        rejected && refused.is_closed(),
        "failed acquisition must close local admission"
    );
    anyhow::ensure!(after_drop == 1, "drop cannot release durable work");
    anyhow::ensure!(
        after_failure == 2,
        "failed completion cannot release durable work"
    );
    anyhow::ensure!(fenced.pending == 2);
    anyhow::ensure!(!fenced.is_drained_fence());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; cancellation during actual blocked witness acquisition"]
async fn pg_organizations_witness_cancelled_begin_closes_admission() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = cancelled(&mut fixture, false).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; cancellation during actual blocked durable completion"]
async fn pg_organizations_witness_cancelled_completion_closes_admission() -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = cancelled(&mut fixture, true).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn cancelled(f: &mut Fixture, completion: bool) -> TestResult {
    let (mut maintenance, scope, selected) = active(f).await?;
    let mut control = f.connect(Role::Runtime).await?;
    let pid = backend(&mut control).await?;
    let local = request_work::Admission::isolated_for_test()?;
    let probe = local.closure_probe_for_test();
    let action: std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> =
        if completion {
            let work = Work::begin(control, local, scope, &selected).await?;
            Box::pin(async move { work.complete().await.map(|_| ()) })
        } else {
            Box::pin(async move {
                let _work = Work::begin(control, local, scope, &selected).await?;
                Ok(())
            })
        };
    let mut blocker = f.owner.begin().await?;
    sqlx::query("SELECT environment_id FROM organization_witness.authorities WHERE environment_id=$1 FOR UPDATE")
        .bind(scope.environment_id).execute(&mut *blocker).await?;
    let task = tokio::spawn(action);
    let query = if completion {
        "%organization_witness.release%"
    } else {
        "%organization_witness.acquire%"
    };
    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE $2)",
            ).bind(pid).bind(query).fetch_one(&mut f.admin).await?;
            if waiting { break Ok::<(), sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await;
    task.abort();
    let joined = task.await;
    blocker.rollback().await?;
    // A dropped transport does not establish server completion. Observe the
    // actual backend ending after releasing the independently owned blocker.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let present: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(&mut f.admin)
                    .await?;
            if !present {
                break Ok::<(), sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    let fenced = maintenance.fence(scope, Uuid::new_v4(), 3).await?;
    maintenance.close().await?;
    observed??;
    anyhow::ensure!(joined.is_err_and(|error| error.is_cancelled()));
    anyhow::ensure!(
        probe.is_closed(),
        "cancelled witness operation must close local admission: completion={completion}"
    );
    // Cancellation can race the real SQL commit in either operation. Record
    // its actual result; neither outcome grants a local recovery permission.
    eprintln!(
        "cancelled witness completion={completion}, durable pending={}",
        fenced.pending
    );
    anyhow::ensure!(fenced.pending <= 1);
    Ok(())
}
