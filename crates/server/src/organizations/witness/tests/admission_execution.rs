use super::*;
use crate::organizations::{request_work, witness::work::Work};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::oneshot;

pub(super) async fn active(f: &Fixture) -> anyhow::Result<(Control, Scope, Selection)> {
    let mut control = f.connect(Role::Maintenance).await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let selected = selection();
    let operation = Uuid::new_v4();
    control.initialize(scope, operation).await?;
    control.prepare(scope, operation, 1, &selected).await?;
    control
        .activate(scope, operation, 2, &selected.acceptance_sha256)
        .await?;
    Ok((control, scope, selected))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; real control connection and blocked acquisition after response loss"]
async fn pg_organizations_owned_admission_survives_unpolled_and_blocked_response_loss() -> TestResult
{
    let mut fixture = Fixture::new().await?;
    let result = retained(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn retained(f: &mut Fixture) -> TestResult {
    let (mut maintenance, scope, selected) = active(f).await?;
    for blocked in [false, true] {
        let mut blocker = f.owner.begin().await?;
        if blocked {
            sqlx::query("SELECT environment_id FROM organization_witness.authorities WHERE environment_id=$1 FOR UPDATE")
                .bind(scope.environment_id).execute(&mut *blocker).await?;
        }
        let local = request_work::Admission::isolated_for_test()?;
        let probe = local.closure_probe_for_test();
        let options = f
            .options
            .clone()
            .username(&f.runtime)
            .password(&f.runtime_password);
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let (entered, started) = oneshot::channel();
        let execution = Work::start(
            local,
            scope,
            selected.clone(),
            async move {
                let connection = PgConnection::connect_with(&options).await?;
                let mut control = Control::checked(connection, Role::Runtime).await?;
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(control.connection.as_mut().ok_or(Error::Refused)?)
                    .await?;
                let _ = entered.send(pid);
                Ok(control)
            },
            async move {
                let owner = request_work::async_store::current_epoch_owner(scope.environment_id);
                if owner.is_ok() {
                    called.fetch_add(1, Ordering::SeqCst);
                }
            },
        );
        if blocked {
            let pid = tokio::time::timeout(Duration::from_secs(5), started).await??;
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND query LIKE '%organization_witness.acquire%')")
                        .bind(pid).fetch_one(&mut f.admin).await?;
                    if waiting { return Ok::<_, sqlx::Error>(()); }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await??;
            anyhow::ensure!(
                calls.load(Ordering::SeqCst) == 0,
                "no store work before admission"
            );
        }
        // Never poll the response handle; the owned operation already started.
        drop(execution);
        blocker.rollback().await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while calls.load(Ordering::SeqCst) != 1
                || maintenance.current(scope).await?.pending != 0
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        anyhow::ensure!(
            !probe.is_closed(),
            "completed detached work must stay usable"
        );
    }
    maintenance.close().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; wrong-role control never starts selected-store work"]
async fn pg_organizations_owned_admission_refuses_wrong_role_before_operation() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = async {
        let (mut maintenance, scope, selected) = active(&fixture).await?;
        let local = request_work::Admission::isolated_for_test()?;
        let probe = local.closure_probe_for_test();
        let options = fixture
            .options
            .clone()
            .username(&fixture.maintenance)
            .password(&fixture.maintenance_password);
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let result = Work::start(
            local,
            scope,
            selected,
            async move {
                let connection = PgConnection::connect_with(&options).await?;
                Control::checked(connection, Role::Maintenance).await
            },
            async move {
                called.fetch_add(1, Ordering::SeqCst);
            },
        )
        .result()
        .await;
        anyhow::ensure!(result.is_err() && calls.load(Ordering::SeqCst) == 0);
        anyhow::ensure!(probe.is_closed());
        anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}
