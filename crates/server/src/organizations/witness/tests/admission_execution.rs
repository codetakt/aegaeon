use super::*;
use crate::organizations::{request_work, witness::work::Starter};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

pub(super) async fn active(f: &mut Fixture) -> anyhow::Result<(Control, Scope, deployment::Start)> {
    let (parent_control, deployment, parent, scope, child) = deployment::setup(f).await?;
    parent_control.close().await?;
    let starter = deployment::Start::new(f, deployment, parent, scope, child)?;
    Ok((f.connect(Role::Maintenance).await?, scope, starter))
}

pub(super) async fn parent_pending(f: &Fixture, scope: Scope) -> anyhow::Result<u32> {
    let mut control = deployment::connect(f, Role::Maintenance).await?;
    let state = control
        .current(crate::organizations::witness::deployment::DeploymentId::new(scope.deployment_id)?)
        .await?;
    control.close().await?;
    Ok(state.pending)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; real control connection and blocked acquisition after response loss"]
async fn shared_redis_organizations_owned_admission_survives_unpolled_and_blocked_response_loss(
) -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = retained(&mut fixture).await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

async fn retained(f: &mut Fixture) -> TestResult {
    let (mut maintenance, scope, starter) = active(f).await?;
    for blocked in [false, true] {
        let mut blocker = f.owner.begin().await?;
        if blocked {
            sqlx::query("SELECT slot FROM organization_witness.slots WHERE environment_id=$1 AND slot=0 FOR UPDATE")
                .bind(scope.environment_id).execute(&mut *blocker).await?;
        }
        let local = request_work::Admission::isolated_for_test()?;
        let probe = local.closure_probe_for_test();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let execution = starter.clone().dispatch(local, move || async move {
            let owner = request_work::async_store::current_epoch_owner(scope.environment_id);
            if owner.is_ok() {
                called.fetch_add(1, Ordering::SeqCst);
            }
        });
        if blocked {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%organization_witness.deployment_acquire_child%')")
                        .bind(&f.runtime).fetch_one(&mut f.admin).await?;
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
                || parent_pending(f, scope).await? != 0
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
#[ignore = "requires PostgreSQL and Redis; wrong-role control never starts selected-store work"]
async fn shared_redis_organizations_owned_admission_refuses_wrong_role_before_operation(
) -> TestResult {
    let mut fixture = Fixture::new().await?;
    let result = async {
        let (mut maintenance, scope, starter) = active(&mut fixture).await?;
        let local = request_work::Admission::isolated_for_test()?;
        let probe = local.closure_probe_for_test();
        let calls = Arc::new(AtomicUsize::new(0));
        let called = calls.clone();
        let control = deployment::connect(&fixture, Role::Maintenance).await?;
        let result = starter
            .start_with_control(local, control, async move {
                called.fetch_add(1, Ordering::SeqCst);
            })
            .result()
            .await;
        anyhow::ensure!(result.is_err() && calls.load(Ordering::SeqCst) == 0);
        anyhow::ensure!(
            probe.is_closed(),
            "wrong-role acquisition closes capacity and cannot clear its parent"
        );
        anyhow::ensure!(parent_pending(&fixture, scope).await? == 1);
        anyhow::ensure!(maintenance.current(scope).await?.pending == 0);
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}
