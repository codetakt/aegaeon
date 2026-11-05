use super::*;
mod finalization;
mod start;
use crate::organizations::{
    request_work,
    witness::deployment::{work::Work, DeploymentControl, DeploymentId},
};
use sqlx::postgres::PgPoolOptions;
pub(super) use start::Start;
use std::sync::Arc;

pub(super) async fn connect(f: &Fixture, role: Role) -> Result<DeploymentControl> {
    let (user, password) = match role {
        Role::Runtime => (&f.runtime, &f.runtime_password),
        Role::Maintenance => (&f.maintenance, &f.maintenance_password),
    };
    let connection =
        PgConnection::connect_with(&f.options.clone().username(user).password(password)).await?;
    DeploymentControl::checked(connection, role).await
}

type Prepared = (DeploymentControl, DeploymentId, Selection, Scope, Selection);

pub(super) async fn setup(f: &mut Fixture) -> anyhow::Result<Prepared> {
    setup_with_owners(f, None).await
}

pub(super) async fn with_history(
    f: &mut Fixture,
    owners: &[(Uuid, Vec<&str>)],
) -> anyhow::Result<Prepared> {
    setup_with_owners(f, Some(owners)).await
}

async fn setup_with_owners(
    f: &mut Fixture,
    owners: Option<&[(Uuid, Vec<&str>)]>,
) -> anyhow::Result<Prepared> {
    let mut maintenance = connect(f, Role::Maintenance).await?;
    let deployment = DeploymentId::new(Uuid::new_v4())?;
    let selected = selection();
    let operation = Uuid::new_v4();
    maintenance.initialize(deployment, operation).await?;
    maintenance
        .prepare(deployment, operation, 1, &selected)
        .await?;
    store_supplier::control(f, deployment.uuid()).await?;
    let (mut primary, mut token) = store_progress::links(f, 0).await?;
    maintenance
        .pin_store_progress(deployment, operation, 2, &mut primary, &mut token)
        .await?;
    maintenance
        .activate(deployment, operation, 2, &selected.acceptance_sha256)
        .await?;
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: deployment.uuid(),
    };
    let plan = owners
        .map(|owners| history::plan(scope, owners))
        .transpose()?;
    let child = Selection {
        epoch: Uuid::new_v4(),
        history_sha256: plan
            .as_ref()
            .map_or_else(|| selected.history_sha256.clone(), |plan| plan.digest()),
        ..selected.clone()
    };
    let environment = maintenance.environment_maintenance()?;
    let operation = if let Some(plan) = &plan {
        history::enrolled(environment, scope, plan).await?
    } else {
        let operation = Uuid::new_v4();
        environment.initialize(scope, operation).await?;
        operation
    };
    environment.prepare(scope, operation, 1, &child).await?;
    environment
        .pin_store_progress(scope, operation, 2, &mut primary, &mut token)
        .await?;
    maintenance
        .bind_child(
            deployment,
            selected.epoch,
            scope.environment_id,
            child.epoch,
        )
        .await?;
    maintenance
        .environment_maintenance()?
        .activate(scope, operation, 2, &child.acceptance_sha256)
        .await?;
    primary.close().await?;
    token.close();
    Ok((maintenance, deployment, selected, scope, child))
}

pub(super) async fn begin(
    f: &mut Fixture,
    deployment: DeploymentId,
    selected: &Selection,
) -> Result<Work> {
    let control = connect(f, Role::Runtime).await?;
    Work::begin(
        control,
        request_work::Admission::isolated_for_test()?,
        deployment,
        selected,
        || async {
            store_progress::links(f, 0)
                .await
                .map_err(|_| Error::Refused)
        },
    )
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; real parent/child observations and retained cleanup"]
async fn shared_redis_organizations_deployment_waits_for_child_and_observed_cleanup() -> TestResult
{
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, deployment, selected, scope, child_selection) = setup(&mut f).await?;
        let parent = begin(&mut f, deployment, &selected).await?;
        anyhow::ensure!(
            parent.admission().epoch_binding().is_err(),
            "deployment became an Environment capability"
        );
        let child_control = connect(&f, Role::Runtime).await?;
        let child = parent
            .child(
                child_control,
                scope.environment_id,
                &child_selection,
                || async {
                    store_progress::links(&mut f, 0)
                        .await
                        .map_err(|_| Error::Refused)
                },
            )
            .await?;
        anyhow::ensure!(!parent.admission().same_work(child.admission()));
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(
                f.options
                    .clone()
                    .username(&f.runtime)
                    .password(&f.runtime_password),
            )
            .await?;
        let mut connection = child.admission().connection(&pool).await?;
        let value: i32 = sqlx::query_scalar("SELECT 42")
            .fetch_one(connection.as_mut()?)
            .await?;
        anyhow::ensure!(value == 42);
        let closure_probe = parent.admission().closure_probe_for_test();
        let mut completing = tokio::spawn(parent.complete());
        anyhow::ensure!(
            tokio::time::timeout(Duration::from_millis(30), &mut completing)
                .await
                .is_err(),
            "parent completed while child owned data work"
        );
        connection.release().await;
        let state = child.complete().await?;
        anyhow::ensure!(state.pending == 0);
        let state = completing.await??;
        anyhow::ensure!(state.pending == 0);
        anyhow::ensure!(
            !closure_probe.is_closed(),
            "successful completion closed admission"
        );
        anyhow::ensure!(closure_probe.available_permits() == 1);
        anyhow::ensure!(maintenance.pending(deployment).await?.state.pending == 0);
        pool.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; actual wrong primary closes parent and child"]
async fn shared_redis_organizations_deployment_confusion_retains_both_pending() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, deployment, selected, scope, child_selection) = setup(&mut f).await?;
        let parent = begin(&mut f, deployment, &selected).await?;
        let child_control = connect(&f, Role::Runtime).await?;
        let child = parent
            .child(
                child_control,
                scope.environment_id,
                &child_selection,
                || async {
                    store_progress::links(&mut f, 0)
                        .await
                        .map_err(|_| Error::Refused)
                },
            )
            .await?;
        let other = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(f.options.clone().database("postgres"))
            .await?;
        parent.admission().ensure_open()?;
        child.admission().ensure_open()?;
        let refused = child.admission().connection(&other).await;
        anyhow::ensure!(
            matches!(refused, Err(sqlx::Error::Protocol(ref message))
            if message.contains("actual store observation refused")),
            "wrong database must fail its actual observation"
        );
        anyhow::ensure!(child.complete().await.is_err());
        anyhow::ensure!(parent.complete().await.is_err());
        anyhow::ensure!(maintenance.pending(deployment).await?.state.pending == 1);
        anyhow::ensure!(
            maintenance
                .environment_maintenance()?
                .pending(scope)
                .await?
                .state
                .pending
                == 1
        );
        other.close().await;
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis; confirmed child refusal does not strand its parent"]
async fn shared_redis_organizations_deployment_fenced_child_allows_parent_cleanup() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = async {
        let (mut maintenance, deployment, selected, scope, child_selection) = setup(&mut f).await?;
        let parent = begin(&mut f, deployment, &selected).await?;
        maintenance
            .environment_maintenance()?
            .fence(scope, Uuid::new_v4(), 3)
            .await?;
        let control = connect(&f, Role::Runtime).await?;
        let opened = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let probe = opened.clone();
        let refused = parent
            .child(
                control,
                scope.environment_id,
                &child_selection,
                || async move {
                    probe.store(true, std::sync::atomic::Ordering::SeqCst);
                    Err(Error::Refused)
                },
            )
            .await;
        anyhow::ensure!(refused.is_err());
        anyhow::ensure!(
            !opened.load(std::sync::atomic::Ordering::SeqCst),
            "selected stores opened after child refusal"
        );
        parent.admission().ensure_open()?;
        anyhow::ensure!(parent.complete().await?.pending == 0);
        anyhow::ensure!(
            maintenance
                .environment_maintenance()?
                .pending(scope)
                .await?
                .state
                .pending
                == 0
        );
        maintenance.close().await?;
        Ok(())
    }
    .await;
    let cleanup = f.finish().await;
    result.and(cleanup)
}
