use super::*;
use crate::organizations::{
    request_work::Admission as Local,
    witness::{
        creation::{Input, Kind, PrimaryOutcome, State as CreationState},
        work::Work,
    },
};

fn input(payload: u8) -> Result<Input> {
    Input::new(
        Kind::ManagementCreate,
        [4; 32],
        [5; 32],
        [payload; 32],
        None,
    )
}

async fn selected(f: &Fixture) -> anyhow::Result<(Scope, Selection)> {
    let scope = Scope {
        environment_id: Uuid::new_v4(),
        deployment_id: Uuid::new_v4(),
    };
    let plan = super::history::plan(scope, &[])?;
    let mut maintenance = f.connect(Role::Maintenance).await?;
    let op = super::history::enrolled(&mut maintenance, scope, &plan).await?;
    let selection = super::history::activated(&mut maintenance, scope, op, &plan).await?;
    maintenance.close().await?;
    Ok((scope, selection))
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; typed creation binding, retry and committed replay with test-only primary outcomes"]
async fn pg_organizations_creation_owned_replay_and_retry() -> TestResult {
    let f = Fixture::new().await?;
    let result = creation_replay(&f).await;
    result.and(f.finish().await)
}

async fn creation_replay(f: &Fixture) -> TestResult {
    let (scope, selection) = selected(f).await?;
    let input = input(6)?;
    anyhow::ensure!(Input::new(Kind::Registration, [0; 32], [1; 32], [2; 32], Some("é")).is_err());
    let bare = Local::isolated_for_test()?;
    anyhow::ensure!(bare
        .prepare_creation(scope.environment_id, &input)
        .await
        .is_err());
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        Local::isolated_for_test()?,
        scope,
        &selection,
    )
    .await?;
    anyhow::ensure!(work
        .admission()
        .prepare_creation(Uuid::new_v4(), &input)
        .await
        .is_err());
    let first = work
        .admission()
        .prepare_creation(scope.environment_id, &input)
        .await?;
    anyhow::ensure!(work
        .admission()
        .lookup_creation(scope.environment_id, Kind::Upstream, [4; 32])
        .await?
        .is_none());
    let observed = work
        .admission()
        .lookup_creation(scope.environment_id, Kind::ManagementCreate, [4; 32])
        .await?
        .ok_or(Error::Refused)?;
    anyhow::ensure!(
        observed.owner_id() == first.owner_id()
            && observed.state() == CreationState::Reserved
            && observed.attempt() == 1
    );
    anyhow::ensure!(
        first.state() == CreationState::Reserved
            && first.attempt() == 1
            && first.subject() == first.owner_id().to_string()
    );
    let repeated = work
        .admission()
        .prepare_creation(scope.environment_id, &input)
        .await?;
    anyhow::ensure!(
        repeated.operation_id() == first.operation_id() && repeated.owner_id() == first.owner_id()
    );
    let conflict = Input::new(Kind::ManagementCreate, [4; 32], [5; 32], [7; 32], None)?;
    anyhow::ensure!(work
        .admission()
        .prepare_creation(scope.environment_id, &conflict)
        .await
        .is_err());
    work.admission().ensure_open()?;
    let retry = work
        .admission()
        .finish_creation(
            scope.environment_id,
            &first,
            &PrimaryOutcome::for_test(&first, None),
        )
        .await?;
    anyhow::ensure!(retry.state() == CreationState::Retryable);
    let observed = work
        .admission()
        .lookup_creation(scope.environment_id, Kind::ManagementCreate, [4; 32])
        .await?
        .ok_or(Error::Refused)?;
    anyhow::ensure!(observed.state() == CreationState::Retryable && observed.attempt() == 1);
    anyhow::ensure!(work.complete().await?.pending == 0);
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        Local::isolated_for_test()?,
        scope,
        &selection,
    )
    .await?;
    let next = work
        .admission()
        .prepare_creation(scope.environment_id, &input)
        .await?;
    anyhow::ensure!(
        next.owner_id() == first.owner_id()
            && next.subject() == first.subject()
            && next.attempt() == 2
    );
    let committed = work
        .admission()
        .finish_creation(
            scope.environment_id,
            &next,
            &PrimaryOutcome::for_test(&next, Some([8; 32])),
        )
        .await?;
    anyhow::ensure!(committed.state() == CreationState::Committed);
    let observed = work
        .admission()
        .lookup_creation(scope.environment_id, Kind::ManagementCreate, [4; 32])
        .await?
        .ok_or(Error::Refused)?;
    anyhow::ensure!(
        observed.state() == CreationState::Committed
            && observed.owner_id() == first.owner_id()
            && observed.attempt() == 2
    );
    anyhow::ensure!(work.complete().await?.pending == 0);
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        Local::isolated_for_test()?,
        scope,
        &selection,
    )
    .await?;
    let replay = work
        .admission()
        .prepare_creation(scope.environment_id, &input)
        .await?;
    anyhow::ensure!(
        replay.state() == CreationState::Committed
            && replay.owner_id() == first.owner_id()
            && replay.attempt() == 2
    );
    anyhow::ensure!(work
        .admission()
        .finish_creation(
            scope.environment_id,
            &replay,
            &PrimaryOutcome::for_test(&replay, None)
        )
        .await
        .is_err());
    anyhow::ensure!(work.complete().await?.pending == 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; unfinished creation cannot release durable work"]
async fn pg_organizations_creation_owned_pending_refuses_completion() -> TestResult {
    let f = Fixture::new().await?;
    let result = async {
        let (scope, selection) = selected(&f).await?;
        let work = Work::begin(
            f.connect(Role::Runtime).await?,
            Local::isolated_for_test()?,
            scope,
            &selection,
        )
        .await?;
        let closure = work.admission().closure_probe_for_test();
        work.admission()
            .prepare_creation(scope.environment_id, &input(6)?)
            .await?;
        anyhow::ensure!(work.complete().await.is_err() && closure.is_closed());
        let mut control = f.connect(Role::Runtime).await?;
        anyhow::ensure!(control.current(scope).await?.pending == 1);
        control.close().await?;
        Ok(())
    }
    .await;
    result.and(f.finish().await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; cancelled creation waiter retains SQL and reserved work"]
async fn pg_organizations_creation_owned_cancel_retains_pending() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = interrupted(&mut f, false).await;
    result.and(f.finish().await)
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; fatal creation transport closes local work and retains pending"]
async fn pg_organizations_creation_owned_fatal_retains_pending() -> TestResult {
    let mut f = Fixture::new().await?;
    let result = interrupted(&mut f, true).await;
    result.and(f.finish().await)
}

async fn interrupted(f: &mut Fixture, fatal: bool) -> TestResult {
    let (scope, selection) = selected(f).await?;
    let work = Work::begin(
        f.connect(Role::Runtime).await?,
        Local::isolated_for_test()?,
        scope,
        &selection,
    )
    .await?;
    let closure = work.admission().closure_probe_for_test();
    let mut observer = PgConnection::connect_with(&f.options).await?;
    let mut barrier = f.owner.begin().await?;
    sqlx::query("LOCK TABLE organization_witness.creation_counts IN SHARE MODE")
        .execute(&mut *barrier)
        .await?;
    let owner = work.admission().clone();
    let waiter = tokio::spawn(async move {
        owner
            .prepare_creation(scope.environment_id, &input(6)?)
            .await
    });
    let observed=tokio::time::timeout(Duration::from_secs(3),async {
        loop {
            let pid:Option<i32>=sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename=$1 AND wait_event_type='Lock' AND query LIKE '%organization_witness.creation_prepare%'")
                .bind(&f.runtime).fetch_optional(&mut observer).await?;
            if let Some(pid)=pid { return Ok::<_,sqlx::Error>(pid); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    let pid = match observed {
        Ok(Ok(pid)) => pid,
        error => {
            waiter.abort();
            let _ = waiter.await;
            barrier.rollback().await?;
            error??;
            return Err(anyhow::anyhow!("unobserved creation query"));
        }
    };
    if fatal {
        sqlx::query("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .execute(&mut observer)
            .await?;
        let failed = waiter.await?;
        barrier.rollback().await?;
        anyhow::ensure!(failed.is_err() && closure.is_closed());
        anyhow::ensure!(work.complete().await.is_err());
    } else {
        waiter.abort();
        let cancelled = waiter.await;
        let mut completion = tokio::spawn(work.complete());
        let held = tokio::time::timeout(Duration::from_millis(40), &mut completion)
            .await
            .is_err();
        barrier.rollback().await?;
        anyhow::ensure!(cancelled.is_err_and(|error| error.is_cancelled()) && held);
        anyhow::ensure!(completion.await?.is_err());
    }
    let creations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM organization_witness.creations WHERE environment_id=$1",
    )
    .bind(scope.environment_id)
    .fetch_one(&mut observer)
    .await?;
    anyhow::ensure!(creations == i64::from(!fatal));
    let mut control = f.connect(Role::Runtime).await?;
    anyhow::ensure!(control.current(scope).await?.pending == 1);
    control.close().await?;
    observer.close().await?;
    Ok(())
}

mod batch;
