use super::*;
use crate::organizations::{
    repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Semaphore;

type TestResult = crate::web::test_support::TestResult;
const STALE: Duration = Duration::from_secs(120);

async fn seed(f: &Fixture, count: i32) -> TestResult {
    sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash) VALUES($1,$2,'unused-fixture-hash')")
        .bind(f.actor.id).bind(format!("{}@example.test", f.actor.id)).execute(&f.pool).await?;
    sqlx::query(
        "INSERT INTO aegaeon.team_memberships(team_id,administrator_id,role) VALUES($1,$2,'OWNER')",
    )
    .bind(f.env.team_id)
    .bind(f.actor.id)
    .execute(&f.pool)
    .await?;
    sqlx::query("INSERT INTO aegaeon.management_user_runtime_commands(team_id,tenant_id,environment_id,end_user_id,actor_administrator_id,request_id,command_type,payload,updated_at) SELECT $1,$2,$3,$4,$5,gen_random_uuid()::text,'fixture','{\"private\":\"not-audit-data\"}',now()-interval '1 day' FROM generate_series(1,$6)")
        .bind(f.env.team_id).bind(f.env.tenant_id).bind(f.env.environment_id)
        .bind(f.users[0]).bind(f.actor.id).bind(count).execute(&f.pool).await?;
    Ok(())
}

async fn pending(f: &Fixture) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM aegaeon.management_user_runtime_commands WHERE environment_id=$1 AND status='requested'")
        .bind(f.env.environment_id).fetch_one(&f.pool).await
}

async fn audits(f: &Fixture) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT count(*) FROM aegaeon.audit_events WHERE environment_id=$1 AND event_type='management.user.runtimeCommand.reconciledStale.v1'")
        .bind(f.env.environment_id).fetch_one(&f.pool).await
}

async fn finish(f: Fixture, witness: CallerFixture, result: TestResult) -> TestResult {
    let cleanup = witness.finish().await.map_err(Into::into);
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; exact Environment, batch, audit and replay"]
async fn pg_organizations_reconciliation_limits_actual_environment() -> TestResult {
    let f = Fixture::new().await?;
    let other = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = async {
        seed(&f, 101).await?;
        seed(&other, 3).await?;
        assert!(reconcile_stale_environment_runtime_commands(&f.pool, f.env.environment_id, STALE).await.is_err());
        assert!(witness.run(reconcile_stale_environment_runtime_commands(&f.pool, other.env.environment_id, STALE)).await?.is_err());
        for expected in [100, 1, 0] {
            let actual = witness.run(reconcile_stale_environment_runtime_commands(&f.pool, f.env.environment_id, STALE)).await??;
            if actual != expected || pending(&other).await? != 3 || audits(&other).await? != 0 {
                return Err("scoped reconciliation changed foreign commands or exceeded its batch".into());
            }
        }
        assert_eq!(pending(&f).await?, 0);
        assert_eq!(audits(&f).await?, 101);
        let leaked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM aegaeon.audit_events WHERE environment_id=$1 AND data::text LIKE '%not-audit-data%')")
            .bind(f.env.environment_id).fetch_one(&f.pool).await?;
        assert!(!leaked);
        // The separately unscoped legacy sweep still processes other Environments.
        assert!(reconcile_stale_management_user_runtime_commands(&f.pool, STALE).await? >= 3);
        assert_eq!(pending(&other).await?, 0);
        assert_eq!(audits(&other).await?, 3);
        Ok(())
    }.await;
    let result = other.cleanup(result).await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; global sweep cannot borrow one Environment owner"]
async fn pg_organizations_reconciliation_global_refuses_owner() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = async {
        seed(&f, 1).await?;
        let result = witness
            .run(reconcile_stale_management_user_runtime_commands(
                &f.pool, STALE,
            ))
            .await?;
        if result.is_ok() || pending(&f).await? != 1 || audits(&f).await? != 0 {
            return Err("global reconciliation ran inside a single Environment owner".into());
        }
        assert_eq!(witness.pending().await?, 0);
        Ok(())
    }
    .await;
    finish(f, witness, result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; actual mutation rollback after owner closure"]
async fn pg_organizations_reconciliation_refuses_closed_commit() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let result = closed_commit(&f, &witness).await;
    finish(f, witness, result).await
}

async fn closed_commit(f: &Fixture, witness: &CallerFixture) -> TestResult {
    seed(f, 1).await?;
    let mut lock = f.pool.begin().await?;
    sqlx::query("LOCK TABLE aegaeon.management_user_runtime_commands IN SHARE MODE")
        .execute(&mut *lock)
        .await?;
    let work = witness.begin().await?;
    let owner = work.admission().clone();
    let pool = f.pool.clone();
    let environment = f.env.environment_id;
    let caller = tokio::spawn(async move {
        let result = work
            .store_scope(reconcile_stale_environment_runtime_commands(
                &pool,
                environment,
                STALE,
            ))
            .await;
        (work, result)
    });
    let observed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND usename=current_user AND wait_event_type='Lock' AND query LIKE '%WITH stale AS%')")
                .fetch_one(&f.pool).await?;
            if blocked { return Ok::<_, sqlx::Error>(()); }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }).await;
    owner.close_until_restart();
    lock.rollback().await?;
    let (work, result) = tokio::time::timeout(Duration::from_secs(5), caller).await??;
    drop(owner);
    let completion = work.complete().await;
    observed??;
    if result.is_ok() || completion.is_ok() || pending(f).await? != 1 || audits(f).await? != 0 {
        return Err("reconciliation committed after closure or omitted audit rollback".into());
    }
    assert_eq!(witness.pending().await?, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL; cancelled waiter retains actual pool return"]
async fn pg_organizations_reconciliation_owns_pool_return() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::new(f.env.environment_id).await?;
    let entered = Arc::new(AtomicBool::new(false));
    let enabled = Arc::new(AtomicBool::new(true));
    let gate = Arc::new(Semaphore::new(0));
    let (observed, active, wait) = (entered.clone(), enabled.clone(), gate.clone());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .after_release(move |_, _| {
            let (observed, active, wait) = (observed.clone(), active.clone(), wait.clone());
            Box::pin(async move {
                if active.load(Ordering::SeqCst) {
                    observed.store(true, Ordering::SeqCst);
                    wait.acquire_owned().await.unwrap().forget();
                }
                Ok(true)
            })
        })
        .connect_lazy_with(f.pool.connect_options().as_ref().clone());
    let result = async {
        seed(&f, 1).await?;
        let work = witness.begin().await?;
        work.store_scope(async {
            let mut call = Box::pin(reconcile_stale_environment_runtime_commands(&pool, f.env.environment_id, STALE));
            let observed = async {
                while !entered.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(5)).await; }
            };
            tokio::select! {
                result = &mut call => Err::<(), Box<dyn std::error::Error>>(format!("reconciliation returned before pool cleanup: {result:?}").into()),
                result = tokio::time::timeout(Duration::from_secs(5), observed) => { result?; drop(call); Ok(()) }
            }
        }).await??;
        let mut completion = tokio::spawn(work.complete());
        let early = tokio::time::timeout(Duration::from_millis(100), &mut completion).await;
        let retained = witness.pending().await?;
        enabled.store(false, Ordering::SeqCst);
        gate.add_permits(8);
        if early.is_ok() || retained != 1 {
            return Err("reconciliation completed witness before actual connection return".into());
        }
        tokio::time::timeout(Duration::from_secs(5), completion).await???;
        assert_eq!(witness.pending().await?, 0);
        assert_eq!(pending(&f).await?, 0);
        assert_eq!(audits(&f).await?, 1);
        Ok(())
    }.await;
    enabled.store(false, Ordering::SeqCst);
    gate.add_permits(8);
    pool.close().await;
    finish(f, witness, result).await
}
