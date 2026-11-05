use super::*;
use crate::organizations::{
    repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture,
};
use crate::web::test_support::TestResult;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug)]
enum Completion {
    Commit,
    Rollback,
    Drop,
}

struct ReturnGate {
    entered: Arc<AtomicBool>,
    enabled: Arc<AtomicBool>,
    release: Arc<Semaphore>,
}
impl ReturnGate {
    fn pool(f: &Fixture) -> (PgPool, Self) {
        let gate = Self {
            entered: Arc::new(AtomicBool::new(false)),
            enabled: Arc::new(AtomicBool::new(true)),
            release: Arc::new(Semaphore::new(0)),
        };
        let (entered, enabled, release) = (
            gate.entered.clone(),
            gate.enabled.clone(),
            gate.release.clone(),
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .after_release(move |_, _| {
                let (entered, enabled, release) =
                    (entered.clone(), enabled.clone(), release.clone());
                Box::pin(async move {
                    if enabled.load(Ordering::SeqCst) {
                        entered.store(true, Ordering::SeqCst);
                        let _ =
                            tokio::time::timeout(Duration::from_secs(10), release.acquire_owned())
                                .await;
                    }
                    Ok(true)
                })
            })
            .connect_lazy_with(f.pool.connect_options().as_ref().clone());
        (pool, gate)
    }
    fn open(&self) {
        self.enabled.store(false, Ordering::SeqCst);
        self.release.add_permits(4);
    }
}

async fn seed_administrator(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO aegaeon.administrators(id,email,password_hash,kind,status) VALUES($1,$2,'owned-login-hash','HUMAN','ACTIVE')")
        .bind(id).bind(format!("owned-login-{id}@example.test")).execute(pool).await?;
    Ok(id)
}

async fn retained_return(completion: Completion) -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let (pool, gate) = ReturnGate::pool(&f);
    let result = async {
        let id = seed_administrator(&f.pool).await?;
        let work = witness.begin().await?;
        let operation_pool = pool.clone();
        let mut waiter = tokio::spawn(work.execute(async move {
            let mut connection = connection(&operation_pool, "transaction-return").await?;
            let mut tx =
                begin_management_transaction(&mut connection, "transaction-return").await?;
            sqlx::query("UPDATE aegaeon.administrators SET last_login_at=now() WHERE id=$1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|_| owned::unavailable("transaction-return"))?;
            match completion {
                Completion::Commit => {
                    finish(
                        commit_management_transaction(tx, "transaction-return").await,
                        connection,
                        "transaction-return",
                    )
                    .await
                }
                Completion::Rollback => {
                    let result = tx
                        .rollback()
                        .await
                        .map_err(|_| owned::unavailable("transaction-return"));
                    finish(result, connection, "transaction-return").await
                }
                Completion::Drop => {
                    drop(tx);
                    drop(connection);
                    Ok(())
                }
            }
        }));
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let early = tokio::time::timeout(Duration::from_millis(100), &mut waiter).await;
        let premature = early.is_ok();
        let pending = witness.pending().await;
        if !premature {
            waiter.abort();
            let _ = waiter.await;
        }
        gate.open();
        let finished = tokio::time::timeout(Duration::from_secs(5), async {
            while witness.pending().await? != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        observed?;
        finished??;
        if premature || pending? != 1 {
            return Err(
                format!("{completion:?} completed before actual transaction pool return").into(),
            );
        }
        let updated: bool = sqlx::query_scalar(
            "SELECT last_login_at IS NOT NULL FROM aegaeon.administrators WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await?;
        if updated != matches!(completion, Completion::Commit) {
            return Err("commit/rollback persistence diverged".into());
        }
        Ok(())
    }
    .await;
    gate.open();
    pool.close().await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; committed management transaction retains cancelled return; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_transaction_commit_retains_return() -> TestResult {
    retained_return(Completion::Commit).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; rolled back management transaction retains cancelled return; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_transaction_rollback_retains_return() -> TestResult {
    retained_return(Completion::Rollback).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; early return queues rollback and retains actual pool return; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_transaction_drop_retains_return() -> TestResult {
    retained_return(Completion::Drop).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; closure before commit refuses actual mutation; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_transaction_closed_commit_rolls_back() -> TestResult
{
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let id = seed_administrator(&f.pool).await?;
        let work = witness.begin().await?;
        let owner = work.admission().clone();
        let mut refused = false;
        let outcome = work
            .store_scope(async {
                let mut connection = connection(&f.pool, "closed-commit").await?;
                let mut tx = begin_management_transaction(&mut connection, "closed-commit").await?;
                sqlx::query("UPDATE aegaeon.administrators SET last_login_at=now() WHERE id=$1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| owned::unavailable("closed-commit"))?;
                owner.close_until_restart();
                let commit = commit_management_transaction(tx, "closed-commit").await;
                refused = commit
                    .as_ref()
                    .is_err_and(|r| r.status() == StatusCode::SERVICE_UNAVAILABLE);
                finish(commit, connection, "closed-commit").await
            })
            .await;
        drop(owner);
        if outcome.is_ok() || work.complete().await.is_ok() || !refused {
            return Err("closed management transaction committed".into());
        }
        let updated: bool = sqlx::query_scalar(
            "SELECT last_login_at IS NOT NULL FROM aegaeon.administrators WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await?;
        if updated || witness.pending().await? != 1 {
            return Err("closed mutation persisted or uncertain witness disappeared".into());
        }
        Ok(())
    }
    .await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; lost transaction socket cannot complete durable work; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_transaction_lost_primary_retains_pending(
) -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let id = seed_administrator(&f.pool).await?;
        let work = witness.begin().await?;
        let closed = work.admission().closure_probe_for_test();
        let mut commit_failed = false;
        let outcome = work
            .store_scope(async {
                let mut connection = connection(&f.pool, "lost-transaction").await?;
                let mut tx =
                    begin_management_transaction(&mut connection, "lost-transaction").await?;
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(|_| owned::unavailable("lost-transaction"))?;
                sqlx::query("UPDATE aegaeon.administrators SET last_login_at=now() WHERE id=$1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|_| owned::unavailable("lost-transaction"))?;
                let stopped: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
                    .bind(pid)
                    .fetch_one(&f.pool)
                    .await
                    .map_err(|_| owned::unavailable("lost-transaction"))?;
                if !stopped {
                    return Err(owned::unavailable("lost-transaction"));
                }
                let commit = commit_management_transaction(tx, "lost-transaction").await;
                commit_failed = commit.is_err();
                finish(commit, connection, "lost-transaction").await
            })
            .await;
        if outcome.is_ok() || !commit_failed || !closed.is_closed() || work.complete().await.is_ok()
        {
            return Err("lost transaction completed witness work".into());
        }
        let updated: bool = sqlx::query_scalar(
            "SELECT last_login_at IS NOT NULL FROM aegaeon.administrators WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await?;
        if updated || witness.pending().await? != 1 {
            return Err("terminated transaction persisted or lost uncertain work".into());
        }
        Ok(())
    }
    .await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    f.cleanup(result.and(cleanup)).await
}
