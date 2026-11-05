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
enum Call {
    Read,
    Touch,
}

impl Call {
    async fn run(
        self,
        pool: &PgPool,
        id: Uuid,
        email: &str,
        hash: &str,
    ) -> Result<bool, StatusCode> {
        match self {
            Self::Read => load_management_login_record(pool, email, "owned-login")
                .await
                .map(|record| {
                    record.is_some_and(|record| {
                        record.administrator_id == id && record.password_hash == hash
                    })
                })
                .map_err(|response| response.status()),
            Self::Touch => update_management_login_state(pool, id, hash, "owned-login")
                .await
                .map_err(|response| response.status()),
        }
    }
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

async fn retained_return(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let (pool, gate) = ReturnGate::pool(&f);
    let result = async {
        let id = seed_administrator(&f.pool).await?;
        let (email, hash): (String, String) =
            sqlx::query_as("SELECT email,password_hash FROM aegaeon.administrators WHERE id=$1")
                .bind(id)
                .fetch_one(&f.pool)
                .await?;
        let work = witness.begin().await?;
        let operation_pool = pool.clone();
        let returned = Arc::new(AtomicBool::new(false));
        let actual = returned.clone();
        let mut waiter = tokio::spawn(work.execute(async move {
            actual.store(
                call.run(&operation_pool, id, &email, &hash).await == Ok(true),
                Ordering::SeqCst,
            );
        }));
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            while !gate.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        let early = tokio::time::timeout(Duration::from_millis(100), &mut waiter).await;
        let pending = witness.pending().await;
        let premature = early.is_ok();
        if !premature {
            waiter.abort();
            let _ = waiter.await;
        }
        // Always release the real return hook before asserting observations.
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
            return Err(format!("{call:?} released witness before pool return").into());
        }
        if !returned.load(Ordering::SeqCst) {
            return Err("actual login operation failed".into());
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
#[ignore = "requires PostgreSQL; login lookup owns actual cancelled pool return; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_login_read_retains_return() -> TestResult {
    retained_return(Call::Read).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; conditional login update owns actual cancelled pool return; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_login_touch_retains_return() -> TestResult {
    retained_return(Call::Touch).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; stale login credential still prevents bookkeeping; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_login_rechecks_verified_password() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let id = seed_administrator(&f.pool).await?;
        let (email, hash): (String, String) =
            sqlx::query_as("SELECT email,password_hash FROM aegaeon.administrators WHERE id=$1")
                .bind(id)
                .fetch_one(&f.pool)
                .await?;
        let before: Option<String> = sqlx::query_scalar(
            "SELECT last_login_at::text FROM aegaeon.administrators WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await?;
        if witness
            .run(Call::Touch.run(&f.pool, id, &email, "stale-hash"))
            .await?
            != Ok(false)
        {
            return Err("stale hash accepted".into());
        }
        let after: Option<String> = sqlx::query_scalar(
            "SELECT last_login_at::text FROM aegaeon.administrators WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await?;
        if before != after {
            return Err("stale hash changed login state".into());
        }
        if witness
            .run(Call::Touch.run(&f.pool, id, &email, &hash))
            .await?
            != Ok(true)
        {
            return Err("current login update refused".into());
        }
        if witness
            .run(Call::Read.run(&f.pool, id, &email, &hash))
            .await?
            != Ok(true)
        {
            return Err("current login lookup refused".into());
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
#[ignore = "requires PostgreSQL; closed scope cannot fall back to raw login queries; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_login_refuses_closed_owner() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let id = seed_administrator(&f.pool).await?;
        let (email, hash): (String, String) =
            sqlx::query_as("SELECT email,password_hash FROM aegaeon.administrators WHERE id=$1")
                .bind(id)
                .fetch_one(&f.pool)
                .await?;
        for call in [Call::Read, Call::Touch] {
            let work = witness.begin().await?;
            let owner = work.admission().clone();
            let mut refused = false;
            let result = work
                .store_scope(async {
                    owner.close_until_restart();
                    refused = call.run(&f.pool, id, &email, &hash).await
                        == Err(StatusCode::SERVICE_UNAVAILABLE);
                })
                .await;
            drop(owner);
            if result.is_ok() {
                return Err("closed scope completed".into());
            }
            if work.complete().await.is_ok() {
                return Err("closed witness completed".into());
            }
            if !refused {
                return Err("closed owner reached raw login persistence".into());
            }
        }
        if witness.pending().await? != 2 {
            return Err("uncertain work lost".into());
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
#[ignore = "requires PostgreSQL; actual lost login connection retains uncertain durable work; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_login_refuses_lost_primary() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let id = seed_administrator(&f.pool).await?;
        let (email, hash): (String, String) = sqlx::query_as(
            "SELECT email,password_hash FROM aegaeon.administrators WHERE id=$1",
        )
        .bind(id)
        .fetch_one(&f.pool)
        .await?;
        let mut barrier = f.pool.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.administrators IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *barrier)
            .await?;
        let work = witness.begin().await?;
        let closed = work.admission().closure_probe_for_test();
        let label = work.admission().store_label()?.ok_or("missing login label")?.to_owned();
        let pool = f.pool.clone();
        let waiter = tokio::spawn(work.execute(async move { Call::Read.run(&pool, id, &email, &hash).await }));
        let observed = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE application_name=$1 AND datname=current_database() AND usename=current_user AND wait_event_type='Lock'")
                    .bind(&label).fetch_optional(&f.pool).await?;
                if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }).await;
        let termination = match &observed {
            Ok(Ok(pid)) => sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)")
                .bind(pid).fetch_one(&f.pool).await,
            _ => Ok(false),
        };
        // Release the actual lock even if the label observation failed.
        let release = barrier.rollback().await;
        let outcome = tokio::time::timeout(Duration::from_secs(5), waiter).await;
        release?;
        observed??;
        if !termination? { return Err("owned login backend was not terminated".into()); }
        if outcome??.is_ok() || !closed.is_closed() || witness.pending().await? != 1 {
            return Err("lost login connection completed uncertain witness work".into());
        }
        Ok(())
    }.await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    f.cleanup(result.and(cleanup)).await
}
