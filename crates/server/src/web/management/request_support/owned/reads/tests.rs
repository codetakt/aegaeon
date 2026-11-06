use crate::organizations::{
    repository_tests::Fixture, witness::tests::caller_fixture::CallerFixture,
};
use crate::web::{
    management::{
        client_store::{list_client_rows, load_visible_client},
        request_support::validate_expires_at,
    },
    test_support::TestResult,
};
use axum::http::StatusCode;
use sqlx::{PgPool, Row};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::Semaphore;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
enum Call {
    List,
    Load,
    InvalidTimestamp,
}
impl Call {
    async fn run(
        self,
        pool: &PgPool,
        team: Uuid,
        environment: Uuid,
        client: Uuid,
    ) -> Result<bool, StatusCode> {
        match self {
            Self::List => list_client_rows(pool, team, environment, None, None, 10, "owned-read")
                .await
                .map(|rows| {
                    rows.len() == 1 && rows[0].try_get::<Uuid, _>("id").ok() == Some(client)
                })
                .map_err(|r| r.status()),
            Self::Load => load_visible_client(pool, team, environment, client, "owned-read")
                .await
                .map(|value| value.is_some_and(|c| c.id == client.to_string()))
                .map_err(|r| r.status()),
            Self::InvalidTimestamp => {
                Ok(
                    validate_expires_at(pool, Some("invalid-time"), "owned-read")
                        .await
                        .is_err_and(|r| r.status() == StatusCode::BAD_REQUEST),
                )
            }
        }
    }
}

async fn seed_client(f: &Fixture) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar("INSERT INTO aegaeon.clients(environment_id,configuration_version_id,client_identifier,name,client_type,redirect_uris,allowed_grant_types,allowed_scopes,token_endpoint_authentication_method) SELECT id,active_configuration_version_id,'owned-read-client','Owned read','PUBLIC',ARRAY['https://client.example/callback'],ARRAY['authorization_code'],ARRAY['openid'],'none' FROM aegaeon.environments WHERE id=$1 RETURNING id")
        .bind(f.env.environment_id).fetch_one(&f.pool).await
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

async fn retained_return(call: Call) -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let (pool, gate) = ReturnGate::pool(&f);
    let result = async {
        let client = seed_client(&f).await?;
        let (team, environment) = (f.env.team_id, f.env.environment_id);
        let work = witness.begin().await?;
        let operation_pool = pool.clone();
        let returned = Arc::new(AtomicBool::new(false));
        let actual = returned.clone();
        let mut waiter = tokio::spawn(work.execute(async move {
            actual.store(
                call.run(&operation_pool, team, environment, client).await == Ok(true),
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
            return Err("actual management read failed".into());
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
#[ignore = "requires PostgreSQL; list owns actual cancelled pool return; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_read_list_retains_return() -> TestResult {
    retained_return(Call::List).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; optional lookup owns actual cancelled pool return; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_read_optional_retains_return() -> TestResult {
    retained_return(Call::Load).await
}
#[tokio::test]
#[ignore = "requires PostgreSQL; SQL input error retains return and its original status; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_read_error_retains_return() -> TestResult {
    retained_return(Call::InvalidTimestamp).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; closed scope cannot fall back to raw management reads; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_read_refuses_closed_owner() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let client = seed_client(&f).await?;
        for call in [Call::List, Call::Load] {
            let work = witness.begin().await?;
            let owner = work.admission().clone();
            let mut refused = false;
            let result = work
                .store_scope(async {
                    owner.close_until_restart();
                    refused = call
                        .run(&f.pool, f.env.team_id, f.env.environment_id, client)
                        .await
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
                return Err("closed owner reached raw management reads".into());
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
#[ignore = "requires PostgreSQL; actual lost management read connection retains uncertain durable work; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_read_refuses_lost_primary() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let client = seed_client(&f).await?;
        let (team, environment) = (f.env.team_id, f.env.environment_id);
        let mut barrier = f.pool.begin().await?;
        sqlx::query("LOCK TABLE aegaeon.clients IN ACCESS EXCLUSIVE MODE")
            .execute(&mut *barrier)
            .await?;
        let work = witness.begin().await?;
        let closed = work.admission().closure_probe_for_test();
        let label = work.admission().store_label()?.ok_or("missing management read label")?.to_owned();
        let pool = f.pool.clone();
        let waiter = tokio::spawn(work.execute(async move { Call::List.run(&pool, team, environment, client).await }));
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
        if !termination? { return Err("owned management read backend was not terminated".into()); }
        if outcome??.is_ok() || !closed.is_closed() || witness.pending().await? != 1 {
            return Err("lost management read connection completed uncertain witness work".into());
        }
        Ok(())
    }.await;
    let cleanup = witness
        .finish()
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() });
    f.cleanup(result.and(cleanup)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; ordinary/scoped reads preserve visibility and recover after SQL error; requires explicit Redis observation supplier"]
async fn shared_redis_organizations_management_read_visibility_and_recovery() -> TestResult {
    let f = Fixture::new().await?;
    let witness = CallerFixture::with_test_stores(
        f.env.environment_id,
        f.pool.connect_options().as_ref().clone(),
    )
    .await?;
    let result = async {
        let client = seed_client(&f).await?;
        for call in [Call::List, Call::Load] {
            if call
                .run(&f.pool, f.env.team_id, f.env.environment_id, client)
                .await
                != Ok(true)
            {
                return Err("ordinary management read failed".into());
            }
            let result = witness
                .run(async {
                    if Call::InvalidTimestamp
                        .run(&f.pool, f.env.team_id, f.env.environment_id, client)
                        .await
                        != Ok(true)
                    {
                        return false;
                    }
                    if call
                        .run(&f.pool, f.env.team_id, f.env.environment_id, client)
                        .await
                        != Ok(true)
                    {
                        return false;
                    }
                    if call
                        .run(&f.pool, Uuid::new_v4(), f.env.environment_id, client)
                        .await
                        != Ok(false)
                    {
                        return false;
                    }
                    if call
                        .run(&f.pool, f.env.team_id, Uuid::new_v4(), client)
                        .await
                        != Ok(false)
                    {
                        return false;
                    }
                    true
                })
                .await?;
            if !result {
                return Err("visibility or post-error recovery failed".into());
            }
        }
        if witness.pending().await? != 0 {
            return Err("successful read left pending work".into());
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
