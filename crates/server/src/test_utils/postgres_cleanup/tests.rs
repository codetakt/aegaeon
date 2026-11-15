use super::*;
use anyhow::Context;
use sqlx::{postgres::PgPoolOptions, Connection, PgConnection};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(3);

#[test]
fn cleanup_diagnostic_limits_large_multibyte_snapshots() {
    let mut observations = vec![json!({"states": "older snapshot"}); 63];
    observations.push(json!({"states": "界".repeat(8192)}));
    let summary = observation_summary(&observations);
    assert!(summary.len() < 4352);
    assert!(summary.contains("retained_observations=64"));
    assert!(summary.contains("latest_truncated=true"));
    assert!(!summary.contains("older snapshot"));
    let empty = observation_summary(&[]);
    assert!(empty.contains("latest_observation=null"));
    assert!(empty.contains("latest_truncated=false"));
    let ordinary = observation_summary(&[json!({"states": [{"pid": 123}]})]);
    assert!(ordinary.contains("\"pid\":123"));
    assert!(ordinary.contains("latest_truncated=false"));
}

struct Fixture {
    admin: PgPool,
    pool: PgPool,
    observer: PgConnection,
    name: String,
}

impl Fixture {
    async fn new(options: PgPoolOptions) -> anyhow::Result<Self> {
        let url = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await?;
        let observer = PgConnection::connect(&url).await?;
        // Exercise identifier escaping through actual CREATE, observation and DROP.
        let name = format!("cleanup_probe_{}\"quoted", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!(
            "CREATE DATABASE {}",
            quote_database_identifier(&name)
        ))
        .execute(&admin)
        .await?;
        let pool = options
            .connect_with(admin.connect_options().as_ref().clone().database(&name))
            .await?;
        Ok(Self {
            admin,
            pool,
            observer,
            name,
        })
    }

    async fn exists(&mut self) -> anyhow::Result<bool> {
        Ok(
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                .bind(&self.name)
                .fetch_one(&mut self.observer)
                .await?,
        )
    }

    async fn assert_finished(&mut self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.exists().await?,
            "owned database survived successful cleanup"
        );
        anyhow::ensure!(self.pool.is_closed() && self.pool.size() == 0);
        anyhow::ensure!(self.admin.is_closed() && self.admin.size() == 0);
        Ok(())
    }

    // Independent recovery preserves the scenario failure and uses only this
    // fixture's connections/database. It never terminates server sessions.
    async fn recover(mut self, result: anyhow::Result<()>) -> anyhow::Result<()> {
        let cleanup = timeout(LIMIT, async {
            drain_pool(&self.pool).await;
            drain_pool(&self.admin).await;
            loop {
                let live: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=$1)",
                )
                .bind(&self.name)
                .fetch_one(&mut self.observer)
                .await?;
                if !live {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            if self.exists().await? {
                sqlx::query(&format!(
                    "DROP DATABASE {}",
                    quote_database_identifier(&self.name)
                ))
                .execute(&mut self.observer)
                .await?;
            }
            anyhow::ensure!(!self.exists().await?);
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("independent fixture recovery timed out")
        .and_then(|r| r);
        let close = timeout(LIMIT, self.observer.close())
            .await
            .context("independent observer close timed out")
            .and_then(|r| r.map_err(Into::into));
        eprintln!(
            "owned cleanup probe: scenario={result:?}; recovery={cleanup:?}; observer={close:?}"
        );
        combine(combine(result, cleanup), close)
    }
}

fn combine(result: anyhow::Result<()>, cleanup: anyhow::Result<()>) -> anyhow::Result<()> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("additional recovery error: {cleanup:#}")))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(()), cleanup) => cleanup,
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; failed startup and a held lease retain the SQL error chain"]
async fn pg_owned_fixture_startup_failure_retains_error_chain() -> anyhow::Result<()> {
    let mut fixture = Fixture::new(PgPoolOptions::new().max_connections(2)).await?;
    let mut held = fixture.pool.acquire().await?;
    let env = crate::web::test_support::TestEnvironment {
        team_id: uuid::Uuid::new_v4(),
        tenant_id: uuid::Uuid::new_v4(),
        environment_id: uuid::Uuid::new_v4(),
        issuer_host: "cleanup-probe.invalid".into(),
        issuer_url: "https://cleanup-probe.invalid".into(),
    };
    let result = async {
        let error = timeout(
            Duration::from_secs(10),
            crate::web::test_support::test_app_state_from_owned_pool(fixture.pool.clone(), &env),
        )
        .await?
        .err()
        .context("empty database unexpectedly admitted runtime startup")?;
        let diagnostic = error.to_string();
        anyhow::ensure!(diagnostic.contains("additional owned startup pool cleanup failure"));
        anyhow::ensure!(diagnostic.contains("owned fixture pool close deadline"));
        // RuntimeConfigurationError stores its SQLx cause in a typed variant;
        // it does not expose that field through another Error::source link.
        let initial = error.source().context("startup error source was lost")?;
        let Some(crate::runtime_configuration::RuntimeConfigurationError::DatabaseQuery(
            sqlx::Error::Database(database),
        )) = initial.downcast_ref::<crate::runtime_configuration::RuntimeConfigurationError>()
        else {
            anyhow::bail!("startup error type or SQL cause was lost: {initial:?}");
        };
        anyhow::ensure!(database.code().as_deref() == Some("42P01"));
        anyhow::ensure!(fixture.pool.is_closed() && fixture.pool.size() > 0);
        let _: i32 = sqlx::query_scalar("SELECT 1").fetch_one(&mut *held).await?;
        eprintln!("expected startup and cleanup refusal: {error}");
        Ok(())
    }
    .await;
    drop(held);
    let cleanup = finish_database(&fixture.admin, &fixture.pool, &fixture.name, LIMIT)
        .await
        .map_err(Into::into);
    let result = combine(result, cleanup);
    let result = if result.is_ok() {
        fixture.assert_finished().await
    } else {
        result
    };
    fixture.recover(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; controlled late pool return reproduces the single-close defect"]
async fn pg_owned_fixture_drains_late_return_after_single_close() -> anyhow::Result<()> {
    use std::future::{poll_fn, Future};
    use std::task::Poll;
    let armed = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    let options = PgPoolOptions::new().max_connections(1).after_release({
        let armed = armed.clone();
        let entered = entered.clone();
        let release = release.clone();
        move |_, _| {
            let armed = armed.swap(false, Ordering::SeqCst);
            let entered = entered.clone();
            let release = release.clone();
            Box::pin(async move {
                if armed {
                    entered.add_permits(1);
                    release
                        .acquire()
                        .await
                        .map_err(|_| sqlx::Error::Protocol("return barrier closed".into()))?
                        .forget();
                }
                Ok(true)
            })
        }
    });
    let mut fixture = Fixture::new(options).await?;
    let result = async {
        let connection = fixture.pool.acquire().await?;
        armed.store(true, Ordering::SeqCst);
        drop(connection);
        timeout(LIMIT, entered.acquire()).await??.forget();
        let mut closing = Box::pin(fixture.pool.close());
        anyhow::ensure!(poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx).is_pending())).await);
        release.add_permits(1);
        timeout(LIMIT, closing).await?;
        // Preserve this actual old-boundary negative result before recovery.
        eprintln!(
            "single close returned with pool_size={}",
            fixture.pool.size()
        );
        anyhow::ensure!(
            fixture.pool.size() > 0,
            "controlled late return did not exercise the original defect"
        );
        close_pool(&fixture.pool, LIMIT).await?;
        anyhow::ensure!(fixture.pool.size() == 0);
        finish_database(&fixture.admin, &fixture.pool, &fixture.name, LIMIT).await?;
        fixture.assert_finished().await
    }
    .await;
    release.add_permits(1);
    fixture.recover(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; ordinary DROP waits for an observed live owned backend"]
async fn pg_owned_fixture_waits_for_backend_before_drop() -> anyhow::Result<()> {
    let mut fixture = Fixture::new(PgPoolOptions::new().max_connections(1)).await?;
    let mut held = PgConnection::connect_with(&fixture.pool.connect_options()).await?;
    let result = async {
        let mut closing = Box::pin(finish_database(
            &fixture.admin,
            &fixture.pool,
            &fixture.name,
            LIMIT,
        ));
        anyhow::ensure!(timeout(Duration::from_millis(50), closing.as_mut())
            .await
            .is_err());
        let _: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut held)
            .await?;
        held.close().await?;
        closing.await?;
        fixture.assert_finished().await
    }
    .await;
    fixture.recover(result).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; a live backend causes bounded refusal and admin cleanup"]
async fn pg_owned_fixture_deadline_preserves_database_and_closes_admin() -> anyhow::Result<()> {
    let mut fixture = Fixture::new(PgPoolOptions::new().max_connections(1)).await?;
    let mut held = PgConnection::connect_with(&fixture.pool.connect_options()).await?;
    let result = async {
        let error = finish_database(
            &fixture.admin,
            &fixture.pool,
            &fixture.name,
            Duration::from_millis(100),
        )
        .await
        .expect_err("held backend must block ordinary database removal");
        let diagnostic = error.to_string();
        anyhow::ensure!(diagnostic.contains("owned fixture cleanup deadline"));
        anyhow::ensure!(diagnostic.contains("latest_observation="));
        anyhow::ensure!(diagnostic.contains("latest_truncated=false"));
        anyhow::ensure!(diagnostic.len() < 4352);
        anyhow::ensure!(fixture.exists().await?);
        anyhow::ensure!(fixture.admin.is_closed() && fixture.admin.size() == 0);
        let _: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut held)
            .await?;
        eprintln!("expected refusal: {error}");
        Ok(())
    }
    .await;
    let held_close = timeout(LIMIT, held.close())
        .await
        .context("held backend close timed out")
        .and_then(|r| r.map_err(Into::into));
    fixture.recover(combine(result, held_close)).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; held pool leases share the bounded cleanup deadline"]
async fn pg_owned_fixture_pool_lease_has_bounded_cleanup() -> anyhow::Result<()> {
    let mut fixture = Fixture::new(PgPoolOptions::new().max_connections(1)).await?;
    let held = fixture.pool.acquire().await?;
    let result = async {
        let error = timeout(LIMIT, close_pool(&fixture.pool, Duration::from_millis(100)))
            .await?
            .expect_err("held lease must also bound auxiliary pool cleanup");
        anyhow::ensure!(error
            .to_string()
            .contains("owned fixture pool close deadline"));
        let error = timeout(
            LIMIT,
            finish_database(
                &fixture.admin,
                &fixture.pool,
                &fixture.name,
                Duration::from_millis(100),
            ),
        )
        .await?
        .expect_err("held pool lease must not leave close unbounded");
        anyhow::ensure!(error.to_string().contains("owned fixture cleanup deadline"));
        anyhow::ensure!(fixture.exists().await?);
        anyhow::ensure!(fixture.admin.is_closed() && fixture.admin.size() == 0);
        Ok(())
    }
    .await;
    drop(held);
    fixture.recover(result).await
}
