use super::*;
use anyhow::Context;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Connection, PgConnection,
};
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
        // Exercise identifier escaping through actual CREATE, observation and DROP.
        let name = format!("cleanup_probe_{}\"quoted", uuid::Uuid::new_v4().simple());
        Self::named(options, name).await
    }

    async fn named(options: PgPoolOptions, name: String) -> anyhow::Result<Self> {
        let url = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?;
        let connect: PgConnectOptions = url.parse()?;
        let connect = connect.application_name(&name);
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(LIMIT)
            .connect_with(connect.clone())
            .await?;
        let observer = match timeout(LIMIT, PgConnection::connect_with(&connect))
            .await
            .context("cleanup probe observer connection timed out")
            .and_then(|r| r.map_err(Into::into))
        {
            Ok(observer) => observer,
            Err(error) => {
                return combine(
                    Err(error),
                    close_pool(&admin, LIMIT).await.map_err(Into::into),
                );
            }
        };
        let created = timeout(
            LIMIT,
            sqlx::query(&format!(
                "CREATE DATABASE {}",
                quote_database_identifier(&name)
            ))
            .execute(&admin),
        )
        .await
        .context("cleanup probe database creation timed out")
        .and_then(|r| r.map_err(Into::into));
        if let Err(error) = created {
            // Without a successful CREATE acknowledgement, ownership is not
            // established. In particular, never remove a pre-existing database.
            let admin_cleanup = close_pool(&admin, LIMIT).await.map_err(Into::into);
            let observer_cleanup = timeout(LIMIT, observer.close())
                .await
                .context("cleanup probe observer close timed out")
                .and_then(|r| r.map_err(Into::into));
            return combine(combine(Err(error), admin_cleanup), observer_cleanup);
        }
        // Own the pool before the first connection attempt, including failures.
        let pool = options.connect_lazy_with(connect.database(&name));
        let fixture = Self {
            admin,
            pool,
            observer,
            name,
        };
        let initialized = async {
            let connection = timeout(LIMIT, fixture.pool.acquire())
                .await
                .context("cleanup probe pool connection timed out")??;
            drop(connection);
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match initialized {
            Ok(()) => Ok(fixture),
            Err(error) => fixture.recover(Err(error)).await,
        }
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
    async fn recover<T>(mut self, result: anyhow::Result<T>) -> anyhow::Result<T> {
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
            "owned cleanup probe: scenario={:?}; recovery={cleanup:?}; observer={close:?}",
            result.as_ref().map(|_| ())
        );
        combine(combine(result, cleanup), close)
    }
}

fn combine<T>(result: anyhow::Result<T>, cleanup: anyhow::Result<()>) -> anyhow::Result<T> {
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            Err(error.context(format!("additional recovery error: {cleanup:#}")))
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(error)) => Err(error),
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL; failed post-CREATE connections must recover the database"]
async fn pg_owned_fixture_connection_failure_recovers_database() -> anyhow::Result<()> {
    let url = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?;
    let mut observer = PgConnection::connect(&url).await?;
    let name = format!("cleanup_probe_{}\"quoted", uuid::Uuid::new_v4().simple());
    let rejected = Arc::new(AtomicBool::new(false));
    let options = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(500))
        .after_connect({
            let rejected = rejected.clone();
            move |connection, _| {
                let rejected = rejected.clone();
                Box::pin(async move {
                    // The actual supplier rejects every new connection's setup.
                    let result = sqlx::query("SELECT missing_cleanup_probe_column")
                        .execute(connection)
                        .await;
                    if let Err(sqlx::Error::Database(error)) = &result {
                        rejected.store(error.code().as_deref() == Some("42703"), Ordering::SeqCst);
                    }
                    result.map(|_| ())
                })
            }
        });
    let result = async {
        let error = match Fixture::named(options, name.clone()).await {
            Err(error) => error,
            Ok(fixture) => {
                return fixture
                    .recover(Err(anyhow::anyhow!("connection unexpectedly succeeded")))
                    .await;
            }
        };
        anyhow::ensure!(rejected.load(Ordering::SeqCst));
        anyhow::ensure!(matches!(
            error.downcast_ref::<sqlx::Error>(),
            Some(sqlx::Error::PoolTimedOut)
        ));
        timeout(LIMIT, async {
            loop {
                let live: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name=$1)",
                )
                .bind(&name)
                .fetch_one(&mut observer)
                .await?;
                if !live {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                    .bind(&name)
                    .fetch_one(&mut observer)
                    .await?;
            anyhow::ensure!(
                !exists,
                "post-CREATE connection failure leaked its database"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
    .await;
    // Independent test recovery remains available even if the assertions fail.
    let cleanup = if rejected.load(Ordering::SeqCst) {
        timeout(LIMIT, async {
            sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {}",
                quote_database_identifier(&name)
            ))
            .execute(&mut observer)
            .await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .context("connection-failure probe recovery timed out")
        .and_then(|r| r)
    } else {
        Ok(())
    };
    let close = timeout(LIMIT, observer.close())
        .await
        .context("connection-failure observer close timed out")
        .and_then(|r| r.map_err(Into::into));
    combine(combine(result, cleanup), close)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; a duplicate database name must not establish ownership"]
async fn pg_owned_fixture_duplicate_database_is_preserved() -> anyhow::Result<()> {
    let url = std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?;
    let mut observer = PgConnection::connect(&url).await?;
    let name = format!("cleanup_probe_{}\"quoted", uuid::Uuid::new_v4().simple());
    timeout(
        LIMIT,
        sqlx::query(&format!(
            "CREATE DATABASE {}",
            quote_database_identifier(&name)
        ))
        .execute(&mut observer),
    )
    .await??;
    let entered = Arc::new(AtomicBool::new(false));
    let options = PgPoolOptions::new().max_connections(1).after_connect({
        let entered = entered.clone();
        move |_, _| {
            entered.store(true, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    });
    let result = async {
        let error = match Fixture::named(options, name.clone()).await {
            Err(error) => error,
            Ok(fixture) => {
                return fixture
                    .recover(Err(anyhow::anyhow!("duplicate CREATE succeeded")))
                    .await
            }
        };
        let Some(sqlx::Error::Database(database)) = error.downcast_ref::<sqlx::Error>() else {
            anyhow::bail!("original CREATE error was lost: {error:#}");
        };
        anyhow::ensure!(database.code().as_deref() == Some("42P04"));
        anyhow::ensure!(!entered.load(Ordering::SeqCst));
        timeout(LIMIT, async {
            loop {
                let live: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name=$1)",
                )
                .bind(&name)
                .fetch_one(&mut observer)
                .await?;
                if !live {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                    .bind(&name)
                    .fetch_one(&mut observer)
                    .await?;
            anyhow::ensure!(exists, "failed CREATE removed a pre-existing database");
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        Ok(())
    }
    .await;
    // This observer, unlike the failed fixture, received the successful CREATE.
    let cleanup = timeout(LIMIT, async {
        sqlx::query(&format!(
            "DROP DATABASE IF EXISTS {}",
            quote_database_identifier(&name)
        ))
        .execute(&mut observer)
        .await?;
        Ok::<_, anyhow::Error>(())
    })
    .await
    .context("duplicate-name probe recovery timed out")
    .and_then(|r| r);
    let close = timeout(LIMIT, observer.close())
        .await
        .context("duplicate-name observer close timed out")
        .and_then(|r| r.map_err(Into::into));
    combine(combine(result, cleanup), close)
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
