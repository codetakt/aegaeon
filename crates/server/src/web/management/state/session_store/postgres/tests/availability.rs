use super::*;
use crate::web::management::http_errors::management_session_error;
use crate::web::management::state::{ManagementSessionBackend, ManagementSessionStore};
use axum::http::StatusCode;

async fn operation(
    store: &ManagementSessionStore,
    op: usize,
    sid: String,
    now: u64,
) -> Result<(), SessionStoreError> {
    match op {
        0 => store
            .try_get_for_request(sid, now, "session-fault")
            .await
            .map(|_| ()),
        1 => store
            .try_create_for_request(Uuid::new_v4(), now, "session-fault")
            .await
            .map(|_| ()),
        _ => store
            .try_delete_for_request(sid, "session-fault")
            .await
            .map(|_| ()),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionProbe {
    None,
    Assertion,
    BlockedOperation,
    OperationPanic,
}

async fn run_session_outage(probe: SessionProbe, database: &mut String) -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    database.clone_from(&fixture.database);
    let label = format!("session-outage-{}", Uuid::new_v4());
    let pool = PgPoolOptions::new().max_connections(1).connect_lazy_with(
        fixture
            .pool
            .connect_options()
            .as_ref()
            .clone()
            .application_name(&label),
    );
    let store = ManagementSessionStore {
        backend: ManagementSessionBackend::Postgres(PostgresManagementSessions::new(
            pool.clone(),
            "outage".into(),
        )),
        session_ttl_secs: 60,
        max_sessions: 16,
        diagnostics: Default::default(),
    };
    let mut operation_task = None;
    let result: anyhow::Result<()> = crate::test_utils::catch_test_panic(async {
        let now = crate::util::now_unix_epoch_secs()?;
        for op in 0..3 {
            let sid = store.try_create_async(Uuid::new_v4(), now).await?.ok_or_else(|| anyhow::anyhow!("session"))?;
            assert!(probe != SessionProbe::Assertion, "injected session outage assertion");
            let mut held = fixture.pool.begin().await?;
            sqlx::query("LOCK TABLE aegaeon.runtime_management_sessions IN ACCESS EXCLUSIVE MODE").execute(&mut *held).await?;
            let clone = store.clone();
            let target = sid.clone();
            operation_task = Some(tokio::spawn(async move {
                assert!(probe != SessionProbe::OperationPanic, "injected session operation task panic");
                operation(&clone, op, target, now).await
            }));
            let termination = if probe == SessionProbe::OperationPanic { Ok(Ok(())) } else { tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let pid: Option<i32> = sqlx::query_scalar("SELECT DISTINCT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.application_name=$1 AND NOT l.granted AND l.locktype='relation' AND l.relation='aegaeon.runtime_management_sessions'::regclass AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())")
                        .bind(&label).fetch_optional(&fixture.pool).await?;
                    if let Some(pid) = pid {
                        if probe == SessionProbe::BlockedOperation { return Err(sqlx::Error::Protocol("injected blocked session operation failure".into())); }
                        assert!(sqlx::query_scalar::<_,bool>("SELECT pg_terminate_backend($1)").bind(pid).fetch_one(&fixture.pool).await?);
                        return Ok::<_, sqlx::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await };
            held.rollback().await?;
            termination??;
            let joined = tokio::time::timeout(Duration::from_secs(5), operation_task.as_mut().ok_or_else(|| anyhow::anyhow!("operation owner"))?).await;
            if joined.is_ok() { operation_task.take(); }
            let error = joined??.unwrap_err();
            assert!(matches!(error, SessionStoreError::Database(_)));
            let response = management_session_error("session-fault", &error);
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(response.headers()["retry-after"], "1");
            assert_eq!(response.headers()["x-request-id"], "session-fault");
            assert!(response.headers()["cache-control"].to_str()?.contains("no-store"));
            // Interrupted SQL did not delete the existing session. The same pool recovers.
            assert!(store.try_get_async(sid.clone(), now).await?.is_some());
            operation(&store, op, sid, now).await?;
        }
        // A missing relation is a deployment defect, not a retryable outage.
        fixture.pool.execute("DROP TABLE aegaeon.runtime_management_sessions").await?;
        for op in 0..3 {
            let error = operation(&store, op, "missing".into(), now).await.unwrap_err();
            assert_eq!(error.sqlstate().as_deref(), Some("42P01"));
            let response = management_session_error("permanent", &error);
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert!(!response.headers().contains_key("retry-after"));
        }
        Ok(())
    }).await;
    let task_cleanup: anyhow::Result<()> = if let Some(mut task) = operation_task {
        task.abort();
        match tokio::time::timeout(Duration::from_secs(5), &mut task).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        }
    } else {
        Ok(())
    };
    let pool_cleanup =
        crate::test_utils::postgres_cleanup::close_pool(&pool, Duration::from_secs(5)).await;
    let fixture_cleanup = fixture.finish().await;
    let result = preserve_session_fixture(result, task_cleanup);
    let result = preserve_session_fixture(result, pool_cleanup.map_err(Into::into));
    preserve_session_fixture(result, fixture_cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; terminate real session read/create/delete and retain permanent SQL errors"]
async fn pg_management_session_outages_preserve_failure_class_and_recover() -> anyhow::Result<()> {
    run_session_outage(SessionProbe::None, &mut String::new()).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; injected assertion must drop the actual session database"]
async fn pg_management_session_outage_assertion_cleans_database() -> anyhow::Result<()> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
        .await?;
    let result = crate::test_utils::catch_test_panic(async {
        let mut database = String::new();
        let result = run_session_outage(SessionProbe::Assertion, &mut database).await;
        let remaining: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                .bind(&database)
                .fetch_one(&admin)
                .await?;
        anyhow::ensure!(
            !database.is_empty() && !remaining,
            "session fixture database remains"
        );
        let error = result.expect_err("injected assertion must remain a test failure");
        anyhow::ensure!(
            error.to_string() == "test panicked: injected session outage assertion",
            "{error:#}"
        );
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let cleanup =
        crate::test_utils::postgres_cleanup::close_pool(&admin, Duration::from_secs(5)).await;
    preserve_session_fixture(result, cleanup.map_err(Into::into))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; blocked and panicking session tasks must be joined before database teardown"]
async fn pg_management_session_outage_task_failures_clean_database() -> anyhow::Result<()> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
        .await?;
    let result = crate::test_utils::catch_test_panic(async {
        for probe in [SessionProbe::BlockedOperation, SessionProbe::OperationPanic] {
            let mut database = String::new();
            let result = run_session_outage(probe, &mut database).await;
            let remaining: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)")
                    .bind(&database)
                    .fetch_one(&admin)
                    .await?;
            anyhow::ensure!(
                !database.is_empty() && !remaining,
                "session task failure leaked its database"
            );
            let error = result.expect_err("injected task failure must remain");
            let text = format!("{error:#}");
            let expected = if probe == SessionProbe::BlockedOperation {
                "injected blocked session operation failure"
            } else {
                "injected session operation task panic"
            };
            anyhow::ensure!(
                text.contains(expected) && !text.contains("cleanup failure"),
                "{text}"
            );
        }
        Ok::<_, anyhow::Error>(())
    })
    .await;
    let cleanup =
        crate::test_utils::postgres_cleanup::close_pool(&admin, Duration::from_secs(5)).await;
    preserve_session_fixture(result, cleanup.map_err(Into::into))
}

#[tokio::test]
#[ignore = "requires PostgreSQL; failed initialization drops only its acknowledged owned database"]
async fn pg_management_session_fixture_initialization_failure_removes_database(
) -> anyhow::Result<()> {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)
        .await?;
    let database = format!("management_session_{}", Uuid::new_v4().simple());
    let result = crate::test_utils::catch_test_panic(async {
        let error = match Fixture::initialize(database.clone(), "SELECT missing_session_fixture_column").await {
            Err(error) => error,
            Ok(fixture) => return fixture.finish_result(Err(anyhow::anyhow!("invalid migration succeeded"))).await,
        };
        anyhow::ensure!(matches!(error.downcast_ref::<sqlx::Error>(), Some(sqlx::Error::Database(e)) if e.code().as_deref()==Some("42703")), "{error:#}");
        let remaining: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_database WHERE datname=$1)").bind(&database).fetch_one(&admin).await?;
        anyhow::ensure!(!remaining, "initialization failure leaked its database");
        let existing = Fixture::new().await?;
        let preserved = crate::test_utils::catch_test_panic(async {
            let error = match Fixture::initialize(existing.database.clone(), migration()).await {
                Err(error) => error,
                Ok(_) => anyhow::bail!("CREATE of existing database unexpectedly succeeded"),
            };
            anyhow::ensure!(matches!(error.downcast_ref::<sqlx::Error>(), Some(sqlx::Error::Database(e)) if e.code().as_deref()==Some("42P04")), "{error:#}");
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM aegaeon.runtime_management_sessions").fetch_one(&existing.pool).await?;
            anyhow::ensure!(count==0);
            Ok::<_, anyhow::Error>(())
        }).await;
        existing.finish_result(preserved).await
    }).await;
    let cleanup =
        crate::test_utils::postgres_cleanup::close_pool(&admin, Duration::from_secs(5)).await;
    preserve_session_fixture(result, cleanup.map_err(Into::into))
}
