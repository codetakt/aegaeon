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

#[tokio::test]
#[ignore = "requires PostgreSQL; terminate real session read/create/delete and retain permanent SQL errors"]
async fn pg_management_session_outages_preserve_failure_class_and_recover() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let label = format!("session-outage-{}", Uuid::new_v4());
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            fixture
                .pool
                .connect_options()
                .as_ref()
                .clone()
                .application_name(&label),
        )
        .await?;
    let store = ManagementSessionStore {
        backend: ManagementSessionBackend::Postgres(PostgresManagementSessions::new(
            pool.clone(),
            "outage".into(),
        )),
        session_ttl_secs: 60,
        max_sessions: 16,
        diagnostics: Default::default(),
    };
    let result = async {
        let now = crate::util::now_unix_epoch_secs()?;
        for op in 0..3 {
            let sid = store.try_create_async(Uuid::new_v4(), now).await?.ok_or_else(|| anyhow::anyhow!("session"))?;
            let mut held = fixture.pool.begin().await?;
            sqlx::query("LOCK TABLE aegaeon.runtime_management_sessions IN ACCESS EXCLUSIVE MODE").execute(&mut *held).await?;
            let clone = store.clone();
            let target = sid.clone();
            let task = tokio::spawn(async move { operation(&clone, op, target, now).await });
            let termination = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let pid: Option<i32> = sqlx::query_scalar("SELECT DISTINCT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.application_name=$1 AND NOT l.granted AND l.locktype='relation' AND l.relation='aegaeon.runtime_management_sessions'::regclass AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())")
                        .bind(&label).fetch_optional(&fixture.pool).await?;
                    if let Some(pid) = pid {
                        assert!(sqlx::query_scalar::<_,bool>("SELECT pg_terminate_backend($1)").bind(pid).fetch_one(&fixture.pool).await?);
                        return Ok::<_, sqlx::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await;
            held.rollback().await?;
            termination??;
            let error = tokio::time::timeout(Duration::from_secs(5), task).await??.unwrap_err();
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
    }.await;
    pool.close().await;
    fixture.finish().await?;
    result
}
