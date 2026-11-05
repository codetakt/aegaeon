use super::*;
use crate::organizations::repository_tests::Fixture;
use crate::web::management::http_errors::management_database_error as database_error;
use crate::web::test_support::{log_capture::Capture, TestResult};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    Executor,
};
use std::{str::FromStr, time::Duration};

async fn refusal(response: Response, status: StatusCode, request: &str) -> TestResult {
    assert_eq!(response.status(), status);
    assert_eq!(response.headers()["x-request-id"], request);
    assert!(response.headers()["cache-control"]
        .to_str()?
        .contains("no-store"));
    if status == StatusCode::SERVICE_UNAVAILABLE {
        assert_eq!(response.headers()["retry-after"], "1");
    }
    let body = axum::body::to_bytes(response.into_body(), 4096).await?;
    let body: serde_json::Value = serde_json::from_slice(&body)?;
    assert_eq!(body["requestId"], request);
    assert_eq!(
        body["errorCode"],
        if status == StatusCode::SERVICE_UNAVAILABLE {
            "temporarily_unavailable"
        } else {
            "internal_error"
        }
    );
    Ok(())
}

#[test]
#[ignore = "requires PostgreSQL; terminate the real policies query and observe safe request-correlated diagnostics"]
fn pg_management_policy_connection_loss_is_503_logged_and_recovers() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.subscriber(), || {
        runtime.block_on(async {
        let fixture = Fixture::new().await?;
        let label = format!("policy-crash-{}", Uuid::new_v4());
        let pool = PgPoolOptions::new().max_connections(1).acquire_timeout(Duration::from_secs(3))
            .connect_with(fixture.pool.connect_options().as_ref().clone().application_name(&label)).await?;
        let admin = PgPoolOptions::new().max_connections(2).connect_with(
            PgConnectOptions::from_str(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?)?
                .database(fixture.pool.connect_options().get_database().ok_or("database")?),
        ).await?;
        let result: TestResult = async {
            sqlx::query("INSERT INTO aegaeon.environment_policies (environment_id, configuration_version_id, pkce_required, dcr_enabled, allowed_signing_algorithms, allowed_grant_types, access_token_time_to_live_seconds, id_token_time_to_live_seconds, refresh_token_time_to_live_seconds, authorization_code_time_to_live_seconds) SELECT id, active_configuration_version_id, true, false, ARRAY['RS256'], ARRAY['authorization_code'], 300, 300, 86400, 90 FROM aegaeon.environments WHERE id=$1")
                .bind(fixture.env.environment_id).execute(&admin).await?;
            load_environment_policy_document(&pool, fixture.env.environment_id, "policy-before-crash")
                .await.map_err(|response| format!("policy fixture: {}", response.status()))?;
            let mut held = admin.begin().await?;
            sqlx::query("LOCK TABLE aegaeon.environment_policies IN ACCESS EXCLUSIVE MODE").execute(&mut *held).await?;
            let query_pool = pool.clone();
            let environment = fixture.env.environment_id;
            let query = tokio::spawn(async move {
                load_environment_policy_document(&query_pool, environment, "policy-crash-request").await
            });
            let termination = tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let pid: Option<i32> = sqlx::query_scalar("SELECT DISTINCT a.pid FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.application_name=$1 AND NOT l.granted AND l.locktype='relation' AND l.relation='aegaeon.environment_policies'::regclass AND l.database=(SELECT oid FROM pg_database WHERE datname=current_database())")
                        .bind(&label).fetch_optional(&admin).await?;
                    if let Some(pid) = pid {
                        assert!(sqlx::query_scalar::<_, bool>("SELECT pg_terminate_backend($1)").bind(pid).fetch_one(&admin).await?);
                        return Ok::<_, sqlx::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await;
            held.rollback().await?;
            termination??;
            let response = tokio::time::timeout(Duration::from_secs(5), query).await??.err().ok_or("failed policy query unexpectedly succeeded")?;
            refusal(response, StatusCode::SERVICE_UNAVAILABLE, "policy-crash-request").await?;
            let log = capture.text();
            assert!(log.contains("policy-crash-request") && log.contains("configuration_version_store/policy.rs"));
            assert!(log.contains("sqlstate=") && log.contains("unavailable=true"));
            load_environment_policy_document(&pool, environment, "policy-recovered")
                .await.map_err(|response| format!("policy recovery: {}", response.status()))?;
            for code in ["42501", "42601", "23505"] {
                let error = admin.execute(format!("DO $$ BEGIN RAISE SQLSTATE '{code}' USING MESSAGE='private-credential-detail'; END $$").as_str()).await.unwrap_err();
                let response = database_error("permanent-request", &error, "Database query failed");
                refusal(response, StatusCode::INTERNAL_SERVER_ERROR, "permanent-request").await?;
                assert!(capture.text().contains(code));
            }
            assert!(!capture.text().contains("private-credential-detail"));
            Ok(())
        }.await;
        crate::organizations::lifecycle::close_pool(&pool).await;
        crate::organizations::lifecycle::close_pool(&admin).await;
        fixture.cleanup(result).await
    })
    })
}
