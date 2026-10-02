use super::*;
use crate::web::test_support::{setup_test_environment, test_pg_pool, TestResult};
use std::{ffi::OsString, net::SocketAddr, sync::Arc, time::Duration};

struct IssuerSelector(Option<OsString>);
impl Drop for IssuerSelector {
    fn drop(&mut self) {
        if let Some(value) = &self.0 {
            std::env::set_var("AEGAEON_RUNTIME_ISSUER_HOST", value);
        } else {
            std::env::remove_var("AEGAEON_RUNTIME_ISSUER_HOST");
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL, shared Redis and a dedicated test process"]
async fn shared_redis_pg_public_factory_refuses_audit_history_mutation() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("restricted PostgreSQL fixture required")?;
    let environment = setup_test_environment(&pool).await?;
    let _selector = IssuerSelector(std::env::var_os("AEGAEON_RUNTIME_ISSUER_HOST"));
    std::env::set_var("AEGAEON_RUNTIME_ISSUER_HOST", &environment.issuer_host);
    sqlx::query("INSERT INTO aegaeon.control_plane_policies (id) VALUES ('default') ON CONFLICT (id) DO NOTHING")
        .execute(&pool).await?;
    let admin = sqlx::PgPool::connect(&std::env::var("AEGAEON_TEST_ADMIN_DATABASE_URL")?).await?;
    let runtime: String = sqlx::query_scalar("SELECT current_user::text")
        .fetch_one(&pool)
        .await?;
    // PostgreSQL quotes the fixture login as an identifier, never SQL input.
    let grant: String = sqlx::query_scalar(
        "SELECT format('GRANT UPDATE(event_type) ON aegaeon.audit_events_default TO %I', $1::text)",
    )
    .bind(&runtime)
    .fetch_one(&admin)
    .await?;
    let revoke: String = sqlx::query_scalar("SELECT format('REVOKE UPDATE(event_type) ON aegaeon.audit_events_default FROM %I', $1::text)")
        .bind(&runtime).fetch_one(&admin).await?;
    sqlx::raw_sql(&grant).execute(&admin).await?;
    let refused = AppState::from_environment().await;
    sqlx::raw_sql(&revoke).execute(&admin).await?;
    let error = refused
        .err()
        .ok_or("unsafe audit writer received validated runtime state")?;
    assert!(format!("{error:#}").contains("rewrite protected audit history"));
    let state = AppState::from_environment().await?;
    assert!(state.require_subject_namespace().is_ok());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated restricted PostgreSQL, shared Redis and a dedicated test process"]
async fn shared_redis_pg_public_factory_starts_monitors_and_drains_embedding() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("restricted PostgreSQL fixture required")?;
    let environment = setup_test_environment(&pool).await?;
    let _selector = IssuerSelector(std::env::var_os("AEGAEON_RUNTIME_ISSUER_HOST"));
    std::env::set_var("AEGAEON_RUNTIME_ISSUER_HOST", &environment.issuer_host);
    sqlx::query("INSERT INTO aegaeon.control_plane_policies (id) VALUES ('default') ON CONFLICT (id) DO NOTHING")
        .execute(&pool).await?;
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(configuration_document,'{policy,runtimeConfigMonitorIntervalSeconds}','1') WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(environment.environment_id).execute(&pool).await?;
    let state = AppState::from_environment().await?;
    assert!(state.require_subject_namespace().is_ok());
    let drain = state.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let admitted = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let held_state = state.clone();
    let held_admitted = admitted.clone();
    let held_release = release.clone();
    let app = crate::web::build_router(state.clone()).route(
        "/held-namespace",
        axum::routing::get(move || {
            let state = held_state.clone();
            let admitted = held_admitted.clone();
            let release = held_release.clone();
            async move {
                let capability = state.require_subject_namespace()?;
                admitted.notify_one();
                release.notified().await;
                // This request already passed admission. Its capability remains
                // usable during drain, without re-admitting a new operation.
                Ok::<_, Response>(capability.state().environment_id.to_string())
            }
        }),
    );
    let mut server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            drain.shutdown_requested().await;
        })
        .await
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client
        .get(format!("http://{address}/ready"))
        .header("x-forwarded-proto", "https")
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let held_client = client.clone();
    let held_request = tokio::spawn(async move {
        held_client
            .get(format!("http://{address}/held-namespace"))
            .header("x-forwarded-proto", "https")
            .send()
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), admitted.notified()).await?;
    // A real committed database revision change is observed by the mandatory
    // listener/monitor. The test never injects a restart request itself.
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(configuration_document,'{policy,runtimeConfigMonitorIntervalSeconds}','2') WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(environment.environment_id).execute(&pool).await?;
    tokio::time::timeout(Duration::from_secs(30), state.shutdown_requested()).await?;
    assert!(state.require_subject_namespace().is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut server)
            .await
            .is_err(),
        "listener drain must wait for the already-admitted request"
    );
    release.notify_one();
    let completed = held_request.await??;
    assert_eq!(completed.status(), StatusCode::OK);
    assert_eq!(
        completed.text().await?,
        environment.environment_id.to_string()
    );
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    Ok(())
}
