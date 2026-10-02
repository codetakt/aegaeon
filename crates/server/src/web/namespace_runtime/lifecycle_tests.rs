use super::*;
use crate::web::test_support::{setup_test_environment, test_pg_pool, TestResult};
use std::{ffi::OsString, net::SocketAddr, time::Duration};

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
    let app = crate::web::build_router(state.clone());
    let server = tokio::spawn(async move {
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
    // A real committed database revision change is observed by the mandatory
    // listener/monitor. The test never injects a restart request itself.
    sqlx::query("UPDATE aegaeon.configuration_versions SET configuration_document=jsonb_set(configuration_document,'{policy,runtimeConfigMonitorIntervalSeconds}','2') WHERE environment_id=$1 AND status='ACTIVE'")
        .bind(environment.environment_id).execute(&pool).await?;
    tokio::time::timeout(Duration::from_secs(30), state.shutdown_requested()).await?;
    assert!(state.require_subject_namespace().is_err());
    tokio::time::timeout(Duration::from_secs(5), server).await???;
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    Ok(())
}
