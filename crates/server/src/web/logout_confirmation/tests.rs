mod browser;
mod fixture;
mod rejection;
mod retention;
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_pg_pool, TestResult,
};
use fixture::*;

async fn scenario(name: &str) -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let fixture = Fixture::new(&pool, &env).await?;
        match name {
            "browser" => browser::sessions(&fixture).await,
            "bindings" => rejection::bindings(&fixture).await,
            "admission" => rejection::admission(&fixture).await,
            "retention" => retention::limits(&fixture).await,
            "failures" => rejection::failures(&fixture).await,
            _ => browser::upstream(&fixture).await,
        }
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn logout_confirmation_real_router_session_scope_and_get_post_parity() -> TestResult {
    scenario("browser").await
}
#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn logout_confirmation_real_router_binding_expiry_replay_and_races() -> TestResult {
    scenario("bindings").await
}
#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn logout_confirmation_real_router_input_and_client_admission() -> TestResult {
    scenario("admission").await
}
#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn logout_confirmation_bounded_admission_retains_decisions_and_prunes_expiry() -> TestResult {
    scenario("retention").await
}
#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn logout_confirmation_fail_closed_storage_and_policy_changes() -> TestResult {
    scenario("failures").await
}
#[tokio::test]
#[ignore = "requires private PostgreSQL and Redis"]
async fn logout_confirmation_preserves_upstream_relay_and_cookie_headers() -> TestResult {
    scenario("upstream").await
}
