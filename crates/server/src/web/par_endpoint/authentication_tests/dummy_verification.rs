use super::{
    cleanup_test_environment, finish_test, fixture, rejected, setup_test_environment, test_pg_pool,
    TestResult, Uuid, STANDARD,
};
use crate::client_registry::dummy_secret_test_hook::VerificationObserver;
use base64::Engine as _;

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires PostgreSQL and AEGAEON_PAR_REDIS_URL / AEGAEON_TEST_REDIS_URL"]
async fn shared_redis_par_secret_rejections_preserve_actual_dummy_verification() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env).await?;
        let url = std::env::var("AEGAEON_TEST_REDIS_URL")?;
        let mut conn = redis::Client::open(url)?.get_connection()?;
        let mut missing_verifications = Vec::new();
        for (basic, client) in [
            (true, "unknown"),
            (false, "unknown"),
            (true, "client_secret_post"),
            (false, "client_secret_basic"),
            (true, "client_secret_basic"),
            (false, "client_secret_post"),
        ] {
            let secret = format!("par-rejected-secret-{}", Uuid::new_v4());
            let observer = VerificationObserver::for_secret(&secret);
            if basic {
                let auth = format!("Basic {}", STANDARD.encode(format!("{client}:{secret}")));
                rejected(&state, &mut conn, client, Some(&auth), &[]).await?;
            } else {
                rejected(
                    &state,
                    &mut conn,
                    client,
                    None,
                    &[("client_secret", &secret)],
                )
                .await?;
            }
            if observer.calls() != 1 {
                missing_verifications.push(format!(
                    "basic={basic}, client={client}, actual_calls={}",
                    observer.calls()
                ));
            }
        }
        if !missing_verifications.is_empty() {
            return Err(format!(
                "each rejection must execute one actual dummy verification: {}",
                missing_verifications.join("; ")
            )
            .into());
        }
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
