//! The same regression also runs against the unmodified base implementation.
use super::*;
use crate::web::authorize_context::build_authorize_request_context;

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn authorization_snapshot_refuses_a_mismatched_environment() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("PostgreSQL required; no silent skip"))?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = async {
        let client = sample_registered_client("snapshot-boundary-client");
        create_test_registration(&pool, &env, &client, "synthetic-boundary-token").await?;
        let mut state = test_app_state(pool.clone(), &env).await?;
        let query = serde_urlencoded::to_string([
            ("client_id", client.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", client.redirect_uris[0].as_str()),
            ("iss", env.issuer_url.as_str()),
            ("state", "boundary-state"),
            (
                "code_challenge",
                "boundary-challenge-AAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            ("code_challenge_method", "S256"),
        ])?;
        let uri = format!("/authorize?{query}").parse()?;
        if let Err(response) =
            build_authorize_request_context(&state, &uri, &env.issuer_url, "matching".into()).await
        {
            return Err(io::Error::other(format!(
                "matching fixture refused: {}",
                response.status()
            ))
            .into());
        }
        state.environment_id = uuid::Uuid::new_v4();
        let response =
            build_authorize_request_context(&state, &uri, &env.issuer_url, "mismatched".into())
                .await
                .err()
                .ok_or_else(|| {
                    io::Error::other("authorization accepted a mismatched environment")
                })?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers().get(header::LOCATION).is_none());
        assert_eq!(
            response_json(response).await?["error"],
            "temporarily_unavailable"
        );
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}
