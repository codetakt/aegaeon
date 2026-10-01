use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn grant_errors_two_authenticated_clients_preserve_redis_code_for_owner() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = scenario(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
async fn scenario(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let state = fixture(pool, env).await?;
    let auth = serde_json::from_value(
        json!({"response_type":"code", "client_id":OWNER, "redirect_uri":REDIRECT, "code_challenge":CHALLENGE, "code_challenge_method":"S256"}),
    )?;
    let (code, _) = state
        .tokens
        .issuer
        .issue_authorization_code(auth, "grant-user".into())?;
    let values = [
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", REDIRECT),
        ("code_verifier", VERIFIER),
    ];
    error(
        token(&state, OTHER, &values).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    // Policy refusal also leaves the owner's code intact.
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1 WHERE environment_id=$2")
        .bind(vec!["refresh_token"])
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    error(
        token(&state, OWNER, &values).await?,
        StatusCode::BAD_REQUEST,
        "unauthorized_client",
    )
    .await?;
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1 WHERE environment_id=$2")
        .bind(grants())
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    let response = token(&state, OWNER, &values).await?;
    assert_eq!(response.status(), StatusCode::OK);
    no_cache(&response);
    let issued = body(response).await?;
    let access = issued["access_token"]
        .as_str()
        .ok_or("access token required")?;
    let stored = state
        .tokens
        .store
        .try_verify_access_token(access)?
        .ok_or("Redis access token missing")?;
    assert_eq!(stored.client_id, OWNER);
    assert_eq!(stored.user_id, "grant-user");
    error(
        token(&state, OWNER, &values).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    Ok(())
}
