use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn grant_errors_exact_wire_taxonomy_and_authentication_precedence() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = scenario(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
async fn scenario(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let mut state = fixture(pool, env).await?;
    wire_admission(&state).await?;
    // All supported extensions reach their grant-specific input validation.
    for grant in [JWT_GRANT, TOKEN_EXCHANGE_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE] {
        error(
            token(&state, OWNER, &[("grant_type", grant)]).await?,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await?;
    }
    update_test_policy(&mut state, |policy| {
        policy.allowed_grant_types = vec![
            "authorization_code".into(),
            "refresh_token".into(),
            "client_credentials".into(),
        ]
    })
    .await?;
    for grant in [JWT_GRANT, TOKEN_EXCHANGE_GRANT_TYPE, DEVICE_CODE_GRANT_TYPE] {
        error(
            token(&state, OWNER, &[("grant_type", grant)]).await?,
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
        )
        .await?;
    }
    sqlx::query("UPDATE aegaeon.oauth_profiles SET allowed_grant_types=$1 WHERE environment_id=$2")
        .bind(vec!["authorization_code"])
        .bind(env.environment_id)
        .execute(pool)
        .await?;
    for grant in [
        "refresh_token",
        "client_credentials",
        JWT_GRANT,
        TOKEN_EXCHANGE_GRANT_TYPE,
        DEVICE_CODE_GRANT_TYPE,
    ] {
        error(
            token(&state, OWNER, &[("grant_type", grant)]).await?,
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
        )
        .await?;
    }
    Ok(())
}

async fn wire_admission(state: &AppState) -> TestResult {
    for grant in [
        "password",
        "unknown",
        "urn:example:grant",
        "Authorization_Code",
        "authorization_code ",
        " refresh_token",
        "CLIENT_CREDENTIALS",
        "urn:ietf:params:oauth:grant-type:DEVICE_CODE",
    ] {
        error(
            token(state, OWNER, &[("grant_type", grant)]).await?,
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
        )
        .await?;
    }
    for grant in grants() {
        for variant in [
            grant.to_uppercase(),
            format!(" {grant}"),
            format!("{grant} "),
        ] {
            error(
                token(state, OWNER, &[("grant_type", &variant)]).await?,
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
            )
            .await?;
        }
    }
    for values in [vec![], vec![("grant_type", "")]] {
        error(
            token(state, OWNER, &values).await?,
            StatusCode::BAD_REQUEST,
            "invalid_request",
        )
        .await?;
    }
    for grant in ["unknown", "authorization_code"] {
        let response = super::super::router::build_router(state.clone())
            .oneshot(request(
                "/token",
                form(&[("grant_type", grant)]),
                OWNER,
                "incorrect-secret",
            )?)
            .await?;
        error(response, StatusCode::UNAUTHORIZED, "invalid_client").await?;
    }

    for grant in [
        "refresh_token",
        "client_credentials",
        JWT_GRANT,
        DEVICE_CODE_GRANT_TYPE,
    ] {
        error(
            token(state, LIMITED, &[("grant_type", grant)]).await?,
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
        )
        .await?;
    }
    Ok(())
}
