use super::*;

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn device_confirmation_exact_values_refuse_without_mutating_pending_code() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = exact_values(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn exact_values(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let state = fixture(pool, env).await?;
    let sid = browser_session(&state).await?;
    let device = create(&state).await?;
    let code = device["device_code"].as_str().ok_or("device code")?;
    let user_code = device["user_code"].as_str().ok_or("user code")?;
    let pending = snapshot(&state, code)?;
    assert_eq!(pending["status"], "pending");
    let invalid: &[&[&str]] = &[
        &[],
        &[""],
        &["no"],
        &["YES"],
        &[" yes"],
        &["yes "],
        &["yes", "yes"],
        &["yes", "no"],
    ];
    for values in invalid {
        assert_page_error(
            action(&state, "/device/approve", Some(&sid), user_code, values).await?,
            StatusCode::BAD_REQUEST,
        )
        .await?;
        assert_eq!(
            snapshot(&state, code)?,
            pending,
            "confirmation values: {values:?}"
        );
    }
    let response = action(&state, "/device/approve", Some(&sid), user_code, &["yes"]).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(snapshot(&state, code)?["status"], "approved");
    assert_issued_once(&state, code).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn device_confirmation_preserves_session_csrf_denial_expiry_and_reuse_guards() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = guards(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

async fn guards(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let mut state = fixture(pool, env).await?;
    let sid = browser_session(&state).await?;
    let device = create(&state).await?;
    let code = device["device_code"].as_str().ok_or("device code")?;
    let user_code = device["user_code"].as_str().ok_or("user code")?;
    let pending = snapshot(&state, code)?;
    // Existing session and CSRF precedence remains even when confirmation is absent.
    assert_page_error(
        action(&state, "/device/approve", None, user_code, &[]).await?,
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, pending);
    let (cookie, _) = entry(&state, "/device").await?;
    let invalid = [("user_code", user_code), ("csrf_token", "wrong")];
    assert_page_error(
        browser_post(&state, "/device/approve", &cookie, Some(&sid), &invalid).await?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, pending);
    let csrf = cookie.split_once('=').ok_or("CSRF value")?.1;
    let fields = [("user_code", user_code), ("csrf_token", csrf)];
    assert_page_error(
        browser_post(&state, "/device/approve", &cookie, Some(&sid), &fields).await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, pending);
    // Valid CSRF was consumed despite the missing confirmation.
    let fields = [
        ("user_code", user_code),
        ("csrf_token", csrf),
        ("confirm_device", "yes"),
    ];
    assert_page_error(
        browser_post(&state, "/device/approve", &cookie, Some(&sid), &fields).await?,
        StatusCode::FORBIDDEN,
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, pending);
    let response = action(&state, "/device/deny", Some(&sid), user_code, &[]).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(snapshot(&state, code)?["status"], "denied");
    assert_page_error(
        action(&state, "/device/approve", Some(&sid), user_code, &["yes"]).await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    error(
        poll(&state, OWNER, code).await?,
        StatusCode::BAD_REQUEST,
        "access_denied",
    )
    .await?;
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(env.environment_id);
    state.device.code_store = Arc::new(
        crate::device_authz::DeviceCodeStore::try_from_shared_store_env_with_policy(
            1, 5, &namespace,
        )?,
    );
    let expired = create(&state).await?;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert_page_error(
        action(
            &state,
            "/device/approve",
            Some(&sid),
            expired["user_code"].as_str().ok_or("expired code")?,
            &["yes"],
        )
        .await?,
        StatusCode::BAD_REQUEST,
    )
    .await?;
    error(
        poll(
            &state,
            OWNER,
            expired["device_code"]
                .as_str()
                .ok_or("expired device code")?,
        )
        .await?,
        StatusCode::BAD_REQUEST,
        "expired_token",
    )
    .await
}
