use super::*;
use crate::device_authz::DevicePollResult;
use std::collections::BTreeMap;

async fn create(state: &AppState) -> TestResult<Value> {
    let response = super::super::router::build_router(state.clone())
        .oneshot(request(
            "/device_authorization",
            form(&[("resource", "https://resource.example/one")]),
            OWNER,
            SECRET,
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    no_cache(&response);
    body(response).await
}
async fn decide(state: &AppState, user_code: &str, action: &str) -> TestResult {
    let app = super::super::router::build_router(state.clone());
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/device").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()?
        .split(';')
        .next()
        .ok_or("CSRF cookie")?
        .to_string();
    let csrf = cookie.split_once('=').ok_or("CSRF value")?.1;
    let sid = state
        .browser_auth
        .auth_sessions
        .try_create(
            "grant-user",
            super::super::AuthSessionTimes::local(crate::util::now_unix_epoch_secs()?),
            None,
            None,
            None,
        )?
        .ok_or("session")?;
    let mut request = request(
        &format!("/device/{action}"),
        form(&[("user_code", user_code), ("csrf_token", csrf)]),
        OWNER,
        SECRET,
    )?;
    request.headers_mut().insert(
        header::COOKIE,
        format!("{cookie}; {}={sid}", super::super::AUTH_SESSION_COOKIE_NAME).parse()?,
    );
    let response = app.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    no_cache(&response);
    Ok(())
}
fn snapshot(state: &AppState, code: &str) -> TestResult<BTreeMap<String, String>> {
    let namespace = crate::config::RuntimeStateNamespace::from_environment_id(state.environment_id);
    let key = format!(
        "{}:entry:{}",
        namespace.redis_prefix("device-code", "v2"),
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(aegaeon_crypto::hash::sha256_digest(code.as_bytes()))
    );
    let mut conn =
        redis::Client::open(std::env::var("AEGAEON_TEST_REDIS_URL")?)?.get_connection()?;
    Ok(redis::cmd("HGETALL").arg(key).query(&mut conn)?)
}
async fn poll(state: &AppState, client: &str, code: &str) -> TestResult<Response> {
    token(
        state,
        client,
        &[
            ("grant_type", DEVICE_CODE_GRANT_TYPE),
            ("device_code", code),
        ],
    )
    .await
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn grant_errors_device_wrong_client_preserves_approval_and_single_use() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = approved_scenario(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
async fn approved_scenario(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let state = fixture(pool, env).await?;
    let device = create(&state).await?;
    let code = device["device_code"].as_str().ok_or("device_code")?;
    let before = snapshot(&state, code)?;
    assert_eq!(before.get("status").map(String::as_str), Some("pending"));
    error(
        poll(&state, OTHER, code).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, before);
    decide(
        &state,
        device["user_code"].as_str().ok_or("user_code")?,
        "approve",
    )
    .await?;
    let approved = snapshot(&state, code)?;
    assert_eq!(approved.get("status").map(String::as_str), Some("approved"));
    assert_eq!(
        approved.get("approved_user_id").map(String::as_str),
        Some("grant-user")
    );
    error(
        poll(&state, OTHER, code).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, approved);
    error(
        token(
            &state,
            OWNER,
            &[
                ("grant_type", DEVICE_CODE_GRANT_TYPE),
                ("device_code", code),
                ("resource", "https://resource.example/other"),
            ],
        )
        .await?,
        StatusCode::BAD_REQUEST,
        "invalid_target",
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, approved);
    // Environment mismatch must conceal the code even from the wrong client.
    assert!(matches!(
        state
            .device
            .code_store
            .try_poll(code, OTHER, Some("other-environment"), None)?,
        DevicePollResult::ExpiredToken
    ));
    assert_eq!(snapshot(&state, code)?, approved);
    let response = poll(&state, OWNER, code).await?;
    assert_eq!(response.status(), StatusCode::OK);
    no_cache(&response);
    let issued = body(response).await?;
    let access = issued["access_token"].as_str().ok_or("access token")?;
    let stored = state
        .tokens
        .store
        .try_verify_access_token(access)?
        .ok_or("Redis access token")?;
    assert_eq!(stored.client_id, OWNER);
    assert_eq!(stored.user_id, "grant-user");
    assert!(snapshot(&state, code)?.is_empty());
    for client in [OWNER, OTHER] {
        error(
            poll(&state, client, code).await?,
            StatusCode::BAD_REQUEST,
            "expired_token",
        )
        .await?;
    }
    Ok(())
}
#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn grant_errors_device_pending_backoff_denial_expiry_and_isolation() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = controls(&pool, &env).await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
async fn controls(pool: &PgPool, env: &TestEnvironment) -> TestResult {
    let mut state = fixture(pool, env).await?;
    let pending = create(&state).await?;
    let code = pending["device_code"].as_str().ok_or("device_code")?;
    error(
        poll(&state, OWNER, code).await?,
        StatusCode::BAD_REQUEST,
        "authorization_pending",
    )
    .await?;
    let first = snapshot(&state, code)?;
    error(
        poll(&state, OTHER, code).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, first);
    error(
        poll(&state, OWNER, code).await?,
        StatusCode::BAD_REQUEST,
        "slow_down",
    )
    .await?;
    let second = snapshot(&state, code)?;
    assert_eq!(
        second["poll_interval_secs"].parse::<u64>()?,
        first["poll_interval_secs"].parse::<u64>()? + 5
    );
    error(
        poll(&state, OTHER, code).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, second);
    let denied = create(&state).await?;
    let code = denied["device_code"].as_str().ok_or("device_code")?;
    decide(
        &state,
        denied["user_code"].as_str().ok_or("user_code")?,
        "deny",
    )
    .await?;
    let before = snapshot(&state, code)?;
    error(
        poll(&state, OTHER, code).await?,
        StatusCode::BAD_REQUEST,
        "invalid_grant",
    )
    .await?;
    assert_eq!(snapshot(&state, code)?, before);
    error(
        poll(&state, OWNER, code).await?,
        StatusCode::BAD_REQUEST,
        "access_denied",
    )
    .await?;
    error(
        poll(&state, OWNER, "unknown-code").await?,
        StatusCode::BAD_REQUEST,
        "expired_token",
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
    for client in [OTHER, OWNER] {
        error(
            poll(
                &state,
                client,
                expired["device_code"].as_str().ok_or("device_code")?,
            )
            .await?,
            StatusCode::BAD_REQUEST,
            "expired_token",
        )
        .await?;
    }
    Ok(())
}
