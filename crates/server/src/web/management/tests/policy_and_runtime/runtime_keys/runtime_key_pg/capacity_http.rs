#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_runtime_key_capacity_http_all_usages_and_mutation_paths() -> TestResult {
    let pool = capacity_pg_pool().await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _kek = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61u8; 32]));
    for usage in CAPACITY_USAGES {
        for activate_next in [false, true] {
            let env = setup_runtime_key_test_environment(&pool).await?;
            let result = capacity_http_scenario(&pool, &env, usage, activate_next).await;
            let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
            finish_runtime_key_pg_test(result, cleanup)?;
        }
    }
    Ok(())
}

async fn capacity_http_scenario(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    usage: crate::runtime_keys::RuntimeKeyUsage,
    activate_next: bool,
) -> TestResult {
    let mgmt = test_management_state();
    let now = crate::util::now_unix_epoch_secs()?;
    let sid = mgmt
        .sessions
        .create(env.administrator_id, now)
        .ok_or_else(|| io::Error::other("session creation failed"))?;
    let nonmember = mgmt
        .sessions
        .create(env.non_member_administrator_id, now)
        .ok_or_else(|| io::Error::other("session creation failed"))?;
    let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
    for index in 0..4 {
        let req = capacity_create_request(env, usage, &format!("seed-{index}"), true)?;
        capacity_create_http(&app, env, &sid, &req).await?;
        capacity_loaded(pool, env, usage, &format!("seed-{index}"), index).await?;
    }
    // Retirement occurs before insertion. A duplicate kid must roll it back.
    let before = configuration_transition_snapshot(pool, env).await?;
    let duplicate = capacity_create_request(env, usage, "seed-0", true)?;
    let response = capacity_post(
        &app,
        env,
        &sid,
        "runtimeKeys",
        serde_json::to_value(duplicate)?,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response_json(response).await?;
    assert_eq!(
        body["message"],
        "Failed to create runtime key (unique constraint?)"
    );
    capacity_unchanged(pool, env, &before).await?;
    let next = capacity_create_request(env, usage, "next-1", false)?;
    capacity_create_http(&app, env, &sid, &next).await?;
    let activate = serde_json::to_value(capacity_activate_request(env, usage))?;
    if activate_next {
        let response = capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys/activateNext",
            activate.clone(),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        capacity_loaded(pool, env, usage, "next-1", 4).await?;
        let next = capacity_create_request(env, usage, "next-2", false)?;
        capacity_create_http(&app, env, &sid, &next).await?;
    } else {
        let req = capacity_create_request(env, usage, "last-slot", true)?;
        capacity_create_http(&app, env, &sid, &req).await?;
        capacity_loaded(pool, env, usage, "last-slot", 4).await?;
    }
    let create = serde_json::to_value(capacity_create_request(env, usage, "refused", true)?)?;
    for (suffix, value) in [
        ("runtimeKeys", create),
        ("runtimeKeys/activateNext", activate.clone()),
    ] {
        let before = configuration_transition_snapshot(pool, env).await?;
        capacity_refused(
            capacity_post(&app, env, &sid, suffix, value.clone()).await?,
            usage,
        )
        .await?;
        capacity_unchanged(pool, env, &before).await?;
        capacity_http_controls(&app, pool, env, (&sid, &nonmember), suffix, value).await?;
    }
    capacity_revoke_active(&app, pool, env, &sid, usage).await?;
    let first = capacity_create_request(env, usage, "no-predecessor", true)?;
    capacity_create_http(&app, env, &sid, &first).await?;
    capacity_loaded(pool, env, usage, "no-predecessor", 4).await?;
    capacity_revoke_active(&app, pool, env, &sid, usage).await?;
    let response = capacity_post(&app, env, &sid, "runtimeKeys/activateNext", activate).await?;
    assert_eq!(response.status(), StatusCode::OK);
    capacity_loaded(
        pool,
        env,
        usage,
        if activate_next { "next-2" } else { "next-1" },
        4,
    )
    .await?;
    capacity_expiry_frees_slot(&app, pool, env, &sid, usage).await
}

async fn capacity_http_controls(
    app: &axum::Router,
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    sessions: (&str, &str),
    suffix: &str,
    value: serde_json::Value,
) -> TestResult {
    let before = configuration_transition_snapshot(pool, env).await?;
    let response = capacity_post(app, env, sessions.1, suffix, value.clone()).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    sqlx::query("UPDATE aegaeon.team_memberships SET role='AUDITOR' WHERE team_id=$1 AND administrator_id=$2")
        .bind(env.team_id).bind(env.administrator_id).execute(pool).await?;
    let forbidden = capacity_post(app, env, sessions.0, suffix, value.clone()).await;
    sqlx::query(
        "UPDATE aegaeon.team_memberships SET role='OWNER' WHERE team_id=$1 AND administrator_id=$2",
    )
    .bind(env.team_id)
    .bind(env.administrator_id)
    .execute(pool)
    .await?;
    assert_eq!(forbidden?.status(), StatusCode::FORBIDDEN);
    let mut wrong_base = value.clone();
    wrong_base["baseConfigurationVersionId"] = serde_json::json!(Uuid::new_v4());
    let response = capacity_post(app, env, sessions.0, suffix, wrong_base).await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = response_json(response).await?;
    assert_eq!(body["errorCode"], "base_version_mismatch");
    let mut request = membership_http_request(Method::POST, env, suffix, sessions.0, value)?;
    *request.uri_mut() = format!(
        "/api/v1/teams/{}/environments/{}/{suffix}",
        env.team_id,
        Uuid::new_v4()
    )
    .parse()?;
    let response = app.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    capacity_unchanged(pool, env, &before).await
}

async fn capacity_expiry_frees_slot(
    app: &axum::Router,
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    sid: &str,
    usage: crate::runtime_keys::RuntimeKeyUsage,
) -> TestResult {
    // Fixture-only deadline change, preserving the complete expired row afterwards.
    let expired: serde_json::Value = sqlx::query_scalar("UPDATE aegaeon.runtime_keys r SET retiring_expires_at=now()-interval '1 second' WHERE environment_id=$1 AND kid='seed-0' RETURNING to_jsonb(r)")
        .bind(env.environment_id).fetch_one(pool).await?;
    let req = capacity_create_request(env, usage, "after-expiry", true)?;
    capacity_create_http(app, env, sid, &req).await?;
    capacity_loaded(pool, env, usage, "after-expiry", 4).await?;
    let after: serde_json::Value = sqlx::query_scalar(
        "SELECT to_jsonb(r) FROM aegaeon.runtime_keys r WHERE environment_id=$1 AND kid='seed-0'",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    assert!(expired == after, "rotation changed expired history");
    Ok(())
}
