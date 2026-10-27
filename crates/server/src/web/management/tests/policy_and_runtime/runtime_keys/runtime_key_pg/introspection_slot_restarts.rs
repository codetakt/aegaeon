#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_introspection_slots_http_restart_requests_target_only_served_issuer() -> TestResult {
    let pool = capacity_pg_pool().await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _kek = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61; 32]));
    for algorithm in ["RS256", "EdDSA"] {
        for served in [true, false] {
            for operation in ["create-next", "create-active", "activate", "revoke"] {
                let env = setup_runtime_key_test_environment(&pool).await?;
                let result = slot_restart_scenario(&pool, &env, algorithm, served, operation).await;
                let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
                finish_runtime_key_pg_test(result, cleanup)?;
            }
        }
    }
    Ok(())
}

async fn slot_restart_scenario(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    algorithm: &str,
    served: bool,
    operation: &str,
) -> TestResult {
    let path = runtime_key_test_path(env);
    let session = crate::web::management::state::ManagementSession::human(env.administrator_id, 1);
    let seed = create_runtime_key_inner(
        pool,
        &path,
        &slot_create_request(env, algorithm, "seed", operation != "activate")?,
        &session,
        "restart-seed",
    )
    .await
    .map_err(|_| "seed")?;
    let mgmt = test_management_state();
    let sid = mgmt
        .sessions
        .create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
        .ok_or("session")?;
    let mut state = test_app_state(pool.clone(), mgmt)?;
    state.runtime_authority =
        crate::web::RuntimeAuthorityState::new_process_local_for_tests(if served {
            env.issuer_host.clone()
        } else {
            "other.example.com".into()
        });
    let restart = state.runtime_restart.clone();
    let app = super::super::build_router(state);
    let (suffix, body, expected) = match operation {
        "activate" => {
            let mut req = capacity_activate_request(
                env,
                crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning,
            );
            req.algorithm = Some(algorithm.into());
            (
                "runtimeKeys/activateNext".into(),
                serde_json::to_value(req)?,
                StatusCode::OK,
            )
        }
        "revoke" => (
            format!("runtimeKeys/{}/revoke", seed.runtime_key.id),
            serde_json::json!({"baseConfigurationVersionId":env.configuration_version_id}),
            StatusCode::OK,
        ),
        _ => (
            "runtimeKeys".into(),
            serde_json::to_value(slot_create_request(
                env,
                algorithm,
                "created",
                operation == "create-active",
            )?)?,
            StatusCode::CREATED,
        ),
    };
    assert_eq!(
        capacity_post(&app, env, &sid, &suffix, body)
            .await?
            .status(),
        expected
    );
    assert_eq!(restart.is_requested(), served && operation != "create-next");
    // This exercises actual handler restart requests, not process supervision/recovery.
    Ok(())
}
