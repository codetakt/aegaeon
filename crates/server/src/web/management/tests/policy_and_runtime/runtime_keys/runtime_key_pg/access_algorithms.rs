fn access_create_request(
    env: &RuntimeKeyTestEnvironment,
    algorithm: &str,
    kid: &str,
    activate: bool,
) -> Result<CreateRuntimeKeyRequest, Box<dyn StdError>> {
    let mut req = capacity_create_request(
        env,
        crate::runtime_keys::RuntimeKeyUsage::JwtAccessTokenSigning,
        kid,
        activate,
    )?;
    if algorithm == "RS256" {
        req.algorithm = Some(algorithm.into());
        req.private_key_pem = Some(TEST_RSA_PRIVATE_KEY_PEM.into());
    }
    // Omission deliberately exercises existing EdDSA creation compatibility.
    Ok(req)
}

async fn access_loaded_manager(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    algorithm: &str,
) -> Result<Arc<dyn crate::kms::KeyManager>, Box<dyn StdError>> {
    let mut tx = pool.begin().await?;
    let keys = crate::runtime_keys::load_runtime_key_set_for_environment_in_tx(
        &mut tx,
        env.environment_id,
    )
    .await?;
    tx.rollback().await?;
    let manager = crate::kms::ManagedJwtKeyManager::try_from_runtime_keys(
        &keys,
        crate::runtime_keys::RuntimeKeyUsage::JwtAccessTokenSigning,
    )?;
    assert_eq!(crate::kms::KeyManager::jwt_signing_alg(&manager), algorithm);
    Ok(Arc::new(manager))
}

fn access_issued_probe(
    manager: Arc<dyn crate::kms::KeyManager>,
    issuer: &str,
) -> Result<(String, crate::authcode::store::TokenStore), Box<dyn StdError>> {
    let token_issuer = crate::authcode::TokenIssuer::new_process_local_for_tests(manager.clone())
        .with_issuer(issuer.into())
        .with_jwt_access_tokens_enabled(true);
    let response = token_issuer.issue_client_credentials_token(
        token_issuer.client_credentials_permit_for_tests(
            "caller",
            &["read".into()],
            "https://api.example/resource",
        ),
        None,
    )?;
    let crate::authcode::types::TokenResponse::Success { access_token, .. } = response else {
        return Err("actual JWT access-token issuance refused".into());
    };
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(access_token.split('.').next().ok_or("header")?)?,
    )?;
    assert_eq!(header["typ"], "at+jwt");
    assert_eq!(header["alg"], manager.jwt_signing_alg());
    assert_eq!(header["kid"], manager.key_id());
    let validator = crate::authcode::TokenValidator::new(token_issuer.token_store.clone(), manager)
        .with_issuer(Some(issuer.into()))
        .with_jwt_access_tokens_enabled(true);
    assert!(validator
        .validate_bearer_token_with_meta(&format!("Bearer {access_token}"))
        .is_ok());
    Ok((access_token, token_issuer.token_store))
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_access_algorithms_cross_rotation_restart_issuance_and_capacity() -> TestResult {
    let pool = capacity_pg_pool().await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _kek = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61; 32]));
    for initial in ["EdDSA", "RS256"] {
        let env = setup_runtime_key_test_environment(&pool).await?;
        let result = access_rotation_scenario(&pool, &env, initial).await;
        finish_runtime_key_pg_test(
            result,
            cleanup_runtime_key_test_environment(&pool, &env).await,
        )?;
    }
    Ok(())
}

async fn access_rotation_scenario(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    initial: &str,
) -> TestResult {
    let other = if initial == "RS256" { "EdDSA" } else { "RS256" };
    let usage = crate::runtime_keys::RuntimeKeyUsage::JwtAccessTokenSigning;
    let mgmt = test_management_state();
    let sid = mgmt
        .sessions
        .create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
        .ok_or("session")?;
    let mut state = test_app_state(pool.clone(), mgmt.clone())?;
    state.runtime_authority =
        crate::web::RuntimeAuthorityState::new_process_local_for_tests(env.issuer_host.clone());
    let restart = state.runtime_restart.clone();
    let app = super::super::build_router(state);
    capacity_create_http(
        &app,
        env,
        &sid,
        &access_create_request(env, initial, "access-initial", true)?,
    )
    .await?;
    assert!(restart.is_requested());
    let issuer = format!("https://{}", env.issuer_host);
    let old = access_issued_probe(access_loaded_manager(pool, env, initial).await?, &issuer)?;

    // Reconstruct state as after a restart before exercising NEXT admission/promotion.
    let mut state = test_app_state(pool.clone(), mgmt.clone())?;
    state.runtime_authority =
        crate::web::RuntimeAuthorityState::new_process_local_for_tests(env.issuer_host.clone());
    let restart = state.runtime_restart.clone();
    let app = super::super::build_router(state);
    capacity_create_http(
        &app,
        env,
        &sid,
        &access_create_request(env, other, "access-next", false)?,
    )
    .await?;
    assert!(!restart.is_requested());
    let before = configuration_transition_snapshot(pool, env).await?;
    let duplicate_next = access_create_request(env, initial, "second-next", false)?;
    assert_eq!(
        capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys",
            serde_json::to_value(duplicate_next)?
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    capacity_unchanged(pool, env, &before).await?;
    let mut activate = capacity_activate_request(env, usage);
    activate.algorithm = Some(initial.into());
    assert_eq!(
        capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys/activateNext",
            serde_json::to_value(&activate)?
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND
    );
    capacity_unchanged(pool, env, &before).await?;
    activate.algorithm = None;
    assert_eq!(
        capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys/activateNext",
            serde_json::to_value(&activate)?
        )
        .await?
        .status(),
        StatusCode::OK
    );
    assert!(restart.is_requested());
    capacity_loaded(pool, env, usage, "access-next", 1).await?;
    assert_eq!(
        runtime_key_status(pool, env.environment_id, "access-initial").await?,
        "RETIRING"
    );
    let manager = access_loaded_manager(pool, env, other).await?;
    access_issued_probe(manager.clone(), &issuer)?;
    let overlap = crate::authcode::TokenValidator::new(old.1, manager.clone())
        .with_issuer(Some(issuer.clone()))
        .with_jwt_access_tokens_enabled(true);
    assert!(overlap
        .validate_bearer_token_with_meta(&format!("Bearer {}", old.0))
        .is_ok());
    let mut metadata_state = test_app_state(pool.clone(), test_management_state())?;
    let mut policy = base_secure_policy();
    policy.jwt_access_tokens_enabled = true;
    Arc::make_mut(&mut metadata_state.cfg).apply_management_policy(&policy)?;
    metadata_state.keys.access_token = manager;
    let metadata = crate::web::metadata::authorization_server_metadata_for_state(&metadata_state)?;
    assert_eq!(
        metadata.access_token_signing_alg_values_supported,
        Some(vec![other.into()])
    );

    // Continue mutation controls through a management node that does not serve this
    // issuer. The served node correctly becomes unavailable after requesting restart.
    let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
    // A failed insert after retiring a different algorithm must roll back state and audit.
    let before = configuration_transition_snapshot(pool, env).await?;
    assert_eq!(
        capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys",
            serde_json::to_value(access_create_request(env, initial, "access-initial", true)?)?
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    capacity_unchanged(pool, env, &before).await?;
    for (index, algorithm) in [(2, initial), (3, other), (4, initial)] {
        capacity_create_http(
            &app,
            env,
            &sid,
            &access_create_request(env, algorithm, &format!("access-{index}"), true)?,
        )
        .await?;
        capacity_loaded(pool, env, usage, &format!("access-{index}"), index).await?;
    }
    capacity_create_http(
        &app,
        env,
        &sid,
        &access_create_request(env, other, "blocked-next", false)?,
    )
    .await?;
    for (suffix, value) in [
        (
            "runtimeKeys",
            serde_json::to_value(access_create_request(env, other, "blocked-active", true)?)?,
        ),
        ("runtimeKeys/activateNext", serde_json::to_value(activate)?),
    ] {
        let before = configuration_transition_snapshot(pool, env).await?;
        capacity_refused(capacity_post(&app, env, &sid, suffix, value).await?, usage).await?;
        capacity_unchanged(pool, env, &before).await?;
    }
    Ok(())
}
