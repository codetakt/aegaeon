fn slot_create_request(
    env: &RuntimeKeyTestEnvironment,
    algorithm: &str,
    kid: &str,
    activate: bool,
) -> Result<CreateRuntimeKeyRequest, Box<dyn StdError>> {
    let mut req = capacity_create_request(
        env,
        crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning,
        kid,
        activate,
    )?;
    req.algorithm = Some(algorithm.into());
    if algorithm == "RS256" {
        req.private_key_pem = Some(TEST_RSA_PRIVATE_KEY_PEM.into());
    }
    Ok(req)
}

async fn slot_rows(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    algorithm: &str,
) -> Result<Vec<serde_json::Value>, Box<dyn StdError>> {
    Ok(sqlx::query_scalar("SELECT to_jsonb(r) FROM aegaeon.runtime_keys r WHERE environment_id=$1 AND usage='JWT_INTROSPECTION_SIGNING' AND algorithm=$2 ORDER BY id")
        .bind(env.environment_id).bind(algorithm).fetch_all(pool).await?)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_introspection_slots_http_selection_history_and_capacity() -> TestResult {
    let pool = capacity_pg_pool().await?;
    crate::db::preflight_required_schema_revision(&pool).await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _kek = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61; 32]));
    for first in ["RS256", "EdDSA"] {
        let env = setup_runtime_key_test_environment(&pool).await?;
        let result = slot_http_scenario(&pool, &env, first).await;
        let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
        finish_runtime_key_pg_test(result, cleanup)?;
    }
    Ok(())
}

async fn slot_http_scenario(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
    first: &str,
) -> TestResult {
    let other = if first == "RS256" { "EdDSA" } else { "RS256" };
    let usage = crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning;
    let mgmt = test_management_state();
    let now = crate::util::now_unix_epoch_secs()?;
    let sid = mgmt
        .sessions
        .create(env.administrator_id, now)
        .ok_or("session")?;
    let nonmember = mgmt
        .sessions
        .create(env.non_member_administrator_id, now)
        .ok_or("session")?;
    let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
    for (alg, kid) in [(first, "first-active"), (other, "other-active")] {
        capacity_create_http(&app, env, &sid, &slot_create_request(env, alg, kid, true)?).await?;
        capacity_create_http(
            &app,
            env,
            &sid,
            &slot_create_request(env, alg, &format!("{kid}-next"), false)?,
        )
        .await?;
    }
    let invalid_before = configuration_transition_snapshot(pool, env).await?;
    let valid = slot_create_request(env, "RS256", "invalid-control", true)?;
    capacity_http_controls(
        &app,
        pool,
        env,
        (&sid, &nonmember),
        "runtimeKeys",
        serde_json::to_value(&valid)?,
    )
    .await?;
    for mutation in ["provider", "algorithm", "material"] {
        let mut invalid = valid.clone();
        match mutation {
            "provider" => invalid.provider = "awsKms".into(),
            "algorithm" => invalid.algorithm = Some("PS256".into()),
            _ => invalid.private_key_pem = Some("malformed".into()),
        }
        assert_eq!(
            capacity_post(
                &app,
                env,
                &sid,
                "runtimeKeys",
                serde_json::to_value(invalid)?
            )
            .await?
            .status(),
            StatusCode::BAD_REQUEST
        );
        capacity_unchanged(pool, env, &invalid_before).await?;
    }
    sqlx::query("UPDATE aegaeon.environment_policies SET allowed_signing_algorithms=ARRAY['EdDSA'] WHERE environment_id=$1").bind(env.environment_id).execute(pool).await?;
    let restricted = configuration_transition_snapshot(pool, env).await?;
    let response =
        capacity_post(&app, env, &sid, "runtimeKeys", serde_json::to_value(valid)?).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    capacity_unchanged(pool, env, &restricted).await?;
    sqlx::query("UPDATE aegaeon.environment_policies SET allowed_signing_algorithms=ARRAY['RS256','EdDSA'] WHERE environment_id=$1").bind(env.environment_id).execute(pool).await?;
    let before = configuration_transition_snapshot(pool, env).await?;
    let mut activate = serde_json::to_value(capacity_activate_request(env, usage))?;
    let response = capacity_post(
        &app,
        env,
        &sid,
        "runtimeKeys/activateNext",
        activate.clone(),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = response_json(response).await?;
    assert_eq!(body["errorCode"], "invalid_request");
    assert_eq!(
        body["details"]["allowedAlgorithms"],
        serde_json::json!(["RS256", "EdDSA"])
    );
    capacity_unchanged(pool, env, &before).await?;
    let other_before = slot_rows(pool, env, other).await?;
    activate["algorithm"] = serde_json::json!(first.to_ascii_lowercase());
    capacity_http_controls(
        &app,
        pool,
        env,
        (&sid, &nonmember),
        "runtimeKeys/activateNext",
        activate.clone(),
    )
    .await?;
    let response = capacity_post(
        &app,
        env,
        &sid,
        "runtimeKeys/activateNext",
        activate.clone(),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        other_before == slot_rows(pool, env, other).await?,
        "other slot changed"
    );
    // Explicit selector must not activate the sole NEXT of the other algorithm.
    let before = configuration_transition_snapshot(pool, env).await?;
    assert_eq!(
        capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys/activateNext",
            activate.clone()
        )
        .await?
        .status(),
        StatusCode::NOT_FOUND
    );
    capacity_unchanged(pool, env, &before).await?;
    activate
        .as_object_mut()
        .ok_or("object")?
        .remove("algorithm");
    assert_eq!(
        capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys/activateNext",
            activate.clone()
        )
        .await?
        .status(),
        StatusCode::OK
    );
    assert_eq!(
        runtime_key_status(pool, env.environment_id, "other-active").await?,
        "RETIRING"
    );
    // Two live retirements now. An insertion failure after retirement is atomic.
    let before = configuration_transition_snapshot(pool, env).await?;
    let duplicate = slot_create_request(env, first, "first-active", true)?;
    assert_eq!(
        capacity_post(
            &app,
            env,
            &sid,
            "runtimeKeys",
            serde_json::to_value(duplicate)?
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    capacity_unchanged(pool, env, &before).await?;
    for index in 0..2 {
        capacity_create_http(
            &app,
            env,
            &sid,
            &slot_create_request(env, first, &format!("rotate-{index}"), true)?,
        )
        .await?;
    }
    let before = configuration_transition_snapshot(pool, env).await?;
    for alg in [first, other] {
        let req = slot_create_request(env, alg, &format!("refused-{alg}"), true)?;
        capacity_refused(
            capacity_post(&app, env, &sid, "runtimeKeys", serde_json::to_value(req)?).await?,
            usage,
        )
        .await?;
        capacity_unchanged(pool, env, &before).await?;
    }
    // Exact emergency revoke leaves the other ACTIVE and all history unchanged.
    let other_before = slot_rows(pool, env, other).await?;
    let id: Uuid = sqlx::query_scalar(
        "SELECT id FROM aegaeon.runtime_keys WHERE environment_id=$1 AND kid='rotate-1'",
    )
    .bind(env.environment_id)
    .fetch_one(pool)
    .await?;
    let response = capacity_post(
        &app,
        env,
        &sid,
        &format!("runtimeKeys/{id}/revoke"),
        serde_json::json!({"baseConfigurationVersionId":env.configuration_version_id}),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        other_before == slot_rows(pool, env, other).await?,
        "revoke changed other slot"
    );
    // Four retirements plus another algorithm ACTIVE still allows first key in empty slot.
    capacity_create_http(
        &app,
        env,
        &sid,
        &slot_create_request(env, first, "no-predecessor", true)?,
    )
    .await?;
    let mut tx = pool.begin().await?;
    let keys = crate::runtime_keys::load_runtime_key_set_for_environment_in_tx(
        &mut tx,
        env.environment_id,
    )
    .await?;
    assert_eq!(keys.active_keys(usage).count(), 2);
    assert_eq!(keys.retiring_keys(usage).count(), 4);
    for algorithm in [
        crate::runtime_keys::RuntimeKeyAlgorithm::Rs256,
        crate::runtime_keys::RuntimeKeyAlgorithm::EdDsa,
    ] {
        let manager = crate::kms::ManagedJwtKeyManager::try_from_runtime_keys_for_algorithm(
            &keys, usage, algorithm,
        )?;
        let sig = crate::kms::KeyManager::sign(&manager, b"loaded")?;
        assert!(crate::kms::KeyManager::verify(&manager, b"loaded", &sig)?);
    }
    tx.rollback().await?;
    let expired: serde_json::Value = sqlx::query_scalar("UPDATE aegaeon.runtime_keys r SET retiring_expires_at=now()-interval '1 second' WHERE environment_id=$1 AND kid='first-active' RETURNING to_jsonb(r)").bind(env.environment_id).fetch_one(pool).await?;
    capacity_create_http(
        &app,
        env,
        &sid,
        &slot_create_request(env, other, "after-expiry", true)?,
    )
    .await?;
    let after: serde_json::Value=sqlx::query_scalar("SELECT to_jsonb(r) FROM aegaeon.runtime_keys r WHERE environment_id=$1 AND kid='first-active'").bind(env.environment_id).fetch_one(pool).await?;
    assert!(expired == after, "rotation altered expired history");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_introspection_slots_audit_failure_and_existing_overflow_are_atomic() -> TestResult {
    let pool = capacity_pg_pool().await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _kek = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61; 32]));
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let path=runtime_key_test_path(&env);
        let session=crate::web::management::state::ManagementSession::human(env.administrator_id,1);
        for (alg,kid,active) in [("RS256","rsa",true),("EdDSA","ed",true),("RS256","next",false)] {
            create_runtime_key_inner(&pool,&path,&slot_create_request(&env,alg,kid,active)?,&session,"slot-seed").await.map_err(|_|"seed")?;
        }
        // Test-only trigger scoped to this environment; production audit path is exercised.
        let function=format!("slot_audit_fail_{}",env.environment_id.simple());
        sqlx::raw_sql(&format!("CREATE FUNCTION aegaeon.{function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.environment_id = '{}'::uuid THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER {function} BEFORE INSERT ON aegaeon.audit_events FOR EACH ROW EXECUTE FUNCTION aegaeon.{function}();",env.environment_id)).execute(&pool).await?;
        let before=configuration_transition_snapshot(&pool,&env).await?;
        let create=create_runtime_key_inner(&pool,&path,&slot_create_request(&env,"RS256","audit-create",true)?,&session,"slot-audit-create").await;
        let mut req=capacity_activate_request(&env,crate::runtime_keys::RuntimeKeyUsage::JwtIntrospectionSigning);req.algorithm=Some("RS256".into());
        let activate=activate_next_runtime_key_inner(&pool,&path,&req,&session,"slot-audit-activate").await;
        sqlx::raw_sql(&format!("DROP TRIGGER {function} ON aegaeon.audit_events; DROP FUNCTION aegaeon.{function}();")).execute(&pool).await?;
        assert!(create.is_err() && activate.is_err());
        capacity_unchanged(&pool,&env,&before).await?;
        // Construct an already over-capacity fixture without weakening production constraints.
        sqlx::query("INSERT INTO aegaeon.runtime_keys (id,environment_id,configuration_version_id,usage,kid,algorithm,provider,status,public_jwk,key_handle,provider_configuration,retiring_expires_at) SELECT gen_random_uuid(),environment_id,configuration_version_id,usage,'overflow-'||i,algorithm,provider,'RETIRING',jsonb_set(public_jwk,'{kid}',to_jsonb('overflow-'||i)),key_handle,provider_configuration,now()+interval '1 hour' FROM aegaeon.runtime_keys CROSS JOIN generate_series(1,5) i WHERE environment_id=$1 AND kid='rsa'").bind(env.environment_id).execute(&pool).await?;
        let before=configuration_transition_snapshot(&pool,&env).await?;
        let refused=create_runtime_key_inner(&pool,&path,&slot_create_request(&env,"EdDSA","overflow-refused",true)?,&session,"slot-overflow").await;
        assert_eq!(refused.err().ok_or("must refuse")?.status(),StatusCode::CONFLICT);
        capacity_unchanged(&pool,&env,&before).await?;
        Ok(())
    }.await;
    let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}
