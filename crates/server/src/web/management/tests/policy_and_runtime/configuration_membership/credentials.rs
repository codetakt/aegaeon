async fn assert_membership_credentials(
    pool: &sqlx::PgPool,
    env: &RuntimeKeyTestEnvironment,
) -> TestResult {
    use crate::kms::KeyManager;
    let revision =
        crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
            pool,
            &env.issuer_host,
        )
        .await
        .map_err(|err| io::Error::other(format!("runtime revision: {err:?}")))?;
    let projection = crate::runtime_clients::load_runtime_client_projection_from_database_guarded(
        pool,
        &env.issuer_host,
        &revision,
    )
    .await
    .map_err(|err| io::Error::other(format!("runtime clients: {err:?}")))?;
    let registry = crate::client_registry::ClientRegistry::new_process_local_for_tests();
    projection
        .into_commit()
        .try_commit(&registry)
        .map_err(|err| io::Error::other(format!("runtime registry: {err:?}")))?;
    assert!(registry.is_registered_client("bound"));
    assert!(!registry.is_registered_client("deleted"));
    assert!(!registry.is_registered_client("historical"));
    let credentials = registry.client_secret_credentials("bound");
    assert!(crate::client_registry::verify_client_secret_credentials(
        "current-test-secret",
        &credentials
    ));
    for secret in [
        "expired-test-secret",
        "revoked-test-secret",
        "wrong-test-secret",
    ] {
        assert!(!crate::client_registry::verify_client_secret_credentials(
            secret,
            &credentials
        ));
    }
    let mut tx = pool.begin().await?;
    let keys = crate::runtime_keys::load_runtime_key_set_for_environment_in_tx(
        &mut tx,
        env.environment_id,
    )
    .await?;
    tx.commit().await?;
    let key = crate::kms::ManagedJwtKeyManager::try_from_runtime_keys(
        &keys,
        crate::runtime_keys::RuntimeKeyUsage::JwtAccessTokenSigning,
    )?;
    let signature = key.sign(b"configuration-membership-test")?;
    assert!(key.verify(b"configuration-membership-test", &signature)?);
    assert!(!key.verify(b"changed-test-message", &signature)?);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_policy_patch_preserves_signing_and_client_secret_provenance() -> TestResult {
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _key_env = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x69u8; 32]));
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        sqlx::query("UPDATE aegaeon.clients SET client_type='CONFIDENTIAL', token_endpoint_authentication_method='client_secret_basic' WHERE environment_id=$1 AND client_identifier='bound'")
            .bind(env.environment_id).execute(&pool).await?;
        for (secret, status, expired) in [
            ("current-test-secret", "ACTIVE", false),
            ("expired-test-secret", "ACTIVE", true),
            ("revoked-test-secret", "REVOKED", false),
        ] {
            let hash = crate::local_credentials::hash_password(secret).map_err(io::Error::other)?;
            sqlx::query("INSERT INTO aegaeon.client_secrets (environment_id,client_id,configuration_version_id,secret_hash,status,expires_at)
                SELECT environment_id,id,configuration_version_id,$2,$3::aegaeon.client_secret_status,
                    now() + CASE WHEN $4 THEN interval '-1 day' ELSE interval '1 day' END
                FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier='bound'")
                .bind(env.environment_id).bind(hash).bind(status).bind(expired).execute(&pool).await?;
        }
        let key_data = aegaeon_crypto::signing::Ed25519SigningKey::generate()
            .map_err(|_| io::Error::other("test key generation failed"))?;
        let mut req = runtime_key_create_request("JWT_ACCESS_TOKEN_SIGNING");
        req.base_configuration_version_id = env.configuration_version_id.to_string();
        req.private_key_pem = Some(pkcs8_private_key_pem(key_data.pkcs8));
        let session = crate::web::management::state::ManagementSession::human(env.administrator_id,1);
        create_runtime_key_inner(&pool, &runtime_key_test_path(&env), &req, &session, "membership-key").await
            .map_err(|_| io::Error::other("runtime key import failed"))?;
        assert_membership_credentials(&pool, &env).await?;
        let before = configuration_membership_snapshot(&pool, env.environment_id).await?;
        let mgmt = test_management_state();
        let sid = mgmt.sessions.create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
            .ok_or_else(|| io::Error::other("session creation failed"))?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        let response = app.clone().oneshot(membership_http_request(Method::PATCH, &env, "policies", &sid,
            serde_json::json!({"baseConfigurationVersionId":env.configuration_version_id,"accessTokenTimeToLiveSeconds":300}))?).await?;
        let status = response.status(); let value = response_json(response).await?;
        assert_eq!(status,StatusCode::OK,"{value}");
        let next: Uuid = sqlx::query_scalar("SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_membership_credentials(&pool, &env).await?;
        assert_eq!(configuration_membership_snapshot(&pool, env.environment_id).await?,
            expected_configuration_membership(&before,env.configuration_version_id,next));
        let explicit = membership_version(&pool, &env, 4, "DRAFT").await?;
        let before_explicit = configuration_membership_snapshot(&pool, env.environment_id).await?;
        for _ in 0..2 {
            let response = app.clone().oneshot(membership_http_request(Method::POST, &env,
                &format!("configurationVersions/{explicit}/activate"), &sid, serde_json::json!({"allowSecurityDowngrade":true,"reason":"restore draft TTL in activation credential test"}))?).await?;
            let status = response.status(); let value = response_json(response).await?;
            assert_eq!(status, StatusCode::OK, "explicit activation: {value}");
            assert_membership_credentials(&pool, &env).await?;
            assert_eq!(configuration_membership_snapshot(&pool, env.environment_id).await?,
                expected_configuration_membership(&before_explicit, next, explicit));
        }
        Ok(())
    }.await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_configuration_membership_sql_failure_rolls_back_all_rows() -> TestResult {
    use super::configuration_version_store::switch_active_configuration_version;
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool,&env).await?;
        let next = membership_version(&pool,&env,3,"DRAFT").await?;
        let before = configuration_transition_snapshot(&pool,&env).await?;
        let mut tx = pool.begin().await?;
        // Transaction-local fault injection after earlier membership updates.
        // The trigger creation is rolled back and never published to other sessions.
        sqlx::raw_sql("CREATE FUNCTION pg_temp.reject_membership_update() RETURNS trigger LANGUAGE plpgsql AS
            $$ BEGIN RAISE EXCEPTION 'injected membership write failure'; END $$;
            CREATE TRIGGER membership_write_failure BEFORE UPDATE OF configuration_version_id ON aegaeon.connections
            FOR EACH ROW EXECUTE FUNCTION pg_temp.reject_membership_update();")
            .execute(&mut *tx).await?;
        let result = switch_active_configuration_version(&mut tx,env.environment_id,env.configuration_version_id,next,"membership-failure").await;
        assert!(matches!(result,Err(ref r) if r.status()==StatusCode::INTERNAL_SERVER_ERROR));
        tx.rollback().await?;
        let active: Uuid = sqlx::query_scalar("SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1")
            .bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(active,env.configuration_version_id);
        assert_eq!(configuration_transition_snapshot(&pool,&env).await?,before);
        assert_configuration_runtime_members(&pool,&env).await?;
        Ok(())
    }.await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_policy_patch_audit_failure_rolls_back_configuration() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool,&env).await?;
        let before = configuration_transition_snapshot(&pool,&env).await?;
        let mgmt = test_management_state();
        let sid = mgmt.sessions.create(env.administrator_id,crate::util::now_unix_epoch_secs()?)
            .ok_or_else(||io::Error::other("session creation failed"))?;
        let app = super::super::build_router(test_app_state(pool.clone(),mgmt)?);
        let request = membership_http_request(Method::PATCH,&env,"policies",&sid,
            serde_json::json!({"baseConfigurationVersionId":env.configuration_version_id,"accessTokenTimeToLiveSeconds":300}))?;
        // A fixture-specific constraint makes the final audit write fail. Unlike
        // mocking, the handler must roll back its real PostgreSQL transaction.
        let constraint = format!("membership_audit_{}",env.environment_id.simple());
        sqlx::query(&format!("ALTER TABLE aegaeon.audit_events ADD CONSTRAINT {constraint} CHECK (environment_id <> '{}') NOT VALID",env.environment_id))
            .execute(&pool).await?;
        let response = app.oneshot(request).await;
        sqlx::query(&format!("ALTER TABLE aegaeon.audit_events DROP CONSTRAINT {constraint}"))
            .execute(&pool).await?;
        let response = response?;
        assert_eq!(response.status(),StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(management_error_response_body(response).await?.error_code,"audit_failure");
        assert_eq!(configuration_transition_snapshot(&pool,&env).await?,before);
        assert_configuration_runtime_members(&pool,&env).await?;
        Ok(())
    }.await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}
