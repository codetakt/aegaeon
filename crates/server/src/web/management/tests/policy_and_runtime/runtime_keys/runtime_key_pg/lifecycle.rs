#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_runtime_key_lifecycle_transitions_and_audits_public_metadata() -> TestResult {
    runtime_key_lifecycle_case(false).await
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires restricted PostgreSQL and managed signing keys"]
async fn pg_runtime_key_rotation_preserves_lti_overlap_with_short_oidc_policy() -> TestResult {
    runtime_key_lifecycle_case(true).await
}

async fn runtime_key_lifecycle_case(short_oidc_policy: bool) -> TestResult {
    let pool = runtime_key_test_pg_pool().await?;
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD.lock().await;
    let _env = EnvVarGuard::set(KEY_ENCRYPTION_KEY_ENV, URL_SAFE_NO_PAD.encode([0x61u8; 32]));
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let path = runtime_key_test_path(&env);
        let session =
            crate::web::management::state::ManagementSession::human(env.administrator_id, 1);

        let active_req = CreateRuntimeKeyRequest {
            base_configuration_version_id: env.configuration_version_id.to_string(),
            usage: "OIDC_ID_TOKEN_SIGNING".to_string(),
            algorithm: None,
            provider: "databaseEncrypted".to_string(),
            kid: Some("runtime-active-1".to_string()),
            provider_configuration: None,
            private_key_pem: Some(TEST_RSA_PRIVATE_KEY_PEM.to_string()),
            activate: true,
            comment: Some("active import".to_string()),
        };
        let active = create_runtime_key_inner(
            &pool,
            &path,
            &active_req,
            &session,
            "req-active",
        )
        .await
        .map_err(|_| io::Error::other("active runtime key create failed"))?;
        assert_eq!(active.runtime_key.status, "ACTIVE");
        assert_eq!(active.runtime_key.public_jwk["kid"], "runtime-active-1");

        let next_req = CreateRuntimeKeyRequest {
            kid: Some("runtime-next-1".to_string()),
            activate: false,
            comment: Some("next import".to_string()),
            ..active_req.clone()
        };
        let next = create_runtime_key_inner(&pool, &path, &next_req, &session, "req-next")
            .await
            .map_err(|_| io::Error::other("next runtime key create failed"))?;
        assert_eq!(next.runtime_key.status, "NEXT");

        let before_activation_revision =
            crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
                &pool,
                &env.issuer_host,
            )
            .await?;

        if short_oidc_policy {
            sqlx::query("UPDATE aegaeon.environment_policies SET id_token_time_to_live_seconds=1,jwt_leeway_seconds=0 WHERE environment_id=$1")
                .bind(env.environment_id).execute(&pool).await?;
        }
        let before_rotation: i64 = sqlx::query_scalar("SELECT floor(extract(epoch from clock_timestamp()))::bigint")
            .fetch_one(&pool).await?;
        let activate_req = ActivateRuntimeKeyRequest { algorithm: None,
            base_configuration_version_id: env.configuration_version_id.to_string(),
            usage: "OIDC_ID_TOKEN_SIGNING".to_string(),
            comment: Some("promote next".to_string()),
        };
        // Hold the same Environment boundary used by an in-flight launch. A
        // rotation transaction can start before the last old-key issuance.
        let blocker = if short_oidc_policy {
            let mut tx = pool.begin().await?;
            sqlx::query("SELECT id FROM aegaeon.environments WHERE id=$1 FOR UPDATE")
                .bind(env.environment_id).execute(&mut *tx).await?;
            Some(tx)
        } else { None };
        let (activated, released_at) = tokio::join!(
            activate_next_runtime_key_inner(&pool, &path, &activate_req, &session, "req-activate"),
            release_rotation_blocker(blocker, before_rotation),
        );
        let before_rotation = released_at?;
        let activated = activated
            .map_err(|_| io::Error::other("runtime key activation failed"))?;
        assert_eq!(activated.runtime_key.kid, "runtime-next-1");
        assert_eq!(activated.runtime_key.status, "ACTIVE");
        assert_eq!(
            runtime_key_status(&pool, env.environment_id, "runtime-active-1").await?,
            "RETIRING"
        );
        assert!(
            runtime_key_retiring_expires_at(&pool, env.environment_id, "runtime-active-1")
                .await?
                .is_some(),
            "retired runtime key must have a bounded overlap expiry"
        );

        if short_oidc_policy {
            let deadline: i64 = sqlx::query_scalar("SELECT floor(extract(epoch from retiring_expires_at))::bigint FROM aegaeon.runtime_keys WHERE environment_id=$1 AND kid='runtime-active-1'")
                .bind(env.environment_id).fetch_one(&pool).await?;
            assert!(deadline >= before_rotation + crate::lti::model::TOKEN_TTL_SECONDS,
                "retired key must remain available for every unexpired LTI token");
        }

        let after_activation_revision =
            crate::runtime_configuration::load_active_runtime_configuration_revision_for_issuer_host(
                &pool,
                &env.issuer_host,
            )
            .await?;
        assert_ne!(
            before_activation_revision.active_runtime_key_set_fingerprint(),
            after_activation_revision.active_runtime_key_set_fingerprint(),
            "ACTIVE/RETIRING runtime key changes must be monitor-visible"
        );

        let revoke_req = ConfigurationTransactionRequest {
            base_configuration_version_id: env.configuration_version_id.to_string(),
            comment: Some("compromise response".to_string()),
        };
        let revoke_path = runtime_key_test_runtime_key_path(
            &env,
            Uuid::parse_str(&activated.runtime_key.id)?,
        );
        let revoked = revoke_runtime_key_inner(
            &pool,
            &revoke_path,
            &revoke_req,
            &session,
            "req-revoke",
        )
        .await
        .map_err(|_| io::Error::other("runtime key revoke failed"))?;
        assert_eq!(revoked.runtime_key.status, "REVOKED");
        assert_eq!(
            runtime_key_retiring_expires_at(&pool, env.environment_id, "runtime-next-1").await?,
            None,
            "revoked runtime key must clear RETIRING expiry"
        );

        let audit_payloads = runtime_key_audit_payloads(&pool, env.environment_id).await?;
        let audit_text = serde_json::to_string(&audit_payloads)?;
        assert!(audit_text.contains("management.runtimeKey.created.v1"));
        assert!(audit_text.contains("management.runtimeKey.activated.v1"));
        assert!(audit_text.contains("management.runtimeKey.revoked.v1"));
        assert!(!audit_text.contains("PRIVATE KEY"));
        assert!(!audit_text.contains("key_handle"));
        assert!(!audit_text.contains("keyHandle"));

        Ok(())
    }
    .await;
    let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

async fn release_rotation_blocker(
    blocker: Option<sqlx::Transaction<'_, sqlx::Postgres>>,
    before_rotation: i64,
) -> Result<i64, Box<dyn std::error::Error>> {
    let Some(mut tx) = blocker else {
        return Ok(before_rotation);
    };
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_catalog.pg_stat_activity WHERE $1=ANY(pg_catalog.pg_blocking_pids(pid)))")
                .bind(pid).fetch_one(&mut *tx).await?;
            if waiting { return Ok::<_, sqlx::Error>(()); }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await??;
    // Cross an epoch-second boundary after the blocked transaction began.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let released_at =
        sqlx::query_scalar("SELECT floor(extract(epoch from clock_timestamp()))::bigint")
            .fetch_one(&mut *tx)
            .await?;
    tx.rollback().await?;
    Ok(released_at)
}
