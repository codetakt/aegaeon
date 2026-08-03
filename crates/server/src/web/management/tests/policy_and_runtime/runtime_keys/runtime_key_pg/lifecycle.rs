
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_runtime_key_lifecycle_transitions_and_audits_public_metadata() -> TestResult {
    let Some(pool) = runtime_key_test_pg_pool().await? else {
        return Ok(());
    };
    let _guard = crate::util::KEY_ENCRYPTION_KEY_ASYNC_ENV_GUARD
        .lock()
        .await;
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

        let activate_req = ActivateRuntimeKeyRequest {
            base_configuration_version_id: env.configuration_version_id.to_string(),
            usage: "OIDC_ID_TOKEN_SIGNING".to_string(),
            comment: Some("promote next".to_string()),
        };
        let activated = activate_next_runtime_key_inner(
            &pool,
            &path,
            &activate_req,
            &session,
            "req-activate",
        )
        .await
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
