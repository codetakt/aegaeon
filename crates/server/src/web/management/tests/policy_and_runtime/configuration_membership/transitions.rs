#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_policy_patch_preserves_configuration_membership() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        assert_configuration_runtime_members(&pool, &env).await?;
        let before = configuration_membership_snapshot(&pool, env.environment_id).await?;
        let mgmt = test_management_state();
        let sid = mgmt
            .sessions
            .create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
            .ok_or_else(|| io::Error::other("session creation failed"))?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        let request = serde_json::json!({
            "baseConfigurationVersionId": env.configuration_version_id,
            "accessTokenTimeToLiveSeconds": 300
        });
        let response = app
            .clone()
            .oneshot(membership_http_request(
                Method::PATCH,
                &env,
                "policies",
                &sid,
                request.clone(),
            )?)
            .await?;
        let status = response.status();
        let value = response_json(response).await?;
        assert_eq!(status, StatusCode::OK, "{value}");
        let next: Uuid = sqlx::query_scalar(
            "SELECT active_configuration_version_id FROM aegaeon.environments WHERE id=$1",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        assert_ne!(next, env.configuration_version_id);
        // This reader is the production path that reported 'oauth profile is required'.
        assert_configuration_runtime_members(&pool, &env)
            .await
            .map_err(|err| {
                io::Error::other(format!("runtime after successful HTTP policy PATCH: {err}"))
            })?;
        assert_eq!(
            configuration_membership_snapshot(&pool, env.environment_id).await?,
            expected_configuration_membership(&before, env.configuration_version_id, next)
        );
        let stale = app
            .oneshot(membership_http_request(
                Method::PATCH,
                &env,
                "policies",
                &sid,
                request,
            )?)
            .await?;
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        Ok(())
    }
    .await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_explicit_activation_preserves_configuration_membership() -> TestResult {
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        let next = membership_version(&pool, &env, 3, "DRAFT").await?;
        let before = configuration_membership_snapshot(&pool, env.environment_id).await?;
        assert_configuration_runtime_members(&pool, &env).await?;
        let mgmt = test_management_state();
        let sid = mgmt
            .sessions
            .create(env.administrator_id, crate::util::now_unix_epoch_secs()?)
            .ok_or_else(|| io::Error::other("session creation failed"))?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        for _ in 0..2 {
            let response = app
                .clone()
                .oneshot(membership_http_request(
                    Method::POST,
                    &env,
                    &format!("configurationVersions/{next}/activate"),
                    &sid,
                    serde_json::json!({}),
                )?)
                .await?;
            let status = response.status();
            let value = response_json(response).await?;
            assert_eq!(status, StatusCode::OK, "{value}");
            assert_configuration_runtime_members(&pool, &env)
                .await
                .map_err(|err| {
                    io::Error::other(format!(
                        "runtime after successful HTTP explicit activation: {err}"
                    ))
                })?;
        }
        assert_eq!(
            configuration_membership_snapshot(&pool, env.environment_id).await?,
            expected_configuration_membership(&before, env.configuration_version_id, next)
        );
        Ok(())
    }
    .await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_configuration_switch_rejects_stale_base_and_destination_members() -> TestResult {
    use super::configuration_version_store::switch_active_configuration_version;
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        let next = membership_version(&pool, &env, 3, "DRAFT").await?;
        // Each table independently prevents importing unexplained destination authority.
        for table in ["clients", "oauth_profiles", "connections"] {
            let mut tx = pool.begin().await?;
            sqlx::query(&format!("UPDATE aegaeon.{table} SET configuration_version_id=$1 WHERE environment_id=$2 AND name='historical'"))
                .bind(next).bind(env.environment_id).execute(&mut *tx).await?;
            let response = switch_active_configuration_version(&mut tx, env.environment_id,
                env.configuration_version_id, next, "dirty-target").await;
            assert!(matches!(response, Err(ref r) if r.status() == StatusCode::CONFLICT),
                "live target members in {table} must reject activation");
            tx.rollback().await?;
        }
        let before = configuration_membership_snapshot(&pool, env.environment_id).await?;
        let mut tx = pool.begin().await?;
        let response = switch_active_configuration_version(&mut tx, env.environment_id,
            Uuid::new_v4(), next, "stale-base").await;
        assert!(matches!(response, Err(ref r) if r.status() == StatusCode::CONFLICT));
        tx.rollback().await?;
        assert_eq!(configuration_membership_snapshot(&pool, env.environment_id).await?, before);
        Ok(())
    }.await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_dcr_registration_waiting_for_activation_uses_current_version() -> TestResult {
    use super::configuration_version_store::switch_active_configuration_version;
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        let next = membership_version(&pool, &env, 3, "DRAFT").await?;
        let mut tx = pool.begin().await?;
        super::load_locked_environment_mutation_context(&mut tx, env.team_id, env.environment_id, "dcr-activation").await
            .map_err(|_| io::Error::other("environment lock failed"))?;
        switch_active_configuration_version(&mut tx, env.environment_id, env.configuration_version_id, next, "dcr-activation").await
            .map_err(|_| io::Error::other("activation failed"))?;
        let client = crate::client_registry::RegisteredClient {
            client_id: "concurrent-dcr".into(), client_secret: None,
            redirect_uris: vec!["https://client.example/callback".into()],
            post_logout_redirect_uris: vec![], backchannel_logout_uri: None,
            backchannel_logout_session_required: false, token_endpoint_auth_method: "none".into(),
            jwks_pem: None, inline_jwks: None, jwks_uri: None,
            token_endpoint_auth_signing_alg: None, allowed_scopes: vec!["openid".into()],
            allowed_grant_types: vec!["authorization_code".into()],
            registration_access_token: Some("test-only-registration-token".into()),
            client_id_issued_at: Some(crate::util::now_unix_epoch_secs()?),
        };
        let task_pool = pool.clone();
        let host = env.issuer_host.clone();
        let mut task = tokio::spawn(async move {
            crate::dcr_persistence::create_dynamic_registration(&task_pool, &host,
                &client, &["code".into()], "test-only-registration-token", "concurrent-dcr").await
        });
        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity
                     WHERE datname=current_database() AND wait_event_type='Lock'
                       AND pg_backend_pid()=ANY(pg_blocking_pids(pid)))"
                ).fetch_one(&mut *tx).await?;
                if blocked { return Ok::<_,sqlx::Error>(()); }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await;
        if !matches!(observed, Ok(Ok(()))) {
            task.abort();
            let _ = task.await;
            tx.rollback().await?;
            return Err(io::Error::other("DCR did not demonstrably block on activation").into());
        }
        if let Err(err) = tx.commit().await {
            task.abort();
            let _ = task.await;
            return Err(err.into());
        }
        let joined = match tokio::time::timeout(std::time::Duration::from_secs(5), &mut task).await {
            Ok(result) => result?,
            Err(_) => {
                task.abort();
                let _ = task.await;
                return Err(io::Error::other("DCR timed out after activation").into());
            }
        };
        joined.map_err(|err| io::Error::other(format!("DCR failed after activation: {err:?}")))?;
        let actual: Uuid = sqlx::query_scalar(
            "SELECT configuration_version_id FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier='concurrent-dcr'"
        ).bind(env.environment_id).fetch_one(&pool).await?;
        assert_eq!(actual, next, "successful registration must not be stranded in the archived version");
        crate::oauth_profile::resolve_downstream_profile(&pool, &format!("https://{}",env.issuer_host), "concurrent-dcr").await
            .map_err(|err| io::Error::other(format!("registered runtime client: {err:?}")))?;
        Ok(())
    }.await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test]
#[ignore = "requires isolated AEGAEON_DATABASE_URL-backed PostgreSQL"]
async fn pg_configuration_switch_preserves_members_and_rolls_back() -> TestResult {
    use super::configuration_version_store::switch_active_configuration_version;
    let pool = membership_test_pool().await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let other = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        seed_configuration_members(&pool, &env).await?;
        seed_configuration_members(&pool, &other).await?;
        let before = configuration_membership_snapshot(&pool, env.environment_id).await?;
        let other_before = configuration_membership_snapshot(&pool, other.environment_id).await?;
        let next = membership_version(&pool, &env, 3, "DRAFT").await?;
        for commit in [false, true] {
            let mut tx = pool.begin().await?;
            super::load_locked_environment_mutation_context(
                &mut tx,
                env.team_id,
                env.environment_id,
                "membership-switch",
            )
            .await
            .map_err(|_| io::Error::other("environment lock failed"))?;
            switch_active_configuration_version(
                &mut tx,
                env.environment_id,
                env.configuration_version_id,
                next,
                "membership-switch",
            )
            .await
            .map_err(|_| io::Error::other("configuration switch failed"))?;
            if commit {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            let after = configuration_membership_snapshot(&pool, env.environment_id).await?;
            assert_eq!(
                after,
                if commit {
                    expected_configuration_membership(&before, env.configuration_version_id, next)
                } else {
                    before.clone()
                }
            );
            assert_configuration_runtime_members(&pool, &env).await?;
            assert_eq!(
                configuration_membership_snapshot(&pool, other.environment_id).await?,
                other_before
            );
        }
        Ok(())
    }
    .await;
    let cleanup = cleanup_configuration_members(&pool, &env).await;
    let cleanup_other = cleanup_configuration_members(&pool, &other).await;
    finish_runtime_key_pg_test(finish_runtime_key_pg_test(result, cleanup), cleanup_other)
}
