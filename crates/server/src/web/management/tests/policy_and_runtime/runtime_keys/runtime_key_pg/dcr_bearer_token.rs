#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_dcr_bearer_token_management_audits_hash_only() -> TestResult {
    let Some(pool) = runtime_key_test_pg_pool().await? else {
        return Ok(());
    };
    crate::dcr_persistence::preflight_dynamic_registration_schema(&pool).await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let scope = ManagementEnvironmentScope {
            team: env.team_id,
            tenant: env.tenant_id,
            environment: env.environment_id,
        };
        let session =
            crate::web::management::state::ManagementSession::human(env.administrator_id, 1);
        let token = "0123456789abcdef0123456789abcdef";
        let expected_hash = crate::dcr_persistence::dcr_bearer_token_hash(token);

        let status = set_dcr_bearer_token_inner(
            &pool,
            scope,
            &session,
            "req-dcr-bearer-set",
            token,
        )
        .await
        .map_err(|_| io::Error::other("DCR bearer token set failed"))?;
        assert!(status.configured);
        assert_eq!(status.hash_algorithm.as_deref(), Some("sha256"));

        let row = sqlx::query(
            r"
SELECT token_hash, token_hash_algorithm
FROM aegaeon.environment_dcr_bearer_tokens
WHERE environment_id = $1
            ",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        let stored_hash: String = row.try_get("token_hash")?;
        let stored_algorithm: String = row.try_get("token_hash_algorithm")?;
        assert_eq!(stored_hash, expected_hash);
        assert_eq!(stored_algorithm, "sha256");
        assert_ne!(stored_hash, token);

        delete_dcr_bearer_token_inner(&pool, scope, &session, "req-dcr-bearer-delete")
            .await
            .map_err(|_| io::Error::other("DCR bearer token delete failed"))?;
        delete_dcr_bearer_token_inner(
            &pool,
            scope,
            &session,
            "req-dcr-bearer-delete-empty",
        )
        .await
        .map_err(|_| io::Error::other("empty DCR bearer token delete failed"))?;

        let configured_after_delete =
            load_dcr_bearer_token_status(&pool, env.environment_id, "req-dcr-bearer-status")
                .await
                .map_err(|_| io::Error::other("DCR bearer token status load failed"))?;
        assert!(!configured_after_delete.configured);

        let audit_payloads = dcr_bearer_token_audit_payloads(&pool, env.environment_id).await?;
        let audit_text = serde_json::to_string(&audit_payloads)?;
        assert!(audit_text.contains("management.dcrBearerToken.set.v1"));
        assert!(audit_text.contains("management.dcrBearerToken.deleted.v1"));
        assert!(audit_text.contains(r#""removed":true"#));
        assert!(audit_text.contains(r#""removed":false"#));
        assert!(!audit_text.contains(token));
        assert!(!audit_text.contains(&expected_hash));
        assert!(!audit_text.contains("token_hash"));
        assert!(!audit_text.contains("tokenHash"));

        Ok(())
    }
    .await;
    let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn pg_dcr_bearer_token_management_http_api_enforces_session_csrf_and_hash_only() -> TestResult
{
    let Some(pool) = runtime_key_test_pg_pool().await? else {
        return Ok(());
    };
    crate::dcr_persistence::preflight_dynamic_registration_schema(&pool).await?;
    let env = setup_runtime_key_test_environment(&pool).await?;
    let result: TestResult = async {
        let mgmt = test_management_state();
        let now_epoch_secs = crate::util::now_unix_epoch_secs()?;
        let sid = mgmt
            .sessions
            .create(env.administrator_id, now_epoch_secs)
            .ok_or_else(|| io::Error::other("management session creation failed"))?;
        let unprivileged_sid = mgmt
            .sessions
            .create(env.non_member_administrator_id, now_epoch_secs)
            .ok_or_else(|| io::Error::other("unprivileged session creation failed"))?;
        let app = super::super::build_router(test_app_state(pool.clone(), mgmt)?);
        let csrf_token = "csrf-secret";
        let token = "0123456789abcdef0123456789abcdef";
        let expected_hash = crate::dcr_persistence::dcr_bearer_token_hash(token);

        let unauthenticated = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::PUT,
                &env,
                None,
                Some(csrf_token),
                Some(r#"{"token":"0123456789abcdef0123456789abcdef"}"#),
            )?)
            .await?;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert_no_store_and_request_id(&unauthenticated);

        let missing_csrf = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::PUT,
                &env,
                Some(&sid),
                None,
                Some(r#"{"token":"0123456789abcdef0123456789abcdef"}"#),
            )?)
            .await?;
        assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
        assert_no_store_and_request_id(&missing_csrf);

        let unauthorized = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::PUT,
                &env,
                Some(&unprivileged_sid),
                Some(csrf_token),
                Some(r#"{"token":"0123456789abcdef0123456789abcdef"}"#),
            )?)
            .await?;
        assert_eq!(unauthorized.status(), StatusCode::NOT_FOUND);
        assert_no_store_and_request_id(&unauthorized);

        let weak_token = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::PUT,
                &env,
                Some(&sid),
                Some(csrf_token),
                Some(r#"{"token":"short"}"#),
            )?)
            .await?;
        assert_eq!(weak_token.status(), StatusCode::BAD_REQUEST);
        assert_no_store_and_request_id(&weak_token);

        let set_response = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::PUT,
                &env,
                Some(&sid),
                Some(csrf_token),
                Some(r#"{"token":"0123456789abcdef0123456789abcdef"}"#),
            )?)
            .await?;
        assert_eq!(set_response.status(), StatusCode::OK);
        assert_no_store_and_request_id(&set_response);
        let set_body = response_json(set_response).await?;
        assert_eq!(set_body["environmentId"], env.environment_id.to_string());
        assert_eq!(set_body["configured"], true);
        assert_eq!(set_body["hashAlgorithm"], "sha256");
        assert!(set_body["updatedAt"].is_string());

        let row = sqlx::query(
            r"
SELECT token_hash, token_hash_algorithm
FROM aegaeon.environment_dcr_bearer_tokens
WHERE environment_id = $1
                ",
        )
        .bind(env.environment_id)
        .fetch_one(&pool)
        .await?;
        let stored_hash: String = row.try_get("token_hash")?;
        let stored_algorithm: String = row.try_get("token_hash_algorithm")?;
        assert_eq!(stored_hash, expected_hash);
        assert_eq!(stored_algorithm, "sha256");
        assert_ne!(stored_hash, token);

        let configured = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::GET,
                &env,
                Some(&sid),
                None,
                None,
            )?)
            .await?;
        assert_eq!(configured.status(), StatusCode::OK);
        assert_no_store_and_request_id(&configured);
        let configured_body = response_json(configured).await?;
        assert_eq!(configured_body["configured"], true);
        assert_eq!(configured_body["hashAlgorithm"], "sha256");

        let deleted = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::DELETE,
                &env,
                Some(&sid),
                Some(csrf_token),
                None,
            )?)
            .await?;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert_no_store_and_request_id(&deleted);

        let unconfigured = app
            .clone()
            .oneshot(dcr_bearer_token_management_request(
                Method::GET,
                &env,
                Some(&sid),
                None,
                None,
            )?)
            .await?;
        assert_eq!(unconfigured.status(), StatusCode::OK);
        assert_no_store_and_request_id(&unconfigured);
        let unconfigured_body = response_json(unconfigured).await?;
        assert_eq!(unconfigured_body["configured"], false);
        assert!(unconfigured_body.get("hashAlgorithm").is_none());

        let audit_payloads = dcr_bearer_token_audit_payloads(&pool, env.environment_id).await?;
        let audit_text = serde_json::to_string(&audit_payloads)?;
        assert!(audit_text.contains("management.dcrBearerToken.set.v1"));
        assert!(audit_text.contains("management.dcrBearerToken.deleted.v1"));
        assert!(!audit_text.contains(token));
        assert!(!audit_text.contains(&expected_hash));
        assert!(!audit_text.contains("token_hash"));
        assert!(!audit_text.contains("tokenHash"));

        Ok(())
    }
    .await;
    let cleanup = cleanup_runtime_key_test_environment(&pool, &env).await;
    finish_runtime_key_pg_test(result, cleanup)
}
