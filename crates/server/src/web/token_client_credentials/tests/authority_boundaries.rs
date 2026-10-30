use super::*;

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn client_credentials_authority_backend_failure_is_operational() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env, false, false).await?;
        let (status, body) = request(
            &state,
            "/token",
            CALLER,
            SECRET,
            &[("grant_type", "client_credentials"), ("audience", TARGET)],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["access_token"].as_str().ok_or("token missing")?;
        assert_eq!(
            introspect(&state, RS, token).await?["active"],
            true,
            "valid control"
        );
        let access = state
            .tokens
            .store
            .try_verify_access_token_async(token.into())
            .await?
            .ok_or("access missing")?;
        let meta = state
            .tokens
            .store
            .try_get_bearer_meta_async(token.into())
            .await?
            .ok_or("metadata missing")?;
        let mut unavailable = crate::web::client_request_snapshot::request_state(&state, &[RS])
            .map_err(|response| format!("snapshot returned {}", response.status()))?;
        unavailable.db_pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgresql://fixture@127.0.0.1:1/absent?sslmode=disable")?;
        let response = crate::web::client_credentials_authorization::introspection_visible(
            &unavailable,
            &access,
            Some(&meta),
            RS,
        )
        .await
        .expect_err("unavailable authority must not become inactive or active");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let (status, body) = request(
            &unavailable,
            "/introspect",
            RS,
            RS_SECRET,
            &[("token", token)],
        )
        .await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"], "temporarily_unavailable");
        let mut changed = policy(false)?;
        changed.client_credentials.rules.clear();
        install_policy(&pool, &env, &changed).await?;
        let changed = reload(&state, &env).await?;
        assert_eq!(
            introspect(&changed, RS, token).await?["active"],
            false,
            "stale authority is an inactive token"
        );
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}

#[tokio::test]
#[ignore = "requires private PostgreSQL"]
async fn client_credentials_held_resource_auth_snapshot_rejects_replacement() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL is required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = fixture(&pool, &env, false, false).await?;
        let (status, body) = request(
            &state,
            "/token",
            CALLER,
            SECRET,
            &[("grant_type", "client_credentials"), ("audience", TARGET)],
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "{body}");
        let token = body["access_token"].as_str().ok_or("token missing")?;
        let access = state
            .tokens
            .store
            .try_verify_access_token_async(token.into())
            .await?
            .ok_or("access missing")?;
        let meta = state
            .tokens
            .store
            .try_get_bearer_meta_async(token.into())
            .await?
            .ok_or("metadata missing")?;
        let captured = crate::web::client_request_snapshot::request_state(&state, &[RS])
            .map_err(|response| format!("snapshot returned {}", response.status()))?;
        let old_header = format!("Basic {}", STANDARD.encode(format!("{RS}:{RS_SECRET}")));
        assert!(captured
            .clients
            .try_validate_basic_auth(&old_header)?
            .is_some());
        assert!(
            crate::web::client_credentials_authorization::introspection_visible(
                &captured,
                &access,
                Some(&meta),
                RS
            )
            .await
            .map_err(|response| format!("valid control returned {}", response.status()))?
        );
        replace_registration(&pool, &env, RS).await?;
        state
            .runtime_authority
            .try_synchronize_client_projection_from_database(&pool, state.clients.as_ref())
            .await?;
        assert!(
            captured
                .clients
                .try_validate_basic_auth(&old_header)?
                .is_some(),
            "in-flight snapshot retains authenticated identity material"
        );
        assert!(
            state
                .clients
                .try_validate_basic_auth(&old_header)?
                .is_none(),
            "replacement registration has different credentials"
        );
        let response = crate::web::client_credentials_authorization::introspection_visible(
            &captured,
            &access,
            Some(&meta),
            RS,
        )
        .await
        .expect_err("held old authentication cannot be rebound to the replacement UUID");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let (status, body) = request(
            &state,
            "/introspect",
            RS,
            "replacement-private-fixture-secret",
            &[("token", token)],
        )
        .await?;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], false);
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
