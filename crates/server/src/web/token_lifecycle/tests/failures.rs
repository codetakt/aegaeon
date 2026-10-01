use super::*;

fn metrics() -> TestResult<(f64, f64)> {
    MetricsIntegration::with_global(|m| {
        (
            m.metrics
                .introspection_requests
                .with_label_values(&["access_token", "true"])
                .get(),
            m.metrics
                .introspection_requests
                .with_label_values(&["access_token", "false"])
                .get(),
        )
    })
    .ok_or_else(|| "global metrics missing".into())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn refresh_parent_introspection_skips_lookup_when_retention_is_disabled() -> TestResult {
    let fixture = Fixture::new(false).await?;
    let state = &fixture.state;
    let result = async {
        let (access, refresh, meta) = grant(state, true, None);
        let refresh = refresh.ok_or("refresh missing")?;
        state.tokens.store.store_issued_grant(
            access.clone(),
            Some(refresh.clone()),
            meta.clone(),
        )?;
        let _: () =
            fixture
                .connection()?
                .set_ex(fixture.key("refresh", &refresh.token), "{", 300)?;
        observe(state, &access.token, true).await?;
        assert_eq!(
            state.tokens.validator.validate_refresh_parent(&meta),
            Ok(())
        );
        assert_eq!(
            state
                .tokens
                .validator
                .validate_refresh_parent_async(&meta)
                .await,
            Ok(())
        );
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn refresh_parent_introspection_backend_error_is_not_an_active_observation() -> TestResult {
    let fixture = Fixture::new(true).await?;
    let state = &fixture.state;
    let result = async {
        let (access, refresh, meta) = grant(state, true, None);
        let refresh = refresh.ok_or("refresh missing")?;
        state.tokens.store.store_issued_grant(
            access.clone(),
            Some(refresh.clone()),
            meta.clone(),
        )?;
        observe(state, &access.token, true).await?;
        // Only the parent's stored JSON is corrupt. Access, metadata and caller lookups succeed.
        let _: () =
            fixture
                .connection()?
                .set_ex(fixture.key("refresh", &refresh.token), "{", 300)?;
        assert!(state
            .tokens
            .store
            .try_verify_access_token(&access.token)?
            .is_some());
        assert!(state
            .tokens
            .store
            .try_get_bearer_meta(&access.token)?
            .is_some());
        assert!(matches!(
            state.tokens.validator.validate_refresh_parent(&meta),
            Err(TokenPolicyError::TokenStoreUnavailable(_))
        ));
        assert!(matches!(
            state
                .tokens
                .validator
                .validate_refresh_parent_async(&meta)
                .await,
            Err(TokenPolicyError::TokenStoreUnavailable(_))
        ));
        for jwt in [false, true] {
            let before = metrics()?;
            let (status, body) = introspection(state, &access.token, OWNER, jwt).await?;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
            assert_eq!(body["error"], "temporarily_unavailable");
            assert!(body.get("active").is_none());
            assert_eq!(
                metrics()?,
                before,
                "backend error is not successful active/inactive determination"
            );
            let (status, body) = introspection(state, &access.token, OTHER, jwt).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                body,
                json!({"active":false}),
                "visibility checked before parent storage"
            );
        }
        let response = router(state)
            .oneshot(
                Request::get("/resource")
                    .header(header::AUTHORIZATION, format!("Bearer {}", access.token))
                    .body(Body::empty())?,
            )
            .await?;
        // The existing resource policy-error mapping uses 500 for this failure.
        // This change preserves that mapping; HTTP introspection above uses 503.
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL and Redis; run serially"]
async fn refresh_parent_introspection_counts_final_application_status_and_signing_errors(
) -> TestResult {
    let mut fixture = Fixture::new(true).await?;
    let result = async {
        let audience = crate::resource_audience::protected_resource(&fixture.env.issuer_url);
        seed_test_projection(
            &fixture.pool,
            &fixture.env,
            OWNER,
            "subject",
            json!([audience]),
            json!({"roles":["USER"],"organization_roles":[]}),
        )
        .await?;
        fixture.state.application_authority = Some(crate::application_authorization::Authority {
            projections: fixture.pool.clone(),
            memberships: None,
        });
        let (access, refresh, mut meta) = grant(&fixture.state, false, None);
        meta.application_grant = crate::application_authorization::store::capture(
            &fixture.pool,
            fixture.env.environment_id,
            &fixture.env.issuer_url,
            OWNER,
            "subject",
        )
        .await?;
        assert!(meta.application_grant.is_some());
        fixture
            .state
            .tokens
            .store
            .store_issued_grant(access.clone(), refresh, meta)?;
        for jwt in [false, true] {
            let before = metrics()?;
            let (status, body) = introspection(&fixture.state, &access.token, OWNER, jwt).await?;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["active"], true);
            assert_eq!(metrics()?, (before.0 + 1.0, before.1));
        }
        sqlx::query("UPDATE aegaeon.end_users SET status='SUSPENDED' WHERE environment_id=$1")
            .bind(fixture.env.environment_id)
            .execute(&fixture.pool)
            .await?;
        for jwt in [false, true] {
            let before = metrics()?;
            let (status, body) = introspection(&fixture.state, &access.token, OWNER, jwt).await?;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, json!({"active":false}));
            assert_eq!(metrics()?, (before.0, before.1 + 1.0));
        }
        let closed = sqlx::postgres::PgPoolOptions::new()
            .connect(&std::env::var("AEGAEON_DATABASE_URL")?)
            .await?;
        closed.close().await;
        fixture.state.application_authority = Some(crate::application_authorization::Authority {
            projections: closed,
            memberships: None,
        });
        let before = metrics()?;
        let (status, body) = introspection(&fixture.state, &access.token, OWNER, false).await?;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert_eq!(metrics()?, before);
        // An active ordinary grant can reach signing; missing public material is an error.
        let (plain, refresh, meta) = grant(&fixture.state, false, None);
        fixture
            .state
            .tokens
            .store
            .store_issued_grant(plain.clone(), refresh, meta)?;
        fixture.state.keys.jwt_introspection =
            Some(Arc::new(crate::kms::InMemoryKeyManager::new()));
        let before = metrics()?;
        let (status, body) = introspection(&fixture.state, &plain.token, OWNER, true).await?;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(metrics()?, before);
        Ok(())
    }
    .await;
    fixture.finish(result).await
}
