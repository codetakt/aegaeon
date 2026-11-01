use super::*;

#[tokio::test]
#[ignore = "requires real PostgreSQL and native DCR parser; missing configuration is an error"]
async fn dcr_device_disabled_and_unknown_grants_preserve_owner_state() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("AEGAEON_DATABASE_URL required"))?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    for enabled in [false, true] {
        let app = crate::web::router::build_router(configured_state(pool, env, enabled).await?);
        let mut valid = metadata();
        valid["grant_types"] = json!(["authorization_code"]);
        let response = app
            .clone()
            .oneshot(request(Method::POST, "/register", None, &valid)?)
            .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
        let created = response_json(response).await?;
        let client = field(&created, "client_id")?;
        let token = field(&created, "registration_access_token")?;
        let mut invalid = metadata();
        if enabled {
            invalid["grant_types"] = json!(["authorization_code", "urn:example:unsupported"]);
        }
        for method in [Method::POST, Method::PUT] {
            let before = state_digest(pool, env).await?;
            invalid["client_id"] = json!(client);
            let (path, owner) = if method == Method::PUT {
                (format!("/register/{client}"), Some(token))
            } else {
                ("/register".into(), None)
            };
            let response = app
                .clone()
                .oneshot(request(method, &path, owner, &invalid)?)
                .await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(response.headers()[header::PRAGMA], "no-cache");
            assert_eq!(
                response_json(response).await?["error"],
                "invalid_client_metadata"
            );
            assert_eq!(before, state_digest(pool, env).await?);
            assert_eq!(
                read(&app, client, token).await?["grant_types"],
                valid["grant_types"]
            );
        }
    }
    Ok(())
}
