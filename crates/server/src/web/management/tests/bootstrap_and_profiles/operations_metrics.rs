fn lazy_metrics_test_pg_pool() -> Result<PgPool, Box<dyn StdError>> {
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://aegaeon:test@127.0.0.1/aegaeon_test")
        .map_err(|err| format!("lazy test PgPool should be constructible: {err}").into())
}

fn operations_metrics_test_router() -> Result<Router, Box<dyn StdError>> {
    let management = test_management_state();
    operations_metrics_test_router_with_pool(lazy_metrics_test_pg_pool()?, management)
}

fn operations_metrics_test_router_with_pool(
    pool: PgPool,
    management: ManagementState,
) -> Result<Router, Box<dyn StdError>> {
    let state = test_app_state(pool, management.clone())?;
    Ok(Router::new()
        .nest("/api/v1", router(management))
        .with_state(state))
}

#[tokio::test]
async fn operations_metrics_route_rejects_unauthenticated_requests() -> TestResult {
    let app = operations_metrics_test_router()?;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/operations/metrics")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_store_and_request_id(&response);
    let body = management_error_response_body(response).await?;
    assert_eq!(body.error_code, "unauthenticated");
    Ok(())
}

#[tokio::test]
async fn operations_metrics_route_rejects_api_key_requests_with_cookies() -> TestResult {
    let app = operations_metrics_test_router()?;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/operations/metrics")
                .header("authorization", "Bearer aeg_validlooking_test_key")
                .header("cookie", "aegaeon_admin_session=session; csrf_token=csrf")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_store_and_request_id(&response);
    let body = management_error_response_body(response).await?;
    assert_eq!(body.error_code, "invalid_request");
    Ok(())
}

#[tokio::test]
async fn operations_metrics_route_allows_db_validated_human_session() -> TestResult {
    let Some(pool) = runtime_key_test_pg_pool().await? else {
        eprintln!(
            "skipping operations metrics success-path test: AEGAEON_DATABASE_URL is not configured"
        );
        return Ok(());
    };
    let env = setup_runtime_key_test_environment(&pool).await?;

    let result = async {
        let management = test_management_state();
        let now_epoch_secs = crate::web::now_epoch_secs().map_err(io::Error::other)?;
        let sid = management
            .sessions
            .try_create(env.administrator_id, now_epoch_secs)
            .map_err(io::Error::other)?
            .ok_or_else(|| io::Error::other("management session should be created"))?;
        let app = operations_metrics_test_router_with_pool(pool.clone(), management)?;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/v1/operations/metrics")
                    .header(header::COOKIE, format!("{MGMT_SESSION_COOKIE_NAME}={sid}"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; version=0.0.4")
        );
        Ok(())
    }
    .await;

    finish_runtime_key_pg_test(result, cleanup_runtime_key_test_environment(&pool, &env).await)
}
