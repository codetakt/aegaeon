use super::*;

async fn error_body(
    response: axum::response::Response,
    status: StatusCode,
    error: &str,
) -> TestResult {
    assert_eq!(response.status(), status);
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error"], error, "{body}");
    assert!(body.get("access_token").is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL and Redis"]
async fn token_snapshot_failures_keep_authentication_and_operational_categories() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("PostgreSQL required; no silent skip")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let state = all_grants_fixture(&pool, &env).await?;
        let unknown = format!("Basic {}", STANDARD.encode("unknown-client:secret"));
        for grant in crate::policy::SUPPORTED_GRANT_TYPES {
            error_body(
                context(&state, grant, &unknown)
                    .await
                    .err()
                    .ok_or("unknown accepted")?,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
            )
            .await?;
        }
        let mut unavailable = state.clone();
        unavailable.db_pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgresql://fixture@127.0.0.1:1/absent?sslmode=disable")?;
        error_body(
            context(&unavailable, "authorization_code", &basic())
                .await
                .err()
                .ok_or("profile failure accepted")?,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
        )
        .await?;
        state.clients.poison_request_snapshot_for_test();
        // Malformed caller-ID selection still precedes snapshot acquisition.
        error_body(
            context(&state, "authorization_code", "Basic")
                .await
                .err()
                .ok_or("malformed accepted")?,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
        )
        .await?;
        for grant in crate::policy::SUPPORTED_GRANT_TYPES {
            error_body(
                context(&state, grant, &basic())
                    .await
                    .err()
                    .ok_or("poison accepted")?,
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
            )
            .await?;
        }
        assert!(state.tokens.store.try_snapshot()?.access_tokens.is_empty());
        Ok(())
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
