use super::*;

#[tokio::test]
#[ignore = "requires real PostgreSQL and native DCR parser; missing configuration is an error"]
async fn dcr_device_self_check_registers_updates_and_authorizes() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or_else(|| io::Error::other("AEGAEON_DATABASE_URL required"))?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let state = configured_state(pool, env, true).await?;
    let app = crate::web::router::build_router(state.clone());
    let response = app
        .clone()
        .oneshot(request(Method::POST, "/register", None, &metadata())?)
        .await?;
    let status = response.status();
    let created = response_json(response).await?;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(created["grant_types"], metadata()["grant_types"]);
    let client = field(&created, "client_id")?;
    let token = field(&created, "registration_access_token")?;
    assert_persisted(pool, env, client).await?;
    assert_eq!(
        read(&app, client, token).await?["grant_types"],
        created["grant_types"]
    );
    // Omitted grant metadata must inherit the existing device grant before self-check.
    let update = json!({"client_id":client, "pkce_required":true,
        "post_logout_redirect_uris":["https://client.example/logout"]});
    let response = app
        .clone()
        .oneshot(request(
            Method::PUT,
            &format!("/register/{client}"),
            Some(token),
            &update,
        )?)
        .await?;
    let status = response.status();
    let updated = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["grant_types"], created["grant_types"]);
    assert_eq!(
        updated["post_logout_redirect_uris"],
        update["post_logout_redirect_uris"]
    );
    let replacement = field(&updated, "registration_access_token")?;
    assert_ne!(token, replacement);
    assert_persisted(pool, env, client).await?;
    let reloaded = crate::web::router::build_router(configured_state(pool, env, true).await?);
    assert_eq!(
        read(&reloaded, client, replacement).await?["grant_types"],
        created["grant_types"]
    );
    let old = reloaded
        .clone()
        .oneshot(registration_request(
            Method::GET,
            client,
            Some(token),
            None,
        )?)
        .await?;
    assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
    let mut device_request = Request::builder()
        .method(Method::POST)
        .uri("/device_authorization")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header("x-forwarded-proto", "https")
        .body(Body::from(format!("client_id={client}&scope=openid")))?;
    device_request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(
            "127.0.0.1:43210".parse::<std::net::SocketAddr>()?,
        ));
    let response = reloaded.oneshot(device_request).await?;
    let status = response.status();
    let device = response_json(response).await?;
    assert_eq!(status, StatusCode::OK, "{device}");
    assert!(!field(&device, "device_code")?.is_empty());
    assert!(!field(&device, "user_code")?.is_empty());
    Ok(())
}

async fn assert_persisted(pool: &PgPool, env: &TestDcrEnvironment, client: &str) -> TestResult {
    let grants: Vec<String> = sqlx::query_scalar("SELECT allowed_grant_types FROM aegaeon.clients WHERE environment_id=$1 AND client_identifier=$2")
        .bind(env.environment_id).bind(client).fetch_one(pool).await?;
    assert_eq!(json!(grants), metadata()["grant_types"]);
    Ok(())
}
