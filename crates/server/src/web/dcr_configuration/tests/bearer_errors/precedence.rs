use super::*;

pub(super) async fn scenario(
    pool: &PgPool,
    env: &TestDcrEnvironment,
    state: &AppState,
    client: &str,
    token: &str,
) -> TestResult {
    let app = crate::web::router::build_router(state.clone());
    let before = state_digest(pool, env).await?;
    body_and_header(&app, env, client, token).await?;
    framework(&app, client, token).await?;
    transport_and_runtime(state, env, client).await?;
    direct_backend(state, env, client, token).await?;
    assert_eq!(before, state_digest(pool, env).await?);
    owner_read(&app, client, token).await
}

async fn body_and_header(
    app: &axum::Router,
    env: &TestDcrEnvironment,
    client: &str,
    token: &str,
) -> TestResult {
    for (method, path, credential) in [
        (Method::POST, "/register".into(), INITIAL_TOKEN),
        (Method::PUT, format!("/register/{client}"), token),
    ] {
        for supplied in [credential, "private-sentinel"] {
            let initial = method == Method::POST;
            let response = app
                .clone()
                .oneshot(request(method.clone(), &path, &bearer(supplied)?, "{")?)
                .await?;
            if supplied == credential {
                response_headers(&response, StatusCode::BAD_REQUEST, None);
                let body = json_error(response, "invalid_request", &env.issuer_url).await?;
                assert_eq!(body["error_description"], "invalid json body");
            } else {
                headers::refusal(
                    response,
                    headers::Refusal::Invalid,
                    false,
                    initial,
                    &env.issuer_url,
                )
                .await?;
            }
            let mut headers = bearer(supplied)?;
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
            let response = app
                .clone()
                .oneshot(request(method.clone(), &path, &headers, "{")?)
                .await?;
            response_headers(&response, StatusCode::BAD_REQUEST, None);
            let body = json_error(response, "invalid_request", &env.issuer_url).await?;
            assert_eq!(
                body["error_description"],
                "Content-Type must be application/json"
            );
            let response = app
                .clone()
                .oneshot(request(
                    method.clone(),
                    &path,
                    &bearer(supplied)?,
                    &json!({"client_id":client,"redirect_uris":[7]}).to_string(),
                )?)
                .await?;
            if supplied == credential {
                response_headers(&response, StatusCode::BAD_REQUEST, None);
                assert_eq!(
                    response_json(response).await?["error"],
                    "invalid_redirect_uri"
                );
            } else {
                headers::refusal(
                    response,
                    headers::Refusal::Invalid,
                    false,
                    initial,
                    &env.issuer_url,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn framework(app: &axum::Router, client: &str, token: &str) -> TestResult {
    for (method, path, credential) in [
        (Method::POST, "/register".into(), INITIAL_TOKEN),
        (Method::PUT, format!("/register/{client}"), token),
    ] {
        for supplied in [credential, "private-sentinel"] {
            let body = "x".repeat(crate::web::router::SERVER_REQUEST_BODY_LIMIT_BYTES + 1);
            let response = app
                .clone()
                .oneshot(request(method.clone(), &path, &bearer(supplied)?, &body)?)
                .await?;
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        }
    }
    for supplied in [token, "private-sentinel"] {
        let response = app
            .clone()
            .oneshot(request(
                Method::GET,
                "/register/%FF",
                &bearer(supplied)?,
                "",
            )?)
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    }
    Ok(())
}

async fn transport_and_runtime(
    state: &AppState,
    env: &TestDcrEnvironment,
    client: &str,
) -> TestResult {
    let mut secured = state.clone();
    secured.transport =
        crate::middleware::TransportSecurity::new(crate::config::TransportSecurityConfig {
            require_tls_proxy: true,
            ..crate::config::TransportSecurityConfig::default()
        });
    let app = crate::web::router::build_router(secured);
    let response = app
        .oneshot(request(
            Method::GET,
            &format!("/register/{client}?access_token="),
            &HeaderMap::new(),
            "",
        )?)
        .await?;
    response_headers(&response, StatusCode::FORBIDDEN, None);
    json_error(response, "access_denied", &env.issuer_url).await?;
    let mut restarting = state.clone();
    restarting.runtime_restart = crate::runtime_restart::RuntimeRestartState::new();
    restarting.runtime_restart.request_restart(
        crate::runtime_restart::RuntimeRestartRequest::runtime_authority_unavailable(
            "test",
            env.issuer_host.as_str(),
            "test",
        ),
    );
    let app = crate::web::router::build_router(restarting);
    let response = app
        .clone()
        .oneshot(request(
            Method::GET,
            &format!("/register/{client}"),
            &HeaderMap::new(),
            "",
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    json_error(response, "temporarily_unavailable", &env.issuer_url).await?;
    // Outer URI refusal still precedes the runtime guard.
    let response = app
        .oneshot(request(
            Method::GET,
            &format!("/register/{client}?access_token="),
            &HeaderMap::new(),
            "",
        )?)
        .await?;
    response_headers(&response, StatusCode::BAD_REQUEST, Some(REQUEST_CHALLENGE));
    Ok(())
}

async fn direct_backend(
    state: &AppState,
    env: &TestDcrEnvironment,
    client: &str,
    token: &str,
) -> TestResult {
    // An owned, never-connected pool exercises the real owner lookup failure without closing shared services.
    let pool =
        sqlx::postgres::PgPoolOptions::new().connect_lazy("postgresql://unused.example/unused")?;
    pool.close().await;
    let mut unavailable = state.clone();
    unavailable.db_pool = pool;
    unavailable.runtime_restart = crate::runtime_restart::RuntimeRestartState::new();
    let response = crate::web::dcr_configuration::auth::authenticate_database_registration_token(
        &unavailable,
        &bearer(token)?,
        client,
    )
    .await
    .err()
    .ok_or_else(|| io::Error::other("closed lookup pool unexpectedly accepted token"))?;
    response_headers(&response, StatusCode::INTERNAL_SERVER_ERROR, None);
    json_error(response, "server_error", &env.issuer_url).await?;
    let app = crate::web::router::build_router(unavailable);
    let response = app
        .oneshot(request(
            Method::GET,
            &format!("/register/{client}"),
            &bearer(token)?,
            "",
        )?)
        .await?;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    json_error(response, "temporarily_unavailable", &env.issuer_url).await?;
    let response = crate::web::dcr_runtime::dcr_database_error_response(
        &crate::dcr_persistence::DcrDatabaseError::CorruptRegistration("private-sentinel".into()),
        &env.issuer_url,
    );
    response_headers(&response, StatusCode::INTERNAL_SERVER_ERROR, None);
    json_error(response, "server_error", &env.issuer_url).await?;
    let response = crate::web::clock_error_response(&env.issuer_url);
    response_headers(&response, StatusCode::INTERNAL_SERVER_ERROR, None);
    json_error(response, "server_error", &env.issuer_url).await?;
    Ok(())
}
