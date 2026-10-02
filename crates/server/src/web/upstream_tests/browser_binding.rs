use super::super::test_support;
use super::*;
use axum::{body::Body, extract::ConnectInfo, http::Request, routing::get, Router};
use tower::ServiceExt;

fn bound_request(
    state: &AppState,
    token: &str,
    secret: &str,
) -> crate::upstream::UpstreamAuthRequest {
    let mut request = make_auth_request(token, std::time::Duration::from_secs(60));
    request.issuer = validate_upstream_issuer(&request.issuer).expect("valid test issuer");
    request.browser_binding_digest = Some(aegaeon_crypto::hash::sha256_hex(secret.as_bytes()));
    request.redirect_uri = build_upstream_redirect_uri(state.base_url.as_str(), "example");
    request.return_to = Some("/continue".to_string());
    request
}

async fn callback_http(
    app: &Router,
    route: &str,
    query: &str,
    cookies: &[String],
) -> Result<axum::response::Response, Box<dyn std::error::Error>> {
    let mut request = Request::builder()
        .uri(format!("/oauth/upstream/{route}/callback?{query}"))
        .extension(ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            12345,
        ))));
    for cookie in cookies {
        request = request.header(header::COOKIE, cookie);
    }
    Ok(app.clone().oneshot(request.body(Body::empty())?).await?)
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn upstream_browser_binding_callback_router_rejects_cross_browser_and_route(
) -> test_support::TestResult {
    let pool = test_support::test_pg_pool()
        .await?
        .ok_or("Postgres fixture required")?;
    let env = test_support::setup_test_environment(&pool).await?;
    let result = browser_binding_router_scenario(&pool, &env).await;
    test_support::finish_test(
        result,
        test_support::cleanup_test_environment(&pool, &env).await,
    )
}

async fn browser_binding_router_scenario(
    pool: &sqlx::PgPool,
    env: &test_support::TestEnvironment,
) -> test_support::TestResult {
    let state = test_support::test_app_state(pool.clone(), env).await?;
    let app = Router::new()
        .route(
            "/oauth/upstream/:connection/callback",
            get(super::super::upstream_callback::upstream_callback),
        )
        .with_state(state.clone());
    let secret = crate::upstream::random_token(32);
    let other_secret = crate::upstream::random_token(32);
    let cookie = format!(
        "{}={secret}",
        super::super::upstream_browser_binding::cookie_name("first")
    );
    let other_cookie = format!(
        "{}={other_secret}",
        super::super::upstream_browser_binding::cookie_name("second")
    );
    state
        .upstream
        .auth_store
        .try_insert(bound_request(&state, "first", &secret))?;
    state
        .upstream
        .auth_store
        .try_insert(bound_request(&state, "second", &other_secret))?;
    let query = "state=first&code=valid-code&iss=https%3A%2F%2Fissuer.example";
    let wrong = cookie.replace(&secret, &other_secret);
    let malformed = cookie.replace(&secret, "malformed");
    for cookies in [
        vec![],
        vec![wrong],
        vec![other_cookie.clone()],
        vec![cookie.clone(), cookie.clone()],
        vec![format!("{cookie}; {cookie}")],
        vec![malformed],
    ] {
        let response = callback_http(&app, "example", query, &cookies).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    let response = callback_http(&app, "wrong", query, std::slice::from_ref(&cookie)).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    // A matching browser reaches the real database currentness check. The fixture
    // deliberately has no active upstream connection, so no token/session effects occur.
    let response = callback_http(
        &app,
        "example",
        query,
        &[cookie.clone(), other_cookie.clone()],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        1
    );
    assert!(response.headers()[header::SET_COOKIE]
        .to_str()?
        .starts_with(&format!(
            "{}=;",
            super::super::upstream_browser_binding::cookie_name("first")
        )));
    assert!(response.headers()[header::SET_COOKIE]
        .to_str()?
        .contains("Max-Age=0"));
    let response = callback_http(&app, "example", query, &[cookie]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error_query = "state=second&error=access_denied&iss=https%3A%2F%2Fissuer.example";
    let response = callback_http(&app, "example", error_query, &[]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = callback_http(
        &app,
        "example",
        error_query,
        std::slice::from_ref(&other_cookie),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(response.headers()[header::LOCATION]
        .to_str()?
        .starts_with("/continue?"));
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        1
    );
    assert_eq!(
        callback_http(&app, "example", error_query, &[other_cookie])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    for (token, issuer_query) in [
        ("missing-issuer", ""),
        ("wrong-issuer", "&iss=https%3A%2F%2Fother.example"),
    ] {
        state
            .upstream
            .auth_store
            .try_insert(bound_request(&state, token, &secret))?;
        let cookie = format!(
            "{}={secret}",
            super::super::upstream_browser_binding::cookie_name(token)
        );
        let response = callback_http(
            &app,
            "example",
            &format!("state={token}&error=access_denied{issuer_query}"),
            &[cookie],
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::LOCATION));
        assert!(response.headers().contains_key(header::SET_COOKIE));
    }
    for (token, legacy) in [("expired", false), ("legacy", true)] {
        let mut request = bound_request(&state, token, &secret);
        if legacy {
            request.browser_binding_digest = None;
        } else {
            request.expires_at = std::time::SystemTime::now();
        }
        state.upstream.auth_store.try_insert(request)?;
        let cookie = format!(
            "{}={secret}",
            super::super::upstream_browser_binding::cookie_name(token)
        );
        let response = callback_http(
            &app,
            "example",
            &format!("state={token}&code=code&iss=https%3A%2F%2Fissuer.example"),
            &[cookie],
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
    Ok(())
}

#[test]
fn upstream_browser_binding_cookie_attributes_and_session_cookie_preservation() -> TestResult {
    use super::super::upstream_browser_binding::{
        browser_digest, clear_cookie, cookie_name, cookie_value,
    };
    let secret = crate::upstream::random_token(32);
    let cookie = cookie_value("state", &secret, 59);
    assert!(cookie.starts_with("__Host-aegaeon-upstream-"));
    assert!(cookie.ends_with("; Path=/; Max-Age=59; Secure; HttpOnly; SameSite=Lax"));
    assert!(!cookie.contains("Domain="));
    assert_ne!(cookie_name("state"), cookie_name("other"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_str(cookie.split(';').next().ok_or("cookie")?)
            .map_err(|e| e.to_string())?,
    );
    assert_eq!(
        browser_digest(&headers, "state"),
        Some(aegaeon_crypto::hash::sha256_hex(secret.as_bytes()))
    );
    headers.insert(
        header::SET_COOKIE,
        HeaderValue::from_static("session=existing; Secure; HttpOnly"),
    );
    clear_cookie(&mut headers, "state");
    assert_eq!(headers.get_all(header::SET_COOKIE).iter().count(), 2);
    assert_eq!(
        headers
            .get_all(header::SET_COOKIE)
            .iter()
            .next()
            .ok_or("session cookie")?,
        "session=existing; Secure; HttpOnly"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn upstream_browser_binding_callback_router_backend_failure_is_unavailable(
) -> test_support::TestResult {
    let pool = test_support::test_pg_pool()
        .await?
        .ok_or("Postgres fixture required")?;
    let env = test_support::setup_test_environment(&pool).await?;
    let result = async {
        let mut state = test_support::test_app_state(pool.clone(), &env).await?;
        let unavailable_store = {
            let _guard = crate::util::SERVER_TEST_ENV_GUARD
                .lock()
                .map_err(|e| e.to_string())?;
            let _env = EnvVarGuard::new(
                "AEGAEON_UPSTREAM_AUTH_REDIS_URL",
                Some("redis://127.0.0.1:1/"),
            );
            crate::upstream::UpstreamAuthStore::try_new_from_shared_store_env_with_ttl_secs(
                60,
                &crate::config::RuntimeStateNamespace::for_tests("upstream-browser-outage"),
            )?
        };
        state.upstream.auth_store = std::sync::Arc::new(unavailable_store);
        let app = Router::new()
            .route(
                "/oauth/upstream/:connection/callback",
                get(super::super::upstream_callback::upstream_callback),
            )
            .with_state(state);
        let cookie = format!(
            "{}={}",
            super::super::upstream_browser_binding::cookie_name("outage"),
            crate::upstream::random_token(32)
        );
        for query in ["state=outage&code=code", "state=outage&error=access_denied"] {
            let response =
                callback_http(&app, "example", query, std::slice::from_ref(&cookie)).await?;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert!(!response.headers().contains_key(header::LOCATION));
            assert!(!response.headers().contains_key(header::SET_COOKIE));
        }
        Ok(())
    }
    .await;
    test_support::finish_test(
        result,
        test_support::cleanup_test_environment(&pool, &env).await,
    )
}
