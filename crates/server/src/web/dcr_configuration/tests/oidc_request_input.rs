//! Actual router regressions reuse the existing database/active-client fixture.
//! These check GET input compatibility and HEAD routing, not complete POST flows.
use super::*;
use axum::extract::ConnectInfo;
use std::net::SocketAddr;

fn browser_request(method: Method, uri: &str) -> Result<Request<Body>, axum::http::Error> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::empty())?;
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 43123))));
    Ok(request)
}

fn assert_no_cache(response: &Response) {
    assert!(response.headers()[header::CACHE_CONTROL]
        .to_str()
        .expect("cache header")
        .contains("no-store"));
}

#[tokio::test]
#[ignore = "requires AEGAEON_DATABASE_URL-backed Postgres integration test"]
async fn oidc_input_real_router_preserves_get_head_and_early_rejections() -> TestResult {
    let pool = test_pg_pool().await?.ok_or_else(|| {
        io::Error::other("AEGAEON_DATABASE_URL required; test must not silently skip")
    })?;
    let env = setup_test_dcr_environment(&pool).await?;
    let result = scenario(&pool, &env).await;
    finish_test(result, cleanup_test_dcr_environment(&pool, &env).await)
}

async fn scenario(pool: &PgPool, env: &TestDcrEnvironment) -> TestResult {
    let client = sample_registered_client("oidc-input-client");
    create_test_registration(pool, env, &client, "synthetic-registration-token").await?;
    let pem = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/rsa2048-private.pk8.pem"
    ));
    let signing_key = crate::oidc::OidcSigningKey::from_rsa_pem("oidc-input-test".into(), pem)?;
    let mut state = test_app_state(pool.clone(), env).await?;
    state.oidc.config = Some(std::sync::Arc::new(crate::oidc::OidcConfig {
        issuer: env.issuer_url.clone(),
        id_token_ttl_secs: 300,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: true,
        backchannel_logout_enabled: false,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: false,
        signing_key,
        request_object_encryption_key: None,
    }));
    let app = crate::web::router::build_router(state);
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("response_type", "code")
        .append_pair("client_id", &client.client_id)
        .append_pair("redirect_uri", &client.redirect_uris[0])
        .append_pair("iss", &env.issuer_url)
        .append_pair("scope", "openid")
        .append_pair("state", "normal-state")
        .append_pair(
            "code_challenge",
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        .append_pair("code_challenge_method", "S256")
        .finish();
    let uri = format!("/authorize?{query}");
    let get = app
        .clone()
        .oneshot(browser_request(Method::GET, &uri)?)
        .await?;
    assert_eq!(get.status(), StatusCode::FOUND);
    assert_no_cache(&get);
    let location = get.headers()[header::LOCATION].clone();
    assert!(location.to_str()?.starts_with("/auth/login?return_to="));
    let head = app
        .clone()
        .oneshot(browser_request(Method::HEAD, &uri)?)
        .await?;
    assert_eq!(head.status(), StatusCode::FOUND);
    // Each request has its own login continuation; the protocol input is stable.
    let return_to_pairs = |value: &str| -> TestResult<Vec<(String, String)>> {
        let login = url::Url::parse(&format!("https://issuer.example{value}"))?;
        let return_to = login
            .query_pairs()
            .find(|(key, _)| key == "return_to")
            .ok_or_else(|| io::Error::other("return_to missing"))?
            .1
            .into_owned();
        let authorize = url::Url::parse(&format!("https://issuer.example{return_to}"))?;
        assert!(authorize
            .query_pairs()
            .any(|(key, value)| key == "aeg_login_continue" && !value.is_empty()));
        Ok(authorize
            .query_pairs()
            .filter(|(key, _)| key != "aeg_login_continue")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect())
    };
    assert_eq!(
        return_to_pairs(head.headers()[header::LOCATION].to_str()?)?,
        return_to_pairs(location.to_str()?)?
    );
    assert_no_cache(&head);
    assert!(body::to_bytes(head.into_body(), 4096).await?.is_empty());

    // Empty known values are omitted; unknown duplicates do not override state.
    let empty_unknown = format!("{uri}&max_age=&unknown=a&unknown=b");
    for method in [Method::GET, Method::HEAD] {
        let response = app
            .clone()
            .oneshot(browser_request(method, &empty_unknown)?)
            .await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_no_cache(&response);
    }
    for uri in [
        "/authorize?client_id=a&client_id=b",
        "/authorize?state=%FF",
        "/authorize?password=synthetic-sensitive-value",
        "/logout?state=a&state=b",
        "/logout?unknown=%GG",
        "/logout?client_secret=synthetic-sensitive-value",
    ] {
        for method in [Method::GET, Method::HEAD] {
            let is_head = method == Method::HEAD;
            let response = app.clone().oneshot(browser_request(method, uri)?).await?;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
            assert_no_cache(&response);
            if !is_head {
                let body = response_json(response).await?;
                assert_eq!(body["error"], "invalid_request");
                assert!(!body.to_string().contains("synthetic-sensitive-value"));
            }
        }
    }
    let multiple =
        format!("{uri}&resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example");
    let response = app
        .clone()
        .oneshot(browser_request(Method::GET, &multiple)?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_no_cache(&response);
    assert_eq!(response_json(response).await?["error"], "invalid_target");

    // Normal no-hint logout reaches the existing GET/HEAD handler.
    for method in [Method::GET, Method::HEAD] {
        let is_head = method == Method::HEAD;
        let response = app
            .clone()
            .oneshot(browser_request(method, "/logout?state=&unknown=x")?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_no_cache(&response);
        if is_head {
            assert!(body::to_bytes(response.into_body(), 4096).await?.is_empty());
        } else {
            assert_eq!(response_json(response).await?["logout"], "ok");
        }
    }
    for uri in [
        "/authorize?request=synthetic",
        "/logout?id_token_hint=synthetic",
    ] {
        let response = app
            .clone()
            .oneshot(browser_request(Method::HEAD, uri)?)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "existing HEAD URI credential restriction"
        );
        assert_no_cache(&response);
    }
    for uri in ["/authorize", "/logout"] {
        let response = app
            .clone()
            .oneshot(browser_request(Method::POST, uri)?)
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::METHOD_NOT_ALLOWED,
            "POST routing remains unchanged"
        );
    }
    Ok(())
}
