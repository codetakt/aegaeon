// ---------------------------------------------------------------
// P0: Security middleware HTTP-level tests
// ---------------------------------------------------------------

#[tokio::test]
async fn middleware_get_passes_without_csrf() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn middleware_get_sets_no_store_headers() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get(header::CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
    assert_eq!(
        resp.headers().get(header::PRAGMA),
        Some(&HeaderValue::from_static("no-cache"))
    );
    Ok(())
}

#[tokio::test]
async fn middleware_get_rejects_duplicate_cookie_header() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .header("cookie", "csrf_token=one")
        .header("cookie", "csrf_token=two")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_options_passes_without_csrf() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::OPTIONS)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    // OPTIONS bypasses CSRF check (returns whatever the underlying handler/cors returns)
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn middleware_post_without_origin_returns_403() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("content-type", "application/json")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_post_with_wrong_origin_returns_403() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("origin", "https://evil.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .header("content-type", "application/json")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_post_with_mismatched_csrf_returns_403() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", "wrong-token")
        .header("cookie", "csrf_token=correct-token")
        .header("content-type", "application/json")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_post_with_valid_csrf_passes() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .header("content-type", "application/json")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn middleware_post_with_bearer_api_key_skips_csrf() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("authorization", "Bearer aeg_test_api_key")
        .header("content-type", "application/json")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn middleware_post_with_malformed_authorization_does_not_skip_csrf() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("authorization", "not-a-bearer-token")
        .header("content-type", "application/json")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_rejects_bearer_api_key_with_cookie() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("authorization", "Bearer aeg_test_api_key")
        .header("cookie", "csrf_token=present")
        .header("content-type", "application/json")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_post_with_valid_json_body_reaches_json_extractor() -> TestResult {
    let mgmt = test_management_state();
    let app = test_json_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/json")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"configurationDocument":{"policy":{},"scopeAllowlist":["openid"]}}"#,
        ))?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn middleware_post_rejects_duplicate_json_keys() -> TestResult {
    let mgmt = test_management_state();
    let app = test_json_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/json")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"configurationDocument":{"policy":{},"policy":{}}}"#,
        ))?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_post_rejects_duplicate_content_type_header() -> TestResult {
    let mgmt = test_management_state();
    let app = test_json_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/json")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .header("content-type", "application/json")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"ok":true}"#))?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_delete_requires_csrf() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_delete_rejects_request_body() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/test")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .body(Body::from(r#"{"baseConfigurationVersionId":"00000000-0000-0000-0000-000000000000"}"#))?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_get_sets_csrf_cookie_when_absent() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find(|v| v.to_str().unwrap_or("").contains("csrf_token="));
    assert!(
        set_cookie.is_some(),
        "should set csrf_token cookie on first request"
    );
    Ok(())
}

#[tokio::test]
async fn middleware_get_does_not_reset_csrf_when_present() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .header("cookie", "csrf_token=existing-token")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    let set_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find(|v| v.to_str().unwrap_or("").contains("csrf_token="));
    assert!(
        set_cookie.is_none(),
        "should not re-set csrf_token when cookie already present"
    );
    Ok(())
}

#[tokio::test]
async fn middleware_sets_request_id_header() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert!(resp.headers().contains_key("x-request-id"));
    Ok(())
}

#[tokio::test]
async fn middleware_echoes_provided_request_id() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .header("x-request-id", "my-custom-id")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    let request_id = resp
        .headers()
        .get("x-request-id")
        .ok_or_else(|| io::Error::other("missing x-request-id"))?;
    assert_eq!(request_id.to_str()?, "my-custom-id");
    Ok(())
}

#[tokio::test]
async fn middleware_replaces_invalid_request_id() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .header("x-request-id", "invalid id")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    let request_id = resp
        .headers()
        .get("x-request-id")
        .ok_or_else(|| io::Error::other("missing x-request-id"))?
        .to_str()?;
    assert_ne!(request_id, "invalid id");
    assert!(uuid::Uuid::parse_str(request_id).is_ok());
    Ok(())
}
