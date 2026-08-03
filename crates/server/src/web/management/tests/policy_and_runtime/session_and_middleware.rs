
#[test]
fn management_app_state_handlers_remain_session_guarded() -> ManagementTestResult {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/web/management");
    let mut unguarded = Vec::new();
    visit_management_sources(&root, &mut |path, source| {
        let has_app_state_handler =
            source.contains("State(state): State<AppState>") || source.contains("State<AppState>");
        if !has_app_state_handler || management_public_exception(source) {
            return;
        }
        let has_guard = [
            "require_management_session_async",
            "require_human_management_session_async",
            "require_user_management_context",
            "require_user_management_scope",
        ]
        .iter()
        .any(|marker| source.contains(marker));
        if !has_guard {
            unguarded.push(path.display().to_string());
        }
    })?;

    if unguarded.is_empty() {
        return Ok(());
    }

    fail_test!(
        "management AppState handlers must call a session/scope guard or be listed as a public exception:\n{}",
        unguarded.join("\n")
    );
}

fn management_public_exception(source: &str) -> bool {
    [
        "system_health",
        "system_version",
        "create_authentication_session",
        "delete_current_authentication_session",
        "bootstrap_owner",
    ]
    .iter()
    .any(|marker| source.contains(marker))
}

fn visit_management_sources(
    dir: &std::path::Path,
    visitor: &mut impl FnMut(&std::path::Path, &str),
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "tests") {
                continue;
            }
            visit_management_sources(&path, visitor)?;
            continue;
        }
        if path.extension().is_some_and(|ext| ext == "rs") {
            let source = std::fs::read_to_string(&path)?;
            visitor(&path, &source);
        }
    }
    Ok(())
}

#[test]
fn validate_redirect_uris_accepts_http_127_0_0_1() {
    let uris = vec!["http://127.0.0.1:3000/cb".to_string()];
    let result = validate_redirect_uris(&uris, "req-1");
    assert!(result.is_ok());
}

#[test]
fn validate_redirect_uris_rejects_invalid_url() {
    let uris = vec!["not a url".to_string()];
    let result = validate_redirect_uris(&uris, "req-1");
    assert!(result.is_err());
}

#[test]
fn validate_redirect_uris_skips_empty_strings() -> TestResult {
    let uris = vec![
        String::new(),
        "  ".to_string(),
        "https://example.com/cb".to_string(),
    ];
    let Ok(result) = validate_redirect_uris(&uris, "req-1") else {
        return Err(io::Error::other("expected valid redirect URIs").into());
    };
    assert_eq!(result.len(), 1);
    Ok(())
}

// ---------------------------------------------------------------
// P2: Session store concurrent sessions
// ---------------------------------------------------------------

#[test]
fn session_store_different_admins_coexist() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(3600);
    let admin1 = Uuid::new_v4();
    let admin2 = Uuid::new_v4();
    let now = 1_000_000;

    let sid1 = must_some!(store.create(admin1, now), "session created");
    let sid2 = must_some!(store.create(admin2, now), "session created");

    let s1 = store
        .get(&sid1, now)
        .ok_or_else(|| io::Error::other("missing first session"))?;
    let s2 = store
        .get(&sid2, now)
        .ok_or_else(|| io::Error::other("missing second session"))?;

    assert_eq!(s1.administrator_id, admin1);
    assert_eq!(s2.administrator_id, admin2);
    assert_ne!(sid1, sid2);
    Ok(())
}

#[test]
fn session_store_delete_one_keeps_others() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(3600);
    let sid1 = must_some!(store.create(Uuid::new_v4(), 1000), "session created");
    let sid2 = must_some!(store.create(Uuid::new_v4(), 1000), "session created");

    assert!(must_ok!(
        store.try_delete(&sid1),
        "in-memory delete should be confirmed"
    ));

    assert!(store.get(&sid1, 1000).is_none());
    assert!(store.get(&sid2, 1000).is_some());
    Ok(())
}

#[test]
fn session_store_delete_nonexistent_is_noop() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_ttl_for_tests(3600);
    assert!(!must_ok!(
        store.try_delete("nonexistent"),
        "in-memory delete should be confirmed"
    ));
    // Should not panic
    Ok(())
}

#[test]
fn session_store_default_ttl() {
    let store = ManagementSessionStore::new_process_local_for_tests();
    assert_eq!(store.session_ttl_secs, DEFAULT_SESSION_TTL_SECS);
    assert_eq!(store.max_sessions, DEFAULT_MAX_SESSIONS);
}

// ---------------------------------------------------------------
// M-6: Session store max_sessions limit
// ---------------------------------------------------------------

#[test]
fn session_store_max_sessions_evicts_expired_first() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_limits(10, 3);
    let admin = Uuid::new_v4();

    // s1 and s2 will expire by t=15; s3 created late enough to survive
    let s1 = must_some!(store.create(admin, 0), "session created");
    let s2 = must_some!(store.create(admin, 1), "session created");
    let s3 = must_some!(store.create(admin, 10), "session created");
    assert_eq!(store.len(), 3);

    // At t=15: s1 (age 15>=10) and s2 (age 14>=10) expired, s3 (age 5<10) valid
    let s4 = must_some!(store.create(admin, 15), "session created");
    // s1 and s2 expired → evicted; s3 kept; s4 added
    assert_eq!(store.len(), 2);
    assert!(store.get(&s1, 15).is_none());
    assert!(store.get(&s2, 15).is_none());
    assert!(store.get(&s3, 15).is_some());
    assert!(store.get(&s4, 15).is_some());
    Ok(())
}

#[test]
fn session_store_max_sessions_evicts_oldest_when_all_valid() -> TestResult {
    let store = ManagementSessionStore::new_process_local_with_limits(100, 3);
    let admin = Uuid::new_v4();

    let s1 = must_some!(store.create(admin, 0), "session created");
    let s2 = must_some!(store.create(admin, 1), "session created");
    let _s3 = must_some!(store.create(admin, 2), "session created");
    assert_eq!(store.len(), 3);

    // All sessions valid, but max=3 — creating s4 should evict oldest (s1)
    let s4 = must_some!(store.create(admin, 3), "session created");
    assert_eq!(store.len(), 3);
    assert!(store.get(&s1, 3).is_none()); // evicted as oldest
    assert!(store.get(&s2, 3).is_some());
    assert!(store.get(&s4, 3).is_some());
    Ok(())
}

#[test]
fn session_store_max_sessions_default_is_10000() {
    assert_eq!(DEFAULT_MAX_SESSIONS, 10_000);
}

// ---------------------------------------------------------------
// P2: Middleware additional HTTP-level tests
// ---------------------------------------------------------------

#[tokio::test]
async fn middleware_put_requires_csrf_and_json() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router_extended(mgmt);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn middleware_patch_requires_csrf_and_json() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router_extended(mgmt);

    let req = Request::builder()
        .method(Method::PATCH)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn middleware_post_with_valid_csrf_but_wrong_content_type_returns_400() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::POST)
        .uri("/test")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .header("content-type", "text/plain")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_no_store_and_request_id(&resp);
    Ok(())
}

#[tokio::test]
async fn middleware_delete_does_not_require_json_content_type() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let csrf = must_ok!(generate_csrf_token(), "csrf token");
    let req = Request::builder()
        .method(Method::DELETE)
        .uri("/test")
        .header("origin", "https://admin.example.com")
        .header("x-csrf-token", &csrf)
        .header("cookie", format!("csrf_token={csrf}"))
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn middleware_head_passes_without_csrf() -> TestResult {
    let mgmt = test_management_state();
    let app = test_middleware_router(mgmt);

    let req = Request::builder()
        .method(Method::HEAD)
        .uri("/test")
        .body(Body::empty())?;

    let resp = app.oneshot(req).await?;
    // HEAD on an existing route may return 200 or 405, but not 403
    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    Ok(())
}

/// Extended router for PUT/PATCH tests
fn test_middleware_router_extended(mgmt: ManagementState) -> Router {
    Router::new()
        .route("/test", get(|| async { StatusCode::OK.into_response() }))
        .route("/test", post(|| async { StatusCode::OK.into_response() }))
        .route(
            "/test",
            axum::routing::delete(|| async { StatusCode::OK.into_response() }),
        )
        .route(
            "/test",
            axum::routing::put(|| async { StatusCode::OK.into_response() }),
        )
        .route(
            "/test",
            axum::routing::patch(|| async { StatusCode::OK.into_response() }),
        )
        .layer(middleware::from_fn_with_state(
            mgmt,
            management_security_middleware,
        ))
}

// ---------------------------------------------------------------
// Existing tests below
// ---------------------------------------------------------------
