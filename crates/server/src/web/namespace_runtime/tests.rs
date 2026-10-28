use super::*;
use crate::web::test_support::{setup_test_environment, test_app_state, test_pg_pool, TestResult};
use axum::{body::Body, extract::ConnectInfo, http::Request, Extension};
use std::net::SocketAddr;
use tower::ServiceExt;

async fn validated_fixture() -> TestResult<AppState> {
    let pool = test_pg_pool()
        .await?
        .ok_or("isolated restricted PostgreSQL is required")?;
    let env = setup_test_environment(&pool).await?;
    test_app_state(pool, &env).await
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with provisioned restricted runtime"]
async fn pg_subject_namespace_binds_database_and_identity_services() -> TestResult {
    let state = validated_fixture().await?;
    assert!(state.require_subject_namespace().is_ok());
    let mut changed = state.clone();
    changed.clients =
        Arc::new(crate::client_registry::ClientRegistry::new_process_local_for_tests());
    assert!(
        changed.require_subject_namespace().is_ok(),
        "client snapshots retain namespace"
    );
    changed.environment_id = Uuid::new_v4();
    assert!(changed.require_subject_namespace().is_err());
    changed = state.clone();
    changed.issuer = Arc::new("https://other.example.com".into());
    assert!(changed.require_subject_namespace().is_err());
    changed = state.clone();
    changed.cfg = Arc::new(state.cfg.as_ref().clone());
    assert!(changed.require_subject_namespace().is_err());
    changed = state.clone();
    changed.tokens.validator = Arc::new(state.tokens.validator.as_ref().clone());
    assert!(changed.require_subject_namespace().is_err());
    changed = state.clone();
    changed.db_pool = sqlx::postgres::PgPoolOptions::new()
        .connect_with(state.db_pool.connect_options().as_ref().clone())
        .await?;
    assert!(
        changed.require_subject_namespace().is_err(),
        "equal options do not alias the owned pool"
    );
    changed = state.clone();
    changed.application_authority = Some(Arc::new(crate::application_authorization::Authority {
        projections: state.db_pool.clone(),
        memberships: None,
    }));
    assert!(changed.require_subject_namespace().is_err());
    changed.validate_subject_namespace().await?;
    assert!(changed.require_subject_namespace().is_ok());
    changed.application_authority = Some(Arc::new(crate::application_authorization::Authority {
        projections: changed.db_pool.clone(),
        memberships: None,
    }));
    assert!(
        changed.require_subject_namespace().is_err(),
        "replacement needs fresh validation"
    );
    let other = sqlx::postgres::PgPoolOptions::new()
        .connect_with(state.db_pool.connect_options().as_ref().clone())
        .await?;
    changed.application_authority = Some(Arc::new(crate::application_authorization::Authority {
        projections: other,
        memberships: None,
    }));
    assert!(changed.validate_subject_namespace().await.is_err());
    assert!(changed.require_subject_namespace().is_err());
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with provisioned restricted runtime"]
async fn pg_subject_namespace_pending_routes_and_exceptions_are_explicit() -> TestResult {
    let mut state = validated_fixture().await?;
    state.subject_namespace = None;
    let router = crate::web::build_router(state).layer(Extension(ConnectInfo(SocketAddr::from((
        [127, 0, 0, 1],
        12345,
    )))));
    for (method, path) in [
        ("GET", "/authorize"),
        ("POST", "/token"),
        ("POST", "/par"),
        ("GET", "/userinfo"),
        ("POST", "/userinfo"),
        ("POST", "/introspect"),
        ("GET", "/resource"),
        ("GET", "/application/authorization"),
        ("GET", "/auth/login"),
        ("POST", "/auth/login"),
        ("POST", "/auth/activate"),
        ("POST", "/auth/password/reset"),
        ("POST", "/auth/consent"),
        ("POST", "/auth/logout"),
        ("GET", "/logout"),
        ("POST", "/register"),
        ("GET", "/register/client"),
        ("PUT", "/register/client"),
        ("DELETE", "/register/client"),
        ("GET", "/ready"),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))?,
            )
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{method} {path}"
        );
        assert!(!response.headers().contains_key("set-cookie"));
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["pragma"], "no-cache");
        let body: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "server_error");
        assert_eq!(body["error_description"], "Subject namespace unavailable");
    }
    for (method, path, status) in [
        ("GET", "/health", StatusCode::OK),
        ("GET", "/does-not-exist", StatusCode::NOT_FOUND),
        ("GET", "/token", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), status);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with provisioned restricted runtime"]
async fn pg_subject_namespace_restart_revokes_publication_and_notifies_embedder() -> TestResult {
    let state = validated_fixture().await?;
    assert!(state.require_subject_namespace().is_ok());
    state.runtime_restart.request_restart(
        crate::runtime_restart::RuntimeRestartRequest::runtime_authority_drift(
            "namespace-test",
            state.runtime_authority.issuer_host(),
            "test-drift",
        ),
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        state.shutdown_requested(),
    )
    .await?;
    assert!(state.require_subject_namespace().is_err());
    Ok(())
}
