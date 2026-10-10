use super::{
    authorization_fixture as f,
    support::{remote, unavailable, unavailable_states, TestResult},
};
use crate::web;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Extension,
};
use tower::ServiceExt;

#[tokio::test]
#[ignore = "requires isolated PostgreSQL with restricted runtime"]
async fn pg_namespace_mounted_exceptions_and_readiness_have_exact_responses() -> TestResult {
    let (state, _) = f::fixture().await?;
    let app = |s| web::build_router(s).layer(Extension(remote()));
    let ready = app(state.clone())
        .oneshot(Request::get("/ready").body(Body::empty())?)
        .await?;
    assert_eq!(ready.status(), StatusCode::NO_CONTENT);
    assert!(
        !state.cfg.require_client_auth_revocation,
        "fixture explicitly permits registered public-client revocation"
    );
    for denied in unavailable_states(&state) {
        unavailable(
            app(denied.clone())
                .oneshot(Request::get("/ready").body(Body::empty())?)
                .await?,
        )
        .await?;
        for path in [
            "/health",
            "/.well-known/oauth-authorization-server",
            "/.well-known/openid-configuration",
            "/.well-known/oauth-protected-resource",
            "/jwks",
            "/.well-known/jwks.json",
        ] {
            let positive = app(state.clone())
                .oneshot(Request::get(path).body(Body::empty())?)
                .await?;
            assert_eq!(positive.status(), StatusCode::OK, "{path}");
            let response = app(denied.clone())
                .oneshot(Request::get(path).body(Body::empty())?)
                .await?;
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                to_bytes(response.into_body(), 65536).await?,
                to_bytes(positive.into_body(), 65536).await?,
                "{path}"
            );
        }
        for (method, path, status) in [
            ("GET", "/not-a-route", StatusCode::NOT_FOUND),
            ("GET", "/token", StatusCode::METHOD_NOT_ALLOWED),
        ] {
            let response = app(denied.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(response.status(), status);
        }
        let response = app(denied)
            .oneshot(
                Request::post("/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("client_id=namespace-client&token=unknown-token"))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(to_bytes(response.into_body(), 65536).await?.is_empty());
    }
    Ok(())
}
