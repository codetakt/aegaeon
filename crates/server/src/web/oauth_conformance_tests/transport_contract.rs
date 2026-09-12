//! Real transport middleware with a certificate-only probe handler; not a TLS endpoint.
use super::*;
use crate::middleware::tls::{TransportSecurity, VerifiedClientCertificate};
use crate::web::test_support::{
    cleanup_test_environment, finish_test, setup_test_environment, test_app_state, test_pg_pool,
};
use axum::{
    body::Body,
    extract::{ConnectInfo, OriginalUri, Query, State},
    middleware,
    routing::get,
    Extension, Router,
};
use http::Request;
use tower::ServiceExt;

async fn admitted(Extension(_certificate): Extension<VerifiedClientCertificate>) -> StatusCode {
    StatusCode::NO_CONTENT
}

fn request(
    path: &str,
    certificate: bool,
    trusted: bool,
) -> Result<Request<Body>, Box<dyn std::error::Error>> {
    let remote: std::net::SocketAddr = if trusted {
        "127.0.0.3:12345"
    } else {
        "127.0.0.2:12345"
    }
    .parse()?;
    let mut request = Request::builder()
        .uri(path)
        .header("x-forwarded-proto", "https")
        .extension(ConnectInfo(remote));
    if certificate {
        request = request.header(
            "x-forwarded-client-cert",
            format!("SHA256:{}", "AB".repeat(32)),
        );
    }
    Ok(request.body(Body::empty())?)
}

async fn missing_certificate(response: Response) -> TestResult {
    assert_eq!(
        response.headers()["www-authenticate"],
        "Bearer realm=\"aegaeon\", error=\"invalid_token\""
    );
    error(response, StatusCode::UNAUTHORIZED, "invalid_token").await
}

#[tokio::test]
#[ignore = "requires PostgreSQL"]
async fn resource_ingress_certificate_errors_preserve_resource_contract() -> TestResult {
    let pool = test_pg_pool()
        .await?
        .ok_or("AEGAEON_DATABASE_URL required")?;
    let env = setup_test_environment(&pool).await?;
    let result = async {
        let mut state = test_app_state(pool.clone(), &env).await?;
        state.transport = TransportSecurity::new(crate::config::TransportSecurityConfig {
            require_tls_proxy: true,
            require_proxy_mtls: true,
            trusted_proxies: vec!["127.0.0.3/32".parse()?],
            ..Default::default()
        });
        let app = Router::new()
            .route("/resource", get(admitted))
            .route("/userinfo", get(admitted))
            .route("/oauth/upstream/refresh", get(admitted))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                crate::web::transport_boundary::transport_security_middleware,
            ));
        for path in ["/resource", "/userinfo", "/oauth/upstream/refresh"] {
            for certificate in [true, false, true] {
                let response = app
                    .clone()
                    .oneshot(request(path, certificate, true)?)
                    .await?;
                if certificate {
                    assert_eq!(response.status(), StatusCode::NO_CONTENT);
                } else {
                    missing_certificate(response).await?;
                }
            }
            let response = app.clone().oneshot(request(path, true, false)?).await?;
            error(response, StatusCode::FORBIDDEN, "access_denied").await?;
        }
        // The handler has its own transport check for direct invocation; it must
        // classify the same rejection even without the outer router middleware.
        let response = crate::web::upstream_refresh::upstream_refresh(
            State(state),
            ConnectInfo("127.0.0.3:12345".parse()?),
            OriginalUri("/oauth/upstream/refresh".parse()?),
            request("/oauth/upstream/refresh", false, true)?
                .headers()
                .clone(),
            Query(crate::web::upstream_refresh_links::UpstreamRefreshQuery {
                upstream_issuer: None,
            }),
        )
        .await;
        missing_certificate(response).await
    }
    .await;
    finish_test(result, cleanup_test_environment(&pool, &env).await)
}
