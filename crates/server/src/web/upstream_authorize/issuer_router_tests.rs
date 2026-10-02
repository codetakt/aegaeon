use crate::upstream::{random_token, UpstreamAuthRequest};
use crate::web::{
    test_support, upstream_browser_binding, upstream_callback, upstream_tests, AppState,
};
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    routing::get,
    Router,
};
use tower::ServiceExt;

pub(super) async fn check_callbacks(
    state: &AppState,
    identifier: &str,
    request: &UpstreamAuthRequest,
) -> test_support::TestResult {
    let app = Router::new()
        .route(
            "/oauth/upstream/:connection/callback",
            get(upstream_callback::upstream_callback),
        )
        .with_state(state.clone());
    // Stop successful issuer/currentness admission at the cached-discovery boundary.
    // The adjacent fixture separately verifies the real signed ID Token decoder.
    state.upstream.discovery_cache.try_insert(
        &request.issuer,
        upstream_tests::base_discovery("https://other.example")?,
    )?;
    for error in [false, true] {
        for claim in [
            None,
            Some(request.issuer.as_str()),
            Some("https://other.example"),
        ] {
            let mut pending = request.clone();
            pending.state = random_token(32);
            let secret = random_token(32);
            pending.browser_binding_digest =
                Some(aegaeon_crypto::hash::sha256_hex(secret.as_bytes()));
            let cookie = format!(
                "{}={secret}",
                upstream_browser_binding::cookie_name(&pending.state)
            );
            let mut query = url::form_urlencoded::Serializer::new(String::new());
            query.append_pair("state", &pending.state);
            query.append_pair(
                if error { "error" } else { "code" },
                if error { "access_denied" } else { "code" },
            );
            if let Some(claim) = claim {
                query.append_pair("iss", claim);
            }
            state.upstream.auth_store.try_insert(pending)?;
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!(
                            "/oauth/upstream/{identifier}/callback?{}",
                            query.finish()
                        ))
                        .header(header::COOKIE, cookie)
                        .extension(ConnectInfo(std::net::SocketAddr::from((
                            [127, 0, 0, 1],
                            12345,
                        ))))
                        .body(Body::empty())?,
                )
                .await?;
            let accepted = claim == Some(request.issuer.as_str())
                || (claim.is_none() && !request.require_iss_parameter);
            let expected = if !accepted {
                StatusCode::BAD_REQUEST
            } else if error {
                StatusCode::FOUND
            } else {
                StatusCode::BAD_GATEWAY
            };
            assert_eq!(response.status(), expected);
            if accepted && !error {
                let body = to_bytes(response.into_body(), 16384).await?;
                assert!(std::str::from_utf8(&body)?.contains("upstream discovery issuer mismatch"));
            }
        }
    }
    Ok(())
}
