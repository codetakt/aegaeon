use super::fixture::*;
use crate::web::test_support::TestResult;
use axum::{
    body::Body,
    http::{HeaderValue, StatusCode},
};

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual protected-resource routers"]
async fn resource_authentication_presentations_have_exact_shared_envelopes() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = async {
        for (method, path) in SURFACES {
            for value in [
                None,
                Some(""),
                Some(" \t "),
                Some("Basic"),
                Some("Basic credentials"),
                Some("Unknown extra words"),
            ] {
                let response = request(
                    &fixture.state,
                    method,
                    path,
                    headers(value, Some("unvalidated-proof"), method == "POST")?,
                    Body::empty(),
                )
                .await?;
                expect(
                    response,
                    StatusCode::UNAUTHORIZED,
                    Some("Bearer"),
                    None,
                    false,
                )
                .await?;
            }
            for (value, scheme) in [
                ("Bearer", "Bearer"),
                ("Bearer token extra", "Bearer"),
                ("DPoP", "DPoP"),
                ("dpop token extra", "DPoP"),
                ("Bearer token, DPoP other", "Bearer"),
            ] {
                let response = request(
                    &fixture.state,
                    method,
                    path,
                    headers(Some(value), Some("unvalidated-proof"), method == "POST")?,
                    Body::empty(),
                )
                .await?;
                expect(
                    response,
                    StatusCode::BAD_REQUEST,
                    Some(scheme),
                    Some("invalid_request"),
                    false,
                )
                .await?;
            }
            let mut duplicate = headers(
                Some("DPoP token"),
                Some("unvalidated-proof"),
                method == "POST",
            )?;
            duplicate.append("authorization", HeaderValue::from_static("Bearer second"));
            expect(
                request(&fixture.state, method, path, duplicate, Body::empty()).await?,
                StatusCode::BAD_REQUEST,
                Some("Bearer"),
                Some("invalid_request"),
                false,
            )
            .await?;
            let mut nontext = headers(None, Some("unvalidated-proof"), method == "POST")?;
            nontext.insert("authorization", HeaderValue::from_bytes(&[0x80])?);
            expect(
                request(&fixture.state, method, path, nontext, Body::empty()).await?,
                StatusCode::BAD_REQUEST,
                Some("Bearer"),
                Some("invalid_request"),
                false,
            )
            .await?;
            // This coalesced string remains one token word; it is not split into alternatives.
            expect(
                request(
                    &fixture.state,
                    method,
                    path,
                    headers(Some("Bearer token,other"), None, method == "POST")?,
                    Body::empty(),
                )
                .await?,
                StatusCode::UNAUTHORIZED,
                Some("Bearer"),
                Some("invalid_token"),
                false,
            )
            .await?;
            expect(
                request(
                    &fixture.state,
                    method,
                    path,
                    headers(Some("DPoP token"), None, method == "POST")?,
                    Body::empty(),
                )
                .await?,
                StatusCode::UNAUTHORIZED,
                Some("DPoP"),
                Some("invalid_dpop_proof"),
                false,
            )
            .await?;
        }
        for path in ["/resource", "/userinfo", "/application/authorization"] {
            for auth in [None, Some(" "), Some("Unknown credentials")] {
                expect(
                    request(
                        &fixture.state,
                        "HEAD",
                        path,
                        headers(auth, Some("unvalidated-proof"), false)?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::UNAUTHORIZED,
                    Some("Bearer"),
                    None,
                    false,
                )
                .await?;
            }
        }
        assert_eq!(fixture.replay.attempts(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; actual query/form/method admission"]
async fn resource_authentication_query_and_userinfo_form_errors_are_route_specific() -> TestResult {
    let fixture = Fixture::new().await?;
    let result = async {
        for (method, path) in SURFACES.into_iter().chain([
            ("HEAD", "/resource"),
            ("HEAD", "/userinfo"),
            ("HEAD", "/application/authorization"),
        ]) {
            for query in [
                "access_token=synthetic",
                "%61ccess_token=",
                "ACCESS-TOKEN=synthetic",
            ] {
                for (auth, scheme) in [
                    (None, "Bearer"),
                    (Some("Bearer synthetic"), "Bearer"),
                    (Some("DPoP synthetic"), "DPoP"),
                ] {
                    let response = request(
                        &fixture.state,
                        method,
                        &format!("{path}?{query}"),
                        headers(auth, Some("unvalidated-proof"), method == "POST")?,
                        Body::empty(),
                    )
                    .await?;
                    if method == "HEAD" {
                        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
                        assert_eq!(
                            response
                                .headers()
                                .get_all("www-authenticate")
                                .iter()
                                .count(),
                            1
                        );
                        assert!(response.headers()["www-authenticate"]
                            .to_str()?
                            .starts_with(scheme));
                        assert!(!response.headers().contains_key("dpop-nonce"));
                    } else {
                        expect(
                            response,
                            StatusCode::BAD_REQUEST,
                            Some(scheme),
                            Some("invalid_request"),
                            false,
                        )
                        .await?;
                    }
                }
            }
        }
        for (method, path) in [
            ("POST", "/resource"),
            ("PUT", "/userinfo"),
            ("POST", "/application/authorization"),
            ("GET", "/oauth/upstream/refresh"),
            ("GET", "/unknown"),
            ("POST", "/token"),
            ("POST", "/par"),
        ] {
            expect(
                request(
                    &fixture.state,
                    method,
                    &format!("{path}?access_token=synthetic"),
                    headers(Some("DPoP synthetic"), None, false)?,
                    Body::empty(),
                )
                .await?,
                StatusCode::BAD_REQUEST,
                None,
                Some("invalid_request"),
                false,
            )
            .await?;
        }
        for (method, path) in SURFACES {
            for query in ["refresh_token=synthetic", "client_secret=synthetic"] {
                expect(
                    request(
                        &fixture.state,
                        method,
                        &format!("{path}?{query}"),
                        headers(Some("DPoP synthetic"), None, method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::BAD_REQUEST,
                    None,
                    Some("invalid_request"),
                    false,
                )
                .await?;
            }
        }
        let mut disabled = fixture.state.clone();
        disabled.oidc.userinfo_endpoint = None;
        expect(
            request(
                &disabled,
                "GET",
                "/userinfo?access_token=synthetic",
                headers(None, None, false)?,
                Body::empty(),
            )
            .await?,
            StatusCode::BAD_REQUEST,
            None,
            Some("invalid_request"),
            false,
        )
        .await?;
        expect(
            request(
                &disabled,
                "GET",
                "/userinfo",
                headers(None, None, false)?,
                Body::empty(),
            )
            .await?,
            StatusCode::NOT_FOUND,
            None,
            Some("not_found"),
            false,
        )
        .await?;
        // DCR retains its separate Bearer envelope at the configured authenticated boundary.
        let mut protected_dcr = fixture.state.clone();
        protected_dcr.dcr_required_bearer_hash = Some("fixture-required-hash".into());
        expect(
            request(
                &protected_dcr,
                "POST",
                "/register?access_token=synthetic",
                headers(Some("DPoP synthetic"), None, false)?,
                Body::empty(),
            )
            .await?,
            StatusCode::BAD_REQUEST,
            Some("Bearer"),
            Some("invalid_request"),
            false,
        )
        .await?;
        for auth in [None, Some("DPoP synthetic")] {
            let scheme = if auth.is_some() { "DPoP" } else { "Bearer" };
            let mut wrong_type = headers(auth, Some("unvalidated-proof"), false)?;
            wrong_type.insert("content-type", HeaderValue::from_static("application/json"));
            expect(
                request(&fixture.state, "POST", "/userinfo", wrong_type, "{}").await?,
                StatusCode::BAD_REQUEST,
                Some(scheme),
                Some("invalid_request"),
                false,
            )
            .await?;
            expect(
                request(
                    &fixture.state,
                    "POST",
                    "/userinfo",
                    headers(auth, Some("unvalidated-proof"), false)?,
                    Body::empty(),
                )
                .await?,
                StatusCode::BAD_REQUEST,
                Some(scheme),
                Some("invalid_request"),
                false,
            )
            .await?;
            for body in [
                "access_token=&access_token=",
                "access_token=one&access_token=two",
            ] {
                expect(
                    request(
                        &fixture.state,
                        "POST",
                        "/userinfo",
                        headers(auth, Some("unvalidated-proof"), true)?,
                        body,
                    )
                    .await?,
                    StatusCode::BAD_REQUEST,
                    Some(scheme),
                    Some("invalid_request"),
                    false,
                )
                .await?;
            }
            for invalid_type in ["duplicate", "nontext"] {
                let mut invalid = headers(auth, Some("unvalidated-proof"), true)?;
                if invalid_type == "duplicate" {
                    invalid.append(
                        "content-type",
                        HeaderValue::from_static("application/x-www-form-urlencoded"),
                    );
                } else {
                    invalid.insert("content-type", HeaderValue::from_bytes(&[0x80])?);
                }
                expect(
                    request(&fixture.state, "POST", "/userinfo", invalid, Body::empty()).await?,
                    StatusCode::BAD_REQUEST,
                    Some(scheme),
                    Some("invalid_request"),
                    false,
                )
                .await?;
            }
            let oversized = format!(
                "ignored={}",
                "x".repeat(super::super::super::router::SERVER_REQUEST_BODY_LIMIT_BYTES + 1)
            );
            expect(
                request(
                    &fixture.state,
                    "POST",
                    "/userinfo",
                    headers(auth, Some("unvalidated-proof"), true)?,
                    oversized,
                )
                .await?,
                StatusCode::BAD_REQUEST,
                Some(scheme),
                Some("invalid_request"),
                false,
            )
            .await?;
        }
        for (auth, scheme) in [("Unknown credentials", "Bearer"), ("DPoP token", "DPoP")] {
            expect(
                request(
                    &fixture.state,
                    "POST",
                    "/userinfo",
                    headers(Some(auth), Some("unvalidated-proof"), true)?,
                    "access_token=body",
                )
                .await?,
                StatusCode::BAD_REQUEST,
                Some(scheme),
                Some("invalid_request"),
                false,
            )
            .await?;
        }
        assert_eq!(fixture.replay.attempts(), 0);
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}
