use super::fixture::*;
use crate::web::test_support::TestResult;
use axum::{
    body::{to_bytes, Body},
    http::StatusCode,
};

pub(super) async fn accepted(response: axum::response::Response, path: &str) -> TestResult {
    let status = response.status();
    assert!(!response.headers().contains_key("www-authenticate"));
    assert!(!response.headers().contains_key("dpop-nonce"));
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    if path == "/oauth/upstream/refresh" {
        // Authentication passed into real PG link lookup. No provider exchange is claimed.
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(
            body["error_description"],
            "no upstream refresh token found for this user"
        );
    } else {
        assert_eq!(status, StatusCode::OK, "{body}");
        if path == "/resource" {
            assert_eq!(body["status"], "granted");
            assert_eq!(body["subject"], "resource-auth-subject");
            assert_eq!(body["client_id"], "resource-auth-client");
        } else {
            assert_eq!(body["sub"], "resource-auth-subject");
            if path == "/application/authorization" {
                assert_eq!(body["client_id"], "resource-auth-client");
            }
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; real router, native signed DPoP, synthetic issued metadata"]
async fn resource_authentication_native_controls_preserve_presented_scheme_and_policy() -> TestResult
{
    let fixture = Fixture::new().await?;
    let result = async {
        for (method, path) in SURFACES {
            for dpop in [false, true] {
                let token = fixture.token(path, "openid read", dpop, false).await?;
                let scheme = if dpop { "DPoP" } else { "Bearer" };
                let auth = format!(" \t{}   {token}\t ", scheme.to_ascii_lowercase());
                let proof = dpop
                    .then(|| signed_proof(method, path, Some(&token), None))
                    .transpose()?;
                accepted(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(Some(&auth), proof.as_deref(), method == "POST")?,
                        Body::empty(),
                    )
                    .await?,
                    path,
                )
                .await?;
                let expired = fixture.token(path, "openid read", dpop, true).await?;
                let expired_proof = dpop
                    .then(|| signed_proof(method, path, Some(&expired), None))
                    .transpose()?;
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(
                            Some(&format!("{scheme} {expired}")),
                            expired_proof.as_deref(),
                            method == "POST",
                        )?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::UNAUTHORIZED,
                    Some(scheme),
                    Some("invalid_token"),
                    false,
                )
                .await?;
                let limited = fixture.token(path, "profile", dpop, false).await?;
                let limited_proof = dpop
                    .then(|| signed_proof(method, path, Some(&limited), None))
                    .transpose()?;
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(
                            Some(&format!("{scheme} {limited}")),
                            limited_proof.as_deref(),
                            method == "POST",
                        )?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::FORBIDDEN,
                    Some(scheme),
                    Some("insufficient_scope"),
                    false,
                )
                .await?;
                // Valid signed proof attached to Bearer must not select a DPoP token challenge.
                let invalid_proof =
                    signed_proof(method, path, Some("invalid-fixture-token"), None)?;
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(
                            Some(&format!("{scheme} invalid-fixture-token")),
                            Some(&invalid_proof),
                            method == "POST",
                        )?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::UNAUTHORIZED,
                    Some(scheme),
                    Some("invalid_token"),
                    false,
                )
                .await?;
                let wrong_scheme = if dpop { "Bearer" } else { "DPoP" };
                let wrong_proof = signed_proof(method, path, Some(&token), None)?;
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(
                            Some(&format!("{wrong_scheme} {token}")),
                            Some(&wrong_proof),
                            method == "POST",
                        )?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::UNAUTHORIZED,
                    Some(wrong_scheme),
                    Some("invalid_token"),
                    false,
                )
                .await?;
            }
            let token = fixture.token(path, "openid read", true, false).await?;
            for (algorithm, corrupt) in [(ffi::DPOP_SIGNING_ALGORITHM, true), ("ES256", false)] {
                let before = fixture.replay.attempts();
                let proof =
                    proof_with_algorithm(method, path, Some(&token), None, algorithm, corrupt)?;
                expect(
                    request(
                        &fixture.state,
                        method,
                        path,
                        headers(
                            Some(&format!("DPoP {token}")),
                            Some(&proof),
                            method == "POST",
                        )?,
                        Body::empty(),
                    )
                    .await?,
                    StatusCode::UNAUTHORIZED,
                    Some("DPoP"),
                    Some("invalid_dpop_proof"),
                    false,
                )
                .await?;
                assert_eq!(
                    fixture.replay.attempts(),
                    before,
                    "invalid native signature/algorithm must not reserve replay"
                );
            }
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}

#[tokio::test]
#[ignore = "requires PostgreSQL CREATEDB; current UserInfo body/header and ath contracts"]
async fn resource_authentication_userinfo_post_retains_body_tokens_and_proof_relationships(
) -> TestResult {
    let fixture = Fixture::new().await?;
    let result = async {
        let token = fixture
            .token("/userinfo", "openid read", false, false)
            .await?;
        for (auth, body) in [
            (None, format!("access_token={token}")),
            (Some("  ".to_string()), format!("access_token={token}")),
            (Some(format!("Bearer {token}")), "access_token=+%09+".into()),
            (Some(format!("Bearer {token}")), String::new()),
        ] {
            accepted(
                request(
                    &fixture.state,
                    "POST",
                    "/userinfo",
                    headers(auth.as_deref(), None, true)?,
                    body,
                )
                .await?,
                "/userinfo",
            )
            .await?;
        }
        for body in ["", "access_token=", "access_token=+%09+"] {
            expect(
                request(
                    &fixture.state,
                    "POST",
                    "/userinfo",
                    headers(None, None, true)?,
                    body,
                )
                .await?,
                StatusCode::UNAUTHORIZED,
                Some("Bearer"),
                None,
                false,
            )
            .await?;
        }
        // Body-only Bearer does not synthesize Authorization for the proof's ath check.
        let no_ath = signed_proof("POST", "/userinfo", None, None)?;
        accepted(
            request(
                &fixture.state,
                "POST",
                "/userinfo",
                headers(None, Some(&no_ath), true)?,
                format!("access_token={token}"),
            )
            .await?,
            "/userinfo",
        )
        .await?;
        let with_ath = signed_proof("POST", "/userinfo", Some(&token), None)?;
        expect(
            request(
                &fixture.state,
                "POST",
                "/userinfo",
                headers(None, Some(&with_ath), true)?,
                format!("access_token={token}"),
            )
            .await?,
            StatusCode::UNAUTHORIZED,
            Some("DPoP"),
            Some("invalid_dpop_proof"),
            false,
        )
        .await?;
        let bound = fixture
            .token("/userinfo", "openid read", true, false)
            .await?;
        let no_ath = signed_proof("POST", "/userinfo", None, None)?;
        expect(
            request(
                &fixture.state,
                "POST",
                "/userinfo",
                headers(None, Some(&no_ath), true)?,
                format!("access_token={bound}"),
            )
            .await?,
            StatusCode::UNAUTHORIZED,
            Some("Bearer"),
            Some("invalid_token"),
            false,
        )
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result?;
    cleanup
}
