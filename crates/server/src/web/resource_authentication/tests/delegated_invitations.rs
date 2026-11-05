use super::fixture::*;
use crate::web::test_support::TestResult;
use axum::{
    body::{to_bytes, Body},
    http::StatusCode,
};

fn require(condition: bool, message: &str) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

async fn check(methods: &[&str], suffix: &str, protected: bool) -> TestResult {
    let fixture = Fixture::new().await?;
    let result: TestResult = async {
        let path = format!(
            "/organizations/{}/invitations{suffix}",
            uuid::Uuid::new_v4()
        );
        for method in methods {
            for query in [
                "access_token=synthetic",
                "%61ccess_token=",
                "ACCESS-TOKEN=synthetic",
                "refresh_token=synthetic",
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
                        headers(auth, Some("unvalidated-proof"), false)?,
                        Body::empty(),
                    )
                    .await?;
                    require(
                        response.status() == StatusCode::BAD_REQUEST,
                        "query credentials must be refused",
                    )?;
                    let challenged = protected && !query.starts_with("refresh_token");
                    require(
                        response
                            .headers()
                            .get_all("www-authenticate")
                            .iter()
                            .count()
                            == usize::from(challenged),
                        "delegated invitation challenge count",
                    )?;
                    if challenged {
                        let mut expected =
                            format!("{scheme} realm=\"aegaeon\", error=\"invalid_request\"");
                        if scheme == "DPoP" {
                            expected.push_str(", algs=\"EdDSA\"");
                        }
                        require(
                            response.headers()["www-authenticate"] == expected,
                            "delegated invitation challenge scheme",
                        )?;
                    }
                    require(
                        !response.headers().contains_key("dpop-nonce"),
                        "query refusal must not issue nonce",
                    )?;
                    require(
                        response.headers()["cache-control"] == "no-store"
                            && response.headers()["pragma"] == "no-cache",
                        "query refusal must prevent caching",
                    )?;
                    if *method != "HEAD" {
                        let body: serde_json::Value =
                            serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
                        require(body["error"] == "invalid_request", "query error code")?;
                    }
                    require(
                        fixture.replay.attempts() == 0,
                        "early refusal must not consume a proof",
                    )?;
                }
            }
        }
        Ok(())
    }
    .await;
    let cleanup = fixture.finish().await;
    result.and(cleanup)
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual delegated invitation issue URI admission"]
async fn resource_authentication_delegated_invitation_issue_query() -> TestResult {
    check(&["POST"], "", true).await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual delegated invitation read and HEAD URI admission"]
async fn resource_authentication_delegated_invitation_read_query() -> TestResult {
    check(
        &["GET", "HEAD"],
        &format!("/{}", uuid::Uuid::new_v4()),
        true,
    )
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; actual delegated invitation revoke URI admission"]
async fn resource_authentication_delegated_invitation_revoke_query() -> TestResult {
    check(
        &["POST"],
        &format!("/{}/revoke", uuid::Uuid::new_v4()),
        true,
    )
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL; unsupported invitation methods and paths retain generic errors"]
async fn resource_authentication_delegated_invitation_other_routes() -> TestResult {
    check(&["GET", "HEAD", "PUT"], "", false).await?;
    check(
        &["POST", "PUT"],
        &format!("/{}", uuid::Uuid::new_v4()),
        false,
    )
    .await?;
    check(
        &["GET", "HEAD", "PUT"],
        &format!("/{}/revoke", uuid::Uuid::new_v4()),
        false,
    )
    .await?;
    check(&["GET", "POST"], "/unknown/path/extra", false).await
}
