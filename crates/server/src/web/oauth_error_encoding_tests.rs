use super::*;
use axum::{
    body::to_bytes,
    http::{header, StatusCode},
};
use serde_json::{json, Value};
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn oauth_error_encoding_dynamic_web_serializers_preserve_status_and_envelopes() -> TestResult
{
    const BAD: &str = "\"\\é雪😀\r\n\t\0";
    const CLEAN: &str = "?????????";
    const ISSUER: &str = "https://issuer.example/é?x=+&y=%25";
    let par = crate::par::ParError {
        error: BAD.into(),
        error_description: Some(BAD.into()),
    };
    let (par_body, status) = par_endpoint::par_error_response_body_and_status(&par);
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        par_body,
        json!({"error":"server_error","error_description":CLEAN})
    );
    for response in [
        oauth_errors::json_error_with_iss(StatusCode::BAD_REQUEST, BAD, Some(BAD), ISSUER),
        token_response::token_error_response(StatusCode::BAD_REQUEST, BAD, Some(BAD)),
        token_response::token_issuer_error_response(BAD, Some(BAD)),
        authorize_request::par_authorize_error_response(ISSUER, &par),
    ] {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["error"], "server_error");
        assert_eq!(body["error_description"], CLEAN);
        if let Some(issuer) = body.get("iss") {
            assert_eq!(issuer, ISSUER);
        }
    }
    for detail in [Some(BAD), Some(""), None] {
        let response =
            oauth_errors::bearer_json_error_with_iss(StatusCode::FORBIDDEN, BAD, detail, ISSUER);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer realm=\"aegaeon\", error=\"server_error\""
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
        assert_eq!(body["iss"], ISSUER);
        if detail == Some(BAD) {
            assert_eq!(body["error_description"], CLEAN);
        } else {
            assert!(body.get("error_description").is_none());
        }
    }
    let response = userinfo_error_response(
        crate::oidc::userinfo::Error::InvalidRequest(BAD.into()),
        ISSUER,
        "DPoP",
    );
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "DPoP realm=\"aegaeon\", error=\"invalid_request\""
    );
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), 65536).await?)?;
    assert_eq!(body["error_description"], CLEAN);
    Ok(())
}
