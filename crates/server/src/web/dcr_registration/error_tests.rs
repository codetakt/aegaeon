use super::*;
use axum::{body::to_bytes, http::header};

#[tokio::test]
async fn registration_parser_internal_error_is_fixed_server_error(
) -> Result<(), Box<dyn std::error::Error>> {
    let response = registration_parser_internal_error_response(
        "private-sentinel \"é",
        "https://issuer.example",
    );
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::PRAGMA], "no-cache");
    assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(body["error"], "server_error");
    assert_eq!(
        body["error_description"],
        "registration parser backend misconfigured"
    );
    Ok(())
}
