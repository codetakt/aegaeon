use super::*;
use axum::{body::to_bytes, http::header};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn software_statement_mapper_keeps_internal_failures_private() -> TestResult {
    for error in [
        SoftwareStatementVerificationError::Internal("private diagnostic \"é"),
        SoftwareStatementVerificationError::BackendPolicy("private backend diagnostic"),
    ] {
        let response = software_statement_verification_response(&error, "https://issuer.example");
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"], "server_error");
        assert_eq!(
            body["error_description"],
            "software statement verification unavailable"
        );
    }
    let response = software_statement_verification_response(
        &SoftwareStatementVerificationError::Invalid("private assertion diagnostic \"é".into()),
        "https://issuer.example",
    );
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
    assert_eq!(body["error"], "invalid_software_statement");
    assert_eq!(body["error_description"], "software statement is invalid");
    Ok(())
}
