use super::*;
use crate::dcr::DcrEverparseSelfCheckError;
use axum::{body::to_bytes, http::header};

#[tokio::test]
async fn registration_self_check_errors_stay_internal() -> Result<(), Box<dyn std::error::Error>> {
    for error in [
        DcrEverparseSelfCheckError::ParserUnavailable,
        DcrEverparseSelfCheckError::InvalidPayload,
        DcrEverparseSelfCheckError::Encode("private-sentinel \"é".into()),
    ] {
        let response = registration_self_check_error_response(&error);
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert!(!response.headers().contains_key(header::WWW_AUTHENTICATE));
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(body["error"], "server_error");
        assert_eq!(
            body["error_description"],
            "internal registration validation failed"
        );
    }
    Ok(())
}
