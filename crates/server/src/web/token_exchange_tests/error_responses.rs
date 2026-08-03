use super::*;

#[test]
fn dpop_error_responses_are_no_store() {
    let invalid =
        dpop_invalid_token_response("https://issuer.example", "DPoP proof validation failed");
    assert_response_no_store(&invalid);

    let backend_unavailable = dpop_backend_unavailable_response("https://issuer.example");
    assert_response_no_store(&backend_unavailable);

    let nonce = dpop_use_nonce_response("https://issuer.example", "nonce-value");
    assert_response_no_store(&nonce);
    assert_eq!(
        nonce.headers().get("DPoP-Nonce"),
        Some(&HeaderValue::from_static("nonce-value"))
    );
}

#[test]
fn protected_error_helpers_are_no_store() -> TokenExchangeTestResult {
    const ISSUER: &str = "https://issuer.example";

    let form_error = form_parse_error_response(ISSUER);
    assert_response_no_store(&form_error);

    let duplicate_param_error = must_err!(
        optional_token_param(
            &[
                ("client_id".to_string(), "one".to_string()),
                ("client_id".to_string(), "two".to_string()),
            ],
            "client_id",
            ISSUER,
        ),
        "duplicate token endpoint parameters must be rejected",
    );
    assert_response_no_store(&duplicate_param_error);

    let missing_param_error = must_err!(
        required_token_param(&[], "grant_type", ISSUER),
        "missing required token endpoint parameters must be rejected",
    );
    assert_response_no_store(&missing_param_error);

    let dcr_metadata_error = invalid_client_metadata_response("invalid test metadata");
    assert_response_no_store(&dcr_metadata_error);
    Ok(())
}

#[test]
fn par_resolution_errors_are_no_store() -> Result<(), String> {
    const ISSUER: &str = "https://issuer.example";

    for response in [
        require_error_response(
            finalize_par_resolved_parameters(
                par_draft(None, Some("code"), Some("challenge"), Some("S256")),
                ISSUER,
            ),
            "missing redirect_uri must fail",
        )?,
        require_error_response(
            finalize_par_resolved_parameters(
                par_draft(
                    Some("https://rp.example/callback"),
                    Some("token"),
                    Some("challenge"),
                    Some("S256"),
                ),
                ISSUER,
            ),
            "unsupported response_type must fail",
        )?,
        require_error_response(
            finalize_par_resolved_parameters(
                par_draft(
                    Some("https://rp.example/callback"),
                    Some("code"),
                    None,
                    Some("S256"),
                ),
                ISSUER,
            ),
            "missing code_challenge must fail",
        )?,
        require_error_response(
            finalize_par_resolved_parameters(
                par_draft(
                    Some("https://rp.example/callback"),
                    Some("code"),
                    Some("challenge"),
                    Some("plain"),
                ),
                ISSUER,
            ),
            "plain code_challenge_method must fail",
        )?,
    ] {
        assert_response_no_store(&response);
    }
    Ok(())
}

#[tokio::test]
async fn token_issuer_server_error_response_uses_500_and_generic_description() -> Result<(), String>
{
    let response =
        token_issuer_error_response("server_error", Some("failed to sign access_token: detail"));

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .ok_or_else(|| "missing Cache-Control header".to_string())?,
        "no-store"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|err| err.to_string())?;
    let body: Value = serde_json::from_slice(&body).map_err(|err| err.to_string())?;
    assert_eq!(body["error"], "server_error");
    assert_eq!(
        body["error_description"],
        "token endpoint failed internally"
    );
    Ok(())
}

#[tokio::test]
async fn userinfo_server_error_response_uses_500_and_generic_description() -> Result<(), String> {
    let response = userinfo_error_response(
        crate::oidc::userinfo::Error::ServerError("database detail".to_string()),
        "https://issuer.example",
        "Bearer",
    );

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response
            .headers()
            .get(header::CACHE_CONTROL)
            .ok_or_else(|| "missing Cache-Control header".to_string())?,
        "no-store"
    );
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .map_err(|err| err.to_string())?;
    let body: Value = serde_json::from_slice(&body).map_err(|err| err.to_string())?;
    assert_eq!(body["error"], "server_error");
    assert_eq!(
        body["error_description"],
        "userinfo endpoint failed internally"
    );
    Ok(())
}
