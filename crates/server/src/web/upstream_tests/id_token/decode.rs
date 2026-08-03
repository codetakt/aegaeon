use super::*;
use crate::web::upstream_id_token::UpstreamIdTokenDecodeInput;

#[test]
fn decode_upstream_id_token_accepts_rs256_required_slice() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();

    let request = make_auth_request("state-rs256", std::time::Duration::from_secs(60));
    let discovery = base_discovery(&request.issuer)?;
    let signing_key = upstream_signing_key()?;
    let jwks = upstream_jwks(&signing_key)?;
    let access_token = "upstream-access-token";
    let code = "upstream-auth-code";
    let token = sign_upstream_id_token(&signing_key, &request, access_token, code)?;
    if id_token_structure_parser_unavailable(&token) {
        return Ok(());
    }

    let decoded = decode_upstream_id_token(UpstreamIdTokenDecodeInput {
        token: &token,
        jwks: &jwks,
        discovery: &discovery,
        request: &request,
        access_token: Some(access_token),
        code,
        jwt_leeway_secs: 60,
        jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
    })
    .map_err(|err| format!("decode upstream id_token: {}", err.message))?;

    assert_eq!(decoded.signing_alg, "RS256");
    assert_eq!(decoded.claims.sub, "subject-123");
    assert_eq!(
        decoded.claims.nonce.as_deref(),
        Some(request.nonce.as_str())
    );
    Ok(())
}

#[test]
fn decode_upstream_id_token_rejects_duplicate_payload_claims_in_non_rs256_branch() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();

    let request = make_auth_request("state-rs384-duplicate", std::time::Duration::from_secs(60));
    let mut discovery = base_discovery(&request.issuer)?;
    discovery.id_token_signing_alg_values_supported = vec!["RS384".to_string()];
    let signing_key = upstream_signing_key()?;
    let jwks = upstream_jwks_with_alg(&signing_key, "RS384")?;
    let now = now_epoch_secs().map_err(|err| err.to_string())?;
    let payload = format!(
        r#"{{"iss":"{}","iss":"{}","sub":"subject-123","aud":"{}","exp":{},"iat":{},"nonce":"{}"}}"#,
        request.issuer,
        request.issuer,
        request.client_id,
        now.saturating_add(3600),
        now,
        request.nonce
    );
    let token = sign_raw_upstream_id_token(
        &signing_key,
        jsonwebtoken::Algorithm::RS384,
        payload.as_bytes(),
    )?;

    let err = require_err(
        decode_upstream_id_token(UpstreamIdTokenDecodeInput {
            token: &token,
            jwks: &jwks,
            discovery: &discovery,
            request: &request,
            access_token: None,
            code: "upstream-auth-code",
            jwt_leeway_secs: 60,
            jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        }),
        "duplicate upstream ID Token payload claims must fail closed",
    )?;

    assert_eq!(err.status, StatusCode::BAD_GATEWAY);
    assert_eq!(err.message, "upstream id_token payload invalid");
    Ok(())
}

#[test]
fn decode_upstream_id_token_reports_internal_error_for_unknown_raw_json_backend_override(
) -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::JoseHeader,
    );
    let _env = EnvVarGuard::new(key, Some("future"));

    let result = {
        let request = make_auth_request("state-rs256", std::time::Duration::from_secs(60));
        let discovery = base_discovery(&request.issuer)?;
        let signing_key = upstream_signing_key()?;
        let jwks = upstream_jwks(&signing_key)?;
        let access_token = "upstream-access-token";
        let code = "upstream-auth-code";
        let token = sign_upstream_id_token(&signing_key, &request, access_token, code)?;

        decode_upstream_id_token(UpstreamIdTokenDecodeInput {
            token: &token,
            jwks: &jwks,
            discovery: &discovery,
            request: &request,
            access_token: Some(access_token),
            code,
            jwt_leeway_secs: 60,
            jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
        })
    };

    let err = require_err(result, "unknown raw JSON backend must fail closed")?;

    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        err.message,
        "upstream id_token processing failed internally"
    );
    Ok(())
}

#[test]
fn refreshed_upstream_id_token_signature_failure_uses_internal_server_error() {
    let failure = refreshed_upstream_id_token_signature_failure(
        UpstreamIdTokenSignatureError::Internal("local JOSE header parser misconfigured".into()),
    );

    assert_eq!(failure.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        failure.message,
        "upstream id_token processing failed internally"
    );
}
