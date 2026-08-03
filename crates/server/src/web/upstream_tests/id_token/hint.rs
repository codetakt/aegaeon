use super::*;

#[test]
fn decode_id_token_hint_rejects_duplicate_payload_claims() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();

    let signing_key = upstream_signing_key()?;
    let now = now_epoch_secs().map_err(|err| err.to_string())?;
    let payload = format!(
        r#"{{"iss":"https://issuer.example","iss":"https://issuer.example","sub":"subject-123","aud":"client","exp":{},"iat":{}}}"#,
        now.saturating_add(3600),
        now
    );
    let token = sign_raw_upstream_id_token(
        &signing_key,
        jsonwebtoken::Algorithm::RS256,
        payload.as_bytes(),
    )?;
    let cfg = OidcConfig {
        issuer: "https://issuer.example".to_string(),
        id_token_ttl_secs: 3600,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: true,
        backchannel_logout_enabled: false,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: false,
        signing_key,
        request_object_encryption_key: None,
    };

    let err = require_err(
        decode_id_token_hint(&cfg, &token, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN),
        "duplicate id_token_hint payload claims must fail closed",
    )?;

    assert_eq!(err.status, StatusCode::BAD_REQUEST);
    assert_eq!(err.public_description(), "id_token_hint payload invalid");
    Ok(())
}

#[test]
fn decode_id_token_hint_reports_internal_error_for_unknown_header_backend_override() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::JoseHeader,
    );
    let _env = EnvVarGuard::new(key, Some("future"));
    let signing_key = upstream_signing_key()?;
    let request = make_auth_request(
        "state-id-token-hint-header-backend",
        std::time::Duration::from_secs(60),
    );
    let token = sign_upstream_id_token(&signing_key, &request, "upstream-access-token", "code")?;
    let cfg = OidcConfig {
        issuer: request.issuer,
        id_token_ttl_secs: 3600,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: true,
        backchannel_logout_enabled: false,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: false,
        signing_key,
        request_object_encryption_key: None,
    };

    let err = require_err(
        decode_id_token_hint(&cfg, &token, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN),
        "unknown id_token_hint header backend must fail closed",
    )?;

    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        err.public_description(),
        "id_token_hint processing failed internally"
    );
    Ok(())
}

#[test]
fn decode_id_token_hint_reports_internal_error_for_unknown_payload_backend_override() -> TestResult
{
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let key = aegaeon_jose::raw_json::raw_json_backend_env_var_for_surface(
        aegaeon_jose::raw_json::RawJsonSurface::OidcIdTokenPayload,
    );
    let _env = EnvVarGuard::new(key, Some("future"));
    let signing_key = upstream_signing_key()?;
    let request = make_auth_request("state-id-token-hint", std::time::Duration::from_secs(60));
    let token = sign_upstream_id_token(&signing_key, &request, "upstream-access-token", "code")?;
    let cfg = OidcConfig {
        issuer: request.issuer,
        id_token_ttl_secs: 3600,
        discovery_enabled: true,
        userinfo_enabled: true,
        logout_enabled: true,
        backchannel_logout_enabled: false,
        logout_session_ttl_secs: 600,
        backchannel_logout_timeout_secs: 2,
        require_nonce: false,
        signing_key,
        request_object_encryption_key: None,
    };

    let err = require_err(
        decode_id_token_hint(&cfg, &token, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN),
        "unknown id_token_hint payload backend must fail closed",
    )?;

    assert_eq!(err.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        err.public_description(),
        "id_token_hint processing failed internally"
    );
    Ok(())
}
