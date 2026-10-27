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


fn sign_hint_fixture(cfg: &OidcConfig, typ: Option<&str>, payload: &[u8]) -> Result<String, String> {
    let mut header = json!({"alg": "RS256", "kid": cfg.signing_key.kid()});
    if let Some(typ) = typ {
        header["typ"] = json!(typ);
    }
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|e| e.to_string())?);
    let signing_input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(payload));
    let key = cfg
        .signing_key
        .local_encoding_key()
        .ok_or_else(|| "fixture requires a local signing key".to_string())?;
    let signature = jsonwebtoken::crypto::sign(
        signing_input.as_bytes(),
        key,
        jsonwebtoken::Algorithm::RS256,
    )
    .map_err(|e| e.to_string())?;
    Ok(format!("{signing_input}.{signature}"))
}

fn hint_fixture_claims(cfg: &OidcConfig) -> Result<serde_json::Value, String> {
    let now = now_epoch_secs().map_err(|e| e.to_string())?;
    Ok(json!({
        "iss": cfg.issuer, "sub": "subject-123", "aud": "client",
        "iat": now, "exp": now.saturating_add(300)
    }))
}

#[test]
fn decode_id_token_hint_rejects_logout_header_without_event() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let cfg = test_oidc_logout_config(upstream_signing_key()?);
    let payload = serde_json::to_vec(&hint_fixture_claims(&cfg)?).map_err(|e| e.to_string())?;
    for typ in ["logout+jwt", "application/logout+jwt", "LoGoUt+JwT", "APPLICATION/LOGOUT+JWT"] {
        let token = sign_hint_fixture(&cfg, Some(typ), &payload)?;
        let err = require_err(
            decode_id_token_hint(&cfg, &token, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN),
            "Logout Token header must fail without an event claim",
        )?;
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.error, "invalid_request");
        assert_eq!(err.public_description(), "id_token_hint must be an ID Token");
    }
    Ok(())
}

#[test]
fn decode_id_token_hint_rejects_logout_event_without_logout_header() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let cfg = test_oidc_logout_config(upstream_signing_key()?);
    for typ in [None, Some("JWT"), Some("application/jwt")] {
        for value in [json!({}), json!(null), json!(false), json!("logout"), json!([]), json!(1)] {
            let mut claims = hint_fixture_claims(&cfg)?;
            claims["events"] = json!({"http://schemas.openid.net/event/backchannel-logout": value});
            let raw = serde_json::to_string(&claims).map_err(|e| e.to_string())?;
            // JSON escapes must not disguise the exact event key after typed decoding.
            for payload in [raw.clone(), raw.replace("backchannel-logout", r"backchannel-\u006cogout")] {
                let token = sign_hint_fixture(&cfg, typ, payload.as_bytes())?;
                let err = require_err(
                    decode_id_token_hint(&cfg, &token, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN),
                    "logout event must fail with a legacy or missing type",
                )?;
                assert_eq!(err.status, StatusCode::BAD_REQUEST);
                assert_eq!(err.error, "invalid_request");
                assert_eq!(err.public_description(), "id_token_hint must be an ID Token");
            }
        }
    }
    Ok(())
}

#[test]
fn decode_id_token_hint_preserves_ordinary_types_and_additional_claims() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let cfg = test_oidc_logout_config(upstream_signing_key()?);
    for typ in [None, Some("JWT"), Some("application/jwt"), Some("custom+jwt")] {
        let mut claims = hint_fixture_claims(&cfg)?;
        claims["events"] = json!({"https://events.example/other": {}});
        claims["email"] = json!("subject@example.com");
        let payload = serde_json::to_vec(&claims).map_err(|e| e.to_string())?;
        let token = sign_hint_fixture(&cfg, typ, &payload)?;
        let decoded = decode_id_token_hint(&cfg, &token, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN)
            .map_err(|e| e.public_description().to_string())?;
        assert_eq!(decoded.sub, "subject-123");
        assert_eq!(decoded.additional_claims.get("events"), Some(&claims["events"]));
        assert_eq!(decoded.additional_claims.get("email"), Some(&claims["email"]));
    }
    Ok(())
}

#[test]
fn decode_id_token_hint_checks_signature_and_duplicates_before_event() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD
        .lock()
        .map_err(|_| "raw json env guard".to_string())?;
    let _header_backend = use_jose_header_verified_structural_backend();
    let _payload_backend = use_oidc_id_token_payload_verified_structural_backend();
    let cfg = test_oidc_logout_config(upstream_signing_key()?);
    let mut claims = hint_fixture_claims(&cfg)?;
    claims["events"] = json!({"http://schemas.openid.net/event/backchannel-logout": {}});
    let payload = serde_json::to_string(&claims).map_err(|e| e.to_string())?;
    let token = sign_hint_fixture(&cfg, Some("JWT"), payload.as_bytes())?;
    let (signing_input, signature) = token.rsplit_once('.').ok_or_else(|| "signature".to_string())?;
    let mut signature = URL_SAFE_NO_PAD.decode(signature).map_err(|e| e.to_string())?;
    signature[0] ^= 1;
    let tampered = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    let err = require_err(
        decode_id_token_hint(&cfg, &tampered, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN),
        "invalid signature must fail before event purpose validation",
    )?;
    assert_eq!(err.public_description(), "id_token_hint signature invalid");
    for duplicate in [r#""iss":"https://issuer.example","#, r#""events":{},"#] {
        let payload = format!("{{{duplicate}{}", &payload[1..]);
        let token = sign_hint_fixture(&cfg, Some("JWT"), payload.as_bytes())?;
        let err = require_err(
            decode_id_token_hint(&cfg, &token, aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN),
            "duplicate claims must fail before event purpose validation",
        )?;
        assert_eq!(err.public_description(), "id_token_hint payload invalid");
    }
    Ok(())
}
