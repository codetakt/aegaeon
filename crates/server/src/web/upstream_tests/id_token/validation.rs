use super::*;

#[test]
fn validate_upstream_id_token_requires_access_token_when_at_hash_present() -> TestResult {
    let request = make_auth_request("state-rs256", std::time::Duration::from_secs(60));
    let access_token = "upstream-access-token";
    let code = "upstream-auth-code";
    let claims = crate::oidc::IdTokenBuilder::try_new(
        request.issuer.clone(),
        "subject-123".to_string(),
        request.client_id.clone(),
    )
    .map_err(|err| err.to_string())?
    .access_token_hash(
        access_token,
        crate::oidc::required_rs256::REQUIRED_SIGNING_ALG,
    )
    .map_err(|err| err.to_string())?
    .code_hash(code, crate::oidc::required_rs256::REQUIRED_SIGNING_ALG)
    .map_err(|err| err.to_string())?
    .build();
    let id_token = crate::oidc::IdToken {
        claims: claims.claims,
        signing_alg: crate::oidc::required_rs256::REQUIRED_SIGNING_ALG.to_string(),
    };

    let err = require_err(
        validate_upstream_id_token(
            &id_token,
            &UpstreamIdTokenValidationInput {
                client_id: &request.client_id,
                issuer: &request.issuer,
                expected_nonce: None,
                max_age: None,
                access_token: None,
                code: Some(code),
                requested_acr: None,
                jwt_leeway_secs: 60,
            },
        ),
        "missing upstream access_token should be rejected",
    )?;

    assert_eq!(err, "upstream access_token missing");
    Ok(())
}

#[test]
fn validate_upstream_id_token_rejects_negative_auth_time_without_max_age() -> TestResult {
    let request = make_auth_request(
        "state-negative-auth-time",
        std::time::Duration::from_secs(60),
    );
    let claims = crate::oidc::IdTokenBuilder::try_new(
        request.issuer.clone(),
        "subject-123".to_string(),
        request.client_id.clone(),
    )
    .map_err(|err| err.to_string())?
    .auth_time(-1)
    .build();
    let id_token = crate::oidc::IdToken {
        claims: claims.claims,
        signing_alg: crate::oidc::required_rs256::REQUIRED_SIGNING_ALG.to_string(),
    };

    let err = require_err(
        validate_upstream_id_token(
            &id_token,
            &UpstreamIdTokenValidationInput {
                client_id: &request.client_id,
                issuer: &request.issuer,
                expected_nonce: None,
                max_age: None,
                access_token: None,
                code: None,
                requested_acr: None,
                jwt_leeway_secs: 60,
            },
        ),
        "negative upstream auth_time should be rejected",
    )?;

    assert_eq!(err, "upstream id_token auth_time is invalid");
    Ok(())
}

#[test]
fn validate_upstream_id_token_rejects_future_auth_time_without_max_age() -> TestResult {
    let request = make_auth_request("state-future-auth-time", std::time::Duration::from_secs(60));
    let auth_time = now_epoch_secs()
        .map_err(|err| err.to_string())?
        .saturating_add(120)
        .cast_signed();
    let claims = crate::oidc::IdTokenBuilder::try_new(
        request.issuer.clone(),
        "subject-123".to_string(),
        request.client_id.clone(),
    )
    .map_err(|err| err.to_string())?
    .auth_time(auth_time)
    .build();
    let id_token = crate::oidc::IdToken {
        claims: claims.claims,
        signing_alg: crate::oidc::required_rs256::REQUIRED_SIGNING_ALG.to_string(),
    };

    let err = require_err(
        validate_upstream_id_token(
            &id_token,
            &UpstreamIdTokenValidationInput {
                client_id: &request.client_id,
                issuer: &request.issuer,
                expected_nonce: None,
                max_age: None,
                access_token: None,
                code: None,
                requested_acr: None,
                jwt_leeway_secs: 60,
            },
        ),
        "future upstream auth_time should be rejected",
    )?;

    assert_eq!(err, "upstream id_token auth_time is in the future");
    Ok(())
}

#[test]
fn oidc_subject_format_signed_upstream_decode() -> TestResult {
    let request = make_auth_request("subject-format", std::time::Duration::from_secs(60));
    let discovery = base_discovery(&request.issuer)?;
    let key = upstream_signing_key()?;
    let jwks = upstream_jwks(&key)?;
    for (subject, valid) in [
        ("A".into(), true),
        ("x".repeat(255), true),
        (String::new(), false),
        ("é".into(), false),
        ("x".repeat(256), false),
    ] {
        let mut claims = crate::oidc::IdTokenBuilder::try_new(
            request.issuer.clone(),
            "valid".into(),
            request.client_id.clone(),
        )
        .map_err(|e| e.to_string())?
        .nonce(request.nonce.clone())
        .build()
        .claims;
        claims.sub = subject.clone();
        let encoded = serde_json::to_vec(&claims).map_err(|e| e.to_string())?;
        let token = sign_raw_upstream_id_token(&key, jsonwebtoken::Algorithm::RS256, &encoded)?;
        let decoded =
            decode_upstream_id_token(crate::web::upstream_id_token::UpstreamIdTokenDecodeInput {
                token: &token,
                jwks: &jwks,
                discovery: &discovery,
                request: &request,
                access_token: None,
                code: "code",
                jwt_leeway_secs: 60,
                jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
            });
        if valid {
            assert_eq!(decoded.map_err(|e| e.message)?.claims.sub, subject);
        } else {
            assert!(decoded.is_err());
        }
    }
    Ok(())
}
