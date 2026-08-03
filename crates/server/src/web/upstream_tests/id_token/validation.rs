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
