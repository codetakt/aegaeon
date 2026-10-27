use super::*;
use crate::web::upstream_id_token::{
    verify_upstream_id_token_claims, UpstreamIdTokenDecodeInput,
};

fn audience_payload(request: &crate::upstream::UpstreamAuthRequest) -> Result<serde_json::Value, String> {
    let now = now_epoch_secs()?;
    Ok(json!({"iss":request.issuer,"sub":"subject-123","aud":request.client_id,
        "iat":now,"exp":now + 3600,"nonce":request.nonce}))
}

fn sign_audience_payload(payload: &serde_json::Value) -> Result<String, String> {
    sign_raw_upstream_id_token(&upstream_signing_key()?, jsonwebtoken::Algorithm::RS256,
        &serde_json::to_vec(payload).map_err(|err| err.to_string())?)
}

fn check_audience_paths(token: &str, request: &crate::upstream::UpstreamAuthRequest, expected: bool) -> TestResult {
    let discovery = base_discovery(&request.issuer)?;
    let jwks = upstream_jwks(&upstream_signing_key()?)?;
    let callback = decode_upstream_id_token(UpstreamIdTokenDecodeInput {
        token, jwks: &jwks, discovery: &discovery, request,
        access_token: Some("access-token"), code: "code", jwt_leeway_secs: 60,
        jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
    });
    assert_eq!(callback.is_ok(), expected, "callback admission");
    let verified = verify_upstream_id_token_claims(token, &jwks, &discovery,
        aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN);
    // Refresh verifies the same signed claims, then uses this exact context
    // without the authorization response's nonce/code. No network/DB fixture.
    let refresh = verified.map_err(|err| format!("{err:?}")).and_then(|(claims, alg)| {
        validate_upstream_id_token(&crate::oidc::IdToken {claims, signing_alg: alg.into()},
            &UpstreamIdTokenValidationInput {
                client_id: &request.client_id, issuer: &request.issuer,
                expected_nonce: None, max_age: None, access_token: Some("access-token"),
                code: None, requested_acr: None, jwt_leeway_secs: 60,
            })
    });
    assert_eq!(refresh.is_ok(), expected, "refresh admission: {refresh:?}");
    Ok(())
}

#[test]
fn signed_upstream_audience_trust_applies_to_callback_and_refresh() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD.lock().map_err(|_| "raw json env guard")?;
    let _header = use_jose_header_verified_structural_backend();
    let _payload = use_oidc_id_token_payload_verified_structural_backend();
    let mut request = make_auth_request("audience-trust", std::time::Duration::from_secs(60));
    request.client_id = "client456".into();
    for (aud, trusted) in [
        (json!("client456"), true), (json!(["client456"]), true),
        (json!(["client456", "client456"]), true),
        (json!([]), false), (json!(""), false), (json!(["other"]), false),
        (json!(["client456", "other"]), false), (json!(["other", "client456"]), false),
        (json!(["client456", ""]), false), (json!(["client456", "Client456"]), false),
        (json!(["client456", "client456 "]), false), (json!(["client456", "client%34%35%36"]), false),
        (json!("Client456"), false), (json!(" client456"), false),
        (json!("client456 "), false), (json!("client%34%35%36"), false),
    ] {
        for azp in [None, Some("client456"), Some("other"), Some("Client456"), Some("client456 "), Some("client%34%35%36"), Some("")] {
            let mut payload = audience_payload(&request)?;
            payload["aud"] = aud.clone();
            if let Some(value) = azp { payload["azp"] = json!(value); }
            check_audience_paths(&sign_audience_payload(&payload)?, &request,
                trusted && azp.is_none_or(|value| value == "client456"))?;
        }
    }
    Ok(())
}

#[test]
fn signed_upstream_audience_missing_or_wrong_type_is_rejected() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD.lock().map_err(|_| "raw json env guard")?;
    let _header = use_jose_header_verified_structural_backend();
    let _payload = use_oidc_id_token_payload_verified_structural_backend();
    let request = make_auth_request("audience-types", std::time::Duration::from_secs(60));
    for aud in [json!(null), json!(7), json!({}), json!([request.client_id, 7])] {
        let mut payload = audience_payload(&request)?;
        payload["aud"] = aud;
        check_audience_paths(&sign_audience_payload(&payload)?, &request, false)?;
    }
    let mut payload = audience_payload(&request)?;
    payload.as_object_mut().ok_or("claims object")?.remove("aud");
    check_audience_paths(&sign_audience_payload(&payload)?, &request, false)
}

#[test]
fn signed_upstream_audience_policy_preserves_other_claim_and_signature_checks() -> TestResult {
    let _guard = crate::util::RAW_JSON_ENV_GUARD.lock().map_err(|_| "raw json env guard")?;
    let _header = use_jose_header_verified_structural_backend();
    let _payload = use_oidc_id_token_payload_verified_structural_backend();
    let request = make_auth_request("audience-controls", std::time::Duration::from_secs(60));
    let baseline = audience_payload(&request)?;
    check_audience_paths(&sign_audience_payload(&baseline)?, &request, true)?;
    for (field, value) in [("iss", json!("https://other.example")), ("exp", json!(1)),
        ("iat", json!(now_epoch_secs()? + 7200)), ("at_hash", json!("wrong-hash"))] {
        let mut payload = baseline.clone();
        payload[field] = value;
        check_audience_paths(&sign_audience_payload(&payload)?, &request, false)?;
    }
    let mut payload = baseline;
    payload["nonce"] = json!("wrong-nonce");
    let discovery = base_discovery(&request.issuer)?;
    let jwks = upstream_jwks(&upstream_signing_key()?)?;
    let token = sign_audience_payload(&payload)?;
    assert!(decode_upstream_id_token(UpstreamIdTokenDecodeInput {
        token: &token, jwks: &jwks, discovery: &discovery, request: &request,
        access_token: Some("access-token"), code: "code", jwt_leeway_secs: 60,
        jose_header_max_len: aegaeon_jose::policy::DEFAULT_HEADER_MAX_LEN,
    }).is_err());
    payload["nonce"] = json!(request.nonce);
    payload["c_hash"] = json!("wrong-hash");
    check_audience_paths(&sign_audience_payload(&payload)?, &request, false)?;
    payload.as_object_mut().ok_or("claims object")?.remove("c_hash");
    let token = sign_audience_payload(&payload)?;
    let (message, signature) = token.rsplit_once('.').ok_or("compact signature")?;
    let mut signature = URL_SAFE_NO_PAD.decode(signature).map_err(|err| err.to_string())?;
    signature[0] ^= 1;
    check_audience_paths(&format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)), &request, false)
}
