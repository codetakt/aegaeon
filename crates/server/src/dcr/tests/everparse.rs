use super::super::everparse::{
    encode_dcr_registration_request, finalize_dcr_everparse_self_check,
    should_run_dcr_everparse_self_check,
};
use super::*;
use ffi::dcr_parser::DcrParseError;

#[test]
fn dcr_everparse_encoding_supports_jwt_bearer_grant_type() -> DcrTestResult {
    let meta = ClientRegistration {
        client_id: None,
        token_endpoint_auth_method: None,
        token_endpoint_auth_signing_alg: None,
        id_token_signed_response_alg: None,
        redirect_uris: None,
        post_logout_redirect_uris: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        jwks_uri: None,
        jwks: None,
        software_statement: None,
        grant_types: Some(vec![JWT_BEARER_GRANT_TYPE.to_string()]),
        response_types: None,
        scope: None,
        pkce_required: None,
        require_sender_constrained_tokens: None,
        sender_constrained_methods: None,
        require_dpop: None,
        require_mtls: None,
    };

    let encoded = must_ok!(
        encode_dcr_registration_request(&meta),
        "encoding should succeed for JWT bearer grant type",
    );
    assert!(
        encoded.len() >= 18,
        "encoded buffer too short: {}",
        encoded.len()
    );

    // Layout:
    // [0..4]   version
    // [4..8]   redirect_uris_length
    // [8]      has_token_endpoint_auth_method
    // [9..13]  token_endpoint_auth_method
    // [13]     has_grant_types
    // [14..18] grant_types bitmask
    assert_eq!(encoded[13], 1, "grant_types presence flag must be set");
    let mask = u32::from_le_bytes([encoded[14], encoded[15], encoded[16], encoded[17]]);
    assert_eq!(mask, 0x8);
    Ok(())
}

#[test]
fn dcr_everparse_encoding_supports_token_exchange_grant_type() -> DcrTestResult {
    let meta = ClientRegistration {
        client_id: None,
        token_endpoint_auth_method: None,
        token_endpoint_auth_signing_alg: None,
        id_token_signed_response_alg: None,
        redirect_uris: None,
        post_logout_redirect_uris: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        jwks_uri: None,
        jwks: None,
        software_statement: None,
        grant_types: Some(vec![TOKEN_EXCHANGE_GRANT_TYPE.to_string()]),
        response_types: None,
        scope: None,
        pkce_required: None,
        require_sender_constrained_tokens: None,
        sender_constrained_methods: None,
        require_dpop: None,
        require_mtls: None,
    };

    let encoded = must_ok!(
        encode_dcr_registration_request(&meta),
        "encoding should succeed for token exchange grant type",
    );
    assert!(
        encoded.len() >= 18,
        "encoded buffer too short: {}",
        encoded.len()
    );

    assert_eq!(encoded[13], 1, "grant_types presence flag must be set");
    let mask = u32::from_le_bytes([encoded[14], encoded[15], encoded[16], encoded[17]]);
    assert_eq!(mask, 0x10);
    Ok(())
}

#[test]
fn compat_profile_allows_dcr_self_check_bypass_when_disabled() -> DcrTestResult {
    assert!(!should_run_dcr_everparse_self_check(false));
    assert!(should_run_dcr_everparse_self_check(true));
    assert_eq!(
        finalize_dcr_everparse_self_check(false, Err(DcrParseError::ParserUnavailable)),
        Ok(())
    );
    Ok(())
}

#[cfg(feature = "verified-claim")]
#[test]
fn verified_claim_profile_requires_dcr_self_check_without_env_gate() -> DcrTestResult {
    assert!(should_run_dcr_everparse_self_check(false));

    let err = must_err!(
        finalize_dcr_everparse_self_check(true, Err(DcrParseError::ParserUnavailable)),
        "strict profile must fail closed when DCR parser is unavailable",
    );

    assert_eq!(err, DcrEverparseSelfCheckError::ParserUnavailable);
    Ok(())
}
