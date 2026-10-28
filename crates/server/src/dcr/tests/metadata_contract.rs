use super::*;
use crate::dcr::metadata_contract::{
    resolve_registration_defaults, validate_grant_response_relation,
};
use crate::policy::DEVICE_CODE_GRANT_TYPE;
use std::collections::HashSet;

fn metadata(grants: Option<Vec<String>>) -> ClientRegistration {
    ClientRegistration {
        grant_types: grants,
        redirect_uris: Some(vec!["https://client.example/callback".into()]),
        ..Default::default()
    }
}

fn validate(meta: &ClientRegistration) -> Result<(), RegistrationValidationError> {
    validate_registration_with_config_detailed(
        meta,
        false,
        &HashSet::from(["RS256".into()]),
        &DcrValidationConfig::default(),
    )
}

#[test]
fn registration_defaults_to_code_without_implicit_refresh() {
    let effective = resolve_registration_defaults(metadata(None));
    assert_eq!(
        effective.grant_types,
        Some(vec!["authorization_code".into()])
    );
    assert_eq!(effective.response_types, Some(vec!["code".into()]));
    assert_eq!(
        effective.token_endpoint_auth_method.as_deref(),
        Some("client_secret_basic")
    );
    assert!(validate(&effective).is_ok());
}

#[test]
fn registration_non_code_resolves_empty_responses_and_allows_no_redirects() {
    for redirects in [None, Some(vec![])] {
        let mut meta = metadata(Some(vec!["client_credentials".into()]));
        meta.redirect_uris = redirects;
        let effective = resolve_registration_defaults(meta);
        assert_eq!(effective.response_types, Some(vec![]));
        assert!(validate(&effective).is_ok());
    }
}

#[test]
fn registration_code_requires_redirects_and_matching_responses() {
    for grants in [None, Some(vec!["authorization_code".into()])] {
        for redirects in [None, Some(vec![])] {
            let mut meta = metadata(grants.clone());
            meta.redirect_uris = redirects;
            assert!(matches!(
                validate(&meta),
                Err(RegistrationValidationError::RedirectUri(_))
            ));
        }
    }
    let mut code = metadata(None);
    code.response_types = Some(vec![]);
    assert!(matches!(
        validate(&code),
        Err(RegistrationValidationError::Metadata(_))
    ));
    let mut non_code = metadata(Some(vec!["client_credentials".into()]));
    non_code.response_types = Some(vec!["code".into()]);
    assert!(matches!(
        validate(&non_code),
        Err(RegistrationValidationError::Metadata(_))
    ));
}

#[test]
fn registration_rejects_duplicate_grants_and_redirects_without_normalization() {
    let grants = metadata(Some(vec![
        "authorization_code".into(),
        "authorization_code".into(),
    ]));
    assert!(matches!(
        validate(&grants),
        Err(RegistrationValidationError::Metadata(_))
    ));
    let mut redirects = metadata(None);
    redirects.redirect_uris = Some(vec!["https://client.example/callback".into(); 2]);
    assert!(matches!(
        validate(&redirects),
        Err(RegistrationValidationError::RedirectUri(_))
    ));
    for uri in [
        " https://client.example/callback",
        "https://client.example/callback ",
        "https://client.example/call\tback",
        "https://client.example/\u{7f}",
    ] {
        redirects.redirect_uris = Some(vec![uri.into()]);
        assert!(matches!(
            validate(&redirects),
            Err(RegistrationValidationError::RedirectUri(_))
        ));
    }
    redirects.redirect_uris = Some(vec!["HTTPS://CLIENT.EXAMPLE:443/%63allback".into()]);
    assert!(validate(&redirects).is_ok());
    assert_eq!(
        resolve_registration_defaults(redirects).redirect_uris,
        Some(vec!["HTTPS://CLIENT.EXAMPLE:443/%63allback".into()])
    );
}

#[test]
fn registration_conflicting_key_sources_fail_before_key_parsing() {
    for method in ["none", "client_secret_basic", "private_key_jwt"] {
        let mut meta = metadata(None);
        meta.token_endpoint_auth_method = Some(method.into());
        meta.jwks_uri = Some("not a URI".into());
        meta.jwks = Some(serde_json::json!({"keys": "not keys"}));
        let error = validate(&meta).expect_err("dual sources must fail");
        assert!(
            matches!(error, RegistrationValidationError::Metadata(ref text) if text.contains("must not both"))
        );
    }
}

#[test]
fn registration_authenticated_grants_reject_none_without_rejecting_public_code() {
    for grant in ["client_credentials", TOKEN_EXCHANGE_GRANT_TYPE] {
        assert!(
            crate::dcr::metadata_contract::validate_grant_authentication(&[grant.into()], "none")
                .is_err()
        );
        assert!(
            crate::dcr::metadata_contract::validate_grant_authentication(
                &[grant.into()],
                "private_key_jwt"
            )
            .is_ok()
        );
    }
    for grant in ["authorization_code", DEVICE_CODE_GRANT_TYPE] {
        assert!(
            crate::dcr::metadata_contract::validate_grant_authentication(&[grant.into()], "none")
                .is_ok()
        );
    }
    let mut meta = metadata(Some(vec!["client_credentials".into()]));
    meta.token_endpoint_auth_method = Some("none".into());
    assert!(matches!(
        validate(&meta),
        Err(RegistrationValidationError::Metadata(_))
    ));
}

#[test]
fn registration_response_relation_is_exact_for_code_device_and_mixed_grants() {
    for grants in [
        vec!["authorization_code".into()],
        vec!["authorization_code".into(), DEVICE_CODE_GRANT_TYPE.into()],
    ] {
        assert!(validate_grant_response_relation(&grants, &["code".into()]).is_ok());
        assert!(validate_grant_response_relation(&grants, &[]).is_err());
        assert!(
            validate_grant_response_relation(&grants, &["code".into(), "code".into()]).is_err()
        );
    }
    assert!(validate_grant_response_relation(&[DEVICE_CODE_GRANT_TYPE.into()], &[]).is_ok());
    assert!(
        validate_grant_response_relation(&[DEVICE_CODE_GRANT_TYPE.into()], &["code".into()])
            .is_err()
    );
}
