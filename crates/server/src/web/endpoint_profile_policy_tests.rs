use super::*;
use axum::http::StatusCode;

type EndpointProfileTestResult = Result<(), String>;

macro_rules! fail_test {
    ($($arg:tt)*) => {
        return Err(format!($($arg)*))
    };
}

macro_rules! must_err {
    ($result:expr, $context:expr $(,)?) => {
        match $result {
            Ok(_) => fail_test!("{}", $context),
            Err(err) => err,
        }
    };
}

fn profile(grants: &[&str], auth_methods: &[&str]) -> oauth_profile::ResolvedProfile {
    oauth_profile::ResolvedProfile {
        id: "profile-id".to_string(),
        name: "test-profile".to_string(),
        require_pkce: false,
        require_state_parameter: false,
        require_iss_parameter: false,
        sender_constrained: SenderConstraint::None,
        enforce_refresh_sender_binding: false,
        allowed_grant_types: grants.iter().map(ToString::to_string).collect(),
        token_endpoint_auth_methods_allowed: auth_methods.iter().map(ToString::to_string).collect(),
    }
}

#[test]
fn par_profile_requires_state_when_profile_requires_state() -> EndpointProfileTestResult {
    let mut profile = profile(&["authorization_code"], &["private_key_jwt"]);
    profile.require_state_parameter = true;

    let err = must_err!(
        validate_downstream_par_profile_policy(
            &profile,
            "code",
            None,
            None,
            "private_key_jwt",
            "https://issuer.example",
        ),
        "profile state requirement must be enforced at PAR",
    );
    assert_eq!(err.reason, "state_required");

    assert!(validate_downstream_par_profile_policy(
        &profile,
        "code",
        Some("opaque-state"),
        None,
        "private_key_jwt",
        "https://issuer.example",
    )
    .is_ok());
    Ok(())
}

#[test]
fn par_profile_enforces_issuer_identification() -> EndpointProfileTestResult {
    let mut profile = profile(&["authorization_code"], &["client_secret_basic"]);
    profile.require_iss_parameter = true;

    let missing = must_err!(
        validate_downstream_par_profile_policy(
            &profile,
            "code",
            Some("state"),
            None,
            "client_secret_basic",
            "https://issuer.example",
        ),
        "missing iss must fail closed",
    );
    assert_eq!(missing.reason, "iss_required");

    let mismatch = must_err!(
        validate_downstream_par_profile_policy(
            &profile,
            "code",
            Some("state"),
            Some("https://other.example"),
            "client_secret_basic",
            "https://issuer.example",
        ),
        "mismatched iss must fail closed",
    );
    assert_eq!(mismatch.reason, "iss_mismatch");

    assert!(validate_downstream_par_profile_policy(
        &profile,
        "code",
        Some("state"),
        Some("https://issuer.example"),
        "client_secret_basic",
        "https://issuer.example",
    )
    .is_ok());
    Ok(())
}

#[test]
fn device_profile_requires_device_code_grant() -> EndpointProfileTestResult {
    let profile = profile(&["authorization_code"], &["client_secret_post"]);

    let err = must_err!(
        validate_downstream_device_profile_policy(&profile, "client_secret_post"),
        "device endpoint must honor profile grant allowlist",
    );
    assert_eq!(err.reason, "grant_type_not_allowed");
    Ok(())
}

#[test]
fn endpoint_profile_enforces_auth_method_allowlist() -> EndpointProfileTestResult {
    let profile = profile(&["authorization_code"], &["private_key_jwt"]);

    let err = must_err!(
        validate_downstream_endpoint_auth_profile(&profile, "client_secret_basic"),
        "introspection/revocation must honor profile auth methods",
    );
    assert_eq!(err.reason, "token_auth_method_not_allowed");
    Ok(())
}

#[test]
fn upstream_refresh_profile_requires_refresh_grant_and_auth_method() -> EndpointProfileTestResult {
    let mut profile = profile(&["authorization_code"], &["client_secret_basic"]);

    assert_eq!(
        must_err!(
            validate_upstream_refresh_profile_policy(
                &profile,
                "https://issuer.example",
                "client_secret_basic",
            ),
            "refresh grant must be allowed by upstream profile",
        )
        .status(),
        StatusCode::BAD_REQUEST
    );

    profile
        .allowed_grant_types
        .push("refresh_token".to_string());
    assert_eq!(
        must_err!(
            validate_upstream_refresh_profile_policy(&profile, "https://issuer.example", "none"),
            "refresh auth method must be allowed by upstream profile",
        )
        .status(),
        StatusCode::BAD_REQUEST
    );

    assert!(validate_upstream_refresh_profile_policy(
        &profile,
        "https://issuer.example",
        "client_secret_basic",
    )
    .is_ok());
    Ok(())
}
