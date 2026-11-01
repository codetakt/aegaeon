//! Shared registration defaults and cross-field relationships.
use super::ClientRegistration;
use crate::policy::TOKEN_EXCHANGE_GRANT_TYPE;

pub(crate) fn default_registration_grants() -> Vec<String> {
    vec!["authorization_code".into()]
}

pub(crate) fn effective_grant_types(meta: &ClientRegistration) -> Vec<String> {
    meta.grant_types
        .clone()
        .unwrap_or_else(default_registration_grants)
}

pub(crate) fn response_types_for_grants(grants: &[String]) -> Vec<String> {
    if grants.iter().any(|grant| grant == "authorization_code") {
        vec!["code".into()]
    } else {
        Vec::new()
    }
}

pub(crate) fn effective_response_types(meta: &ClientRegistration) -> Vec<String> {
    meta.response_types
        .clone()
        .unwrap_or_else(|| response_types_for_grants(&effective_grant_types(meta)))
}

pub(crate) fn resolve_registration_defaults(mut meta: ClientRegistration) -> ClientRegistration {
    meta.grant_types = Some(effective_grant_types(&meta));
    meta.response_types = Some(effective_response_types(&meta));
    meta.token_endpoint_auth_method = Some(
        meta.token_endpoint_auth_method
            .as_deref()
            .unwrap_or("client_secret_basic")
            .trim()
            .to_ascii_lowercase(),
    );
    meta
}

pub(crate) fn validate_grant_response_relation(
    grants: &[String],
    responses: &[String],
) -> Result<(), String> {
    if responses != response_types_for_grants(grants) {
        return Err(
            "response_types must be [\"code\"] with authorization_code and empty otherwise".into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_grant_authentication(grants: &[String], method: &str) -> Result<(), String> {
    if method.trim().eq_ignore_ascii_case("none")
        && grants
            .iter()
            .any(|grant| grant == "client_credentials" || grant == TOKEN_EXCHANGE_GRANT_TYPE)
    {
        return Err("client_credentials and token exchange require client authentication".into());
    }
    Ok(())
}
