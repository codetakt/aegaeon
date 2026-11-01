use super::super::registration::ClientRegistration;
use super::config::DcrValidationConfig;
use super::reject_bcp;
use crate::policy::{DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};

use super::super::metadata_contract::{
    effective_grant_types, effective_response_types, validate_grant_authentication,
    validate_grant_response_relation,
};

pub(super) fn validate_grant_response_policy(
    meta: &ClientRegistration,
    config: &DcrValidationConfig,
) -> Result<(), String> {
    let grants = effective_grant_types(meta);
    let responses = effective_response_types(meta);
    validate_bcp_grant_response_policy(&grants, &responses, config)?;
    validate_grant_authentication(
        &grants,
        meta.token_endpoint_auth_method
            .as_deref()
            .unwrap_or("client_secret_basic"),
    )
}

fn validate_bcp_grant_response_policy(
    grants: &[String],
    responses: &[String],
    config: &DcrValidationConfig,
) -> Result<(), String> {
    if grants.iter().any(|g| g == "password") {
        return reject_bcp(
            "ropc_disallowed",
            "grant_type password (ROPC) is forbidden by BCP",
        );
    }
    if grants.iter().any(|g| g == "implicit") {
        return reject_bcp(
            "implicit_disallowed",
            "grant_type implicit is forbidden by BCP",
        );
    }
    if grants.is_empty() {
        return reject_bcp("grant_types_empty", "grant_types must not be empty");
    }
    let mut distinct = std::collections::HashSet::new();
    if grants.iter().any(|grant| !distinct.insert(grant)) {
        return reject_bcp(
            "grant_types_duplicate",
            "grant_types must not contain duplicates",
        );
    }
    if grants.iter().any(|g| g == "refresh_token")
        && !grants.iter().any(|g| g == "authorization_code")
    {
        return reject_bcp(
            "refresh_requires_code",
            "refresh_token requires authorization_code grant",
        );
    }
    validate_grant_response_relation(grants, responses)?;
    validate_supported_grants(grants, config)
}

fn validate_supported_grants(
    grants: &[String],
    config: &DcrValidationConfig,
) -> Result<(), String> {
    for grant in grants {
        match grant.as_str() {
            "authorization_code" | "refresh_token" | "client_credentials" => {}
            JWT_BEARER_GRANT_TYPE if config.jwt_bearer_enabled => {}
            JWT_BEARER_GRANT_TYPE => {
                return reject_bcp(
                    "jwt_bearer_grant_disabled",
                    "jwt-bearer grant is disabled by policy",
                );
            }
            TOKEN_EXCHANGE_GRANT_TYPE if config.token_exchange_enabled => {}
            TOKEN_EXCHANGE_GRANT_TYPE => {
                return reject_bcp(
                    "token_exchange_grant_disabled",
                    "token-exchange grant is disabled by policy",
                );
            }
            DEVICE_CODE_GRANT_TYPE if config.device_code_enabled => {}
            DEVICE_CODE_GRANT_TYPE => {
                return reject_bcp(
                    "device_code_grant_disabled",
                    "device_code grant is disabled by policy",
                );
            }
            _ => {
                return reject_bcp(
                    "unsupported_grant",
                    format!("unsupported grant_type {grant}"),
                );
            }
        }
    }
    Ok(())
}
