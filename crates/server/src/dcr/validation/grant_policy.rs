use super::super::registration::ClientRegistration;
use super::config::DcrValidationConfig;
use super::reject_bcp;
use crate::policy::{DEVICE_CODE_GRANT_TYPE, JWT_BEARER_GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE};

fn effective_grant_types(meta: &ClientRegistration) -> Vec<String> {
    meta.grant_types.clone().unwrap_or_else(|| {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    })
}

fn effective_response_types(meta: &ClientRegistration) -> Vec<String> {
    meta.response_types
        .clone()
        .unwrap_or_else(|| vec!["code".to_string()])
}

pub(super) fn validate_grant_response_policy(
    meta: &ClientRegistration,
    config: &DcrValidationConfig,
) -> Result<(), String> {
    let grants = effective_grant_types(meta);
    let responses = effective_response_types(meta);
    validate_bcp_grant_response_policy(&grants, &responses, config)
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
    if !(responses.len() == 1 && responses[0] == "code") {
        return reject_bcp(
            "response_types_not_allowed",
            "response_types must be [\"code\"] under BCP",
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
