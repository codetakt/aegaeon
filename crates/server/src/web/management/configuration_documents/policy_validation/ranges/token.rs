use axum::response::Response;

use crate::config::{
    valid_access_token_ttl_secs, valid_authorization_code_ttl_secs, valid_refresh_token_ttl_secs,
};
use crate::management::types::PolicyDocument;
use crate::oidc::config::valid_backchannel_logout_timeout_secs;
use crate::oidc::session::valid_logout_session_ttl_secs;
use crate::policy::validate_supported_grant_types;
use crate::runtime_keys::canonical_runtime_signing_algorithm_name;

use super::invalid_request;

pub(in crate::web::management::configuration_documents::policy_validation) fn validate_allowlists_and_token_ttls(
    policy: &PolicyDocument,
    request_id: &str,
) -> Result<(), Response> {
    if policy.allowed_signing_algorithms.is_empty() || policy.allowed_grant_types.is_empty() {
        return Err(invalid_request(
            "Algorithm and grant allowlists must not be empty",
            request_id,
        ));
    }
    validate_supported_grant_types(&policy.allowed_grant_types)
        .map_err(|error| invalid_request(&error.to_string(), request_id))?;
    if policy.crypto_profile.as_str() != "verified" {
        return Err(invalid_request(
            "Crypto profile must be verified",
            request_id,
        ));
    }
    reject_invalid_or_duplicate_signing_algorithms(&policy.allowed_signing_algorithms, request_id)?;
    reject_invalid_or_duplicate_client_jwt_algorithms(&policy.client_jwt_allowed_algs, request_id)?;
    if policy.access_token_time_to_live_seconds == 0
        || policy.id_token_time_to_live_seconds == 0
        || policy.refresh_token_time_to_live_seconds == 0
        || policy.authorization_code_time_to_live_seconds == 0
    {
        return Err(invalid_request("Token TTLs must be positive", request_id));
    }
    if !valid_access_token_ttl_secs(u64::from(policy.access_token_time_to_live_seconds))
        || !valid_access_token_ttl_secs(u64::from(policy.id_token_time_to_live_seconds))
        || !valid_refresh_token_ttl_secs(u64::from(policy.refresh_token_time_to_live_seconds))
        || !valid_authorization_code_ttl_secs(u64::from(
            policy.authorization_code_time_to_live_seconds,
        ))
    {
        return Err(invalid_request(
            "Token TTLs exceed the supported policy range",
            request_id,
        ));
    }
    if !valid_logout_session_ttl_secs(u64::from(policy.oidc_logout_session_ttl_seconds))
        || !valid_backchannel_logout_timeout_secs(u64::from(
            policy.oidc_backchannel_logout_timeout_seconds,
        ))
    {
        return Err(invalid_request(
            "OIDC runtime lifetimes exceed the supported policy range",
            request_id,
        ));
    }

    Ok(())
}

fn reject_invalid_or_duplicate_signing_algorithms(
    algorithms: &[String],
    request_id: &str,
) -> Result<(), Response> {
    let mut seen = std::collections::BTreeSet::new();
    for algorithm in algorithms {
        let Some(canonical) = canonical_runtime_signing_algorithm_name(algorithm) else {
            return Err(invalid_request(
                "Runtime signing algorithm allowlist contains an unsupported algorithm",
                request_id,
            ));
        };
        if !matches!(canonical, "RS256" | "EdDSA") {
            return Err(invalid_request(
                "Runtime signing algorithm allowlist exceeds the verified server boundary",
                request_id,
            ));
        }
        if !seen.insert(canonical) {
            return Err(invalid_request(
                "Runtime signing algorithm allowlist entries must be unique",
                request_id,
            ));
        }
    }
    Ok(())
}

fn reject_invalid_or_duplicate_client_jwt_algorithms(
    algorithms: &[String],
    request_id: &str,
) -> Result<(), Response> {
    let mut seen = std::collections::BTreeSet::new();
    for algorithm in algorithms {
        let normalized = algorithm.trim().to_ascii_uppercase();
        if !matches!(normalized.as_str(), "RS256" | "PS256") {
            return Err(invalid_request(
                "Client JWT algorithm allowlist exceeds the promoted RSA verification boundary",
                request_id,
            ));
        }
        if !seen.insert(normalized) {
            return Err(invalid_request(
                "Client JWT algorithm allowlist entries must be unique",
                request_id,
            ));
        }
    }
    Ok(())
}
