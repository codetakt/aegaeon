use super::super::{error_response, sha256_array};
use crate::management::types::ApiKeyCapability;
use crate::web::management::state::ControlPlanePolicy;
use axum::{http::StatusCode, response::Response};
use std::collections::BTreeSet;

pub(super) fn validate_api_key_name(name: &str, request_id: &str) -> Result<String, Response> {
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 128 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Name must be 1-128 characters",
            None,
            Some(request_id),
        ));
    }

    Ok(name)
}

pub(super) fn parse_api_key_expiration_days(
    value: Option<u32>,
    never_expires: bool,
    policy: &ControlPlanePolicy,
    request_id: &str,
) -> Result<Option<i32>, Response> {
    if never_expires {
        if value.is_some() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "expiresInDays and neverExpires cannot both be specified",
                None,
                Some(request_id),
            ));
        }
        if policy.api_key_allow_no_expiration {
            return Ok(None);
        }
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Non-expiring API keys are disabled by control-plane policy",
            None,
            Some(request_id),
        ));
    }

    let days = value.unwrap_or(policy.api_key_default_expiration_days);
    if days == 0 || days > policy.api_key_max_expiration_days {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expiresInDays is out of range",
            None,
            Some(request_id),
        ));
    }
    i32::try_from(days).map(Some).map_err(|_| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "expiresInDays is too large",
            None,
            Some(request_id),
        )
    })
}

pub(super) fn validate_api_key_capabilities(
    capabilities: &[ApiKeyCapability],
    request_id: &str,
) -> Result<Vec<ApiKeyCapability>, Response> {
    let deduped = capabilities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if deduped.is_empty() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "API key capabilities must be non-empty",
            None,
            Some(request_id),
        ));
    }

    Ok(deduped)
}

pub(super) fn generate_api_key_material() -> (String, [u8; 32], String) {
    let raw_key = format!("aeg_{}", aegaeon_crypto::rand::random_base64url(32));
    let key_hash = sha256_array(raw_key.as_bytes());
    let key_prefix = raw_key.chars().take(12).collect();
    (raw_key, key_hash, key_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_capabilities_are_required() {
        assert!(validate_api_key_capabilities(&[], "req-1").is_err());
    }

    #[test]
    fn api_key_capabilities_are_deduplicated_and_ordered() {
        let capabilities = validate_api_key_capabilities(
            &[
                ApiKeyCapability::AuditRead,
                ApiKeyCapability::Read,
                ApiKeyCapability::AuditRead,
            ],
            "req-1",
        )
        .expect("valid capabilities");

        assert_eq!(
            capabilities,
            vec![ApiKeyCapability::Read, ApiKeyCapability::AuditRead]
        );
    }

    #[test]
    fn api_key_expiration_uses_control_plane_default_and_maximum() {
        let policy = ControlPlanePolicy::default();

        assert!(matches!(
            parse_api_key_expiration_days(None, false, &policy, "req-1"),
            Ok(Some(90))
        ));
        assert!(parse_api_key_expiration_days(Some(0), false, &policy, "req-1").is_err());
        assert!(parse_api_key_expiration_days(Some(366), false, &policy, "req-1").is_err());
    }

    #[test]
    fn api_key_expiration_requires_policy_for_never_expires() {
        let policy = ControlPlanePolicy::default();
        assert!(parse_api_key_expiration_days(None, true, &policy, "req-1").is_err());

        let allow_no_expiration = ControlPlanePolicy {
            api_key_allow_no_expiration: true,
            ..ControlPlanePolicy::default()
        };
        assert!(matches!(
            parse_api_key_expiration_days(None, true, &allow_no_expiration, "req-1"),
            Ok(None)
        ));
        assert!(
            parse_api_key_expiration_days(Some(30), true, &allow_no_expiration, "req-1").is_err()
        );
    }
}
