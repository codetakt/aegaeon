//! Supplied provider capabilities, without completeness or local support claims.
use super::OidcDiscovery;
use crate::metadata::language_tags;
use serde_json::{Map, Value};

const COMMON_ARRAYS: &[&str] = &[
    "scopes_supported",
    "response_types_supported",
    "response_modes_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "token_endpoint_auth_signing_alg_values_supported",
    "ui_locales_supported",
    "revocation_endpoint_auth_methods_supported",
    "revocation_endpoint_auth_signing_alg_values_supported",
    "introspection_endpoint_auth_methods_supported",
    "introspection_endpoint_auth_signing_alg_values_supported",
    "code_challenge_methods_supported",
    "dpop_signing_alg_values_supported",
];
const OP_ARRAYS: &[&str] = &[
    "acr_values_supported",
    "subject_types_supported",
    "id_token_signing_alg_values_supported",
    "id_token_encryption_alg_values_supported",
    "id_token_encryption_enc_values_supported",
    "userinfo_signing_alg_values_supported",
    "userinfo_encryption_alg_values_supported",
    "userinfo_encryption_enc_values_supported",
    "request_object_signing_alg_values_supported",
    "request_object_encryption_alg_values_supported",
    "request_object_encryption_enc_values_supported",
    "display_values_supported",
    "claim_types_supported",
    "claims_supported",
    "claims_locales_supported",
    // Existing Aegaeon DTO extension, not an imported standard parameter.
    "aegaeon_access_token_formats_supported",
];
const COMMON_BOOLEANS: &[&str] = &[
    "require_pushed_authorization_requests",
    "require_signed_request_object",
    "authorization_response_iss_parameter_supported",
    "tls_client_certificate_bound_access_tokens",
];
const OP_BOOLEANS: &[&str] = &[
    "claims_parameter_supported",
    "request_parameter_supported",
    "request_uri_parameter_supported",
    "require_request_uri_registration",
];
const AUTH_ALGORITHMS: [&str; 3] = [
    "token_endpoint_auth_signing_alg_values_supported",
    "revocation_endpoint_auth_signing_alg_values_supported",
    "introspection_endpoint_auth_signing_alg_values_supported",
];

fn permits_auth_algorithms<'a>(mut values: impl Iterator<Item = &'a str>) -> bool {
    !values.any(|value| value == "none")
}

/// Exact known role maps only. Omission, empty arrays, duplicates and unknown
/// string identifiers remain representable except language tags, which use the
/// pinned IANA admission profile. Errors reveal only a known field.
pub(crate) fn validate_supplied(
    role: &str,
    parameters: &Map<String, Value>,
) -> Result<(), &'static str> {
    let (extra_arrays, extra_booleans) = match role {
        "openid_provider" => (OP_ARRAYS, OP_BOOLEANS),
        "oauth_authorization_server" => (&[][..], &[][..]),
        _ => return Ok(()),
    };
    for &field in COMMON_ARRAYS.iter().chain(extra_arrays) {
        if let Some(value) = parameters.get(field) {
            let values = value.as_array().ok_or(field)?;
            if values.iter().any(|value| !value.is_string()) {
                return Err(field);
            }
            if matches!(field, "ui_locales_supported" | "claims_locales_supported")
                && values
                    .iter()
                    .any(|value| !value.as_str().is_some_and(language_tags::is_valid))
            {
                return Err(field);
            }
            if AUTH_ALGORITHMS.contains(&field)
                && !permits_auth_algorithms(values.iter().filter_map(Value::as_str))
            {
                return Err(field);
            }
        }
    }
    for &field in COMMON_BOOLEANS.iter().chain(extra_booleans) {
        if parameters
            .get(field)
            .is_some_and(|value| !value.is_boolean())
        {
            return Err(field);
        }
    }
    Ok(())
}

/// Recheck semantics when a typed ordinary/cache value reaches a live operation.
/// Its Rust types already enforce list element kinds and optional booleans.
pub(crate) fn validate_typed(discovery: &OidcDiscovery) -> Result<(), &'static str> {
    for (field, values) in [
        ("ui_locales_supported", &discovery.ui_locales_supported),
        (
            "claims_locales_supported",
            &discovery.claims_locales_supported,
        ),
    ] {
        if values
            .as_ref()
            .is_some_and(|values| values.iter().any(|tag| !language_tags::is_valid(tag)))
        {
            return Err(field);
        }
    }
    for (field, values) in AUTH_ALGORITHMS.into_iter().zip([
        &discovery.token_endpoint_auth_signing_alg_values_supported,
        &discovery.revocation_endpoint_auth_signing_alg_values_supported,
        &discovery.introspection_endpoint_auth_signing_alg_values_supported,
    ]) {
        if values
            .as_ref()
            .is_some_and(|values| !permits_auth_algorithms(values.iter().map(String::as_str)))
        {
            return Err(field);
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_contract;
