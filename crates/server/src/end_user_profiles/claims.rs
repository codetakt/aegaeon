use super::model::{EndUserProfileRecord, OidcProfileClaims};
use serde_json::{Map, Value};
use std::collections::HashMap;

const RESERVED_CUSTOM_CLAIMS: &[&str] = &[
    "sub",
    "iss",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "nonce",
    "auth_time",
    "acr",
    "amr",
    "azp",
    "sid",
    "at_hash",
    "c_hash",
    "name",
    "given_name",
    "family_name",
    "middle_name",
    "nickname",
    "preferred_username",
    "profile",
    "picture",
    "website",
    "email",
    "email_verified",
    "gender",
    "birthdate",
    "zoneinfo",
    "locale",
    "phone_number",
    "phone_number_verified",
    "address",
    "updated_at",
];

#[must_use]
pub fn normalize_display_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn custom_claims_to_map(value: &Value) -> HashMap<String, Value> {
    match value {
        Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        _ => HashMap::new(),
    }
}

#[must_use]
pub fn empty_custom_claims() -> Value {
    Value::Object(Map::new())
}

#[must_use]
pub fn oidc_profile_claims_from_record(record: &EndUserProfileRecord) -> OidcProfileClaims {
    OidcProfileClaims {
        email: record.email.clone(),
        email_verified: record.email.as_ref().map(|_| record.email_verified),
        display_name: record.display_name.clone(),
        custom_claims: custom_claims_to_map(&record.custom_claims),
        updated_at_epoch_seconds: Some(record.updated_at_epoch_seconds),
    }
}

/// Validate custom OIDC profile claims before they are stored.
///
/// # Errors
///
/// Returns an error when `customClaims` is not a JSON object, contains blank keys, or attempts to
/// override reserved OIDC/user-profile claim names.
pub fn validate_custom_claims(value: &Value) -> Result<(), &'static str> {
    let Value::Object(map) = value else {
        return Err("customClaims must be a JSON object");
    };

    for key in map.keys() {
        let trimmed = key.trim();
        if trimmed.is_empty() {
            return Err("customClaims keys must not be blank");
        }
        let normalized = trimmed.to_ascii_lowercase();
        if RESERVED_CUSTOM_CLAIMS.contains(&normalized.as_str()) {
            return Err("customClaims contains reserved claim names");
        }
    }

    Ok(())
}
