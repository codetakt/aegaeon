use serde_json::Value;

use super::REG_BCP_NONCOMPLIANT;

pub(super) fn validate_inline_jwks(jwks_value: Value, require_kid: bool) -> Result<(), String> {
    let jwks = aegaeon_jose::jwk::JwkSet::from_value(jwks_value).map_err(|err| {
        REG_BCP_NONCOMPLIANT
            .with_label_values(&["jwks_invalid"])
            .inc();
        format!("invalid jwks: {err}")
    })?;
    jwks.ensure_unique_kid().map_err(|err| {
        REG_BCP_NONCOMPLIANT.with_label_values(&["dup_kid"]).inc();
        format!("duplicate kid: {err}")
    })?;
    if require_kid {
        jwks.ensure_all_have_kid().map_err(|_| {
            REG_BCP_NONCOMPLIANT
                .with_label_values(&["kid_missing"])
                .inc();
            "private_key_jwt requires jwks with kid".to_string()
        })?;
    }
    if jwks.signature_keys().next().is_none() {
        REG_BCP_NONCOMPLIANT
            .with_label_values(&["jwks_not_signature"])
            .inc();
        return Err("jwks must include signature-capable keys".into());
    }
    Ok(())
}

pub(super) fn runtime_supported_client_jwt_alg(input: &str) -> Option<&'static str> {
    match input.trim().to_ascii_uppercase().as_str() {
        "RS256" => Some("RS256"),
        "PS256" => Some("PS256"),
        _ => None,
    }
}
