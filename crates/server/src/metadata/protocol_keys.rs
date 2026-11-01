//! Public protocol-key profiles; generic JOSE and private key storage are separate.
use aegaeon_jose::jwk::JwkSet;
use serde_json::{Map, Value};

const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Check originals before projecting usable verification keys. Presence rejection,
/// including null and unusable siblings, is the server's public profile policy.
/// Unknown nested extensions are opaque. Mixed-purpose and any supported
/// certificate semantics have separate actor-specific applicability; this gate
/// does not add certificate interpretation, retrieval or trust.
pub(crate) fn validate_public_jwks(value: &Value) -> Result<(), &'static str> {
    let keys = value
        .as_object()
        .and_then(|object| object.get("keys"))
        .and_then(Value::as_array)
        .ok_or("invalid public JWKS envelope")?;
    for key in keys {
        if key.as_object().is_some_and(|object| {
            PRIVATE_MEMBERS
                .iter()
                .any(|field| object.contains_key(*field))
        }) {
            return Err("public JWKS contains a forbidden private member");
        }
    }
    Ok(())
}

/// Typed views can check only visible fields, never reconstruct erased raw data.
pub(crate) fn validate_visible_public_jwks(jwks: &JwkSet) -> Result<(), &'static str> {
    if jwks.keys().iter().any(|key| {
        PRIVATE_MEMBERS
            .iter()
            .any(|field| key.extra.contains_key(*field))
    }) {
        return Err("public JWKS contains a forbidden private member");
    }
    Ok(())
}

pub(crate) fn validate_supplied(
    role: &str,
    parameters: &Map<String, Value>,
) -> Result<(), &'static str> {
    if !matches!(
        role,
        "openid_provider"
            | "openid_relying_party"
            | "oauth_authorization_server"
            | "oauth_client"
            | "oauth_resource"
    ) {
        return Ok(());
    }
    if let Some(jwks) = parameters.get("jwks") {
        validate_public_jwks(jwks).map_err(|_| "jwks")?;
    }
    for field in ["jwks_uri", "signed_jwks_uri"] {
        if parameters.get(field).is_some_and(|value| {
            !value
                .as_str()
                .is_some_and(crate::oidc::provider_urls::valid_https_endpoint)
        }) {
            return Err(field);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
