//! Public-client profile ownership; generic JOSE and other issuers are separate.
use serde_json::Value;

const PRIVATE_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Reject standard secret members before any value-reflecting structural error.
/// Envelope and public-material validity remain the caller's existing checks.
pub(crate) fn validate_public_client_jwks(value: &Value) -> Result<(), String> {
    if let Some(keys) = value.get("keys").and_then(Value::as_array) {
        for (index, key) in keys.iter().enumerate() {
            if let Some(object) = key.as_object() {
                for field in PRIVATE_MEMBERS {
                    if object.contains_key(*field) {
                        return Err(format!(
                            "public jwks key index {index} contains forbidden member {field}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Project only legacy stored members; never use this to admit new input.
pub(super) fn remove_private_members(value: &mut Value) {
    if let Some(keys) = value.get_mut("keys").and_then(Value::as_array_mut) {
        for key in keys {
            if let Some(object) = key.as_object_mut() {
                for field in PRIVATE_MEMBERS {
                    object.remove(*field);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
