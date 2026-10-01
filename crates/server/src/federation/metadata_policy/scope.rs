use super::{error, operators::FieldPolicy, FederationError};
use serde_json::Value;

pub(super) fn is_client_scope(entity_type: Option<&str>, field: &str) -> bool {
    matches!(entity_type, Some("openid_relying_party" | "oauth_client")) && field == "scope"
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|b| matches!(b, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}

fn tokens(value: &Value) -> Result<Vec<&str>, FederationError> {
    let values = value
        .as_array()
        .ok_or_else(|| error("scope policy/result must be an array"))?;
    values
        .iter()
        .map(|v| {
            v.as_str()
                .filter(|s| valid_token(s))
                .ok_or_else(|| error("invalid scope token"))
        })
        .collect()
}

pub(super) fn validate_policy(policy: &FieldPolicy) -> Result<(), FederationError> {
    for (name, value) in &policy.0 {
        if name != "essential" && !(name == "value" && value.is_null()) {
            tokens(value)?;
        }
    }
    Ok(())
}

pub(super) fn decode(value: &Value) -> Result<Value, FederationError> {
    let text = value
        .as_str()
        .ok_or_else(|| error("client scope must be a string"))?;
    let mut result = Vec::new();
    if !text.is_empty() {
        for token in text.split(' ') {
            if !valid_token(token) {
                return Err(error("invalid client scope string"));
            }
            let token = Value::String(token.into());
            if !result.contains(&token) {
                result.push(token);
            }
        }
    }
    Ok(Value::Array(result))
}

pub(super) fn encode(value: &Value) -> Result<Value, FederationError> {
    let tokens = tokens(value)?;
    let mut unique = Vec::new();
    for token in tokens {
        if !unique.contains(&token) {
            unique.push(token);
        }
    }
    Ok(Value::String(unique.join(" ")))
}
