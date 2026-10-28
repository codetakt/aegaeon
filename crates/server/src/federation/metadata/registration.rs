use super::{invalid, validate_url, FederationError};
use serde_json::{Map, Value};

const OP: &str = "openid_provider";
const OP_MODES: &str = "client_registration_types_supported";
const ENDPOINT: &str = "federation_registration_endpoint";

fn advertises_explicit(parameters: &Map<String, Value>) -> bool {
    parameters
        .get(OP_MODES)
        .and_then(Value::as_array)
        .is_some_and(|modes| modes.iter().any(|mode| mode.as_str() == Some("explicit")))
}

pub(super) fn validate_supplied(
    entity_type: &str,
    parameters: &Map<String, Value>,
) -> Result<(), FederationError> {
    let field = match entity_type {
        OP => OP_MODES,
        "openid_relying_party" => "client_registration_types",
        _ => return Ok(()),
    };
    if let Some(value) = parameters.get(field) {
        let modes = value
            .as_array()
            .ok_or_else(|| invalid(entity_type, field))?;
        if modes.iter().any(|mode| !mode.is_string()) {
            return Err(invalid(entity_type, field));
        }
    }
    if entity_type == OP {
        if let Some(value) = parameters.get(ENDPOINT) {
            let endpoint = validate_url(OP, ENDPOINT, value)?;
            if advertises_explicit(parameters) {
                crate::federation::profile::validate_endpoint(endpoint)
                    .map_err(|_| invalid(OP, ENDPOINT))?;
            }
        }
    }
    Ok(())
}

/// Check the selected signed OP's registration declarations after completion.
/// This is not full OP schema validation or inference of a Dynamic OP class.
pub(crate) fn validate_complete_op_registration(metadata: &Value) -> Result<(), FederationError> {
    super::validate(OP, metadata)?;
    let parameters = metadata.as_object().ok_or_else(|| invalid(OP, "object"))?;
    if advertises_explicit(parameters) && !parameters.contains_key(ENDPOINT) {
        return Err(invalid(OP, ENDPOINT));
    }
    Ok(())
}
