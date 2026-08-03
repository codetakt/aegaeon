use super::FederationError;
use serde_json::Value;

// ─── Metadata Policy ─────────────────────────────────────────────────────

/// Canonicalize a JSON value for deterministic comparison.
///
/// Object keys are sorted lexicographically and nested structures are
/// recursed into.  Arrays are **not** reordered — they are compared
/// element-by-element in their original order.  This matches the F* spec's
/// structural equality (`anchor_sub_policy_consistent` uses `=` on
/// `metadata_policy_concrete`, which is order-sensitive).
///
/// Since both the anchor configuration and the subordinate statement
/// originate from the same trust anchor's published data, array element
/// order should be identical.  If order-independent comparison is needed
/// in the future, it should be opt-in per operator type.
fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: serde_json::Map<String, Value> = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), canonicalize_json(&map[k]));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => {
            // Preserve array order — policy arrays are order-sensitive
            // for the `value` operator and both sides should originate
            // from the same source.
            Value::Array(arr.iter().map(canonicalize_json).collect())
        }
        other => other.clone(),
    }
}

/// Compare two JSON values for semantic equivalence after canonicalization.
///
/// Two policies are equivalent if their canonicalized forms are identical,
/// meaning they have the same structure with object keys in a deterministic
/// order and array elements in their original order.
///
/// **F* alignment note:** The F* spec's `anchor_sub_policy_consistent` uses
/// structural equality (`=`) on `metadata_policy_concrete`, which is an
/// association list where key order matters.  The Rust code relaxes this by
/// sorting object keys (since `HashMap` iteration order is unspecified) but
/// preserves array element order, providing a strictly less permissive
/// comparison than full unordered-set equivalence.
///
/// **Optionality note:** In the F* model, `trust_anchor.ta_policy` is
/// non-optional — every anchor has a policy, and
/// `anchor_sub_policy_consistent` requires `anchor_sub.policy = Some
/// ta.ta_policy`.  The Rust validation keeps the storage type optional for
/// deserialization compatibility, but chain validation rejects `None` before
/// this comparison and therefore preserves the same proof shape.
pub(super) fn policy_equiv(a: &Value, b: &Value) -> bool {
    canonicalize_json(a) == canonicalize_json(b)
}

/// Apply a metadata policy to a metadata object.
///
/// The `policy` is a JSON object where each key is a metadata field name
/// and each value is an object of policy operators:
///
/// ```json
/// {
///   "grant_types": { "subset_of": ["authorization_code"], "default": ["authorization_code"] },
///   "id_token_signed_response_alg": { "one_of": ["ES256"], "essential": true }
/// }
/// ```
///
/// Supported operators (per `OpenID` Federation §5):
/// - `value`: Override the field unconditionally
/// - `default`: Set the field if not present
/// - `add`: Append values to an array field
/// - `intersect`: Keep only array values present in both (§5.1.2.4)
/// - `one_of`: Field must be one of the specified values
/// - `subset_of`: Field (array) must be a subset of the specified values
/// - `superset_of`: Field (array) must be a superset of the specified values
/// - `essential`: If `true`, the field must be present
///
/// # Errors
///
/// Returns [`FederationError`] when metadata or policy is not an object, policy operators are
/// malformed, or a constraint rejects the resulting metadata value.
pub fn apply_metadata_policy(metadata: &Value, policy: &Value) -> Result<Value, FederationError> {
    let metadata_obj = metadata
        .as_object()
        .ok_or_else(|| FederationError::MetadataPolicy("metadata must be an object".into()))?;
    let policy_obj = policy
        .as_object()
        .ok_or_else(|| FederationError::MetadataPolicy("policy must be an object".into()))?;

    let mut result = metadata_obj.clone();

    for (field, operators) in policy_obj {
        let ops = operators.as_object().ok_or_else(|| {
            FederationError::MetadataPolicy(format!("policy for '{field}' must be an object"))
        })?;

        let current_value = result.get(field).cloned();
        let new_value = apply_field_policy(field, current_value, ops)?;

        match new_value {
            Some(v) => {
                result.insert(field.clone(), v);
            }
            None => {
                result.remove(field);
            }
        }
    }

    Ok(Value::Object(result))
}

fn apply_field_policy(
    field_name: &str,
    current: Option<Value>,
    operators: &serde_json::Map<String, Value>,
) -> Result<Option<Value>, FederationError> {
    for operator in operators.keys() {
        validate_metadata_policy_operator_name(field_name, operator)?;
    }

    let intersect_operator = metadata_policy_array_operator(field_name, operators, "intersect")?;
    let one_of_operator = metadata_policy_array_operator(field_name, operators, "one_of")?;
    let subset_of_operator = metadata_policy_array_operator(field_name, operators, "subset_of")?;
    let superset_of_operator =
        metadata_policy_array_operator(field_name, operators, "superset_of")?;
    let essential_operator = metadata_policy_bool_operator(field_name, operators, "essential")?;

    let mut value = current;

    // `value` operator: unconditional override (highest precedence)
    if let Some(v) = operators.get("value") {
        value = Some(v.clone());
    }

    // `default` operator: set if absent or null
    if value.is_none() || value.as_ref().is_some_and(Value::is_null) {
        if let Some(default) = operators.get("default") {
            value = Some(default.clone());
        }
    }

    // `add` operator: append to array
    if let Some(add_value) = operators.get("add") {
        match &mut value {
            Some(Value::Array(arr)) => {
                if let Value::Array(add_values) = add_value {
                    for item in add_values {
                        if !arr.contains(item) {
                            arr.push(item.clone());
                        }
                    }
                } else if !arr.contains(add_value) {
                    arr.push(add_value.clone());
                }
            }
            None => {
                value = Some(match add_value {
                    Value::Array(add_values) => Value::Array(add_values.clone()),
                    other => Value::Array(vec![other.clone()]),
                });
            }
            Some(_) => {
                return Err(metadata_policy_value_type_error(field_name, "add", "array"));
            }
        }
    }

    // `intersect` operator (§5.1.2.4): keep only values present in both arrays
    if let Some(intersect_values) = intersect_operator {
        match &value {
            Some(Value::Array(current_arr)) => {
                let intersected: Vec<Value> = current_arr
                    .iter()
                    .filter(|item| intersect_values.contains(item))
                    .cloned()
                    .collect();
                value = Some(Value::Array(intersected));
            }
            None => {}
            Some(_) => {
                return Err(metadata_policy_value_type_error(
                    field_name,
                    "intersect",
                    "array",
                ));
            }
        }
    }

    // Constraint validation
    if let Some(ref v) = value {
        // `one_of`: value must be in the allowed set
        if let Some(allowed) = one_of_operator {
            if !allowed.contains(v) {
                return Err(FederationError::MetadataPolicy(format!(
                    "field '{field_name}': value not in one_of"
                )));
            }
        }

        // `subset_of`: array value must be a subset of allowed
        if let Some(allowed) = subset_of_operator {
            let values = metadata_policy_array_value(field_name, "subset_of", v)?;
            for item in values {
                if !allowed.contains(item) {
                    return Err(FederationError::MetadataPolicy(format!(
                        "field '{field_name}': value not in subset_of"
                    )));
                }
            }
        }

        // `superset_of`: array value must contain all required items
        if let Some(required) = superset_of_operator {
            let values = metadata_policy_array_value(field_name, "superset_of", v)?;
            for item in required {
                if !values.contains(item) {
                    return Err(FederationError::MetadataPolicy(format!(
                        "field '{field_name}': missing required value from superset_of"
                    )));
                }
            }
        }
    }

    // `essential`: field must be present
    if matches!(essential_operator, Some(true)) && value.is_none() {
        return Err(FederationError::MetadataPolicy(format!(
            "essential field '{field_name}' is missing"
        )));
    }

    Ok(value)
}

fn validate_metadata_policy_operator_name(
    field_name: &str,
    operator: &str,
) -> Result<(), FederationError> {
    match operator {
        "value" | "default" | "add" | "intersect" | "one_of" | "subset_of" | "superset_of"
        | "essential" => Ok(()),
        other => Err(FederationError::MetadataPolicy(format!(
            "field '{field_name}': unsupported policy operator '{other}'"
        ))),
    }
}

fn metadata_policy_array_operator<'a>(
    field_name: &str,
    operators: &'a serde_json::Map<String, Value>,
    operator: &str,
) -> Result<Option<&'a Vec<Value>>, FederationError> {
    match operators.get(operator) {
        Some(Value::Array(values)) => Ok(Some(values)),
        Some(_) => Err(FederationError::MetadataPolicy(format!(
            "field '{field_name}': operator '{operator}' must be an array"
        ))),
        None => Ok(None),
    }
}

fn metadata_policy_bool_operator(
    field_name: &str,
    operators: &serde_json::Map<String, Value>,
    operator: &str,
) -> Result<Option<bool>, FederationError> {
    match operators.get(operator) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(FederationError::MetadataPolicy(format!(
            "field '{field_name}': operator '{operator}' must be a boolean"
        ))),
        None => Ok(None),
    }
}

fn metadata_policy_array_value<'a>(
    field_name: &str,
    operator: &str,
    value: &'a Value,
) -> Result<&'a Vec<Value>, FederationError> {
    match value {
        Value::Array(values) => Ok(values),
        _ => Err(metadata_policy_value_type_error(
            field_name, operator, "array",
        )),
    }
}

fn metadata_policy_value_type_error(
    field_name: &str,
    operator: &str,
    expected: &str,
) -> FederationError {
    FederationError::MetadataPolicy(format!(
        "field '{field_name}': operator '{operator}' requires {expected} value"
    ))
}
