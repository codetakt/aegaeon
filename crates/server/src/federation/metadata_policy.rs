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
/// A local anchor pin is optional. When supplied, this comparison preserves
/// its original JSON structure; the signed policy is resolved independently.
/// This local restriction is not a Federation requirement or a statement that
/// the historical non-optional formal model covers the current optional API.
pub(super) fn policy_equiv(a: &Value, b: &Value) -> bool {
    canonicalize_json(a) == canonicalize_json(b)
}

mod equality;
mod operators;
mod scope;

use operators::FieldPolicy;
use std::collections::{BTreeMap, HashMap};

type TypePolicy = BTreeMap<String, FieldPolicy>;
pub(super) type ResolvedPolicy = BTreeMap<String, TypePolicy>;

fn error(message: &str) -> FederationError {
    FederationError::MetadataPolicy(message.into())
}

fn parse_type(policy: &Value, entity_type: Option<&str>) -> Result<TypePolicy, FederationError> {
    let fields = policy
        .as_object()
        .filter(|fields| !fields.is_empty())
        .ok_or_else(|| error("parameter policy must be a nonempty object"))?;
    fields
        .iter()
        .map(|(field, value)| {
            let parsed = FieldPolicy::parse(value)?;
            if scope::is_client_scope(entity_type, field) {
                scope::validate_policy(&parsed)?;
            }
            Ok((field.clone(), parsed))
        })
        .collect()
}

pub(super) fn resolve_policies<'a>(
    policies: impl IntoIterator<Item = &'a HashMap<String, Value>>,
) -> Result<ResolvedPolicy, FederationError> {
    let mut resolved = ResolvedPolicy::new();
    for policy in policies {
        if policy.is_empty() {
            return Err(error("entity policy must be a nonempty object"));
        }
        for (entity_type, value) in policy {
            let parsed = parse_type(value, Some(entity_type))?;
            let target = resolved.entry(entity_type.clone()).or_default();
            for (field, operators) in parsed {
                if let Some(previous) = target.get_mut(&field) {
                    previous.merge(&operators)?;
                } else {
                    target.insert(field, operators);
                }
            }
        }
    }
    Ok(resolved)
}

/// Apply a flat parameter policy using generic JSON representations.
///
/// Implements OpenID Federation 1.0/1.1 section 6.1 standard operators.
/// `intersect` is a local compatibility alias for `subset_of`. Unknown
/// noncritical operators are ignored. This helper cannot process critical
/// declarations or recover duplicate members lost during JSON deserialization;
/// callers must validate those on the original signed input. Client `scope`
/// strings require [`apply_metadata_policy_for_entity_type`].
///
/// # Errors
/// Returns an error for malformed policy, unsupported types, contradictory
/// operator combinations or metadata that fails the resolved constraints.
pub fn apply_metadata_policy(metadata: &Value, policy: &Value) -> Result<Value, FederationError> {
    apply_resolved(metadata, &parse_type(policy, None)?, None)
}

/// Apply a flat policy with entity-type-specific client scope representation.
///
/// `openid_relying_party` and `oauth_client` scope strings are processed as
/// arrays of scope tokens and serialized back to strings. Other metadata is
/// unchanged by this representation step. Admission limitations are the same
/// as [`apply_metadata_policy`].
///
/// # Errors
/// Also rejects invalid scope strings and policy operands.
pub fn apply_metadata_policy_for_entity_type(
    entity_type: &str,
    metadata: &Value,
    policy: &Value,
) -> Result<Value, FederationError> {
    apply_resolved(
        metadata,
        &parse_type(policy, Some(entity_type))?,
        Some(entity_type),
    )
}

pub(super) fn apply_resolved(
    metadata: &Value,
    policy: &TypePolicy,
    entity_type: Option<&str>,
) -> Result<Value, FederationError> {
    let mut result = metadata
        .as_object()
        .ok_or_else(|| error("metadata must be an object"))?
        .clone();
    if result.values().any(Value::is_null) {
        return Err(error("null metadata parameter"));
    }
    let client_scope = scope::is_client_scope(entity_type, "scope");
    if client_scope {
        if let Some(value) = result.get_mut("scope") {
            *value = scope::decode(value)?;
        }
    }
    for (field, operators) in policy {
        if let Some(value) = operators.apply(result.remove(field))? {
            result.insert(field.clone(), value);
        }
    }
    if client_scope {
        if let Some(value) = result.get_mut("scope") {
            *value = scope::encode(value)?;
        }
    }
    Ok(Value::Object(result))
}

/// Validate an optional local anchor equality pin without applying it.
/// Original values remain authoritative for the separate pin comparison.
pub(crate) fn validate_metadata_policy_pin(policy: Option<&Value>) -> Result<(), FederationError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    let types = policy
        .as_object()
        .filter(|types| !types.is_empty())
        .ok_or_else(|| error("anchor metadata policy must be a nonempty object"))?;
    for (entity_type, policy) in types {
        parse_type(policy, Some(entity_type))?;
    }
    Ok(())
}
