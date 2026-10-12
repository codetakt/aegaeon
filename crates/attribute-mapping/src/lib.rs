//! Deterministic attribute transformation after identity and recipient resolution.
//!
//! The caller authenticates sources, resolves the local owner, and authorizes
//! configuration before constructing a snapshot. Deserializing input does not
//! authenticate it. This crate never links accounts, signs tokens, or performs IO.
//! Source restrictions apply to derived values and control dependencies as well
//! as direct copies. Each evaluation uses one immutable policy revision.
#![forbid(unsafe_code)]

mod engine;
mod model;
mod validation;

pub use engine::{evaluate, MappedClaim, MappingOutput, SourceEvidence};
pub use model::*;

/// Validate the depth, collection sizes and encoded size of an attribute value.
///
/// # Errors
/// Returns [`MappingError::ResourceLimit`] when the value exceeds input limits.
pub fn validate_attribute_value(value: &serde_json::Value) -> Result<(), MappingError> {
    validation::json(value, 0)?;
    validation::encoded_size(value, MAX_INPUT_BYTES)?;
    Ok(())
}

#[cfg(test)]
mod tests;

/// Bound an adapter's serialized configuration without allocating its JSON text.
///
/// # Errors
/// Returns a resource error if encoding fails or exceeds the supplied byte limit.
pub fn validate_encoded_size(
    value: &impl serde::Serialize,
    limit: usize,
) -> Result<(), MappingError> {
    validation::encoded_size(value, limit).map(|_| ())
}

/// Whether a root claim is owned by a protocol or by its adapter.
#[must_use]
pub fn is_protocol_owned_claim(
    name: &str,
    additional: &std::collections::BTreeSet<String>,
) -> bool {
    validation::reserved(name, additional)
}
