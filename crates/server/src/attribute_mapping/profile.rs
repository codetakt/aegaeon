//! Generic configuration for a recipient-specific protocol adapter.
//! The caller supplies authenticated inputs, revision and output semantics.
use aegaeon_attribute_mapping::{
    AttributeKey, Expression, FieldSchema, MappingError, MappingPolicy, OutputContract, Recipient,
    ValueSchema,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileRule {
    pub expression: Expression,
    pub schema: ValueSchema,
    #[serde(default)]
    pub required: bool,
}

/// Source grants, transformation admission and output release are independent.
/// This value carries no authentication merely because it can be deserialized.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileMapping {
    #[serde(default)]
    pub inputs: BTreeSet<AttributeKey>,
    #[serde(default)]
    pub source_grants: BTreeSet<AttributeKey>,
    #[serde(default)]
    pub outputs: BTreeMap<String, ProfileRule>,
    #[serde(default)]
    pub released_outputs: BTreeSet<String>,
}

impl ProfileMapping {
    /// Add admitted custom rules to an adapter-owned preset and contract.
    ///
    /// # Errors
    /// Rejects preset replacement, reserved claims and invalid mapping structure.
    pub fn extend(
        &self,
        policy: &mut MappingPolicy,
        contract: &mut OutputContract,
    ) -> Result<(), MappingError> {
        aegaeon_attribute_mapping::validate_encoded_size(
            self,
            aegaeon_attribute_mapping::MAX_INPUT_BYTES,
        )?;
        for (name, rule) in &self.outputs {
            if policy.outputs.contains_key(name) || contract.fields.contains_key(name) {
                return Err(MappingError::ReservedClaim);
            }
            policy.outputs.insert(name.clone(), rule.expression.clone());
            contract.fields.insert(
                name.clone(),
                FieldSchema {
                    required: rule.required,
                    schema: rule.schema.clone(),
                },
            );
        }
        policy.inputs.extend(self.inputs.iter().cloned());
        policy
            .released_outputs
            .extend(self.released_outputs.iter().cloned());
        policy.validate(contract)
    }

    /// Bind configuration to the actual recipient and storage revision.
    #[must_use]
    pub fn empty_policy(recipient: Recipient, revision: String) -> MappingPolicy {
        MappingPolicy {
            schema_version: 1,
            revision,
            recipient,
            inputs: BTreeSet::new(),
            outputs: BTreeMap::new(),
            released_outputs: BTreeSet::new(),
        }
    }
}
