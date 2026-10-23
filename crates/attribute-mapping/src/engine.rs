use crate::{model::*, validation};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappedClaim {
    pub value: Value,
    pub sources: Vec<SourceEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEvidence {
    pub attribute: AttributeKey,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappingOutput {
    pub subject: Subject,
    pub recipient: Recipient,
    pub policy_revision: String,
    pub claims: BTreeMap<String, MappedClaim>,
}

/// Evaluate a selected immutable policy using already authenticated input metadata.
///
/// No output is returned on a permission, freshness, ownership, schema or limit
/// failure. This function does not authenticate a policy or input provenance;
/// callers must obtain both from their authorized configuration/source adapters.
///
/// # Errors
/// Returns a value-free [`MappingError`] if any boundary check fails.
pub fn evaluate(
    subject: &Subject,
    recipient: &Recipient,
    now: i64,
    attributes: &[Attribute],
    policy: &MappingPolicy,
    contract: &OutputContract,
) -> Result<MappingOutput, MappingError> {
    validation::subject(subject)?;
    validation::recipient(recipient)?;
    validation::policy(policy, contract)?;
    if policy.recipient != *recipient || subject.environment_id != recipient.environment_id {
        return Err(MappingError::RecipientMismatch);
    }
    if now < 0 {
        return Err(MappingError::InvalidTime);
    }
    validation::collection(attributes.len())?;
    let mut inputs = BTreeMap::new();
    let mut input_bytes = 0;
    for attribute in attributes {
        validation::attribute(attribute)?;
        if attribute.owner != *subject {
            return Err(MappingError::SubjectMismatch);
        }
        input_bytes += validation::encoded_size(attribute, MAX_INPUT_BYTES - input_bytes)?;
        if inputs.insert(&attribute.key, attribute).is_some() {
            return Err(MappingError::DuplicateAttribute);
        }
    }

    let mut engine = Engine { inputs, steps: 0 };
    let mut claims = BTreeMap::new();
    let mut output_bytes = 0;
    for (name, expr) in &policy.outputs {
        let mut dependencies = BTreeSet::new();
        references(expr, &mut dependencies);
        let mut sources = Vec::with_capacity(dependencies.len());
        for key in dependencies {
            if !policy.inputs.contains(key) {
                return Err(MappingError::InputDenied);
            }
            let attribute = engine
                .inputs
                .get(key)
                .ok_or(MappingError::UnknownAttribute)?;
            if !attribute.recipients.contains(recipient) {
                return Err(MappingError::DisclosureDenied);
            }
            let provenance = &attribute.provenance;
            if provenance.observed_at < 0
                || provenance.observed_at > now
                || provenance
                    .expires_at
                    .is_some_and(|end| end <= provenance.observed_at)
            {
                return Err(MappingError::InvalidTime);
            }
            if provenance.expires_at.is_some_and(|end| end <= now) {
                return Err(MappingError::Expired);
            }
            sources.push(SourceEvidence {
                attribute: key.clone(),
                provenance: provenance.clone(),
            });
        }
        if let Some(value) = engine.eval(expr, None)? {
            let field = contract
                .fields
                .get(name)
                .ok_or(MappingError::OutputContract)?;
            validation::matches_schema(&value, &field.schema)?;
            let claim = MappedClaim { value, sources };
            output_bytes += validation::encoded_size(&claim, MAX_OUTPUT_BYTES - output_bytes)?;
            claims.insert(name.clone(), claim);
        }
    }
    for (name, field) in &contract.fields {
        if field.required && !claims.contains_key(name) {
            return Err(MappingError::MissingRequired);
        }
    }
    let output = MappingOutput {
        subject: subject.clone(),
        recipient: recipient.clone(),
        policy_revision: policy.revision.clone(),
        claims,
    };
    validation::encoded_size(&output, MAX_OUTPUT_BYTES)?;
    Ok(output)
}

pub(crate) fn references<'a>(expr: &'a Expression, output: &mut BTreeSet<&'a AttributeKey>) {
    match expr {
        Expression::Read { attribute, .. } => {
            output.insert(attribute);
        }
        Expression::Object { fields } => {
            for expr in fields.values() {
                references(expr, output);
            }
        }
        Expression::Array { items }
        | Expression::Coalesce { choices: items }
        | Expression::Concat { parts: items, .. } => {
            for expr in items {
                references(expr, output);
            }
        }
        Expression::LowerAscii { input } => references(input, output),
        Expression::Map { input, item } => {
            references(input, output);
            references(item, output);
        }
        Expression::Literal { .. } | Expression::Item { .. } => {}
    }
}

fn select<'a>(
    mut value: Option<&'a Value>,
    path: &[PathStep],
) -> Result<Option<&'a Value>, MappingError> {
    for step in path {
        value = match (value, step) {
            (None, _) => return Ok(None),
            (Some(Value::Object(fields)), PathStep::Key(key)) => fields.get(key),
            (Some(Value::Array(items)), PathStep::Index(index)) => items.get(*index),
            _ => return Err(MappingError::TypeMismatch),
        };
    }
    Ok(value)
}

struct Engine<'a> {
    inputs: BTreeMap<&'a AttributeKey, &'a Attribute>,
    steps: usize,
}

impl Engine<'_> {
    fn eval(
        &mut self,
        expr: &Expression,
        current: Option<&Value>,
    ) -> Result<Option<Value>, MappingError> {
        if self.steps >= MAX_EVALUATION_STEPS {
            return Err(MappingError::ResourceLimit);
        }
        self.steps += 1;
        let result = match expr {
            Expression::Read { attribute, path } => {
                let input = self
                    .inputs
                    .get(attribute)
                    .ok_or(MappingError::UnknownAttribute)?;
                let selected = select(input.value.as_ref(), path)?;
                if let Some(value) = selected {
                    validation::encoded_size(value, MAX_OUTPUT_BYTES)?;
                }
                selected.cloned()
            }
            Expression::Item { path } => {
                select(Some(current.ok_or(MappingError::ItemScope)?), path)?.cloned()
            }
            Expression::Literal { value } => {
                validation::encoded_size(value, MAX_OUTPUT_BYTES)?;
                Some(value.clone())
            }
            Expression::Object { fields } => {
                let mut object = Map::new();
                let mut bytes = 0;
                for (name, expr) in fields {
                    if let Some(value) = self.eval(expr, current)? {
                        bytes += validation::encoded_size(&value, MAX_OUTPUT_BYTES - bytes)?;
                        object.insert(name.clone(), value);
                    }
                }
                Some(Value::Object(object))
            }
            Expression::Array { items } => {
                let mut values = Vec::with_capacity(items.len());
                let mut bytes = 0;
                for expr in items {
                    // An absent array item must not silently shift subsequent positions.
                    let value = self
                        .eval(expr, current)?
                        .ok_or(MappingError::MissingRequired)?;
                    bytes += validation::encoded_size(&value, MAX_OUTPUT_BYTES - bytes)?;
                    values.push(value);
                }
                Some(Value::Array(values))
            }
            Expression::Coalesce { choices } => {
                let mut selected = None;
                for expr in choices {
                    let candidate = self.eval(expr, current)?;
                    if selected.is_none() {
                        selected = candidate;
                    }
                }
                selected
            }
            Expression::LowerAscii { input } => match self.eval(input, current)? {
                Some(Value::String(value)) => Some(Value::String(value.to_ascii_lowercase())),
                None => None,
                _ => return Err(MappingError::TypeMismatch),
            },
            Expression::Concat { parts, separator } => {
                let mut result = String::new();
                for (index, part) in parts.iter().enumerate() {
                    let Some(Value::String(value)) = self.eval(part, current)? else {
                        return Err(MappingError::TypeMismatch);
                    };
                    let separator = if index == 0 { "" } else { separator.as_str() };
                    if result.len() + separator.len() + value.len() > MAX_OUTPUT_BYTES {
                        return Err(MappingError::ResourceLimit);
                    }
                    result.push_str(separator);
                    result.push_str(&value);
                }
                Some(Value::String(result))
            }
            Expression::Map { input, item } => match self.eval(input, current)? {
                None => None,
                Some(Value::Array(values)) => {
                    let mut output = Vec::with_capacity(values.len());
                    let mut bytes = 0;
                    for value in &values {
                        let mapped = self
                            .eval(item, Some(value))?
                            .ok_or(MappingError::MissingRequired)?;
                        bytes += validation::encoded_size(&mapped, MAX_OUTPUT_BYTES - bytes)?;
                        output.push(mapped);
                    }
                    Some(Value::Array(output))
                }
                _ => return Err(MappingError::TypeMismatch),
            },
        };
        if let Some(value) = &result {
            validation::json(value, 0)?;
            validation::encoded_size(value, MAX_OUTPUT_BYTES)?;
        }
        Ok(result)
    }
}
