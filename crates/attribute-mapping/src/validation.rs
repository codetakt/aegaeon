use crate::model::*;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::io::{self, Write};

pub(crate) fn identifier(value: &str) -> Result<(), MappingError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(MappingError::Identifier);
    }
    Ok(())
}

pub(crate) fn subject(value: &Subject) -> Result<(), MappingError> {
    identifier(&value.environment_id)?;
    identifier(&value.user_id)
}

pub(crate) fn recipient(value: &Recipient) -> Result<(), MappingError> {
    identifier(&value.environment_id)?;
    identifier(&value.client_id)?;
    if let Surface::Profile(name) = &value.surface {
        identifier(name)?;
    }
    Ok(())
}

fn key(value: &AttributeKey) -> Result<(), MappingError> {
    identifier(&value.source)?;
    identifier(&value.name)
}

pub(crate) fn collection(size: usize) -> Result<(), MappingError> {
    if size > MAX_COLLECTION_ITEMS {
        return Err(MappingError::ResourceLimit);
    }
    Ok(())
}

pub(crate) fn json(value: &Value, depth: usize) -> Result<(), MappingError> {
    if depth > MAX_JSON_DEPTH {
        return Err(MappingError::ResourceLimit);
    }
    match value {
        Value::String(text) if text.len() > MAX_INPUT_BYTES => {
            return Err(MappingError::ResourceLimit);
        }
        Value::Array(values) => {
            collection(values.len())?;
            for value in values {
                json(value, depth + 1)?;
            }
        }
        Value::Object(values) => {
            collection(values.len())?;
            for (name, value) in values {
                if name.len() > MAX_IDENTIFIER_BYTES {
                    return Err(MappingError::ResourceLimit);
                }
                json(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct LimitedCounter {
    bytes: usize,
    limit: usize,
}

impl Write for LimitedCounter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let remaining = self.limit.saturating_sub(self.bytes);
        if buf.len() > remaining {
            return Err(io::Error::other("mapping size limit"));
        }
        self.bytes += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn encoded_size(value: &impl Serialize, limit: usize) -> Result<usize, MappingError> {
    let mut counter = LimitedCounter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| MappingError::ResourceLimit)?;
    Ok(counter.bytes)
}

pub(crate) fn attribute(value: &Attribute) -> Result<(), MappingError> {
    key(&value.key)?;
    subject(&value.owner)?;
    identifier(&value.provenance.authority)?;
    identifier(&value.provenance.source_revision)?;
    collection(value.recipients.len())?;
    for target in &value.recipients {
        recipient(target)?;
        if target.environment_id != value.owner.environment_id {
            return Err(MappingError::RecipientMismatch);
        }
    }
    if let Some(data) = value.value.as_ref() {
        json(data, 0)?;
    }
    Ok(())
}

struct Nodes(usize);

impl Nodes {
    fn enter(&mut self, depth: usize) -> Result<(), MappingError> {
        if depth > MAX_EXPRESSION_DEPTH || self.0 >= MAX_POLICY_NODES {
            return Err(MappingError::ResourceLimit);
        }
        self.0 += 1;
        Ok(())
    }
}

fn path(steps: &[PathStep]) -> Result<(), MappingError> {
    if steps.len() > MAX_JSON_DEPTH {
        return Err(MappingError::ResourceLimit);
    }
    for step in steps {
        match step {
            // JSON object keys may be empty or contain spaces; do not normalize them.
            PathStep::Key(name) if name.len() > MAX_IDENTIFIER_BYTES => {
                return Err(MappingError::ResourceLimit);
            }
            PathStep::Index(index) if *index >= MAX_COLLECTION_ITEMS => {
                return Err(MappingError::ResourceLimit);
            }
            _ => {}
        }
    }
    Ok(())
}

fn expression(
    expr: &Expression,
    nodes: &mut Nodes,
    depth: usize,
    in_map: bool,
) -> Result<(), MappingError> {
    nodes.enter(depth)?;
    match expr {
        Expression::Read {
            attribute,
            path: steps,
        } => {
            key(attribute)?;
            path(steps)?;
        }
        Expression::Literal { value } => json(value, 0)?,
        Expression::Object { fields } => {
            collection(fields.len())?;
            for (name, expr) in fields {
                if name.len() > MAX_IDENTIFIER_BYTES {
                    return Err(MappingError::ResourceLimit);
                }
                expression(expr, nodes, depth + 1, in_map)?;
            }
        }
        Expression::Array { items }
        | Expression::Coalesce { choices: items }
        | Expression::Concat { parts: items, .. } => {
            collection(items.len())?;
            if matches!(expr, Expression::Coalesce { .. }) && items.is_empty() {
                return Err(MappingError::Expression);
            }
            if let Expression::Concat { separator, .. } = expr {
                if separator.len() > MAX_OUTPUT_BYTES {
                    return Err(MappingError::ResourceLimit);
                }
            }
            for expr in items {
                expression(expr, nodes, depth + 1, in_map)?;
            }
        }
        Expression::LowerAscii { input } => expression(input, nodes, depth + 1, in_map)?,
        Expression::Map { input, item } => {
            expression(input, nodes, depth + 1, in_map)?;
            expression(item, nodes, depth + 1, true)?;
        }
        Expression::Item { path: steps } => {
            if !in_map {
                return Err(MappingError::ItemScope);
            }
            path(steps)?;
        }
    }
    Ok(())
}

fn schema(value: &ValueSchema, nodes: &mut Nodes, depth: usize) -> Result<(), MappingError> {
    nodes.enter(depth)?;
    match value {
        ValueSchema::Array { items } => schema(items, nodes, depth + 1)?,
        ValueSchema::Object { properties } => {
            collection(properties.len())?;
            for (name, field) in properties {
                if name.len() > MAX_IDENTIFIER_BYTES {
                    return Err(MappingError::ResourceLimit);
                }
                schema(&field.schema, nodes, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn reserved(name: &str, additional: &BTreeSet<String>) -> bool {
    const OWNED: &[&str] = &[
        "sub",
        "iss",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "nonce",
        "auth_time",
        "acr",
        "amr",
        "azp",
        "sid",
        "at_hash",
        "c_hash",
        "cnf",
        "act",
        "may_act",
        "client_id",
        "scope",
        "_claim_names",
        "_claim_sources",
    ];
    let canonical = name.trim().to_ascii_lowercase();
    OWNED.contains(&canonical.as_str())
        || additional
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(&canonical))
}

pub(crate) fn policy(value: &MappingPolicy, contract: &OutputContract) -> Result<(), MappingError> {
    if value.schema_version != 1 {
        return Err(MappingError::SchemaVersion);
    }
    identifier(&value.revision)?;
    recipient(&value.recipient)?;
    collection(value.inputs.len())?;
    collection(value.outputs.len())?;
    collection(value.released_outputs.len())?;
    collection(contract.fields.len())?;
    collection(contract.additional_reserved_names.len())?;
    for name in &contract.additional_reserved_names {
        identifier(name)?;
    }
    for input in &value.inputs {
        key(input)?;
    }
    let mut nodes = Nodes(0);
    for (name, field) in &contract.fields {
        identifier(name)?;
        if reserved(name, &contract.additional_reserved_names) {
            return Err(MappingError::ReservedClaim);
        }
        schema(&field.schema, &mut nodes, 0)?;
    }
    for name in &value.released_outputs {
        if !value.outputs.contains_key(name) {
            return Err(MappingError::OutputContract);
        }
    }
    for (name, expr) in &value.outputs {
        identifier(name)?;
        if reserved(name, &contract.additional_reserved_names) {
            return Err(MappingError::ReservedClaim);
        }
        if !contract.fields.contains_key(name) {
            return Err(MappingError::OutputContract);
        }
        if !value.released_outputs.contains(name) {
            return Err(MappingError::OutputDenied);
        }
        expression(expr, &mut nodes, 0, false)?;
        let mut inputs = BTreeSet::new();
        crate::engine::references(expr, &mut inputs);
        if inputs.iter().any(|input| !value.inputs.contains(*input)) {
            return Err(MappingError::InputDenied);
        }
    }
    if contract
        .fields
        .iter()
        .any(|(name, field)| field.required && !value.outputs.contains_key(name))
    {
        return Err(MappingError::MissingRequired);
    }
    encoded_size(value, MAX_INPUT_BYTES)?;
    encoded_size(contract, MAX_INPUT_BYTES)?;
    Ok(())
}

pub(crate) fn matches_schema(value: &Value, expected: &ValueSchema) -> Result<(), MappingError> {
    match (value, expected) {
        (Value::String(_), ValueSchema::String)
        | (Value::Bool(_), ValueSchema::Boolean)
        | (Value::Number(_), ValueSchema::Number)
        | (Value::Null, ValueSchema::Null) => Ok(()),
        (Value::Number(number), ValueSchema::Integer) if number.is_i64() || number.is_u64() => {
            Ok(())
        }
        (Value::Array(values), ValueSchema::Array { items }) => {
            for value in values {
                matches_schema(value, items)?;
            }
            Ok(())
        }
        (Value::Object(values), ValueSchema::Object { properties }) => {
            if values.keys().any(|key| !properties.contains_key(key)) {
                return Err(MappingError::OutputContract);
            }
            for (name, field) in properties {
                match values.get(name) {
                    Some(value) => matches_schema(value, &field.schema)?,
                    None if field.required => return Err(MappingError::MissingRequired),
                    None => {}
                }
            }
            Ok(())
        }
        _ => Err(MappingError::OutputContract),
    }
}
