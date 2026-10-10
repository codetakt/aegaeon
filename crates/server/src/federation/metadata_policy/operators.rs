use super::{
    equality::{contains, equal, intersection, union},
    error, FederationError,
};
use serde_json::{Map, Value};

#[derive(Clone, Debug)]
pub(in crate::federation) struct FieldPolicy(pub(super) Map<String, Value>);

fn kind(value: &Value) -> Option<u8> {
    match value {
        Value::String(_) => Some(0),
        Value::Object(_) => Some(1),
        Value::Number(_) => Some(2),
        _ => None,
    }
}

fn array(value: &Value) -> Result<&[Value], FederationError> {
    let values = value
        .as_array()
        .ok_or_else(|| error("set operator requires an array"))?;
    if let Some(first) = values.first() {
        let expected = kind(first).ok_or_else(|| error("unsupported set element type"))?;
        if values.iter().any(|value| kind(value) != Some(expected)) {
            return Err(error("set arrays must have a homogeneous supported type"));
        }
    }
    Ok(values)
}

fn subset(left: &Value, right: &Value) -> Result<bool, FederationError> {
    let left = array(left)?;
    let right = array(right)?;
    Ok(left.iter().all(|value| contains(right, value)))
}

impl FieldPolicy {
    pub(super) fn parse(value: &Value) -> Result<Self, FederationError> {
        let original = value
            .as_object()
            .filter(|ops| !ops.is_empty())
            .ok_or_else(|| error("operator policy must be a nonempty object"))?;
        let mut ops = Map::new();
        for (name, value) in original {
            match name.as_str() {
                "value" | "default" | "essential" | "add" | "one_of" | "subset_of"
                | "superset_of" => {
                    ops.insert(name.clone(), value.clone());
                }
                "intersect" => {
                    array(value)?;
                }
                _ => {} // Additional, noncritical operators: section 6.1.3.2.
            }
        }
        if let Some(alias) = original.get("intersect") {
            let normalized = if let Some(standard) = ops.get("subset_of") {
                let standard = array(standard)?;
                let alias = array(alias)?;
                if standard
                    .first()
                    .zip(alias.first())
                    .is_some_and(|(left, right)| kind(left) != kind(right))
                {
                    return Err(error("set operators require compatible element types"));
                }
                Value::Array(intersection(standard, alias))
            } else {
                alias.clone()
            };
            ops.insert("subset_of".into(), normalized);
        }
        let policy = Self(ops);
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<(), FederationError> {
        let ops = &self.0;
        let mut set_kind = None;
        for name in ["add", "one_of", "subset_of", "superset_of"] {
            if let Some(value) = ops.get(name) {
                if let Some(value_kind) = array(value)?.first().and_then(kind) {
                    if set_kind.is_some_and(|expected| expected != value_kind) {
                        return Err(error("set operators require compatible element types"));
                    }
                    set_kind = Some(value_kind);
                }
            }
        }
        if ops.get("default").is_some_and(Value::is_null) {
            return Err(error("default cannot be null"));
        }
        if ops.get("essential").is_some_and(|v| !v.is_boolean()) {
            return Err(error("essential must be boolean"));
        }
        if ops.contains_key("one_of")
            && ["add", "subset_of", "superset_of"]
                .iter()
                .any(|name| ops.contains_key(*name))
        {
            return Err(error("one_of cannot combine with array operators"));
        }
        if let Some(value) = ops.get("value") {
            if value.is_null()
                && (ops.contains_key("default") || ops.get("essential") == Some(&Value::Bool(true)))
            {
                return Err(error("null value conflicts with default or essential"));
            }
            if let Some(allowed) = ops.get("one_of") {
                if !contains(array(allowed)?, value) {
                    return Err(error("value must be in one_of"));
                }
            }
        }
        for (left, right) in [
            ("add", "value"),
            ("value", "subset_of"),
            ("superset_of", "value"),
            ("add", "subset_of"),
            ("superset_of", "subset_of"),
        ] {
            if let (Some(left), Some(right)) = (ops.get(left), ops.get(right)) {
                if !subset(left, right)? {
                    return Err(error("contradictory policy operator sets"));
                }
            }
        }
        Ok(())
    }

    pub(super) fn merge(&mut self, other: &Self) -> Result<(), FederationError> {
        for (name, right) in &other.0 {
            let value = if let Some(left) = self.0.get(name) {
                match name.as_str() {
                    "value" | "default" => {
                        if !equal(left, right) {
                            return Err(error("conflicting value/default policies"));
                        }
                        left.clone()
                    }
                    "add" | "superset_of" => Value::Array(union(array(left)?, array(right)?)),
                    "one_of" | "subset_of" => {
                        let merged = intersection(array(left)?, array(right)?);
                        if name == "one_of" && merged.is_empty() {
                            return Err(error("empty merged one_of"));
                        }
                        Value::Array(merged)
                    }
                    "essential" => {
                        Value::Bool(left == &Value::Bool(true) || right == &Value::Bool(true))
                    }
                    _ => return Err(error("unexpected normalized operator")),
                }
            } else {
                right.clone()
            };
            self.0.insert(name.clone(), value);
        }
        self.validate()
    }

    pub(super) fn apply(&self, current: Option<Value>) -> Result<Option<Value>, FederationError> {
        let ops = &self.0;
        let mut value = current;
        if let Some(forced) = ops.get("value") {
            value = (!forced.is_null()).then(|| forced.clone());
        }
        if let Some(add) = ops.get("add") {
            let old = value.as_ref().map(array).transpose()?.unwrap_or(&[]);
            let merged = Value::Array(union(old, array(add)?));
            array(&merged)?;
            value = Some(merged);
        }
        if value.is_none() {
            value = ops.get("default").cloned();
        }
        if let Some(present) = &value {
            if let Some(allowed) = ops.get("one_of") {
                if kind(present).is_none() || !contains(array(allowed)?, present) {
                    return Err(error("metadata not in one_of"));
                }
            }
            if let Some(allowed) = ops.get("subset_of") {
                value = Some(Value::Array(intersection(array(present)?, array(allowed)?)));
            }
        }
        if let (Some(present), Some(required)) = (&value, ops.get("superset_of")) {
            if !subset(required, present)? {
                return Err(error("metadata misses superset_of values"));
            }
        }
        if value.is_none() && ops.get("essential") == Some(&Value::Bool(true)) {
            return Err(error("essential metadata is absent"));
        }
        Ok(value)
    }
}
