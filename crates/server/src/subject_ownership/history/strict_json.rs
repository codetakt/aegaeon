use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::cell::Cell;
use std::collections::HashSet;
use std::fmt;
use std::rc::Rc;

#[derive(Debug, thiserror::Error)]
#[error("invalid subject history input: {0}")]
pub struct HistoryInputError(pub(super) String);

/// Parse the closed-contract JSON lexical domain without discarding duplicate keys.
/// Semantic schema and ownership validation must follow this syntax check.
///
/// # Errors
/// Refuses excessive bytes/depth, duplicate decoded keys, NUL, noninteger numeric
/// syntax, BOM, trailing data and invalid UTF8/JSON. Error text contains no input.
pub fn parse_strict(raw: &[u8], max_bytes: usize) -> Result<Value, HistoryInputError> {
    if raw.len() > max_bytes {
        return Err(HistoryInputError("byte limit exceeded".into()));
    }
    validate_numbers(raw)?;
    let mut parser = serde_json::Deserializer::from_slice(raw);
    let value = Node {
        depth: 0,
        entries: Rc::new(Cell::new(0)),
        count_items: false,
        item_limit: None,
    }
    .deserialize(&mut parser)
    .map_err(|_| {
        HistoryInputError("JSON syntax, duplicate member, string or depth violation".into())
    })?;
    parser
        .end()
        .map_err(|_| HistoryInputError("trailing data".into()))?;
    Ok(value)
}

fn validate_numbers(raw: &[u8]) -> Result<(), HistoryInputError> {
    let mut index = 0;
    let mut quoted = false;
    while index < raw.len() {
        let byte = raw[index];
        if quoted {
            if byte == b'\\' {
                index += 2;
                continue;
            }
            if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            while index < raw.len() && !b",]} \t\r\n".contains(&raw[index]) {
                index += 1;
            }
            let token = &raw[start..index];
            if token.is_empty()
                || !token.iter().all(u8::is_ascii_digit)
                || (token.len() > 1 && token[0] == b'0')
            {
                return Err(HistoryInputError("noncanonical integer syntax".into()));
            }
            continue;
        }
        index += 1;
    }
    Ok(())
}

struct Node {
    depth: usize,
    entries: Rc<Cell<usize>>,
    count_items: bool,
    item_limit: Option<usize>,
}
struct Element {
    node: Node,
    count_entry: bool,
    ordinal: usize,
    limit: Option<usize>,
}
impl<'de> DeserializeSeed<'de> for Element {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.limit.is_some_and(|limit| self.ordinal >= limit) {
            return Err(serde::de::Error::custom("array limit"));
        }
        if self.count_entry {
            let count = self.node.entries.get();
            if count >= 1_000_000 {
                return Err(serde::de::Error::custom("combined entry limit"));
            }
            self.node.entries.set(count + 1);
        }
        self.node.deserialize(deserializer)
    }
}
impl<'de> DeserializeSeed<'de> for Node {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > 32 {
            return Err(serde::de::Error::custom("depth"));
        }
        deserializer.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Node {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded strict history JSON")
    }
    fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Value, E> {
        if v > i64::MAX as u64 {
            return Err(E::custom("bigint"));
        }
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Value, E> {
        if v < 0 {
            return Err(E::custom("nonnegative integer"));
        }
        Ok(Value::Number(Number::from(v)))
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Value, E> {
        if v.contains('\0') {
            return Err(E::custom("NUL"));
        }
        Ok(Value::String(v.to_owned()))
    }
    fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Value, E> {
        if v.contains('\0') {
            return Err(E::custom("NUL"));
        }
        Ok(Value::String(v))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = input.next_element_seed(Element {
            node: Node {
                depth: self.depth + 1,
                entries: Rc::clone(&self.entries),
                count_items: false,
                item_limit: None,
            },
            count_entry: self.count_items,
            ordinal: values.len(),
            limit: self.item_limit,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut keys = HashSet::new();
        let mut values = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if key.contains('\0') || !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate or NUL key"));
            }
            let count_items = self.depth == 0
                && matches!(
                    key.as_str(),
                    "owners" | "reservations" | "invalid_history" | "resolutions"
                );
            let item_limit =
                matches!(key.as_str(), "sources" | "source_refs" | "fact_refs").then_some(256);
            let value = input.next_value_seed(Node {
                depth: self.depth + 1,
                entries: Rc::clone(&self.entries),
                count_items,
                item_limit,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_strict_lexical_distinctions() {
        for invalid in [
            r#"{"a":1,"\u0061":2}"#,
            r#"{"x":{"a":1,"a":2}}"#,
            "-0",
            "1e0",
            "1.0",
            "01",
            r#""\u0000""#,
            "{}{}",
        ] {
            assert!(parse_strict(invalid.as_bytes(), 4096).is_err(), "{invalid}");
        }
        assert!(parse_strict(br#"{"a":"1e0","b":1,"c":null}"#, 4096).is_ok());
        assert!(parse_strict(b"{}", 1).is_err());
        let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
        assert!(parse_strict(deep.as_bytes(), 4096).is_err());
    }
}
