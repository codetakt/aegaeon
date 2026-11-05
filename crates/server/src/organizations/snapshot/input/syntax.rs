//! Duplicate-aware integer JSON. Values are bounded by the caller before parsing.
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

pub(super) fn parse(raw: &[u8]) -> Result<Value, &'static str> {
    let mut parser = serde_json::Deserializer::from_slice(raw);
    let value = Node(0)
        .deserialize(&mut parser)
        .map_err(|_| "JSON syntax, duplicate key, integer or depth")?;
    parser.end().map_err(|_| "trailing JSON")?;
    Ok(value)
}

struct Node(usize);
impl<'de> DeserializeSeed<'de> for Node {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, parser: D) -> Result<Value, D::Error> {
        if self.0 > 32 {
            return Err(serde::de::Error::custom("depth"));
        }
        parser.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Node {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded integer JSON without duplicate keys")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        if value.contains('\0') {
            return Err(E::custom("NUL"));
        }
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        if value.contains('\0') {
            return Err(E::custom("NUL"));
        }
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut result = Vec::new();
        while let Some(value) = input.next_element_seed(Node(self.0 + 1))? {
            result.push(value);
        }
        Ok(Value::Array(result))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> Result<Value, A::Error> {
        let mut result = Map::new();
        while let Some(key) = input.next_key::<String>()? {
            if key.contains('\0') || result.contains_key(&key) {
                return Err(serde::de::Error::custom("duplicate or NUL key"));
            }
            result.insert(key, input.next_value_seed(Node(self.0 + 1))?);
        }
        Ok(Value::Object(result))
    }
}
