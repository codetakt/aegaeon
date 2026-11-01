//! Normalize only outgoing OAuth error fields before transport encoding.
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use std::borrow::Cow;

fn permitted(value: char) -> bool {
    matches!(value, '\u{20}'..='\u{21}' | '\u{23}'..='\u{5b}' | '\u{5d}'..='\u{7e}')
}

pub(crate) fn code(value: &str) -> &str {
    if !value.is_empty() && value.chars().all(permitted) {
        value
    } else {
        "server_error"
    }
}

pub(crate) fn description(value: Option<&str>) -> Option<Cow<'_, str>> {
    let value = value.filter(|value| !value.is_empty())?;
    Some(if value.chars().all(permitted) {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(
            value
                .chars()
                .map(|value| if permitted(value) { value } else { '?' })
                .collect(),
        )
    })
}

pub(crate) fn json_body(error: &str, detail: Option<&str>) -> Value {
    let mut body = json!({ "error": code(error) });
    if let Some(detail) = description(detail) {
        body["error_description"] = json!(detail);
    }
    body
}

pub(crate) fn serialize_code<S: Serializer>(value: &str, serializer: S) -> Result<S::Ok, S::Error> {
    code(value).serialize(serializer)
}

#[expect(
    clippy::ref_option,
    reason = "Serde field callbacks borrow the original Option field"
)]
pub(crate) fn description_is_empty(value: &Option<String>) -> bool {
    value.as_deref().is_none_or(str::is_empty)
}

#[expect(
    clippy::ref_option,
    reason = "Serde field callbacks borrow the original Option field"
)]
pub(crate) fn serialize_description<S: Serializer>(
    value: &Option<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    description(value.as_deref()).serialize(serializer)
}

#[cfg(test)]
pub(crate) mod tests;
