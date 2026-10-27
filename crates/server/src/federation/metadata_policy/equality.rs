use serde_json::{Number, Value};

// Compare the decimal represented by Number, without rounding integers to f64.
// Raw JSON parser precision loss is outside this typed-Value boundary.
fn decimal(number: &Number) -> Option<(bool, String, i64)> {
    let text = number.to_string();
    let (negative, unsigned) = text
        .strip_prefix('-')
        .map_or((false, text.as_str()), |s| (true, s));
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or(Some((unsigned, 0)), |(m, e)| {
            e.parse::<i64>().ok().map(|e| (m, e))
        })?;
    let fraction = mantissa.split_once('.').map_or(0, |(_, f)| f.len());
    let mut exponent = exponent.checked_sub(i64::try_from(fraction).ok()?)?;
    let mut digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    digits = digits.trim_start_matches('0').to_owned();
    if digits.is_empty() {
        return Some((false, "0".into(), 0));
    }
    while digits.ends_with('0') {
        digits.pop();
        exponent = exponent.checked_add(1)?;
    }
    Some((negative, digits, exponent))
}

pub(super) fn equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(a), Value::Number(b)) => match (decimal(a), decimal(b)) {
            (Some(a), Some(b)) => a == b,
            _ => false,
        },
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len() && a.iter().all(|(k, a)| b.get(k).is_some_and(|b| equal(a, b)))
        }
        _ => a == b,
    }
}

pub(super) fn contains(values: &[Value], value: &Value) -> bool {
    values.iter().any(|candidate| equal(candidate, value))
}

pub(super) fn union(left: &[Value], right: &[Value]) -> Vec<Value> {
    let mut result = Vec::new();
    for value in left.iter().chain(right) {
        if !contains(&result, value) {
            result.push(value.clone());
        }
    }
    result
}

pub(super) fn intersection(left: &[Value], right: &[Value]) -> Vec<Value> {
    left.iter()
        .filter(|value| contains(right, value))
        .cloned()
        .collect()
}
