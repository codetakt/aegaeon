//! Preserve endpoint query bytes while rejecting ambiguous protocol parameters.
use url::Url;

const TOKEN_FIELDS: &[&str] = &[
    "grant_type",
    "code",
    "redirect_uri",
    "code_verifier",
    "refresh_token",
    "client_id",
    "client_secret",
    "client_assertion",
    "client_assertion_type",
    "scope",
];

fn decode_component(raw: &str) -> Result<String, String> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = bytes.next().and_then(|b| char::from(b).to_digit(16));
                let low = bytes.next().and_then(|b| char::from(b).to_digit(16));
                match (high, low) {
                    (Some(high), Some(low)) => ((high << 4) | low) as u8,
                    _ => return Err("endpoint query has invalid form encoding".to_string()),
                }
            }
            byte => byte,
        });
    }
    String::from_utf8(decoded)
        .map_err(|_| "endpoint query has invalid UTF-8 form encoding".to_string())
}

/// Only decoded names and applicable values are inspected; unrelated values stay opaque.
/// Validate the entire query before appending anything, so errors do not partially mutate it.
pub(super) fn append_endpoint_parameters(
    url: &mut Url,
    generated: &[(&str, &str)],
    forbidden: &[&str],
) -> Result<(), String> {
    let mut present = vec![false; generated.len()];
    for pair in url
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
    {
        let (raw_name, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode_component(raw_name)?;
        if forbidden.contains(&name.as_str()) {
            return Err(format!("endpoint query must not contain {name}"));
        }
        if let Some(index) = generated.iter().position(|(key, _)| *key == name) {
            if present[index] || decode_component(raw_value)? != generated[index].1 {
                return Err(format!("endpoint query conflicts with generated {name}"));
            }
            present[index] = true;
        }
    }
    for ((name, value), exists) in generated.iter().zip(present) {
        if !exists {
            url.query_pairs_mut().append_pair(name, value);
        }
    }
    Ok(())
}

pub(super) fn validate_token_endpoint_query(endpoint: &str) -> Result<(), String> {
    let mut url = Url::parse(endpoint).map_err(|_| "token_endpoint is invalid".to_string())?;
    append_endpoint_parameters(&mut url, &[], TOKEN_FIELDS)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(in crate::web) mod http_fixture;
