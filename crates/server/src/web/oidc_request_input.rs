//! Strict query admission shared by the OIDC browser endpoints.
//!
//! This only interprets request parameters. The caller must still apply transport
//! and credential-in-URI admission to the actual request URI, and all protocol,
//! profile, session, CSRF and effect checks to the admitted values.

use axum::{
    http::{StatusCode, Uri},
    response::Response,
};
use serde::de::DeserializeOwned;

use super::authorize_request::RawAuthzQuery;
use super::oauth_errors::no_cache_json_error_with_iss;
use super::request_admission::{BoundedQueryLimits, DEFAULT_QUERY_LIMITS};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::web) enum OidcEndpoint {
    Authorize,
    Logout,
    LogoutConfirmation,
}

impl OidcEndpoint {
    fn recognizes(self, name: &str) -> bool {
        match self {
            Self::Authorize => RawAuthzQuery::recognizes_parameter(name),
            Self::LogoutConfirmation => matches!(name, "transaction" | "decision"),
            Self::Logout => matches!(
                name,
                "id_token_hint"
                    | "logout_hint"
                    | "client_id"
                    | "post_logout_redirect_uri"
                    | "state"
                    | "ui_locales"
            ),
        }
    }

    fn repeatable(self, name: &str) -> bool {
        // RFC 8707 section 2 explicitly permits repeated resource parameters.
        self == Self::Authorize && name == "resource"
    }
}

/// Admitted values may contain request objects or ID tokens: deliberately no Debug.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::web) struct OidcParameters {
    pairs: Vec<(String, String)>,
}

impl OidcParameters {
    /// Revalidate decoded values loaded from a private transaction envelope.
    pub(in crate::web) fn validate_authorization(&self) -> Result<(), OidcInputError> {
        let limits = DEFAULT_QUERY_LIMITS;
        if self.pairs.len() > limits.max_params() {
            return Err(OidcInputError::TooManyParameters);
        }
        let mut total = 0_usize;
        for (index, (key, value)) in self.pairs.iter().enumerate() {
            if key.len() > limits.max_key_bytes() || value.len() > limits.max_value_bytes() {
                return Err(OidcInputError::ParametersTooLarge);
            }
            total = total
                .saturating_add(key.len())
                .saturating_add(value.len())
                .saturating_add(2);
            if value.is_empty()
                || !OidcEndpoint::Authorize.recognizes(key)
                || (!OidcEndpoint::Authorize.repeatable(key)
                    && self.pairs[..index].iter().any(|(other, _)| other == key))
            {
                return Err(OidcInputError::InvalidParameterValue);
            }
        }
        // Every original encoding has at least these decoded bytes and separators.
        if total.saturating_sub(1) > limits.max_bytes() {
            return Err(OidcInputError::ParametersTooLarge);
        }
        Ok(())
    }

    pub(in crate::web) fn as_pairs(&self) -> &[(String, String)] {
        &self.pairs
    }

    /// Lower singleton fields through the existing serde form representation.
    /// Authorization uses its own lowering to preserve repeated `resource` values.
    pub(in crate::web) fn deserialize<T: DeserializeOwned>(&self) -> Result<T, OidcInputError> {
        let encoded = serde_urlencoded::to_string(&self.pairs)
            .map_err(|_| OidcInputError::InvalidParameterValue)?;
        serde_urlencoded::from_str(&encoded).map_err(|_| OidcInputError::InvalidParameterValue)
    }
}

/// Rejections contain no supplied parameter, header, URI or token values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web) enum OidcInputError {
    MalformedEncoding,
    ParametersTooLarge,
    TooManyParameters,
    ParameterNameTooLarge,
    ParameterValueTooLarge,
    DuplicateParameter,
    InvalidParameterValue,
}

impl OidcInputError {
    pub(in crate::web) fn into_response(self, issuer: &str) -> Response {
        let description = match self {
            Self::MalformedEncoding => "request parameters have invalid form encoding",
            Self::ParametersTooLarge => "request parameters are too large",
            Self::TooManyParameters => "too many request parameters",
            Self::ParameterNameTooLarge => "request parameter name is too large",
            Self::ParameterValueTooLarge => "request parameter value is too large",
            Self::DuplicateParameter => "request parameter must not be specified multiple times",
            Self::InvalidParameterValue => "request parameter value is invalid",
        };
        no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(description),
            issuer,
        )
    }
}

/// Admit the query used by GET and Axum's implicit HEAD routes.
pub(in crate::web) fn admit_oidc_query(
    endpoint: OidcEndpoint,
    uri: &Uri,
) -> Result<OidcParameters, OidcInputError> {
    admit_pairs(
        endpoint,
        uri.query().unwrap_or("").as_bytes(),
        DEFAULT_QUERY_LIMITS,
    )
}

/// The caller must bound body buffering and validate form content type first.
pub(in crate::web) fn admit_oidc_form(
    endpoint: OidcEndpoint,
    raw: &[u8],
) -> Result<OidcParameters, OidcInputError> {
    admit_pairs(endpoint, raw, DEFAULT_QUERY_LIMITS)
}

fn admit_pairs(
    endpoint: OidcEndpoint,
    raw: &[u8],
    limits: BoundedQueryLimits,
) -> Result<OidcParameters, OidcInputError> {
    if raw.len() > limits.max_bytes() {
        return Err(OidcInputError::ParametersTooLarge);
    }
    let mut pairs: Vec<(String, String)> = Vec::new();
    for (index, segment) in raw
        .split(|byte| *byte == b'&')
        .filter(|s| !s.is_empty())
        .enumerate()
    {
        // Count before empty-value/unknown filtering, as validate_raw_query does.
        if index >= limits.max_params() {
            return Err(OidcInputError::TooManyParameters);
        }
        let split = segment.iter().position(|byte| *byte == b'=');
        let (key, value) = split.map_or((segment, &[][..]), |at| {
            (&segment[..at], &segment[at + 1..])
        });
        let key = decode_component(
            key,
            limits.max_key_bytes(),
            OidcInputError::ParameterNameTooLarge,
        )?;
        let value = decode_component(
            value,
            limits.max_value_bytes(),
            OidcInputError::ParameterValueTooLarge,
        )?;
        if endpoint == OidcEndpoint::LogoutConfirmation
            && (value.is_empty() || !endpoint.recognizes(&key))
        {
            return Err(OidcInputError::InvalidParameterValue);
        }
        // RFC 6749 section 3.1: valueless parameters are treated as omitted.
        if value.is_empty() || !endpoint.recognizes(&key) {
            continue;
        }
        if !endpoint.repeatable(&key) && pairs.iter().any(|(existing, _)| *existing == key) {
            return Err(OidcInputError::DuplicateParameter);
        }
        pairs.push((key, value));
    }
    Ok(OidcParameters { pairs })
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(in crate::web) fn decode_component(
    raw: &[u8],
    max_decoded_bytes: usize,
    too_large: OidcInputError,
) -> Result<String, OidcInputError> {
    let mut decoded = Vec::with_capacity(raw.len().min(max_decoded_bytes));
    let mut cursor = 0;
    while cursor < raw.len() {
        let byte = match raw[cursor] {
            b'+' => b' ',
            b'%' => {
                let high = raw
                    .get(cursor + 1)
                    .copied()
                    .and_then(hex_value)
                    .ok_or(OidcInputError::MalformedEncoding)?;
                let low = raw
                    .get(cursor + 2)
                    .copied()
                    .and_then(hex_value)
                    .ok_or(OidcInputError::MalformedEncoding)?;
                cursor += 2;
                (high << 4) | low
            }
            byte => byte,
        };
        if decoded.len() == max_decoded_bytes {
            return Err(too_large);
        }
        decoded.push(byte);
        cursor += 1;
    }
    String::from_utf8(decoded).map_err(|_| OidcInputError::MalformedEncoding)
}

#[cfg(test)]
mod tests;
