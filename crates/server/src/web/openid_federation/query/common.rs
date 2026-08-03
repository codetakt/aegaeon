use axum::{http::StatusCode, response::Response};

use super::super::super::oauth_errors::json_error_with_iss;
use super::super::super::request_admission::{
    bounded_query_pairs, BoundedQueryLimits, BoundedQueryRejection,
};

pub(super) const FEDERATION_QUERY_LIMITS: BoundedQueryLimits =
    BoundedQueryLimits::new(8 * 1024, 32, 64, MAX_FEDERATION_LIST_CURSOR_BYTES);
pub(super) const MAX_FEDERATION_ENTITY_ID_BYTES: usize = 2 * 1024;
pub(super) const MAX_FEDERATION_ENTITY_TYPE_BYTES: usize = 128;
pub(super) const MAX_FEDERATION_LIST_PARAM_BYTES: usize = 128;
pub(super) const MAX_FEDERATION_LIST_CURSOR_BYTES: usize = 3 * 1024;
pub(super) const MAX_FEDERATION_LIST_PARAM_VALUES: usize = 16;
pub(super) const MAX_RESOLVE_TRUST_ANCHORS: usize = 8;
pub(super) const MAX_RESOLVE_ENTITY_TYPES: usize = 16;

pub(super) fn parse_bounded_query_pairs(
    raw_query: Option<&str>,
    label: &'static str,
    issuer: &str,
) -> Result<Vec<(String, String)>, Response> {
    bounded_query_pairs(raw_query, FEDERATION_QUERY_LIMITS)
        .map_err(|err| federation_query_bounds_error(label, err, issuer))
}

pub(super) fn push_limited_value(
    values: &mut Vec<String>,
    value: String,
    parameter: &'static str,
    max_bytes: usize,
    max_count: Option<usize>,
    issuer: &str,
) -> Result<(), Response> {
    if value.len() > max_bytes {
        return Err(resolve_query_bounds_error(
            &format!("{parameter} query parameter is too large"),
            issuer,
        ));
    }
    if max_count.is_some_and(|max| values.len() >= max) {
        return Err(resolve_query_bounds_error(
            &format!("too many {parameter} query parameters"),
            issuer,
        ));
    }
    values.push(value);
    Ok(())
}

pub(super) fn parse_optional_usize_parameter(
    values: &[String],
    parameter: &'static str,
    default: usize,
    accepted_range: Option<std::ops::RangeInclusive<usize>>,
    issuer: &str,
) -> Result<usize, Response> {
    let Some(value) = values.first() else {
        return Ok(default);
    };
    let parsed = value.trim().parse::<usize>().map_err(|_| {
        resolve_query_bounds_error(
            &format!("{parameter} query parameter must be an unsigned integer"),
            issuer,
        )
    })?;
    if let Some(range) = accepted_range
        .as_ref()
        .filter(|range| !range.contains(&parsed))
    {
        return Err(resolve_query_bounds_error(
            &format!(
                "{parameter} query parameter must be between {} and {}",
                range.start(),
                range.end()
            ),
            issuer,
        ));
    }
    Ok(parsed)
}

pub(super) fn resolve_query_bounds_error(message: &str, issuer: &str) -> Response {
    json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some(message),
        issuer,
    )
}

pub(super) fn validate_federation_entity_id_parameter(
    parameter: &'static str,
    value: &str,
    issuer: &str,
) -> Result<String, Response> {
    let value = value.trim();
    if value.is_empty() {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&format!("{parameter} query parameter must not be empty")),
            issuer,
        ));
    }
    if crate::federation::validate_entity_url(value).is_err() {
        return Err(json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&format!(
                "invalid '{parameter}' query parameter; expected an HTTPS entity_id without userinfo, query, or fragment"
            )),
            issuer,
        ));
    }
    Ok(value.to_string())
}

pub(super) fn validate_federation_entity_type_parameters(
    entity_type: Vec<String>,
    issuer: &str,
) -> Result<Vec<String>, Response> {
    entity_type
        .into_iter()
        .map(|entity_type| {
            let entity_type = entity_type.trim();
            if entity_type.is_empty() {
                return Err(json_error_with_iss(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some("entity_type query parameter must not be empty"),
                    issuer,
                ));
            }
            Ok(entity_type.to_string())
        })
        .collect()
}

fn federation_query_bounds_error(
    label: &'static str,
    error: BoundedQueryRejection,
    issuer: &str,
) -> Response {
    resolve_query_bounds_error(&error.description(label), issuer)
}
