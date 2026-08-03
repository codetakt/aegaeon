use axum::{http::StatusCode, response::Response};

use super::super::no_cache_json_error_with_iss;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::web) struct DuplicateFormField;

pub(in crate::web) fn form_field(
    params: &[(String, String)],
    name: &str,
) -> Result<Option<String>, DuplicateFormField> {
    params
        .iter()
        .filter(|(key, _)| key == name)
        .try_fold(None, |current, (_, value)| match current {
            Some(_) => Err(DuplicateFormField),
            None => Ok(Some(value.clone())),
        })
}

pub(in crate::web) fn reject_duplicate_form_fields(
    params: &[(String, String)],
    names: &[&str],
) -> Result<(), DuplicateFormField> {
    names
        .iter()
        .try_for_each(|name| form_field(params, name).map(|_| ()))
}

pub(in crate::web) fn form_parse_error_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        Some("invalid form body"),
        issuer_base,
    )
}

pub(in crate::web) fn singleton_form_field(
    params: &[(String, String)],
    name: &str,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    form_field(params, name).map_err(|_| {
        let description = format!("{name} must not be specified multiple times");
        no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some(&description),
            issuer_base,
        )
    })
}

pub(in crate::web) fn singleton_form_u64(
    params: &[(String, String)],
    name: &str,
    issuer_base: &str,
) -> Result<Option<u64>, Response> {
    singleton_form_field(params, name, issuer_base)?
        .map(|value| {
            value.parse::<u64>().map_err(|_| {
                let description = format!("{name} must be an unsigned integer");
                no_cache_json_error_with_iss(
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    Some(&description),
                    issuer_base,
                )
            })
        })
        .transpose()
}
