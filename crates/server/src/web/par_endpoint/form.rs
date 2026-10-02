use axum::response::Response;

use super::super::form_helpers::{singleton_form_field, singleton_form_u64};

#[derive(Clone, Default)]
pub(in crate::web) struct ParForm {
    pub(super) dpop_jkt: Option<String>,
    pub(super) client_id: Option<String>,
    pub(super) response_type: Option<String>,
    pub(super) response_mode: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) iss: Option<String>,
    pub(in crate::web) resource: Vec<String>,
    pub(super) authorization_details: Option<String>,
    pub(super) scope: Option<String>,
    pub(super) prompt: Option<String>,
    pub(super) state: Option<String>,
    pub(super) nonce: Option<String>,
    pub(super) acr_values: Option<String>,
    pub(super) max_age: Option<u64>,
    pub(super) code_challenge: Option<String>,
    pub(super) code_challenge_method: Option<String>,
    pub(super) client_secret: Option<String>,
    pub(super) client_assertion_type: Option<String>,
    pub(super) client_assertion: Option<String>,
    pub(super) request: Option<String>,
}

#[cfg(test)]
pub(in crate::web) fn parse_par_form(
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    issuer_base: &str,
) -> Result<ParForm, Response> {
    let params = form
        .map(|axum::extract::Form(params)| super::super::token_form::effective_oauth_form(params))
        .map_err(|_| super::super::form_helpers::form_parse_error_response(issuer_base))?;
    parse_par_pairs(&params, issuer_base)
}

/// Strict decoding retains PAR's 2 MiB router body limit and unrestricted fields.
/// The front-channel URI cap is deliberately not applied to pushed bodies.
pub(super) fn decode_par_form(raw: &[u8], issuer_base: &str) -> Result<ParForm, Response> {
    use super::super::oidc_request_input::{decode_component, OidcInputError};
    let mut params = Vec::new();
    for segment in raw
        .split(|byte| *byte == b'&')
        .filter(|segment| !segment.is_empty())
    {
        let split = segment.iter().position(|byte| *byte == b'=');
        let (key, value) = split.map_or((segment, &[][..]), |at| {
            (&segment[..at], &segment[at + 1..])
        });
        let key = decode_component(key, raw.len(), OidcInputError::ParameterNameTooLarge)
            .map_err(|error| error.into_response(issuer_base))?;
        let value = decode_component(value, raw.len(), OidcInputError::ParameterValueTooLarge)
            .map_err(|error| error.into_response(issuer_base))?;
        params.push((key, value));
    }
    parse_par_pairs(
        &super::super::token_form::effective_oauth_form(params),
        issuer_base,
    )
}

fn parse_par_pairs(params: &[(String, String)], issuer_base: &str) -> Result<ParForm, Response> {
    if params.iter().any(|(key, _)| key == "request_uri") {
        return Err(super::super::oauth_errors::no_cache_json_error_with_iss(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("request_uri must not be supplied to PAR"),
            issuer_base,
        ));
    }
    // RFC 9126 section 3 applies to all effective parameters, including extensions
    // that are not represented in ParForm. Do not silently drop an outer claim.
    if params.iter().any(|(key, _)| key == "request")
        && params.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "request"
                    | "client_id"
                    | "client_secret"
                    | "client_assertion_type"
                    | "client_assertion"
            )
        })
    {
        return Err(super::super::oauth_errors::no_cache_json_error_with_iss(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("authorization parameters must not be supplied outside request"),
            issuer_base,
        ));
    }
    Ok(ParForm {
        dpop_jkt: singleton_form_field(params, "dpop_jkt", issuer_base)?,
        client_id: singleton_form_field(params, "client_id", issuer_base)?,
        response_type: singleton_form_field(params, "response_type", issuer_base)?,
        response_mode: singleton_form_field(params, "response_mode", issuer_base)?,
        iss: singleton_form_field(params, "iss", issuer_base)?,
        redirect_uri: singleton_form_field(params, "redirect_uri", issuer_base)?,
        resource: params
            .iter()
            .filter(|(key, _)| key == "resource")
            .map(|(_, value)| value.clone())
            .collect(),
        authorization_details: singleton_form_field(params, "authorization_details", issuer_base)?,
        scope: singleton_form_field(params, "scope", issuer_base)?,
        prompt: singleton_form_field(params, "prompt", issuer_base)?,
        state: singleton_form_field(params, "state", issuer_base)?,
        nonce: singleton_form_field(params, "nonce", issuer_base)?,
        acr_values: singleton_form_field(params, "acr_values", issuer_base)?,
        max_age: singleton_form_u64(params, "max_age", issuer_base)?,
        code_challenge: singleton_form_field(params, "code_challenge", issuer_base)?,
        code_challenge_method: singleton_form_field(params, "code_challenge_method", issuer_base)?,
        client_secret: singleton_form_field(params, "client_secret", issuer_base)?,
        client_assertion_type: singleton_form_field(params, "client_assertion_type", issuer_base)?,
        client_assertion: singleton_form_field(params, "client_assertion", issuer_base)?,
        request: singleton_form_field(params, "request", issuer_base)?,
    })
}
