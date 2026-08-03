use axum::response::Response;

use super::super::form_helpers::{
    form_parse_error_response, singleton_form_field, singleton_form_u64,
};

#[derive(Clone, Default)]
pub(in crate::web) struct ParForm {
    pub(super) client_id: Option<String>,
    pub(super) response_type: Option<String>,
    pub(super) redirect_uri: Option<String>,
    pub(super) iss: Option<String>,
    pub(in crate::web) resource: Vec<String>,
    pub(super) authorization_details: Option<String>,
    pub(super) scope: Option<String>,
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

pub(in crate::web) fn parse_par_form(
    form: Result<
        axum::extract::Form<Vec<(String, String)>>,
        axum::extract::rejection::FormRejection,
    >,
    issuer_base: &str,
) -> Result<ParForm, Response> {
    let params = form
        .map(|axum::extract::Form(params)| params)
        .map_err(|_| form_parse_error_response(issuer_base))?;
    Ok(ParForm {
        client_id: singleton_form_field(&params, "client_id", issuer_base)?,
        response_type: singleton_form_field(&params, "response_type", issuer_base)?,
        iss: singleton_form_field(&params, "iss", issuer_base)?,
        redirect_uri: singleton_form_field(&params, "redirect_uri", issuer_base)?,
        resource: params
            .iter()
            .filter(|(key, _)| key == "resource")
            .map(|(_, value)| value.clone())
            .collect(),
        authorization_details: singleton_form_field(&params, "authorization_details", issuer_base)?,
        scope: singleton_form_field(&params, "scope", issuer_base)?,
        state: singleton_form_field(&params, "state", issuer_base)?,
        nonce: singleton_form_field(&params, "nonce", issuer_base)?,
        acr_values: singleton_form_field(&params, "acr_values", issuer_base)?,
        max_age: singleton_form_u64(&params, "max_age", issuer_base)?,
        code_challenge: singleton_form_field(&params, "code_challenge", issuer_base)?,
        code_challenge_method: singleton_form_field(&params, "code_challenge_method", issuer_base)?,
        client_secret: singleton_form_field(&params, "client_secret", issuer_base)?,
        client_assertion_type: singleton_form_field(&params, "client_assertion_type", issuer_base)?,
        client_assertion: singleton_form_field(&params, "client_assertion", issuer_base)?,
        request: singleton_form_field(&params, "request", issuer_base)?,
    })
}
