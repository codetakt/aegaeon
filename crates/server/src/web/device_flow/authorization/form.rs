use axum::{http::StatusCode, response::Response};

use crate::util;

use super::super::super::oauth_errors::json_error_with_iss;
use super::super::super::{optional_token_param, TokenForm, DEVICE_CODE_GRANT_TYPE};

pub(super) struct DeviceAuthorizationForm {
    pub(super) scope: Option<String>,
    pub(super) resource: Option<String>,
    pub(super) token_form: TokenForm,
}

pub(super) fn device_authorization_form_from_params(
    params: &[(String, String)],
    issuer_base: &str,
) -> Result<DeviceAuthorizationForm, Response> {
    let client_id = optional_token_param(params, "client_id", issuer_base)?
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let scope = optional_token_param(params, "scope", issuer_base)?;
    let resource = params
        .iter()
        .filter(|(key, _)| key == "resource")
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    let resource = util::parse_single_resource_indicator(&resource).map_err(|description| {
        json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            Some(&description),
            issuer_base,
        )
    })?;
    let client_secret = optional_token_param(params, "client_secret", issuer_base)?;
    let client_assertion_type = optional_token_param(params, "client_assertion_type", issuer_base)?;
    let client_assertion = optional_token_param(params, "client_assertion", issuer_base)?;
    let token_form = TokenForm {
        grant_type: DEVICE_CODE_GRANT_TYPE.to_string(),
        code: None,
        client_id,
        client_secret,
        code_verifier: None,
        redirect_uri: None,
        scope: scope.clone(),
        refresh_token: None,
        assertion: None,
        client_assertion_type,
        client_assertion,
        device_code: None,
    };
    Ok(DeviceAuthorizationForm {
        scope,
        resource,
        token_form,
    })
}
