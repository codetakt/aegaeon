use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};

use crate::client_registry::ClientRegistry;

use super::super::super::oauth_errors::{
    authorization_header, no_cache_header_error, no_cache_json_error_with_iss,
    registry_state_error_response,
};
use super::super::super::{
    multiple_client_auth_methods_present, token_auth_presence,
    validate_private_key_jwt_client_assertion, AppState, ClientAuthPresence, TokenForm,
};

pub(super) struct DeviceAuthorizationClientContext {
    pub(super) client_id: String,
    pub(super) client_auth_method: &'static str,
}

fn device_invalid_client_response(issuer_base: &str) -> Response {
    no_cache_json_error_with_iss(
        StatusCode::UNAUTHORIZED,
        "invalid_client",
        None,
        issuer_base,
    )
}

fn device_client_id_from_basic(
    auth_header: Option<&str>,
    auth_presence: ClientAuthPresence,
    issuer_base: &str,
) -> Result<Option<String>, Response> {
    match (auth_presence.basic, auth_header) {
        (true, Some(header)) => ClientRegistry::decode_basic_auth_credentials(header)
            .map(|(id, _)| Some(id))
            .ok_or_else(|| device_invalid_client_response(issuer_base)),
        _ => Ok(None),
    }
}

fn resolve_device_authorization_client_id(
    auth_header: Option<&str>,
    auth_presence: ClientAuthPresence,
    form: &TokenForm,
    issuer_base: &str,
) -> Result<String, Response> {
    let client_id_from_basic =
        device_client_id_from_basic(auth_header, auth_presence, issuer_base)?;
    let client_id_from_form = form
        .client_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    match (client_id_from_form, client_id_from_basic.as_deref()) {
        (Some(form_id), Some(basic_id)) if form_id != basic_id => {
            Err(device_invalid_client_response(issuer_base))
        }
        (Some(form_id), _) => Ok(form_id.to_string()),
        (None, Some(basic_id)) => Ok(basic_id.to_string()),
        (None, None) => Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("client_id is required"),
            issuer_base,
        )),
    }
}

async fn device_client_authenticated(
    state: &AppState,
    auth_header: Option<&str>,
    form: &TokenForm,
    client_id: &str,
    client_auth_method: &str,
    issuer_base: &str,
) -> Result<bool, Response> {
    match client_auth_method {
        "client_secret_basic" => auth_header
            .map(|header| {
                state
                    .clients
                    .try_validate_basic_auth(header)
                    .map(|validated| {
                        validated.is_some_and(|(authenticated_id, _)| authenticated_id == client_id)
                    })
                    .map_err(|error| {
                        registry_state_error_response(
                            issuer_base,
                            "device_authorization_validate_basic_auth",
                            error,
                        )
                    })
            })
            .transpose()
            .map(|authenticated| authenticated.unwrap_or(false)),
        "client_secret_post" => Ok(state
            .clients
            .try_validate_client_secret_post(Some(client_id), form.client_secret.as_deref())
            .map_err(|error| {
                registry_state_error_response(
                    issuer_base,
                    "device_authorization_validate_client_secret_post",
                    error,
                )
            })?
            .is_some()),
        "private_key_jwt" => Ok(validate_private_key_jwt_client_assertion(
            state,
            client_id,
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
            format!("{}/device_authorization", issuer_base.trim_end_matches('/')),
        )
        .await?
        .as_deref()
            == Some(client_id)),
        _ => Ok(false),
    }
}

fn enforce_device_client_authentication_result(
    state: &AppState,
    client_id: String,
    client_auth_method: &'static str,
    client_authenticated: bool,
    issuer_base: &str,
) -> Result<DeviceAuthorizationClientContext, Response> {
    if client_auth_method == "none" {
        let confidential = state
            .clients
            .try_is_confidential(&client_id)
            .map_err(|error| {
                registry_state_error_response(
                    issuer_base,
                    "device_authorization_is_confidential",
                    error,
                )
            })?;
        return if confidential {
            Err(device_invalid_client_response(issuer_base))
        } else {
            Ok(DeviceAuthorizationClientContext {
                client_id,
                client_auth_method,
            })
        };
    }
    if client_authenticated {
        Ok(DeviceAuthorizationClientContext {
            client_id,
            client_auth_method,
        })
    } else {
        Err(device_invalid_client_response(issuer_base))
    }
}

pub(super) async fn authenticate_device_authorization_client(
    state: &AppState,
    headers: &HeaderMap,
    form: &TokenForm,
    issuer_base: &str,
) -> Result<DeviceAuthorizationClientContext, Response> {
    let auth_header = authorization_header(headers)
        .map_err(|err| no_cache_header_error(issuer_base, "Authorization", err))?;
    let auth_presence = token_auth_presence(auth_header, form);
    if multiple_client_auth_methods_present(auth_presence) {
        return Err(no_cache_json_error_with_iss(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("multiple client authentication methods are not allowed"),
            issuer_base,
        ));
    }

    let client_id =
        resolve_device_authorization_client_id(auth_header, auth_presence, form, issuer_base)?;
    let registered = state
        .clients
        .try_get(&client_id)
        .map_err(|error| {
            registry_state_error_response(issuer_base, "device_authorization_get_client", error)
        })?
        .is_some();
    if !registered {
        return Err(device_invalid_client_response(issuer_base));
    }

    let client_auth_method = auth_presence.method();
    let client_authenticated = device_client_authenticated(
        state,
        auth_header,
        form,
        &client_id,
        client_auth_method,
        issuer_base,
    )
    .await?;

    enforce_device_client_authentication_result(
        state,
        client_id,
        client_auth_method,
        client_authenticated,
        issuer_base,
    )
}
