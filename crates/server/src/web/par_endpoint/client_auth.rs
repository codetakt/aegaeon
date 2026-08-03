use axum::{http::HeaderMap, response::Response};

use super::super::oauth_errors::{
    authorization_header, invalid_client_header_error, registry_state_error_response,
};
use super::super::{
    client_auth_presence, multiple_client_auth_methods_present, token_client_auth_method,
    validate_private_key_jwt_client_assertion, AppState,
};
use super::form::ParForm;
use crate::client_registry::ClientRegistry;
use crate::util;

pub(super) struct ParClientContext {
    pub(super) client_id: String,
    pub(super) client_auth_method: &'static str,
    pub(super) client_secret_for_store: Option<String>,
    pub(super) client_authenticated: bool,
}

pub(super) async fn authenticate_par_client(
    state: &AppState,
    headers: &HeaderMap,
    form: &ParForm,
) -> Result<ParClientContext, Response> {
    let auth = authorization_header(headers)
        .map_err(|err| invalid_client_header_error("oauth", "Authorization", err))?;
    let presence = client_auth_presence(
        auth,
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    if multiple_client_auth_methods_present(presence) {
        return Err(util::invalid_client_response(
            "oauth",
            "Multiple client authentication methods are not allowed",
        ));
    }
    let client_id_from_basic = match (presence.basic, auth) {
        (true, Some(header)) => Some(
            ClientRegistry::decode_basic_auth_credentials(header)
                .map(|(id, _)| id)
                .ok_or_else(|| {
                    util::invalid_client_response("oauth", "Client authentication failed")
                })?,
        ),
        _ => None,
    };
    let client_id = match (form.client_id.as_deref(), client_id_from_basic.as_deref()) {
        (Some(form_id), Some(basic_id)) if form_id != basic_id => {
            return Err(util::invalid_client_response(
                "oauth",
                "Client authentication failed",
            ));
        }
        (Some(form_id), _) => Some(form_id.to_string()),
        (None, Some(basic_id)) => Some(basic_id.to_string()),
        (None, None) => None,
    };
    let Some(client_id) = client_id else {
        return Err(util::invalid_client_response(
            "oauth",
            "Client authentication failed or was not provided",
        ));
    };

    let authenticated_secret = if presence.basic {
        auth.map(|value| {
            state
                .clients
                .try_validate_basic_auth(value)
                .map_err(|error| {
                    registry_state_error_response(
                        state.issuer.as_str(),
                        "par_validate_basic_auth",
                        error,
                    )
                })
        })
        .transpose()?
        .flatten()
        .filter(|(auth_client_id, _)| auth_client_id == &client_id)
        .map(|(_, secret)| secret)
    } else if presence.post {
        state
            .clients
            .try_validate_client_secret_post(Some(&client_id), form.client_secret.as_deref())
            .map_err(|error| {
                registry_state_error_response(
                    state.issuer.as_str(),
                    "par_validate_client_secret_post",
                    error,
                )
            })?
            .and_then(|auth_client_id| {
                (auth_client_id == client_id)
                    .then(|| form.client_secret.clone())
                    .flatten()
            })
    } else {
        None
    };
    let pkjwt_authenticated = if presence.private_key_jwt {
        validate_private_key_jwt_client_assertion(
            state,
            &client_id,
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
            format!("{}/par", state.issuer.trim_end_matches('/')),
        )
        .await?
        .as_deref()
            == Some(client_id.as_str())
    } else {
        false
    };
    let client_authenticated = authenticated_secret.is_some() || pkjwt_authenticated;
    if presence.any() && !client_authenticated {
        return Err(util::invalid_client_response(
            "oauth",
            "Client authentication failed",
        ));
    }
    if state.cfg.require_client_auth_par && !client_authenticated {
        return Err(util::invalid_client_response(
            "oauth",
            "Client authentication failed or was not provided",
        ));
    }

    Ok(ParClientContext {
        client_id,
        client_auth_method: token_client_auth_method(presence),
        client_secret_for_store: authenticated_secret,
        client_authenticated,
    })
}
