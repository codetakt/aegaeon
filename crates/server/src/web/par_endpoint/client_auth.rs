use axum::{http::HeaderMap, response::Response};

use super::super::oauth_errors::{
    authorization_header, invalid_client_header_error, registry_state_error_response,
};
use super::super::{
    client_auth_presence, client_authentication_conflict_response, private_key_jwt_client_id,
    token_client_auth_method, validate_private_key_jwt_client_assertion, AppState,
};
use super::form::ParForm;
use crate::client_registry::ClientRegistry;
use crate::util;

pub(super) struct ParClientContext {
    pub(super) state: AppState,
    pub(super) client_id: String,
    pub(super) client_auth_method: &'static str,
    pub(super) client_authenticated: bool,
}

#[expect(
    clippy::too_many_lines,
    reason = "existing PAR authentication workflow; new oversized functions remain gated"
)]
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
    if auth.is_some() && !presence.basic {
        return Err(util::invalid_client_response(
            "oauth",
            "Unsupported client authentication scheme",
        ));
    }
    if let Some(response) = client_authentication_conflict_response(presence, "oauth", None) {
        return Err(response);
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
    if form.request.is_none() && form.client_id.is_none() {
        return Err(super::super::oauth_errors::no_cache_json_error_with_iss(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("client_id is required for a plain pushed authorization request"),
            state.issuer.as_str(),
        ));
    }
    let assertion_id = if presence.private_key_jwt {
        Some(
            private_key_jwt_client_id(
                state,
                form.client_id.as_deref(),
                form.client_assertion_type.as_deref(),
                form.client_assertion.as_deref(),
            )?
            .ok_or_else(|| {
                util::invalid_client_response("oauth", "Client authentication failed")
            })?,
        )
    } else {
        None
    };
    let client_id_from_basic = client_id_from_basic.or(assertion_id);
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

    let snapshot = super::super::client_request_snapshot::request_state(state, &[&client_id])?;
    #[cfg(test)]
    super::snapshot_test_hook::pause(super::snapshot_test_hook::Phase::BeforeAuthentication).await;
    let state = &snapshot;
    let registered_client = state
        .clients
        .try_get(&client_id)
        .map_err(|error| {
            registry_state_error_response(state.issuer.as_str(), "par_get_auth_client", error)
        })?
        .ok_or_else(|| util::invalid_client_response("oauth", "Client authentication failed"))?;
    let registered_method = registered_client.token_endpoint_auth_method.trim();
    let presented_method = token_client_auth_method(presence);
    if !registered_method.eq_ignore_ascii_case(presented_method) {
        return Err(util::invalid_client_response(
            "oauth",
            "Client authentication failed or was not provided",
        ));
    }

    let secret_authenticated = if presence.basic {
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
        .is_some()
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
            .is_some_and(|auth_client_id| auth_client_id == client_id)
    } else {
        false
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
    let client_authenticated = secret_authenticated || pkjwt_authenticated;
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

    #[cfg(test)]
    super::snapshot_test_hook::pause(super::snapshot_test_hook::Phase::AfterAuthentication).await;
    Ok(ParClientContext {
        state: snapshot,
        client_id,
        client_auth_method: token_client_auth_method(presence),
        client_authenticated,
    })
}
