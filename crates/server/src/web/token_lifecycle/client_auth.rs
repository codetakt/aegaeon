use super::super::oauth_errors::{
    authorization_header, invalid_client_header_error, registry_state_error_response,
};
use super::super::{
    client_auth_presence, multiple_client_auth_methods_present, token_client_auth_method,
    validate_private_key_jwt_client_assertion, AppState,
};
use super::forms::{IntrospectForm, RevokeForm};
use axum::{http::HeaderMap, response::Response};

use crate::util;

#[derive(Clone, Debug)]
pub(super) struct EndpointClientAuthContext {
    pub(super) client_id: Option<String>,
    pub(super) client_auth_method: &'static str,
}

#[expect(
    clippy::too_many_lines,
    reason = "existing endpoint authentication workflow; new oversized functions remain gated"
)]
pub(super) async fn introspection_requesting_client_id(
    state: &AppState,
    headers: &HeaderMap,
    form: &IntrospectForm,
) -> Result<EndpointClientAuthContext, Response> {
    let auth_header = authorization_header(headers)
        .map_err(|err| invalid_client_header_error("token_introspection", "Authorization", err))?;
    let presence = client_auth_presence(
        auth_header,
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    if multiple_client_auth_methods_present(presence) {
        return Err(util::invalid_client_response(
            "token_introspection",
            "Multiple client authentication methods are not allowed",
        ));
    }
    let client_auth_method = token_client_auth_method(presence);
    let basic_client_id = if presence.basic {
        auth_header
            .map(|value| {
                state
                    .clients
                    .try_validate_basic_auth(value)
                    .map(|validated| validated.map(|(id, _)| id))
                    .map_err(|error| {
                        registry_state_error_response(
                            state.issuer.as_str(),
                            "introspection_validate_basic_auth",
                            error,
                        )
                    })
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let post_client_id = if presence.post {
        state
            .clients
            .try_validate_client_secret_post(
                form.client_id.as_deref(),
                form.client_secret.as_deref(),
            )
            .map_err(|error| {
                registry_state_error_response(
                    state.issuer.as_str(),
                    "introspection_validate_client_secret_post",
                    error,
                )
            })?
    } else {
        None
    };
    let pkjwt_client_id = if presence.private_key_jwt {
        let Some(client_id) = form.client_id.as_deref() else {
            return Err(util::invalid_client_response(
                "token_introspection",
                "Client authentication failed",
            ));
        };
        validate_private_key_jwt_client_assertion(
            state,
            client_id,
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
            format!("{}/introspect", state.issuer.trim_end_matches('/')),
        )
        .await?
    } else {
        None
    };
    let authenticated_client_id = basic_client_id.or(post_client_id).or(pkjwt_client_id);
    if let (Some(provided_client_id), Some(authenticated_client_id)) = (
        form.client_id.as_deref(),
        authenticated_client_id.as_deref(),
    ) {
        if provided_client_id != authenticated_client_id {
            return Err(util::invalid_client_response(
                "token_introspection",
                "Client authentication failed",
            ));
        }
    }
    if presence.any() && authenticated_client_id.is_none() {
        return Err(util::invalid_client_response(
            "token_introspection",
            "Client authentication failed",
        ));
    }
    if authenticated_client_id.is_none() {
        if let Some(client_id) = form.client_id.as_deref() {
            let registered_public = state
                .clients
                .try_is_registered_public_client(client_id)
                .map_err(|error| {
                    registry_state_error_response(
                        state.issuer.as_str(),
                        "introspection_is_registered_public_client",
                        error,
                    )
                })?;
            if !state.cfg.require_client_auth_introspection && registered_public {
                return Ok(EndpointClientAuthContext {
                    client_id: Some(client_id.to_string()),
                    client_auth_method,
                });
            }
            return Err(util::invalid_client_response(
                "token_introspection",
                "Client authentication failed or was not provided",
            ));
        }
    }
    if state.cfg.require_client_auth_introspection && authenticated_client_id.is_none() {
        return Err(util::invalid_client_response(
            "token_introspection",
            "Client authentication failed or was not provided",
        ));
    }
    Ok(EndpointClientAuthContext {
        client_id: authenticated_client_id,
        client_auth_method,
    })
}

#[expect(
    clippy::too_many_lines,
    reason = "existing endpoint authentication workflow; new oversized functions remain gated"
)]
pub(super) async fn revocation_requesting_client_id(
    state: &AppState,
    headers: &HeaderMap,
    form: &RevokeForm,
) -> Result<EndpointClientAuthContext, Response> {
    let auth_header = authorization_header(headers)
        .map_err(|err| invalid_client_header_error("token_revocation", "Authorization", err))?;
    let presence = client_auth_presence(
        auth_header,
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    );
    if multiple_client_auth_methods_present(presence) {
        return Err(util::invalid_client_response(
            "token_revocation",
            "Multiple client authentication methods are not allowed",
        ));
    }
    let client_auth_method = token_client_auth_method(presence);

    let basic_client_id = if presence.basic {
        auth_header
            .map(|value| {
                state
                    .clients
                    .try_validate_basic_auth(value)
                    .map(|validated| validated.map(|(id, _)| id))
                    .map_err(|error| {
                        registry_state_error_response(
                            state.issuer.as_str(),
                            "revocation_validate_basic_auth",
                            error,
                        )
                    })
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let post_client_id = if presence.post {
        state
            .clients
            .try_validate_client_secret_post(
                form.client_id.as_deref(),
                form.client_secret.as_deref(),
            )
            .map_err(|error| {
                registry_state_error_response(
                    state.issuer.as_str(),
                    "revocation_validate_client_secret_post",
                    error,
                )
            })?
    } else {
        None
    };
    let pkjwt_client_id = if presence.private_key_jwt {
        let Some(client_id) = form.client_id.as_deref() else {
            return Err(util::invalid_client_response(
                "token_revocation",
                "Client authentication failed",
            ));
        };
        validate_private_key_jwt_client_assertion(
            state,
            client_id,
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
            format!("{}/revoke", state.issuer.trim_end_matches('/')),
        )
        .await?
    } else {
        None
    };
    let authenticated_client_id = basic_client_id.or(post_client_id).or(pkjwt_client_id);

    if let (Some(provided_client_id), Some(authenticated_client_id)) = (
        form.client_id.as_deref(),
        authenticated_client_id.as_deref(),
    ) {
        if provided_client_id != authenticated_client_id {
            return Err(util::invalid_client_response(
                "token_revocation",
                "Client authentication failed",
            ));
        }
    }
    if presence.any() && authenticated_client_id.is_none() {
        return Err(util::invalid_client_response(
            "token_revocation",
            "Client authentication failed",
        ));
    }
    if authenticated_client_id.is_none() {
        if let Some(client_id) = form.client_id.as_deref() {
            let registered_public = state
                .clients
                .try_is_registered_public_client(client_id)
                .map_err(|error| {
                    registry_state_error_response(
                        state.issuer.as_str(),
                        "revocation_is_registered_public_client",
                        error,
                    )
                })?;
            if !state.cfg.require_client_auth_revocation && registered_public {
                return Ok(EndpointClientAuthContext {
                    client_id: Some(client_id.to_string()),
                    client_auth_method,
                });
            }
            return Err(util::invalid_client_response(
                "token_revocation",
                "Client authentication failed or was not provided",
            ));
        }
        return Err(util::invalid_client_response(
            "token_revocation",
            "Client authentication failed or was not provided",
        ));
    }

    Ok(EndpointClientAuthContext {
        client_id: authenticated_client_id,
        client_auth_method,
    })
}
