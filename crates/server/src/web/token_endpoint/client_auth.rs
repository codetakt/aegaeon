use axum::{http::StatusCode, response::Response};

use crate::client_registry::{ClientAssertionValidationError, ClientRegistry};
use crate::util;

use super::super::oauth_errors::json_error_with_iss;
use super::super::token_response::{token_error_response, token_registry_state_error_response};
use super::super::{AppState, CLIENT_ASSERTION_TYPE_JWT_BEARER, TOKEN_EXCHANGE_GRANT_TYPE};
use super::TokenForm;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::web) struct ClientAuthPresence {
    pub(in crate::web) basic: bool,
    pub(in crate::web) post: bool,
    pub(in crate::web) private_key_jwt: bool,
}

impl ClientAuthPresence {
    fn from_parts(basic: bool, post: bool, private_key_jwt: bool) -> Self {
        Self {
            basic,
            post,
            private_key_jwt,
        }
    }

    pub(in crate::web) fn multiple_methods_present(self) -> bool {
        (u8::from(self.basic) + u8::from(self.post) + u8::from(self.private_key_jwt)) > 1
    }

    pub(in crate::web) fn any(self) -> bool {
        self.basic || self.post || self.private_key_jwt
    }

    pub(in crate::web) fn method(self) -> &'static str {
        if self.basic {
            "client_secret_basic"
        } else if self.post {
            "client_secret_post"
        } else if self.private_key_jwt {
            "private_key_jwt"
        } else {
            "none"
        }
    }
}

pub(in crate::web) fn token_auth_presence(
    auth_header: Option<&str>,
    form: &TokenForm,
) -> ClientAuthPresence {
    client_auth_presence(
        auth_header,
        form.client_secret.as_deref(),
        form.client_assertion_type.as_deref(),
        form.client_assertion.as_deref(),
    )
}

fn non_empty(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

pub(in crate::web) fn client_auth_presence(
    auth_header: Option<&str>,
    client_secret: Option<&str>,
    client_assertion_type: Option<&str>,
    client_assertion: Option<&str>,
) -> ClientAuthPresence {
    let basic_present = auth_header.is_some_and(ClientRegistry::basic_auth_present);
    let post_present = non_empty(client_secret);
    let pkjwt_present = non_empty(client_assertion) || non_empty(client_assertion_type);
    ClientAuthPresence::from_parts(basic_present, post_present, pkjwt_present)
}

pub(in crate::web) fn multiple_client_auth_methods_present(presence: ClientAuthPresence) -> bool {
    presence.multiple_methods_present()
}

pub(in crate::web) async fn validate_private_key_jwt_client_assertion(
    state: &AppState,
    client_id: &str,
    assertion_type: Option<&str>,
    assertion: Option<&str>,
    audience: String,
) -> Result<Option<String>, Response> {
    if !state.cfg.grant_runtime().private_key_jwt_enabled() {
        return Ok(None);
    }
    let assertion = match (assertion_type, assertion) {
        (Some(CLIENT_ASSERTION_TYPE_JWT_BEARER), Some(assertion))
            if !assertion.trim().is_empty() =>
        {
            assertion.to_string()
        }
        _ => return Ok(None),
    };
    let clients = state.clients.clone();
    let client_id = client_id.to_string();
    let crypto_profile = state.cfg.crypto_profile;
    match tokio::task::spawn_blocking(move || {
        clients.try_validate_private_key_jwt(&client_id, &assertion, &audience, crypto_profile)
    })
    .await
    {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(ClientAssertionValidationError::InvalidAssertion)) => Ok(None),
        Ok(Err(ClientAssertionValidationError::Internal(message))) => {
            Err(client_assertion_internal_error_response(
                state.issuer.as_str(),
                "private_key_jwt",
                &message,
            ))
        }
        Err(_) => Err(client_assertion_internal_error_response(
            state.issuer.as_str(),
            "private_key_jwt",
            "client assertion validation task failed",
        )),
    }
}

fn client_assertion_internal_error_response(
    issuer_base: &str,
    assertion_kind: &'static str,
    message: &str,
) -> Response {
    tracing::error!(
        target: "oauth",
        assertion_kind,
        error = %message,
        "client assertion validation failed internally"
    );
    let mut response = json_error_with_iss(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        Some("client assertion parser backend misconfigured"),
        issuer_base,
    );
    util::apply_no_cache_headers(&mut response);
    response
}

pub(super) fn token_resolve_client_id(
    auth_header: Option<&str>,
    form: &TokenForm,
) -> Result<(String, ClientAuthPresence), Response> {
    let presence = token_auth_presence(auth_header, form);
    if multiple_client_auth_methods_present(presence) {
        return Err(token_error_response(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            Some("multiple client authentication methods are not allowed"),
        ));
    }
    let client_id_from_basic = match (presence.basic, auth_header) {
        (true, Some(header)) => Some(
            ClientRegistry::decode_basic_auth_credentials(header)
                .map(|(id, _)| id)
                .ok_or_else(|| {
                    token_error_response(StatusCode::UNAUTHORIZED, "invalid_client", None)
                })?,
        ),
        _ => None,
    };
    let client_id_from_form = form.client_id.clone();
    let client_id = match (
        client_id_from_form.as_deref(),
        client_id_from_basic.as_deref(),
    ) {
        (Some(form_id), Some(basic_id)) if form_id != basic_id => {
            return Err(token_error_response(
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                None,
            ));
        }
        (Some(form_id), _) => form_id.to_string(),
        (None, Some(basic_id)) => basic_id.to_string(),
        (None, None) => {
            return Err(token_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                Some("missing client_id"),
            ));
        }
    };
    Ok((client_id, presence))
}

pub(in crate::web) fn token_client_auth_method(presence: ClientAuthPresence) -> &'static str {
    presence.method()
}

pub(super) async fn token_validate_client_authentication(
    state: &AppState,
    form: &TokenForm,
    client_id: &str,
    auth_header: Option<&str>,
    grant_type: &str,
    client_auth_method: &str,
) -> Result<(), Response> {
    let basic_ok = if client_auth_method == "client_secret_basic" {
        auth_header
            .map(|header| {
                state
                    .clients
                    .try_validate_basic_auth(header)
                    .map(|validated| validated.map(|(id, _)| id))
                    .map_err(|error| {
                        token_registry_state_error_response("token_validate_basic_auth", error)
                    })
            })
            .transpose()?
            .flatten()
    } else {
        None
    };
    let post_ok = if client_auth_method == "client_secret_post" {
        state
            .clients
            .try_validate_client_secret_post(Some(client_id), form.client_secret.as_deref())
            .map_err(|error| {
                token_registry_state_error_response("token_validate_client_secret_post", error)
            })?
    } else {
        None
    };
    let pkjwt_ok = if client_auth_method == "private_key_jwt" {
        let audience = format!("{}/token", state.issuer.trim_end_matches('/'));
        validate_private_key_jwt_client_assertion(
            state,
            client_id,
            form.client_assertion_type.as_deref(),
            form.client_assertion.as_deref(),
            audience,
        )
        .await?
    } else {
        None
    };
    let client_authenticated = match client_auth_method {
        "client_secret_basic" => basic_ok.is_some(),
        "client_secret_post" => post_ok.is_some(),
        "private_key_jwt" => pkjwt_ok.as_deref() == Some(client_id),
        _ => false,
    };
    let client_registered = state
        .clients
        .try_is_registered_client(client_id)
        .map_err(|error| {
            token_registry_state_error_response("token_is_registered_client", error)
        })?;
    if !client_registered {
        return Err(token_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            None,
        ));
    }
    let client_confidential = state
        .clients
        .try_is_confidential(client_id)
        .map_err(|error| token_registry_state_error_response("token_is_confidential", error))?;
    if client_auth_method == "none" && client_confidential {
        return Err(token_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            None,
        ));
    }
    if client_auth_method != "none" && !client_authenticated {
        return Err(token_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            None,
        ));
    }
    let require_client_auth =
        matches!(grant_type, "client_credentials" | TOKEN_EXCHANGE_GRANT_TYPE)
            || (state.cfg.require_client_auth_token && client_confidential);
    if require_client_auth && !client_authenticated {
        return Err(token_error_response(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            None,
        ));
    }
    Ok(())
}
