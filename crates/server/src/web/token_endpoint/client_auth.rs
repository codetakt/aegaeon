use axum::{http::StatusCode, response::Response};

use crate::client_registry::{ClientAssertionValidationError, ClientRegistry};
use crate::util;

use super::super::oauth_errors::{
    json_error_with_iss, no_cache_json_error_with_iss, with_basic_client_challenge,
};
use super::super::token_response::{
    token_error_response, token_invalid_client_response, token_registry_state_error_response,
};
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
    value.is_some_and(|value| !value.is_empty())
}

pub(in crate::web) fn client_auth_presence(
    auth_header: Option<&str>,
    client_secret: Option<&str>,
    client_assertion_type: Option<&str>,
    client_assertion: Option<&str>,
) -> ClientAuthPresence {
    let basic_present = auth_header.is_some_and(ClientRegistry::basic_auth_attempted);
    let post_present = non_empty(client_secret);
    let pkjwt_present = client_assertion.is_some() || client_assertion_type.is_some();
    ClientAuthPresence::from_parts(basic_present, post_present, pkjwt_present)
}

/// Classify only mechanisms admitted by the existing form/header parsers.
/// An assertion mixture has RFC 7521's invalid_client category; ordinary
/// password mixtures retain RFC 6749's invalid_request category.
pub(in crate::web) fn client_authentication_conflict_response(
    presence: ClientAuthPresence,
    realm: &'static str,
    issuer: Option<&str>,
) -> Option<Response> {
    if !presence.multiple_methods_present() {
        return None;
    }
    let description = "multiple client authentication methods are not allowed";
    let (status, error) = if presence.private_key_jwt {
        (StatusCode::UNAUTHORIZED, "invalid_client")
    } else {
        (StatusCode::BAD_REQUEST, "invalid_request")
    };
    let mut response = match issuer {
        Some(issuer) => no_cache_json_error_with_iss(status, error, Some(description), issuer),
        None => token_error_response(status, error, Some(description)),
    };
    if presence.private_key_jwt {
        response = with_basic_client_challenge(response, realm);
    }
    Some(response)
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

pub(super) fn client_assertion_internal_error_response(
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
    state: &AppState,
    auth_header: Option<&str>,
    form: &TokenForm,
) -> Result<(String, ClientAuthPresence), Response> {
    let presence = token_auth_presence(auth_header, form);
    if let Some(response) = client_authentication_conflict_response(presence, "oauth", None) {
        return Err(response);
    }
    let client_id_from_basic = match (presence.basic, auth_header) {
        (true, Some(header)) => Some(
            ClientRegistry::decode_basic_auth_credentials(header)
                .map(|(id, _)| id)
                .ok_or_else(token_invalid_client_response)?,
        ),
        _ => None,
    };
    let client_id_from_assertion = if presence.private_key_jwt {
        Some(
            super::assertion_subject::private_key_jwt_client_id(
                state,
                form.client_id.as_deref(),
                form.client_assertion_type.as_deref(),
                form.client_assertion.as_deref(),
            )?
            .ok_or_else(token_invalid_client_response)?,
        )
    } else {
        None
    };
    let client_id_from_basic = client_id_from_basic.or(client_id_from_assertion);
    let client_id_from_form = form.client_id.clone();
    let client_id = match (
        client_id_from_form.as_deref(),
        client_id_from_basic.as_deref(),
    ) {
        (Some(form_id), Some(basic_id)) if form_id != basic_id => {
            return Err(token_invalid_client_response());
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
        return Err(token_invalid_client_response());
    }
    let client_confidential = state
        .clients
        .try_is_confidential(client_id)
        .map_err(|error| token_registry_state_error_response("token_is_confidential", error))?;
    if client_auth_method == "none" && client_confidential {
        return Err(token_invalid_client_response());
    }
    if client_auth_method != "none" && !client_authenticated {
        return Err(token_invalid_client_response());
    }
    let require_client_auth =
        matches!(grant_type, "client_credentials" | TOKEN_EXCHANGE_GRANT_TYPE)
            || (state.cfg.require_client_auth_token && client_confidential);
    if require_client_auth && !client_authenticated {
        return Err(token_invalid_client_response());
    }
    Ok(())
}
