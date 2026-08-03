use super::{ConnectionClientSecretAction, ConnectionInput};
use crate::management::types::{CreateConnectionRequest, UpdateConnectionRequest};
use crate::upstream::upstream_client_auth_method_uses_secret;
use crate::web::management::error_response;
use axum::{http::StatusCode, response::Response};

pub(in crate::web::management) fn connection_client_secret_action_from_create(
    req: &CreateConnectionRequest,
) -> ConnectionClientSecretAction {
    req.client_secret
        .as_deref()
        .and_then(normalize_client_secret)
        .map_or(
            ConnectionClientSecretAction::Clear,
            ConnectionClientSecretAction::Set,
        )
}

pub(in crate::web::management) fn connection_client_secret_action_from_update(
    req: &UpdateConnectionRequest,
) -> ConnectionClientSecretAction {
    match req.client_secret.as_ref() {
        None => ConnectionClientSecretAction::Preserve,
        Some(None) => ConnectionClientSecretAction::Clear,
        Some(Some(value)) => normalize_client_secret(value).map_or(
            ConnectionClientSecretAction::Clear,
            ConnectionClientSecretAction::Set,
        ),
    }
}

pub(in crate::web::management) fn resolve_connection_client_secret_action(
    input: &ConnectionInput,
    requested: ConnectionClientSecretAction,
    existing_client_secret_present: bool,
    request_id: &str,
) -> Result<ConnectionClientSecretAction, Response> {
    if upstream_client_auth_method_uses_secret(&input.client_auth_method) {
        return match requested {
            ConnectionClientSecretAction::Set(secret) => {
                Ok(ConnectionClientSecretAction::Set(secret))
            }
            ConnectionClientSecretAction::Preserve if existing_client_secret_present => {
                Ok(ConnectionClientSecretAction::Preserve)
            }
            ConnectionClientSecretAction::Preserve | ConnectionClientSecretAction::Clear => {
                Err(connection_secret_lifecycle_error(
                    "clientSecret is required for client_secret_basic and client_secret_post connections",
                    request_id,
                ))
            }
        };
    }

    match requested {
        ConnectionClientSecretAction::Set(_) => Err(connection_secret_lifecycle_error(
            "clientSecret can only be supplied for client_secret_basic and client_secret_post connections",
            request_id,
        )),
        ConnectionClientSecretAction::Preserve | ConnectionClientSecretAction::Clear => {
            Ok(ConnectionClientSecretAction::Clear)
        }
    }
}

pub(in crate::web::management) fn validate_preserved_connection_client_secret(
    client_auth_method: &str,
    client_secret_present: bool,
    request_id: &str,
) -> Result<(), Response> {
    if upstream_client_auth_method_uses_secret(client_auth_method) && !client_secret_present {
        return Err(connection_secret_lifecycle_error(
            "clientSecret is required for client_secret_basic and client_secret_post connections",
            request_id,
        ));
    }
    Ok(())
}

fn normalize_client_secret(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn connection_secret_lifecycle_error(message: &str, request_id: &str) -> Response {
    error_response(
        StatusCode::BAD_REQUEST,
        "invalid_request",
        message,
        None,
        Some(request_id),
    )
}
